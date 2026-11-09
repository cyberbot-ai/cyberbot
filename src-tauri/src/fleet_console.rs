use crate::{
    activity,
    model::{Endpoint, Server},
    process::GroupGuard,
    ssh, ssh_pool,
    store::Store,
    AppState,
};
use serde::Serialize;
use std::{
    collections::HashSet,
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tauri::{State, WebviewWindow};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub(crate) const MAX_TARGETS: usize = 500;
const PARALLEL: usize = 8;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(600);
const PREPARE_TIMEOUT: Duration = Duration::from_secs(120);
const STDOUT_LIMIT: usize = 24 * 1024;
const STDERR_LIMIT: usize = 8 * 1024;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TargetLabel {
    id: String,
    name: String,
    address: String,
}
struct Target {
    label: TargetLabel,
    endpoint: Endpoint,
}
fn target_set(store: &Store, ids: &[String]) -> Result<(Vec<Target>, bool), String> {
    let selected: HashSet<_> = ids.iter().collect();
    if selected.is_empty() || selected.len() != ids.len() || selected.len() > MAX_TARGETS {
        return Err(format!("Choose from 1 to {MAX_TARGETS} different servers"));
    }
    let db = store.0.lock().map_err(err)?;
    let servers = Store::list::<Server>(&db, "servers")?;
    let all = selected.len() == servers.len();
    let mut targets = Vec::with_capacity(selected.len());
    for server in servers.into_iter().filter(|s| selected.contains(&s.id)) {
        targets.push(Target {
            label: TargetLabel {
                id: server.id,
                name: server.name,
                address: ssh::target(&server.endpoint),
            },
            endpoint: server.endpoint,
        });
    }
    if targets.len() != selected.len() {
        return Err(
            "The server list has changed. Check the selection and send the command again.".into(),
        );
    }
    targets.sort_by(|a, b| {
        a.label
            .name
            .cmp(&b.label.name)
            .then(a.label.id.cmp(&b.label.id))
    });
    Ok((targets, all))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Review {
    ticket: Uuid,
    confirm_all: bool,
    targets: Vec<TargetLabel>,
}
struct Prepared {
    ticket: Uuid,
    command: String,
    targets: Vec<Target>,
    confirm_all: bool,
    all_requested: bool,
    at: Instant,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
enum Status {
    Queued,
    Running,
    Ok,
    Fail,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Row {
    #[serde(flatten)]
    target: TargetLabel,
    status: Status,
    duration_ms: Option<u64>,
    code: Option<i32>,
    reason: Option<String>,
}

#[derive(Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Output {
    stdout: String,
    stderr: String,
    truncated: bool,
}
struct ResultRow {
    row: Row,
    output: Output,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Summary {
    id: Uuid,
    revision: u64,
    active: bool,
    stopping: bool,
    command: String,
    rows: Vec<Row>,
}
struct Batch {
    id: Uuid,
    revision: u64,
    active: bool,
    command: Arc<str>,
    cancel: CancellationToken,
    rows: Vec<ResultRow>,
}
impl Batch {
    fn summary(&self) -> Summary {
        Summary {
            id: self.id,
            revision: self.revision,
            active: self.active,
            stopping: self.active && self.cancel.is_cancelled(),
            command: self.command.to_string(),
            rows: self.rows.iter().map(|row| row.row.clone()).collect(),
        }
    }
}

#[derive(Default)]
struct Runtime {
    prepared: Option<Prepared>,
    latest: Option<Batch>,
}
#[derive(Default)]
pub(crate) struct Console(Mutex<Runtime>);

impl Console {
    fn prepare(
        &self,
        store: &Store,
        ids: Vec<String>,
        command: String,
        all: bool,
    ) -> Result<Review, String> {
        if command.trim().is_empty()
            || command.len() > 16 * 1024
            || command
                .chars()
                .any(|ch| ch.is_control() && ch != '\n' && ch != '\t')
        {
            return Err("Enter the command to 16 KiB without control symbols".into());
        }
        let (targets, full_fleet) = target_set(store, &ids)?;
        if all && !full_fleet {
            return Err(
                "The server list has changed. Check the targets and send the command again.".into(),
            );
        }
        let mut runtime = self.0.lock().map_err(err)?;
        if runtime.latest.as_ref().is_some_and(|batch| batch.active) {
            return Err("Wait for the completion of the current team".into());
        }
        let ticket = Uuid::new_v4();
        let review = Review {
            ticket,
            confirm_all: full_fleet,
            targets: targets.iter().map(|t| t.label.clone()).collect(),
        };
        runtime.prepared = Some(Prepared {
            ticket,
            command,
            targets,
            confirm_all: full_fleet,
            all_requested: all,
            at: Instant::now(),
        });
        Ok(review)
    }

    fn start(
        &self,
        store: &Store,
        ticket: Uuid,
        confirmed: bool,
    ) -> Result<(Prepared, Summary, CancellationToken), String> {
        let mut runtime = self.0.lock().map_err(err)?;
        let prepared = runtime
            .prepared
            .as_ref()
            .filter(|p| p.ticket == ticket && p.at.elapsed() < PREPARE_TIMEOUT)
            .ok_or("Preparation’s out of date. Send the command again.")?;
        if prepared.confirm_all && !confirmed {
            return Err("Confirm launch on all servers".into());
        }
        if runtime.latest.as_ref().is_some_and(|batch| batch.active) {
            return Err("Wait for the completion of the current team".into());
        }
        let ids: Vec<_> = prepared
            .targets
            .iter()
            .map(|t| t.label.id.clone())
            .collect();
        let (current, all) = target_set(store, &ids)?;
        if (prepared.all_requested && !all)
            || (!prepared.confirm_all && all)
            || current.iter().any(|target| {
                !prepared.targets.iter().any(|prior| {
                    prior.label.id == target.label.id && prior.endpoint == target.endpoint
                })
            })
        {
            runtime.prepared = None;
            return Err(
                "The target list or connection has changed. Send the command again.".into(),
            );
        }
        let prepared = runtime.prepared.take().unwrap();
        let cancel = CancellationToken::new();
        let batch = Batch {
            id: ticket,
            revision: 0,
            active: true,
            command: prepared.command.as_str().into(),
            cancel: cancel.clone(),
            rows: prepared
                .targets
                .iter()
                .map(|target| ResultRow {
                    row: Row {
                        target: target.label.clone(),
                        status: Status::Queued,
                        duration_ms: None,
                        code: None,
                        reason: None,
                    },
                    output: Output::default(),
                })
                .collect(),
        };
        let summary = batch.summary();
        runtime.latest = Some(batch);
        Ok((prepared, summary, cancel))
    }

    pub(crate) fn shutdown(&self) {
        if let Ok(runtime) = self.0.lock() {
            if let Some(batch) = &runtime.latest {
                batch.cancel.cancel();
            }
        }
    }

    fn change(&self, id: Uuid, update: impl FnOnce(&mut Batch)) {
        if let Ok(mut runtime) = self.0.lock() {
            if let Some(batch) = runtime.latest.as_mut().filter(|batch| batch.id == id) {
                update(batch);
                batch.revision += 1;
            }
        }
    }
}

fn main_window(window: &WebviewWindow) -> Result<(), String> {
    if window.label() != "main" {
        return Err("The console is only available in the main window".into());
    }
    Ok(())
}

#[tauri::command]
pub(crate) fn prepare_console_batch(
    window: WebviewWindow,
    state: State<'_, Arc<AppState>>,
    server_ids: Vec<String>,
    command: String,
    all: bool,
) -> Result<Review, String> {
    main_window(&window)?;
    state
        .fleet_console
        .prepare(&state.store, server_ids, command, all)
}

#[tauri::command]
pub(crate) fn start_console_batch(
    window: WebviewWindow,
    state: State<'_, Arc<AppState>>,
    ticket: Uuid,
    confirmed: bool,
) -> Result<Summary, String> {
    main_window(&window)?;
    let state = state.inner().clone();
    let (prepared, summary, cancel) = state.fleet_console.start(&state.store, ticket, confirmed)?;
    tauri::async_runtime::spawn(run_batch(state, prepared, cancel));
    Ok(summary)
}

#[tauri::command]
pub(crate) fn console_batch_status(
    window: WebviewWindow,
    state: State<'_, Arc<AppState>>,
    id: Option<Uuid>,
    revision: Option<u64>,
) -> Result<Option<Summary>, String> {
    main_window(&window)?;
    let runtime = state.fleet_console.0.lock().map_err(err)?;
    Ok(runtime
        .latest
        .as_ref()
        .filter(|batch| id != Some(batch.id) || revision != Some(batch.revision))
        .map(Batch::summary))
}

#[tauri::command]
pub(crate) fn console_batch_output(
    window: WebviewWindow,
    state: State<'_, Arc<AppState>>,
    id: Uuid,
    server_id: String,
) -> Result<Output, String> {
    main_window(&window)?;
    let runtime = state.fleet_console.0.lock().map_err(err)?;
    runtime
        .latest
        .as_ref()
        .filter(|batch| batch.id == id)
        .and_then(|batch| batch.rows.iter().find(|row| row.row.target.id == server_id))
        .map(|row| row.output.clone())
        .ok_or_else(|| "Results no longer available".into())
}

#[tauri::command]
pub(crate) fn stop_console_batch(
    window: WebviewWindow,
    state: State<'_, Arc<AppState>>,
    id: Uuid,
) -> Result<(), String> {
    main_window(&window)?;
    state
        .fleet_console
        .change(id, |batch| batch.cancel.cancel());
    Ok(())
}

struct Outcome {
    code: Option<i32>,
    reason: Option<String>,
    output: Output,
}
impl Outcome {
    fn failed(reason: impl Into<String>) -> Self {
        Self {
            code: None,
            reason: Some(reason.into()),
            output: Output::default(),
        }
    }
    fn ok(&self) -> bool {
        self.code == Some(0) && self.reason.is_none()
    }
}

async fn run_batch(state: Arc<AppState>, prepared: Prepared, cancel: CancellationToken) {
    let id = prepared.ticket;
    let command: Arc<str> = prepared.command.into();
    let mut targets = prepared.targets.into_iter().enumerate();
    let mut jobs = JoinSet::new();
    loop {
        while jobs.len() < PARALLEL && !cancel.is_cancelled() {
            let Some((index, target)) = targets.next() else {
                break;
            };
            jobs.spawn(run_target(
                state.clone(),
                id,
                index,
                target,
                command.clone(),
                cancel.clone(),
            ));
        }
        if jobs.join_next().await.is_none() {
            break;
        }
    }
    state.fleet_console.change(id, |batch| {
        batch.active = false;
        for row in &mut batch.rows {
            if matches!(row.row.status, Status::Queued | Status::Running) {
                row.row.reason = Some(
                    if row.row.status == Status::Queued && cancel.is_cancelled() {
                        "Taken off the line"
                    } else {
                        "Execution interrupted. Outcome unknown"
                    }
                    .into(),
                );
                row.row.status = Status::Fail;
            }
        }
    });
}

async fn run_target(
    state: Arc<AppState>,
    batch_id: Uuid,
    index: usize,
    target: Target,
    command: Arc<str>,
    cancel: CancellationToken,
) {
    let mut span = activity::begin_run(
        "server",
        "console_command",
        Some(ssh::target(&target.endpoint)),
        Some(batch_id.to_string()),
    );
    let mut started = None;
    let mut launched = false;
    let result = async {
        let _guard = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err("Stopped before launch".into()),
            guard = state.collectors.manual(&target.label.id) => guard?,
        };
        let pool = ssh_pool::global()?;
        current_target(&state.store, &target)?;
        let lease = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err("Stopped before launch".into()),
            lease = pool.acquire(&target.endpoint) => lease?,
        };
        current_target(&state.store, &target)?;
        let mut args = lease.options()?;
        args.extend([
            "--".into(),
            target.endpoint.host.clone(),
            command.to_string(),
        ]);
        if cancel.is_cancelled() {
            return Err("Stopped before launch".into());
        }
        started = Some(Instant::now());
        state.fleet_console.change(batch_id, |batch| {
            batch.rows[index].row.status = Status::Running
        });
        let result = capture(&args, &cancel, &lease, &mut launched).await;
        if result.code == Some(255) {
            lease.invalidate();
        }
        Ok::<_, String>(result)
    }
    .await
    .unwrap_or_else(Outcome::failed);
    if launched {
        state.package_refresh_after_command(&target.label.id, &target.endpoint);
    }
    let ok = result.ok();
    span.finish(if ok { "completed" } else { "failed" });
    state.fleet_console.change(batch_id, |batch| {
        let row = &mut batch.rows[index];
        row.row.status = if ok { Status::Ok } else { Status::Fail };
        row.row.code = result.code;
        row.row.reason = result.reason;
        row.row.duration_ms = started.map(|at| at.elapsed().as_millis() as u64);
        row.output = result.output;
    });
}

fn current_target(store: &Store, target: &Target) -> Result<(), String> {
    if store.server_endpoint(&target.label.id)? != target.endpoint {
        return Err("The connection changed. The team didn’t start.".into());
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Interrupted {
    Overflow,
    Timeout,
    Cancelled,
    Io,
    Revoked,
}
async fn read_output(
    mut pipe: impl AsyncRead + Unpin,
    saved: &mut Vec<u8>,
    limit: usize,
) -> Result<(), Interrupted> {
    let mut buf = [0; 4096];
    loop {
        let n = pipe.read(&mut buf).await.map_err(|_| Interrupted::Io)?;
        if n == 0 {
            return Ok(());
        }
        let keep = n.min(limit - saved.len());
        saved.extend_from_slice(&buf[..keep]);
        if keep < n {
            return Err(Interrupted::Overflow);
        }
    }
}

async fn capture(
    args: &[String],
    cancel: &CancellationToken,
    lease: &ssh_pool::Lease,
    launched: &mut bool,
) -> Outcome {
    let mut command = Command::new("/usr/bin/ssh");
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    let Ok(mut child) = command.spawn() else {
        return Outcome::failed("Failed to launch SSH");
    };
    *launched = true;
    let Some(_guard) = child.id().and_then(|id| GroupGuard::register(id).ok()) else {
        return Outcome::failed("Failed to register the SSH process");
    };
    let (Some(out), Some(error)) = (child.stdout.take(), child.stderr.take()) else {
        return Outcome::failed("SSH output unavailable");
    };
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let done = async {
        let (status, (), ()) = tokio::try_join!(
            async { child.wait().await.map_err(|_| Interrupted::Io) },
            read_output(out, &mut stdout, STDOUT_LIMIT),
            read_output(error, &mut stderr, STDERR_LIMIT),
        )?;
        Ok(status.code())
    };
    let result = tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(Interrupted::Cancelled),
        _ = lease.revoked() => Err(Interrupted::Revoked),
        result = tokio::time::timeout(COMMAND_TIMEOUT, done) => result.unwrap_or(Err(Interrupted::Timeout)),
    };
    let code = result.as_ref().ok().copied().flatten();
    let reason = match result {
        Ok(Some(0)) => None,
        Ok(Some(255)) => Some("SSH did not confirm the result (255)".into()),
        Ok(Some(_)) => Some("The team ended with a mistake".into()),
        Ok(None) | Err(Interrupted::Io | Interrupted::Revoked) => {
            Some("SSH aborted. Team result unknown".into())
        }
        Err(Interrupted::Overflow) => Some("Output limit reached. Team result unknown".into()),
        Err(Interrupted::Timeout) => Some("It’s been 10 minutes. Team result is unknown".into()),
        Err(Interrupted::Cancelled) => {
            Some("The SSH channel is closed. Team result is unknown".into())
        }
    };
    Outcome {
        code,
        reason,
        output: Output {
            stdout: display_text(&stdout),
            stderr: display_text(&stderr),
            truncated: matches!(result, Err(Interrupted::Overflow)),
        },
    }
}

fn display_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .filter(|ch| !ch.is_control() || matches!(ch, '\n' | '\t'))
        .collect()
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{inventory::parse_manual, model::Source};

    fn import(store: &Store, source_id: &str, port: u16, ssh_dir: Option<&str>) -> String {
        let source = Source {
            id: source_id.into(),
            name: source_id.into(),
            kind: "manual".into(),
            location: format!("ops@127.0.0.1:{port}"),
            last_sync: None,
            error: None,
        };
        let mut hosts = parse_manual(&source.location).unwrap();
        if let Some(dir) = ssh_dir {
            hosts[0].endpoint.identity_file = Some(format!("{dir}/id_ed25519"));
            hosts[0].endpoint.known_hosts_file = Some(format!("{dir}/known_hosts"));
        }
        store.import(&source, hosts).unwrap();
        store
            .snapshot()
            .unwrap()
            .servers
            .into_iter()
            .find(|s| s.source_id == source_id)
            .unwrap()
            .id
    }

    #[test]
    fn full_fleet_ticket_requires_confirmation_and_cannot_be_replayed_or_widened() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("state.sqlite")).unwrap();
        let console = Console::default();
        let a = import(&store, "a", 101, None);
        let review = console
            .prepare(&store, vec![a.clone()], "df -h".into(), true)
            .unwrap();
        assert!(review.confirm_all);
        assert!(console.start(&store, review.ticket, false).is_err());

        let b = import(&store, "b", 102, None);
        assert!(console.start(&store, review.ticket, true).is_err());
        assert!(console
            .prepare(&store, vec![a.clone(), a.clone()], "true".into(), false)
            .is_err());
        let review = console
            .prepare(&store, vec![a.clone(), b], "true".into(), false)
            .unwrap();
        assert!(review.confirm_all);
        let (_, batch, _) = console.start(&store, review.ticket, true).unwrap();
        assert_eq!(batch.rows.len(), 2);
        assert!(console.start(&store, review.ticket, true).is_err());
        assert_eq!(COMMAND_TIMEOUT.as_secs(), 600);
    }

    #[tokio::test]
    #[ignore = "requires a disposable Debian package fixture: python3 scripts/test-packages.py"]
    async fn debian_ssh_package_refresh_recovers_after_two_reads() {
        let root = std::env::var_os("CYBERBOT_TEST_PACKAGE_STATE").unwrap();
        let fixture_port: u16 = std::env::var("CYBERBOT_TEST_SSH_PORT")
            .unwrap()
            .parse()
            .unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config = config_dir.path().join("ssh_config");
        std::fs::write(&config, "").unwrap();
        ssh_pool::install(ssh_pool::Pool::new(4, Duration::from_secs(60), Some(config)).unwrap())
            .unwrap();
        let state = crate::create_state(root.into()).unwrap();
        let snapshot = state.store.snapshot().unwrap();
        let server = &snapshot.servers[0];
        assert_eq!(server.endpoint.host, "127.0.0.1");
        assert_eq!(server.endpoint.port, fixture_port);
        assert!(fixture_port >= 1024);
        let id = &server.id;
        let before = state.store.cached_package_state(id).unwrap();
        assert_eq!(state.store.vulnerability_view(id, 0).unwrap().total, 1);
        assert_eq!(snapshot.incidents[0].status, "open");

        let ticket = state
            .fleet_console
            .prepare(&state.store, vec![id.clone()], "exit 7".into(), false)
            .unwrap()
            .ticket;
        let (plan, _, cancel) = state
            .fleet_console
            .start(&state.store, ticket, true)
            .unwrap();
        run_batch(state.clone(), plan, cancel).await;
        let code = state
            .fleet_console
            .0
            .lock()
            .unwrap()
            .latest
            .as_ref()
            .unwrap()
            .rows[0]
            .row
            .code;
        assert_eq!(code, Some(7));

        let rescan = || async {
            let at = *state
                .package_refresh
                .due()
                .get(id)
                .expect("a package refresh should be queued");
            tokio::time::sleep_until(at.into()).await;
            let job = state
                .package_refresh
                .claim(id, &server.endpoint, Instant::now())
                .unwrap();
            crate::monitoring::trigger(
                "schedule",
                crate::packages::refresh_after_ssh(state.clone(), id.clone(), job),
            )
            .await;
        };
        // Pause after dispatch is selected, and then occupy the same server with a normal check.
        let mut settings = state.store.settings().unwrap();
        settings.paused = true;
        state.store.save_settings(&settings).unwrap();
        rescan().await;
        assert_eq!(
            state.store.cached_package_state(id).unwrap().checks,
            before.checks
        );
        settings.paused = false;
        state.store.save_settings(&settings).unwrap();
        let occupied = state.collectors.try_background(id, 1).unwrap().unwrap();
        rescan().await;
        assert_eq!(
            state.store.cached_package_state(id).unwrap().checks,
            before.checks
        );
        drop(occupied);
        rescan().await;
        let fixed = state.store.cached_package_state(id).unwrap();
        assert_eq!(fixed.checks, before.checks + 1);
        assert_ne!(fixed.root, before.root);
        assert_eq!(
            state
                .package_refresh
                .take_advisories()
                .into_iter()
                .collect::<Vec<_>>(),
            ["debian"]
        );

        let retry = crate::model::now() + 3600;
        state.store.0.lock().unwrap().execute(
            "UPDATE advisory_sources SET payload=json_set(payload,'$.error','fixture source unavailable','$.nextCheck',?1) WHERE id='debian'",
            [retry],
        ).unwrap();
        assert_eq!(state.store.package_scope_source(&fixed).unwrap(), None);

        crate::vulnerabilities::process_pending(state.clone())
            .await
            .unwrap();
        assert_eq!(state.store.vulnerability_view(id, 0).unwrap().total, 1);
        state
            .package_refresh
            .reconcile_assessments(&state.store, Instant::now());
        assert!(state.package_refresh.due().is_empty());

        // Simulate the successful promotion of the local bulletin fixture for the new root.
        state.store.0.lock().unwrap().execute(
            "UPDATE advisory_sources SET payload=json_set(payload,'$.roots',json_array(?1),'$.error',NULL) WHERE id='debian'",
            [fixed.root.as_deref().unwrap()],
        ).unwrap();
        state
            .store
            .0
            .lock()
            .unwrap()
            .execute("INSERT INTO vulnerability_pending VALUES(?1)", [id])
            .unwrap();
        crate::vulnerabilities::process_pending(state.clone())
            .await
            .unwrap();
        assert_eq!(state.store.vulnerability_view(id, 0).unwrap().total, 0);
        let first_confirmation = &state.store.snapshot().unwrap().incidents[0];
        assert_eq!(first_confirmation.status, "open");
        assert_eq!(first_confirmation.healthy_streak, 1);
        state
            .store
            .evaluate_vulnerabilities(id, &state.root.join("advisories"))
            .unwrap();
        assert_eq!(
            state.store.snapshot().unwrap().incidents[0].healthy_streak,
            1
        );

        state
            .package_refresh
            .reconcile_assessments(&state.store, Instant::now());
        rescan().await;
        crate::vulnerabilities::process_pending(state.clone())
            .await
            .unwrap();
        assert_eq!(
            state.store.cached_package_state(id).unwrap().checks,
            before.checks + 2
        );
        assert_eq!(
            state.store.snapshot().unwrap().incidents[0].status,
            "resolved"
        );
        state
            .package_refresh
            .reconcile_assessments(&state.store, Instant::now());
        assert!(state.package_refresh.due().is_empty());
    }

    #[tokio::test]
    #[ignore = "requires disposable localhost SSH fixture"]
    async fn real_ssh_fleet_console() {
        let ssh_dir = std::env::var("CYBERBOT_TEST_SSH_DIR").unwrap();
        let port = std::env::var("CYBERBOT_TEST_SSH_PORT")
            .unwrap()
            .parse()
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("ssh_config");
        std::fs::write(&config, "").unwrap();
        let pool = ssh_pool::Pool::new(4, Duration::from_secs(60), Some(config)).unwrap();
        ssh_pool::install(pool.clone()).unwrap();
        let state = crate::create_state(temp.path().join("state")).unwrap();
        let good = import(&state.store, "good", port, Some(&ssh_dir));
        let bad = import(&state.store, "bad", 1, Some(&ssh_dir));
        let endpoints = [&good, &bad].map(|id| state.store.server_endpoint(id).unwrap());
        pool.retain(&endpoints);
        let run = |ids: Vec<String>, cmd: &str| {
            let ticket = state
                .fleet_console
                .prepare(&state.store, ids, cmd.into(), false)
                .unwrap()
                .ticket;
            let (plan, _, cancel) = state
                .fleet_console
                .start(&state.store, ticket, true)
                .unwrap();
            let job = tokio::spawn(run_batch(state.clone(), plan, cancel.clone()));
            (cancel, job)
        };
        let read = |id: &str| {
            let runtime = state.fleet_console.0.lock().unwrap();
            let result = runtime
                .latest
                .as_ref()
                .unwrap()
                .rows
                .iter()
                .find(|r| r.row.target.id == id)
                .unwrap();
            (result.row.clone(), result.output.clone())
        };

        let busy = state.collectors.try_background(&good, 1).unwrap().unwrap();
        let (_, job) = run(
            vec![good.clone(), bad.clone()],
            "printf '%s\\n' stdout; printf '%s\\n' stderr >&2",
        );
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(read(&good).0.status == Status::Queued);
        drop(busy);
        job.await.unwrap();
        let (row, output) = read(&good);
        assert!(row.status == Status::Ok);
        assert_eq!(output.stdout, "stdout\n");
        assert_eq!(output.stderr, "stderr\n");
        assert!(read(&bad).0.status == Status::Fail);

        let (_, job) = run(vec![good.clone()], "exit 13");
        job.await.unwrap();
        assert_eq!(read(&good).0.code, Some(13));

        let (_, job) = run(vec![good.clone()], "head -c 65536 /dev/zero | tr '\\000' x");
        job.await.unwrap();
        let (row, output) = read(&good);
        assert!(row.status == Status::Fail && output.truncated);
        assert_eq!(output.stdout.len(), STDOUT_LIMIT);

        let (cancel, job) = run(vec![good.clone()], "sleep 5");
        tokio::time::timeout(Duration::from_secs(8), async {
            while read(&good).0.status == Status::Queued {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), job)
            .await
            .unwrap()
            .unwrap();
        assert!(read(&good).0.reason.unwrap().contains("unknown"));

        let busy = state.collectors.try_background(&good, 1).unwrap().unwrap();
        let (_, job) = run(vec![good.clone()], "printf 'wrong endpoint'");
        {
            let db = state.store.0.lock().unwrap();
            db.execute(
                "UPDATE servers SET payload=json_set(payload,'$.endpoint.port',2) WHERE id=?1",
                [&good],
            )
            .unwrap();
        }
        drop(busy);
        job.await.unwrap();
        assert!(read(&good)
            .0
            .reason
            .unwrap()
            .contains("Connection has changed"));
        assert!(read(&good).1.stdout.is_empty());
        pool.shutdown();
    }
}
