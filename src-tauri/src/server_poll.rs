use crate::{
    collector_queue, connectivity, first_check, instances, logs,
    model::{now, Endpoint, Server},
    monitoring::{self, thresholds, Book, Execution, Policy},
    nginx, packages, postgresql, services, ssh, AppState,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    sync::{atomic::Ordering, Arc, Mutex},
    time::{Duration, Instant},
};
use tauri::Emitter;
use tokio::sync::{watch, Notify};

type Result<T> = std::result::Result<T, String>;
type Completion = Option<Result<Report>>;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Report {
    updated: usize,
    failed: Vec<String>,
}

#[derive(Default)]
pub(crate) struct Queue {
    entries: Mutex<HashMap<String, EntryState>>,
    pub(crate) wake: Notify,
}

struct EntryState {
    endpoint: Endpoint,
    first: Instant,
    started: Option<Instant>,
    forced: bool,
    rotate_to: Option<(String, String)>,
    running: Option<watch::Sender<Completion>>,
}

impl EntryState {
    fn new(server: &Server, at: Instant) -> Self {
        let spread = server.id.bytes().fold(0_u64, |hash, byte| {
            hash.wrapping_mul(31).wrapping_add(u64::from(byte))
        }) % 31;
        Self {
            endpoint: server.endpoint.clone(),
            first: at + Duration::from_secs(spread),
            started: None,
            forced: false,
            rotate_to: None,
            running: None,
        }
    }

    fn next(&self, interval: Duration, at: Instant) -> Instant {
        if self.forced {
            return at;
        }
        self.started
            .map_or(self.first, |started| started + interval)
    }
}

impl Queue {
    pub(crate) fn forced(&self, id: &str) -> bool {
        self.entries
            .lock()
            .is_ok_and(|entries| entries.get(id).is_some_and(|entry| entry.forced))
    }

    pub(crate) fn reset(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            for (id, entry) in entries.iter_mut() {
                let spread = id.bytes().fold(0_u64, |hash, byte| {
                    hash.wrapping_mul(31).wrapping_add(u64::from(byte))
                }) % 31;
                entry.first = Instant::now() + Duration::from_secs(spread);
                entry.started = None;
            }
        }
        self.wake.notify_one();
    }

    pub(crate) fn force(&self, server: &Server) {
        if let Ok(mut entries) = self.entries.lock() {
            let entry = entry_for(&mut entries, server, Instant::now());
            entry.forced = true;
            self.wake.notify_one();
        }
    }

    pub(crate) fn due<'a>(
        &self,
        servers: &'a [Server],
        active: &collector_queue::Activity,
        interval: Duration,
        at: Instant,
    ) -> (Vec<&'a Server>, Option<Instant>) {
        let Ok(mut entries) = self.entries.lock() else {
            return (Vec::new(), None);
        };
        let ids: HashSet<_> = servers.iter().map(|server| server.id.as_str()).collect();
        entries.retain(|id, _| ids.contains(id.as_str()));
        let mut ready = Vec::new();
        let mut next = None;
        for server in servers {
            let entry = entry_for(&mut entries, server, at);
            if entry.running.is_some() || active.occupied(&server.id) {
                continue;
            }
            let due = entry.next(interval, at);
            if due <= at {
                ready.push((due, server));
            } else {
                next = Some(next.map_or(due, |old: Instant| old.min(due)));
            }
        }
        ready.sort_by(|(a, x), (b, y)| (a, &x.id).cmp(&(b, &y.id)));
        (ready.into_iter().map(|(_, server)| server).collect(), next)
    }

    pub(crate) fn start(
        &self,
        app: Arc<AppState>,
        server: Server,
        manual: bool,
    ) -> Result<watch::Receiver<Completion>> {
        let mut entries = self.entries.lock().map_err(err)?;
        let entry = entry_for(&mut entries, &server, Instant::now());
        if let Some(running) = &entry.running {
            return Ok(running.subscribe());
        }
        let (done, receiver) = watch::channel(None);
        entry.running = Some(done.clone());
        drop(entries);
        tokio::spawn(async move {
            let job = Job {
                app: app.clone(),
                server: &server,
                done,
            };
            let result = execute(&app, &server, manual).await;
            let done = job.done.clone();
            drop(job);
            done.send_replace(Some(result));
            if let Some(handle) = app.app.get() {
                let _ = handle.emit("state-changed", ());
            }
        });
        Ok(receiver)
    }
}

fn entry_for<'a>(
    entries: &'a mut HashMap<String, EntryState>,
    server: &Server,
    at: Instant,
) -> &'a mut EntryState {
    match entries.entry(server.id.clone()) {
        Entry::Occupied(mut occupied) => {
            if occupied.get().endpoint != server.endpoint {
                occupied.insert(EntryState::new(server, at));
            }
            occupied.into_mut()
        }
        Entry::Vacant(vacant) => vacant.insert(EntryState::new(server, at)),
    }
}

struct Job<'a> {
    app: Arc<AppState>,
    server: &'a Server,
    done: watch::Sender<Completion>,
}

impl Drop for Job<'_> {
    fn drop(&mut self) {
        if let Ok(mut entries) = self.app.polls.entries.lock() {
            if let Some(entry) = entries.get_mut(&self.server.id) {
                if entry
                    .running
                    .as_ref()
                    .is_some_and(|current| current.same_channel(&self.done))
                {
                    entry.running = None;
                }
            }
        }
        self.app.polls.wake.notify_one();
    }
}

pub(crate) async fn refresh(app: Arc<AppState>, id: String) -> Result<Report> {
    let server = app.store.server(&id)?;
    let mut job = app.polls.start(app.clone(), server, true)?;
    let report = job.wait_for(Option::is_some).await.map_err(err)?.clone();
    report.ok_or_else(|| "Server polling ended unexpectedly".to_owned())?
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

enum Check {
    Metrics,
    Logs(logs::LogState),
    Packages {
        checkpoint: packages::State,
        apt: Vec<String>,
    },
    Nginx(nginx::Checkpoint),
    Postgres(postgresql::Checkpoint),
    Service(services::Checkpoint),
}

struct Task {
    execution: Execution,
    request: Value,
    check: Check,
    updated: bool,
    terminal: bool,
    error: bool,
}

impl Task {
    fn new(
        server: &Server,
        policy: Policy,
        trigger: &str,
        check: Check,
        request: Value,
    ) -> Result<Self> {
        let kind = policy_kind(&request)?;
        let instance = request["state"]["instanceId"].as_str().map(str::to_owned);
        Ok(Self {
            execution: Execution {
                definition_id: kind.into(),
                version: monitoring::definition(kind)?.version.clone(),
                trigger: trigger.into(),
                instance_id: instance,
                server_id: Some(server.id.clone()),
                revision: policy.revision,
            },
            request,
            check,
            updated: false,
            terminal: false,
            error: false,
        })
    }

    fn name(&self) -> String {
        match self.execution.instance_id.as_deref() {
            Some(instance) if instance != instances::DEFAULT => {
                format!("{} ({instance})", self.execution.definition_id)
            }
            _ => self.execution.definition_id.clone(),
        }
    }

    fn identity(&self) -> (String, String) {
        (
            self.execution.definition_id.clone(),
            self.execution.instance_id.clone().unwrap_or_default(),
        )
    }

    fn record(
        &mut self,
        app: &AppState,
        server: &Server,
        attempt: &first_check::Attempt,
        started: Instant,
        payload: &Value,
    ) -> Result<()> {
        if self.updated && !matches!(self.check, Check::Packages { .. }) {
            return Err("Duplicate collector result".into());
        }
        let bytes = serde_json::to_vec(payload).map_err(err)?;
        if bytes.len() > 32768 {
            return Err("Collector result exceeds the size limit".into());
        }
        let store = &app.store;
        let at = now();
        let kind = &self.execution.definition_id;
        let instance = self
            .execution
            .instance_id
            .as_deref()
            .unwrap_or(instances::DEFAULT);
        monitoring::with_execution(self.execution.clone(), || {
            store.check_poll_attempt(attempt, server)?;
            match &mut self.check {
                Check::Metrics => {
                    let observation = ssh::decode_metrics(&bytes, started)?;
                    store.record_network_metrics(attempt, server, Ok(observation), None)?;
                }
                Check::Logs(checkpoint) => {
                    store.record_logs(server, checkpoint, &bytes, at)?;
                }
                Check::Packages { checkpoint, .. } => {
                    let previous = checkpoint.root.clone();
                    *checkpoint = store.record_packages(server, checkpoint, &bytes, at)?;
                    if checkpoint.stage.is_none() && checkpoint.root != previous {
                        if let Ok(Some(source)) = store.package_scope_source(checkpoint) {
                            app.advisory_priority.prioritize_advisory(source);
                        }
                    }
                }
                Check::Nginx(checkpoint) => {
                    let details = ssh::decode_service_sample(kind, instance, &bytes)?;
                    store.record_nginx(server, checkpoint, &details, at)?;
                }
                Check::Postgres(checkpoint) => {
                    let details = ssh::decode_service_sample(kind, instance, &bytes)?;
                    store.record_postgresql(server, checkpoint, &details, at)?;
                }
                Check::Service(checkpoint) => {
                    let details = ssh::decode_service_sample(kind, instance, &bytes)?;
                    store.record_service(server, kind, checkpoint, &details, at)?;
                }
            }
            Ok::<(), String>(())
        })?;
        self.updated = true;
        Ok(())
    }

    fn record_error(
        &self,
        app: &AppState,
        server: &Server,
        attempt: &first_check::Attempt,
        reason: &str,
        verdict: Option<connectivity::Ticket>,
    ) {
        let store = &app.store;
        let _ = monitoring::with_execution(self.execution.clone(), || {
            store.check_poll_attempt(attempt, server)?;
            match &self.check {
                Check::Metrics if self.updated => Ok(()),
                Check::Metrics => {
                    store.record_network_metrics(attempt, server, Err(reason.into()), verdict)
                }
                Check::Logs(checkpoint) => store.log_error(server, checkpoint),
                Check::Packages { checkpoint, .. } => store.package_error(&server.id, checkpoint),
                Check::Nginx(checkpoint) => store.nginx_error(&server.id, checkpoint),
                Check::Postgres(checkpoint) => store.postgresql_error(&server.id, checkpoint),
                Check::Service(checkpoint) => {
                    store.service_error(&server.id, &self.execution.definition_id, checkpoint)
                }
            }
        });
    }
}

fn policy_kind(request: &Value) -> Result<&str> {
    let field = if request["kind"] == "service" {
        &request["state"]["kind"]
    } else {
        &request["kind"]
    };
    field
        .as_str()
        .ok_or_else(|| "Missing collector operation".into())
}

fn prepare(
    app: &AppState,
    server: &Server,
    book: &Book,
    trigger: &str,
    rotate_to: Option<(String, String)>,
) -> Result<Vec<Task>> {
    let store = &app.store;
    let id = &server.id;
    let mut tasks = Vec::new();
    for kind in ["metrics", "logs", "packages"] {
        let policy = book.resolve(&monitoring::scope(kind, Some(id), None))?;
        if !policy.values.enabled {
            continue;
        }
        let (check, request) = match kind {
            "metrics" => (Check::Metrics, json!({"kind":"metrics"})),
            "logs" => {
                let checkpoint = store.log_state(id)?;
                let request = checkpoint.request(&policy.values);
                (Check::Logs(checkpoint), request)
            }
            _ => {
                let checkpoint = store.package_state(id)?;
                let apt = if checkpoint.stage.is_none() && book.enabled("apt", id, "") {
                    store.apt_targets(id)?
                } else {
                    Vec::new()
                };
                let request = store.package_poll_request(id, &checkpoint, &apt)?;
                (Check::Packages { checkpoint, apt }, request)
            }
        };
        tasks.push(Task::new(server, policy, trigger, check, request)?);
    }
    let mut service_tasks = Vec::new();
    for instance in store.service_instances(id)? {
        let kind = instance.kind.as_str();
        let instance_id = instance.id.as_str();
        let policy = book.resolve(&monitoring::scope(kind, Some(id), Some(instance_id)))?;
        if !policy.values.enabled {
            continue;
        }
        let (check, config, cursor) = match kind {
            "nginx" => {
                let checkpoint = store.nginx_state(id)?;
                let cursor = checkpoint.poll_checkpoint();
                (Check::Nginx(checkpoint), Value::Null, cursor)
            }
            "postgresql" => {
                let checkpoint = store.postgresql_state_for(id, instance_id)?;
                let config = json!(checkpoint.config);
                (Check::Postgres(checkpoint), config, Value::Null)
            }
            _ => {
                let checkpoint = store.service_state_for(id, kind, instance_id)?;
                let config = json!(checkpoint.config);
                (Check::Service(checkpoint), config, Value::Null)
            }
        };
        let request = ssh::service_request(
            kind,
            instance_id,
            config,
            cursor,
            thresholds::collector_values(kind, &policy.values.thresholds),
        );
        service_tasks.push(Task::new(server, policy, trigger, check, request)?);
    }
    if let Some(index) = rotate_to.and_then(|identity| {
        service_tasks
            .iter()
            .position(|task| task.identity() == identity)
    }) {
        service_tasks.rotate_left(index);
    }
    tasks.extend(service_tasks);
    Ok(tasks)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    id: usize,
    event: Event,
    payload: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Event {
    Data,
    Apt,
    AptError,
    Done,
    Error,
    Deferred,
}

async fn execute(app: &AppState, server: &Server, manual: bool) -> Result<Report> {
    let settings = app.store.settings()?;
    let _slot = if manual {
        app.collectors.manual(&server.id).await?
    } else {
        if settings.paused {
            return Err("Monitoring paused".into());
        }
        app.collectors
            .try_background(&server.id, settings.concurrency)?
            .ok_or(collector_queue::BUSY)?
    };
    if app.stop.load(Ordering::Relaxed) {
        return Err("Monitoring stopped".into());
    }
    crate::storage::admit(&*app.store.0.lock().map_err(err)?)?;
    let started = Instant::now();
    let (forced, rotate_to) = {
        let mut entries = app.polls.entries.lock().map_err(err)?;
        let entry = entries
            .get_mut(&server.id)
            .filter(|entry| entry.endpoint == server.endpoint)
            .ok_or("Connection has changed")?;
        entry.started = Some(started);
        (std::mem::take(&mut entry.forced), entry.rotate_to.take())
    };
    let attempt = app.store.begin_metrics_check(server)?;
    let book = app.store.monitoring_book()?;
    let trigger = if manual {
        "manual"
    } else if forced {
        "after_action"
    } else {
        "schedule"
    };
    let mut tasks = prepare(app, server, &book, trigger, rotate_to)?;
    if tasks.is_empty() {
        return Err("All monitoring checks are disabled for this server".into());
    }
    let request = serde_json::to_vec(&json!({
        "version": 1,
        "tasks": tasks.iter().map(|task| &task.request).collect::<Vec<_>>(),
    }))
    .map_err(err)?;
    let network = app.store.connectivity();
    let ticket = network.ticket();
    let mut first_deferred = None;
    let mut apt_result = None;
    let mut had_frame = false;
    let mut span = crate::activity::begin("server", "poll", Some(server.id.clone()));
    let transport = connectivity::observe_ssh(network.clone(), ticket, ssh::poll_server(
        &server.endpoint,
        &app.collector,
        &request,
        &mut |line| {
            let frame: Frame = serde_json::from_slice(line).map_err(err)?;
            let task = tasks.get_mut(frame.id).filter(|task| !task.terminal)
                .ok_or("Unexpected collector result")?;
            had_frame = true;
            match frame.event {
                Event::Data if !task.error => {
                    if task.record(app, server, &attempt, started, &frame.payload).is_err() {
                        task.error = true;
                    } else if matches!(task.check, Check::Metrics) {
                        if let Some(handle) = app.app.get() {
                            let _ = handle.emit("state-changed", ());
                        }
                    }
                }
                Event::Data => (),
                Event::Apt | Event::AptError => {
                    let Check::Packages { checkpoint, apt } = &task.check else {
                        return Err("Unexpected APT result".into());
                    };
                    if apt.is_empty() || apt_result.is_some() {
                        return Err("Unexpected APT result".into());
                    }
                    if !task.error {
                        let policy = book.resolve(&monitoring::scope("apt", Some(&server.id), None))?;
                        let execution = Execution {
                            definition_id: "apt".into(),
                            version: monitoring::definition("apt")?.version.clone(),
                            revision: policy.revision,
                            instance_id: None,
                            ..task.execution.clone()
                        };
                        let bytes = serde_json::to_vec(&frame.payload).map_err(err)?;
                        let stored = monitoring::with_execution(execution.clone(), || {
                            app.store.check_poll_attempt(&attempt, server)?;
                            if matches!(frame.event, Event::Apt) {
                                if let Err(error) = app.store.record_apt(server, checkpoint, apt, &bytes) {
                                    let _ = app.store.record_apt_error(server, checkpoint);
                                    return Err(error);
                                }
                            } else {
                                app.store.record_apt_error(server, checkpoint)?;
                            }
                            Ok::<(), String>(())
                        });
                        let success = stored.is_ok() && matches!(frame.event, Event::Apt);
                        apt_result = Some(success);
                        monitoring::with_execution(execution, || crate::activity::poll_result(&server.id, success));
                    }
                }
                Event::Done => {
                    task.terminal = true;
                    task.error |= !task.updated || matches!(&task.check, Check::Packages { checkpoint, .. } if checkpoint.stage.is_some());
                }
                Event::Error | Event::Deferred => {
                    task.terminal = true;
                    task.error = true;
                    if matches!(frame.event, Event::Deferred) && task.execution.instance_id.is_some() {
                        first_deferred.get_or_insert_with(|| task.identity());
                    }
                }
            }
            Ok(())
        },
    )).await;
    span.result(&transport);
    let verdict = if transport.is_err() && !had_frame {
        network.confirm_failure(ticket).await
    } else {
        None
    };
    let reason = transport
        .as_ref()
        .err()
        .map(String::as_str)
        .unwrap_or("A server check did not complete");
    let mut report = Report {
        updated: 0,
        failed: Vec::new(),
    };
    for task in &tasks {
        let complete = task.updated
            && !matches!(&task.check, Check::Packages { checkpoint, .. } if checkpoint.stage.is_some());
        let success = complete && !task.error;
        monitoring::with_execution(task.execution.clone(), || {
            crate::activity::poll_result(&server.id, success);
        });
        if success {
            report.updated += 1;
        } else {
            task.record_error(app, server, &attempt, reason, verdict);
            report.failed.push(task.name());
        }
    }
    match apt_result {
        Some(true) => report.updated += 1,
        Some(false) => report.failed.push("apt".into()),
        None => (),
    }
    if let Some(entry) = app.polls.entries.lock().map_err(err)?.get_mut(&server.id) {
        if entry.endpoint == server.endpoint && entry.started == Some(started) {
            entry.rotate_to = first_deferred;
        }
    }
    if !had_frame {
        transport?;
        return Err("The collector returned no results".into());
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{activity, inventory, model::Source, ssh_pool};

    fn fixture(app: &AppState, count: usize) -> Vec<Server> {
        let source = Source {
            id: "poll-fixture".into(),
            name: "Poll fixture".into(),
            kind: "manual".into(),
            location: (0..count)
                .map(|index| format!("ops@node-{index}.invalid"))
                .collect::<Vec<_>>()
                .join("\n"),
            last_sync: None,
            error: None,
        };
        app.store
            .import(&source, inventory::parse_manual(&source.location).unwrap())
            .unwrap();
        app.store.poll_targets().unwrap().0
    }

    #[test]
    fn dispatches_200_servers_without_idle_slots_or_duplicate_cycles() {
        let temp = tempfile::tempdir().unwrap();
        let app = crate::create_state(temp.path().to_owned()).unwrap();
        let servers = fixture(&app, 200);
        let at = Instant::now();
        let interval = Duration::from_secs(180);
        let slots = 24;
        let (first, next) =
            app.polls
                .due(&servers, &app.collectors.snapshot().unwrap(), interval, at);
        assert!(first.len() < slots);
        assert!(next.is_some_and(|deadline| deadline <= at + Duration::from_secs(30)));
        let mut dispatched = HashSet::new();
        let mut longest_wait = Duration::ZERO;
        let mut waiting = Vec::new();
        for elapsed in 0..60 {
            let current = at + Duration::from_secs(elapsed);
            waiting.retain(|(released, _)| *released > current);
            let active = app.collectors.snapshot().unwrap();
            let (ready, _) = app.polls.due(&servers, &active, interval, current);
            let free = slots - active.background_count();
            let expected = ready.len().min(free);
            for server in ready.into_iter().take(free) {
                let guard = app
                    .collectors
                    .try_background(&server.id, slots)
                    .unwrap()
                    .unwrap();
                assert!(dispatched.insert(server.id.clone()));
                let mut entries = app.polls.entries.lock().unwrap();
                let entry = entries.get_mut(&server.id).unwrap();
                longest_wait = longest_wait.max(current - entry.first);
                entry.started = Some(current);
                waiting.push((current + Duration::from_secs(2), guard));
            }
            assert_eq!(
                app.collectors.snapshot().unwrap().background_count(),
                active.background_count() + expected
            );
        }
        assert_eq!(dispatched.len(), 200);
        assert!(longest_wait <= Duration::from_secs(2), "{longest_wait:?}");
        println!("200 hosts, 24 slots, simulated 2 s checks: max start delay {longest_wait:?}");
    }

    #[tokio::test]
    #[ignore = "requires disposable localhost SSH fixture"]
    async fn real_ssh_server_poll_uses_one_command_and_shares_manual_requests() {
        let folder = std::env::var("CYBERBOT_TEST_SSH_DIR").unwrap();
        let port = std::env::var("CYBERBOT_TEST_SSH_PORT")
            .unwrap()
            .parse()
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("ssh_config");
        std::fs::write(&config, "").unwrap();
        let pool = ssh_pool::Pool::new(4, Duration::from_secs(60), Some(config)).unwrap();
        ssh_pool::install(pool.clone()).unwrap();
        let app = crate::create_state(temp.path().join("state")).unwrap();
        let source = Source {
            id: "ssh-poll".into(),
            name: "Fixture".into(),
            kind: "manual".into(),
            location: String::new(),
            last_sync: None,
            error: None,
        };
        app.store
            .import(
                &source,
                vec![inventory::Imported {
                    identity: "poll-fixture".into(),
                    name: "Poll fixture".into(),
                    endpoint: Endpoint {
                        host: "127.0.0.1".into(),
                        user: "ops".into(),
                        port,
                        identity_file: Some(format!("{folder}/id_ed25519")),
                        known_hosts_file: Some(format!("{folder}/known_hosts")),
                        jump_host: None,
                    },
                }],
            )
            .unwrap();
        let servers = app.store.poll_targets().unwrap().0;
        let server = &servers[0];
        activity::install(&app.root, &servers);
        pool.retain(std::slice::from_ref(&server.endpoint));

        let first = refresh(app.clone(), server.id.clone()).await.unwrap();
        assert!(first.failed.is_empty(), "{first:?}");
        let inventory = app.store.cached_package_state(&server.id).unwrap();
        assert!(inventory.root.is_some());
        assert!(app.store.server(&server.id).unwrap().observation.is_some());
        let log_at = app.store.log_state(&server.id).unwrap().last_success;
        assert!(log_at.is_some());
        let commands = |action: &str| {
            activity::page(activity::Query {
                phase: Some("completed".into()),
                search: Some(action.into()),
                ..Default::default()
            })
            .unwrap()
            .events
            .into_iter()
            .filter(|e| e.action == action)
            .count()
        };
        let before = commands("Collect server");
        let version_checks = commands("Check collector version");
        assert_eq!(before, 1);
        assert_eq!(
            version_checks, 1,
            "the first poll must deploy and verify the collector"
        );

        let scope = monitoring::scope("logs", Some(&server.id), None);
        let policy = app.store.monitoring_policy(&scope).unwrap();
        app.store
            .set_monitoring(
                &scope,
                monitoring::Overrides {
                    enabled: Some(false),
                    ..Default::default()
                },
                policy.revision,
            )
            .unwrap();
        let (one, two) = tokio::join!(
            refresh(app.clone(), server.id.clone()),
            refresh(app.clone(), server.id.clone())
        );
        let one = one.unwrap();
        let two = two.unwrap();
        assert!(one.failed.is_empty(), "{one:?}");
        assert_eq!(one.updated + 1, first.updated);
        assert_eq!(one.updated, two.updated);
        assert_eq!(commands("Collect server"), before + 1);
        assert_eq!(commands("Check collector version"), version_checks);
        assert_eq!(pool.stats().opened, 1);
        assert_eq!(
            app.store.cached_package_state(&server.id).unwrap().checks,
            inventory.checks + 1
        );
        assert!(app
            .store
            .log_state(&server.id)
            .unwrap()
            .last_success
            .is_none());
        assert!(app.store.apt_targets(&server.id).unwrap().is_empty());

        // Start a full transfer, persist its manifest, and cut the SSH stream
        // before the first page can be committed.
        {
            let mut db = app.store.0.lock().unwrap();
            let tx = db.transaction().unwrap();
            for sql in [
                "DELETE FROM package_buckets WHERE server_id=?1",
                "DELETE FROM package_state WHERE server_id=?1",
            ] {
                tx.execute(sql, [&server.id]).unwrap();
            }
            tx.commit().unwrap();
        }
        let mut checkpoint = app.store.package_state(&server.id).unwrap();
        let request = app
            .store
            .package_poll_request(&server.id, &checkpoint, &[])
            .unwrap();
        let bytes = serde_json::to_vec(&json!({"version":1,"tasks":[request]})).unwrap();
        let interrupted = ssh::poll_server(&server.endpoint, &app.collector, &bytes, &mut |line| {
            let frame: Frame = serde_json::from_slice(line).map_err(err)?;
            if frame.payload["kind"] != "manifest" {
                return Err("Simulated client disconnect".into());
            }
            let data = serde_json::to_vec(&frame.payload).map_err(err)?;
            checkpoint = app
                .store
                .record_packages(server, &checkpoint, &data, now())?;
            Ok(())
        })
        .await;
        assert_eq!(interrupted.unwrap_err(), "Simulated client disconnect");
        assert!(checkpoint.stage.is_some());
        assert!(!checkpoint.pending.is_empty());
        assert!(refresh(app.clone(), server.id.clone())
            .await
            .unwrap()
            .failed
            .is_empty());
        let resumed = app.store.cached_package_state(&server.id).unwrap();
        assert!(resumed.stage.is_none());
        assert_eq!(resumed.root, inventory.root);
        ssh_pool::shutdown_global();
    }
}
