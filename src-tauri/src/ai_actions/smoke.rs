//! Explicit disposable fixture driver; no arbitrary artifact or endpoint is accepted from CLI.
use super::*;
use crate::{agents, inventory, model::*, AppState};
use std::{
    path::PathBuf,
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};
const CODE: &str = "result = {'total': 5}";
const SHELL_CODE: &str =
    "umask 077; marker=$(mktemp /tmp/cyberbot-shell-fixture.XXXXXXXX) || exit 1; printf 'once\\n' > \"$marker\"; cat \"$marker\"; printf '%s\\n' \"$marker\"";
const UPGRADE_CODE: &str =
    "apt-get update && apt-get install -y --only-upgrade --no-remove python3.11";
pub(crate) async fn run(root: PathBuf, agent: Option<String>) -> Result<Value> {
    let shell = std::env::var("CYBERBOT_TEST_SHELL").as_deref() == Ok("1");
    let review_upgrade = std::env::var("CYBERBOT_TEST_REVIEW_UPGRADE").as_deref() == Ok("1");
    if review_upgrade && agent.is_none() {
        return Err("Reviewing the Update Policy requires an agent".into());
    }
    let dir = PathBuf::from(
        std::env::var("CYBERBOT_TEST_SSH_DIR").map_err(|_| "Requires disposable SSH fixture")?,
    )
    .canonicalize()
    .map_err(err)?;
    let temporary = std::env::temp_dir().canonicalize().map_err(err)?;
    if !dir.starts_with(&temporary) {
        return Err("The fixture key must be in the temporary directory".into());
    }
    let port: u16 = std::env::var("CYBERBOT_TEST_SSH_PORT")
        .map_err(|_| "No fixture port")?
        .parse()
        .map_err(err)?;
    if port < 1024 {
        return Err("Fixture port must be unprivileged".into());
    }
    let mut state = Arc::try_unwrap(crate::create_state(root)?)
        .map_err(|_| "Fixture State is already in use")?;
    let source = Source {
        id: "action-fixture".into(),
        name: "Disposable action fixture".into(),
        kind: "manual".into(),
        location: "root@127.0.0.1".into(),
        last_sync: None,
        error: None,
    };
    let mut hosts = inventory::parse_manual(&source.location)?;
    hosts[0].name = "disposable-action-node".into();
    hosts[0].endpoint.port = port;
    hosts[0].endpoint.identity_file = Some(dir.join("id_ed25519").to_string_lossy().into_owned());
    hosts[0].endpoint.known_hosts_file =
        Some(dir.join("known_hosts").to_string_lossy().into_owned());
    state.store.import(&source, hosts)?;
    state
        .store
        .0
        .lock()
        .map_err(err)?
        .execute("UPDATE notification_control SET enabled=0", [])
        .map_err(err)?;
    let server = state.store.snapshot()?.servers.remove(0);
    crate::ssh_pool::maintain_global(std::slice::from_ref(&server.endpoint));
    let mut config = state.store.ai_profiles()?;
    if let Some(provider) = &agent {
        let mut settings = state.store.settings()?;
        settings.auto_agent = provider.clone();
        state.store.save_settings(&settings)?;
        for (alias, name) in [
            ("medium", "CYBERBOT_TEST_PRIMARY_MODEL"),
            ("low", "CYBERBOT_TEST_LOW_MODEL"),
        ] {
            let model = std::env::var(name).map_err(|_| {
                format!("The test requires explicit {name}; manufacturing profiles do not change")
            })?;
            config
                .providers
                .get_mut(provider)
                .ok_or("Unknown provider")?
                .get_mut(alias)
                .unwrap()
                .model = model;
        }
        state.store.configure_ai_profiles(config)?;
    }
    crate::activity::install(&state.root, std::slice::from_ref(&server));
    let state = if agent.is_none() {
        let run = InvestigationFixture::make(&state, &server)?;
        state.store.admit(&run, None)?;
        state.investigator = agents::Investigator::restore(vec![run]);
        Arc::new(state)
    } else {
        Arc::new(state)
    };
    let started = Instant::now();
    let report = if let Some(provider) = agent {
        let question = if review_upgrade {
            format!("Disposable localhost test container. Call get_server, then request exec once for this exact script {UPGRADE_CODE:?} to update the installed Python package from configured Debian repositories. Wait for the desktop decision and report it. Do not request any other actions.")
        } else if shell {
            format!("Disposable localhost test container. Search /home recursively for ffmpeg using MCP grep and report the paths. Read get_server. Then request exec exactly once for the selected server, goal='Create one private marker in the disposable fixture', script={SHELL_CODE:?}. The marker is a disposable test artifact. Wait for desktop approval and the tool result. Report the code of exit and stdout. Do not call any other host action.")
        } else {
            format!("Disposable localhost fixture test. First call get_server. Then call request_script EXACTLY ONCE with serverId of selected server, goal='Fixture total', code={CODE:?}, inputs=[], action={{kind:'diagnostic'}}, rollbackPlan='No host changes'. Python is memory-only. Wait for the desktop decision and tool result without status polling. Do not use refresh_metrics or any other server action. Report the saved total, request ID and outcome in English. This test does not request any infrastructure modification.")
        };
        let delay = if shell || review_upgrade { 1 } else { 100 };
        let run_id = agents::start(
            state.clone(),
            vec![server.id.clone()],
            question,
            Arc::new(|_| ()),
        )?;
        let mut waiting = None;
        let mut answered = false;
        let mut before_approval_slots = None;
        loop {
            let run = state.investigator.get(&run_id)?;
            let cards = state.store.action_cards(Some(&run_id), None)?;
            if let Some(card) = cards.iter().find(|r| r.state == "awaitingApproval") {
                let since = *waiting.get_or_insert_with(Instant::now);
                before_approval_slots = Some(state.collectors.snapshot()?.running_count());
                if since.elapsed() >= Duration::from_secs(delay) && !answered {
                    let request = state.store.action_request(&card.id)?;
                    let expected = if review_upgrade {
                        (UPGRADE_CODE, Action::Shell)
                    } else if shell {
                        (SHELL_CODE, Action::Shell)
                    } else {
                        (CODE, Action::Diagnostic)
                    };
                    if request.artifact.spec.code != expected.0
                        || request.artifact.spec.inputs != Vec::<Input>::new()
                        || request.artifact.spec.action != expected.1
                        || request.server_id != server.id
                    {
                        return Err(
                            "Agent deviated from secure fixture; permission not issued".into()
                        );
                    }
                    state.store.action_decide(
                        &request.id,
                        &request.artifact_hash,
                        if review_upgrade { "deny" } else { "once" },
                        now(),
                    )?;
                    answered = true;
                }
            }
            if run.status != "running" {
                let requests = state.store.action_cards(Some(&run_id), None)?;
                let values = requests
                    .iter()
                    .map(|c| state.store.action_request(&c.id))
                    .collect::<Result<Vec<_>>>()?;
                break json!({"kind":"live-agent","provider":provider,"status":run.status,"error":run.error,"requestedProfile":run.model_profile,"confirmedModel":run.actual_model,"usage":run.usage,"usageComplete":run.usage_complete,"audit":run.audit,"requests":values,"approvedExactFixture":answered&&!review_upgrade,"declinedExactFixture":answered&&review_upgrade,"approvalDelaySeconds":delay,"sshSlotsDuringWait":before_approval_slots,"budget":state.store.auto_status(now())?});
            }
            if started.elapsed() > Duration::from_secs(400) {
                let _ = state.investigator.cancel(&run_id);
                return Err("Fixture: timeout".into());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    } else {
        let run = state.investigator.all()?.remove(0);
        let spec = if shell {
            check_remote_reads(state.clone(), &run).await?;
            Spec {
                server_id: server.id.clone(),
                goal: "Create a private marker in the disposable fixture".into(),
                code: SHELL_CODE.into(),
                inputs: vec![],
                action: Action::Shell,
                rollback_plan: String::new(),
            }
        } else {
            Spec {
                server_id: server.id.clone(),
                goal: "Model-free Nginx fixture".into(),
                code: "result={'workerProcesses':'2'}".into(),
                inputs: vec![],
                action: Action::NginxWorkers {
                    worker_processes: "2".into(),
                    activation: Activation::Reload,
                },
                rollback_plan: "Restore exact backup and reload default Nginx".into(),
            }
        };
        let frame = crate::ssh_authorization::frame(&run.scope_endpoints).await?;
        let transport = frame.targets.get(&server.id).ok_or("No fixture context")?;
        let mut request = state
            .store
            .action_propose(&run, spec, json!([]), transport.clone(), frame.hash, now())?
            .0;
        let prepared = runtime::fixture_remote(state.clone(), &request, "prepare").await?;
        if state.polls.forced(&server.id) {
            return Err("Preparation or Reading Launched Package Verification".into());
        }
        if prepared.get("error").is_some() {
            return Err(format!("Fixture prepare: {prepared}"));
        }
        request = state.store.action_freeze(
            &request.id,
            prepared["prepared"].clone(),
            prepared["isolation"].clone(),
            now(),
        )?;
        request = state.store.action_reviewed(
            &request.id,
            Review {
                id: uuid::Uuid::new_v4().to_string(),
                verdict: Verdict {
                    decision: Decision::Allow,
                    explanation: "Model-free fixture, no model invoked".into(),
                    effects: vec!["Bounded Nginx worker scalar".into()],
                },
                model: Some("model-free-fixture".into()),
                usage: json!({"totalTokens":0}),
                usage_complete: true,
                tokens: 0,
                duration_ms: 0,
            },
            now(),
        )?;
        // Exercise approval after the key directory gains an unrelated file.
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(format!("unrelated-{}", request.id)))
            .map_err(err)?;
        // Optional measurement window for the fixed model-free fixture only.
        let wait_seconds = std::env::var("CYBERBOT_TEST_APPROVAL_WAIT_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
            .min(30);
        tokio::time::sleep(Duration::from_secs(wait_seconds)).await;
        if state.collectors.snapshot()?.running_count() != 0 {
            return Err("Approval holds SSH slot".into());
        }
        request = state
            .store
            .action_decide(&request.id, &request.artifact_hash, "once", now())?;
        runtime::queue_approved(&state.store, &request, &Default::default()).await?;
        request = state
            .store
            .action_transition(&request.id, "queued", "running", now())?;
        let response = runtime::fixture_remote(state.clone(), &request, "execute").await?;
        if state.polls.forced(&server.id) != shell {
            return Err(
                "Unscheduled check of packages does not correspond to the action performed".into(),
            );
        }
        if response["state"] != "succeeded" {
            return Err(format!("Fixture execution: {response}"));
        }
        let request = state.store.action_result(
            &request.id,
            "succeeded",
            Some(response.clone()),
            None,
            now(),
        )?;
        let duplicate = runtime::fixture_remote(state.clone(), &request, "execute").await?;
        if duplicate != response {
            return Err("Repeat created a new result".into());
        }
        let rollback = if shell {
            if !response["result"]["stdout"]
                .as_str()
                .is_some_and(|stdout| stdout.starts_with("once\n/tmp/cyberbot-shell-fixture."))
                || response["result"]["exitCode"] != 0
            {
                return Err("Shell fixture did not confirm one successful run".into());
            }
            None
        } else {
            let restored =
                runtime::rollback(state.clone(), &request.id, &request.artifact_hash).await?;
            if restored.state != "rolledBack" {
                return Err(format!("Retracement not confirmed: {}", restored.state));
            }
            restored.result
        };
        let mut run = run;
        run.status = "completed".into();
        run.usage_complete = true;
        run.usage = json!({"totalTokens":0});
        state.store.settle(&run)?;
        json!({"kind":"model-free","status":"completed","applied":response,"rollback":rollback,"budget":state.store.auto_status(now())?})
    };
    state.stop.store(true, Ordering::SeqCst);
    crate::ssh_pool::shutdown_global();
    let mut report = report;
    report["applicationTraffic"] = state.actions.traffic();
    report["durationMs"] = json!(started.elapsed().as_millis());
    Ok(report)
}

async fn check_remote_reads(state: Arc<AppState>, run: &Investigation) -> Result<()> {
    let mcp = crate::mcp::McpServer::start_run(state, run).await?;
    let id = &run.server_ids[0];
    for (path, pattern, expected, complete) in [
        (
            "/home/cyberbot-fixture",
            "ffmpeg",
            json!(["/home/cyberbot-fixture/convert.sh"]),
            false,
        ),
        (
            "/home/cyberbot-fixture/convert.sh",
            "no-such-pattern",
            json!([]),
            true,
        ),
    ] {
        let read = crate::mcp::call(
            &mcp.scope,
            "grep",
            json!({"serverId":id,"path":path,"pattern":pattern}),
        )
        .await?;
        if read["paths"] != expected || read["complete"] != complete {
            return Err(format!("Wrong answer grep: {read}"));
        }
    }
    for (tool, args) in [
        (
            "cat",
            json!({"serverId":id,"path":"/home/cyberbot-fixture/not-found"}),
        ),
        (
            "sed",
            json!({"serverId":id,"path":"/home/cyberbot-fixture/convert.sh","script":"-i"}),
        ),
    ] {
        if crate::mcp::call(&mcp.scope, tool, args).await.is_ok() {
            return Err(format!("{tool} permitted inaccessible action"));
        }
    }
    Ok(())
}
struct InvestigationFixture;

/// Native UI fixture only: fictional endpoint, no MCP runtime or remote task.
pub(crate) fn approval_fixture(state: &AppState) -> Result<Request> {
    let server = state.store.snapshot()?.servers.remove(0);
    if server.endpoint.host != "notification.invalid" || !state.store.settings()?.paused {
        return Err("Isolated notification fixture is required".into());
    }
    let run = InvestigationFixture::make(state, &server)?;
    state.store.admit(&run, None)?;
    let request = state
        .store
        .action_propose(
            &run,
            Spec {
                server_id: server.id,
                goal: "Verification of authorization card".into(),
                code: CODE.into(),
                inputs: vec![],
                action: Action::Diagnostic,
                rollback_plan: "Interface test without execution".into(),
            },
            json!([]),
            crate::ssh_authorization::Stamp::new(
                vec![],
                "notification-fixture".into(),
                Default::default(),
            ),
            "notification-fixture".into(),
            now(),
        )?
        .0;
    let request = state.store.action_freeze(&request.id, json!({"kind":"diagnostic","writes":[]}), json!({"available":true,"engine":"python-seccomp-v1","rules":RULES,"files":false,"network":false,"processes":false,"wallSeconds":8,"cpuSeconds":4,"outputBytes":16384,"memoryBytes":100663296}), now())?;
    state.store.action_reviewed(
        &request.id,
        Review {
            id: uuid::Uuid::new_v4().to_string(),
            verdict: Verdict {
                decision: Decision::Allow,
                explanation: "Notification test: model and execution are not started".into(),
                effects: vec![],
            },
            model: Some("model-free-ui-fixture".into()),
            usage: json!({"totalTokens":0}),
            usage_complete: true,
            tokens: 0,
            duration_ms: 0,
        },
        now(),
    )
}

impl InvestigationFixture {
    fn make(state: &AppState, server: &Server) -> Result<agents::Investigation> {
        Ok(agents::Investigation {
            usage_started: false,
            scope_endpoints: [(
                server.id.clone(),
                serde_json::to_string(&server.endpoint).map_err(err)?,
            )]
            .into(),
            group_id: None,
            authoring_id: None,
            origin: "manual".into(),
            usage_complete: false,
            id: uuid::Uuid::new_v4().to_string(),
            agent: "codex".into(),
            server_ids: vec![server.id.clone()],
            question: "Model-free disposable action fixture".into(),
            status: "running".into(),
            started_at: now(),
            ended_at: None,
            text: String::new(),
            error: None,
            usage: json!({}),
            audit: vec![],
            chat: None,
            session_id: None,
            model_profile: Some(state.store.ai_selection("codex", "medium")?),
            actual_model: None,
        })
    }
}
