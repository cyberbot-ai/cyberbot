include!(concat!(env!("OUT_DIR"), "/service_modules.rs"));
use rusqlite::OptionalExtension;
mod activity;
mod advisories;
mod agents;
mod ai_actions;
mod ai_models;
mod auth;
mod automation;
mod check_engine;
mod check_runtime;
mod checks;
mod collector_queue;
mod collector_schedule;
mod connectivity;
mod console;
mod correlation;
mod debversion;
pub mod egress;
mod first_check;
mod fleet_console;
mod incidents;
mod instances;
pub mod inventory;
pub mod isolation;
mod local_resources;
mod logs;
mod mcp;
pub mod model;
mod monitoring;
mod notifications;
mod oval;
mod package_refresh;
mod packages;
mod platform;
mod power;
mod process;
mod service_migration;
mod services;
pub mod ssh;
mod ssh_authorization;
pub mod ssh_pool;
mod startup_monitoring;
mod storage;
pub mod store;
mod vulnerabilities;
mod vulnerability_catalog;
mod web_evidence;
mod window_size;

use model::*;
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, OnceLock,
    },
    time::{Duration, Instant},
};
use store::Store;
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Emitter, Manager, State,
};

struct AppState {
    app: OnceLock<tauri::AppHandle>,
    root: PathBuf,
    _instance: InstanceLock,
    investigator: agents::Investigator,
    store: Store,
    collector: PathBuf,
    collectors: collector_queue::Queue,
    package_refresh: package_refresh::Queue,
    fleet_console: fleet_console::Console,
    consoles: console::Sessions,
    stop: AtomicBool,
    advisory_refresh: tokio::sync::Mutex<()>,
    wake_reset: AtomicBool,
    startup_cancel: tokio_util::sync::CancellationToken,
    check_runtime: check_runtime::Runtime,
    actions: ai_actions::Runtime,
}

impl AppState {
    fn package_refresh_after_command(&self, id: &str, endpoint: &Endpoint) {
        if self
            .store
            .server_endpoint(id)
            .as_ref()
            .is_ok_and(|current| current == endpoint)
        {
            self.package_refresh.command_finished(id, endpoint);
        }
    }
}

#[tauri::command]
async fn activity_log(query: activity::Query) -> Result<activity::Page, String> {
    tauri::async_runtime::spawn_blocking(move || activity::page(query))
        .await
        .map_err(err_string)?
}

#[tauri::command]
async fn local_resource_sample(
    window: tauri::WebviewWindow,
) -> Result<local_resources::Sample, String> {
    let visible = || {
        window.label() == "main"
            && window.is_visible().unwrap_or(false)
            && !window.is_minimized().unwrap_or(true)
    };
    if !visible() {
        return Err("The log window is hidden".into());
    }
    let sample = local_resources::sample().await?;
    if !visible() {
        return Err("The log window is hidden".into());
    }
    Ok(sample)
}

#[tauri::command]
fn monitoring_catalog() -> Vec<monitoring::Definition> {
    monitoring::catalog()
}
#[tauri::command]
fn monitoring_library(
    state: State<'_, Arc<AppState>>,
    server_id: Option<String>,
) -> Result<std::collections::BTreeMap<String, monitoring::LibraryEntry>, String> {
    state.store.monitoring_library(server_id.as_deref())
}
#[tauri::command]
fn monitoring_sources(definition_id: String) -> Result<Vec<monitoring::Source>, String> {
    monitoring::sources(&definition_id)
}
#[tauri::command]
fn monitoring_policy(
    state: State<'_, Arc<AppState>>,
    scope: monitoring::Scope,
) -> Result<monitoring::Policy, String> {
    state.store.monitoring_policy(&scope)
}
#[tauri::command]
fn configure_monitoring(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    scope: monitoring::Scope,
    overrides: monitoring::Overrides,
    expected_revision: i64,
) -> Result<monitoring::Policy, String> {
    let mut span = activity::begin("app", "configure_monitoring", scope.server_id.clone());
    let result = state
        .store
        .set_monitoring(&scope, overrides, expected_revision);
    span.result(&result);
    if result.is_ok() {
        let _ = app.emit("state-changed", ());
    }
    result
}

#[tauri::command]
async fn notification_status(
    state: State<'_, Arc<AppState>>,
) -> Result<notifications::Status, String> {
    notifications::status(&state.store).await
}
#[tauri::command]
async fn configure_notifications(
    state: State<'_, Arc<AppState>>,
    enabled: bool,
) -> Result<notifications::Status, String> {
    let mut span = activity::begin("app", "configure_notifications", None);
    let result = notifications::configure(&state.store, enabled).await;
    span.result(&result);
    result
}
#[tauri::command]
async fn test_notification(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    notifications::test(&state.store).await
}
#[tauri::command]
async fn request_notification_permission(
    state: State<'_, Arc<AppState>>,
) -> Result<notifications::Status, String> {
    notifications::request_permission(&state.store).await
}
#[tauri::command]
fn open_notification_settings() -> Result<(), String> {
    notifications::open_settings()
}
#[tauri::command]
fn take_notification_target(
    state: State<'_, Arc<AppState>>,
    window: tauri::WebviewWindow,
) -> Result<notifications::Target, String> {
    if window.label() != "main" {
        return Err("Open this page from the main window".into());
    }
    notifications::take_target(&state.store)
}

#[tauri::command]
fn snapshot(state: State<'_, Arc<AppState>>) -> Result<Snapshot, String> {
    state.store.snapshot()
}

#[tauri::command]
async fn pick_inventory_file(
    window: tauri::WebviewWindow,
) -> Result<Option<inventory::SelectedInventory>, String> {
    let mut _activity_span = crate::activity::begin("app", "pick_inventory_file", None);
    let _activity_result = (async {
        use tauri_plugin_dialog::DialogExt;
        if window.label() != "main" {
            return Err("Add servers from the main window".into());
        }
        let (sender, receiver) = tokio::sync::oneshot::channel();
        window
            .dialog()
            .file()
            .set_parent(&window)
            .set_title("Select Ansible inventory")
            .pick_file(move |file| {
                let _ = sender.send(file);
            });
        receiver
            .await
            .map_err(|_| "Could not open the file picker")?
            .map(|file| {
                let path = file
                    .into_path()
                    .map_err(|_| "Select a local inventory file")?;
                inventory::selected_file(&path)
            })
            .transpose()
    })
    .await;
    _activity_span.result(&_activity_result);
    _activity_result
}

#[tauri::command]
async fn add_source(
    state: State<'_, Arc<AppState>>,
    kind: String,
    location: String,
) -> Result<usize, String> {
    let mut _activity_span = crate::activity::begin("app", "add_source", None);
    let _activity_result = (async {
        let source = Source {
            id: uuid::Uuid::new_v4().to_string(),
            name: String::new(),
            kind,
            location,
            last_sync: None,
            error: None,
        };
        sync_source(&state, &source).await
    })
    .await;
    _activity_span.result(&_activity_result);
    _activity_result
}
async fn sync_source(state: &AppState, source: &Source) -> Result<usize, String> {
    monitoring::run(
        &state.store,
        "inventory",
        "",
        "",
        sync_source_inner(state, source),
    )
    .await
}
async fn sync_source_inner(state: &AppState, source: &Source) -> Result<usize, String> {
    let mut _activity_span = crate::activity::begin("app", "sync_source", Some(source.id.clone()));
    let _activity_result = (async {
        let kind = source.kind.clone();
        let location = source.location.clone();
        let imported =
            tauri::async_runtime::spawn_blocking(move || inventory::read_source(&kind, &location))
                .await
                .map_err(err_string)??;
        let mut source = source.clone();
        source.name = if source.kind == "manual" {
            imported
                .iter()
                .map(|host| host.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            inventory::selected_file(std::path::Path::new(&source.location))?.name
        };
        source.last_sync = Some(now());
        source.error = None;
        let count = state.store.import(&source, imported)?;
        let snapshot = state.store.snapshot()?;
        activity::set_servers(&snapshot.servers);
        state.consoles.retain(&snapshot.servers);
        state.package_refresh.retain(&snapshot.servers, |_| true);
        ssh_pool::maintain_global(
            &snapshot
                .servers
                .into_iter()
                .map(|s| s.endpoint)
                .collect::<Vec<_>>(),
        );
        Ok(count)
    })
    .await;
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
async fn refresh_source(state: State<'_, Arc<AppState>>, id: String) -> Result<usize, String> {
    let mut _activity_span =
        crate::activity::begin("app", "refresh_source", crate::activity::id_target(&id));
    let _activity_result = (async {
        let source = state
            .store
            .snapshot()?
            .sources
            .into_iter()
            .find(|s| s.id == id)
            .ok_or("Server list not found")?;
        match sync_source(&state, &source).await {
            Ok(n) => Ok(n),
            Err(e) => {
                state.store.source_error(&source, e.clone())?;
                Err(e)
            }
        }
    })
    .await;
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
fn delete_source(state: State<'_, Arc<AppState>>, id: String) -> Result<(), String> {
    let mut _activity_span =
        crate::activity::begin("app", "delete_source", crate::activity::id_target(&id));
    let _activity_result = (|| {
        state.store.delete_source(&id)?;
        let snapshot = state.store.snapshot()?;
        activity::set_servers(&snapshot.servers);
        state.consoles.retain(&snapshot.servers);
        state.package_refresh.retain(&snapshot.servers, |_| true);
        ssh_pool::maintain_global(
            &snapshot
                .servers
                .into_iter()
                .map(|s| s.endpoint)
                .collect::<Vec<_>>(),
        );
        Ok::<_, String>(())
    })();
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
fn update_settings(
    state: State<'_, Arc<AppState>>,
    patch: SettingsPatch,
) -> Result<Settings, String> {
    let mut _activity_span = crate::activity::begin("app", "update_settings", None);
    let _activity_result = (|| {
        let _lifecycle = state
            .investigator
            .lifecycle
            .lock()
            .map_err(|e| e.to_string())?;
        let settings = state.store.update_settings(patch)?;
        if settings.mode != "auto" || settings.paused {
            state.investigator.cancel_auto();
        }
        Ok(settings)
    })();
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
fn history(state: State<'_, Arc<AppState>>, id: String) -> Result<Vec<Observation>, String> {
    state.store.history(&id)
}

async fn poll(state: Arc<AppState>, id: String, app: tauri::AppHandle) -> Result<(), String> {
    monitoring::run(
        &state.store,
        "metrics",
        &id,
        "",
        poll_inner(state.clone(), id.clone(), app),
    )
    .await
}
async fn poll_inner(state: Arc<AppState>, id: String, app: tauri::AppHandle) -> Result<(), String> {
    let mut _activity_span =
        crate::activity::begin("server", "poll", crate::activity::id_target(&id));
    let _activity_result = (async {
        let _guard = state.collectors.acquire(&id, &state.store).await?;
        let snapshot = state.store.snapshot()?;
        let server = snapshot
            .servers
            .into_iter()
            .find(|s| s.id == id)
            .ok_or("The server is remote")?;
        let result = collect_metrics(&state, &server).await;
        let _ = app.emit("state-changed", ());
        result.map(|_| ())
    })
    .await;
    _activity_span.result(&_activity_result);
    _activity_result
}
async fn collect_metrics(state: &AppState, server: &Server) -> Result<Observation, String> {
    let attempt = state.store.begin_metrics_check(server)?;
    let network = state.store.connectivity();
    let ticket = network.ticket();
    let startup = monitoring::context().is_some_and(|e| e.trigger == startup_monitoring::TRIGGER);
    let result = connectivity::observe_ssh(network.clone(), ticket, async {
        // Keep the same pool entry alive across deployment and collection even
        // if the connection cap falls while the check is running.
        let _pin = if startup {
            Some(ssh_pool::global()?.acquire(&server.endpoint).await?)
        } else {
            None
        };
        ssh::collect(&server.endpoint, &state.collector).await
    })
    .await;
    let confirmed = if result.is_err() {
        Box::pin(network.confirm_failure(ticket)).await
    } else {
        None
    };
    state
        .store
        .record_network_metrics(&attempt, server, result.clone(), confirmed)?;
    if !startup {
        if let Some(app) = state.app.get() {
            let _ = app.emit("state-changed", ());
        }
    }
    result
}

async fn monitor_connectivity(app: tauri::AppHandle, state: Arc<AppState>) {
    let network = state.store.connectivity();
    let mut updates = network.updates();
    let mut status = *updates.borrow_and_update();
    let mut next_probe = tokio::time::Instant::now();
    let interval = |offline| Duration::from_secs(if offline { 5 } else { 30 });
    while !state.stop.load(Ordering::Relaxed) {
        tokio::select! {
            _ = updates.changed() => {
                let current = *updates.borrow_and_update();
                if !current.offline && current.recoveries != status.recoveries {
                    let _ = state.store.reschedule_metrics_checks();
                    state.package_refresh.wake.notify_one();
                }
                if current.offline != status.offline || current.recoveries != status.recoveries {
                    let _ = app.emit("state-changed", ());
                }
                if current.probe_revision != status.probe_revision {
                    next_probe = tokio::time::Instant::now();
                } else if current.offline != status.offline {
                    next_probe = tokio::time::Instant::now() + interval(current.offline);
                }
                status = current;
            }
            _ = async {
                tokio::time::sleep_until(next_probe).await;
                network.periodic().await;
            } => {
                let period = interval(network.offline());
                next_probe += period;
                if next_probe < tokio::time::Instant::now() {
                    next_probe = tokio::time::Instant::now() + period;
                }
            }
        }
    }
}
#[tauri::command]
async fn poll_server(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    id: String,
) -> Result<(), String> {
    let mut _activity_span =
        crate::activity::begin("app", "poll_server", crate::activity::id_target(&id));
    let _activity_result = (async { poll(state.inner().clone(), id, app).await }).await;
    _activity_span.result(&_activity_result);
    _activity_result
}

#[tauri::command]
async fn diagnose(
    state: State<'_, Arc<AppState>>,
    id: String,
    kind: String,
) -> Result<serde_json::Value, String> {
    let mut _activity_span =
        crate::activity::begin("app", "diagnose", crate::activity::id_target(&id));
    let _activity_result = (async {
        if kind != "logs" {
            return Err("Unknown check".into());
        }
        serde_json::to_value(logs::collect(state.inner().clone(), id).await?).map_err(err_string)
    })
    .await;
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
fn storage_status(state: State<'_, Arc<AppState>>) -> Result<storage::Status, String> {
    state.store.storage_status()
}
#[tauri::command]
fn vulnerability_summary(
    state: State<'_, Arc<AppState>>,
    id: String,
    offset: Option<usize>,
    include_hidden: Option<bool>,
) -> Result<vulnerabilities::View, String> {
    state.store.vulnerability_view_filtered(
        &id,
        offset.unwrap_or(0),
        include_hidden.unwrap_or(false),
    )
}
#[tauri::command]
async fn vulnerability_catalog(
    state: State<'_, Arc<AppState>>,
    query: vulnerability_catalog::Query,
) -> Result<vulnerability_catalog::Page, String> {
    let app = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        vulnerability_catalog::page(&app.store, &app.root.join("advisories"), query)
    })
    .await
    .map_err(err_string)?
}
#[tauri::command]
async fn vulnerability_catalog_detail(
    state: State<'_, Arc<AppState>>,
    cve: String,
) -> Result<vulnerability_catalog::Detail, String> {
    let app = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        vulnerability_catalog::detail(&app.store, &app.root.join("advisories"), &cve)
    })
    .await
    .map_err(err_string)?
}
#[tauri::command]
fn set_vulnerability_hidden(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    id: String,
    source: String,
    cve: String,
    fingerprint: String,
    hidden: bool,
) -> Result<(), String> {
    let mut span = activity::begin("app", "set_vulnerability_hidden", Some(id.clone()));
    let result = (|| {
        let cancel = state.store.set_vulnerability_hidden(
            &id,
            &source,
            &cve,
            &fingerprint,
            hidden,
            now(),
        )?;
        for run in cancel {
            let _ = state.investigator.cancel(&run);
        }
        let _ = app.emit("state-changed", ());
        Ok(())
    })();
    span.result(&result);
    result
}
#[tauri::command]
async fn refresh_packages(state: State<'_, Arc<AppState>>, id: String) -> Result<(), String> {
    let mut _activity_span =
        crate::activity::begin("app", "refresh_packages", crate::activity::id_target(&id));
    let _activity_result = (async {
        let app = state.inner().clone();
        packages::rescan(app.clone(), id.clone()).await?;
        tokio::task::spawn_blocking(move || {
            app.store
                .evaluate_vulnerabilities(&id, &app.root.join("advisories"))
        })
        .await
        .map_err(err_string)?
    })
    .await;
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
async fn refresh_apt(state: State<'_, Arc<AppState>>, id: String) -> Result<(), String> {
    let mut _activity_span =
        crate::activity::begin("app", "refresh_apt", crate::activity::id_target(&id));
    let _activity_result = (async { packages::collect_apt(state.inner().clone(), id).await }).await;
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
fn advisory_status(state: State<'_, Arc<AppState>>) -> Result<Vec<advisories::Source>, String> {
    state.store.advisory_sources()
}
#[tauri::command]
async fn refresh_advisories(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    let mut _activity_span = crate::activity::begin("app", "refresh_advisories", None);
    let _activity_result = (async { advisories::refresh(state.inner().clone(), true).await }).await;
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
fn list_service_instances(
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<Vec<instances::Instance>, String> {
    state.store.service_instances(&id)
}
#[tauri::command]
fn add_service_instance(
    state: State<'_, Arc<AppState>>,
    id: String,
    kind: String,
    port: Option<u16>,
) -> Result<instances::Instance, String> {
    let mut _activity_span = crate::activity::begin(
        "app",
        "add_service_instance",
        crate::activity::id_target(&id),
    );
    let _activity_result = (|| state.store.add_service_instance(&id, &kind, port))();
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
fn remove_service_instance(
    state: State<'_, Arc<AppState>>,
    id: String,
    kind: String,
    instance_id: String,
) -> Result<(), String> {
    let mut _activity_span = crate::activity::begin(
        "app",
        "remove_service_instance",
        crate::activity::id_target(&id),
    );
    let _activity_result = (|| {
        state
            .store
            .remove_service_instance(&id, &kind, &instance_id)
    })();
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
fn service_catalog() -> std::collections::BTreeMap<String, services::Spec> {
    services::catalog()
}
#[tauri::command]
fn service_summary(
    state: State<'_, Arc<AppState>>,
    id: String,
    kind: String,
    instance_id: Option<String>,
) -> Result<serde_json::Value, String> {
    services::snapshot_for(
        &state.store,
        &id,
        &kind,
        instance_id.as_deref().unwrap_or(instances::DEFAULT),
    )
}
#[tauri::command]
fn configure_service(
    state: State<'_, Arc<AppState>>,
    id: String,
    kind: String,
    instance_id: Option<String>,
    config: serde_json::Value,
) -> Result<(), String> {
    let mut _activity_span =
        crate::activity::begin("app", "configure_service", crate::activity::id_target(&id));
    let _activity_result = (|| {
        services::configure_for(
            &state.store,
            &id,
            &kind,
            instance_id.as_deref().unwrap_or(instances::DEFAULT),
            config,
        )
    })();
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
async fn refresh_service(
    state: State<'_, Arc<AppState>>,
    id: String,
    kind: String,
    instance_id: Option<String>,
) -> Result<serde_json::Value, String> {
    let mut _activity_span =
        crate::activity::begin("app", "refresh_service", crate::activity::id_target(&id));
    let _activity_result = (async {
        services::refresh_for(
            state.inner().clone(),
            id,
            kind,
            instance_id.unwrap_or_else(instances::default_id),
        )
        .await
    })
    .await;
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
fn log_summary(
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<logs::DesktopLogView, String> {
    state.store.desktop_log_view(&id)
}
#[tauri::command]
fn action_requests(
    state: State<'_, Arc<AppState>>,
    run_id: Option<String>,
    server_id: Option<String>,
) -> Result<Vec<ai_actions::Card>, String> {
    state
        .store
        .action_cards(run_id.as_deref(), server_id.as_deref())
}
#[tauri::command]
fn action_request(
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<ai_actions::Request, String> {
    state.store.action_request(&id)
}
#[tauri::command]
async fn open_action_approval(app: tauri::AppHandle, id: String) -> Result<(), String> {
    ai_actions::open_approval(&app, &id)
}
#[tauri::command]
fn decide_action(
    window: tauri::WebviewWindow,
    state: State<'_, Arc<AppState>>,
    id: String,
    artifact_hash: String,
    decision: String,
) -> Result<ai_actions::Request, String> {
    if window.label() != ai_actions::approval_label(&id)? {
        return Err("Approve the action in its request window".into());
    }
    let request = state.store.action_request(&id)?;
    let mut span = activity::begin_run(
        "app",
        match decision.as_str() {
            "once" => "approve_action_once",
            "session" => "approve_action_session",
            _ => "deny_action",
        },
        Some(request.server_id.clone()),
        Some(request.run_id.clone()),
    );
    let result = state
        .store
        .action_decide(&id, &artifact_hash, &decision, now());
    span.result(&result);
    ai_actions::changed(&id);
    if let Ok(r) = &result {
        activity::action(
            r,
            match decision.as_str() {
                "once" => "script_approved_once",
                "session" => "script_approved_session",
                _ => "script_denied",
            },
        );
    }
    result
}
#[tauri::command]
fn cancel_action(
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<ai_actions::Request, String> {
    let cancellation =
        state
            .store
            .interrupt_action(&id, "cancelled", "Cancelled by the user".into(), now());
    // A storage error must not prevent asking the active executor to stop.
    if !matches!(&cancellation, Ok((_, false))) {
        state.actions.cancel(&id);
    }
    let (request, changed) = cancellation?;
    if changed {
        activity::action(&request, "script_cancelled_by_user");
        ai_actions::changed(&id);
    }
    Ok(request)
}
#[tauri::command]
fn revoke_action_grant(state: State<'_, Arc<AppState>>, run_id: String) -> Result<(), String> {
    for card in state.store.action_cards(Some(&run_id), None)? {
        if let Ok(r) = state.store.action_request(&card.id) {
            activity::action(&r, "script_grant_revoked");
        }
    }
    state.actions.cancel_run(&run_id);
    ai_actions::changed(&run_id);
    state.store.action_revoke(&run_id, now()).map(|_| ())
}
#[tauri::command]
async fn refresh_action_result(
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<ai_actions::Request, String> {
    ai_actions::reconcile(state.inner().clone(), &id).await
}
#[tauri::command]
async fn rollback_action(
    state: State<'_, Arc<AppState>>,
    id: String,
    artifact_hash: String,
) -> Result<ai_actions::Request, String> {
    ai_actions::rollback(state.inner().clone(), &id, &artifact_hash).await
}
#[tauri::command]
fn ai_profiles(state: State<'_, Arc<AppState>>) -> Result<ai_models::Profiles, String> {
    state.store.ai_profiles()
}
#[tauri::command]
fn configure_ai_profiles(
    state: State<'_, Arc<AppState>>,
    config: ai_models::Profiles,
) -> Result<ai_models::Profiles, String> {
    let result = state.store.configure_ai_profiles(config);
    if result.is_ok() {
        state.actions.cancel_all();
    }
    result
}
#[tauri::command]
async fn agent_models(
    state: State<'_, Arc<AppState>>,
    provider: String,
) -> Result<Vec<ai_models::ModelInfo>, String> {
    agents::model_catalog(&state.root, &provider).await
}
pub async fn actions_smoke(
    root: PathBuf,
    agent: Option<String>,
) -> Result<serde_json::Value, String> {
    ai_actions::smoke(root, agent).await
}
pub async fn models_smoke(root: PathBuf, provider: String) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!(
        agents::model_catalog(&root, &provider).await?
    ))
}
/// Explicit metadata-only compatibility diagnostic. No model turns or SSH.
pub async fn agents_probe() -> Vec<agents::AgentStatus> {
    agents::detect().await
}
#[tauri::command]
async fn detect_agents() -> Vec<agents::AgentStatus> {
    agents::detect().await
}

#[tauri::command]
fn open_ai_settings(app: tauri::AppHandle) -> Result<(), String> {
    let main = app
        .get_webview_window("main")
        .ok_or("The main window is not available")?;
    main.show().map_err(err_string)?;
    main.unminimize().map_err(err_string)?;
    main.set_focus().map_err(err_string)?;
    app.emit_to("main", "ai-settings-open", ())
        .map_err(err_string)
}

#[tauri::command]
fn server_directory(state: State<'_, Arc<AppState>>) -> Result<Vec<serde_json::Value>, String> {
    let db = state.store.0.lock().map_err(err_string)?;
    let servers: Vec<model::Server> = Store::list(&db, "servers")?;
    Ok(servers
        .into_iter()
        .map(|server| {
            serde_json::json!({
                "id": server.id,
                "name": server.name,
                "endpoint": {
                    "host": server.endpoint.host,
                    "user": server.endpoint.user,
                    "port": server.endpoint.port,
                    "jumpHost": server.endpoint.jump_host,
                }
            })
        })
        .collect())
}

#[tauri::command]
fn open_server_sidebar(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
    id: String,
    incidents: bool,
) -> Result<(), String> {
    state.store.server(&id)?;
    let main = app
        .get_webview_window("main")
        .ok_or("The main window is not available")?;
    main.show().map_err(err_string)?;
    main.unminimize().map_err(err_string)?;
    main.set_focus().map_err(err_string)?;
    app.emit_to(
        "main",
        "server-sidebar-open",
        serde_json::json!({ "id": id, "incidents": incidents }),
    )
    .map_err(err_string)
}

#[tauri::command]
async fn start_investigation(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    server_ids: Vec<String>,
    question: String,
    model_alias: Option<String>,
    chat_id: Option<String>,
) -> Result<String, String> {
    let mut _activity_span = crate::activity::begin("app", "start_investigation", None);
    let _activity_result = (async {
        agents::start_profile(
            state.inner().clone(),
            server_ids,
            question,
            model_alias.as_deref().unwrap_or("medium"),
            chat_id.as_deref(),
            Arc::new(move |id| {
                let _ = app.emit("investigation-changed", id);
            }),
        )
    })
    .await;
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
async fn start_console_chat(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    server_ids: Vec<String>,
    question: String,
    model_alias: Option<String>,
    chat_id: Option<String>,
) -> Result<String, String> {
    if window.label() != "main" {
        return Err("Fleet chats are available in the main window".into());
    }
    let mut span = activity::begin("app", "start_console_chat", None);
    let result = agents::start_fleet_chat(
        state.inner().clone(),
        server_ids,
        question,
        model_alias.as_deref().unwrap_or("medium"),
        chat_id.as_deref(),
        Arc::new(move |id| {
            let _ = app.emit("investigation-changed", id);
        }),
    );
    span.result(&result);
    result
}
#[tauri::command]
fn investigations(state: State<'_, Arc<AppState>>) -> Result<Vec<agents::Investigation>, String> {
    state.investigator.all()
}
#[tauri::command]
fn investigation(
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<agents::Investigation, String> {
    state.investigator.get(&id)
}

#[tauri::command]
fn cancel_investigation(state: State<'_, Arc<AppState>>, id: String) -> Result<(), String> {
    let mut _activity_span = crate::activity::begin(
        "app",
        "cancel_investigation",
        crate::activity::id_target(&id),
    );
    let _activity_result = (|| state.investigator.cancel(&id))();
    _activity_span.result(&_activity_result);
    _activity_result
}

#[tauri::command]
fn resolve_incident(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    id: String,
    episode: String,
) -> Result<(), String> {
    let mut span = activity::begin(
        "app",
        "resolve_incident",
        state.store.incident_server(&id).ok(),
    );
    let result = (|| {
        let cancel = state.store.resolve_incident(&id, &episode, now())?;
        for run in cancel {
            let _ = state.investigator.cancel(&run);
        }
        let _ = app.emit("state-changed", ());
        Ok(())
    })();
    span.result(&result);
    result
}

#[tauri::command]
async fn resolve_incidents(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    episodes: Vec<incidents::IncidentEpisode>,
) -> Result<(), String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut span = activity::begin("app", "resolve_incidents", None);
        let result = (|| {
            for run in state.store.resolve_incidents(&episodes, now())? {
                let _ = state.investigator.cancel(&run);
            }
            let _ = app.emit("state-changed", ());
            Ok(())
        })();
        span.result(&result);
        result
    })
    .await
    .map_err(err_string)?
}

#[tauri::command]
async fn incident_groups(
    state: State<'_, Arc<AppState>>,
    include_closed: Option<bool>,
    offset: Option<usize>,
    search: Option<String>,
) -> Result<correlation::Overview, String> {
    let app = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        app.store.incident_groups(
            include_closed.unwrap_or(false),
            offset.unwrap_or(0),
            search.as_deref().unwrap_or_default(),
        )
    })
    .await
    .map_err(err_string)?
}
#[tauri::command]
fn incident_group(
    state: State<'_, Arc<AppState>>,
    id: String,
    offset: Option<usize>,
) -> Result<correlation::View, String> {
    state.store.incident_group(&id, offset.unwrap_or(0), None)
}
#[tauri::command]
fn server_dependencies(
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<correlation::Dependencies, String> {
    state.store.server_dependencies(&id)
}
#[tauri::command]
fn save_server_dependencies(
    state: State<'_, Arc<AppState>>,
    id: String,
    depends_on: Vec<String>,
) -> Result<(), String> {
    let mut _activity_span = crate::activity::begin(
        "app",
        "save_server_dependencies",
        crate::activity::id_target(&id),
    );
    let _activity_result = (|| state.store.save_dependencies(&id, depends_on))();
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
fn start_group_investigation(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<String, String> {
    let mut _activity_span = crate::activity::begin(
        "app",
        "start_group_investigation",
        crate::activity::id_target(&id),
    );
    let _activity_result = (|| {
        agents::start_group_run(
            state.inner().clone(),
            id,
            Arc::new(move |id| {
                let _ = app.emit("investigation-changed", id);
            }),
            None,
        )
    })();
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
fn group_investigations(
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<Vec<agents::Investigation>, String> {
    let view = state.store.incident_group(&id, 0, None)?;
    let mut runs = state.store.investigations()?;
    runs.retain(|r| r.group_id.as_ref() == Some(&id) || view.group.run_id.as_ref() == Some(&r.id));
    runs.sort_by_key(|r| std::cmp::Reverse(r.started_at));
    runs.truncate(5);
    Ok(runs)
}
#[tauri::command]
fn auto_status(state: State<'_, Arc<AppState>>) -> Result<automation::AutoStatus, String> {
    state.store.auto_status(now())
}
#[tauri::command]
fn resume_auto(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    let mut _activity_span = crate::activity::begin("app", "resume_auto", None);
    let _activity_result = (|| state.store.resume_auto())();
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
fn dismiss_auto_job(state: State<'_, Arc<AppState>>, id: String) -> Result<(), String> {
    let mut _activity_span =
        crate::activity::begin("app", "dismiss_auto_job", crate::activity::id_target(&id));
    let _activity_result = (|| state.store.dismiss_job(&id))();
    _activity_span.result(&_activity_result);
    _activity_result
}

#[tauri::command]
fn checks_view(
    state: State<'_, Arc<AppState>>,
    server_id: String,
    check_id: Option<String>,
) -> Result<checks::View, String> {
    state.store.check_view(&server_id, check_id.as_deref())
}
#[tauri::command]
fn new_check(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    let mut _activity_span = crate::activity::begin("app", "new_check", None);
    let _activity_result = (|| state.store.new_check())();
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
fn save_check_version(
    state: State<'_, Arc<AppState>>,
    check_id: String,
    spec: check_engine::Spec,
) -> Result<checks::Version, String> {
    let mut _activity_span = crate::activity::begin("app", "save_check_version", None);
    let _activity_result = (|| state.store.propose_check(&check_id, spec, "user"))();
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
async fn test_check_version(
    state: State<'_, Arc<AppState>>,
    version_id: String,
) -> Result<checks::Tested, String> {
    let mut _activity_span = crate::activity::begin("app", "test_check_version", None);
    let _activity_result =
        (async { checks::test_version(state.inner().clone(), version_id).await }).await;
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
async fn preview_check_version(
    state: State<'_, Arc<AppState>>,
    server_id: String,
    version_id: String,
) -> Result<checks::Preview, String> {
    let mut _activity_span = crate::activity::begin(
        "app",
        "preview_check_version",
        crate::activity::id_target(&server_id),
    );
    let _activity_result =
        (async { checks::preview_version(state.inner().clone(), server_id, version_id).await })
            .await;
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
fn activate_check(
    state: State<'_, Arc<AppState>>,
    server_id: String,
    version_id: String,
    token: String,
) -> Result<(), String> {
    let mut _activity_span = crate::activity::begin(
        "app",
        "activate_check",
        crate::activity::id_target(&server_id),
    );
    let _activity_result = (|| state.store.activate_check(&server_id, &version_id, &token))();
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
fn disable_check(
    state: State<'_, Arc<AppState>>,
    server_id: String,
    check_id: String,
) -> Result<(), String> {
    let mut _activity_span = crate::activity::begin(
        "app",
        "disable_check",
        crate::activity::id_target(&server_id),
    );
    let _activity_result = (|| state.store.disable_check(&server_id, &check_id))();
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
fn discard_check_version(
    state: State<'_, Arc<AppState>>,
    version_id: String,
) -> Result<(), String> {
    let mut _activity_span = crate::activity::begin("app", "discard_check_version", None);
    let _activity_result = (|| state.store.discard_check_version(&version_id))();
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
fn delete_check(state: State<'_, Arc<AppState>>, check_id: String) -> Result<(), String> {
    let mut _activity_span = crate::activity::begin("app", "delete_check", None);
    let _activity_result = (|| state.store.delete_check(&check_id))();
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
async fn run_checks(state: State<'_, Arc<AppState>>, server_id: String) -> Result<bool, String> {
    let mut _activity_span =
        crate::activity::begin("app", "run_checks", crate::activity::id_target(&server_id));
    let _activity_result =
        (async { checks::run_pending(state.inner().clone(), Some(server_id)).await }).await;
    _activity_span.result(&_activity_result);
    _activity_result
}
#[tauri::command]
fn create_check_with_agent(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    server_id: String,
    check_id: String,
    question: String,
) -> Result<String, String> {
    let mut _activity_span = crate::activity::begin(
        "app",
        "create_check_with_agent",
        crate::activity::id_target(&server_id),
    );
    let _activity_result = (|| {
        agents::start_authoring(
            state.inner().clone(),
            server_id,
            check_id,
            question,
            Arc::new(move |id| {
                let _ = app.emit("investigation-changed", id);
            }),
        )
    })();
    _activity_span.result(&_activity_result);
    _activity_result
}

// Hold an OS lock for the lifetime of this data directory. Recovery must never
// settle another live application's reservation. flock releases after a crash.
struct InstanceLock(std::fs::File);
impl InstanceLock {
    fn acquire(root: &std::path::Path) -> Result<Self, String> {
        use std::os::fd::AsRawFd;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(root.join("instance.lock"))
            .map_err(|e| e.to_string())?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("Another Cyberbot instance is using this data directory".into());
        }
        Ok(Self(file))
    }
}
impl Drop for InstanceLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn create_state(root: PathBuf) -> Result<Arc<AppState>, String> {
    std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let instance = InstanceLock::acquire(&root)?;
    let store = Store::open(&root.join("cyberbot.sqlite"))?;
    store.recover_actions()?;
    store.maintain_storage()?;
    store.backfill_ledger()?;
    let mut runs = store.investigations()?;
    for run in &mut runs {
        if run.status == "running" {
            run.status = "interrupted".into();
            run.error = Some(
                "Cyberbot closed during the AI run. The run will not restart automatically.".into(),
            );
            run.ended_at = Some(now());
            store.settle(run)?;
        }
    }
    let state = Arc::new(AppState {
        app: OnceLock::new(),
        _instance: instance,
        collector: ssh::write_collector(&root)?,
        root,
        store,
        investigator: agents::Investigator::restore(runs),
        collectors: collector_queue::Queue::default(),
        package_refresh: package_refresh::Queue::default(),
        fleet_console: fleet_console::Console::default(),
        consoles: console::Sessions::default(),
        stop: AtomicBool::new(false),
        advisory_refresh: tokio::sync::Mutex::new(()),
        wake_reset: AtomicBool::new(false),
        startup_cancel: tokio_util::sync::CancellationToken::new(),
        check_runtime: check_runtime::Runtime::default(),
        actions: ai_actions::Runtime::default(),
    });
    ssh_pool::maintain_global(
        &state
            .store
            .snapshot()?
            .servers
            .into_iter()
            .map(|s| s.endpoint)
            .collect::<Vec<_>>(),
    );
    Ok(state)
}

/// Explicit smoke test. Only the opt-in disposable fixture enables remote collection.
pub async fn agent_smoke(
    root: PathBuf,
    agent: String,
    cancel_after_start: bool,
    auto_limit: Option<u64>,
    web: bool,
) -> Result<serde_json::Value, String> {
    if web && root.exists() && root.read_dir().map_err(err_string)?.next().is_some() {
        return Err("Web Stand Requires an Empty Data Catalogue".into());
    }
    let state = create_state(root)?;
    let mut settings = state.store.settings()?;
    settings.auto_agent = agent.clone();
    state.store.save_settings(&settings)?;
    let source = Source {
        id: "smoke".into(),
        name: "Synthetic fixture".into(),

        kind: "manual".into(),
        location: "tester@127.0.0.1:1".into(),
        last_sync: None,
        error: None,
    };
    let fixture = if web {
        None
    } else {
        std::env::var("CYBERBOT_TEST_SSH_DIR").ok()
    };
    let mut hosts = inventory::parse_manual(&source.location)?;
    if let Some(dir) = &fixture {
        hosts[0].name = "debian-ssh-fixture".into();
        hosts[0].endpoint = Endpoint {
            host: "127.0.0.1".into(),
            user: "ops".into(),
            port: std::env::var("CYBERBOT_TEST_SSH_PORT")
                .map_err(|_| "No fixture port")?
                .parse()
                .map_err(|_| "Incorrect fixture port")?,
            identity_file: Some(format!("{dir}/id_ed25519")),
            known_hosts_file: Some(format!("{dir}/known_hosts")),
            jump_host: None,
        };
    }
    state.store.import(&source, hosts)?;
    let id = state.store.snapshot()?.servers[0].id.clone();
    let question = if web {
        use mcp::fixtures::{CVE, TRACKER};
        mcp::fixtures::seed_server_context(&state, &id, 1)?;
        let search = if agent == "codex" {
            "Also use Codex’s built-in live search on the public ID CVE-2023-6879 if search is available."
        } else {
            ""
        };
        format!("This is a test card. Call get_server, find a stored vulnerability {CVE} via get_vulnerability_summary, then call read_cve_advisory and read_web_page separately at the link {TRACKER}. Compare the installed version and the status of bookworm, specify the link and reading time. {search}")
    } else if fixture.is_some() {
        "This is a test Debian container. Call refresh_metrics over MCP, then get_server. Estimate the status from real metrics you’ve received and clearly list unavailable checks.".into()
    } else {
        "This is a synthetic connection check. Call only get_server for the selected server and explain what data is missing. Don’t run refresh_metrics or get_log_summary and don’t connect to SSH.".into()
    };
    let run = if let Some(limit) = auto_limit {
        if fixture.is_none() {
            return Err("Smoke requires a disposable SSH fixture".into());
        }
        state.store.save_settings(&Settings {
            mode: "auto".into(),
            auto_agent: agent.clone(),
            daily_run_limit: Some(2),
            daily_token_limit: Some(limit * 2),
            run_token_limit: limit,
            ..Settings::default()
        })?;
        let server = state.store.snapshot()?.servers[0].clone();
        let attempt = state.store.begin_metrics_check(&server)?;
        let mut observation = ssh::collect(&server.endpoint, &state.collector).await?;
        // Inject one threshold event into disposable data, without changing the server.
        observation.cpu_percent = Some(95.0);
        for _ in 0..100 {
            state
                .store
                .record_metrics(&attempt, &server, Ok(observation.clone()), 180)?;
        }
        state.store.reconcile_auto(now())?;
        let job = state.store.next_auto(now())?.ok_or("No AUTO mission")?;
        agents::start_auto(state.clone(), &job, Arc::new(|_| {}))?
    } else {
        agents::start(state.clone(), vec![id], question, Arc::new(|_| {}))?
    };
    loop {
        let r = state
            .investigator
            .all()?
            .into_iter()
            .find(|r| r.id == run)
            .ok_or("No launch")?;
        if cancel_after_start && r.session_id.is_some() && r.status == "running" {
            let _ = state.investigator.cancel(&run);
        }
        if r.status != "running" {
            let mut report = serde_json::to_value(r).map_err(|e| e.to_string())?;
            if auto_limit.is_some() {
                state.store.reconcile_auto(now())?;
                report["autoStatus"] = serde_json::to_value(state.store.auto_status(now())?)
                    .map_err(|e| e.to_string())?;
            }
            return Ok(report);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Explicit opt-in authoring acceptance. No infrastructure is contacted or changed.
pub async fn checks_smoke(root: PathBuf, agent: String) -> Result<serde_json::Value, String> {
    let state = create_state(root)?;
    let mut settings = state.store.settings()?;
    settings.auto_agent = agent.clone();
    state.store.save_settings(&settings)?;
    let source = Source {
        id: "checks-smoke".into(),
        name: "Synthetic checks".into(),

        kind: "manual".into(),
        location: "tester@127.0.0.1:1".into(),
        last_sync: None,
        error: None,
    };
    state
        .store
        .import(&source, inventory::parse_manual(&source.location)?)?;
    let server = state.store.snapshot()?.servers[0].id.clone();
    let check = state.store.new_check()?;
    let id=agents::start_authoring(state.clone(),server.clone(),check.clone(),"This is a synthetic test. Create a memory_percent test > 90, warning, badWindows=2, intervalSeconds=180, with three tests: 95 warning, 50 healthy, missing value unknown.Call get_check_contract, propose_check_version, test_check_version: no refresh_metrics or SSH after the tests.".into(),Arc::new(|_|{}))?;
    loop {
        let run = state.investigator.get(&id)?;
        if run.status != "running" {
            let view = state.store.check_view(&server, Some(&check))?;
            let d = view
                .definitions
                .iter()
                .find(|d| d.id == check)
                .ok_or("There’s no check")?;
            let passed = d
                .versions
                .iter()
                .any(|v| v.report.as_ref().is_some_and(|r| r.report.passed));
            return Ok(
                serde_json::json!({"status":if run.status=="completed"&&passed&&d.binding.is_none(){"completed"}else{"failed"},"agent":run.agent,"agentStatus":run.status,"error":run.error,"audit":run.audit,"usage":run.usage,"testedDraft":passed,"enabled":d.binding.is_some(),"versionCount":d.versions.len()}),
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Explicit local SSH log fixture. "none" exercises the pipeline without a model.
pub async fn logs_smoke(root: PathBuf, agent: String) -> Result<serde_json::Value, String> {
    collector_smoke(root, agent, "logs").await
}
pub async fn service_smoke(root: PathBuf, kind: String) -> Result<serde_json::Value, String> {
    if services::descriptor(&kind).is_none() {
        return Err("Unknown service".into());
    }
    collector_smoke(root, "none".into(), &kind).await
}
pub async fn packages_smoke(root: PathBuf) -> Result<serde_json::Value, String> {
    collector_smoke(root, "none".into(), "packages").await
}
async fn collector_smoke(
    root: PathBuf,
    agent: String,
    kind: &str,
) -> Result<serde_json::Value, String> {
    let state = create_state(root)?;
    let dir = std::env::var("CYBERBOT_TEST_SSH_DIR").map_err(|_| "SSH fixture is required")?;
    let source = Source {
        id: "logs-smoke".into(),
        name: "Log fixture".into(),

        kind: "manual".into(),
        location: "ops@127.0.0.1".into(),
        last_sync: None,
        error: None,
    };
    let mut hosts = inventory::parse_manual(&source.location)?;
    hosts[0].endpoint.port = std::env::var("CYBERBOT_TEST_SSH_PORT")
        .map_err(err_string)?
        .parse()
        .map_err(err_string)?;
    hosts[0].endpoint.identity_file = Some(format!("{dir}/id_ed25519"));
    hosts[0].endpoint.known_hosts_file = Some(format!("{dir}/known_hosts"));
    state.store.import(&source, hosts)?;
    state.store.save_settings(&Settings {
        mode: "auto".into(),
        auto_agent: if agent == "none" {
            "codex".into()
        } else {
            agent.clone()
        },
        daily_run_limit: Some(5),
        daily_token_limit: Some(300000),
        run_token_limit: 100000,
        ..Settings::default()
    })?;
    let snapshot = state.store.snapshot()?;
    ssh_pool::maintain_global(
        &snapshot
            .servers
            .iter()
            .map(|server| server.endpoint.clone())
            .collect::<Vec<_>>(),
    );
    let id = snapshot.servers[0].id.clone();
    // Optional, explicit disposable-fixture selector; no production configuration is changed.
    let instance = if std::env::var("CYBERBOT_TEST_INSTANCE").is_ok() {
        let port: u16 = std::env::var("CYBERBOT_TEST_INSTANCE_PORT")
            .map_err(err_string)?
            .parse()
            .map_err(err_string)?;
        let existing = {
            let db = state.store.0.lock().map_err(err_string)?;
            db.query_row("SELECT instance_id FROM service_state WHERE server_id=?1 AND json_extract(payload,'$.config.port')=?2 AND instance_id!='default' AND kind=?3 LIMIT 1",rusqlite::params![id,port,kind],|r|r.get::<_,String>(0)).optional().map_err(err_string)?
        };
        match existing {
            Some(id) => id,
            None => state.store.add_service_instance(&id, kind, Some(port))?.id,
        }
    } else {
        instances::DEFAULT.into()
    };
    let summary = if services::descriptor(kind).is_some() {
        services::configure_smoke(&state.store, &id, kind, &instance)?;
        services::refresh_for(state.clone(), id.clone(), kind.into(), instance.clone()).await?
    } else if kind == "packages" {
        packages::rescan(state.clone(), id.clone()).await?;
        let (checkpoint, rows) = state.store.package_snapshot(&id)?;
        if state.root.join("advisories").exists() {
            state
                .store
                .evaluate_vulnerabilities(&id, &state.root.join("advisories"))?;
        }
        serde_json::json!({"packages":rows.len(),"state":checkpoint,"vulnerabilities":state.store.vulnerability_view(&id,0)?})
    } else {
        serde_json::to_value(logs::collect(state.clone(), id.clone()).await?).map_err(err_string)?
    };
    state.store.reconcile_auto(now())?;
    let mut result = serde_json::json!({"status":"completed","summary":summary,"autoStatus":state.store.auto_status(now())?,"incidents":state.store.snapshot()?.incidents});
    if agent != "none" {
        let job = state
            .store
            .next_auto(now())?
            .ok_or("No significant event")?;
        let run = agents::start_auto(state.clone(), &job, Arc::new(|_| {}))?;
        loop {
            let r = state.investigator.get(&run)?;
            if r.status != "running" {
                result["status"] = serde_json::json!(r.status);
                result["investigation"] = serde_json::to_value(r).map_err(err_string)?;
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    Ok(result)
}
pub async fn activity_smoke(root: PathBuf) -> Result<serde_json::Value, String> {
    activity::smoke(&root).await
}

fn err_string(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[tauri::command]
fn open_server(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<(), String> {
    let mut _activity_span =
        crate::activity::begin("app", "open_server", crate::activity::id_target(&id));
    let _activity_result = (|| {
        if !state.store.snapshot()?.servers.iter().any(|s| s.id == id) {
            return Err("No server found".into());
        }
        let label = format!("server-{id}");
        if let Some(window) = app.get_webview_window(&label) {
            window.show().map_err(|e| e.to_string())?;
            window.set_focus().map_err(|e| e.to_string())?;
            return Ok(());
        }
        tauri::WebviewWindowBuilder::new(
            &app,
            label,
            tauri::WebviewUrl::App(format!("index.html?server={id}").into()),
        )
        .title("Cyberbot · Server")
        .inner_size(900.0, 720.0)
        .build()
        .map_err(|e| e.to_string())?;
        Ok(())
    })();
    _activity_span.result(&_activity_result);
    _activity_result
}

fn background(app: tauri::AppHandle, state: Arc<AppState>) {
    tauri::async_runtime::spawn(monitor_connectivity(app.clone(), state.clone()));
    let startup_deadline = Instant::now() + startup_monitoring::WINDOW;
    tauri::async_runtime::spawn(startup_monitoring::run(
        app.clone(),
        state.clone(),
        startup_deadline,
    ));
    tauri::async_runtime::spawn(async move {
        let mut jobs = tokio::task::JoinSet::new();
        let mut inventory_at = now() + 60;
        let mut reconcile_at = 0;
        let mut maintenance_at = 0;
        let mut advisory_at = 0;
        let mut advisory_job: Option<tokio::task::JoinHandle<()>> = None;
        let mut matching_job: Option<tokio::task::JoinHandle<()>> = None;
        let mut checks_job: Option<tokio::task::JoinHandle<()>> = None;
        let mut ssh_refresh: Option<tokio::task::JoinHandle<()>> = None;
        let mut last_tick = now();
        loop {
            let tick = now();
            let native_wake = state.wake_reset.swap(false, Ordering::AcqRel);
            if !native_wake && (tick < last_tick || tick - last_tick > 30) {
                state.startup_cancel.cancel();
                state.store.connectivity().recheck();
                ssh_pool::reset_global();
            }
            last_tick = tick;
            if state.stop.load(Ordering::Relaxed) {
                jobs.abort_all();
                if let Some(job) = checks_job.take() {
                    job.abort();
                }
                if let Some(job) = advisory_job.take() {
                    job.abort();
                }
                if let Some(job) = matching_job.take() {
                    job.abort();
                }
                if let Some(job) = ssh_refresh.take() {
                    job.abort();
                }
                break;
            }
            while jobs.try_join_next().is_some() {}
            if now() >= maintenance_at {
                let maintenance = monitoring::sync(&state.store, "storage", "schedule", || {
                    let mut span = activity::begin("app", "storage_cleanup", None);
                    let result = state.store.maintain_storage();
                    span.result(&result);
                    result
                });
                if let Err(e) = maintenance {
                    let _ = state.store.block_auto(&e);
                }
                maintenance_at = now() + 60;
                let _ = app.emit("state-changed", ());
            }
            let storage_ok = state.store.storage_status().is_ok_and(|s| !s.blocked);
            if storage_ok && state.store.settings().is_ok_and(|s| !s.paused) {
                if checks_job.as_ref().is_none_or(|j| j.is_finished()) {
                    let state = state.clone();
                    let app = app.clone();
                    checks_job = Some(tokio::spawn(async move {
                        match monitoring::trigger("schedule", checks::run_pending(state, None))
                            .await
                        {
                            Ok(false) => (),
                            _ => {
                                let _ = app.emit("state-changed", ());
                            }
                        }
                    }));
                }
                if advisory_job.as_ref().is_none_or(|j| j.is_finished()) {
                    let priority = state.package_refresh.take_advisories();
                    if !priority.is_empty() || now() >= advisory_at {
                        let state = state.clone();
                        let handle = app.clone();
                        advisory_job = Some(tokio::spawn(async move {
                            let _ = monitoring::trigger(
                                "schedule",
                                advisories::refresh_prioritized(state, false, priority),
                            )
                            .await;
                            let _ = handle.emit("state-changed", ());
                        }));
                        advisory_at = now() + 60;
                    }
                }
                if matching_job.as_ref().is_none_or(|j| j.is_finished()) {
                    let state = state.clone();
                    let handle = app.clone();
                    matching_job = Some(tokio::spawn(async move {
                        if vulnerabilities::process_pending(state.clone())
                            .await
                            .unwrap_or(false)
                        {
                            let _ = handle.emit("state-changed", ());
                            state.package_refresh.wake.notify_one();
                        }
                    }));
                }
            }
            if now() >= reconcile_at {
                if let Err(error) = state.store.reconcile_auto(now()) {
                    let _ = state.store.block_auto(&error);
                }
                reconcile_at = now() + 30;
                let _ = app.emit("state-changed", ());
            }
            if !state.investigator.busy() {
                let dispatch = (|| {
                    if let Some(job) = state.store.next_auto(now())? {
                        let handle = app.clone();
                        // Admission rechecks mode, scope, freshness and budget atomically.
                        agents::start_auto(
                            state.clone(),
                            &job,
                            Arc::new(move |id| {
                                let _ = handle.emit("investigation-changed", id);
                                let _ = handle.emit("state-changed", ());
                            }),
                        )?;
                    }
                    Ok::<_, String>(())
                })();
                if let Err(error) = dispatch {
                    let _ = state.store.block_auto(&error);
                }
            }
            if let Ok(snapshot) = state.store.snapshot() {
                state.package_refresh.retain(&snapshot.servers, |_| true);
                ssh_pool::maintain_global(
                    &snapshot
                        .servers
                        .iter()
                        .map(|s| s.endpoint.clone())
                        .collect::<Vec<_>>(),
                );
                if ssh_refresh.as_ref().is_none_or(|job| job.is_finished()) {
                    if let Ok(pool) = ssh_pool::global() {
                        ssh_refresh = Some(tokio::spawn(pool.refresh_changed_directories()));
                    }
                }
                if !snapshot.settings.paused && storage_ok {
                    let active = state.collectors.snapshot().unwrap_or_default();
                    let book = state.store.monitoring_book().unwrap_or_default();
                    state.package_refresh.retain(&snapshot.servers, |id| {
                        book.enabled("packages", id, "default")
                    });
                    state
                        .package_refresh
                        .reconcile_assessments(&state.store, Instant::now());
                    let schedule = collector_schedule::Schedule {
                        logs: state
                            .store
                            .log_schedule(&snapshot.servers)
                            .unwrap_or_default(),
                        packages: state
                            .store
                            .package_schedule(&snapshot.servers)
                            .unwrap_or_default(),
                        services: state
                            .store
                            .service_schedule(&snapshot.servers)
                            .unwrap_or_default(),
                        after_ssh: state.package_refresh.due(),
                    };
                    let startup =
                        startup_monitoring::active(startup_deadline, &state.startup_cancel);
                    let awaiting: std::collections::HashSet<_> =
                        snapshot.awaiting_first_check.iter().collect();
                    let eligible = snapshot.servers.iter().filter(|server| {
                        if active.occupied(&server.id) {
                            return false;
                        }
                        !(startup
                            && awaiting.contains(&server.id)
                            && book.enabled("metrics", &server.id, ""))
                    });
                    let mut slots = snapshot
                        .settings
                        .concurrency
                        .saturating_sub(active.background_count());
                    for (server, work) in schedule.due(eligible, &book, now(), Instant::now()) {
                        if slots == 0 {
                            break;
                        }
                        let state = state.clone();
                        let app = app.clone();
                        let id = server.id.clone();
                        match work {
                            collector_schedule::Work::AfterSsh => {
                                let Some(job) = state.package_refresh.claim(
                                    &id,
                                    &server.endpoint,
                                    Instant::now(),
                                ) else {
                                    continue;
                                };
                                jobs.spawn(monitoring::trigger("schedule", async move {
                                    packages::refresh_after_ssh(state, id, job).await;
                                    let _ = app.emit("state-changed", ());
                                }));
                            }
                            collector_schedule::Work::Scheduled { kind, instance } => {
                                jobs.spawn(monitoring::trigger("schedule", async move {
                                    match monitoring::definition(&kind).map(|d| d.runner) {
                                        Ok(monitoring::Runner::Metrics) => {
                                            let _ = poll(state, id, app.clone()).await;
                                        }
                                        Ok(monitoring::Runner::Logs) => {
                                            let _ = logs::collect(state, id).await;
                                        }
                                        Ok(monitoring::Runner::Packages) => {
                                            let _ = packages::collect(state, id).await;
                                        }
                                        Ok(monitoring::Runner::Service) => {
                                            let _ =
                                                services::refresh_for(state, id, kind, instance)
                                                    .await;
                                        }
                                        _ => (),
                                    }
                                    let _ = app.emit("state-changed", ());
                                }));
                            }
                        }
                        slots -= 1;
                    }
                    if now() >= inventory_at {
                        for source in snapshot.sources.iter().filter(|s| s.kind == "ansible") {
                            if let Err(error) =
                                monitoring::trigger("schedule", sync_source(&state, source)).await
                            {
                                let _ = state.store.source_error(source, error);
                            }
                        }
                        inventory_at = now() + 300;
                        let _ = app.emit("state-changed", ());
                    }
                }
            }
            let time = Instant::now();
            let next = state
                .package_refresh
                .due()
                .into_values()
                .filter(|at| *at > time)
                .min()
                .unwrap_or(time + Duration::from_secs(5))
                .min(time + Duration::from_secs(5));
            tokio::select! {
                _ = tokio::time::sleep_until(next.into()) => (),
                _ = state.package_refresh.wake.notified() => (),
            }
        }
    });
}

pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            console::console_open,
            console::console_send,
            console::console_close,
            fleet_console::prepare_console_batch,
            fleet_console::start_console_batch,
            fleet_console::console_batch_status,
            fleet_console::console_batch_output,
            fleet_console::stop_console_batch,
            checks_view,
            new_check,
            save_check_version,
            test_check_version,
            preview_check_version,
            activate_check,
            disable_check,
            discard_check_version,
            delete_check,
            run_checks,
            create_check_with_agent,
            snapshot,
            activity_log,
            local_resource_sample,
            monitoring_catalog,
            monitoring_library,
            monitoring_sources,
            monitoring_policy,
            configure_monitoring,
            notification_status,
            configure_notifications,
            test_notification,
            request_notification_permission,
            open_notification_settings,
            take_notification_target,
            pick_inventory_file,
            add_source,
            refresh_source,
            delete_source,
            update_settings,
            history,
            poll_server,
            diagnose,
            log_summary,
            list_service_instances,
            add_service_instance,
            remove_service_instance,
            service_catalog,
            service_summary,
            configure_service,
            refresh_service,
            storage_status,
            vulnerability_summary,
            vulnerability_catalog,
            vulnerability_catalog_detail,
            set_vulnerability_hidden,
            refresh_packages,
            refresh_apt,
            advisory_status,
            refresh_advisories,
            action_requests,
            action_request,
            open_action_approval,
            decide_action,
            cancel_action,
            revoke_action_grant,
            refresh_action_result,
            rollback_action,
            ai_profiles,
            configure_ai_profiles,
            agent_models,
            detect_agents,
            open_ai_settings,
            server_directory,
            open_server_sidebar,
            start_investigation,
            start_console_chat,
            investigations,
            investigation,
            cancel_investigation,
            open_server,
            resolve_incident,
            resolve_incidents,
            incident_groups,
            incident_group,
            server_dependencies,
            save_server_dependencies,
            start_group_investigation,
            group_investigations,
            auto_status,
            resume_auto,
            dismiss_auto_job
        ])
        .setup(|app| {
            let args = std::env::args().collect::<Vec<_>>();
            let notification_smoke =
                args.get(1).map(String::as_str) == Some("--notification-smoke");
            let root = if notification_smoke {
                let root = PathBuf::from(
                    args.get(2)
                        .ok_or("Need an empty absolute directory for notification-smoke")?,
                );
                if !root.is_absolute()
                    || root.exists() && std::fs::read_dir(&root)?.next().is_some()
                {
                    return Err(
                        "The notification stand requires an empty separate directory".into(),
                    );
                }
                root
            } else {
                std::env::var_os("CYBERBOT_DATA_DIR")
                    .map(PathBuf::from)
                    .unwrap_or(app.path().app_data_dir()?)
            };
            std::fs::create_dir_all(&root)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
            }
            let state = create_state(root)?;
            if notification_smoke {
                std::fs::write(
                    state.root.join("fixture.pid"),
                    std::process::id().to_string(),
                )?;
            }
            activity::install(&state.root, &state.store.snapshot()?.servers);
            app.manage(state.clone());
            let _ = state.app.set(app.handle().clone());
            let main_window = window_size::create_main(app.handle(), &state.root)?;
            power::install(app.handle().clone(), state.clone());
            ai_actions::install_events(app.handle().clone());
            main_window.show()?;
            window_size::track(&main_window, &state.root);
            notifications::start(app.handle().clone(), state.clone());
            if notification_smoke {
                notifications::seed_smoke(state.clone(), app.handle().clone())?;
            }
            let show = MenuItem::with_id(app, "show", "Open Cyberbot", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit Cyberbot", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            TrayIconBuilder::new()
                .icon(tauri::include_image!("icons/tray/44x44.png"))
                .icon_as_template(true)
                .tooltip("Cyberbot")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "quit" => {
                        let state = app.state::<Arc<AppState>>();
                        state.stop.store(true, Ordering::Relaxed);
                        state.startup_cancel.cancel();
                        state.fleet_console.shutdown();
                        ssh_pool::shutdown_global();
                        process::kill_all();
                        app.exit(0);
                    }
                    _ => {}
                })
                .build(app)?;
            background(app.handle().clone(), state);
            Ok(())
        })
        .on_window_event(|window, event| {
            if matches!(
                event,
                tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed
            ) {
                if let Some(state) = window.try_state::<Arc<AppState>>() {
                    state.consoles.close_window(window.label());
                }
            }
            if window.label() == "main" {
                match event {
                    tauri::WindowEvent::Moved(_) | tauri::WindowEvent::Resized(_) => {
                        window_size::geometry_changed(window);
                    }
                    tauri::WindowEvent::CloseRequested { api, .. } => {
                        api.prevent_close();
                        window_size::flush(window.app_handle());
                        activity::info("app", "window_hidden", None);
                        let _ = window.hide();
                    }
                    _ => {}
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("Cyberbot could not start");
    app.run(|app, event| match event {
        tauri::RunEvent::ExitRequested { .. } => window_size::flush(app),
        tauri::RunEvent::Exit => {
            activity::info("app", "shutdown", None);
            if let Some(state) = app.try_state::<Arc<AppState>>() {
                state.stop.store(true, Ordering::Relaxed);
                state.startup_cancel.cancel();
                state.fleet_console.shutdown();
            }
            ssh_pool::shutdown_global();
            process::kill_all();
        }
        _ => {}
    });
}

#[cfg(test)]
mod investigation_tests {
    use super::*;
    #[tokio::test]
    async fn source_names_are_derived_without_user_supplied_names() {
        let root = tempfile::tempdir().unwrap();
        let state = create_state(root.path().to_owned()).unwrap();
        let source = Source {
            id: "manual".into(),
            name: String::new(),
            kind: "manual".into(),
            location: "# servers\n10.20.1.10\nops@web.example.com".into(),
            last_sync: None,
            error: None,
        };
        assert_eq!(sync_source(&state, &source).await.unwrap(), 2);
        let snapshot = state.store.snapshot().unwrap();
        assert_eq!(snapshot.sources[0].name, "10.20.1.10, ops@web.example.com");
        assert_eq!(snapshot.servers[0].name, "10.20.1.10");
        assert_eq!(snapshot.servers[1].name, "ops@web.example.com");

        let path = root.path().join("inventory.ini");
        std::fs::write(&path, "[web]\nweb ansible_user=ops").unwrap();
        let source = Source {
            id: "ansible".into(),
            kind: "ansible".into(),
            location: path.to_str().unwrap().into(),
            ..source
        };
        assert_eq!(sync_source(&state, &source).await.unwrap(), 1);
        assert_eq!(
            state.store.snapshot().unwrap().sources[1].name,
            "inventory.ini"
        );
    }
    #[test]
    fn migration_recovery_and_retention() {
        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("cyberbot.sqlite");
        let old = rusqlite::Connection::open(&db).unwrap();
        old.execute_batch("PRAGMA user_version=1;").unwrap();
        drop(old);
        let state = create_state(root.path().to_owned()).unwrap();
        for n in 0..55 {
            state
                .store
                .save_investigation(&agents::Investigation {
                    usage_started: false,
                    model_profile: None,
                    actual_model: None,
                    scope_endpoints: Default::default(),
                    group_id: None,
                    authoring_id: None,
                    origin: "manual".into(),
                    usage_complete: false,
                    id: format!("r{n}"),
                    agent: "codex".into(),
                    server_ids: vec!["s".into()],
                    question: "test".into(),
                    status: if n == 54 { "running" } else { "completed" }.into(),
                    started_at: now() - 100 + n,
                    ended_at: None,
                    text: "evidence".into(),
                    error: None,
                    usage: serde_json::json!({"inputTokens":42}),
                    audit: vec![],
                    chat: None,
                    session_id: None,
                })
                .unwrap();
        }
        drop(state);
        let restored = create_state(root.path().to_owned()).unwrap();
        let runs = restored.investigator.all().unwrap();
        assert_eq!(runs.len(), 50);
        let interrupted = runs.iter().find(|r| r.id == "r54").unwrap();
        assert_eq!(interrupted.status, "interrupted");
        assert_eq!(interrupted.usage["inputTokens"], 42);
        assert!(runs.iter().all(|r| r.status != "running"));
        let newer = rusqlite::Connection::open(root.path().join("newer.sqlite")).unwrap();
        newer.execute_batch("PRAGMA user_version=99;").unwrap();
        drop(newer);
        assert!(Store::open(&root.path().join("newer.sqlite")).is_err());
    }
}
