//! Give each server's first metrics attempt priority during desktop startup.
use crate::{activity, collect_metrics, monitoring, ssh_pool, AppState};
use std::{
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};
use tauri::Emitter;
use tokio::{task::JoinSet, time::MissedTickBehavior};
use tokio_util::sync::CancellationToken;

pub(crate) const WINDOW: Duration = Duration::from_secs(60);
pub(crate) const TRIGGER: &str = "startup";
const PERIOD: Duration = Duration::from_millis(500);
const PARALLEL: usize = 64;
const BATCH: usize = 16;

pub(crate) fn active(deadline: Instant, cancelled: &CancellationToken) -> bool {
    !cancelled.is_cancelled() && Instant::now() < deadline
}

pub(crate) async fn run(app: tauri::AppHandle, state: Arc<AppState>, deadline: Instant) {
    let Ok(pool) = ssh_pool::global() else { return };
    let mut ticker = tokio::time::interval(PERIOD);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let until = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
    tokio::pin!(until);
    let mut jobs = JoinSet::new();
    let mut expanded = false;
    loop {
        tokio::select! {
            biased;
            _ = state.startup_cancel.cancelled() => break,
            _ = &mut until => break,
            _ = ticker.tick() => (),
        }
        publish_completed(&app, &mut jobs);
        if state.stop.load(Ordering::Relaxed) || !active(deadline, &state.startup_cancel) {
            break;
        }
        let Ok(activity) = state.collectors.snapshot() else {
            continue;
        };
        let slots = BATCH.min(PARALLEL.saturating_sub(activity.background_count().max(jobs.len())));
        if slots == 0 {
            continue;
        }
        let Ok(targets) = state.store.startup_metrics_targets() else {
            continue;
        };
        for id in targets
            .into_iter()
            .filter(|id| !activity.occupied(id))
            .take(slots)
        {
            if !expanded {
                pool.startup_until(Some(deadline));
                expanded = true;
            }
            let state = state.clone();
            jobs.spawn(async move {
                let result = monitoring::trigger(
                    TRIGGER,
                    monitoring::run(
                        &state.store,
                        "metrics",
                        &id,
                        "",
                        poll(&state, &id, deadline),
                    ),
                )
                .await;
                result.unwrap_or(false)
            });
        }
    }
    if expanded {
        pool.startup_until(None);
        let pool = pool.clone();
        tokio::task::spawn_blocking(move || pool.trim_idle());
    }
    // The startup window closes admission, not the checks already in flight.
    while !jobs.is_empty() && !state.stop.load(Ordering::Relaxed) {
        ticker.tick().await;
        publish_completed(&app, &mut jobs);
    }
}

fn publish_completed(app: &tauri::AppHandle, jobs: &mut JoinSet<bool>) {
    let mut updated = false;
    while let Some(result) = jobs.try_join_next() {
        updated |= result.unwrap_or(false);
    }
    if updated {
        let _ = app.emit("state-changed", ());
    }
}

async fn poll(state: &AppState, id: &str, deadline: Instant) -> Result<bool, String> {
    let Some(_slot) = state.collectors.try_background(id, PARALLEL)? else {
        return Ok(false);
    };
    let Some(server) = state.store.startup_metrics_server(id)? else {
        return Ok(false);
    };
    if !active(deadline, &state.startup_cancel) || state.stop.load(Ordering::Relaxed) {
        return Ok(false);
    }
    let mut span = activity::begin("server", "poll", activity::id_target(id));
    let result = collect_metrics(state, &server).await;
    span.result(&result);
    // An SSH failure can also update the displayed availability.
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{inventory, model::Source, monitoring::Overrides, store::Store};

    #[tokio::test]
    async fn startup_selects_only_pending_enabled_metrics_and_respects_pause_and_wake() {
        let root = tempfile::tempdir().unwrap();
        let state = crate::create_state(root.path().to_owned()).unwrap();
        let store: &Store = &state.store;
        let source = Source {
            id: "startup".into(),
            name: "Startup fixture".into(),
            kind: "manual".into(),
            location: "ops@pending.invalid\nops@checked.invalid\nops@disabled.invalid".into(),
            last_sync: None,
            error: None,
        };
        store
            .import(&source, inventory::parse_manual(&source.location).unwrap())
            .unwrap();
        let snapshot = store.snapshot().unwrap();
        let server = |host| {
            snapshot
                .servers
                .iter()
                .find(|server| server.endpoint.host == host)
                .unwrap()
        };
        let checked = server("checked.invalid");
        let pending = &server("pending.invalid").id;
        let disabled = monitoring::scope("metrics", Some(&server("disabled.invalid").id), None);
        let revision = store.monitoring_policy(&disabled).unwrap().revision;
        store
            .set_monitoring(
                &disabled,
                Overrides {
                    enabled: Some(false),
                    ..Default::default()
                },
                revision,
            )
            .unwrap();
        let attempt = store.begin_metrics_check(checked).unwrap();
        store
            .record_metrics(&attempt, checked, Err("fixture unavailable".into()), 180)
            .unwrap();
        assert_eq!(store.startup_metrics_targets().unwrap(), [pending.clone()]);

        // A deadline can expire while a worker is getting a slot. It must not
        // change the server's first-check status or open a connection.
        let elapsed = Instant::now();
        assert!(!poll(&state, pending, elapsed).await.unwrap());
        assert_eq!(store.startup_metrics_targets().unwrap(), [pending.clone()]);

        store
            .update_settings(serde_json::from_str(r#"{"paused":true}"#).unwrap())
            .unwrap();
        assert!(store.startup_metrics_targets().unwrap().is_empty());
        assert!(store.startup_metrics_server(pending).unwrap().is_none());
        store
            .update_settings(serde_json::from_str(r#"{"paused":false}"#).unwrap())
            .unwrap();
        assert_eq!(store.startup_metrics_targets().unwrap(), [pending.clone()]);
        store.suspend_metrics_checks().unwrap();
        assert!(store.startup_metrics_targets().unwrap().is_empty());
        assert!(store.startup_metrics_server(pending).unwrap().is_none());
    }
}
