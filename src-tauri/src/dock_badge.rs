use crate::{model::Server, monitoring, store::Store};
use std::collections::HashSet;

impl Store {
    fn dock_badge_count(&self, at: i64) -> Result<i64, String> {
        let db = self.0.lock().map_err(|e| e.to_string())?;
        let settings = Self::read_settings(&db)?;
        if !settings.dock_badge_enabled {
            return Ok(0);
        }

        let mut server_ids: HashSet<String> = {
            let mut query = db
                .prepare("SELECT DISTINCT server_id FROM incidents WHERE json_extract(payload,'$.status')='open'")
                .map_err(|e| e.to_string())?;
            let rows = query
                .query_map([], |row| row.get(0))
                .map_err(|e| e.to_string())?;
            rows.collect::<Result<_, _>>().map_err(|e| e.to_string())?
        };
        if self.connectivity().offline() {
            return Ok(server_ids.len() as i64);
        }

        let (servers, awaiting_first_check) = self.fleet_servers(&db, at)?;
        if servers.is_empty() {
            return Ok(server_ids.len() as i64);
        }
        let awaiting_first_check: HashSet<_> =
            awaiting_first_check.iter().map(String::as_str).collect();
        let book = monitoring::Book::load(&db)?;
        let services = Self::service_cards(&db)?;
        let checks = crate::checks::statuses(&db)?;
        let logs = Self::log_statuses(&db, settings.log_poll_seconds)?;
        let vulnerabilities = Self::vulnerability_cards(&db)?;
        for server in servers {
            let id = &server.id;
            if server_ids.contains(id) {
                continue;
            }
            let metrics = book
                .resolve(&monitoring::scope("metrics", Some(id), None))?
                .values;
            let known_critical = services
                .get(id)
                .is_some_and(|cards| cards.iter().any(|card| card.status == "critical"))
                || [checks.get(id), logs.get(id)]
                    .into_iter()
                    .flatten()
                    .any(|s| s == "critical")
                || vulnerabilities
                    .get(id)
                    .is_some_and(|card| card.affected > 0);
            if is_critical(
                &server,
                &metrics,
                awaiting_first_check.contains(id.as_str()),
                known_critical,
                at,
            ) {
                server_ids.insert(server.id);
            }
        }
        Ok(server_ids.len() as i64)
    }
}

// Match the Critical result of src/health.ts, including when newer metrics are unavailable.
fn is_critical(
    server: &Server,
    metrics: &monitoring::Values,
    awaiting_first_check: bool,
    known_critical: bool,
    at: i64,
) -> bool {
    if awaiting_first_check || !metrics.enabled {
        return known_critical;
    }
    if server.last_error.is_some() {
        return false;
    }
    let Some(observation) = &server.observation else {
        return known_critical;
    };
    if at.saturating_sub(observation.at) > (metrics.interval_seconds * 2 + 30) as i64 {
        return false;
    }
    let critical = |rule, value: f64| {
        value.is_finite()
            && monitoring::thresholds::severity(&metrics.thresholds[rule], value) == "critical"
    };
    known_critical
        || observation
            .cpu_percent
            .is_some_and(|value| critical("cpu", value))
        || observation
            .memory_percent
            .is_some_and(|value| critical("memory", value))
        || observation
            .disks
            .iter()
            .any(|disk| critical("disk", disk.used_percent))
}

#[cfg(target_os = "macos")]
pub(crate) fn start(window: tauri::WebviewWindow, state: std::sync::Arc<crate::AppState>) {
    use std::{sync::atomic::Ordering, time::Duration};
    use tauri::{Listener, Manager};
    use tokio::time::{sleep_until, Instant};

    const REFRESH: Duration = Duration::from_secs(15);
    const MIN_INTERVAL: Duration = Duration::from_secs(5);
    let app = window.app_handle().clone();
    let (changed, mut updates) = tokio::sync::watch::channel(());
    let listener = app.listen("state-changed", move |_| changed.send_replace(()));
    tauri::async_runtime::spawn(async move {
        let mut last_count = None;
        while !state.stop.load(Ordering::Relaxed) {
            // Include events received during the wait in the next read.
            updates.borrow_and_update();
            let state = state.clone();
            if let Ok(Ok(count)) = tauri::async_runtime::spawn_blocking(move || {
                state.store.dock_badge_count(crate::model::now())
            })
            .await
            {
                if Some(count) != last_count
                    && crate::notifications::set_dock_badge(&window, count)
                        .await
                        .is_ok()
                {
                    last_count = Some(count);
                }
            }
            let refreshed = Instant::now();
            tokio::select! {
                _ = sleep_until(refreshed + REFRESH) => (),
                result = updates.changed() => {
                    if result.is_err() { break; }
                    sleep_until(refreshed + MIN_INTERVAL).await;
                }
            }
        }
        app.unlisten(listener);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        inventory,
        model::{now, Observation, Source},
    };

    #[test]
    fn counts_each_critical_server_or_server_with_open_incidents_once() {
        let store = Store::open(std::path::Path::new(":memory:")).unwrap();
        let source = Source {
            id: "fleet".into(),
            name: "Test fleet".into(),
            kind: "manual".into(),
            location:
                "ops@critical.invalid\nops@warning.invalid\nops@stale.invalid\nops@failed.invalid"
                    .into(),
            last_sync: None,
            error: None,
        };
        store
            .import(&source, inventory::parse_manual(&source.location).unwrap())
            .unwrap();
        let at = now();
        let servers = store.snapshot().unwrap().servers;
        for (server, cpu, time) in [
            (&servers[0], 97., at),
            (&servers[1], 92., at),
            (&servers[2], 98., at - 391),
            (&servers[3], 99., at),
        ] {
            let observation = Observation {
                at: time,
                cpu_percent: Some(cpu),
                memory_percent: Some(10.),
                swap_percent: None,
                load: None,
                uptime: None,
                disks: vec![],
                services: vec![],
                missing: vec![],
                bytes_received: 0,
                duration_ms: 0,
                service_runtime: vec![],
                service_runtime_complete: false,
                platform: None,
            };
            store.record(server, Ok(observation), 180).unwrap();
        }
        store
            .record(&servers[3], Err("SSH timeout".into()), 180)
            .unwrap();
        let critical = &servers[0].id;
        for incident in store.snapshot().unwrap().incidents {
            if &incident.server_id != critical {
                store
                    .resolve_incident(&incident.id, &incident.episode, at)
                    .unwrap();
            }
        }
        assert_eq!(store.dock_badge_count(at).unwrap(), 1);
        Store::incident(
            &store.0.lock().unwrap(),
            critical,
            "logs:test",
            Some("Fixture".into()),
            "Test incident",
            "critical",
            at,
        )
        .unwrap();

        assert_eq!(store.dock_badge_count(at).unwrap(), 1);
        assert_eq!(store.dock_badge_count(at + 391).unwrap(), 1);
        for incident in store.snapshot().unwrap().incidents {
            if incident.status == "open" {
                store
                    .resolve_incident(&incident.id, &incident.episode, at)
                    .unwrap();
            }
        }
        assert_eq!(store.dock_badge_count(at).unwrap(), 1);
        assert_eq!(store.dock_badge_count(at + 391).unwrap(), 0);

        Store::incident(
            &store.0.lock().unwrap(),
            &servers[1].id,
            "logs:test",
            Some("Fixture".into()),
            "Test incident",
            "warning",
            at,
        )
        .unwrap();
        assert_eq!(store.dock_badge_count(at).unwrap(), 2);
        assert_eq!(store.dock_badge_count(at + 390).unwrap(), 2);
        assert_eq!(store.dock_badge_count(at + 391).unwrap(), 1);
        store
            .update_settings(serde_json::from_str(r#"{"dockBadgeEnabled":false}"#).unwrap())
            .unwrap();
        assert_eq!(store.dock_badge_count(at).unwrap(), 0);
    }

    #[test]
    fn older_settings_enable_the_badge_and_disabling_survives_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cyberbot.sqlite");
        let store = Store::open(&path).unwrap();
        let defaults = store.settings().unwrap();
        assert!(defaults.dock_badge_enabled);
        store
            .0
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO settings VALUES (1, json_remove(?1, '$.dockBadgeEnabled'))",
                [serde_json::to_string(&defaults).unwrap()],
            )
            .unwrap();
        assert!(store.settings().unwrap().dock_badge_enabled);
        store
            .update_settings(serde_json::from_str(r#"{"dockBadgeEnabled":false}"#).unwrap())
            .unwrap();
        drop(store);
        let store = Store::open(&path).unwrap();
        assert!(!store.settings().unwrap().dock_badge_enabled);
    }
}
