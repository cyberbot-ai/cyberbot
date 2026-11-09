//! Process-local freshness, independent of persisted metrics and wall-clock age.
use crate::model::{Endpoint, Server};
use std::collections::HashMap;

#[derive(Clone)]
pub(crate) struct Attempt {
    epoch: u64,
    identity: u64,
    id: String,
    endpoint: String,
}

struct Entry {
    identity: u64,
    endpoint: String,
    checked: bool,
    due: i64,
}
#[derive(Default)]
pub(crate) struct Runtime {
    epoch: u64,
    suspended: bool,
    identity: u64,
    entries: HashMap<String, Entry>,
}
fn endpoint(value: &Endpoint) -> Result<String, String> {
    serde_json::to_string(value).map_err(|e| e.to_string())
}
fn first_due(id: &str, at: i64) -> i64 {
    let jitter = id
        .bytes()
        .fold(0_u64, |n, b| n.wrapping_mul(31).wrapping_add(u64::from(b)))
        % 31;
    at + jitter as i64
}
impl Runtime {
    pub fn reset(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.suspended = false;
        self.entries.clear();
    }
    pub fn suspend(&mut self) -> u64 {
        self.reset();
        self.suspended = true;
        self.epoch
    }
    pub fn resume(&mut self, epoch: u64) {
        if self.epoch == epoch {
            self.suspended = false;
            // Start the spreading window after the old pool has actually closed.
            self.entries.clear();
        }
    }
    pub fn reschedule(&mut self, at: i64, enabled: impl Fn(&str) -> bool) {
        for (id, entry) in self.entries.iter_mut().filter(|(id, _)| enabled(id)) {
            entry.checked = false;
            entry.due = first_due(id, at);
        }
    }
    fn ensure(&mut self, server: &Server, at: i64) -> Result<(), String> {
        let value = endpoint(&server.endpoint)?;
        if self
            .entries
            .get(&server.id)
            .is_none_or(|e| e.endpoint != value)
        {
            self.identity = self
                .identity
                .checked_add(1)
                .ok_or("Check sequence limit reached")?;
            self.entries.insert(
                server.id.clone(),
                Entry {
                    identity: self.identity,
                    endpoint: value,
                    checked: false,
                    due: first_due(&server.id, at),
                },
            );
        }
        Ok(())
    }
    pub fn sync(&mut self, servers: &[Server], at: i64) -> Result<(), String> {
        let ids: std::collections::HashSet<_> = servers.iter().map(|s| s.id.as_str()).collect();
        self.entries.retain(|id, _| ids.contains(id.as_str()));
        for server in servers {
            self.ensure(server, at)?;
        }
        Ok(())
    }
    pub fn pending(&self, server: &Server) -> Option<i64> {
        self.entries
            .get(&server.id)
            .filter(|e| !e.checked)
            .map(|e| if self.suspended { i64::MAX } else { e.due })
    }
    pub fn begin(&mut self, server: &Server, at: i64) -> Result<Attempt, String> {
        if self.suspended {
            return Err("Waiting for SSH to reconnect after sleep".into());
        }
        self.ensure(server, at)?;
        let e = &self.entries[&server.id];
        Ok(Attempt {
            epoch: self.epoch,
            identity: e.identity,
            id: server.id.clone(),
            endpoint: e.endpoint.clone(),
        })
    }
    pub fn accepts(&self, attempt: &Attempt, server: &Server) -> bool {
        !self.suspended
            && self.epoch == attempt.epoch
            && server.id == attempt.id
            && endpoint(&server.endpoint).ok().as_ref() == Some(&attempt.endpoint)
            && self
                .entries
                .get(&server.id)
                .is_some_and(|e| e.identity == attempt.identity && e.endpoint == attempt.endpoint)
    }
    pub fn complete(&mut self, attempt: &Attempt) {
        if let Some(e) = self.entries.get_mut(&attempt.id) {
            e.checked = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{model::*, store::Store};
    use std::path::Path;
    fn source() -> Source {
        Source {
            id: "fixture".into(),
            name: "Fixture".into(),
            kind: "manual".into(),
            location: "root@node.invalid".into(),
            last_sync: None,
            error: None,
        }
    }
    fn seed(db: &Store) -> Server {
        db.import(
            &source(),
            crate::inventory::parse_manual(&source().location).unwrap(),
        )
        .unwrap();
        db.snapshot().unwrap().servers.remove(0)
    }
    fn metrics() -> Observation {
        serde_json::from_value(serde_json::json!({"at":now(),"cpuPercent":10,"memoryPercent":20,"swapPercent":0,"load":1,"uptime":100,"disks":[{"mount":"/","usedPercent":20,"inodePercent":1}],"services":[],"missing":[],"bytesReceived":500,"durationMs":10})).unwrap()
    }
    #[test]
    fn reopening_preserves_history_but_requires_new_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture.sqlite");
        let db = Store::open(&path).unwrap();
        let server = seed(&db);
        let initial = db.snapshot().unwrap();
        assert_eq!(initial.awaiting_first_check, vec![server.id.clone()]);
        assert!((now()..=now() + 30).contains(&initial.servers[0].next_check));
        let attempt = db.begin_metrics_check(&server).unwrap();
        assert_eq!(db.snapshot().unwrap().awaiting_first_check.len(), 1);
        db.record_metrics(&attempt, &server, Ok(metrics()), 180)
            .unwrap();
        assert!(db.snapshot().unwrap().awaiting_first_check.is_empty());
        drop(db);
        let reopened = Store::open(&path).unwrap();
        assert_eq!(
            reopened.snapshot().unwrap().awaiting_first_check,
            vec![server.id.clone()]
        );
        assert_eq!(reopened.history(&server.id).unwrap().len(), 1);
        assert_eq!(
            reopened
                .0
                .lock()
                .unwrap()
                .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            18
        );
    }
    #[test]
    fn systemd_discovery_advances_diagnostics_on_startup_recovery_and_state_changes() {
        let db = Store::open(Path::new(":memory:")).unwrap();
        let server = seed(&db);
        let at = now();
        let later = at + 900;
        let kind = "fail2ban";
        let next_check = || db.service_state(&server.id, kind).unwrap().next_check;
        let postpone = || {
            db.0.lock()
                .unwrap()
                .execute(
                    "UPDATE service_state SET payload=json_set(payload,'$.nextCheck',?2)
                 WHERE server_id=?1 AND kind='fail2ban' AND instance_id='default'",
                    rusqlite::params![server.id, later],
                )
                .unwrap();
        };
        let observe = |name: &str, state: &str| {
            let mut observation = metrics();
            observation.services.push(ServiceStatus {
                name: name.into(),
                state: state.into(),
            });
            db.record(&server, Ok(observation), 180).unwrap();
        };
        observe("fail2ban.service", "failed");
        assert!((at..=now()).contains(&next_check()));

        postpone();
        observe("fail2ban.service", "failed");
        assert_eq!(next_check(), later);

        db.reset_metrics_checks().unwrap();
        observe("fail2ban.service", "failed");
        assert!(next_check() <= now());

        postpone();
        db.record(&server, Err("connection refused".into()), 180)
            .unwrap();
        observe("fail2ban.service", "failed");
        assert!(next_check() <= now());

        postpone();
        observe("fail2ban.service", "active");
        assert!(next_check() <= now());

        postpone();
        observe("fail2ban-exporter.service", "failed");
        assert_eq!(next_check(), later);
        observe("fail2ban.service", "inactive");
        assert!(next_check() <= now());

        let scope = crate::monitoring::scope(kind, Some(&server.id), None);
        let policy = db.monitoring_policy(&scope).unwrap();
        db.set_monitoring(
            &scope,
            crate::monitoring::Overrides {
                enabled: Some(false),
                ..Default::default()
            },
            policy.revision,
        )
        .unwrap();
        postpone();
        observe("fail2ban.service", "active");
        assert_eq!(next_check(), later);
    }
    #[test]
    fn wake_discards_old_replies_and_first_transport_failure_ends_waiting() {
        let db = Store::open(Path::new(":memory:")).unwrap();
        let server = seed(&db);
        let old = db.begin_metrics_check(&server).unwrap();
        db.reset_metrics_checks().unwrap();
        assert!(db
            .record_metrics(&old, &server, Err("old timeout".into()), 180)
            .is_err());
        assert!(db.snapshot().unwrap().servers[0].last_error.is_none());
        assert!(db.snapshot().unwrap().incidents.is_empty());
        let current = db.begin_metrics_check(&server).unwrap();
        db.record_metrics(&current, &server, Err("connection refused".into()), 180)
            .unwrap();
        let view = db.snapshot().unwrap();
        assert!(view.awaiting_first_check.is_empty());
        assert_eq!(
            view.servers[0].last_error.as_deref(),
            Some("connection refused")
        );
        db.reset_metrics_checks().unwrap();
        assert_eq!(db.snapshot().unwrap().awaiting_first_check, vec![server.id]);
    }
    #[test]
    fn database_failure_never_marks_a_check_complete() {
        let db = Store::open(Path::new(":memory:")).unwrap();
        let server = seed(&db);
        let attempt = db.begin_metrics_check(&server).unwrap();
        db.0.lock().unwrap().execute_batch("CREATE TRIGGER fail_record BEFORE UPDATE ON servers BEGIN SELECT RAISE(ABORT,'fixture failure'); END;").unwrap();
        assert!(db
            .record_metrics(&attempt, &server, Ok(metrics()), 180)
            .is_err());
        assert_eq!(db.snapshot().unwrap().awaiting_first_check.len(), 1);
        assert!(db.history(&server.id).unwrap().is_empty());
        db.0.lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_record")
            .unwrap();
        db.record_metrics(&attempt, &server, Ok(metrics()), 180)
            .unwrap();
        assert!(db.snapshot().unwrap().awaiting_first_check.is_empty());
    }
    #[test]
    fn changing_endpoint_back_or_deleting_and_readding_cannot_revive_old_attempts() {
        let db = Store::open(Path::new(":memory:")).unwrap();
        let server = seed(&db);
        let old = db.begin_metrics_check(&server).unwrap();
        let mut hosts = crate::inventory::parse_manual(&source().location).unwrap();
        hosts[0].endpoint.port = 2222;
        db.import(&source(), hosts).unwrap();
        seed(&db);
        assert!(db
            .record_metrics(&old, &server, Ok(metrics()), 180)
            .is_err());
        let removed = db.begin_metrics_check(&server).unwrap();
        db.delete_source(&source().id).unwrap();
        seed(&db);
        assert!(db
            .record_metrics(&removed, &server, Ok(metrics()), 180)
            .is_err());
        assert_eq!(db.snapshot().unwrap().awaiting_first_check.len(), 1);
    }
    #[test]
    fn a_large_fleet_has_staggered_bounded_first_checks_without_connections() {
        let db = Store::open(Path::new(":memory:")).unwrap();
        let text = (0..500)
            .map(|i| format!("node-{i}.invalid"))
            .collect::<Vec<_>>()
            .join("\n");
        db.import(&source(), crate::inventory::parse_manual(&text).unwrap())
            .unwrap();
        let snapshot = db.snapshot().unwrap();
        let at = now();
        assert_eq!(snapshot.awaiting_first_check.len(), 500);
        let deadlines: std::collections::HashSet<_> =
            snapshot.servers.iter().map(|s| s.next_check).collect();
        assert!(deadlines.len() > 20);
        assert!(deadlines.iter().all(|t| *t >= at - 1 && *t <= at + 30));
        assert!(snapshot.servers.iter().all(|s| s.last_attempt.is_none()));
    }
    #[test]
    fn wake_blocks_new_metrics_until_cleanup_and_ignores_an_older_cleanup_completion() {
        let db = Store::open(Path::new(":memory:")).unwrap();
        let server = seed(&db);
        let old = db.begin_metrics_check(&server).unwrap();
        let first = db.suspend_metrics_checks().unwrap();
        assert!(db.begin_metrics_check(&server).is_err());
        assert!(db
            .record_metrics(&old, &server, Err("closed by wake cleanup".into()), 180)
            .is_err());
        assert!(db.snapshot().unwrap().servers[0].last_error.is_none());
        assert_eq!(db.snapshot().unwrap().awaiting_first_check.len(), 1);
        let second = db.suspend_metrics_checks().unwrap();
        db.resume_metrics_checks(first).unwrap();
        assert!(db.begin_metrics_check(&server).is_err());
        db.resume_metrics_checks(second).unwrap();
        let snapshot = db.snapshot().unwrap();
        assert!((now()..=now() + 30).contains(&snapshot.servers[0].next_check));
        let current = db.begin_metrics_check(&server).unwrap();
        db.record_metrics(&current, &server, Ok(metrics()), 180)
            .unwrap();
        assert!(db.snapshot().unwrap().awaiting_first_check.is_empty());
    }
}
