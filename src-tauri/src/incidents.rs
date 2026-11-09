//! User resolution closes the current episode, not the underlying monitoring signal.
use crate::{automation, model::Incident, store::Store};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct IncidentEpisode {
    id: String,
    episode: String,
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        inventory,
        model::{now, Server, Settings, Source},
    };
    fn fixture(n: usize) -> (Store, Vec<Server>) {
        let db = Store::open(std::path::Path::new(":memory:")).unwrap();
        let source = Source {
            id: "incidents".into(),
            name: "Fixture".into(),
            kind: "manual".into(),
            location: (0..n)
                .map(|n| format!("root@node-{n}.invalid"))
                .collect::<Vec<_>>()
                .join("\n"),
            last_sync: None,
            error: None,
        };
        db.import(&source, inventory::parse_manual(&source.location).unwrap())
            .unwrap();
        db.save_settings(&Settings {
            mode: "auto".into(),
            daily_run_limit: Some(10),
            daily_token_limit: Some(1000000),
            ..Default::default()
        })
        .unwrap();
        let servers = db.snapshot().unwrap().servers;
        (db, servers)
    }
    fn event(db: &Store, s: &Server, bad: bool, at: i64) {
        let mut sql = db.0.lock().unwrap();
        let tx = sql.transaction().unwrap();
        Store::incident(
            &tx,
            &s.id,
            "cpu",
            bad.then(|| "CPU 95%".into()),
            "CPU",
            "warning",
            at,
        )
        .unwrap();
        tx.commit().unwrap();
    }
    #[test]
    fn closes_episode_persistently_without_reopening_on_repeated_bad_samples() {
        let (db, s) = fixture(1);
        let at = now();
        event(&db, &s[0], true, at);
        db.reconcile_auto(at).unwrap();
        let i = db.snapshot().unwrap().incidents.remove(0);
        assert_eq!(db.auto_status(at).unwrap().queued, 1);
        db.resolve_incident(&i.id, &i.episode, at + 1).unwrap();
        for t in 2..20 {
            event(&db, &s[0], true, at + t);
            db.reconcile_auto(at + t).unwrap();
        }
        let closed = db.snapshot().unwrap().incidents.remove(0);
        assert_eq!(closed.status, "resolved");
        assert_eq!(closed.episode, i.episode);
        assert_eq!(closed.resolved_by_user_at, Some(at + 1));
        assert!(closed.manual_resolution_pending);
        assert!(!closed.auto_eligible);
        assert_eq!(db.auto_status(at + 20).unwrap().queued, 0);
        assert!(db.next_auto(at + 20).unwrap().is_none());
        assert!(db
            .resolve_incident(&i.id, &i.episode, at + 21)
            .unwrap()
            .is_empty());
        event(&db, &s[0], false, at + 22);
        event(&db, &s[0], true, at + 23);
        assert!(db.snapshot().unwrap().incidents[0].manual_resolution_pending);
        event(&db, &s[0], false, at + 24);
        event(&db, &s[0], false, at + 25);
        assert!(!db.snapshot().unwrap().incidents[0].manual_resolution_pending);
        event(&db, &s[0], true, at + 26);
        let fresh = db.snapshot().unwrap().incidents.remove(0);
        assert_eq!(fresh.status, "open");
        assert_ne!(fresh.episode, i.episode);
        assert_eq!(fresh.resolved_by_user_at, None);
        assert!(db.resolve_incident(&fresh.id, &i.episode, at + 27).is_err());
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "open");
    }
    #[test]
    fn updates_group_and_queue_without_closing_other_members() {
        let (db, servers) = fixture(3);
        let at = now();
        for s in &servers {
            event(&db, s, true, at);
        }
        db.reconcile_auto(at).unwrap();
        assert_eq!(db.incident_groups(false, 0).unwrap().total, 1);
        let incidents = db.snapshot().unwrap().incidents;
        let g = db.incident_groups(false, 0).unwrap().groups.remove(0);
        db.resolve_incident(&incidents[0].id, &incidents[0].episode, at + 1)
            .unwrap();
        assert_eq!(db.incident_group(&g.id, 0, None).unwrap().open, 2);
        assert_eq!(db.auto_status(at + 1).unwrap().queued, 1);
        let episodes: Vec<_> = incidents[1..]
            .iter()
            .map(|i| IncidentEpisode {
                id: i.id.clone(),
                episode: i.episode.clone(),
            })
            .collect();
        db.resolve_incidents(&episodes, at + 2).unwrap();
        assert_eq!(db.incident_groups(false, 0).unwrap().total, 0);
        assert_eq!(db.auto_status(at + 2).unwrap().queued, 0);
        assert_eq!(db.notification_settings().unwrap().queued, 0);
        assert!(db.next_auto(at + 1000).unwrap().is_none());
    }

    #[test]
    fn stale_episode_rolls_back_the_batch_and_keeps_new_incidents_open() {
        let (db, servers) = fixture(2);
        let at = now();
        for s in &servers {
            event(&db, s, true, at);
        }
        let incidents = db.snapshot().unwrap().incidents;
        let episodes = [
            IncidentEpisode {
                id: incidents[0].id.clone(),
                episode: incidents[0].episode.clone(),
            },
            IncidentEpisode {
                id: incidents[1].id.clone(),
                episode: "previous-episode".into(),
            },
        ];
        assert!(db.resolve_incidents(&episodes, at + 1).is_err());
        assert!(db
            .snapshot()
            .unwrap()
            .incidents
            .iter()
            .all(|i| i.status == "open"));
        assert_eq!(db.notification_settings().unwrap().queued, 2);

        db.resolve_incidents(&episodes[..1], at + 2).unwrap();
        db.resolve_incidents(&episodes[..1], at + 3).unwrap();
        let current = db.snapshot().unwrap().incidents;
        assert_eq!(current[0].resolved_by_user_at, Some(at + 2));
        assert_eq!(current[1].status, "open");
        assert_eq!(db.notification_settings().unwrap().queued, 1);
    }
    #[test]
    fn only_returns_running_auto_job_when_its_last_open_member_is_closed() {
        let (db, servers) = fixture(3);
        let at = now();
        for s in &servers {
            event(&db, s, true, at);
        }
        db.reconcile_auto(at).unwrap();
        db.0.lock().unwrap().execute("UPDATE ai_jobs SET state='running',run_id='auto-run',payload=json_set(payload,'$.state','running','$.runId','auto-run')",[]).unwrap();
        let incidents = db.snapshot().unwrap().incidents;
        for i in &incidents[..2] {
            assert!(db
                .resolve_incident(&i.id, &i.episode, at + 1)
                .unwrap()
                .is_empty());
        }
        let last = &incidents[2];
        assert_eq!(
            db.resolve_incident(&last.id, &last.episode, at + 2)
                .unwrap(),
            vec!["auto-run".to_owned()]
        );
    }
    #[test]
    fn rollback_keeps_incident_queue_and_notification_atomic() {
        let (db, s) = fixture(1);
        let at = now();
        event(&db, &s[0], true, at);
        db.reconcile_auto(at).unwrap();
        let i = db.snapshot().unwrap().incidents.remove(0);
        db.0.lock().unwrap().execute_batch("CREATE TRIGGER fail_resolution BEFORE UPDATE ON ai_jobs BEGIN SELECT RAISE(ABORT,'fixture failure'); END;").unwrap();
        assert!(db.resolve_incident(&i.id, &i.episode, at + 1).is_err());
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "open");
        assert_eq!(db.notification_settings().unwrap().queued, 1);
        assert_eq!(db.auto_status(at + 1).unwrap().queued, 1);
    }
    #[test]
    fn suppression_survives_restart_and_does_not_require_a_schema_migration() {
        let (db, s) = fixture(1);
        let at = now();
        event(&db, &s[0], true, at);
        let i = db.snapshot().unwrap().incidents.remove(0);
        db.resolve_incident(&i.id, &i.episode, at + 1).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("copy.sqlite");
        db.0.lock()
            .unwrap()
            .execute("VACUUM INTO ?1", [file.to_str().unwrap()])
            .unwrap();
        let reopened = Store::open(&file).unwrap();
        event(&reopened, &s[0], true, at + 2);
        assert_eq!(reopened.snapshot().unwrap().incidents[0].status, "resolved");
        assert!(reopened.resolve_incident("missing", "missing", at).is_err());
    }
}

/// Closed manual episodes still need healthy observations to release the suppression latch.
pub(crate) fn needs_observation(db: &Connection, id: &str) -> Result<bool, String> {
    db.query_row("SELECT EXISTS(SELECT 1 FROM incidents WHERE id=?1 AND (json_extract(payload,'$.status')='open' OR json_extract(payload,'$.manualResolutionPending')=1))",[id],|r|r.get(0)).map_err(err)
}
impl Store {
    pub(crate) fn incident_server(&self, id: &str) -> Result<String, String> {
        self.0
            .lock()
            .map_err(err)?
            .query_row("SELECT server_id FROM incidents WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .map_err(err)
    }
    /// Returns only automatic runs made obsolete by resolving their final open episode.
    pub(crate) fn resolve_incident(
        &self,
        id: &str,
        episode: &str,
        at: i64,
    ) -> Result<Vec<String>, String> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        let cancel = resolve_in_transaction(&tx, id, episode, at, true)?;
        tx.commit().map_err(err)?;
        Ok(cancel)
    }

    pub(crate) fn resolve_incidents(
        &self,
        episodes: &[IncidentEpisode],
        at: i64,
    ) -> Result<Vec<String>, String> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        let mut resolved = Vec::new();
        for item in episodes {
            if mark_resolved(&tx, &item.id, &item.episode, at, true)? {
                resolved.push(item.id.as_str());
            }
        }
        let cancel = finish_resolution(&tx, &resolved, at)?;
        tx.commit().map_err(err)?;
        Ok(cancel)
    }
}

pub(crate) fn resolve_in_transaction(
    tx: &Connection,
    id: &str,
    episode: &str,
    at: i64,
    hide_related: bool,
) -> Result<Vec<String>, String> {
    if mark_resolved(tx, id, episode, at, hide_related)? {
        finish_resolution(tx, &[id], at)
    } else {
        Ok(vec![])
    }
}

fn mark_resolved(
    tx: &Connection,
    id: &str,
    episode: &str,
    at: i64,
    hide_related: bool,
) -> Result<bool, String> {
    if id.len() > 128 || episode.len() > 256 {
        return Err("Incorrect Incident Identification".into());
    }
    let raw: Option<String> = tx
        .query_row("SELECT payload FROM incidents WHERE id=?1", [id], |r| {
            r.get(0)
        })
        .optional()
        .map_err(err)?;
    let mut i: Incident = serde_json::from_str(&raw.ok_or("Incident deleted")?).map_err(err)?;
    if automation::episode(&i) != episode {
        return Err("The episode of the incident has changed.".into());
    }
    if i.status != "open" {
        return Ok(false);
    }
    if hide_related {
        crate::vulnerabilities::hide_incident_findings(tx, &i, at)?;
    }
    i.status = "resolved".into();
    i.resolved_by_user_at = Some(at);
    i.manual_resolution_pending = true;
    i.healthy_streak = 0;
    i.auto_eligible = false;
    i.fresh_until = Some(at - 1);
    i.updated_at = at;
    tx.execute(
        "UPDATE incidents SET payload=?2 WHERE id=?1",
        params![id, serde_json::to_string(&i).map_err(err)?],
    )
    .map_err(err)?;
    crate::services::resolve_deviation(tx, &i)?;
    crate::notifications::suppress_incident(tx, id, &i.episode)?;
    Ok(true)
}

fn finish_resolution(tx: &Connection, resolved: &[&str], at: i64) -> Result<Vec<String>, String> {
    if resolved.is_empty() {
        return Ok(vec![]);
    }
    let incidents = Store::list(tx, "incidents")?;
    let servers = Store::list(tx, "servers")?;
    let jobs = Store::list(tx, "ai_jobs")?;
    crate::correlation::reconcile(tx, &incidents, &servers, &jobs, at)?;
    let ids = serde_json::to_string(resolved).map_err(err)?;
    let affected = "((json_extract(payload,'$.groupId') IS NULL AND incident_id IN (SELECT value FROM json_each(?1)))
        OR json_extract(payload,'$.groupId') IN (SELECT id FROM incident_groups WHERE status!='open'))";
    let cancel = {
        let mut q=tx.prepare(&format!("SELECT DISTINCT run_id FROM ai_jobs WHERE state='running' AND run_id IS NOT NULL AND {affected}")).map_err(err)?;
        let rows = q
            .query_map([&ids], |r| r.get(0))
            .map_err(err)?
            .collect::<std::result::Result<Vec<String>, _>>()
            .map_err(err)?;
        rows
    };
    tx.execute(&format!("UPDATE ai_jobs SET state='obsolete',payload=json_set(payload,'$.state','obsolete') WHERE state IN ('queued','suppressed') AND {affected}"),[&ids]).map_err(err)?;
    Ok(cancel)
}
