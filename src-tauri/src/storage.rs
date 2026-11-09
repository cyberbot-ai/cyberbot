//! Hard SQLite page ceiling plus bounded, resumable retention work.
use crate::{model::now, store::Store};
use rusqlite::{params, Connection};
use serde::Serialize;
use std::path::PathBuf;
const LIMIT: u64 = 1024 * 1024 * 1024;
const WAL_LIMIT: u64 = 32 * 1024 * 1024;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn path(db: &Connection) -> Option<PathBuf> {
    db.query_row("PRAGMA database_list", [], |r| r.get::<_, String>(2))
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}
fn bytes(path: Option<PathBuf>) -> u64 {
    path.and_then(|p| std::fs::metadata(p).ok())
        .map_or(0, |m| m.len())
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub actions: crate::ai_actions::Storage,
    pub activity: crate::activity::Status,
    pub database_bytes: u64,
    pub wal_bytes: u64,
    pub limit_bytes: u64,
    pub cache_bytes: u64,
    pub cache_limit_bytes: u64,
    pub blocked: bool,
    pub message: Option<String>,
}
pub fn configure(db: &Connection) -> Result<(), String> {
    let size: u64 = db
        .pragma_query_value(None, "page_size", |r| r.get(0))
        .map_err(err)?;
    db.pragma_update(None, "max_page_count", LIMIT / size)
        .map_err(err)?;
    db.execute_batch("PRAGMA journal_size_limit=16777216; PRAGMA wal_autocheckpoint=512;")
        .map_err(err)
}
pub fn admit(db: &Connection) -> Result<(), String> {
    if bytes(path(db)) > LIMIT {
        return Err(
            "The database exceeded 1 GiB. Collection is paused until cleanup and compaction."
                .into(),
        );
    }
    let wal = path(db).map(|p| PathBuf::from(format!("{}-wal", p.display())));
    if bytes(wal.clone()) >= WAL_LIMIT {
        let _: Result<(i64, i64, i64), _> =
            db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            });
        if bytes(wal) >= WAL_LIMIT {
            return Err("The SQLite write-ahead log reached its limit. Collection pauses until the database reader finishes.".into());
        }
    }
    let pages: u64 = db
        .pragma_query_value(None, "page_count", |r| r.get(0))
        .map_err(err)?;
    let free: u64 = db
        .pragma_query_value(None, "freelist_count", |r| r.get(0))
        .map_err(err)?;
    let size: u64 = db
        .pragma_query_value(None, "page_size", |r| r.get(0))
        .map_err(err)?;
    if pages.saturating_sub(free) * size >= LIMIT - 8 * 1024 * 1024 {
        return Err(
            "The SQLite database reached its 1 GiB limit. Collection pauses until cleanup.".into(),
        );
    }
    Ok(())
}
impl Store {
    pub(crate) fn storage_status(&self) -> Result<Status, String> {
        let db = self.0.lock().map_err(err)?;
        let p = path(&db);
        let wal = p
            .as_ref()
            .map(|p| PathBuf::from(format!("{}-wal", p.display())));
        let cache_bytes = p
            .as_ref()
            .and_then(|p| p.parent())
            .and_then(|p| std::fs::read_dir(p.join("advisories")).ok())
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok().and_then(|e| e.metadata().ok()))
            .filter(|m| m.is_file())
            .map(|m| m.len())
            .sum();
        let database_bytes = bytes(p);
        let wal_bytes = bytes(wal);
        let result = admit(&db);
        Ok(Status {
            actions: crate::ai_actions::storage(&db)?,
            activity: crate::activity::status(),
            database_bytes,
            wal_bytes,
            limit_bytes: LIMIT,
            cache_bytes,
            cache_limit_bytes: 128 * 1024 * 1024,
            blocked: result.is_err(),
            message: result.err(),
        })
    }
    pub(crate) fn maintain_storage(&self) -> Result<(), String> {
        let db = self.0.lock().map_err(err)?;
        let cutoff = now() - 30 * 86400;
        crate::checks::trim_runs(&db)?;
        crate::ai_actions::trim(&db, now())?;
        crate::correlation::trim(&db, now())?;
        db.execute("UPDATE package_state SET payload=json_set(payload,'$.stage',NULL,'$.pending',json('[]'),'$.offset',0,'$.revision',json_extract(payload,'$.revision')+1,'$.nextCheck',?1) WHERE json_extract(payload,'$.stage') IS NOT NULL AND json_extract(payload,'$.stageAt')<?2",params![now(),now()-3600]).map_err(err)?;
        // Each delete is capped: cleanup must not monopolize the writer or explode WAL.
        for sql in [
   "DELETE FROM package_buckets WHERE rowid IN (SELECT b.rowid FROM package_buckets b JOIN package_state s ON s.server_id=b.server_id WHERE b.root!=coalesce(json_extract(s.payload,'$.root'),'') AND b.root!=coalesce(json_extract(s.payload,'$.previous'),'') AND (b.root!=coalesce(json_extract(s.payload,'$.stage.root'),'') OR json_extract(s.payload,'$.stageAt')<?1+2592000-3600) LIMIT 16)",
   "DELETE FROM vulnerability_findings WHERE rowid IN (SELECT rowid FROM vulnerability_findings WHERE resolved_at IS NOT NULL AND resolved_at<?1 ORDER BY resolved_at LIMIT 500)",
   "DELETE FROM vulnerability_evidence WHERE rowid IN (SELECT e.rowid FROM vulnerability_evidence e JOIN incidents i ON i.id=e.incident_id WHERE json_extract(i.payload,'$.status')='resolved' AND json_extract(i.payload,'$.updatedAt')<?1 LIMIT 500)",
   "DELETE FROM incidents WHERE rowid IN (SELECT rowid FROM incidents WHERE json_extract(payload,'$.status')='resolved' AND (json_extract(payload,'$.updatedAt')<?1 OR rowid NOT IN (SELECT rowid FROM incidents WHERE json_extract(payload,'$.status')='resolved' ORDER BY json_extract(payload,'$.updatedAt') DESC LIMIT 10000)) LIMIT 500)",
   "DELETE FROM ai_jobs WHERE rowid IN (SELECT rowid FROM ai_jobs WHERE state NOT IN ('queued','running','suppressed') AND created_at<?1 AND id NOT IN (SELECT coalesce(nullif(json_extract(payload,'$.episode'),''),id||':'||json_extract(payload,'$.openedAt')) FROM incidents) AND id NOT IN (SELECT id FROM incident_groups) LIMIT 500)",
   "DELETE FROM ai_ledger WHERE rowid IN (SELECT rowid FROM ai_ledger WHERE day<?1/86400 AND state!='running' LIMIT 500)",
   "DELETE FROM observations WHERE id IN (SELECT id FROM observations WHERE at<?1 OR id NOT IN (SELECT id FROM observations ORDER BY at DESC,id DESC LIMIT 120000) LIMIT 500)",
  ]{db.execute(sql,[cutoff]).map_err(err)?;}
        db.execute("DELETE FROM log_evidence WHERE rowid IN (SELECT e.rowid FROM log_evidence e JOIN incidents i ON i.id=e.incident_id WHERE json_extract(i.payload,'$.status')='resolved' AND json_extract(i.payload,'$.updatedAt')<?1 LIMIT 500)",[cutoff]).map_err(err)?;
        db.execute("DELETE FROM log_summaries WHERE rowid IN (SELECT rowid FROM log_summaries WHERE (at<?1 OR rowid NOT IN (SELECT rowid FROM log_summaries ORDER BY at DESC,rowid DESC LIMIT 50000)) AND id NOT IN (SELECT summary_id FROM log_evidence) LIMIT 500)",[now()-7*86400]).map_err(err)?;
        crate::services::trim_history(&db, now())?;
        db.execute(
            "DELETE FROM vulnerability_evaluations WHERE server_id NOT IN (SELECT id FROM servers)",
            [],
        )
        .map_err(err)?;
        db.execute("DELETE FROM vulnerability_findings WHERE rowid IN (SELECT rowid FROM vulnerability_findings WHERE resolved_at IS NOT NULL AND rowid NOT IN (SELECT rowid FROM vulnerability_findings WHERE resolved_at IS NOT NULL ORDER BY resolved_at DESC LIMIT 10000) LIMIT 500)",[]).map_err(err)?;
        db.execute("DELETE FROM investigations WHERE id IN (SELECT id FROM investigations WHERE started_at<?1 AND json_extract(payload,'$.status')!='running' LIMIT 50)",[cutoff]).map_err(err)?;
        db.execute("DELETE FROM vulnerability_apt WHERE rowid IN (SELECT rowid FROM vulnerability_apt WHERE at<?1 LIMIT 500)",[now()-7*86400]).map_err(err)?;
        // SQLite reuses freed pages; checkpoint truncates the auxiliary WAL file.
        let _: Result<(i64, i64, i64), _> =
            db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            });
        // Older installations can already exceed the new ceiling. Ingestion stays blocked
        // until bounded retention creates enough space for a one-off compaction.
        if bytes(path(&db)) > LIMIT {
            let pages: u64 = db
                .pragma_query_value(None, "page_count", |r| r.get(0))
                .map_err(err)?;
            let free: u64 = db
                .pragma_query_value(None, "freelist_count", |r| r.get(0))
                .map_err(err)?;
            let size: u64 = db
                .pragma_query_value(None, "page_size", |r| r.get(0))
                .map_err(err)?;
            if pages.saturating_sub(free) * size < LIMIT - 16 * 1024 * 1024 {
                db.execute_batch("VACUUM;").map_err(err)?;
                configure(&db)?;
            }
        }
        db.execute(
            "INSERT INTO maintenance VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET at=excluded.at",
            params![now()],
        )
        .map_err(err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{inventory, model::*};
    fn fixture() -> (Store, String) {
        let store = Store::open(std::path::Path::new(":memory:")).unwrap();
        let src = Source {
            id: "source".into(),
            name: "test".into(),

            kind: "manual".into(),
            location: "ops@node".into(),
            last_sync: None,
            error: None,
        };
        store
            .import(&src, inventory::parse_manual(&src.location).unwrap())
            .unwrap();
        let id = store.snapshot().unwrap().servers[0].id.clone();
        (store, id)
    }
    #[test]
    fn retention_preserves_open_evidence_and_purges_old_data() {
        let (store, id) = fixture();
        let old = now() - 31 * 86400;
        {
            let db = store.0.lock().unwrap();
            Store::incident(
                &db,
                &id,
                "logs:oom",
                Some("oom".into()),
                "OOM",
                "critical",
                old,
            )
            .unwrap();
            Store::incident(
                &db,
                &id,
                "nginx:errors",
                Some("error".into()),
                "Nginx",
                "critical",
                old,
            )
            .unwrap();
            Store::incident(&db, &id, "nginx:errors", None, "Nginx", "critical", old).unwrap();
            Store::incident(&db, &id, "nginx:errors", None, "Nginx", "critical", old).unwrap();
            for (name, check) in [("pinned", "logs:oom"), ("closed", "nginx:errors")] {
                db.execute(
                    "INSERT INTO log_summaries VALUES(?1,?2,?3,'{}')",
                    params![name, id, old],
                )
                .unwrap();
                db.execute(
                    "INSERT INTO log_evidence VALUES(?1,?2)",
                    params![inventory::stable_id(&id, check), name],
                )
                .unwrap();
            }
            for n in 0..750 {
                db.execute(
                    "INSERT INTO observations(server_id,at,payload) VALUES(?1,?2,'{}')",
                    params![id, old + n],
                )
                .unwrap();
            }
            db.execute(
                "INSERT INTO observations(server_id,at,payload) VALUES(?1,?2,'{}')",
                params![id, now()],
            )
            .unwrap();
        }
        store.maintain_storage().unwrap();
        {
            let db = store.0.lock().unwrap();
            let n: i64 = db
                .query_row("SELECT count(*) FROM observations", [], |r| r.get(0))
                .unwrap();
            assert_eq!(n, 251);
        }
        store.maintain_storage().unwrap();
        let db = store.0.lock().unwrap();
        let count = |table: &str| -> i64 {
            db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(count("observations"), 1);
        assert_eq!(count("log_summaries"), 1);
        assert_eq!(count("log_evidence"), 1);
        assert_eq!(count("incidents"), 1);
        assert_eq!(
            db.query_row("SELECT id FROM log_summaries", [], |r| r
                .get::<_, String>(0))
                .unwrap(),
            "pinned"
        );
    }
    #[test]
    fn configured_limit_and_sqlite_full_are_hard() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("db.sqlite")).unwrap();
        let db = store.0.lock().unwrap();
        let size: u64 = db
            .pragma_query_value(None, "page_size", |r| r.get(0))
            .unwrap();
        let limit: u64 = db
            .pragma_query_value(None, "max_page_count", |r| r.get(0))
            .unwrap();
        assert_eq!(size * limit, LIMIT);
        let pages: u64 = db
            .pragma_query_value(None, "page_count", |r| r.get(0))
            .unwrap();
        db.pragma_update(None, "max_page_count", pages + 4).unwrap();
        assert!(db
            .execute(
                "INSERT INTO investigations VALUES('full',0,zeroblob(1048576))",
                []
            )
            .is_err());
        let count: i64 = db
            .query_row("SELECT count(*) FROM investigations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }
    #[test]
    fn old_package_generations_and_closed_findings_are_deleted() {
        let (store, id) = fixture();
        let state = store.package_state(&id).unwrap();
        {
            let db = store.0.lock().unwrap();
            db.execute(
                "INSERT INTO package_buckets VALUES(?1,'old',0,'hash','[]')",
                [&id],
            )
            .unwrap();
            db.execute(
                "INSERT INTO vulnerability_findings VALUES(?1,'p','CVE-2025-1000',?2,'{}')",
                params![id, now() - 31 * 86400],
            )
            .unwrap();
        }
        store.maintain_storage().unwrap();
        let db = store.0.lock().unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM package_buckets", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(state.revision, 0);
    }
    #[test]
    fn pinned_wal_stops_admission_then_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db");
        let store = Store::open(&path).unwrap();
        let reader = Connection::open(&path).unwrap();
        reader
            .execute_batch("BEGIN;SELECT count(*) FROM settings;")
            .unwrap();
        let db = store.0.lock().unwrap();
        db.execute_batch("PRAGMA busy_timeout=1;").unwrap();
        for _ in 0..36 {
            db.execute("INSERT INTO investigations VALUES('wal',0,randomblob(1048576)) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",[]).unwrap();
        }
        assert!(admit(&db).is_err());
        reader.execute_batch("ROLLBACK;").unwrap();
        assert!(admit(&db).is_ok());
    }
}
