//! Hard SQLite page ceiling plus bounded, resumable retention work.
use crate::{model::now, store::Store};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};
use tauri::Emitter;
const LIMIT: u64 = 1024 * 1024 * 1024;
const HIGH_WATER: u64 = 900 * 1024 * 1024;
const LOW_WATER: u64 = 800 * 1024 * 1024;
const BATCH: usize = 500;
const PASS_BUDGET: Duration = Duration::from_millis(500);
const WAL_LIMIT: u64 = 32 * 1024 * 1024;
pub(crate) const CLEANUP_INTERVAL_SECONDS: u64 = 300;
const PRESSURE_CHECK: Duration = Duration::from_secs(5);
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn path(db: &Connection) -> Option<PathBuf> {
    db.query_row("PRAGMA database_list", [], |r| r.get::<_, String>(2))
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}
fn bytes(path: Option<&Path>) -> u64 {
    path.and_then(|p| std::fs::metadata(p).ok())
        .map_or(0, |m| m.len())
}
fn wal_path(path: Option<&Path>) -> Option<PathBuf> {
    path.map(|path| {
        let mut wal = path.as_os_str().to_os_string();
        wal.push("-wal");
        wal.into()
    })
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
pub(crate) fn initialize(db: &Connection) -> Result<(), String> {
    loop {
        let setup = (|| -> rusqlite::Result<()> {
            let tx = db.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS storage_cleanup(
        id INTEGER PRIMARY KEY CHECK(id=1), phase INTEGER NOT NULL DEFAULT 0,
        pressure INTEGER NOT NULL DEFAULT 0, exhausted INTEGER NOT NULL DEFAULT 0,
        active INTEGER NOT NULL DEFAULT 0);
        INSERT OR IGNORE INTO storage_cleanup(id) VALUES(1);
        CREATE INDEX IF NOT EXISTS service_evidence_summary ON service_evidence(summary_id);
        CREATE INDEX IF NOT EXISTS log_evidence_summary ON log_evidence(summary_id);
        CREATE INDEX IF NOT EXISTS check_evidence_run ON check_evidence(run_id);
        CREATE INDEX IF NOT EXISTS log_summaries_retention ON log_summaries(at);",
            )?;
            tx.commit()
        })();
        match setup {
            Ok(()) => return Ok(()),
            Err(rusqlite::Error::SqliteFailure(code, _))
                if code.code == rusqlite::ErrorCode::DiskFull =>
            {
                // Legacy databases may have no room even for the cleanup indexes.
                // The same protected-history rules apply before the state table exists.
                let tx = db.unchecked_transaction().map_err(err)?;
                if trim_pressure(&tx)? == 0 {
                    return Err("Cannot initialize storage cleanup: the database is full of protected data.".into());
                }
                tx.commit().map_err(err)?;
                checkpoint(db);
            }
            Err(error) => return Err(err(error)),
        }
    }
}

pub fn admit(db: &Connection) -> Result<(), String> {
    admit_with(db, LIMIT, HIGH_WATER)
}
fn admit_with(db: &Connection, limit: u64, high: u64) -> Result<(), String> {
    let p = path(db);
    let mut space = Space::read(db, p.as_deref())?;
    if space.wal >= WAL_LIMIT {
        checkpoint(db);
        space.wal = bytes(wal_path(p.as_deref()).as_deref());
    }
    space.admit(limit, high)
}

struct Space {
    used: u64,
    file: u64,
    wal: u64,
    pressure: bool,
    exhausted: bool,
}

impl Space {
    fn read(db: &Connection, path: Option<&Path>) -> Result<Self, String> {
        let (pressure, exhausted) = db
            .prepare_cached("SELECT pressure,exhausted FROM storage_cleanup WHERE id=1")
            .and_then(|mut query| query.query_row([], |r| Ok((r.get(0)?, r.get(1)?))))
            .map_err(err)?;
        Ok(Self {
            used: used_bytes(db)?,
            file: bytes(path),
            wal: bytes(wal_path(path).as_deref()),
            pressure,
            exhausted,
        })
    }

    fn admit(&self, limit: u64, high: u64) -> Result<(), String> {
        if self.exhausted && self.used >= high {
            return Err("Local storage is full of protected data. Latest results and incident evidence cannot be removed automatically; collection is paused.".into());
        }
        if self.file > limit {
            return Err(
                "The database exceeded 1 GiB. Collection is paused until cleanup and compaction."
                    .into(),
            );
        }
        if self.wal >= WAL_LIMIT {
            return Err("The SQLite write-ahead log reached its limit. Collection pauses until the database reader finishes.".into());
        }
        if self.used >= limit.saturating_sub(8 * 1024 * 1024) {
            return Err(
                "The SQLite database reached its 1 GiB limit. Collection pauses until cleanup."
                    .into(),
            );
        }
        Ok(())
    }

    fn cleanup_due(&self) -> bool {
        self.pressure
            || (self.used >= HIGH_WATER && !self.exhausted)
            || self.file > LIMIT
            || self.wal >= WAL_LIMIT
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CleanupPass {
    Complete,
    Pending,
    Pressure,
    Deferred,
}

impl CleanupPass {
    fn has_more(self) -> bool {
        matches!(self, Self::Pending | Self::Pressure)
    }

    fn delay(self) -> Duration {
        Duration::from_secs(match self {
            Self::Complete => CLEANUP_INTERVAL_SECONDS,
            Self::Pending => 5,
            Self::Pressure => 1,
            Self::Deferred => 60,
        })
    }
}

impl Store {
    pub(crate) fn collection_allowed(&self) -> Result<bool, String> {
        let db = self.0.lock().map_err(err)?;
        Ok(Space::read(&db, path(&db).as_deref())?
            .admit(LIMIT, HIGH_WATER)
            .is_ok())
    }

    fn storage_cleanup_due(&self) -> Result<bool, String> {
        let db = self.0.lock().map_err(err)?;
        Ok(Space::read(&db, path(&db).as_deref())?.cleanup_due())
    }

    pub(crate) fn storage_status(&self) -> Result<Status, String> {
        let db = self.0.lock().map_err(err)?;
        let p = path(&db);
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
        let space = Space::read(&db, p.as_deref())?;
        let result = space.admit(LIMIT, HIGH_WATER);
        Ok(Status {
            actions: crate::ai_actions::storage(&db)?,
            activity: crate::activity::status(),
            database_bytes: space.used,
            wal_bytes: space.wal,
            limit_bytes: LIMIT,
            cache_bytes,
            cache_limit_bytes: 128 * 1024 * 1024,
            blocked: result.is_err(),
            message: result.err(),
        })
    }
    /// A pass resumes from the last committed phase, including after a restart.
    pub(crate) fn maintain_storage(&self) -> Result<CleanupPass, String> {
        self.maintain_storage_with(PASS_BUDGET, HIGH_WATER, LOW_WATER, LIMIT)
    }

    fn maintain_storage_with(
        &self,
        budget: Duration,
        high: u64,
        low: u64,
        limit: u64,
    ) -> Result<CleanupPass, String> {
        let started = Instant::now();
        // Cache a history cutoff for this pass, rather than recounting its quota per batch.
        let mut boundary = None;
        let database_path = path(&*self.0.lock().map_err(err)?);
        let wal = wal_path(database_path.as_deref());
        loop {
            let mut db = self.0.lock().map_err(err)?;
            if bytes(wal.as_deref()) >= WAL_LIMIT {
                checkpoint(&db);
                if bytes(wal.as_deref()) >= WAL_LIMIT {
                    // A pinned reader must not let cleanup grow the WAL indefinitely.
                    return Ok(CleanupPass::Deferred);
                }
            }
            let tx = db.transaction().map_err(err)?;
            tx.execute(
                "UPDATE storage_cleanup SET active=1,exhausted=0 WHERE id=1 AND active=0",
                [],
            )
            .map_err(err)?;
            let (mut phase, mut pressure, mut exhausted): (usize, bool, bool) = tx
                .query_row(
                    "SELECT phase,pressure,exhausted FROM storage_cleanup WHERE id=1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .map_err(err)?;
            let used = used_bytes(&tx)?;
            if used >= high && !exhausted && !pressure {
                pressure = true;
            }
            if pressure {
                if used <= low {
                    pressure = false;
                    exhausted = false;
                } else if trim_pressure(&tx)? == 0 {
                    pressure = false;
                    exhausted = true;
                }
            } else if phase < RETENTION_SQL.len() {
                let (sql, batch) = RETENTION_SQL[phase];
                let removed = tx.execute(sql, [now() - 30 * 86400]).map_err(err)?;
                if removed < batch {
                    phase += 1;
                }
            } else if phase < RETENTION_SQL.len() + 3 {
                let before = tx.total_changes();
                match phase - RETENTION_SQL.len() {
                    0 => crate::checks::trim_runs(&tx)?,
                    1 => crate::ai_actions::trim(&tx, now())?,
                    _ => crate::correlation::trim(&tx, now())?,
                }
                if tx.total_changes() - before < [50, 100, 100][phase - RETENTION_SQL.len()] {
                    phase += 1;
                }
            } else if phase < RETENTION_SQL.len() + 6 {
                let history = &HISTORIES[phase - RETENTION_SQL.len() - 3];
                let cutoff = match boundary {
                    Some((saved_phase, cutoff)) if saved_phase == phase => cutoff,
                    _ => {
                        let cutoff = history.boundary(&tx, now())?;
                        boundary = Some((phase, cutoff));
                        cutoff
                    }
                };
                if history.trim(&tx, cutoff)? < BATCH {
                    phase += 1;
                }
            } else {
                exhausted &= used >= high;
                tx.execute(
                    "UPDATE storage_cleanup SET phase=0,pressure=0,active=0,exhausted=?1 WHERE id=1",
                    [exhausted],
                )
                .map_err(err)?;
                tx.execute("INSERT INTO maintenance VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET at=excluded.at", [now()]).map_err(err)?;
                tx.commit().map_err(err)?;
                checkpoint(&db);
                // Legacy databases above the ceiling need a one-off physical compaction.
                let oversized = bytes(database_path.as_deref()) > limit;
                if oversized && used < limit.saturating_sub(16 * 1024 * 1024) {
                    db.execute_batch("VACUUM;").map_err(err)?;
                    checkpoint(&db);
                    configure(&db)?;
                }
                return Ok(
                    if exhausted
                        || bytes(database_path.as_deref()) > limit
                        || bytes(wal.as_deref()) >= WAL_LIMIT
                    {
                        CleanupPass::Deferred
                    } else {
                        CleanupPass::Complete
                    },
                );
            }
            tx.execute(
                "UPDATE storage_cleanup SET phase=?1,pressure=?2,exhausted=?3 WHERE id=1",
                params![phase, pressure, exhausted],
            )
            .map_err(err)?;
            tx.commit().map_err(err)?;
            if started.elapsed() >= budget {
                checkpoint(&db);
                if bytes(wal.as_deref()) >= WAL_LIMIT {
                    return Ok(CleanupPass::Deferred);
                }
                return Ok(if pressure {
                    CleanupPass::Pressure
                } else {
                    CleanupPass::Pending
                });
            }
            drop(db);
            std::thread::yield_now();
        }
    }
}

pub(crate) async fn maintain_background(app: tauri::AppHandle, state: Arc<crate::AppState>) {
    use tokio::time::{sleep_until, Instant};

    while !state.stop.load(Ordering::Relaxed) {
        let before = state.store.collection_allowed().unwrap_or(false);
        let worker = state.clone();
        let result = tokio::task::spawn_blocking(move || {
            crate::monitoring::sync(&worker.store, "storage", "schedule", || {
                let mut span = crate::activity::begin("app", "storage_cleanup", None);
                let result = worker.store.maintain_storage();
                span.result(&result);
                result
            })
        })
        .await
        .map_err(err)
        .and_then(|result| result);
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => {
                let _ = state.store.block_auto(&error);
                CleanupPass::Deferred
            }
        };
        let after = state.store.collection_allowed().unwrap_or(false);
        if !outcome.has_more() || before != after {
            let _ = app.emit("state-changed", ());
        }
        if before != after {
            state.polls.wake.notify_one();
        }
        let deadline = Instant::now() + outcome.delay();
        if outcome == CleanupPass::Complete {
            loop {
                sleep_until(deadline.min(Instant::now() + PRESSURE_CHECK)).await;
                if Instant::now() >= deadline
                    || state.stop.load(Ordering::Relaxed)
                    || state.store.storage_cleanup_due().unwrap_or(true)
                {
                    break;
                }
            }
        } else {
            sleep_until(deadline).await;
        }
    }
}

fn used_bytes(db: &Connection) -> Result<u64, String> {
    let pages: u64 = db
        .pragma_query_value(None, "page_count", |r| r.get(0))
        .map_err(err)?;
    let free: u64 = db
        .pragma_query_value(None, "freelist_count", |r| r.get(0))
        .map_err(err)?;
    let size: u64 = db
        .pragma_query_value(None, "page_size", |r| r.get(0))
        .map_err(err)?;
    Ok(pages.saturating_sub(free) * size)
}

fn checkpoint(db: &Connection) {
    // PASSIVE never waits for readers; truncate only if all frames were checkpointed.
    let result: rusqlite::Result<(i64, i64, i64)> =
        db.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        });
    if let Ok((0, frames, done)) = result {
        if frames == done {
            let _ = db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        }
    }
}

const TRIM_SERVER_LOGS: &str = "DELETE FROM log_summaries AS h WHERE server_id=?1 AND (h.at,h.rowid) <= (
    SELECT at,rowid FROM log_summaries WHERE server_id=?1 ORDER BY at DESC,rowid DESC LIMIT 1 OFFSET 1000
) AND NOT EXISTS (SELECT 1 FROM log_evidence WHERE summary_id=h.id)";

pub(crate) fn trim_server_logs(db: &Connection, server: &str) -> Result<(), String> {
    db.prepare_cached(TRIM_SERVER_LOGS)
        .and_then(|mut query| query.execute([server]))
        .map(|_| ())
        .map_err(err)
}

const TRIM_SERVICE_INSTANCE: &str = "DELETE FROM service_summaries AS h
WHERE server_id=?1 AND kind=?2 AND instance_id=?3 AND (h.at,h.rowid) <= (
    SELECT at,rowid FROM service_summaries WHERE server_id=?1 AND kind=?2 AND instance_id=?3
    ORDER BY at DESC,rowid DESC LIMIT 1 OFFSET 1000
) AND NOT EXISTS (SELECT 1 FROM service_evidence WHERE summary_id=h.id)";

pub(crate) fn trim_service_instance(
    db: &Connection,
    server: &str,
    kind: &str,
    instance: &str,
) -> Result<(), String> {
    db.prepare_cached(TRIM_SERVICE_INSTANCE)
        .and_then(|mut query| query.execute(params![server, kind, instance]))
        .map(|_| ())
        .map_err(err)
}

struct History {
    table: &'static str,
    scope: &'static str,
    evidence: Option<(&'static str, &'static str)>,
    keep: usize,
    days: i64,
}
const HISTORIES: [History; 4] = [
    History {
        table: "service_summaries",
        scope: "n.server_id=h.server_id AND n.kind=h.kind AND n.instance_id=h.instance_id",
        evidence: Some(("service_evidence", "summary_id")),
        keep: 50_000,
        days: 7,
    },
    History {
        table: "observations",
        scope: "n.server_id=h.server_id",
        evidence: None,
        keep: 120_000,
        days: 30,
    },
    History {
        table: "log_summaries",
        scope: "n.server_id=h.server_id",
        evidence: Some(("log_evidence", "summary_id")),
        keep: 50_000,
        days: 7,
    },
    History {
        table: "check_runs",
        scope: "n.server_id=h.server_id AND n.check_id=h.check_id",
        evidence: Some(("check_evidence", "run_id")),
        keep: 10_000,
        days: 7,
    },
];
impl History {
    fn disposable(&self) -> String {
        let mut filter = format!("h.rowid != (SELECT n.rowid FROM {} n WHERE {} ORDER BY n.at DESC,n.rowid DESC LIMIT 1)", self.table, self.scope);
        if let Some((table, column)) = self.evidence {
            filter.push_str(&format!(
                " AND NOT EXISTS (SELECT 1 FROM {table} e WHERE e.{column}=h.id)"
            ));
        }
        filter
    }
    fn boundary(&self, db: &Connection, at: i64) -> Result<(i64, i64), String> {
        let age = (at - self.days * 86400 - 1, i64::MAX);
        // If the raw history fits, the unprotected history fits as well. The
        // date index can answer this without reading rows or checking evidence.
        let over_quota = db
            .query_row(
                &format!(
                    "SELECT rowid FROM {} ORDER BY at DESC,rowid DESC LIMIT 1 OFFSET ?1",
                    self.table
                ),
                [self.keep],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map_err(err)?
            .is_some();
        if !over_quota {
            return Ok(age);
        }
        let quota: Option<(i64,i64)> = db.query_row(&format!("SELECT h.at,h.rowid FROM {} h WHERE {} ORDER BY h.at DESC,h.rowid DESC LIMIT 1 OFFSET ?1",self.table,self.disposable()), [self.keep], |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(err)?;
        Ok(quota.map_or(age, |quota| quota.max(age)))
    }
    fn trim(&self, db: &Connection, boundary: (i64, i64)) -> Result<usize, String> {
        db.execute(&format!("DELETE FROM {} WHERE rowid IN (SELECT h.rowid FROM {} h WHERE (h.at,h.rowid)<=(?1,?2) AND {} ORDER BY h.at,h.rowid LIMIT {BATCH})", self.table,self.table,self.disposable()),params![boundary.0,boundary.1]).map_err(err)
    }
}

fn trim_pressure(db: &Connection) -> Result<usize, String> {
    let selections: Vec<_> = HISTORIES.iter().enumerate().map(|(index,h)| format!("SELECT * FROM (SELECT {index} AS kind,h.rowid AS id,h.at FROM {} h WHERE {} ORDER BY h.at,h.rowid LIMIT {BATCH})",h.table,h.disposable())).collect();
    let sql = format!(
        "SELECT kind,id FROM ({}) ORDER BY at,kind,id LIMIT {BATCH}",
        selections.join(" UNION ALL ")
    );
    let mut query = db.prepare(&sql).map_err(err)?;
    let rows = query
        .query_map([], |r| Ok((r.get::<_, usize>(0)?, r.get::<_, i64>(1)?)))
        .map_err(err)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(err)?;
    let removed = rows.len();
    for (kind, h) in HISTORIES.iter().enumerate() {
        let ids: Vec<_> = rows
            .iter()
            .filter(|(k, _)| *k == kind)
            .map(|(_, id)| *id)
            .collect();
        if !ids.is_empty() {
            db.execute(
                &format!(
                    "DELETE FROM {} WHERE rowid IN (SELECT value FROM json_each(?1))",
                    h.table
                ),
                [serde_json::to_string(&ids).map_err(err)?],
            )
            .map_err(err)?;
        }
    }
    Ok(removed)
}

const RETENTION_SQL: &[(&str, usize)] = &[
    ("DELETE FROM service_evidence WHERE rowid IN (SELECT e.rowid FROM service_evidence e JOIN incidents i ON i.id=e.incident_id WHERE json_extract(i.payload,'$.status')='resolved' AND json_extract(i.payload,'$.updatedAt')<?1 LIMIT 500)", 500),
    ("UPDATE package_state SET payload=json_set(payload,'$.stage',NULL,'$.pending',json('[]'),'$.offset',0,'$.revision',json_extract(payload,'$.revision')+1,'$.nextCheck',?1+2592000) WHERE json_extract(payload,'$.stage') IS NOT NULL AND rowid IN (SELECT rowid FROM package_state WHERE json_extract(payload,'$.stage') IS NOT NULL AND json_extract(payload,'$.stageAt')<?1+2592000-3600 LIMIT 500)", 500),
    ("DELETE FROM package_buckets WHERE rowid IN (SELECT b.rowid FROM package_buckets b JOIN package_state s ON s.server_id=b.server_id WHERE b.root!=coalesce(json_extract(s.payload,'$.root'),'') AND b.root!=coalesce(json_extract(s.payload,'$.previous'),'') AND (b.root!=coalesce(json_extract(s.payload,'$.stage.root'),'') OR json_extract(s.payload,'$.stageAt')<?1+2592000-3600) LIMIT 16)", 16),
    ("DELETE FROM vulnerability_findings WHERE rowid IN (SELECT rowid FROM vulnerability_findings WHERE resolved_at IS NOT NULL AND resolved_at<?1 ORDER BY resolved_at LIMIT 500)", 500),
    ("DELETE FROM vulnerability_evidence WHERE rowid IN (SELECT e.rowid FROM vulnerability_evidence e JOIN incidents i ON i.id=e.incident_id WHERE json_extract(i.payload,'$.status')='resolved' AND json_extract(i.payload,'$.updatedAt')<?1 LIMIT 500)", 500),
    ("DELETE FROM incidents WHERE rowid IN (SELECT rowid FROM incidents WHERE json_extract(payload,'$.status')='resolved' AND (json_extract(payload,'$.updatedAt')<?1 OR rowid NOT IN (SELECT rowid FROM incidents WHERE json_extract(payload,'$.status')='resolved' ORDER BY json_extract(payload,'$.updatedAt') DESC LIMIT 10000)) LIMIT 500)", 500),
    ("DELETE FROM ai_jobs WHERE rowid IN (SELECT rowid FROM ai_jobs WHERE state NOT IN ('queued','running','suppressed') AND created_at<?1 AND id NOT IN (SELECT coalesce(nullif(json_extract(payload,'$.episode'),''),id||':'||json_extract(payload,'$.openedAt')) FROM incidents) AND id NOT IN (SELECT id FROM incident_groups) LIMIT 500)", 500),
    ("DELETE FROM ai_ledger WHERE rowid IN (SELECT rowid FROM ai_ledger WHERE day<?1/86400 AND state!='running' LIMIT 500)", 500),
    ("DELETE FROM log_evidence WHERE rowid IN (SELECT e.rowid FROM log_evidence e JOIN incidents i ON i.id=e.incident_id WHERE json_extract(i.payload,'$.status')='resolved' AND json_extract(i.payload,'$.updatedAt')<?1 LIMIT 500)", 500),
    ("DELETE FROM vulnerability_evaluations WHERE rowid IN (SELECT rowid FROM vulnerability_evaluations WHERE server_id NOT IN (SELECT id FROM servers) LIMIT 500) AND ?1 IS NOT NULL", 500),
    ("DELETE FROM vulnerability_findings WHERE rowid IN (SELECT rowid FROM vulnerability_findings WHERE resolved_at IS NOT NULL AND rowid NOT IN (SELECT rowid FROM vulnerability_findings WHERE resolved_at IS NOT NULL ORDER BY resolved_at DESC LIMIT 10000) LIMIT 500) AND ?1 IS NOT NULL", 500),
    ("DELETE FROM investigations WHERE id IN (SELECT id FROM investigations WHERE started_at<?1 AND json_extract(payload,'$.status')!='running' LIMIT 50)", 50),
    ("DELETE FROM vulnerability_apt WHERE rowid IN (SELECT rowid FROM vulnerability_apt WHERE at<?1+1987200 LIMIT 500)", 500),
];

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
    fn finish(store: &Store, high: u64, low: u64, limit: u64) {
        for _ in 0..2000 {
            if !store
                .maintain_storage_with(Duration::from_millis(10), high, low, limit)
                .unwrap()
                .has_more()
            {
                return;
            }
        }
        panic!("cleanup did not finish");
    }

    fn seed_services(db: &Connection, server: &str, count: usize, payload_size: usize) {
        let at = now();
        let payload = format!("{{\"padding\":\"{}\"}}", "x".repeat(payload_size));
        let tx = db.unchecked_transaction().unwrap();
        {
            let mut insert = tx.prepare("INSERT INTO service_summaries(id,server_id,kind,instance_id,at,payload) VALUES(?1,?2,?3,?4,?5,?6)").unwrap();
            for n in 0..count {
                insert
                    .execute(params![
                        format!("sample-{n}"),
                        server,
                        format!("kind-{}", n % 18),
                        format!("instance-{}", (n / 18) % 150),
                        at + (n / 2700) as i64,
                        payload
                    ])
                    .unwrap();
            }
        }
        tx.commit().unwrap();
    }

    #[test]
    fn scoped_history_limits_use_time_indexes_and_preserve_incident_samples() {
        let (store, server) = fixture();
        let at = now() - 8 * 86400;
        {
            let db = store.0.lock().unwrap();
            db.execute(
                "INSERT INTO incidents VALUES('open',?1,'{\"status\":\"open\"}')",
                [&server],
            )
            .unwrap();
            db.execute("WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<1001) INSERT INTO log_summaries SELECT 'log-'||i,?1,?2,'{}' FROM n",params![server, at]).unwrap();
            db.execute("WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<1001) INSERT INTO service_summaries(id,server_id,kind,instance_id,at,payload) SELECT 'service-'||i,?1,'redis','default',?2,'{}' FROM n",params![server, at]).unwrap();
            db.execute_batch("INSERT INTO log_evidence VALUES('open','log-0'); INSERT INTO service_evidence VALUES('open','service-0');").unwrap();
            for (sql, args, index) in [
                (
                    TRIM_SERVER_LOGS,
                    vec![server.as_str()],
                    "log_summaries_server_at",
                ),
                (
                    TRIM_SERVICE_INSTANCE,
                    vec![server.as_str(), "redis", "default"],
                    "service_summaries_instance_at",
                ),
            ] {
                let mut stmt = db.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
                let plan = stmt
                    .query_map(rusqlite::params_from_iter(args), |row| {
                        row.get::<_, String>(3)
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap()
                    .join("\n");
                assert!(plan.contains(index) && plan.contains("at<?"), "{plan}");
                assert!(!plan.contains("TEMP B-TREE"), "{plan}");
            }
            trim_server_logs(&db, &server).unwrap();
            trim_service_instance(&db, &server, "redis", "default").unwrap();
            for (table, prefix) in [("log_summaries", "log"), ("service_summaries", "service")] {
                let counts = db.query_row(&format!("SELECT count(*),sum(id=?1||'-0'),sum(id=?1||'-1'),sum(id=?1||'-1001') FROM {table}"), [prefix], |r| Ok((r.get::<_,i64>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?))).unwrap();
                assert_eq!(counts, (1001, 1, 0, 1));
            }
        }
        while store.maintain_storage().unwrap().has_more() {}
        let db = store.0.lock().unwrap();
        for (table, prefix) in [("log_summaries", "log"), ("service_summaries", "service")] {
            let ids = db
                .prepare(&format!("SELECT id FROM {table} ORDER BY rowid"))
                .unwrap()
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(ids, [format!("{prefix}-0"), format!("{prefix}-1001")]);
        }
    }

    #[test]
    fn cleanup_initializes_when_the_old_database_has_no_free_pages() {
        let (store, server) = fixture();
        let db = store.0.lock().unwrap();
        // Recreate an old installation without any of the new cleanup objects.
        db.execute_batch("DROP TABLE storage_cleanup; DROP INDEX service_evidence_summary; DROP INDEX log_evidence_summary; DROP INDEX check_evidence_run; DROP INDEX log_summaries_retention;").unwrap();
        seed_services(&db, &server, 4000, 1024);
        db.execute_batch("VACUUM;").unwrap();
        let pages: u64 = db
            .pragma_query_value(None, "page_count", |r| r.get(0))
            .unwrap();
        assert_eq!(
            db.pragma_query_value(None, "freelist_count", |r| r.get::<_, u64>(0))
                .unwrap(),
            0
        );
        db.pragma_update(None, "max_page_count", pages).unwrap();
        initialize(&db).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM storage_cleanup", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert!(
            db.query_row("SELECT count(*) FROM service_summaries", [], |r| r
                .get::<_, i64>(0))
                .unwrap()
                < 4000
        );
        assert_eq!(db.query_row("SELECT count(*) FROM (SELECT server_id,kind,instance_id FROM service_summaries GROUP BY server_id,kind,instance_id)",[],|r|r.get::<_,i64>(0)).unwrap(),2700);
    }

    #[test]
    fn legacy_oversized_file_is_compacted_after_retention() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("db");
        let store = Store::open(&file).unwrap();
        let limit = 32 * 1024 * 1024;
        {
            let db = store.0.lock().unwrap();
            db.execute(
                "INSERT INTO investigations VALUES('expired',0,?1)",
                [format!(
                    "{{\"status\":\"completed\",\"padding\":\"{}\"}}",
                    "x".repeat(40 * 1024 * 1024)
                )],
            )
            .unwrap();
            checkpoint(&db);
            assert!(bytes(path(&db).as_deref()) > limit);
            assert!(admit_with(&db, limit, 24 * 1024 * 1024).is_err());
        }
        finish(&store, 24 * 1024 * 1024, 16 * 1024 * 1024, limit);
        let db = store.0.lock().unwrap();
        assert!(bytes(path(&db).as_deref()) < limit);
        assert!(admit_with(&db, limit, 24 * 1024 * 1024).is_ok());
        let pages: u64 = db
            .pragma_query_value(None, "max_page_count", |r| r.get(0))
            .unwrap();
        let size: u64 = db
            .pragma_query_value(None, "page_size", |r| r.get(0))
            .unwrap();
        assert_eq!(pages * size, LIMIT);
        assert_eq!(
            db.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
    }

    #[test]
    fn service_quota_is_shared_and_latest_and_evidence_are_extra() {
        let (store, server) = fixture();
        {
            let db = store.0.lock().unwrap();
            seed_services(&db, &server, 60_000, 10);
            Store::incident(
                &db,
                &server,
                "test",
                Some("evidence".into()),
                "Test",
                "critical",
                now(),
            )
            .unwrap();
            db.execute(
                "INSERT INTO service_evidence VALUES(?1,'sample-0')",
                [inventory::stable_id(&server, "test")],
            )
            .unwrap();
        }
        finish(&store, HIGH_WATER, LOW_WATER, LIMIT);
        let db = store.0.lock().unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM service_summaries", [], |r| r
                .get::<_, usize>(0))
                .unwrap(),
            50_000 + 2700 + 1
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM service_summaries WHERE id='sample-0'",
                [],
                |r| r.get::<_, usize>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(db.query_row("SELECT count(*) FROM service_summaries WHERE id IN (SELECT 'sample-'||value FROM json_each(?1))", [serde_json::to_string(&(57_300..60_000).collect::<Vec<_>>()).unwrap()], |r| r.get::<_,usize>(0)).unwrap(),2700);
        // Retention is idempotent and also retains old latest results of silent sources.
        db.execute("UPDATE service_summaries SET at=?1", [now() - 31 * 86400])
            .unwrap();
        drop(db);
        finish(&store, HIGH_WATER, LOW_WATER, LIMIT);
        let db = store.0.lock().unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM service_summaries", [], |r| r
                .get::<_, usize>(0))
                .unwrap(),
            2701
        );
    }

    #[test]
    fn pressure_resumes_after_restart_and_reuses_pages() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("db");
        let (source, server) = fixture();
        source
            .0
            .lock()
            .unwrap()
            .execute("VACUUM INTO ?1", [file.to_str().unwrap()])
            .unwrap();
        let store = Store::open(&file).unwrap();
        let high = 24 * 1024 * 1024;
        let low = 16 * 1024 * 1024;
        let limit = 40 * 1024 * 1024;
        {
            let db = store.0.lock().unwrap();
            let tx = db.unchecked_transaction().unwrap();
            for n in 0..2000 {
                tx.execute(
                    "INSERT INTO observations(server_id,at,payload) VALUES(?1,?2,?3)",
                    params![
                        server,
                        now() + n,
                        format!("{{\"padding\":\"{}\"}}", "x".repeat(20_000))
                    ],
                )
                .unwrap();
            }
            tx.commit().unwrap();
            checkpoint(&db);
            assert!(admit_with(&db, limit, high).is_err());
        }
        assert!(store
            .maintain_storage_with(Duration::ZERO, high, low, limit)
            .unwrap()
            .has_more());
        {
            let db = store.0.lock().unwrap();
            assert_eq!(
                db.query_row("SELECT count(*) FROM observations", [], |r| r
                    .get::<_, usize>(0))
                    .unwrap(),
                1500
            );
            assert!(db
                .query_row("SELECT pressure FROM storage_cleanup", [], |r| r
                    .get::<_, bool>(0))
                .unwrap());
        }
        drop(store);
        let store = Store::open(&file).unwrap();
        finish(&store, high, low, limit);
        let db = store.0.lock().unwrap();
        assert!(used_bytes(&db).unwrap() <= low);
        assert!(admit_with(&db, limit, high).is_ok());
        assert_eq!(
            db.query_row("SELECT max(id) FROM observations", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            2000
        );
        // Allocated but reusable pages must not cause a false full warning.
        assert!(bytes(path(&db).as_deref()) > used_bytes(&db).unwrap());
        assert!(
            db.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap()
                == 0
        );
    }

    #[test]
    fn pressure_preserves_all_latest_scopes_and_pinned_evidence() {
        let (store, server) = fixture();
        let db = store.0.lock().unwrap();
        Store::incident(
            &db,
            &server,
            "test",
            Some("pinned".into()),
            "Test",
            "critical",
            now(),
        )
        .unwrap();
        let incident = inventory::stable_id(&server, "test");
        db.execute("INSERT INTO check_definitions VALUES('check',0,'Test')", [])
            .unwrap();
        db.execute("INSERT INTO check_versions(id,check_id,at,spec,author) VALUES('version','check',0,'{}','user')",[]).unwrap();
        for n in 0..3 {
            db.execute(
                "INSERT INTO observations(server_id,at,payload) VALUES(?1,?2,'{}')",
                params![server, n],
            )
            .unwrap();
            db.execute(
                "INSERT INTO log_summaries VALUES(?1,?2,?3,'{}')",
                params![format!("l{n}"), server, n],
            )
            .unwrap();
            db.execute("INSERT INTO service_summaries(id,server_id,kind,at,payload) VALUES(?1,?2,'docker',?3,'{}')",params![format!("s{n}"),server,n]).unwrap();
            db.execute(
                "INSERT INTO check_runs VALUES(?1,?2,'check','version',?3,'{}')",
                params![format!("c{n}"), server, n],
            )
            .unwrap();
        }
        db.execute("INSERT INTO log_evidence VALUES(?1,'l0')", [&incident])
            .unwrap();
        db.execute("INSERT INTO service_evidence VALUES(?1,'s0')", [&incident])
            .unwrap();
        db.execute("INSERT INTO check_evidence VALUES(?1,'c0')", [&incident])
            .unwrap();
        db.execute(
            "INSERT INTO investigations VALUES('active',0,'{\"status\":\"running\"}')",
            [],
        )
        .unwrap();
        let settings = Store::read_settings(&db).unwrap();
        assert_eq!(trim_pressure(&db).unwrap(), 5);
        assert_eq!(trim_pressure(&db).unwrap(), 0);
        drop(db);
        // Scaled pressure thresholds exercise exhaustion without a 1 GiB test database.
        finish(&store, 1, 0, LIMIT);
        let db = store.0.lock().unwrap();
        assert!(admit_with(&db, LIMIT, 1)
            .unwrap_err()
            .contains("protected data"));
        assert!(db
            .query_row("SELECT exhausted FROM storage_cleanup", [], |r| r
                .get::<_, bool>(0))
            .unwrap());
        assert!(!db
            .query_row("SELECT active FROM storage_cleanup", [], |r| r
                .get::<_, bool>(0))
            .unwrap());
        for table in ["service_summaries", "log_summaries", "check_runs"] {
            assert_eq!(
                db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                2
            );
        }
        assert_eq!(
            db.query_row("SELECT count(*) FROM observations", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM investigations WHERE id='active'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            serde_json::to_value(settings).unwrap(),
            serde_json::to_value(Store::read_settings(&db).unwrap()).unwrap()
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM servers", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            0
        );
    }

    #[test]
    #[ignore = "million-row storage load check; run explicitly"]
    fn million_row_cleanup_uses_indexes_and_short_batches() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("db");
        let (source, server) = fixture();
        source
            .0
            .lock()
            .unwrap()
            .execute("VACUUM INTO ?1", [file.to_str().unwrap()])
            .unwrap();
        let store = Store::open(&file).unwrap();
        {
            let db = store.0.lock().unwrap();
            seed_services(&db, &server, 1_000_000, 512);
            checkpoint(&db);
            let h = &HISTORIES[0];
            let sql=format!("EXPLAIN QUERY PLAN SELECT h.rowid FROM service_summaries h WHERE (h.at,h.rowid)<=(?1,?2) AND {} ORDER BY h.at,h.rowid LIMIT 500",h.disposable());
            let mut q = db.prepare(&sql).unwrap();
            let plan = q
                .query_map(params![i64::MAX, i64::MAX], |r| r.get::<_, String>(3))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
                .join("\n");
            eprintln!("{plan}");
            assert!(plan.contains("service_summaries_retention"));
            assert!(plan.contains("service_summaries_instance_at"));
            assert!(plan.contains("service_evidence_summary"));
            assert!(!plan.contains("TEMP B-TREE"));
        }
        let started = Instant::now();
        let mut passes = 0;
        loop {
            let pass = Instant::now();
            let pending = store.maintain_storage().unwrap().has_more();
            eprintln!("cleanup pass {passes}: {:?}", pass.elapsed());
            assert!(pass.elapsed() < Duration::from_secs(5));
            passes += 1;
            if !pending {
                break;
            }
            assert!(passes < 200);
        }
        eprintln!(
            "million-row cleanup: {:?}, {passes} passes",
            started.elapsed()
        );
        let db = store.0.lock().unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM service_summaries", [], |r| r
                .get::<_, usize>(0))
                .unwrap(),
            52_700
        );
        assert!(admit(&db).is_ok());
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
            db.execute(
                "INSERT INTO log_summaries VALUES('latest',?1,?2,'{}')",
                params![id, now()],
            )
            .unwrap();
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
        while store.maintain_storage().unwrap().has_more() {}
        let db = store.0.lock().unwrap();
        let count = |table: &str| -> i64 {
            db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(count("observations"), 1);
        assert_eq!(count("log_summaries"), 2);
        assert_eq!(count("log_evidence"), 1);
        assert_eq!(count("incidents"), 1);
        assert_eq!(
            db.query_row("SELECT id FROM log_summaries WHERE id='pinned'", [], |r| {
                r.get::<_, String>(0)
            })
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
            db.execute("INSERT INTO investigations VALUES('wal',0,json_object('status','completed','padding',hex(randomblob(524288)))) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",[]).unwrap();
        }
        assert!(admit(&db).is_err());
        let wal = PathBuf::from(format!("{}-wal", path.display()));
        let before = bytes(Some(&wal));
        drop(db);
        assert!(!store.collection_allowed().unwrap());
        assert_eq!(store.maintain_storage().unwrap(), CleanupPass::Deferred);
        assert_eq!(bytes(Some(&wal)), before);
        reader.execute_batch("ROLLBACK;").unwrap();
        assert!(store.storage_cleanup_due().unwrap());
        while store.maintain_storage().unwrap().has_more() {}
        assert!(store.collection_allowed().unwrap());
        let db = store.0.lock().unwrap();
        assert!(admit(&db).is_ok());
    }
}
