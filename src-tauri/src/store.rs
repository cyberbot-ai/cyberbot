use crate::{
    connectivity::{Connectivity, Failure, Ticket},
    inventory::{stable_id, Imported},
    model::*,
};
use rusqlite::{params, Connection, OptionalExtension};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

pub struct Store(
    pub(crate) Mutex<Connection>,
    Mutex<crate::first_check::Runtime>,
    Arc<Connectivity>,
);
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

impl Store {
    pub(crate) fn connectivity(&self) -> &Arc<Connectivity> {
        &self.2
    }

    pub fn open(path: &Path) -> Result<Self> {
        let db = Connection::open(path).map_err(err)?;
        let version: i64 = db
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(err)?;
        if version > 18 {
            return Err(format!(
                "Database version {version} is newer than this app supports. Update Cyberbot."
            ));
        }
        if version < 18 {
            crate::service_migration::initialize_legacy(&db, version)?;
        }
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=3000; BEGIN IMMEDIATE;
          CREATE TABLE IF NOT EXISTS sources(id TEXT PRIMARY KEY, payload TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS servers(id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE, payload TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS observations(id INTEGER PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE, at INTEGER NOT NULL, payload TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS observations_server_at ON observations(server_id, at);
          CREATE INDEX IF NOT EXISTS observations_at ON observations(at);
          CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE, payload TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS investigations(id TEXT PRIMARY KEY, started_at INTEGER NOT NULL, payload TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS ai_jobs(id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE, state TEXT NOT NULL, created_at INTEGER NOT NULL, not_before INTEGER NOT NULL, run_id TEXT, payload TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS ai_jobs_state ON ai_jobs(state,not_before);
          CREATE TABLE IF NOT EXISTS ai_ledger(id TEXT PRIMARY KEY, day INTEGER NOT NULL, reserved INTEGER NOT NULL, actual INTEGER, charged INTEGER NOT NULL, state TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS ai_ledger_day ON ai_ledger(day);
          CREATE TABLE IF NOT EXISTS ai_control(id INTEGER PRIMARY KEY CHECK(id=1), reason TEXT);
          INSERT OR IGNORE INTO ai_control VALUES(1,NULL);
          CREATE TABLE IF NOT EXISTS log_state(server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE, payload TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS log_summaries(id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE, at INTEGER NOT NULL, payload TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS log_summaries_server_at ON log_summaries(server_id,at);
          CREATE TABLE IF NOT EXISTS log_evidence(incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE, summary_id TEXT NOT NULL REFERENCES log_summaries(id) ON DELETE CASCADE, PRIMARY KEY(incident_id,summary_id));
          CREATE TABLE IF NOT EXISTS package_state(server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,payload TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS package_buckets(server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,root TEXT NOT NULL,bucket INTEGER NOT NULL,hash TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(server_id,root,bucket));
          CREATE TABLE IF NOT EXISTS vulnerability_pending(server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE);
          CREATE TABLE IF NOT EXISTS advisory_cvss(cve TEXT PRIMARY KEY,payload TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS advisory_cve_metadata(
            cve TEXT PRIMARY KEY,title TEXT,published_on TEXT,checked_at INTEGER NOT NULL,next_check INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS advisory_network(day INTEGER PRIMARY KEY,bytes INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS advisory_sources(id TEXT PRIMARY KEY,payload TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS vulnerability_findings(server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,source TEXT NOT NULL,cve TEXT NOT NULL,resolved_at INTEGER,payload TEXT NOT NULL,PRIMARY KEY(server_id,source,cve));
          CREATE INDEX IF NOT EXISTS vulnerability_resolved ON vulnerability_findings(resolved_at);
          CREATE TABLE IF NOT EXISTS vulnerability_evaluations(server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,payload TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS vulnerability_evidence(id TEXT PRIMARY KEY,incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,at INTEGER NOT NULL,payload TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS vulnerability_evidence_incident ON vulnerability_evidence(incident_id,at);
          CREATE TABLE IF NOT EXISTS vulnerability_apt(server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,package TEXT NOT NULL,root TEXT NOT NULL,at INTEGER NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(server_id,package));
          CREATE TABLE IF NOT EXISTS maintenance(id INTEGER PRIMARY KEY,at INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS check_definitions(id TEXT PRIMARY KEY,at INTEGER NOT NULL,name TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS check_versions(id TEXT PRIMARY KEY,check_id TEXT NOT NULL REFERENCES check_definitions(id) ON DELETE CASCADE,at INTEGER NOT NULL,spec TEXT NOT NULL,report TEXT,author TEXT NOT NULL,blocked TEXT,UNIQUE(check_id,id));
          CREATE INDEX IF NOT EXISTS check_versions_check ON check_versions(check_id,at);
          CREATE TABLE IF NOT EXISTS check_reviews(server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,version_id TEXT NOT NULL REFERENCES check_versions(id) ON DELETE CASCADE,at INTEGER NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(server_id,version_id));
          CREATE TABLE IF NOT EXISTS check_bindings(server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,check_id TEXT NOT NULL REFERENCES check_definitions(id) ON DELETE CASCADE,payload TEXT NOT NULL,PRIMARY KEY(server_id,check_id));
          CREATE TABLE IF NOT EXISTS check_runs(id TEXT PRIMARY KEY,server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,check_id TEXT NOT NULL REFERENCES check_definitions(id) ON DELETE CASCADE,version_id TEXT NOT NULL REFERENCES check_versions(id) ON DELETE CASCADE,at INTEGER NOT NULL,payload TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS check_runs_at ON check_runs(at);
          CREATE INDEX IF NOT EXISTS check_runs_binding ON check_runs(server_id,check_id,at);
          CREATE TABLE IF NOT EXISTS check_evidence(incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,run_id TEXT NOT NULL REFERENCES check_runs(id) ON DELETE CASCADE,PRIMARY KEY(incident_id,run_id));
          CREATE TABLE IF NOT EXISTS check_events(id INTEGER PRIMARY KEY,check_id TEXT NOT NULL REFERENCES check_definitions(id) ON DELETE CASCADE,server_id TEXT REFERENCES servers(id) ON DELETE CASCADE,at INTEGER NOT NULL,payload TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS service_state(server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,kind TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(server_id,kind));
          CREATE TABLE IF NOT EXISTS service_summaries(id TEXT PRIMARY KEY,server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,kind TEXT NOT NULL,at INTEGER NOT NULL,payload TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS service_summaries_at ON service_summaries(server_id,kind,at);
          CREATE INDEX IF NOT EXISTS service_summaries_retention ON service_summaries(at);
          CREATE TABLE IF NOT EXISTS service_evidence(incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,summary_id TEXT NOT NULL REFERENCES service_summaries(id) ON DELETE CASCADE,PRIMARY KEY(incident_id,summary_id));
          COMMIT;").map_err(err)?;
        // Additive and version-independent: marks inventories whose servers were linked once.
        db.execute_batch("CREATE TABLE IF NOT EXISTS inventory_links(source_id TEXT PRIMARY KEY REFERENCES sources(id) ON DELETE CASCADE);")
            .map_err(err)?;
        if version < 10 {
            crate::service_migration::upgrade_instances(&db)?;
        }
        if version < 11 {
            db.execute_batch("BEGIN IMMEDIATE;
              CREATE TABLE IF NOT EXISTS server_dependencies(server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,depends_on TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,PRIMARY KEY(server_id,depends_on));
              CREATE TABLE IF NOT EXISTS incident_groups(id TEXT PRIMARY KEY,correlation_key TEXT NOT NULL,opened_at INTEGER NOT NULL,status TEXT NOT NULL,updated_at INTEGER NOT NULL,payload TEXT NOT NULL);
              CREATE INDEX IF NOT EXISTS incident_groups_key ON incident_groups(correlation_key,opened_at);
              CREATE TABLE IF NOT EXISTS incident_group_members(episode TEXT PRIMARY KEY,group_id TEXT NOT NULL REFERENCES incident_groups(id) ON DELETE CASCADE,incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,opened_at INTEGER NOT NULL,payload TEXT NOT NULL);
              CREATE INDEX IF NOT EXISTS incident_group_members_group ON incident_group_members(group_id,opened_at);
              PRAGMA user_version=11; COMMIT;").map_err(err)?;
        }
        if version < 12 {
            db.execute_batch(
                "BEGIN IMMEDIATE;
              UPDATE sources SET payload=json_remove(payload,'$.project','$.groups');
              UPDATE servers SET payload=json_remove(payload,'$.project','$.groups');",
            )
            .map_err(err)?;
            crate::correlation::migrate_flat_servers(&db)?;
            db.execute_batch("PRAGMA user_version=12; COMMIT;")
                .map_err(err)?;
        }
        if version < 13 {
            crate::notifications::migrate(&db)?;
        }
        if version < 14 {
            crate::monitoring::migrate(&db)?;
        }
        if version < 15 {
            crate::ai_models::migrate(&db)?;
        }
        if version < 16 {
            crate::ai_actions::migrate(&db)?;
        }
        crate::storage::configure(&db)?;
        if version < 17 {
            crate::vulnerabilities::migrate_groups(&db)?;
        }
        if version < 18 {
            crate::service_migration::upgrade(&db)?;
        }
        crate::storage::initialize(&db)?;
        crate::services::reconcile_resolved_deviations(&db)?;
        let connectivity = Connectivity::new(Self::read_settings(&db)?.connectivity_probe);
        Ok(Self(
            Mutex::new(db),
            Mutex::new(crate::first_check::Runtime::default()),
            Arc::new(connectivity),
        ))
    }
    pub(crate) fn list<T: serde::de::DeserializeOwned>(
        db: &Connection,
        table: &str,
    ) -> Result<Vec<T>> {
        // All table names are internal constants, never user input.
        let mut stmt = db
            .prepare(&format!("SELECT payload FROM {table} ORDER BY rowid"))
            .map_err(err)?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0)).map_err(err)?;
        rows.map(|r| serde_json::from_str(&r.map_err(err)?).map_err(err))
            .collect()
    }
    pub(crate) fn read_server(db: &Connection, id: &str) -> Result<Server> {
        let payload: String = db
            .query_row("SELECT payload FROM servers WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .optional()
            .map_err(err)?
            .ok_or("No server found")?;
        serde_json::from_str(&payload).map_err(err)
    }
    pub(crate) fn server_endpoint(&self, id: &str) -> Result<Endpoint> {
        Ok(self.server(id)?.endpoint)
    }
    pub(crate) fn server(&self, id: &str) -> Result<Server> {
        Self::read_server(&*self.0.lock().map_err(err)?, id)
    }
    pub(crate) fn poll_targets(&self) -> Result<(Vec<Server>, Settings)> {
        let db = self.0.lock().map_err(err)?;
        Ok((Self::list(&db, "servers")?, Self::read_settings(&db)?))
    }
    pub(crate) fn polls_suspended(&self) -> bool {
        self.1.lock().is_ok_and(|runtime| runtime.suspended())
    }
    pub(crate) fn fleet_servers(
        &self,
        db: &Connection,
        at: i64,
    ) -> Result<(Vec<Server>, Vec<String>)> {
        let mut servers: Vec<Server> = Self::list(db, "servers")?;
        let mut first = self.1.lock().map_err(err)?;
        first.sync(&servers, at)?;
        let mut awaiting_first_check = Vec::new();
        for server in &mut servers {
            if let Some(due) = first.pending(server) {
                awaiting_first_check.push(server.id.clone());
                server.next_check = due;
            }
        }
        Ok((servers, awaiting_first_check))
    }
    pub fn snapshot(&self) -> Result<Snapshot> {
        let db = self.0.lock().map_err(err)?;
        let book = crate::monitoring::Book::load(&db)?;
        let (mut servers, awaiting_first_check) = self.fleet_servers(&db, now())?;
        let settings = Self::read_settings(&db)?;
        let monitoring = servers
            .iter()
            .map(|s| {
                Ok((
                    s.id.clone(),
                    book.resolve(&crate::monitoring::scope("metrics", Some(&s.id), None))?
                        .values,
                ))
            })
            .collect::<Result<_>>()?;
        let names = crate::instances::Names::load(&db, None)?;
        let mut incidents: Vec<Incident> = Self::list(&db, "incidents")?;
        for incident in &mut incidents {
            names.decorate_incident(incident);
        }
        // Socket ownership is local label input, not UI/MCP metric history.
        for server in &mut servers {
            if let Some(observation) = &mut server.observation {
                observation.service_runtime.clear();
                observation.service_runtime_complete = false;
            }
        }
        Ok(Snapshot {
            offline: self.2.offline(),
            awaiting_first_check,
            pending_actions: db
                .query_row(
                    "SELECT count(*) FROM ai_requests WHERE state='awaitingApproval'",
                    [],
                    |r| r.get(0),
                )
                .map_err(err)?,
            monitoring,
            services: Self::service_cards(&db)?,
            check_status: crate::checks::statuses(&db)?,
            vulnerabilities: Self::vulnerability_cards(&db)?,
            log_status: Self::log_statuses(&db, settings.log_poll_seconds)?,
            servers,
            sources: Self::list(&db, "sources")?,
            incidents,
            settings,
            collected_at: now(),
        })
    }
    pub(crate) fn read_settings(db: &Connection) -> Result<Settings> {
        let v: Option<String> = db
            .query_row("SELECT payload FROM settings WHERE id=1", [], |r| r.get(0))
            .optional()
            .map_err(err)?;
        let mut s: Settings = v
            .map(|s| serde_json::from_str(&s).map_err(err))
            .unwrap_or_else(|| Ok(Settings::default()))?;
        // During v14 migration this table does not yet exist.
        if db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='monitoring_control')",
                [],
                |r| r.get::<_, bool>(0),
            )
            .map_err(err)?
        {
            s.poll_seconds = crate::monitoring::effective(db, "metrics", "", "")?
                .values
                .interval_seconds;
        }
        Ok(s)
    }
    pub fn settings(&self) -> Result<Settings> {
        let db = self.0.lock().map_err(err)?;
        Self::read_settings(&db)
    }
    pub(crate) fn save_investigation(&self, run: &crate::agents::Investigation) -> Result<()> {
        let db = self.0.lock().map_err(err)?;
        db.execute("INSERT INTO investigations VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", params![run.id,run.started_at,serde_json::to_string(run).map_err(err)?]).map_err(err)?;
        if let Some(actual) = crate::automation::tokens(&run.agent, &run.usage) {
            db.execute("UPDATE ai_ledger SET actual=?2,charged=max(reserved,?2) WHERE id=?1 AND state='running'",params![run.id,actual]).map_err(err)?;
        }
        db.execute("DELETE FROM investigations WHERE id NOT IN (SELECT id FROM investigations ORDER BY started_at DESC, rowid DESC LIMIT 50)", []).map_err(err)?;
        Ok(())
    }
    pub(crate) fn investigations(&self) -> Result<Vec<crate::agents::Investigation>> {
        let db = self.0.lock().map_err(err)?;
        Self::list(&db, "investigations")
    }
    pub fn save_settings(&self, settings: &Settings) -> Result<()> {
        settings.validate()?;
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        let old = Self::read_settings(&tx)?;
        crate::monitoring::legacy_intervals(&tx, &old, settings)?;
        tx.execute("INSERT INTO settings VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", [serde_json::to_string(settings).map_err(err)?]).map_err(err)?;
        tx.commit().map_err(err)?;
        self.2.configure(settings.connectivity_probe.clone());
        Ok(())
    }
    pub fn update_settings(&self, patch: SettingsPatch) -> Result<Settings> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(err)?;
        let mut settings = Self::read_settings(&tx)?;
        let old = settings.clone();
        patch.apply(&mut settings);
        settings.validate()?;
        crate::monitoring::legacy_intervals(&tx, &old, &settings)?;
        tx.execute("INSERT INTO settings VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", [serde_json::to_string(&settings).map_err(err)?]).map_err(err)?;
        tx.commit().map_err(err)?;
        self.2.configure(settings.connectivity_probe.clone());
        Ok(settings)
    }
    pub fn import(&self, source: &Source, hosts: Vec<Imported>) -> Result<usize> {
        let mut db = self.0.lock().map_err(err)?;
        crate::storage::admit(&db)?;
        let tx = db.transaction().map_err(err)?;
        tx.execute("INSERT INTO sources VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", params![source.id,serde_json::to_string(source).map_err(err)?]).map_err(err)?;
        let old: Vec<Server> = Self::list(&tx, "servers")?;
        let mut keep = std::collections::HashSet::new();
        let mut order = Vec::new();
        let mut fresh = std::collections::BTreeSet::new();
        for host in hosts {
            let id = stable_id(&source.id, &host.identity);
            if keep.insert(id.clone()) {
                order.push(id.clone());
            }
            let previous = old.iter().find(|s| {
                s.id == id
                    && serde_json::to_string(&s.endpoint).ok()
                        == serde_json::to_string(&host.endpoint).ok()
            });
            if previous.is_none() && old.iter().any(|s| s.id == id) {
                Self::dependents(&tx, &id, &mut fresh)?;
                tx.execute(
                    "DELETE FROM server_dependencies WHERE server_id=?1 OR depends_on=?1",
                    [&id],
                )
                .map_err(err)?;
                for table in [
                    "service_instances",
                    "service_state",
                    "service_summaries",
                    "check_bindings",
                    "check_runs",
                    "check_events",
                    "check_reviews",
                    "package_state",
                    "package_buckets",
                    "vulnerability_pending",
                    "vulnerability_findings",
                    "vulnerability_groups",
                    "vulnerability_evaluations",
                    "vulnerability_apt",
                ] {
                    tx.execute(&format!("DELETE FROM {table} WHERE server_id=?1"), [&id])
                        .map_err(err)?;
                }
                tx.execute("DELETE FROM log_state WHERE server_id=?1", [&id])
                    .map_err(err)?;
                tx.execute("DELETE FROM log_summaries WHERE server_id=?1", [&id])
                    .map_err(err)?;
                tx.execute("DELETE FROM incidents WHERE server_id=?1", [&id])
                    .map_err(err)?;
                tx.execute("DELETE FROM ai_jobs WHERE server_id=?1", [&id])
                    .map_err(err)?;
            }
            let server = Server {
                id,
                source_id: source.id.clone(),
                name: host.name,

                endpoint: host.endpoint,
                observation: previous.and_then(|s| s.observation.clone()),
                last_error: previous.and_then(|s| s.last_error.clone()),
                last_attempt: previous.and_then(|s| s.last_attempt),
                next_check: previous
                    .map(|s| s.next_check)
                    .unwrap_or_else(|| now() + i64::from(keep.len() as u32 % 30)),
                failures: previous.map(|s| s.failures).unwrap_or(0),
            };
            if previous.is_none() {
                fresh.insert(server.id.clone());
            }
            tx.execute("INSERT INTO servers VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",params![server.id,source.id,serde_json::to_string(&server).map_err(err)?]).map_err(err)?;
        }
        for s in old
            .iter()
            .filter(|s| s.source_id == source.id && !keep.contains(&s.id))
        {
            Self::dependents(&tx, &s.id, &mut fresh)?;
            tx.execute("DELETE FROM servers WHERE id=?1", [&s.id])
                .map_err(err)?;
        }
        if source.kind == "ansible" {
            // Servers orphaned by a removed or re-addressed hub are linked again.
            fresh.retain(|id| keep.contains(id));
            crate::correlation::link_inventory(&tx, &source.id, &order, &fresh)?;
        }
        tx.commit().map_err(err)?;
        self.1
            .lock()
            .map_err(err)?
            .sync(&Self::list(&db, "servers")?, now())?;
        Ok(keep.len())
    }
    fn dependents(
        db: &Connection,
        id: &str,
        into: &mut std::collections::BTreeSet<String>,
    ) -> Result<()> {
        let mut q = db
            .prepare("SELECT server_id FROM server_dependencies WHERE depends_on=?1")
            .map_err(err)?;
        for row in q.query_map([id], |r| r.get::<_, String>(0)).map_err(err)? {
            into.insert(row.map_err(err)?);
        }
        Ok(())
    }
    pub fn source_error(&self, source: &Source, message: String) -> Result<()> {
        let mut s = source.clone();
        s.error = Some(message);
        self.0
            .lock()
            .map_err(err)?
            .execute(
                "UPDATE sources SET payload=?2 WHERE id=?1",
                params![s.id, serde_json::to_string(&s).map_err(err)?],
            )
            .map_err(err)?;
        Ok(())
    }
    pub fn delete_source(&self, id: &str) -> Result<()> {
        let db = self.0.lock().map_err(err)?;
        db.execute("DELETE FROM sources WHERE id=?1", [id])
            .map_err(err)?;
        self.1
            .lock()
            .map_err(err)?
            .sync(&Self::list(&db, "servers")?, now())?;
        Ok(())
    }
    pub fn history(&self, id: &str) -> Result<Vec<Observation>> {
        let db = self.0.lock().map_err(err)?;
        let mut stmt=db.prepare("SELECT payload FROM (SELECT at,payload FROM observations WHERE server_id=?1 ORDER BY at DESC LIMIT 240) ORDER BY at").map_err(err)?;
        let rows = stmt
            .query_map([id], |r| r.get::<_, String>(0))
            .map_err(err)?;
        rows.map(|r| serde_json::from_str(&r.map_err(err)?).map_err(err))
            .collect()
    }
    pub(crate) fn reset_metrics_checks(&self) -> Result<()> {
        let _db = self.0.lock().map_err(err)?;
        self.1.lock().map_err(err)?.reset();
        Ok(())
    }
    pub(crate) fn suspend_metrics_checks(&self) -> Result<u64> {
        let _db = self.0.lock().map_err(err)?;
        self.2.recheck();
        Ok(self.1.lock().map_err(err)?.suspend())
    }
    pub(crate) fn resume_metrics_checks(&self, epoch: u64) -> Result<()> {
        let _db = self.0.lock().map_err(err)?;
        self.1.lock().map_err(err)?.resume(epoch);
        self.2.recheck();
        Ok(())
    }
    pub(crate) fn reschedule_metrics_checks(&self) -> Result<()> {
        let db = self.0.lock().map_err(err)?;
        let book = crate::monitoring::Book::load(&db)?;
        self.1
            .lock()
            .map_err(err)?
            .reschedule(now(), |id| book.enabled("metrics", id, ""));
        Ok(())
    }
    pub(crate) fn begin_metrics_check(
        &self,
        original: &Server,
    ) -> Result<crate::first_check::Attempt> {
        let db = self.0.lock().map_err(err)?;
        let current: String = db
            .query_row(
                "SELECT payload FROM servers WHERE id=?1",
                [&original.id],
                |r| r.get(0),
            )
            .map_err(err)?;
        let current: Server = serde_json::from_str(&current).map_err(err)?;
        if serde_json::to_string(&current.endpoint).map_err(err)?
            != serde_json::to_string(&original.endpoint).map_err(err)?
        {
            return Err("The server connection has changed".into());
        }
        self.1.lock().map_err(err)?.begin(&current, now())
    }
    pub(crate) fn check_poll_attempt(
        &self,
        attempt: &crate::first_check::Attempt,
        server: &Server,
    ) -> Result<()> {
        let db = self.0.lock().map_err(err)?;
        crate::monitoring::check_commit(&db)?;
        let current = Self::read_server(&db, &server.id)?;
        if self.1.lock().map_err(err)?.accepts(attempt, &current) {
            Ok(())
        } else {
            Err("Check response is outdated after sleep or server change".into())
        }
    }
    #[cfg(test)]
    pub fn record(
        &self,
        original: &Server,
        result: Result<Observation>,
        interval: u64,
    ) -> Result<()> {
        let attempt = self.begin_metrics_check(original)?;
        self.record_metrics(&attempt, original, result, interval)
    }
    pub(crate) fn record_metrics(
        &self,
        attempt: &crate::first_check::Attempt,
        original: &Server,
        result: Result<Observation>,
        _interval: u64,
    ) -> Result<()> {
        self.record_metrics_inner(attempt, original, result, None)
    }
    pub(crate) fn record_network_metrics(
        &self,
        attempt: &crate::first_check::Attempt,
        original: &Server,
        result: Result<Observation>,
        confirmed: Option<Ticket>,
    ) -> Result<()> {
        self.record_metrics_inner(attempt, original, result, Some(confirmed))
    }
    fn record_metrics_inner(
        &self,
        attempt: &crate::first_check::Attempt,
        original: &Server,
        result: Result<Observation>,
        network_verdict: Option<Option<Ticket>>,
    ) -> Result<()> {
        let mut db = self.0.lock().map_err(err)?;
        crate::storage::admit(&db)?;
        let tx = db.transaction().map_err(err)?;
        crate::monitoring::check_commit(&tx)?;
        let policy = crate::monitoring::effective(&tx, "metrics", &original.id, "")?.values;
        let interval = policy.interval_seconds;
        let current: Option<String> = tx
            .query_row(
                "SELECT payload FROM servers WHERE id=?1",
                [&original.id],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        let Some(current) = current else {
            return Ok(());
        };
        let mut s: Server = serde_json::from_str(&current).map_err(err)?;
        let mut first = self.1.lock().map_err(err)?;
        if !first.accepts(attempt, &s) {
            return Err("Check response is outdated after sleep or server change".into());
        }
        if serde_json::to_string(&s.endpoint).map_err(err)?
            != serde_json::to_string(&original.endpoint).map_err(err)?
        {
            return Ok(());
        }
        let at = now();
        let gate = network_verdict
            .filter(|_| result.is_err())
            .map(|verdict| self.2.commit_guard(verdict));
        if gate.as_deref() == Some(&Failure::Discard) {
            return Ok(());
        }
        let offline = gate.as_deref() == Some(&Failure::Offline);
        if !offline {
            s.last_attempt = Some(at);
        }
        match result {
            Ok(o) => {
                let refresh_known_units = first.pending(&s).is_some() || s.last_error.is_some();
                s.failures = 0;
                s.last_error = None;
                let running = |r: &crate::instances::RuntimeIdentity| {
                    r.complete && (!r.ports.is_empty() || !r.sockets.is_empty())
                };
                let new_services: std::collections::BTreeSet<_> = o
                    .service_runtime
                    .iter()
                    .filter(|r| {
                        running(r)
                            && !s.observation.as_ref().is_some_and(|old| {
                                old.service_runtime
                                    .iter()
                                    .any(|p| p.kind == r.kind && running(p))
                            })
                    })
                    .map(|r| r.kind.as_str())
                    .collect();
                for kind in new_services {
                    if crate::services::descriptor(kind)
                        .is_some_and(|spec| spec.refresh_on_discovery)
                    {
                        tx.execute("UPDATE service_state SET payload=json_set(payload,'$.nextCheck',min(json_extract(payload,'$.nextCheck'),?3)) WHERE server_id=?1 AND kind=?2 AND instance_id='default'", params![s.id, kind, at]).map_err(err)?;
                    }
                }
                crate::services::schedule_observed_units(&tx, &s, &o, refresh_known_units, at)?;
                let mut history = o.clone();
                history.service_runtime.clear();
                history.service_runtime_complete = false;
                tx.execute(
                    "INSERT INTO observations(server_id,at,payload) VALUES(?1,?2,?3)",
                    params![s.id, o.at, serde_json::to_string(&history).map_err(err)?],
                )
                .map_err(err)?;
                Self::incident(&tx, &s.id, "connection", None, "Connection", "critical", at)?;
                for (check, value) in [("cpu", o.cpu_percent), ("memory", o.memory_percent)] {
                    let threshold = policy.thresholds[check]["warning"];
                    if let Some(v) = value {
                        Self::incident(
                            &tx,
                            &s.id,
                            check,
                            if v >= threshold {
                                Some(format!("{v:.1}% ≥ {threshold}%"))
                            } else {
                                None
                            },
                            if check == "cpu" {
                                "High CPU usage"
                            } else {
                                "Low available memory"
                            },
                            "warning",
                            at,
                        )?;
                    }
                }
                let limits = &policy.thresholds["disk"];
                for d in &o.disks {
                    Self::incident(
                        &tx,
                        &s.id,
                        &format!("disk:{}", d.mount),
                        if d.used_percent >= limits["warning"] {
                            Some(format!("{}: {:.1}% busy", d.mount, d.used_percent))
                        } else {
                            None
                        },
                        "The disk is filling up",
                        crate::monitoring::thresholds::severity(limits, d.used_percent),
                        at,
                    )?;
                }
                s.observation = Some(o);
            }
            Err(message) if !offline => {
                s.failures = s.failures.saturating_add(1);
                s.last_error = Some(message.clone());
                if s.failures >= 2 {
                    Self::incident(
                        &tx,
                        &s.id,
                        "connection",
                        Some(message),
                        "Server poll failed",
                        "warning",
                        at,
                    )?;
                }
            }
            Err(_) => (),
        }
        let backoff = if offline {
            1
        } else {
            2_u64.saturating_pow(s.failures.min(5))
        };
        let jitter = u64::from(s.id.bytes().fold(0_u8, |a, b| a.wrapping_add(b))) % 20;
        s.next_check = at + (interval.saturating_mul(backoff).min(3600) + jitter) as i64;
        tx.execute(
            "UPDATE servers SET payload=?2 WHERE id=?1",
            params![s.id, serde_json::to_string(&s).map_err(err)?],
        )
        .map_err(err)?;
        tx.commit().map_err(err)?;
        first.complete(attempt);
        Ok(())
    }
    pub(crate) fn incident(
        db: &Connection,
        server: &str,
        check: &str,
        evidence: Option<String>,
        title: &str,
        severity: &str,
        at: i64,
    ) -> Result<()> {
        let id = stable_id(server, check);
        let old: Option<String> = db
            .query_row("SELECT payload FROM incidents WHERE id=?1", [&id], |r| {
                r.get(0)
            })
            .optional()
            .map_err(err)?;
        let old: Option<Incident> = old
            .map(|v| serde_json::from_str(&v))
            .transpose()
            .map_err(err)?;
        if evidence.is_none() && old.is_none() {
            return Ok(());
        }
        let active = evidence.is_some();
        if let Some(mut i) = old.clone().filter(|i| i.manual_resolution_pending) {
            i.healthy_streak = if active {
                0
            } else {
                i.healthy_streak.saturating_add(1)
            };
            i.manual_resolution_pending = i.healthy_streak < 2;
            i.updated_at = at;
            i.auto_eligible = false;
            i.fresh_until = Some(at - 1);
            db.execute(
                "UPDATE incidents SET payload=?2 WHERE id=?1",
                params![id, serde_json::to_string(&i).map_err(err)?],
            )
            .map_err(err)?;
            return Ok(());
        }
        let was_open = old.as_ref().is_some_and(|v| v.status == "open");
        let healthy_streak = if active {
            0
        } else {
            old.as_ref()
                .map_or(1, |v| v.healthy_streak.saturating_add(1))
        };
        let still_open = active || was_open && healthy_streak < 2;
        let episode = if active && !was_open {
            uuid::Uuid::new_v4().to_string()
        } else {
            old.as_ref()
                .map(|v| {
                    if v.episode.is_empty() {
                        format!("{}:{}", v.id, v.opened_at)
                    } else {
                        v.episode.clone()
                    }
                })
                .unwrap_or_default()
        };
        let incident = Incident {
            resolved_by_user_at: old
                .as_ref()
                .filter(|_| !active)
                .and_then(|i| i.resolved_by_user_at),
            manual_resolution_pending: false,
            auto_eligible: true,
            fresh_until: if matches!(check, "cpu" | "memory" | "connection")
                || check.starts_with("disk:")
            {
                Some(
                    at + (crate::monitoring::effective(db, "metrics", server, "")?
                        .values
                        .interval_seconds
                        * 2
                        + 30) as i64,
                )
            } else {
                None
            },
            episode,
            occurrences: if active {
                if was_open {
                    old.as_ref().map_or(1, |v| v.occurrences.saturating_add(1))
                } else {
                    1
                }
            } else {
                old.as_ref().map_or(0, |v| v.occurrences)
            },
            healthy_streak,
            id: id.clone(),
            server_id: server.into(),
            check: check.into(),
            title: title.into(),
            severity: if !active {
                old.as_ref().map_or(severity, |v| v.severity.as_str())
            } else {
                severity
            }
            .into(),
            status: if still_open { "open" } else { "resolved" }.into(),
            opened_at: old
                .as_ref()
                .filter(|_| was_open || !active)
                .map(|v| v.opened_at)
                .unwrap_or(at),
            updated_at: at,
            evidence: evidence.unwrap_or_else(|| {
                if still_open {
                    "Awaiting confirmation of recovery"
                } else {
                    "Check recovered"
                }
                .into()
            }),
        };
        db.execute("INSERT INTO incidents VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",params![id,server,serde_json::to_string(&incident).map_err(err)?]).map_err(err)?;
        if active && !was_open {
            crate::notifications::enqueue(db, &incident)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn settings_patches_preserve_unrelated_fields_and_explicitly_clear_optional_limits() {
        let db = Store::open(Path::new(":memory:")).unwrap();
        let initial = Settings {
            mode: "auto".into(),
            daily_run_limit: Some(3),
            daily_token_limit: Some(200_000),
            paused: true,
            ..Settings::default()
        };
        db.save_settings(&initial).unwrap();
        let updated = db
            .update_settings(
                serde_json::from_str(r#"{"pollSeconds":900,"concurrency":24}"#).unwrap(),
            )
            .unwrap();
        assert_eq!(updated.poll_seconds, 900);
        assert!(updated.paused);
        assert_eq!(updated.mode, "auto");
        assert_eq!(updated.daily_token_limit, Some(200_000));
        let cleared = db
            .update_settings(
                serde_json::from_str(r#"{"mode":"manual","dailyTokenLimit":null}"#).unwrap(),
            )
            .unwrap();
        assert_eq!(cleared.daily_token_limit, None);
        assert_eq!(cleared.daily_run_limit, Some(3));
        assert_eq!(cleared.poll_seconds, 900);
        assert_eq!(cleared.concurrency, 24);
    }
    #[test]
    fn invalid_settings_patch_leaves_the_whole_profile_unchanged() {
        let db = Store::open(Path::new(":memory:")).unwrap();
        let before = serde_json::to_value(db.settings().unwrap()).unwrap();
        for json in [
            r#"{"pollSeconds":1,"paused":true}"#,
            r#"{"concurrency":25,"paused":true}"#,
            r#"{"mode":"unknown"}"#,
            r#"{"dailyTokenLimit":999}"#,
            r#"{"runTokenLimit":9007199254740992}"#,
        ] {
            assert!(db
                .update_settings(serde_json::from_str(json).unwrap())
                .is_err());
            assert_eq!(
                serde_json::to_value(db.settings().unwrap()).unwrap(),
                before
            );
        }
        for json in [
            r#"{"concurrency":1.5}"#,
            r#"{"pollSeconds":"300"}"#,
            r#"{"unknown":true}"#,
        ] {
            assert!(serde_json::from_str::<SettingsPatch>(json).is_err());
        }
    }
    #[test]
    fn simultaneous_settings_edits_do_not_replace_each_other() {
        let db = Store::open(Path::new(":memory:")).unwrap();
        std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                db.update_settings(serde_json::from_str(r#"{"pollSeconds":600}"#).unwrap())
                    .unwrap()
            });
            let second = scope.spawn(|| {
                db.update_settings(serde_json::from_str(r#"{"paused":true}"#).unwrap())
                    .unwrap()
            });
            first.join().unwrap();
            second.join().unwrap();
        });
        assert_eq!(db.settings().unwrap().poll_seconds, 600);
        assert!(db.settings().unwrap().paused);
    }
    #[test]
    fn import_is_atomic_and_keeps_last_snapshot() {
        let db = Store::open(Path::new(":memory:")).unwrap();
        let src = Source {
            id: "s".into(),
            name: "test".into(),

            kind: "manual".into(),
            location: "ops@node".into(),
            last_sync: Some(now()),
            error: None,
        };
        db.import(&src, crate::inventory::parse_manual("ops@node").unwrap())
            .unwrap();
        db.source_error(&src, "broken inventory".into()).unwrap();
        assert_eq!(db.snapshot().unwrap().servers.len(), 1);
        db.delete_source("s").unwrap();
        assert!(db.snapshot().unwrap().servers.is_empty());
    }
    #[test]
    fn manual_display_names_keep_existing_ids_and_history() {
        let db = Store::open(Path::new(":memory:")).unwrap();
        let mut source = Source {
            id: "manual".into(),
            name: "Legacy list".into(),
            kind: "manual".into(),
            location: "ops@node".into(),
            last_sync: None,
            error: None,
        };
        let mut legacy = crate::inventory::parse_manual(&source.location).unwrap();
        legacy[0].name = "ops@node:22".into();
        db.import(&source, legacy).unwrap();
        let original = db.snapshot().unwrap().servers.remove(0);
        assert_eq!(original.id, stable_id(&source.id, "ops@node:22"));
        db.record(&original, Err("SSH unavailable".into()), 180)
            .unwrap();
        let recorded = db.snapshot().unwrap().servers.remove(0);

        for address in ["ops@node", "ops@node:22"] {
            source.location = address.into();
            db.import(&source, crate::inventory::parse_manual(address).unwrap())
                .unwrap();
            let snapshot = db.snapshot().unwrap();
            assert_eq!(snapshot.servers.len(), 1);
            let refreshed = &snapshot.servers[0];
            assert_eq!(refreshed.id, original.id);
            assert_eq!(refreshed.name, address);
            assert_eq!(refreshed.last_error, recorded.last_error);
            assert_eq!(refreshed.last_attempt, recorded.last_attempt);
            assert_eq!(refreshed.failures, recorded.failures);
        }
    }
    #[test]
    fn result_does_not_resurrect_removed_server() {
        let db = Store::open(Path::new(":memory:")).unwrap();
        let src = Source {
            id: "s".into(),
            name: "test".into(),

            kind: "manual".into(),
            location: "ops@node".into(),
            last_sync: None,
            error: None,
        };
        db.import(&src, crate::inventory::parse_manual("ops@node").unwrap())
            .unwrap();
        let server = db.snapshot().unwrap().servers.remove(0);
        let attempt = db.begin_metrics_check(&server).unwrap();
        db.delete_source("s").unwrap();
        db.record_metrics(&attempt, &server, Err("timeout".into()), 180)
            .unwrap();
        assert!(db.snapshot().unwrap().servers.is_empty());
    }
    #[test]
    fn incident_recovery_needs_two_successes_and_recurrence_gets_new_episode() {
        let db = Store::open(Path::new(":memory:"))
            .unwrap()
            .0
            .into_inner()
            .unwrap();
        db.pragma_update(None, "foreign_keys", false).unwrap();
        for at in 1..=5 {
            Store::incident(
                &db,
                "server",
                "cpu",
                Some("95%".into()),
                "CPU",
                "warning",
                at,
            )
            .unwrap();
        }
        let current = || Store::list::<Incident>(&db, "incidents").unwrap().remove(0);
        let original = current();
        assert_eq!(original.occurrences, 5);
        assert_eq!(original.opened_at, 1);
        Store::incident(&db, "server", "cpu", None, "CPU", "warning", 6).unwrap();
        assert_eq!(current().status, "open");
        Store::incident(
            &db,
            "server",
            "cpu",
            Some("96%".into()),
            "CPU",
            "warning",
            7,
        )
        .unwrap();
        assert_eq!(current().episode, original.episode);
        assert_eq!(current().healthy_streak, 0);
        Store::incident(&db, "server", "cpu", None, "CPU", "warning", 8).unwrap();
        Store::incident(&db, "server", "cpu", None, "CPU", "warning", 9).unwrap();
        assert_eq!(current().status, "resolved");
        Store::incident(
            &db,
            "server",
            "cpu",
            Some("95%".into()),
            "CPU",
            "warning",
            10,
        )
        .unwrap();
        assert_ne!(current().episode, original.episode);
        assert_eq!(current().opened_at, 10);
        assert_eq!(current().occurrences, 1);
    }
    #[test]
    fn auto_accepts_legacy_unset_daily_limits() {
        let mut s = Settings {
            mode: "auto".into(),
            ..Default::default()
        };
        s.daily_run_limit = None;
        s.daily_token_limit = None;
        s.run_token_limit = 50_000;
        assert!(s.validate().is_ok());
    }
}
