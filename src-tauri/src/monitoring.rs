//! The same allowlisted definitions drive admission, schedules and the inspection UI.
use crate::{instances, model::now, services, ssh, store::Store};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, future::Future, sync::LazyLock};
pub(crate) mod thresholds;
use thresholds::{ThresholdRule, Thresholds};
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Runner {
    Metrics,
    Logs,
    Packages,
    Apt,
    Service,
    Custom,
    Local,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Definition {
    pub id: String,
    pub name: String,
    pub category: String,
    pub runner: Runner,
    pub place: String,
    pub purpose: String,
    pub reads: String,
    pub commands: String,
    pub writes: String,
    pub rights: String,
    pub limits: String,
    pub schedule: String,
    pub configurable: bool,
    pub interval_editable: bool,
    pub diagnostics: bool,
    pub replication: bool,
    pub factory_interval: u64,
    pub thresholds: Vec<ThresholdRule>,
    pub version: String,
}
static REGISTRY: LazyLock<Vec<Definition>> = LazyLock::new(build_catalog);
pub fn catalog() -> Vec<Definition> {
    REGISTRY.clone()
}
fn build_catalog() -> Vec<Definition> {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    for bytes in [
        ssh::COLLECTOR,
        include_str!("store.rs"),
        include_str!("server_poll.rs"),
        include_str!("services.rs"),
        include_str!("logs.rs"),
        include_str!("packages.rs"),
        include_str!("checks.rs"),
        include_str!("monitoring.rs"),
        include_str!("monitoring/thresholds.rs"),
        include_str!("advisories.rs"),
        include_str!("inventory.rs"),
        include_str!("storage.rs"),
    ] {
        digest.update(bytes.as_bytes());
    }
    let catalog = services::catalog();
    for kind in catalog.keys() {
        if let Some(adapter) = services::backend(kind) {
            digest.update(adapter.source.as_bytes());
        }
    }
    let version = format!("{:x}", digest.finalize())[..24].to_owned();
    let mut out = Vec::new();
    for (id,name,category,runner,interval,purpose,reads,commands,rights,limits,schedule) in [
      ("metrics","System resources and services","Operating system",Runner::Metrics,180,"CPU, memory, drives, uptime, and state of selected services","/proc (including limited information about PIDs and listening sockets), /sys, /etc/os-release, mount points; fixed list of services","python3 -I <collector>; systemctl show (fixed-services only)","Reading system information by an SSH user","Answer up to 8 KiB; transport 25 s","With each server poll"),
      ("logs","System and SSH logs","Logs",Runner::Logs,600,"Aggregates logs on the server and detects significant events. Routine SSH activity does not create incidents.","journal or /var/log/{auth.log,syslog,kern.log,fail2ban.log}, with saved read positions","python3 -I <collector>; journalctl --output=json by cursor; files are read on the server","Read access to selected logs. Missing permissions are reported.","Reads up to 2 MiB and returns up to 32 KiB with 10 redacted examples. Limits include 15 s elapsed time, 8 s CPU time, and 96 MiB of Python memory.","With each server poll"),

      ("packages","Installed OS packages","Vulnerabilities",Runner::Packages,21600,"Track changes to installed packages and match them against critical advisories","OS release information and installed packages and versions from the dpkg database","python3 -I <collector>; dpkg-query (page-by-page)","Read access to the installed package database","Response limited to 32 KiB. Sends only changed groups and saves progress between checks.","With each server poll"),
      ("apt","Available APT fixes","Vulnerabilities",Runner::Apt,21600,"Check available versions for affected packages","The existing local APT cache","python3 -I <collector>; apt-cache policy for a verified list of packages","Read access to the existing APT cache","Bounded package count and a 32 KiB response limit","With each server poll when affected packages have been identified"),

      ("custom","Custom checks","Checks",Runner::Custom,0,"Reusable rules with previews, tests, versions, and rollback","Saved metrics from the allowed fields","Declarative rules run in the isolated check runner","The user enables a reviewed version. Scheduled runs require no model.","The check editor shows language limits, versions, and tests.","Each enabled version follows its own schedule"),
      ("advisories","Vulnerability data","Official",Runner::Local,21600,"Refresh Ubuntu and Debian advisories and CVSS scores","Official distribution advisories and CVSS scores for relevant CVEs","HTTPS with conditional requests; local version matching with backport fixes","Network access to public advisory sources","Network and cache limits apply. The app stores critical records only.","Refresh advisories every 6 hours and CVSS scores in daily batches"),
      ("inventory","Updating server lists","Official",Runner::Local,300,"Re-read the selected Ansible inventory and keep the last successfully loaded list","Selected static Ansible inventory","Built-in parser for static inventory files","Access to the selected file","Limits apply to file size, nesting depth, and host count. Reads the source file without modifying it.","Every 5 minutes"),
      ("storage","Cleaning up local storage","Official",Runner::Local,crate::storage::CLEANUP_INTERVAL_SECONDS,"Limit the size of the database, evidence, cache, queues, and activity log","Local SQLite, cache, activity log","Fixed SQL cleanup, WAL checkpointing, and JSONL log rotation","Access only to application data","SQLite up to 1 GiB; action log up to 30 MiB; storage rules in settings","Every 5 minutes, with shorter intervals while cleanup is pending or storage is under pressure"),
      ("transport","SSH and collector deployment","Official",Runner::Local,0,"Verify host keys and deploy immutable collector versions by hash over a bounded SSH connection pool","The SSH process uses local configuration, keys, and known_hosts","OpenSSH; test -f; sha256sum; mkdir; rsync --checksum; python3 -I","Uses the configured SSH user and host-key checks","The pool holds 32 to 192 connections based on inventory. Keepalive is 60 seconds, and idle connections expire after 15 minutes. Strict host key checks and timeouts apply.","Before an authorized check, Cyberbot transfers the collector only if the required version is missing or changed"),
    ] {
      out.push(Definition{id:id.into(),name:name.into(),category:category.into(),runner,place:if matches!(runner,Runner::Custom|Runner::Local){"On the computer"}else{"Data collection on the server, incident rules on this computer"}.into(),purpose:purpose.into(),reads:reads.into(),commands:commands.into(),writes:if matches!(runner,Runner::Custom|Runner::Local){"Limited application state on this computer"}else{"Versioned collector files under ~/.cache/cyberbot"}.into(),rights:rights.into(),limits:limits.into(),schedule:schedule.into(),configurable:!matches!(runner,Runner::Custom|Runner::Local),interval_editable:false,diagnostics:false,replication:false,factory_interval:interval,thresholds:thresholds::for_definition(id, &[]),version:version.clone()});
    }
    for (id, spec) in catalog {
        let thresholds = thresholds::for_definition(&id, &spec.metrics);
        let description = spec
            .monitoring
            .unwrap_or_else(|| services::ServiceDescription {
                purpose: spec
                    .metrics
                    .iter()
                    .map(|m| m.label.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                reads: "Available local service status and statistics".into(),
                commands: format!(
                    "python3 -I <collector>; connector: {}.",
                    spec.actions.join(", ")
                ),
                rights: spec.rights,
                limits:
                    "Fixed requests to a local endpoint, with timeouts and a 32 KiB response limit"
                        .into(),
                schedule: "With each server poll".into(),
            });
        out.push(Definition {
            id,
            name: spec.name,
            category: "Services".into(),
            runner: Runner::Service,
            place: "Data collection on the server, incident rules on this computer".into(),
            purpose: description.purpose,
            reads: description.reads,
            commands: description.commands,
            writes: "Versioned collector files under ~/.cache/cyberbot".into(),
            rights: description.rights,
            limits: description.limits,
            schedule: "With each server poll".into(),
            configurable: true,
            interval_editable: false,
            diagnostics: spec.actions.iter().any(|action| action == "configure"),
            replication: spec.replication,
            factory_interval: spec.factory_interval,
            thresholds,
            version: version.clone(),
        });
    }
    out
}
pub fn definition(id: &str) -> Result<&'static Definition> {
    REGISTRY
        .iter()
        .find(|d| d.id == id)
        .ok_or("Unknown check".into())
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Overrides {
    pub enabled: Option<bool>,
    pub interval_seconds: Option<u64>,
    pub diagnostic_enabled: Option<bool>,
    pub expected_peers: Option<u32>,
    pub expect_replica: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub thresholds: Thresholds,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Scope {
    pub definition_id: String,
    pub server_id: Option<String>,
    pub instance_id: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Values {
    pub enabled: bool,
    pub interval_seconds: u64,
    pub diagnostic_enabled: bool,
    pub expected_peers: u32,
    pub expect_replica: bool,
    pub thresholds: Thresholds,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub values: Values,
    pub inherited: Values,
    pub origins: BTreeMap<String, String>,
    pub threshold_origins: BTreeMap<String, String>,
    pub overrides: Overrides,
    pub revision: i64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryEntry {
    pub values: Values,
    pub server_override: bool,
    pub instance_overrides: BTreeMap<String, Values>,
}
#[derive(Clone, Default)]
pub struct Book {
    rows: BTreeMap<String, Overrides>,
    revision: i64,
}
fn key(s: &Scope) -> String {
    format!(
        "{}:{}:{}",
        s.definition_id,
        s.server_id.as_deref().unwrap_or(""),
        s.instance_id.as_deref().unwrap_or("")
    )
}
impl Book {
    pub(crate) fn poll_seconds(&self) -> u64 {
        self.rows
            .get("metrics::")
            .and_then(|overrides| overrides.interval_seconds)
            .unwrap_or(180)
    }
    fn read(db: &Connection, sql: &str, params: impl rusqlite::Params) -> Result<Self> {
        let revision = db
            .query_row(
                "SELECT revision FROM monitoring_control WHERE id=1",
                [],
                |r| r.get(0),
            )
            .map_err(err)?;
        let mut q = db.prepare(sql).map_err(err)?;
        let rows = q
            .query_map(params, |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(err)?
            .map(|r| {
                let (k, v) = r.map_err(err)?;
                Ok((k, serde_json::from_str(&v).map_err(err)?))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        Ok(Self { rows, revision })
    }
    pub fn load(db: &Connection) -> Result<Self> {
        Self::read(db, "SELECT id,payload FROM monitoring_overrides", [])
    }
    fn selected(db: &Connection, s: &Scope) -> Result<Self> {
        let global = key(&scope(&s.definition_id, None, None));
        let server = key(&scope(&s.definition_id, s.server_id.as_deref(), None));
        Self::read(
            db,
            "SELECT id,payload FROM monitoring_overrides WHERE id IN (?1,?2,?3,'metrics::')",
            params![global, server, key(s)],
        )
    }
    pub fn resolve(&self, s: &Scope) -> Result<Policy> {
        let d = definition(&s.definition_id)?;
        let factory = Values {
            enabled: true,
            interval_seconds: d.factory_interval,
            diagnostic_enabled: d.diagnostics,
            expected_peers: 0,
            expect_replica: false,
            thresholds: d
                .thresholds
                .iter()
                .map(|rule| (rule.key.clone(), rule.defaults()))
                .collect(),
        };
        let mut p = Policy {
            values: factory.clone(),
            inherited: factory,
            threshold_origins: d
                .thresholds
                .iter()
                .map(|rule| (rule.key.clone(), "factory".into()))
                .collect(),
            origins: [
                "enabled",
                "intervalSeconds",
                "diagnosticEnabled",
                "expectedPeers",
                "expectReplica",
            ]
            .map(|k| (k.into(), "factory".into()))
            .into(),
            overrides: self.rows.get(&key(s)).cloned().unwrap_or_default(),
            revision: self.revision,
        };
        let mut layer = Scope {
            definition_id: s.definition_id.clone(),
            server_id: None,
            instance_id: None,
        };
        for origin in ["global", "server", "instance"] {
            if origin == "server" {
                if s.server_id.is_none() {
                    break;
                }
                layer.server_id = s.server_id.clone();
            }
            if origin == "instance" {
                if s.instance_id.is_none() {
                    break;
                }
                layer.instance_id = s.instance_id.clone();
            }
            if key(&layer) == key(s) {
                p.inherited = p.values.clone();
            }
            if let Some(v) = self.rows.get(&key(&layer)) {
                macro_rules! field {
                    ($f:ident,$name:expr) => {
                        if let Some(x) = v.$f {
                            p.values.$f = x;
                            p.origins.insert($name.into(), origin.into());
                        }
                    };
                }
                field!(enabled, "enabled");
                field!(interval_seconds, "intervalSeconds");
                field!(diagnostic_enabled, "diagnosticEnabled");
                field!(expected_peers, "expectedPeers");
                field!(expect_replica, "expectReplica");
                for (rule, fields) in &v.thresholds {
                    p.values.thresholds.insert(rule.clone(), fields.clone());
                    p.threshold_origins.insert(rule.clone(), origin.into());
                }
            }
        }
        if matches!(
            d.runner,
            Runner::Metrics | Runner::Logs | Runner::Packages | Runner::Apt | Runner::Service
        ) {
            p.values.interval_seconds = self.poll_seconds();
            p.inherited.interval_seconds = self.poll_seconds();
            p.overrides.interval_seconds = None;
            p.origins.insert("intervalSeconds".into(), "global".into());
        }
        Ok(p)
    }
    pub fn enabled(&self, kind: &str, server: &str, instance: &str) -> bool {
        self.resolve(&scope(kind, Some(server), Some(instance)))
            .is_ok_and(|p| p.values.enabled)
    }
}
pub fn scope(kind: &str, server: Option<&str>, instance: Option<&str>) -> Scope {
    Scope {
        definition_id: kind.into(),
        server_id: server.map(str::to_owned),
        instance_id: instance.map(str::to_owned),
    }
}
pub fn effective(db: &Connection, kind: &str, server: &str, instance: &str) -> Result<Policy> {
    let s = scope(
        kind,
        (!server.is_empty()).then_some(server),
        (!instance.is_empty()).then_some(instance),
    );
    Book::selected(db, &s)?.resolve(&s)
}
fn validate_server(db: &Connection, server: Option<&str>) -> Result<()> {
    if let Some(id) = server {
        if !db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM servers WHERE id=?1)",
                [id],
                |r| r.get::<_, bool>(0),
            )
            .map_err(err)?
        {
            return Err("The server is remote".into());
        }
    }
    Ok(())
}
fn validate_scope(db: &Connection, s: &Scope) -> Result<&'static Definition> {
    let d = definition(&s.definition_id)?;
    validate_server(db, s.server_id.as_deref())?;
    if let Some(i) = &s.instance_id {
        let server = s.server_id.as_deref().ok_or("Select the server first")?;
        if !services::descriptor(&d.id).is_some_and(|spec| spec.scope_instances) {
            return Err("This check does not support separate instances".into());
        }
        instances::validate(i)?;
        if i != instances::DEFAULT {
            if !db.query_row("SELECT EXISTS(SELECT 1 FROM service_instances WHERE server_id=?1 AND kind=?2 AND id=?3)",params![server,d.id,i],|r|r.get::<_,bool>(0)).map_err(err)? {return Err("Service connection removed".into());}
        }
    }
    Ok(d)
}
pub(crate) fn effective_values(
    store: &Store,
    kind: &str,
    server: &str,
    instance: &str,
) -> Result<Values> {
    Ok(effective(&*store.0.lock().map_err(err)?, kind, server, instance)?.values)
}
pub fn enabled(store: &Store, kind: &str, server: &str, instance: &str) -> Result<bool> {
    Ok(
        effective(&*store.0.lock().map_err(err)?, kind, server, instance)?
            .values
            .enabled,
    )
}

pub fn migrate(db: &Connection) -> Result<()> {
    let old = Store::read_settings(db)?;
    let tx = db.unchecked_transaction().map_err(err)?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS monitoring_control(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL); INSERT OR IGNORE INTO monitoring_control VALUES(1,0); CREATE TABLE IF NOT EXISTS monitoring_overrides(id TEXT PRIMARY KEY,server_id TEXT REFERENCES servers(id) ON DELETE CASCADE,definition_id TEXT NOT NULL,instance_id TEXT,payload TEXT NOT NULL);").map_err(err)?;
    for (kind, n) in legacy_interval_values(&old) {
        let kind = kind.as_str();
        if n != definition(kind)?.factory_interval {
            put(
                &tx,
                &scope(kind, None, None),
                &Overrides {
                    interval_seconds: Some(n),
                    ..Default::default()
                },
            )?;
        }
    }
    for (server, kind, instance, config) in crate::service_migration::legacy_profiles(&tx)? {
        let o = Overrides {
            interval_seconds: config["intervalSeconds"].as_u64().filter(|x| *x != 180),
            diagnostic_enabled: config["enabled"].as_bool().filter(|x| *x),
            expected_peers: config["expectedPeers"]
                .as_u64()
                .filter(|x| *x > 0)
                .map(|x| x as u32),
            expect_replica: config["expectReplica"].as_bool().filter(|x| *x),
            ..Default::default()
        };
        if o != Overrides::default() {
            put(&tx, &scope(&kind, Some(&server), Some(&instance)), &o)?;
        }
    }
    tx.pragma_update(None, "user_version", 14).map_err(err)?;
    tx.commit().map_err(err)
}
fn put(db: &Connection, s: &Scope, o: &Overrides) -> Result<()> {
    if *o == Overrides::default() {
        db.execute("DELETE FROM monitoring_overrides WHERE id=?1", [key(s)])
            .map_err(err)?;
    } else {
        db.execute("INSERT INTO monitoring_overrides VALUES(?1,?2,?3,?4,?5) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",params![key(s),s.server_id,s.definition_id,s.instance_id,serde_json::to_string(o).map_err(err)?]).map_err(err)?;
    }
    Ok(())
}
impl Store {
    pub fn monitoring_library(
        &self,
        server: Option<&str>,
    ) -> Result<BTreeMap<String, LibraryEntry>> {
        let db = self.0.lock().map_err(err)?;
        validate_server(&db, server)?;
        let book = Book::read(
            &db,
            "SELECT id,payload FROM monitoring_overrides WHERE server_id IS NULL OR server_id=?1",
            [server],
        )?;
        REGISTRY
            .iter()
            .filter(|d| d.configurable)
            .map(|d| {
                let target = scope(&d.id, server, None);
                let policy = book.resolve(&target)?;
                let mut instance_overrides = BTreeMap::new();
                if server.is_some() {
                    let prefix = key(&target);
                    for id in book.rows.range(prefix.clone()..).map(|(id, _)| id) {
                        let Some(instance) = id.strip_prefix(&prefix) else {
                            break;
                        };
                        if !instance.is_empty() {
                            let target = scope(&d.id, server, Some(instance));
                            let policy = book.resolve(&target)?;
                            if policy.overrides != Overrides::default() {
                                instance_overrides.insert(instance.to_owned(), policy.values);
                            }
                        }
                    }
                }
                Ok((
                    d.id.clone(),
                    LibraryEntry {
                        values: policy.values,
                        server_override: server.is_some()
                            && policy.overrides != Overrides::default(),
                        instance_overrides,
                    },
                ))
            })
            .collect()
    }
    pub fn monitoring_policy(&self, s: &Scope) -> Result<Policy> {
        let db = self.0.lock().map_err(err)?;
        validate_scope(&db, s)?;
        Book::selected(&db, s)?.resolve(s)
    }
    pub fn monitoring_book(&self) -> Result<Book> {
        Book::load(&*self.0.lock().map_err(err)?)
    }
    pub fn set_monitoring(
        &self,
        s: &Scope,
        mut o: Overrides,
        expected_revision: i64,
    ) -> Result<Policy> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        crate::storage::admit(&tx)?;
        let d = validate_scope(&tx, s)?;
        if !d.configurable {
            return Err(
                "Edit custom checks in the version editor. Required app tasks cannot be disabled."
                    .into(),
            );
        }
        o.interval_seconds = None;
        if (!d.diagnostics && o.diagnostic_enabled.is_some())
            || (!d.replication && (o.expected_peers.is_some() || o.expect_replica.is_some()))
            || o.expected_peers.is_some_and(|n| n > 64)
        {
            return Err("Invalid check settings".into());
        }
        if !thresholds::validate(&d.thresholds, &o.thresholds) {
            return Err("Invalid alert thresholds for this check".into());
        }
        let book = Book::load(&tx)?;
        if book.revision != expected_revision {
            return Err("Settings changed in another window. Reload them and try again.".into());
        }
        let previous = book.resolve(s)?.overrides;
        if previous != o {
            if key(s) == "metrics::" {
                o.interval_seconds = book.rows.get("metrics::").and_then(|p| p.interval_seconds);
            }
            put(&tx, s, &o)?;
            let pattern_limit_changed = previous.thresholds.get("new_error_pattern")
                != o.thresholds.get("new_error_pattern");
            invalidate(&tx, s, pattern_limit_changed)?;
        }
        let policy = Book::load(&tx)?.resolve(s)?;
        tx.commit().map_err(err)?;
        Ok(policy)
    }
}
// Configuration changes invalidate proofs, never resolve incidents. All pending results carry a revision.
fn invalidate(db: &Connection, s: &Scope, pattern_limit_changed: bool) -> Result<()> {
    db.execute(
        "UPDATE monitoring_control SET revision=revision+1 WHERE id=1",
        [],
    )
    .map_err(err)?;
    let ids = if let Some(id) = &s.server_id {
        vec![id.clone()]
    } else {
        let mut q = db.prepare("SELECT id FROM servers").map_err(err)?;
        let rows = q
            .query_map([], |r| r.get(0))
            .map_err(err)?
            .collect::<std::result::Result<Vec<String>, _>>()
            .map_err(err)?;
        rows
    };
    for id in ids {
        let next = now() + 1 + (id.bytes().map(u64::from).sum::<u64>() % 60) as i64;
        let kind = s.definition_id.as_str();
        let table = match kind {
            "metrics" => "servers",
            "logs" => "log_state",
            "packages" => "package_state",
            "apt" => "",
            _ => "service_state",
        };
        if !table.is_empty() {
            let selector: String = if table == "servers" {
                "id=?1".into()
            } else if table == "service_state" {
                "server_id=?1 AND kind=?3 AND (?4 IS NULL OR instance_id=?4)".into()
            } else {
                "server_id=?1".into()
            };
            let sql = if table == "servers" {
                format!("UPDATE {table} SET payload=json_set(payload,'$.observation',NULL,'$.lastAttempt',NULL,'$.lastError',NULL,'$.nextCheck',?2) WHERE {selector} AND ?3 IS NOT NULL AND (?4 IS NULL OR ?4 IS NOT NULL)")
            } else {
                format!("UPDATE {table} SET payload=json_set(payload,'$.revision',coalesce(json_extract(payload,'$.revision'),0)+1,'$.lastSuccess',NULL,'$.lastSample',NULL,'$.error',NULL,'$.nextCheck',?2,'$.streaks',json('{{}}'),'$.previous',NULL,'$.status','unknown','$.coverageComplete',json('false')) WHERE {selector} AND ?3 IS NOT NULL AND (?4 IS NULL OR ?4 IS NOT NULL)")
            };
            db.execute(&sql, params![id, next, kind, s.instance_id])
                .map_err(err)?;
            if let Some(invalidate) = services::backend(kind).and_then(|adapter| adapter.invalidate)
            {
                invalidate(db, &id)?;
            }
            if kind == "logs" {
                let raw: Option<String> = db
                    .query_row(
                        "SELECT payload FROM log_state WHERE server_id=?1",
                        [&id],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(err)?;
                if let Some(raw) = raw {
                    let mut v: serde_json::Value = serde_json::from_str(&raw).map_err(err)?;
                    v["baseline"]["spike"] = 0.into();
                    if let Some(patterns) = v["baseline"]["patterns"].as_object_mut() {
                        for p in patterns.values_mut() {
                            p["streak"] = 0.into();
                            if pattern_limit_changed && p["alerted"] == true {
                                p["alerted"] = false.into();
                                p["candidate"] = true.into();
                            }
                        }
                    }
                    db.execute(
                        "UPDATE log_state SET payload=?2 WHERE server_id=?1",
                        params![id, v.to_string()],
                    )
                    .map_err(err)?;
                }
            }
        }
        let instance_pattern = match kind {
            "metrics" => None,
            "logs" => Some("logs:%".into()),
            "packages" | "apt" => Some("vuln:%".into()),
            _ => Some(instances::prefix(
                kind,
                s.instance_id.as_deref().unwrap_or(instances::DEFAULT),
            )),
        };
        if let Some(pattern) = instance_pattern {
            let other_instances = services::descriptor(kind)
                .filter(|spec| spec.scope_instances && s.instance_id.is_none())
                .map(|spec| format!("{}{kind}@%:%", spec.incident_namespace));
            db.execute("UPDATE incidents SET payload=json_set(payload,'$.autoEligible',json('false'),'$.freshUntil',?2,'$.healthyStreak',0) WHERE server_id=?1 AND (json_extract(payload,'$.check') LIKE ?3 OR json_extract(payload,'$.check') LIKE ?4)",params![id,now()-1,pattern,other_instances]).map_err(err)?;
        } else {
            db.execute("UPDATE incidents SET payload=json_set(payload,'$.autoEligible',json('false'),'$.freshUntil',?2,'$.healthyStreak',0) WHERE server_id=?1 AND (json_extract(payload,'$.check') IN ('connection','cpu','memory') OR json_extract(payload,'$.check') LIKE 'disk:%')",params![id,now()-1]).map_err(err)?;
        }
    }
    Ok(())
}
fn legacy_interval_values(settings: &crate::model::Settings) -> Vec<(String, u64)> {
    let mut values = vec![
        ("metrics".into(), settings.poll_seconds),
        ("logs".into(), settings.log_poll_seconds),
    ];
    values.extend(
        services::catalog()
            .into_iter()
            .filter(|(_, spec)| spec.legacy_log_interval)
            .map(|(id, _)| (id, settings.log_poll_seconds)),
    );
    values
}

// Legacy settings/forms write the same profiles; unchanged fields keep their inheritance.
pub fn legacy_intervals(
    db: &Connection,
    old: &crate::model::Settings,
    new: &crate::model::Settings,
) -> Result<()> {
    if old.poll_seconds != new.poll_seconds {
        let s = scope("metrics", None, None);
        let mut o = Book::load(db)?.resolve(&s)?.overrides;
        o.interval_seconds = Some(new.poll_seconds);
        put(db, &s, &o)?;
        db.execute(
            "UPDATE monitoring_control SET revision=revision+1 WHERE id=1",
            [],
        )
        .map_err(err)?;
    }
    Ok(())
}
pub fn legacy_service(
    db: &Connection,
    kind: &str,
    id: &str,
    instance: &str,
    old: &Values,
    new: &Values,
) -> Result<()> {
    let s = scope(kind, Some(id), Some(instance));
    let mut o = Book::load(db)?.resolve(&s)?.overrides;
    if old.diagnostic_enabled != new.diagnostic_enabled {
        o.diagnostic_enabled = Some(new.diagnostic_enabled);
    }
    if old.expected_peers != new.expected_peers {
        o.expected_peers = Some(new.expected_peers);
    }
    if old.expect_replica != new.expect_replica {
        o.expect_replica = Some(new.expect_replica);
    }
    put(db, &s, &o)?;
    invalidate(db, &s, false)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Execution {
    pub definition_id: String,
    pub version: String,
    pub trigger: String,
    pub instance_id: Option<String>,
    #[serde(default)]
    pub server_id: Option<String>,
    pub revision: i64,
}
tokio::task_local! {static EXECUTION: Execution; static TRIGGER: String;}
pub fn context() -> Option<Execution> {
    EXECUTION.try_with(Clone::clone).ok()
}
pub(crate) fn with_execution<T>(execution: Execution, run: impl FnOnce() -> T) -> T {
    EXECUTION.sync_scope(execution, run)
}
pub fn sync<T>(
    store: &Store,
    kind: &str,
    trigger: &str,
    f: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let revision = effective(&*store.0.lock().map_err(err)?, kind, "", "")?.revision;
    let e = Execution {
        definition_id: kind.into(),
        version: definition(kind)?.version.clone(),
        trigger: trigger.into(),
        instance_id: None,
        server_id: None,
        revision,
    };
    EXECUTION.sync_scope(e, f)
}
#[cfg(test)]
pub fn next_candidate(
    book: &Book,
    server: &str,
    candidates: impl IntoIterator<Item = (i64, String, String)>,
) -> Option<(i64, String, String)> {
    candidates
        .into_iter()
        .filter(|(_, kind, instance)| book.enabled(kind, server, instance))
        .min_by_key(|(at, _, _)| *at)
}
pub async fn trigger<T>(name: &str, f: impl Future<Output = T>) -> T {
    TRIGGER.scope(name.into(), f).await
}
pub async fn run<T>(
    store: &Store,
    kind: &str,
    id: &str,
    instance: &str,
    f: impl Future<Output = Result<T>>,
) -> Result<T> {
    let p = effective(&*store.0.lock().map_err(err)?, kind, id, instance)?;
    if !p.values.enabled {
        return Err("Check is disabled in the monitoring library".into());
    }
    let e = Execution {
        definition_id: kind.into(),
        version: definition(kind)?.version.clone(),
        trigger: TRIGGER.try_with(Clone::clone).unwrap_or("manual".into()),
        instance_id: (!instance.is_empty()).then(|| instance.into()),
        server_id: (!id.is_empty()).then(|| id.into()),
        revision: p.revision,
    };
    let network = store.connectivity();
    EXECUTION
        .scope(
            e,
            crate::connectivity::observe_ssh(network.clone(), network.ticket(), f),
        )
        .await
}
pub(crate) const POLICY_CHANGED: &str = "Monitoring settings have changed; result not applied";

pub fn check_commit(db: &Connection) -> Result<()> {
    if let Some(e) = context() {
        let revision: i64 = db
            .query_row(
                "SELECT revision FROM monitoring_control WHERE id=1",
                [],
                |r| r.get(0),
            )
            .map_err(err)?;
        if revision != e.revision {
            return Err(POLICY_CHANGED.into());
        }
    }
    Ok(())
}
#[derive(Serialize)]
pub struct Source {
    pub name: String,
    pub text: String,
}
pub fn sources(id: &str) -> Result<Vec<Source>> {
    let d = definition(id)?;
    let mut out = vec![];
    if !matches!(d.runner, Runner::Custom | Runner::Local) {
        out.push(Source {
            name: "Python collector bundle (including SQL and modules)".into(),
            text: ssh::COLLECTOR.into(),
        });
    }
    let (name, text) = match d.runner {
        Runner::Metrics => ("server_poll.rs", include_str!("server_poll.rs")),
        Runner::Logs => ("logs.rs", include_str!("logs.rs")),
        Runner::Packages | Runner::Apt => ("packages.rs", include_str!("packages.rs")),
        Runner::Service => ("services.rs and catalog.json", include_str!("services.rs")),
        Runner::Custom => ("checks.rs", include_str!("checks.rs")),
        Runner::Local => match id {
            "advisories" => ("advisories.rs", include_str!("advisories.rs")),
            "inventory" => ("inventory.rs", include_str!("inventory.rs")),
            "storage" => ("storage.rs", include_str!("storage.rs")),
            _ => ("ssh.rs", include_str!("ssh.rs")),
        },
    };
    if d.runner == Runner::Metrics {
        out.push(Source {
            name: "store.rs - rules for metrics and incidents".into(),
            text: include_str!("store.rs").into(),
        });
    }
    out.push(Source {
        name: name.into(),
        text: text.into(),
    });
    if d.runner == Runner::Service {
        if let Some(adapter) = services::backend(id) {
            out.push(Source {
                name: "Diagnostics implementation".into(),
                text: adapter.source.into(),
            });
        }
        out.push(Source {
            name: "Metrics and thresholds".into(),
            text: serde_json::to_string_pretty(&services::catalog().get(id)).map_err(err)?,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{inventory, model::Source as InventorySource};
    fn fixture() -> (Store, String) {
        let db = fixture_with_hosts("root@fixture.invalid");
        let id = db.snapshot().unwrap().servers[0].id.clone();
        (db, id)
    }
    fn fixture_with_hosts(hosts: &str) -> Store {
        let db = Store::open(std::path::Path::new(":memory:")).unwrap();
        let src = InventorySource {
            id: "monitoring".into(),
            name: "Fixture".into(),
            kind: "manual".into(),
            location: hosts.into(),
            last_sync: None,
            error: None,
        };
        db.import(&src, inventory::parse_manual(&src.location).unwrap())
            .unwrap();
        db
    }
    fn change(db: &Store, s: &Scope, o: Overrides) -> Policy {
        let revision = db.monitoring_policy(s).unwrap().revision;
        db.set_monitoring(s, o, revision).unwrap()
    }
    #[test]
    fn thresholds_inherit_and_reset_as_independent_rules() {
        let (db, id) = fixture();
        let fleet = scope("redis", None, None);
        let server = scope("redis", Some(&id), None);
        let connection = scope("redis", Some(&id), Some("default"));
        let other = db.add_service_instance(&id, "redis", None).unwrap();
        let other = scope("redis", Some(&id), Some(&other.id));
        let pair =
            |warning, critical| [("warning".into(), warning), ("critical".into(), critical)].into();
        let defaults = db.monitoring_policy(&connection).unwrap();
        assert_eq!(defaults.values.thresholds["memoryUsage"], pair(90., 98.));
        assert_eq!(defaults.threshold_origins["memoryUsage"], "factory");
        let legacy: Overrides = serde_json::from_str(r#"{"intervalSeconds":300}"#).unwrap();
        change(
            &db,
            &fleet,
            Overrides {
                thresholds: [("memoryUsage".into(), pair(95., 99.))].into(),
                ..legacy
            },
        );
        change(
            &db,
            &server,
            Overrides {
                thresholds: [("blocked".into(), [("warning".into(), 3.)].into())].into(),
                ..Default::default()
            },
        );
        let changed = change(
            &db,
            &connection,
            Overrides {
                thresholds: [("memoryUsage".into(), pair(101., 102.))].into(),
                ..Default::default()
            },
        );
        assert_eq!(changed.values.interval_seconds, 180);
        assert_eq!(changed.values.thresholds["blocked"]["warning"], 3.);
        assert_eq!(changed.values.thresholds["memoryUsage"], pair(101., 102.));
        assert_eq!(changed.inherited.thresholds["memoryUsage"], pair(95., 99.));
        assert_eq!(changed.threshold_origins["blocked"], "server");
        assert_eq!(changed.threshold_origins["memoryUsage"], "instance");
        assert_eq!(
            db.monitoring_policy(&other).unwrap().values.thresholds["memoryUsage"],
            pair(95., 99.)
        );
        for invalid in [
            pair(99., 98.),
            pair(99., 99.),
            pair(-1., 101.),
            [("warning".into(), 99.)].into(),
        ] {
            let result = db.set_monitoring(
                &connection,
                Overrides {
                    thresholds: [("memoryUsage".into(), invalid)].into(),
                    ..Default::default()
                },
                changed.revision,
            );
            assert!(result.unwrap_err().contains("thresholds"));
        }
        let invalid = Overrides {
            thresholds: [("memory".into(), pair(90., 98.))].into(),
            ..Default::default()
        };
        assert!(db
            .set_monitoring(&connection, invalid, changed.revision)
            .is_err());
        let reset = change(&db, &connection, Overrides::default());
        assert_eq!(reset.values.thresholds["memoryUsage"], pair(95., 99.));
        assert_eq!(reset.threshold_origins["memoryUsage"], "global");
    }
    #[test]
    fn nginx_minimum_shares_cannot_exceed_100_percent() {
        let (db, id) = fixture();
        let nginx = scope("nginx", Some(&id), None);
        let policy = db.monitoring_policy(&nginx).unwrap();
        for key in ["http_5xx", "latency"] {
            let mut fields = policy.values.thresholds[key].clone();
            fields.insert("share".into(), 101.);
            let result = db.set_monitoring(
                &nginx,
                Overrides {
                    thresholds: [(key.into(), fields)].into(),
                    ..Default::default()
                },
                policy.revision,
            );
            assert!(result.unwrap_err().contains("Invalid alert thresholds"));
        }
    }
    #[test]
    fn cpu_threshold_above_100_suppresses_only_the_configured_server() {
        let db = fixture_with_hosts("root@one.invalid\nroot@two.invalid");
        let servers = db.snapshot().unwrap().servers;
        let configured_server = &servers[0].id;
        let default_server = &servers[1].id;
        let limits = [("warning".into(), 101.), ("critical".into(), 102.)].into();
        change(
            &db,
            &scope("metrics", Some(configured_server), None),
            Overrides {
                thresholds: [("cpu".into(), limits)].into(),
                ..Default::default()
            },
        );
        for server in &servers {
            let observation = serde_json::from_value(serde_json::json!({
                "at": now(), "cpuPercent": 100, "memoryPercent": 20,
                "disks": [], "services": [], "missing": [], "bytesReceived": 100, "durationMs": 1,
            }))
            .unwrap();
            db.record(server, Ok(observation), 180).unwrap();
        }
        let snapshot = db.snapshot().unwrap();
        assert_eq!(snapshot.servers.len(), 2);
        for server in &snapshot.servers {
            assert_eq!(server.observation.as_ref().unwrap().cpu_percent, Some(100.));
        }
        assert_eq!(snapshot.incidents.len(), 1);
        assert_eq!(snapshot.incidents[0].check, "cpu");
        assert_eq!(&snapshot.incidents[0].server_id, default_server);
    }
    #[test]
    fn resource_incidents_keep_their_severity_rules_with_custom_thresholds() {
        let (db, id) = fixture();
        let metrics = scope("metrics", Some(&id), None);
        change(
            &db,
            &metrics,
            Overrides {
                thresholds: [
                    (
                        "cpu".into(),
                        [("warning".into(), 97.), ("critical".into(), 98.)].into(),
                    ),
                    (
                        "memory".into(),
                        [("warning".into(), 99.), ("critical".into(), 100.)].into(),
                    ),
                    (
                        "disk".into(),
                        [("warning".into(), 96.), ("critical".into(), 98.)].into(),
                    ),
                ]
                .into(),
                ..Default::default()
            },
        );
        let server = db.snapshot().unwrap().servers.remove(0);
        let observation = serde_json::from_value(serde_json::json!({
            "at": now(), "cpuPercent": 98, "memoryPercent": 98.9,
            "disks": [{"mount": "/", "usedPercent": 98, "inodePercent": null}],
            "services": [], "missing": [], "bytesReceived": 100, "durationMs": 1,
        }))
        .unwrap();
        db.record(&server, Ok(observation), 180).unwrap();
        let snapshot = db.snapshot().unwrap();
        let incidents: BTreeMap<_, _> = snapshot
            .incidents
            .into_iter()
            .map(|i| (i.check, i.severity))
            .collect();
        assert_eq!(
            incidents,
            [
                ("cpu".into(), "warning".into()),
                ("disk:/".into(), "critical".into())
            ]
            .into()
        );
        assert_eq!(
            snapshot.monitoring[&id].thresholds["memory"]["warning"],
            99.
        );
    }
    #[test]
    fn library_lists_only_exceptions_at_the_selected_server_and_its_connections() {
        let (db, id) = fixture();
        change(
            &db,
            &scope("redis", None, None),
            Overrides {
                interval_seconds: Some(300),
                ..Default::default()
            },
        );
        let instance = scope("redis", Some(&id), Some("default"));
        change(
            &db,
            &instance,
            Overrides {
                diagnostic_enabled: Some(false),
                ..Default::default()
            },
        );
        let server = scope("metrics", Some(&id), None);
        change(
            &db,
            &server,
            Overrides {
                interval_seconds: Some(90),
                ..Default::default()
            },
        );
        let global = db.monitoring_library(None).unwrap();
        assert!(!global.contains_key("transport"));
        assert_eq!(global["redis"].values.interval_seconds, 180);
        assert!(global["redis"].instance_overrides.is_empty());
        assert!(!global["metrics"].server_override);

        let scoped = db.monitoring_library(Some(&id)).unwrap();
        assert!(!scoped["redis"].instance_overrides["default"].diagnostic_enabled);
        assert_eq!(scoped["redis"].values.interval_seconds, 180);
        assert!(!scoped["redis"].server_override);
        assert!(!scoped["metrics"].server_override);
        assert_eq!(scoped["metrics"].values.interval_seconds, 180);
        assert!(!scoped["logs"].server_override);
        assert!(scoped["logs"].instance_overrides.is_empty());

        change(&db, &instance, Overrides::default());
        assert!(db.monitoring_library(Some(&id)).unwrap()["redis"]
            .instance_overrides
            .is_empty());
        assert!(db.monitoring_library(Some("missing")).is_err());
    }
    #[test]
    fn inheritance_reset_validation_and_instance_independence() {
        let (db, id) = fixture();
        let global = scope("redis", None, None);
        let server = scope("redis", Some(&id), None);
        let extra = db.add_service_instance(&id, "redis", None).unwrap();
        let instance = scope("redis", Some(&id), Some(&extra.id));
        assert_eq!(
            db.monitoring_policy(&instance).unwrap().origins["intervalSeconds"],
            "global"
        );
        change(
            &db,
            &global,
            Overrides {
                interval_seconds: Some(300),
                diagnostic_enabled: Some(true),
                ..Default::default()
            },
        );
        change(
            &db,
            &server,
            Overrides {
                enabled: Some(false),
                ..Default::default()
            },
        );
        let p = change(
            &db,
            &instance,
            Overrides {
                enabled: Some(true),
                expected_peers: Some(2),
                ..Default::default()
            },
        );
        assert!(p.values.enabled && p.values.diagnostic_enabled);
        assert!(!p.inherited.enabled);
        assert_eq!(p.values.interval_seconds, 180);
        assert_eq!(p.origins["enabled"], "instance");
        assert_eq!(p.origins["intervalSeconds"], "global");
        assert!(
            !db.monitoring_policy(&scope("redis", Some(&id), Some("default")))
                .unwrap()
                .values
                .enabled
        );
        assert!(db
            .set_monitoring(&instance, Overrides::default(), p.revision - 1)
            .is_err());
        let inherited = change(&db, &instance, Overrides::default());
        assert!(!inherited.values.enabled);
        assert_eq!(inherited.values.expected_peers, 0);
        change(&db, &server, Overrides::default());
        change(&db, &global, Overrides::default());
        let factory = db.monitoring_policy(&instance).unwrap();
        assert!(factory.values.enabled);
        assert!(factory.values.diagnostic_enabled);
        assert_eq!(factory.values.interval_seconds, 180);
        assert!(db
            .set_monitoring(
                &scope("transport", None, None),
                Overrides {
                    enabled: Some(false),
                    ..Default::default()
                },
                factory.revision
            )
            .is_err());
        assert!(db
            .monitoring_policy(&scope("redis", Some(&id), Some("missing")))
            .is_err());
        assert!(db
            .monitoring_policy(&scope("logs", Some(&id), Some("default")))
            .is_err());
        assert!(serde_json::from_str::<Overrides>(r#"{"command":"id"}"#).is_err());
        db.remove_service_instance(&id, "redis", &extra.id).unwrap();
        assert!(db.monitoring_policy(&instance).is_err());
    }
    #[test]
    fn legacy_forms_use_profiles_and_reset_keeps_connection_details() {
        let (db, id) = fixture();
        db.update_settings(
            serde_json::from_str(r#"{"pollSeconds":480,"logPollSeconds":900}"#).unwrap(),
        )
        .unwrap();
        assert_eq!(
            effective_values(&db, "metrics", &id, "")
                .unwrap()
                .interval_seconds,
            480
        );
        assert_eq!(
            effective_values(&db, "nginx", &id, "")
                .unwrap()
                .interval_seconds,
            480
        );
        let mut c = db
            .service_state_for(&id, "redis", "default")
            .unwrap()
            .config;
        c.port = 6381;
        c.auto_endpoint = Some(false);
        c.enabled = false;
        c.interval_seconds = 240;
        c.user = "diagnostic".into();
        db.configure_service_for(&id, "redis", "default", c)
            .unwrap();
        let s = scope("redis", Some(&id), Some("default"));
        let p = db.monitoring_policy(&s).unwrap();
        assert!(!p.values.diagnostic_enabled);
        assert_eq!(p.values.interval_seconds, 480);
        change(&db, &s, Overrides::default());
        let c = db
            .service_state_for(&id, "redis", "default")
            .unwrap()
            .config;
        assert_eq!(c.port, 6381);
        assert_eq!(c.auto_endpoint, Some(false));
        assert_eq!(c.user, "diagnostic");
        assert!(c.enabled);
        assert_eq!(c.interval_seconds, 480);
        change(&db, &scope("metrics", None, None), Overrides::default());
        assert_eq!(db.settings().unwrap().poll_seconds, 480);
    }
    #[tokio::test]
    async fn disabled_collectors_and_mcp_never_reach_ssh() {
        let tmp = tempfile::tempdir().unwrap();
        let app = crate::create_state(tmp.path().to_owned()).unwrap();
        let src = InventorySource {
            id: "monitoring".into(),
            name: "Fixture".into(),
            kind: "manual".into(),
            location: "root@fixture.invalid".into(),
            last_sync: None,
            error: None,
        };
        app.store
            .import(&src, inventory::parse_manual(&src.location).unwrap())
            .unwrap();
        let id = app.store.snapshot().unwrap().servers[0].id.clone();
        for d in catalog().into_iter().filter(|d| d.configurable) {
            change(
                &app.store,
                &scope(&d.id, Some(&id), None),
                Overrides {
                    enabled: Some(false),
                    ..Default::default()
                },
            );
        }
        assert!(crate::logs::collect(app.clone(), id.clone())
            .await
            .err()
            .unwrap()
            .contains("disabled"));
        assert!(crate::nginx::collect(app.clone(), id.clone())
            .await
            .err()
            .unwrap()
            .contains("disabled"));
        assert!(crate::packages::rescan(app.clone(), id.clone())
            .await
            .err()
            .unwrap()
            .contains("disabled"));
        assert!(
            crate::postgresql::collect_for(app.clone(), id.clone(), "default".into())
                .await
                .err()
                .unwrap()
                .contains("disabled")
        );
        for (kind, s) in services::catalog()
            .into_iter()
            .filter(|(id, _)| services::backend(id).is_none())
        {
            let _ = s;
            assert!(
                crate::services::collect_for(app.clone(), id.clone(), kind, "default".into())
                    .await
                    .err()
                    .unwrap()
                    .contains("disabled")
            );
        }
        let mcp = crate::mcp::McpServer::start(app.clone(), &[id.clone()])
            .await
            .unwrap();
        assert!(crate::mcp::call(
            &mcp.scope,
            "refresh_metrics",
            serde_json::json!({"serverId":id})
        )
        .await
        .err()
        .unwrap()
        .contains("disabled"));
        let cached = crate::mcp::call(
            &mcp.scope,
            "get_log_summary",
            serde_json::json!({"serverId":id,"kind":"logs"}),
        )
        .await
        .unwrap();
        assert_eq!(cached["monitoring"]["enabled"], false);
        assert_eq!(app.collectors.snapshot().unwrap().running_count(), 0);
        assert!(app.store.history(&id).unwrap().is_empty());
    }
    #[tokio::test]
    async fn late_results_are_dropped_and_incidents_stay_open_with_stale_proofs() {
        let (db, id) = fixture();
        let server = db.snapshot().unwrap().servers[0].clone();
        {
            let sql = db.0.lock().unwrap();
            Store::incident(
                &sql,
                &id,
                "logs:oom",
                Some("Synthetic".into()),
                "OOM",
                "critical",
                now(),
            )
            .unwrap();
        }
        let cp = db.log_state(&id).unwrap();
        let cursor = serde_json::to_value(&cp).unwrap()["cursor"].clone();
        let result = trigger(
            "schedule",
            run(&db, "metrics", &id, "", async {
                assert_eq!(context().unwrap().trigger, "schedule");
                change(
                    &db,
                    &scope("logs", Some(&id), None),
                    Overrides {
                        thresholds: [("oom".into(), [("critical".into(), 2.)].into())].into(),
                        ..Default::default()
                    },
                );
                db.record(&server, Err("Late reply".into()), 180)
            }),
        )
        .await;
        assert!(result.unwrap_err().contains("not applied"));
        let incident = db.snapshot().unwrap().incidents.remove(0);
        assert_eq!(incident.status, "open");
        assert!(!incident.auto_eligible);
        assert!(incident.fresh_until.unwrap() < now());
        assert_eq!(
            serde_json::to_value(db.log_state(&id).unwrap()).unwrap()["cursor"],
            cursor
        );
        assert!(!db.log_view(&id).unwrap().fresh);
        change(&db, &scope("logs", Some(&id), None), Overrides::default());
        assert!(!db.log_view(&id).unwrap().fresh);
        assert!(db.snapshot().unwrap().servers[0].last_attempt.is_none());
    }
    #[test]
    fn v13_migration_preserves_global_interval_profiles_and_history() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("db.sqlite");
        let db = Store::open(&file).unwrap();
        let src = InventorySource {
            id: "old".into(),
            name: "Old".into(),
            kind: "manual".into(),
            location: "root@old.invalid".into(),
            last_sync: None,
            error: None,
        };
        db.import(&src, inventory::parse_manual(&src.location).unwrap())
            .unwrap();
        let id = db.snapshot().unwrap().servers[0].id.clone();
        db.service_state_for(&id, "redis", "default").unwrap();
        {
            let sql = db.0.lock().unwrap();
            sql.execute(
                "INSERT OR REPLACE INTO settings VALUES(1,?1)",
                [serde_json::to_string(&crate::model::Settings {
                    poll_seconds: 450,
                    log_poll_seconds: 1200,
                    ..Default::default()
                })
                .unwrap()],
            )
            .unwrap();
            sql.execute("UPDATE service_state SET payload=json_set(payload,'$.config.enabled',json('true'),'$.config.port',6382,'$.config.intervalSeconds',360) WHERE server_id=?1",[&id]).unwrap();
            sql.execute_batch("DROP TABLE monitoring_overrides; DROP TABLE monitoring_control; PRAGMA user_version=13;").unwrap();
        }
        drop(db);
        let db = Store::open(&file).unwrap();
        assert_eq!(db.settings().unwrap().poll_seconds, 450);
        assert_eq!(
            effective_values(&db, "nginx", &id, "")
                .unwrap()
                .interval_seconds,
            450
        );
        let cp = db.service_state_for(&id, "redis", "default").unwrap();
        assert!(cp.config.enabled);
        assert_eq!(cp.config.interval_seconds, 450);
        assert_eq!(cp.config.port, 6382);
        assert!(db.snapshot().unwrap().incidents.is_empty());
    }
    #[test]
    fn catalog_covers_all_connectors_and_source_selection_is_closed() {
        for (id, s) in services::catalog() {
            let d = definition(&id).unwrap();
            assert_eq!(d.name, s.name);
            assert!(!sources(&id).unwrap().is_empty());
        }
        for id in [
            "metrics",
            "logs",
            "packages",
            "apt",
            "custom",
            "advisories",
            "inventory",
            "storage",
            "transport",
        ] {
            assert!(!sources(id).unwrap().is_empty());
        }
        assert!(sources("../../etc/shadow").is_err());
    }
    #[test]
    fn disabled_oldest_work_does_not_starve_other_jobs_in_a_large_fleet() {
        let (db, _) = fixture();
        change(
            &db,
            &scope("metrics", None, None),
            Overrides {
                enabled: Some(false),
                ..Default::default()
            },
        );
        let book = db.monitoring_book().unwrap();
        for n in 0..500 {
            let id = format!("server-{n}");
            let selected = next_candidate(
                &book,
                &id,
                [
                    (1, "metrics".into(), "default".into()),
                    (100 + n, "logs".into(), "default".into()),
                    (200 + n, "redis".into(), "default".into()),
                ],
            )
            .unwrap();
            assert_eq!(selected.1, "logs");
        }
        assert!(
            next_candidate(&book, "server", [(1, "metrics".into(), "default".into())]).is_none()
        );
    }
}
