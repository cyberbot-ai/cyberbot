//! PostgreSQL catalog diagnostics. No SQL or credentials enter the agent interface.
use crate::instances::{self, DEFAULT};
use crate::monitoring::thresholds::{self, Thresholds};
use crate::{inventory::stable_id, model::*, ssh, store::Store, AppState};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc};
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_endpoint: Option<bool>,
    #[serde(rename = "endpoint", alias = "host")]
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    pub interval_seconds: u64,
    #[serde(rename = "expectedPeers", alias = "expectedStreaming")]
    pub expected_streaming: u32,
    #[serde(rename = "expectReplica", alias = "expectReceiver")]
    pub expect_receiver: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_endpoint: None,
            host: "/var/run/postgresql".into(),
            port: 5432,
            database: "postgres".into(),
            user: String::new(),
            interval_seconds: 180,
            expected_streaming: 0,
            expect_receiver: false,
        }
    }
}
impl Config {
    pub(crate) fn automatic(&self, instance: &str) -> bool {
        self.auto_endpoint.unwrap_or(
            instance == DEFAULT && self.host == "/var/run/postgresql" && self.port == 5432,
        )
    }
    fn validate(&self) -> Result<()> {
        let name = |v: &str| {
            !v.is_empty()
                && v.len() <= 63
                && v.bytes().enumerate().all(|(i, b)| {
                    b.is_ascii_alphabetic()
                        || b == b'_'
                        || i > 0 && (b.is_ascii_digit() || b == b'.' || b == b'-')
                })
        };
        if !(["/var/run/postgresql", "/tmp", "127.0.0.1", "::1"].contains(&self.host.as_str())
            || crate::services::literal_address(&self.host))
            || self.port == 0
            || !name(&self.database)
            || (!self.user.is_empty() && !name(&self.user))
            || !(60..=86400).contains(&self.interval_seconds)
            || self.expected_streaming > 64
        {
            return Err("Unacceptable PostgreSQL profile: local endpoint and no connection string names".into());
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Meta {
    pub version: u32,
    pub generation: i64,
    pub full_stats: bool,
    pub superuser: bool,
    pub track_activities: bool,
    pub track_counts: bool,
    pub recovery: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Blocker {
    pub pid: u32,
    pub blockers: Vec<u32>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Metrics {
    pub version: u32,
    pub generation: i64,
    pub recovery: bool,
    pub full_stats: bool,
    pub track_activities: bool,
    pub track_counts: bool,
    pub connections: u64,
    pub max_connections: u64,
    pub reserved_connections: u64,
    pub active: u64,
    pub disabled_activities: u64,
    pub long_queries: u64,
    pub longest_query_seconds: f64,
    pub idle_transactions: u64,
    pub blocked: u64,
    pub unknown_waits: u64,
    pub max_wait_seconds: f64,
    pub blockers: Vec<Blocker>,
    pub streaming: u64,
    pub replication_unknown: u64,
    pub replica_backlog_bytes: Option<f64>,
    pub receiver: u64,
    pub replay_backlog_bytes: Option<f64>,
    pub replay_paused: bool,
    pub slot_retained_bytes: Option<f64>,
    pub inactive_slots: u64,
    pub autovacuum_workers: u64,
    pub xid_age: u64,
    pub deadlocks: u64,
    pub rollbacks: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Wire {
    pub version: u32,
    pub detected: bool,
    pub connected: bool,
    pub coverage: bool,
    pub issues: Vec<String>,
    pub meta: Option<Meta>,
    pub metrics: Option<Metrics>,
    pub duration_ms: u64,
}
const ISSUES: &[&str] = &[
    "endpoint_ambiguous",
    "endpoint_not_local",
    "profile_disabled",
    "psql_missing",
    "unsupported_version",
    "read_all_stats_required",
    "activity_incomplete",
    "counters_disabled",
    "lock_wait_age_unknown",
    "replication_position_unknown",
    "query_timeout",
    "query_output_limit",
    "connection_or_query_denied",
    "instance_changed",
    "collection_failed",
];
fn validate(w: &Wire) -> Result<()> {
    if w.version != 1
        || w.duration_ms > 15000
        || w.issues.len() > 16
        || w.issues.iter().any(|s| !ISSUES.contains(&s.as_str()))
        || w.connected && !w.detected
        || w.coverage && (!w.connected || !w.issues.is_empty() || w.metrics.is_none())
    {
        return Err("Incorrect summary of PostgreSQL".into());
    }
    if w.connected && w.meta.is_none() {
        return Err("No connection metadata".into());
    }
    if let Some(m) = &w.metrics {
        let meta = w.meta.as_ref().ok_or("No metadata")?;
        if !w.connected
            || !meta.full_stats
            || !m.full_stats
            || !(140000..190000).contains(&m.version)
            || m.version != meta.version
            || m.generation != meta.generation
            || m.recovery != meta.recovery
            || m.track_activities != meta.track_activities
            || m.track_counts != meta.track_counts
            || m.max_connections == 0
            || m.max_connections > 1_000_000
            || m.reserved_connections >= m.max_connections
            || m.connections > m.max_connections
            || m.active > m.connections
            || m.long_queries > m.active
            || m.unknown_waits > m.blocked
            || m.blockers.len() > 5
            || m.blockers.iter().any(|b| {
                b.pid == 0
                    || b.pid > i32::MAX as u32
                    || b.blockers.len() > 8
                    || b.blockers.iter().any(|p| *p > i32::MAX as u32)
            })
        {
            return Err("Incorrect PostgreSQL metrics".into());
        }
        if [
            m.longest_query_seconds,
            m.max_wait_seconds,
            m.replica_backlog_bytes.unwrap_or(0.),
            m.replay_backlog_bytes.unwrap_or(0.),
            m.slot_retained_bytes.unwrap_or(0.),
        ]
        .iter()
        .any(|v| !v.is_finite() || *v < 0. || *v > 1e18)
        {
            return Err("Limit of numerical metrics".into());
        }
        if w.coverage
            && (!m.track_activities
                || !m.track_counts
                || m.disabled_activities > 0
                || m.unknown_waits > 0
                || m.replication_unknown > 0
                || m.recovery && m.replay_backlog_bytes.is_none())
        {
            return Err("Inconsistent statistics coverage".into());
        }
    }
    Ok(())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub key: String,
    pub title: String,
    pub severity: String,
    pub value: f64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub id: String,
    pub at: i64,
    pub data: Wire,
    pub findings: Vec<Finding>,
    pub bytes_received: usize,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Checkpoint {
    #[serde(default = "instances::default_id")]
    pub(crate) instance_id: String,
    pub revision: u64,
    pub epoch: String,
    pub config: Config,
    pub next_check: i64,
    pub last_success: Option<i64>,
    pub last_sample: Option<i64>,
    pub error: Option<String>,
    pub failures: u32,
    pub generation: Option<i64>,
    pub streaks: BTreeMap<String, u32>,
}
impl Checkpoint {
    pub(crate) fn new(id: &str) -> Self {
        Self {
            instance_id: DEFAULT.into(),
            revision: 0,
            epoch: uuid::Uuid::new_v4().to_string(),
            config: Config::default(),
            next_check: now() + id.bytes().map(i64::from).sum::<i64>() % 600,
            last_success: None,
            last_sample: None,
            error: None,
            failures: 0,
            generation: None,
            streaks: BTreeMap::new(),
        }
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub monitoring: crate::monitoring::Values,
    pub config: Config,
    pub summary: Option<Summary>,
    pub evidence: Vec<Summary>,
    pub error: Option<String>,
    pub fresh: bool,
    pub next_check: i64,
    pub status: String,
}
pub(crate) const RULES: &[(&str, &str, &str)] = &[
    (
        "freeze_age",
        "PostgreSQL: high frozen transaction ID age",
        "warning",
    ),
    (
        "connections",
        "PostgreSQL: high connection usage",
        "warning",
    ),
    ("locks", "PostgreSQL: sustained lock waits", "warning"),
    ("long_queries", "PostgreSQL: long-running queries", "warning"),
    (
        "idle_transactions",
        "PostgreSQL: idle transactions",
        "warning",
    ),
    (
        "replication",
        "PostgreSQL: replication lag",
        "warning",
    ),
    (
        "streaming",
        "PostgreSQL: fewer streaming connections than expected",
        "critical",
    ),
    (
        "receiver",
        "PostgreSQL: expected WAL receiver not available",
        "critical",
    ),
    (
        "replay_paused",
        "PostgreSQL: WAL replay paused",
        "warning",
    ),
    ("slots", "PostgreSQL: replication slot backlog", "warning"),
];
// None is incomplete coverage, never a healthy sample. Unknown/idle lag is not zero.
fn signals(w: &Wire, c: &Config, thresholds: &Thresholds) -> BTreeMap<&'static str, Option<f64>> {
    let mut out = RULES
        .iter()
        .map(|(k, _, _)| (*k, None))
        .collect::<BTreeMap<_, _>>();
    let Some(m) = &w.metrics else {
        return out;
    };
    out.insert(
        "freeze_age",
        Some(if m.xid_age as f64 >= thresholds["freeze_age"]["warning"] {
            m.xid_age as f64
        } else {
            0.
        }),
    );
    out.insert(
        "connections",
        Some(100. * m.connections as f64 / (m.max_connections - m.reserved_connections) as f64),
    );
    if m.track_activities && m.disabled_activities == 0 {
        for (rule, count) in [
            ("long_queries", m.long_queries),
            ("idle_transactions", m.idle_transactions),
        ] {
            let count = count as f64;
            let value = if count >= thresholds[rule]["warning"] { count } else { 0. };
            out.insert(rule, Some(value));
        }
    }
    if m.unknown_waits == 0 {
        let limits = &thresholds["locks"];
        let bad = m.max_wait_seconds >= limits["seconds"] && m.blocked as f64 >= limits["warning"];
        out.insert(
            "locks",
            Some(if bad { m.blocked as f64 } else { 0. }),
        );
    }
    let backlog = if m.recovery {
        m.replay_backlog_bytes
    } else if m.replication_unknown > 0 {
        None
    } else {
        Some(m.replica_backlog_bytes.unwrap_or(0.))
    };
    let replication_minimum = thresholds["replication"]["warning"] * 1024. * 1024.;
    out.insert("replication", backlog.map(|b| if b >= replication_minimum { b } else { 0. }));
    out.insert(
        "streaming",
        Some(
            if !m.recovery && m.streaming < (c.expected_streaming as u64) {
                (c.expected_streaming as u64 - m.streaming) as f64
            } else {
                0.
            },
        ),
    );
    out.insert(
        "receiver",
        Some(if m.recovery && c.expect_receiver && m.receiver == 0 {
            1.
        } else {
            0.
        }),
    );
    out.insert(
        "replay_paused",
        Some(if m.recovery && m.replay_paused {
            1.
        } else {
            0.
        }),
    );
    out.insert(
        "slots",
        if m.recovery && m.replay_backlog_bytes.is_none() {
            None
        } else {
            Some(
                m.slot_retained_bytes
                    .filter(|b| *b >= thresholds["slots"]["warning"] * 1024. * 1024.)
                    .unwrap_or(0.),
            )
        },
    );
    out
}

fn breached(key: &str, value: f64, thresholds: &Thresholds) -> bool {
    if key == "connections" {
        value >= thresholds[key]["warning"]
    } else {
        value > 0.
    }
}

fn read_state(db: &Connection, id: &str, instance: &str) -> Result<Checkpoint> {
    let raw: String = db
        .query_row(
            "SELECT payload FROM service_state WHERE kind='postgresql' AND server_id=?1 AND instance_id=?2",
            params![id, instance],
            |r| r.get(0),
        )
        .map_err(err)?;
    let mut s: Checkpoint = serde_json::from_str(&raw).map_err(err)?;
    s.instance_id = instance.into();
    s.config.auto_endpoint = Some(s.config.automatic(instance));
    let p = crate::monitoring::effective(db, "postgresql", id, instance)?.values;
    s.config.interval_seconds = p.interval_seconds;
    s.config.enabled = p.diagnostic_enabled;
    s.config.expected_streaming = p.expected_peers;
    s.config.expect_receiver = p.expect_replica;
    Ok(s)
}
fn write_state(db: &Connection, id: &str, s: &Checkpoint) -> Result<()> {
    db.execute(
        "UPDATE service_state SET payload=?2 WHERE kind='postgresql' AND server_id=?1 AND instance_id=?3",
        params![id, serde_json::to_string(s).map_err(err)?, s.instance_id],
    )
    .map_err(err)?;
    Ok(())
}
fn stale(db: &Connection, id: &str, instance: &str, key: Option<&str>) -> Result<()> {
    db.execute("UPDATE incidents SET payload=json_set(payload,'$.freshUntil',0,'$.autoEligible',json('false'),'$.healthyStreak',0) WHERE server_id=?1 AND json_extract(payload,'$.check') LIKE ?3 AND (?2 IS NULL OR json_extract(payload,'$.check')=?2)",params![id,key,instances::prefix("postgresql",instance)]).map_err(err)?;
    Ok(())
}
fn open_incidents(db: &Connection, id: Option<&str>) -> Result<Vec<Incident>> {
    let mut q=db.prepare("SELECT payload FROM incidents WHERE (?1 IS NULL OR server_id=?1) AND json_extract(payload,'$.check') GLOB 'postgresql*:*' AND json_extract(payload,'$.status')='open'").map_err(err)?;
    let result = q
        .query_map([id], |r| r.get::<_, String>(0))
        .map_err(err)?
        .map(|r| serde_json::from_str(&r.map_err(err)?).map_err(err))
        .collect();
    result
}
fn card_status(
    incidents: &[&Incident],
    state: &Checkpoint,
    summary: Option<&Summary>,
    fresh: bool,
    thresholds: &Thresholds,
) -> Result<&'static str> {
    if !fresh {
        return Ok("unknown");
    }
    let Some(s) = summary else {
        return Ok("unknown");
    };
    if s.findings.iter().any(|f| f.severity == "critical") {
        return Ok("critical");
    }
    if !s.findings.is_empty() {
        return Ok("warning");
    }
    if incidents
        .iter()
        .any(|i| i.fresh_until.is_some_and(|t| t >= now()) && i.severity == "critical")
    {
        return Ok("critical");
    }
    if incidents
        .iter()
        .any(|i| i.fresh_until.is_some_and(|t| t >= now()))
    {
        return Ok("warning");
    }
    if !incidents.is_empty() {
        return Ok("unknown");
    }
    if signals(&s.data, &state.config, thresholds)
        .iter()
        .any(|(key, value)| value.is_some_and(|v| breached(key, v, thresholds)))
    {
        return Ok("warning");
    }
    Ok(if s.data.connected && s.data.metrics.is_some() {
        "healthy"
    } else if absent(&s.data, &state.config) {
        "not_detected"
    } else {
        "unknown"
    })
}
fn absent(data: &Wire, config: &Config) -> bool {
    !data.detected && (!config.enabled || config.automatic(DEFAULT) && data.issues.is_empty())
}

fn fresh(state: &Checkpoint, summary: Option<&Summary>) -> bool {
    state.error.is_none()
        && state.last_success.is_some_and(|at| {
            let interval = if state.config.enabled
                && !summary.is_some_and(|s| absent(&s.data, &state.config))
            {
                state.config.interval_seconds * 2 + 30
            } else {
                43230
            };
            now() - at <= interval as i64
        })
}
impl Store {
    #[cfg(test)]
    pub(crate) fn postgresql_state(&self, id: &str) -> Result<Checkpoint> {
        self.postgresql_state_for(id, DEFAULT)
    }
    pub(crate) fn postgresql_state_for(&self, id: &str, instance: &str) -> Result<Checkpoint> {
        let db = self.0.lock().map_err(err)?;
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
        instances::ensure(&db, id, "postgresql", instance)?;
        let mut initial = Checkpoint::new(&format!("{id}:{instance}"));
        initial.instance_id = instance.into();
        db.execute(
            "INSERT OR IGNORE INTO service_state(server_id,kind,payload,instance_id) VALUES(?1,'postgresql',?2,?3)",
            params![
                id,
                serde_json::to_string(&initial).map_err(err)?,instance
            ],
        )
        .map_err(err)?;
        read_state(&db, id, instance)
    }
    #[cfg(test)]
    pub(crate) fn configure_postgresql(&self, id: &str, config: Config) -> Result<()> {
        self.configure_postgresql_for(id, DEFAULT, config)
    }
    pub(crate) fn configure_postgresql_for(
        &self,
        id: &str,
        instance: &str,
        config: Config,
    ) -> Result<()> {
        config.validate()?;
        self.postgresql_state_for(id, instance)?;
        let mut db = self.0.lock().map_err(err)?;
        crate::storage::admit(&db)?;
        let tx = db.transaction().map_err(err)?;
        crate::monitoring::check_commit(&tx)?;
        let mut s = read_state(&tx, id, instance)?;
        if (
            s.config.host.as_str(),
            s.config.port,
            s.config.database.as_str(),
            s.config.automatic(instance),
        ) != (
            config.host.as_str(),
            config.port,
            config.database.as_str(),
            config.automatic(instance),
        ) {
            tx.execute("DELETE FROM ai_jobs WHERE incident_id IN (SELECT id FROM incidents WHERE server_id=?1 AND json_extract(payload,'$.check') LIKE ?2)",params![id,instances::prefix("postgresql",instance)]).map_err(err)?;
            tx.execute("DELETE FROM incidents WHERE server_id=?1 AND json_extract(payload,'$.check') LIKE ?2",params![id,instances::prefix("postgresql",instance)]).map_err(err)?;
            tx.execute(
                "DELETE FROM service_summaries WHERE kind='postgresql' AND server_id=?1 AND instance_id=?2",
                params![id, instance],
            )
            .map_err(err)?;
        }
        let old = crate::monitoring::effective(&tx, "postgresql", id, instance)?.values;
        let new = crate::monitoring::Values {
            enabled: old.enabled,
            interval_seconds: config.interval_seconds,
            diagnostic_enabled: config.enabled,
            expected_peers: config.expected_streaming,
            expect_replica: config.expect_receiver,
            ..old.clone()
        };
        crate::monitoring::legacy_service(&tx, "postgresql", id, instance, &old, &new)?;
        s.config = config;
        s.epoch = uuid::Uuid::new_v4().to_string();
        s.revision += 1;
        s.streaks.clear();
        s.last_sample = None;
        s.last_success = None;
        s.generation = None;
        s.error = None;
        s.next_check = now();
        stale(&tx, id, instance, None)?;
        write_state(&tx, id, &s)?;
        tx.commit().map_err(err)
    }
    #[cfg(test)]
    pub(crate) fn postgresql_view(&self, id: &str) -> Result<View> {
        self.postgresql_view_for(id, DEFAULT)
    }
    pub(crate) fn postgresql_view_for(&self, id: &str, instance: &str) -> Result<View> {
        let s = self.postgresql_state_for(id, instance)?;
        let db = self.0.lock().map_err(err)?;
        let raw:Option<String>=db.query_row("SELECT payload FROM service_summaries WHERE kind='postgresql' AND server_id=?1 AND instance_id=?2 ORDER BY at DESC,rowid DESC LIMIT 1",params![id,instance],|r|r.get(0)).optional().map_err(err)?;
        let mut summary: Option<Summary> = raw
            .map(|s| serde_json::from_str(&s).map_err(err))
            .transpose()?;
        let monitoring = crate::monitoring::effective(&db, "postgresql", id, instance)?.values;
        let fresh = monitoring.enabled && fresh(&s, summary.as_ref());
        let incidents = open_incidents(&db, Some(id))?
            .into_iter()
            .filter(|i| {
                i.check
                    .starts_with(&format!("{}:", instances::scope("postgresql", instance)))
            })
            .collect::<Vec<_>>();
        let status = card_status(
            &incidents.iter().collect::<Vec<_>>(),
            &s,
            summary.as_ref(),
            fresh,
            &monitoring.thresholds,
        )?;
        let mut q=db.prepare("SELECT payload FROM service_summaries WHERE kind='postgresql' AND instance_id=?2 AND id IN (SELECT e.summary_id FROM service_evidence e JOIN incidents i ON i.id=e.incident_id WHERE i.server_id=?1 AND json_extract(i.payload,'$.status')='open') ORDER BY at DESC,rowid DESC LIMIT 5").map_err(err)?;
        let mut evidence = q
            .query_map(params![id, instance], |r| r.get::<_, String>(0))
            .map_err(err)?
            .map(|r| serde_json::from_str(&r.map_err(err)?).map_err(err))
            .collect::<Result<Vec<Summary>>>()?;
        let names = instances::Names::load(&db, Some(id))?;
        for summary in summary.iter_mut().chain(evidence.iter_mut()) {
            for finding in &mut summary.findings {
                finding.title = names.incident_title(id, &finding.key, &finding.title);
            }
        }
        Ok(View {
            monitoring,
            config: s.config,
            summary,
            evidence,
            error: s.error,
            fresh,
            next_check: s.next_check,
            status: status.into(),
        })
    }
    pub(crate) fn postgresql_instance_cards(
        db: &Connection,
        names: &instances::Names,
    ) -> Result<Vec<(String, crate::services::Card)>> {
        let book = crate::monitoring::Book::load(db)?;
        let incidents = open_incidents(db, None)?;
        let mut q=db.prepare("SELECT s.server_id,s.instance_id,s.payload,(SELECT payload FROM service_summaries x WHERE x.kind='postgresql' AND x.server_id=s.server_id AND x.instance_id=s.instance_id ORDER BY at DESC,rowid DESC LIMIT 1) FROM service_state s WHERE s.kind='postgresql'").map_err(err)?;
        let rows = q
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                ))
            })
            .map_err(err)?;
        rows.map(|r| {
            let (id, instance, raw, summary) = r.map_err(err)?;
            let mut state: Checkpoint = serde_json::from_str(&raw).map_err(err)?;
            let policy = book
                .resolve(&crate::monitoring::scope(
                    "postgresql",
                    Some(&id),
                    Some(&instance),
                ))?
                .values;
            state.config.interval_seconds = policy.interval_seconds;
            state.config.enabled = policy.diagnostic_enabled;
            state.config.auto_endpoint = Some(state.config.automatic(&instance));
            let summary: Option<Summary> = summary
                .map(|s| serde_json::from_str(&s).map_err(err))
                .transpose()?;
            let fresh = policy.enabled && fresh(&state, summary.as_ref());
            let key = format!("{}:", instances::scope("postgresql", &instance));
            let selected = incidents
                .iter()
                .filter(|i| i.server_id == id && i.check.starts_with(&key))
                .collect::<Vec<_>>();
            let status = card_status(&selected, &state, summary.as_ref(), fresh, &policy.thresholds)?;
            let name = names.name(&id, "postgresql", &instance);
            Ok((
                id,
                crate::services::Card {
                    kind: "postgresql".into(),
                    availability: None,
                    instance_id: instance,
                    name,
                    detected: summary.is_some_and(|s| s.data.detected),
                    status: status.into(),
                    at: state.last_success,
                    metric: None,
                },
            ))
        })
        .collect()
    }
    pub(crate) fn record_postgresql(
        &self,
        server: &Server,
        expected: &Checkpoint,
        bytes: &[u8],
        at: i64,
    ) -> Result<Summary> {
        if bytes.len() > 32768 {
            return Err("PostgreSQL summary more than 32 KiB".into());
        }
        let wire: Wire =
            serde_json::from_slice(bytes).map_err(|_| "Incorrect PostgreSQL format")?;
        validate(&wire)?;
        let mut db = self.0.lock().map_err(err)?;
        crate::storage::admit(&db)?;
        let tx = db.transaction().map_err(err)?;
        crate::monitoring::check_commit(&tx)?;
        let raw: String = tx
            .query_row(
                "SELECT payload FROM servers WHERE id=?1",
                [&server.id],
                |r| r.get(0),
            )
            .map_err(err)?;
        let current: Server = serde_json::from_str(&raw).map_err(err)?;
        let instance = &expected.instance_id;
        let mut s = read_state(&tx, &server.id, instance)?;
        let policy = crate::monitoring::effective(&tx, "postgresql", &server.id, instance)?;
        let thresholds = &policy.values.thresholds;
        if serde_json::to_value(current.endpoint).map_err(err)?
            != serde_json::to_value(&server.endpoint).map_err(err)?
            || s.epoch != expected.epoch
            || s.revision != expected.revision
        {
            return Err("PostgreSQL connection or profile changed".into());
        }
        if !s.config.enabled && wire.connected {
            return Err("Diagnostic connection disabled".into());
        }
        let generation = wire.meta.as_ref().map(|m| m.generation);
        if generation != s.generation {
            s.streaks.clear();
            s.last_sample = None;
            stale(&tx, &server.id, instance, None)?;
            s.generation = generation;
        }
        let advance = s.last_sample.is_none_or(|t| at - t >= 60);
        let values = signals(&wire, &s.config, thresholds);
        let id = uuid::Uuid::new_v4().to_string();
        let mut findings = vec![];
        for (key, title, severity) in RULES {
            let instance_title = title.replacen(
                "PostgreSQL",
                &instances::name(&tx, &server.id, "postgresql", instance)?,
                1,
            );
            let title = &instance_title.as_str();
            let check = format!("{}:{key}", instances::scope("postgresql", instance));
            let iid = stable_id(&server.id, &check);
            let Some(value) = values[key] else {
                s.streaks.remove(*key);
                stale(&tx, &server.id, instance, Some(&check))?;
                continue;
            };
            let bad = breached(key, value, thresholds);
            if !bad {
                s.streaks.insert((*key).into(), 0);
                if !advance {
                    stale(&tx, &server.id, instance, Some(&check))?;
                }
            }
            if advance {
                let n = if bad {
                    s.streaks.get(*key).copied().unwrap_or(0).saturating_add(1)
                } else {
                    0
                };
                s.streaks.insert((*key).into(), n);
            }
            let firing = bad && s.streaks.get(*key).copied().unwrap_or(0) >= 2;
            if firing {
                let severity = thresholds
                    .get(*key)
                    .map_or(*severity, |limits| thresholds::severity(limits, value));
                findings.push(Finding {
                    key: check.clone(),
                    title: (*title).into(),
                    severity: severity.into(),
                    value,
                });
            }
            let open = crate::incidents::needs_observation(&tx, &iid)?;
            if !advance {
                continue;
            }
            if firing || !bad && open {
                let sev = findings
                    .last()
                    .filter(|f| f.key == check)
                    .map_or(*severity, |f| f.severity.as_str());
                Self::incident(
                    &tx,
                    &server.id,
                    &check,
                    if firing {
                        Some(format!("{title}: {value}; summary {id}"))
                    } else {
                        None
                    },
                    title,
                    sev,
                    at,
                )?;
                tx.execute("UPDATE incidents SET payload=json_set(payload,'$.freshUntil',?2,'$.autoEligible',CASE WHEN json_extract(payload,'$.status')='open' THEN json(?3) ELSE json('false') END) WHERE id=?1",params![iid,at+(s.config.interval_seconds*2+30) as i64,if firing{"true"}else{"false"}]).map_err(err)?;
            } else if open {
                stale(&tx, &server.id, instance, Some(&check))?;
            }
        }
        let summary = Summary {
            id,
            at,
            data: wire,
            findings,
            bytes_received: bytes.len(),
        };
        tx.execute(
            "INSERT INTO service_summaries(id,server_id,kind,at,payload,instance_id) VALUES(?1,?2,'postgresql',?3,?4,?5)",
            params![
                summary.id,
                server.id,
                at,
                serde_json::to_string(&summary).map_err(err)?,instance
            ],
        )
        .map_err(err)?;
        for f in &summary.findings {
            let iid = stable_id(&server.id, &f.key);
            tx.execute(
                "INSERT INTO service_evidence SELECT id,?2 FROM incidents WHERE id=?1",
                params![iid, summary.id],
            )
            .map_err(err)?;
            tx.execute("DELETE FROM service_evidence WHERE incident_id=?1 AND summary_id NOT IN (SELECT e.summary_id FROM service_evidence e JOIN service_summaries s ON s.id=e.summary_id WHERE e.incident_id=?1 ORDER BY s.at DESC,s.rowid DESC LIMIT 5)",[iid]).map_err(err)?;
        }
        if advance {
            s.last_sample = Some(at);
        }
        s.revision += 1;
        s.last_success = Some(at);
        s.error = None;
        let absent = absent(&summary.data, &s.config);
        s.failures = if s.config.enabled && !absent && summary.data.metrics.is_none() {
            s.failures.saturating_add(1)
        } else {
            0
        };
        s.next_check =
            at + if s.config.enabled && !absent {
                s.config
                    .interval_seconds
                    .saturating_mul(2u64.saturating_pow(s.failures.min(5)))
                    .min(if s.failures > 0 { 3600 } else { 86400 }) as i64
            } else {
                21600
            } + server.id.bytes().map(i64::from).sum::<i64>() % 30;
        write_state(&tx, &server.id, &s)?;
        crate::services::trim_instance(&tx, &server.id, "postgresql", instance, at)?;
        tx.commit().map_err(err)?;
        Ok(summary)
    }
    fn postgresql_error(&self, id: &str, expected: &Checkpoint) -> Result<()> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        crate::monitoring::check_commit(&tx)?;
        let instance = &expected.instance_id;
        if let Ok(mut s) = read_state(&tx, id, instance) {
            if s.revision == expected.revision && s.epoch == expected.epoch {
                s.revision += 1;
                s.failures = s.failures.saturating_add(1);
                s.error = Some("No new PostgreSQL summary received. Previous data is stale.".into());
                s.streaks.clear();
                s.next_check = now()
                    + (s.config
                        .interval_seconds
                        .saturating_mul(2u64.saturating_pow(s.failures.min(5)))
                        .min(3600)) as i64;
                write_state(&tx, id, &s)?;
                stale(&tx, id, instance, None)?;
            }
        }
        tx.commit().map_err(err)
    }
}
pub(crate) async fn collect_for(
    state: Arc<AppState>,
    id: String,
    instance: String,
) -> Result<Summary> {
    crate::monitoring::run(
        &state.store,
        "postgresql",
        &id,
        &instance,
        collect_for_inner(state.clone(), id.clone(), instance.clone()),
    )
    .await
}
async fn collect_for_inner(state: Arc<AppState>, id: String, instance: String) -> Result<Summary> {
    let mut _activity_span =
        crate::activity::begin("server", "postgresql.collect_for", Some(id.clone()));
    let _activity_result = (async {
        let _guard = state.collectors.acquire(&id, &state.store).await?;
        let snapshot = state.store.snapshot()?;
        let server = snapshot
            .servers
            .into_iter()
            .find(|s| s.id == id)
            .ok_or("The server is remote")?;
        let checkpoint = state.store.postgresql_state_for(&id, &instance)?;
        let policy = crate::monitoring::effective_values(&state.store, "postgresql", &id, &instance)?;
        let result = async {
            ssh::deploy(&server.endpoint, &state.collector).await?;
            let bytes = ssh::service_sample(
                &server.endpoint,
                "postgresql",
                &instance,
                json!(checkpoint.config),
                serde_json::Value::Null,
                thresholds::collector_values("postgresql", &policy.thresholds),
            )
            .await?;
            state
                .store
                .record_postgresql(&server, &checkpoint, &bytes, now())
        }
        .await;
        if result.is_err() {
            state.store.postgresql_error(&id, &checkpoint)?;
        }
        result
    })
    .await;
    _activity_span.result(&_activity_result);
    _activity_result
}

pub(crate) const BACKEND: crate::services::ServiceBackend = crate::services::ServiceBackend {
    view: |store, id, instance| {
        serde_json::to_value(store.postgresql_view_for(id, instance)?).map_err(err)
    },
    configure: Some(|store, id, instance, config| {
        store.configure_postgresql_for(id, instance, serde_json::from_value(config).map_err(err)?)
    }),
    refresh: |state, id, instance| {
        Box::pin(async move {
            serde_json::to_value(collect_for(state, id, instance).await?).map_err(err)
        })
    },
    init: |server, instance, port| {
        let mut state = Checkpoint::new(&format!("{server}:{instance}"));
        state.instance_id = instance.into();
        if let Some(port) = port {
            state.config.port = port;
        }
        serde_json::to_string(&state).map_err(err)
    },
    cards: Store::postgresql_instance_cards,
    incident_title: |metric, name| {
        RULES
            .iter()
            .find(|(key, _, _)| *key == metric)
            .map(|(_, title, _)| title.replacen("PostgreSQL", name, 1))
    },
    invalidate: None,
    check_input: None,
    configure_smoke: Some(|store, id, instance| {
        let mut config = Config {
            enabled: true,
            port: std::env::var("CYBERBOT_TEST_INSTANCE_PORT")
                .unwrap_or("5432".into())
                .parse()
                .map_err(err)?,
            user: "ops".into(),
            interval_seconds: 60,
            expected_streaming: std::env::var("CYBERBOT_TEST_PG_EXPECTED")
                .unwrap_or("0".into())
                .parse()
                .map_err(err)?,
            ..Config::default()
        };
        config.auto_endpoint = Some(config.automatic(instance));
        if store.postgresql_state_for(id, instance)?.config != config {
            store.configure_postgresql_for(id, instance, config)?;
        }
        Ok(())
    }),
    mutation: None,
    source: include_str!("postgresql.rs"),
};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    fn fixture() -> (Store, Server) {
        let db = Store::open(std::path::Path::new(":memory:")).unwrap();
        let source = Source {
            id: "pg".into(),
            name: "Test".into(),

            kind: "manual".into(),
            location: "ops@host".into(),
            last_sync: None,
            error: None,
        };
        db.import(
            &source,
            crate::inventory::parse_manual(&source.location).unwrap(),
        )
        .unwrap();
        let server = db.snapshot().unwrap().servers.remove(0);
        db.configure_postgresql(
            &server.id,
            Config {
                enabled: true,
                interval_seconds: 60,
                ..Config::default()
            },
        )
        .unwrap();
        (db, server)
    }
    fn wire(connections: u64) -> Value {
        let meta = json!({"version":150000,"generation":1,"fullStats":true,"superuser":false,"trackActivities":true,"trackCounts":true,"recovery":false});
        let mut metrics = meta.clone();
        metrics.as_object_mut().unwrap().remove("superuser");
        for(k,v)in json!({"connections":connections,"maxConnections":100,"reservedConnections":3,"active":1,"disabledActivities":0,"longQueries":0,"longestQuerySeconds":0.1,"idleTransactions":0,"blocked":0,"unknownWaits":0,"maxWaitSeconds":0.0,"blockers":[],"streaming":0,"replicationUnknown":0,"replicaBacklogBytes":null,"receiver":0,"replayBacklogBytes":null,"replayPaused":false,"slotRetainedBytes":null,"inactiveSlots":0,"autovacuumWorkers":0,"xidAge":100,"deadlocks":100,"rollbacks":1000}).as_object().unwrap(){metrics[k]=v.clone();}
        json!({"version":1,"detected":true,"connected":true,"coverage":true,"issues":[],"meta":meta,"metrics":metrics,"durationMs":20})
    }
    fn record(db: &Store, s: &Server, v: Value, at: i64) -> Summary {
        let state = db.postgresql_state(&s.id).unwrap();
        db.record_postgresql(s, &state, &serde_json::to_vec(&v).unwrap(), at)
            .unwrap()
    }
    #[test]
    fn manually_closed_postgresql_recovers_and_reopens_as_a_new_episode() {
        let (db, s) = fixture();
        let at = now();
        record(&db, &s, wire(99), at);
        record(&db, &s, wire(99), at + 60);
        let i = db.snapshot().unwrap().incidents.remove(0);
        db.resolve_incident(&i.id, &i.episode, at + 61).unwrap();
        record(&db, &s, wire(99), at + 120);
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "resolved");
        assert!(!db.snapshot().unwrap().incidents[0].auto_eligible);
        record(&db, &s, wire(10), at + 180);
        record(&db, &s, wire(10), at + 240);
        assert!(!db.snapshot().unwrap().incidents[0].manual_resolution_pending);
        record(&db, &s, wire(99), at + 300);
        record(&db, &s, wire(99), at + 360);
        assert_ne!(db.snapshot().unwrap().incidents[0].episode, i.episode);
    }
    #[test]
    fn migrate_v9_keeps_default_settings_history_and_incidents() {
        let (db, server) = fixture();
        let at = now();
        record(&db, &server, wire(95), at);
        let summary = record(&db, &server, wire(95), at + 60);
        let incident = db.snapshot().unwrap().incidents[0].id.clone();
        let evidence_count = db.postgresql_view(&server.id).unwrap().evidence.len();
        let mut redis = crate::services::Config::default_for("redis").unwrap();
        redis.port = 6382;
        db.configure_service(&server.id, "redis", redis).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v9.sqlite");
        db.0.lock()
            .unwrap()
            .execute("VACUUM INTO ?1", [path.to_str().unwrap()])
            .unwrap();
        let old = rusqlite::Connection::open(&path).unwrap();
        crate::service_migration::initialize_legacy(&old, 9).unwrap();
        old.execute_batch("BEGIN;
            INSERT INTO postgresql_state SELECT server_id,json_remove(payload,'$.instanceId') FROM service_state WHERE kind='postgresql';
            INSERT INTO postgresql_summaries SELECT id,server_id,at,payload FROM service_summaries WHERE kind='postgresql';
            INSERT INTO postgresql_evidence SELECT incident_id,summary_id FROM service_evidence
              WHERE summary_id IN (SELECT id FROM postgresql_summaries);
            DELETE FROM service_evidence WHERE summary_id IN (SELECT id FROM postgresql_summaries);
            DELETE FROM service_summaries WHERE kind='postgresql';
            DELETE FROM service_state WHERE kind='postgresql';
            CREATE TABLE old_services(server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,kind TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(server_id,kind));
            INSERT INTO old_services SELECT server_id,kind,json_remove(payload,'$.instanceId') FROM service_state;
            DROP TABLE service_state; ALTER TABLE old_services RENAME TO service_state;
            DROP INDEX service_summaries_instance_at;
            ALTER TABLE service_summaries DROP COLUMN instance_id;
            DROP TABLE service_instances; PRAGMA user_version=9; COMMIT;").unwrap();
        drop(old);
        for _ in 0..2 {
            let reopened = Store::open(&path).unwrap();
            assert_eq!(
                reopened
                    .postgresql_view(&server.id)
                    .unwrap()
                    .summary
                    .unwrap()
                    .id,
                summary.id
            );
            assert_eq!(reopened.snapshot().unwrap().incidents[0].id, incident);
            assert_eq!(
                reopened
                    .service_state(&server.id, "redis")
                    .unwrap()
                    .config
                    .port,
                6382
            );
            assert_eq!(
                reopened.postgresql_state(&server.id).unwrap().instance_id,
                DEFAULT
            );
            assert_eq!(
                reopened.postgresql_view(&server.id).unwrap().evidence.len(),
                evidence_count
            );
            assert_eq!(
                reopened
                    .0
                    .lock()
                    .unwrap()
                    .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                18
            );
        }
    }
    #[test]
    fn postgres_instances_have_separate_metrics_recovery_and_evidence() {
        let (db, server) = fixture();
        let other = db
            .add_service_instance(&server.id, "postgresql", None)
            .unwrap();
        db.configure_postgresql_for(
            &server.id,
            &other.id,
            Config {
                enabled: true,
                port: 5433,
                interval_seconds: 60,
                ..Config::default()
            },
        )
        .unwrap();
        let at = now();
        for t in [at, at + 60] {
            record(&db, &server, wire(95), t);
            let cp = db.postgresql_state_for(&server.id, &other.id).unwrap();
            db.record_postgresql(&server, &cp, &serde_json::to_vec(&wire(96)).unwrap(), t)
                .unwrap();
        }
        assert_eq!(db.snapshot().unwrap().incidents.len(), 2);
        let other_summary = db
            .postgresql_view_for(&server.id, &other.id)
            .unwrap()
            .summary
            .unwrap()
            .id;
        for t in [at + 120, at + 180] {
            record(&db, &server, wire(1), t);
        }
        let snap = db.snapshot().unwrap();
        assert_eq!(
            snap.incidents.iter().filter(|i| i.status == "open").count(),
            1
        );
        assert_eq!(
            db.postgresql_view_for(&server.id, &other.id)
                .unwrap()
                .summary
                .unwrap()
                .id,
            other_summary
        );
        assert_eq!(
            db.postgresql_view_for(&server.id, &other.id)
                .unwrap()
                .config
                .port,
            5433
        );
        assert_ne!(
            snap.services[&server.id]
                .iter()
                .find(|card| card.kind == "postgresql" && card.instance_id == other.id)
                .unwrap()
                .status,
            "healthy"
        );
        let late = db.postgresql_state_for(&server.id, &other.id).unwrap();
        db.remove_service_instance(&server.id, "postgresql", &other.id)
            .unwrap();
        assert!(db
            .record_postgresql(
                &server,
                &late,
                &serde_json::to_vec(&wire(99)).unwrap(),
                at + 240
            )
            .is_err());
        assert!(db.postgresql_view_for(&server.id, &other.id).is_err());
        assert!(db.postgresql_view(&server.id).unwrap().summary.is_some());
    }
    #[test]
    fn available_statistics_can_be_healthy_without_full_coverage() {
        let (db, s) = fixture();
        assert!(!db.snapshot().unwrap().services[&s.id][0].detected);
        let mut v = wire(1);
        v["coverage"] = json!(false);
        v["issues"] = json!(["counters_disabled"]);
        record(&db, &s, v.clone(), now());
        assert_eq!(db.postgresql_view(&s.id).unwrap().status, "healthy");
        v["meta"]["fullStats"] = json!(false);
        v["metrics"] = Value::Null;
        v["issues"] = json!(["read_all_stats_required"]);
        record(&db, &s, v, now());
        assert!(db.snapshot().unwrap().incidents.is_empty());
        assert_eq!(db.postgresql_view(&s.id).unwrap().status, "unknown");
        assert!(db.snapshot().unwrap().services[&s.id][0].detected);
    }
    #[test]
    fn persistent_anomaly_dedupe_recovery_and_partial_scope() {
        let (db, s) = fixture();
        db.save_settings(&Settings {
            mode: "auto".into(),
            daily_run_limit: Some(10),
            daily_token_limit: Some(1000000),
            ..Settings::default()
        })
        .unwrap();
        let at = now();
        record(&db, &s, wire(95), at);
        record(&db, &s, wire(95), at + 1);
        assert!(db.snapshot().unwrap().incidents.is_empty());
        record(&db, &s, wire(95), at + 60);
        db.reconcile_auto(at + 60).unwrap();
        assert_eq!(db.auto_status(at + 60).unwrap().queued, 1);
        let episode = db.snapshot().unwrap().incidents[0].episode.clone();
        record(&db, &s, wire(95), at + 120);
        db.reconcile_auto(at + 120).unwrap();
        assert_eq!(db.auto_status(at + 120).unwrap().queued, 1);
        assert_eq!(db.snapshot().unwrap().incidents[0].episode, episode);
        let mut missing = wire(1);
        missing["metrics"] = Value::Null;
        missing["coverage"] = json!(false);
        missing["issues"] = json!(["connection_or_query_denied"]);
        record(&db, &s, missing, at + 180);
        assert!(!db.snapshot().unwrap().incidents[0].auto_eligible);
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "open");
        record(&db, &s, wire(1), at + 240);
        assert_ne!(db.postgresql_view(&s.id).unwrap().status, "healthy");
        record(&db, &s, wire(1), at + 300);
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "resolved");
        let updated = db.snapshot().unwrap().incidents[0].updated_at;
        record(&db, &s, wire(1), at + 360);
        assert_eq!(db.snapshot().unwrap().incidents[0].updated_at, updated);
        assert_eq!(db.auto_status(at + 360).unwrap().runs, 0);
    }
    #[test]
    fn replication_is_not_idle_elapsed_time_and_expectations_are_explicit() {
        let v: Wire = serde_json::from_value(wire(1)).unwrap();
        let c = Config::default();
        let thresholds = crate::monitoring::Book::default().resolve(&crate::monitoring::scope("postgresql", None, None)).unwrap().values.thresholds;
        let signal = signals(&v, &c, &thresholds);
        assert_eq!(signal["replication"], Some(0.));
        assert_eq!(signal["streaming"], Some(0.));
        let c = Config {
            expected_streaming: 2,
            ..c
        };
        assert_eq!(signals(&v, &c, &thresholds)["streaming"], Some(2.));
        let mut v = v;
        v.meta.as_mut().unwrap().recovery = true;
        let m = v.metrics.as_mut().unwrap();
        m.recovery = true;
        m.replay_backlog_bytes = None;
        assert_eq!(signals(&v, &c, &thresholds)["replication"], None);
        v.metrics.as_mut().unwrap().replay_backlog_bytes = Some(0.);
        assert_eq!(signals(&v, &c, &thresholds)["replication"], Some(0.));
        v.metrics.as_mut().unwrap().replay_backlog_bytes = Some(100. * 1024. * 1024.);
        assert!(signals(&v, &c, &thresholds)["replication"].unwrap() > 0.);
    }
    #[test]
    fn configured_connection_limits_apply_to_the_card_and_confirmed_incidents() {
        let (db, server) = fixture();
        let scope = crate::monitoring::scope("postgresql", Some(&server.id), Some(DEFAULT));
        let policy = db.monitoring_policy(&scope).unwrap();
        db.set_monitoring(&scope, crate::monitoring::Overrides {
            thresholds: [("connections".into(), [("warning".into(), 99.), ("critical".into(), 100.)].into())].into(),
            ..policy.overrides
        }, policy.revision).unwrap();
        let at = now();
        record(&db, &server, wire(95), at);
        assert_eq!(db.postgresql_view(&server.id).unwrap().status, "healthy");
        record(&db, &server, wire(97), at + 60);
        assert_eq!(db.postgresql_view(&server.id).unwrap().status, "warning");
        record(&db, &server, wire(97), at + 120);
        assert_eq!(db.postgresql_view(&server.id).unwrap().status, "critical");
        assert_eq!(db.snapshot().unwrap().incidents[0].severity, "critical");
    }
    #[test]
    fn connection_failures_back_off_and_freeze_age_is_actionable() {
        let (db, s) = fixture();
        let at = now();
        let mut v = wire(1);
        v["metrics"] = Value::Null;
        v["coverage"] = json!(false);
        v["issues"] = json!(["connection_or_query_denied"]);
        for n in 0..8 {
            record(&db, &s, v.clone(), at + n * 60);
            let state = db.postgresql_state(&s.id).unwrap();
            assert!(state.next_check >= at + n * 60 + 120);
            assert!(state.next_check <= at + n * 60 + 3630);
        }
        let mut v = wire(1);
        v["metrics"]["xidAge"] = json!(1_600_000_000_u64);
        record(&db, &s, v.clone(), at + 600);
        record(&db, &s, v, at + 660);
        assert!(db
            .snapshot()
            .unwrap()
            .incidents
            .iter()
            .any(|i| i.check == "postgresql:freeze_age" && i.severity == "critical"));
        assert_eq!(db.postgresql_state(&s.id).unwrap().failures, 0);
    }
    #[test]
    fn stale_profile_duplicate_reply_endpoint_and_transaction_rollback() {
        let (db, s) = fixture();
        let old = db.postgresql_state(&s.id).unwrap();
        db.configure_postgresql(
            &s.id,
            Config {
                enabled: true,
                user: "new_role".into(),
                ..Config::default()
            },
        )
        .unwrap();
        let bytes = serde_json::to_vec(&wire(95)).unwrap();
        assert!(db.record_postgresql(&s, &old, &bytes, now()).is_err());
        let old = db.postgresql_state(&s.id).unwrap();
        db.record_postgresql(&s, &old, &bytes, now()).unwrap();
        assert!(db.record_postgresql(&s, &old, &bytes, now()).is_err());
        let old = db.postgresql_state(&s.id).unwrap();
        db.0.lock().unwrap().execute_batch("CREATE TRIGGER fail_pg BEFORE INSERT ON service_summaries BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
        assert!(db.record_postgresql(&s, &old, &bytes, now() + 60).is_err());
        assert_eq!(db.postgresql_state(&s.id).unwrap().revision, old.revision);
        assert!(db.snapshot().unwrap().incidents.is_empty());
        db.0.lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_pg")
            .unwrap();
        let mut changed = s.clone();
        changed.endpoint.port += 1;
        assert!(db
            .record_postgresql(&changed, &old, &bytes, now() + 60)
            .is_err());
        db.delete_source("pg").unwrap();
        assert!(db.record_postgresql(&s, &old, &bytes, now() + 60).is_err());
        assert!(db.postgresql_state(&s.id).is_err());
    }
    #[test]
    fn denies_query_text_arbitrary_endpoints_and_false_coverage() {
        let mut c = Config {
            database: "host=attacker".into(),
            ..Config::default()
        };
        assert!(c.validate().is_err());
        c = Config::default();
        c.host = "attacker.example".into();
        assert!(c.validate().is_err());
        let mut v = wire(1);
        v["metrics"]["query"] = json!("secret");
        assert!(serde_json::from_value::<Wire>(v).is_err());
        let mut v: Wire = serde_json::from_value(wire(1)).unwrap();
        v.metrics.as_mut().unwrap().disabled_activities = 1;
        assert!(validate(&v).is_err());
        let v: Wire = serde_json::from_value(wire(1)).unwrap();
        assert!(validate(&v).is_ok());
    }
    #[test]
    fn retirement_preserves_open_evidence_but_expires_closed() {
        let (db, s) = fixture();
        let at = now();
        record(&db, &s, wire(95), at);
        record(&db, &s, wire(95), at + 60);
        let mut guard = db.0.lock().unwrap();
        let tx = guard.transaction().unwrap();
        for n in 0..1100 {
            tx.execute(
                "INSERT INTO service_summaries(id,server_id,kind,at,payload) VALUES(?1,?2,'postgresql',?3,'{}')",
                params![format!("old-{n}"), s.id, at - 8 * 86400],
            )
            .unwrap();
        }
        tx.commit().unwrap();
        drop(guard);
        record(&db, &s, wire(1), at + 120);
        let count: i64 =
            db.0.lock()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM service_summaries WHERE kind='postgresql'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
        assert!(count < 10);
        assert!(!db.postgresql_view(&s.id).unwrap().evidence.is_empty());
        record(&db, &s, wire(1), at + 180);
        db.0.lock()
            .unwrap()
            .execute(
                "UPDATE incidents SET payload=json_set(payload,'$.updatedAt',?1)",
                [at - 31 * 86400],
            )
            .unwrap();
        db.maintain_storage().unwrap();
        assert_eq!(
            db.0.lock()
                .unwrap()
                .query_row("SELECT count(*) FROM service_evidence", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    #[tokio::test]
    async fn mcp_is_cached_and_never_executes_sql() {
        let dir = tempfile::tempdir().unwrap();
        let app = crate::create_state(dir.path().into()).unwrap();
        let source = Source {
            id: "pg".into(),
            name: "PG".into(),

            kind: "manual".into(),
            location: "ops@host".into(),
            last_sync: None,
            error: None,
        };
        app.store
            .import(
                &source,
                crate::inventory::parse_manual(&source.location).unwrap(),
            )
            .unwrap();
        let id = app.store.snapshot().unwrap().servers[0].id.clone();
        let mcp = crate::mcp::McpServer::start(app.clone(), std::slice::from_ref(&id))
            .await
            .unwrap();
        let result = crate::mcp::call(
            &mcp.scope,
            "get_service_summary",
            json!({"kind":"postgresql","serverId":id}),
        )
        .await
        .unwrap();
        let extra = app
            .store
            .add_service_instance(&id, "postgresql", None)
            .unwrap();
        let listed = crate::mcp::call(&mcp.scope, "list_service_instances", json!({"serverId":id}))
            .await
            .unwrap();
        assert!(listed.to_string().contains(&extra.id));
        let selected = crate::mcp::call(
            &mcp.scope,
            "get_service_summary",
            json!({"serverId":id,"kind":"postgresql","instanceId":extra.id}),
        )
        .await
        .unwrap();
        assert_eq!(selected["instanceId"], extra.id);
        assert!(selected.get("config").is_none());
        for (kind, instance) in [("redis", extra.id.as_str()), ("postgresql", "../../secret")] {
            assert!(crate::mcp::call(
                &mcp.scope,
                "get_service_summary",
                json!({"serverId":id,"kind":kind,"instanceId":instance})
            )
            .await
            .is_err());
        }
        app.store
            .remove_service_instance(&id, "postgresql", &extra.id)
            .unwrap();
        assert!(crate::mcp::call(
            &mcp.scope,
            "get_service_summary",
            json!({"kind":"postgresql","serverId":id,"instanceId":extra.id})
        )
        .await
        .is_err());
        assert!(result.get("config").is_none());
        assert_eq!(result["status"], "unknown");
        assert_eq!(
            mcp.scope.remote.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert!(crate::mcp::call(
            &mcp.scope,
            "get_service_summary",
            json!({"kind":"postgresql","serverId":id,"sql":"DROP TABLE users"})
        )
        .await
        .is_err());
        assert!(crate::mcp::call(
            &mcp.scope,
            "get_service_summary",
            json!({"kind":"postgresql","serverId":"outside"})
        )
        .await
        .is_err());
    }
}
