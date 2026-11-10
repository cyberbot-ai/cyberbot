//! Nginx service module. Remote aggregates, durable checkpoints, no model in collection.
use crate::{
    inventory::stable_id,
    logs::{LogCoverage, LogFinding},
    model::*,
    ssh,
    store::Store,
    AppState,
};
use crate::monitoring::thresholds::{self, Thresholds};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Arc};
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
const RULES: &[(&str, &str, &str)] = &[
    (
        "service_failed",
        "Nginx service failed",
        "critical",
    ),
    ("capacity", "Nginx reached its connection limit", "critical"),
    ("critical_error", "Nginx reported critical errors", "critical"),
    ("http_5xx", "Nginx is returning sustained 5xx errors", "warning"),
    ("latency", "Nginx requests have sustained high latency", "warning"),
    (
        "upstream",
        "Nginx reported recurring upstream errors",
        "warning",
    ),
];
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Timing {
    pub samples: u64,
    pub sum_ms: f64,
    pub max_ms: f64,
    pub slow: u64,
    pub histogram: Vec<u64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub active: u64,
    pub accepts: u64,
    pub handled: u64,
    pub requests: u64,
    pub reading: u64,
    pub writing: u64,
    pub waiting: u64,
    pub rps: Option<f64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Example {
    pub at: i64,
    pub category: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Wire {
    pub version: u32,
    pub at: i64,
    pub detected: bool,
    pub service: String,
    pub window_seconds: u64,
    pub coverage: LogCoverage,
    pub access_complete: bool,
    pub error_complete: bool,
    pub missing: Vec<String>,
    pub rps: Option<f64>,
    pub rps_source: String,
    pub status: Option<Status>,
    pub counts: BTreeMap<String, u64>,
    pub statuses: BTreeMap<String, u64>,
    pub request_time: Timing,
    pub upstream_time: Timing,
    pub examples: Vec<Example>,
    pub bytes_read: u64,
    pub duration_ms: u64,
    pub next_state: Value,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub id: String,
    pub received_at: i64,
    #[serde(flatten)]
    pub data: Wire,
    pub bytes_received: usize,
    pub findings: Vec<LogFinding>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Checkpoint {
    pub revision: u64,
    pub next_check: i64,
    pub last_success: Option<i64>,
    pub error: Option<String>,
    pub failures: u32,
    salt: String,
    cursor: Value,
    streaks: BTreeMap<String, u32>,
    card: Card,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Card {
    pub detected: bool,
    pub status: String,
    pub rps: Option<f64>,
    pub rps_source: String,
    pub at: Option<i64>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub monitoring: crate::monitoring::Values,
    pub evidence: Vec<Evidence>,
    pub summary: Option<Summary>,
    pub fresh: bool,
    pub error: Option<String>,
    pub next_check: i64,
    pub card: Card,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub summary_id: String,
    pub at: i64,
    pub findings: Vec<LogFinding>,
    pub counts: BTreeMap<String, u64>,
}
fn refresh_card(card: &mut Card, error: bool, interval: u64) {
    if error {
        card.status = "unknown".into();
        card.rps = None;
    } else if card.at.is_some_and(|t| {
        now() - t
            > (if card.detected {
                interval * 2 + 30
            } else {
                43230
            }) as i64
    }) {
        card.status = "stale".into();
        card.rps = None;
    }
}
impl Checkpoint {
    fn new(id: &str) -> Self {
        Self {
            revision: 0,
            next_check: now()
                + i64::from(
                    id.bytes()
                        .fold(11u16, |a, b| a.wrapping_mul(31).wrapping_add(b.into()))
                        % 600,
                ),
            last_success: None,
            error: None,
            failures: 0,
            salt: format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            ),
            cursor: json!({}),
            streaks: BTreeMap::new(),
            card: Card {
                detected: false,
                status: "unknown".into(),
                rps: None,
                rps_source: "access_log".into(),
                at: None,
            },
        }
    }
}
fn validate(w: &Wire) -> Result<()> {
    let categories = [
        "requests",
        "1xx",
        "2xx",
        "3xx",
        "4xx",
        "5xx",
        "unparsed",
        "upstream_timeout",
        "upstream_connect",
        "upstream_unavailable",
        "capacity",
        "critical_error",
        "client_noise",
        "other_errors",
    ];
    let sources = ["all", "access", "error", "config", "status"];
    let reasons = [
        "config_limit",
        "config_unavailable",
        "unsupported_log_path",
        "multiple_logs",
        "access_filtered",
        "source_unavailable",
        "source_changed",
        "backlog_skipped",
        "file_rewritten",
        "file_truncated",
        "rotation_tail_lost",
        "long_line",
        "incomplete_line",
        "invalid_encoding",
        "read_limit",
        "unknown_format",
        "unknown_timestamp",
        "clock_changed",
        "late_records",
        "timing_unavailable",
        "counter_reset",
    ];
    let counts_ok = w
        .counts
        .iter()
        .all(|(k, n)| categories.contains(&k.as_str()) && *n <= 2097152);
    let timing_ok = |t: &Timing| {
        t.samples <= 2097152
            && t.slow <= t.samples
            && t.histogram.len() == 14
            && t.histogram.iter().all(|n| *n <= 2097152)
            && t.histogram.iter().sum::<u64>() == t.samples
            && t.sum_ms.is_finite()
            && t.max_ms.is_finite()
            && t.sum_ms >= 0.0
            && t.max_ms >= 0.0
            && t.max_ms <= 86400000.0
            && t.sum_ms <= t.samples as f64 * 86400000.0
    };
    if w.version != 1
        || !(1..=3600).contains(&w.window_seconds)
        || ![
            "active",
            "inactive",
            "failed",
            "unknown",
            "activating",
            "deactivating",
        ]
        .contains(&w.service.as_str())
        || w.bytes_read > 2097152
        || w.duration_ms > 16000
        || !counts_ok
        || !timing_ok(&w.request_time)
        || !timing_ok(&w.upstream_time)
        || w.statuses.len() > 500
        || w.statuses.iter().any(|(k, n)| {
            k.parse::<u32>().map_or(true, |v| !(100..=599).contains(&v)) || *n > 2097152
        })
        || w.statuses.values().sum::<u64>() != w.counts.get("requests").copied().unwrap_or(0)
        || w.rps
            .is_some_and(|n| !n.is_finite() || !(0.0..=1e12).contains(&n))
        || !["access_log", "stub_status"].contains(&w.rps_source.as_str())
        || w.coverage.sources.len() > 2
        || w.coverage
            .sources
            .iter()
            .any(|s| !["access", "error"].contains(&s.as_str()))
        || w.coverage.gaps.len() > 16
        || w.coverage.complete && !w.coverage.gaps.is_empty()
        || w.coverage
            .gaps
            .iter()
            .any(|g| !sources.contains(&g.source.as_str()) || !reasons.contains(&g.reason.as_str()))
        || w.missing.len() > 4
        || w.missing.iter().any(|s| {
            ![
                "request_time",
                "upstream_response_time",
                "stub_status",
                "service_state",
            ]
            .contains(&s.as_str())
        })
        || w.examples.len() > 10
        || w.examples.iter().any(|e| {
            ![
                "capacity",
                "critical_error",
                "upstream_timeout",
                "upstream_connect",
                "upstream_unavailable",
            ]
            .contains(&e.category.as_str())
        })
        || !w.next_state.is_object()
        || serde_json::to_vec(&w.next_state).map_err(err)?.len() > 12000
    {
        return Err("Incompatible or oversized Nginx summary".into());
    }
    if let Some(s) = &w.status {
        if [
            s.active, s.accepts, s.handled, s.requests, s.reading, s.writing, s.waiting,
        ]
        .iter()
        .any(|n| *n > 9007199254740991)
            || s.rps
                .is_some_and(|n| !n.is_finite() || !(0.0..=1e12).contains(&n))
        {
            return Err("Incorrect stub_status".into());
        }
    }
    let requests = w.counts.get("requests").copied().unwrap_or(0);
    let complete_source = |source: &str| {
        w.coverage.sources.iter().any(|s| s == source)
            && !w
                .coverage
                .gaps
                .iter()
                .any(|g| g.source == source || g.source == "all" || g.source == "config")
    };
    if w.access_complete && !complete_source("access")
        || w.error_complete && !complete_source("error")
        || w.request_time.samples > requests
        || w.upstream_time.samples > requests.saturating_mul(32)
        || (1..=5).any(|class| {
            w.statuses
                .iter()
                .filter(|(s, _)| s.starts_with(&class.to_string()))
                .map(|(_, n)| n)
                .sum::<u64>()
                != w.counts.get(&format!("{class}xx")).copied().unwrap_or(0)
        })
        || w.rps_source == "stub_status" && w.status.as_ref().is_none_or(|s| s.rps != w.rps)
        || w.rps_source == "access_log"
            && w.rps.is_some()
            && (!w.access_complete || w.coverage.initial)
    {
        return Err("Inconsistent Nginx metrics".into());
    }
    Ok(())
}
fn evaluate(w: &Wire, state: &mut Checkpoint, thresholds: &Thresholds) -> Vec<LogFinding> {
    let count = |k: &str| w.counts.get(k).copied().unwrap_or(0);
    let mut findings = Vec::new();
    for (key, title, severity) in RULES {
        let (bad, complete, n, required) = match *key {
            "service_failed" => (w.service == "failed", w.service == "active", 1, 1),
            "capacity" | "critical_error" => (count(key) as f64 >= thresholds[*key]["critical"], w.error_complete, count(key), 1),
            "http_5xx" => (
                count("5xx") as f64 >= thresholds["http_5xx"]["warning"]
                    && count("5xx") as f64 / count("requests").max(1) as f64 >= thresholds["http_5xx"]["share"] / 100.,
                w.access_complete,
                count("5xx"),
                2,
            ),
            "latency" => (
                w.request_time.slow as f64 >= thresholds["latency"]["warning"]
                    && w.request_time.slow as f64 / w.request_time.samples.max(1) as f64 >= thresholds["latency"]["share"] / 100.,
                w.access_complete && w.request_time.samples > 0,
                w.request_time.slow,
                2,
            ),
            _ => {
                let n = count("upstream_timeout")
                    + count("upstream_connect")
                    + count("upstream_unavailable");
                (n as f64 >= thresholds["upstream"]["warning"], w.error_complete, n, 2)
            }
        };
        let eligible = required == 1 || complete && !w.coverage.initial && w.window_seconds >= 60;
        let streak = state.streaks.entry((*key).into()).or_default();
        *streak = if bad && eligible {
            streak.saturating_add(1)
        } else {
            0
        };
        if *streak >= required {
            findings.push(LogFinding {
                check: format!("nginx:{key}"),
                title: (*title).into(),
                severity: (*severity).into(),
                count: n,
            });
        }
    }
    findings
}
fn can_recover(w: &Wire, key: &str) -> bool {
    if w.coverage.initial || w.window_seconds < 60 {
        return false;
    }
    match key {
        "service_failed" => w.service == "active",
        "http_5xx" => w.access_complete,
        "latency" => w.access_complete && w.request_time.samples > 0,
        _ => w.error_complete,
    }
}
impl Store {
    pub(crate) fn nginx_state(&self, id: &str) -> Result<Checkpoint> {
        let db = self.0.lock().map_err(err)?;
        let found: Option<String> = db
            .query_row(
                "SELECT payload FROM service_state WHERE kind='nginx' AND server_id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        if let Some(s) = found {
            return serde_json::from_str(&s).map_err(err);
        }
        let state = Checkpoint::new(id);
        db.execute(
            "INSERT INTO service_state(server_id,kind,payload) VALUES(?1,'nginx',?2)",
            params![id, serde_json::to_string(&state).map_err(err)?],
        )
        .map_err(err)?;
        Ok(state)
    }
    pub(crate) fn nginx_cards(
        db: &rusqlite::Connection,
        _interval: u64,
    ) -> Result<BTreeMap<String, Card>> {
        let book = crate::monitoring::Book::load(db)?;
        let mut q=db.prepare("SELECT server_id,json_extract(payload,'$.card'),json_extract(payload,'$.error') FROM service_state WHERE kind='nginx'").map_err(err)?;
        let rows = q
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            })
            .map_err(err)?;
        rows.map(|r| {
            let (id, p, error) = r.map_err(err)?;
            let mut card: Card = serde_json::from_str(&p).map_err(err)?;
            let policy = book
                .resolve(&crate::monitoring::scope("nginx", Some(&id), None))?
                .values;
            refresh_card(
                &mut card,
                !policy.enabled || error.is_some(),
                policy.interval_seconds,
            );
            Ok((id, card))
        })
        .collect()
    }
    pub(crate) fn nginx_view(&self, id: &str) -> Result<View> {
        let state = self.nginx_state(id)?;
        let db = self.0.lock().map_err(err)?;
        let raw:Option<String>=db.query_row("SELECT payload FROM service_summaries WHERE kind='nginx' AND server_id=?1 ORDER BY at DESC,rowid DESC LIMIT 1",[id],|r|r.get(0)).optional().map_err(err)?;
        let policy = crate::monitoring::effective(&db, "nginx", id, "")?.values;
        let mut card = state.card;
        refresh_card(
            &mut card,
            !policy.enabled || state.error.is_some(),
            policy.interval_seconds,
        );
        let mut q=db.prepare("SELECT s.payload FROM service_summaries s WHERE s.kind='nginx' AND s.server_id=?1 AND s.id IN (SELECT e.summary_id FROM service_evidence e JOIN incidents i ON i.id=e.incident_id WHERE i.server_id=?1 AND json_extract(i.payload,'$.status')='open') ORDER BY s.at DESC,s.rowid DESC LIMIT 5").map_err(err)?;
        let rows = q.query_map([id], |r| r.get::<_, String>(0)).map_err(err)?;
        let evidence = rows
            .map(|r| {
                let s: Summary = serde_json::from_str(&r.map_err(err)?).map_err(err)?;
                Ok(Evidence {
                    summary_id: s.id,
                    at: s.received_at,
                    findings: s.findings,
                    counts: s.data.counts,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(View {
            monitoring: crate::monitoring::effective(&db, "nginx", id, "")?.values,
            evidence,
            summary: raw
                .map(|s| serde_json::from_str(&s).map_err(err))
                .transpose()?,
            fresh: policy.enabled
                && state.last_success.is_some()
                && !matches!(card.status.as_str(), "stale")
                && state.error.is_none(),
            error: state.error,
            next_check: state.next_check,
            card,
        })
    }
    pub(crate) fn record_nginx(
        &self,
        server: &Server,
        expected: &Checkpoint,
        bytes: &[u8],
        at: i64,
    ) -> Result<Summary> {
        if bytes.len() > 32768 {
            return Err("Nginx summary over 32 KiB".into());
        }
        let mut wire: Wire =
            serde_json::from_slice(bytes).map_err(|_| "Incorrect Nginx summary")?;
        validate(&wire)?;
        let mut db = self.0.lock().map_err(err)?;
        crate::storage::admit(&db)?;
        let tx = db.transaction().map_err(err)?;
        crate::monitoring::check_commit(&tx)?;
        let current: String = tx
            .query_row(
                "SELECT payload FROM servers WHERE id=?1",
                [&server.id],
                |r| r.get(0),
            )
            .map_err(err)?;
        let current: Server = serde_json::from_str(&current).map_err(err)?;
        if serde_json::to_value(&current.endpoint).map_err(err)?
            != serde_json::to_value(&server.endpoint).map_err(err)?
        {
            return Err("Connection has changed".into());
        }
        let stored: String = tx
            .query_row(
                "SELECT payload FROM service_state WHERE kind='nginx' AND server_id=?1",
                [&server.id],
                |r| r.get(0),
            )
            .map_err(err)?;
        let mut state: Checkpoint = serde_json::from_str(&stored).map_err(err)?;
        if state.revision != expected.revision || state.salt != expected.salt {
            return Err("Nginx log position has already changed".into());
        }
        let policy = crate::monitoring::effective(&tx, "nginx", &server.id, "")?.values;
        let interval = policy.interval_seconds;
        let findings = evaluate(&wire, &mut state, &policy.thresholds);
        state.cursor = std::mem::replace(&mut wire.next_state, json!({})); // never expose private checkpoint via MCP/UI
        let summary = Summary {
            id: uuid::Uuid::new_v4().to_string(),
            received_at: at,
            data: wire,
            bytes_received: bytes.len(),
            findings,
        };
        tx.execute(
            "INSERT INTO service_summaries(id,server_id,kind,at,payload) VALUES(?1,?2,'nginx',?3,?4)",
            params![
                summary.id,
                server.id,
                at,
                serde_json::to_string(&summary).map_err(err)?
            ],
        )
        .map_err(err)?;
        for (key, title, severity) in RULES {
            let check = format!("nginx:{key}");
            let iid = stable_id(&server.id, &check);
            let finding = summary.findings.iter().find(|f| f.check == check);
            let old: Option<String> = tx
                .query_row("SELECT payload FROM incidents WHERE id=?1", [&iid], |r| {
                    r.get(0)
                })
                .optional()
                .map_err(err)?;
            if finding.is_none()
                && old.as_ref().is_none_or(|s| {
                    serde_json::from_str::<Incident>(s)
                        .is_ok_and(|i| i.status == "resolved" && !i.manual_resolution_pending)
                })
            {
                continue;
            }
            // A subthreshold first bad window cannot count toward recovery.
            let recovering = can_recover(&summary.data, key)
                && state.streaks.get(*key).copied().unwrap_or(0) == 0;
            if finding.is_some() || recovering {
                Self::incident(
                    &tx,
                    &server.id,
                    &check,
                    finding.map(|f| format!("{}: {}; summary {}", f.title, f.count, summary.id)),
                    title,
                    severity,
                    at,
                )?;
                tx.execute(
                    "UPDATE incidents SET payload=json_set(payload,'$.freshUntil',?2) WHERE id=?1",
                    params![iid, at + (interval * 2 + 30) as i64],
                )
                .map_err(err)?;
                if finding.is_some() {
                    tx.execute(
                        "INSERT OR IGNORE INTO service_evidence VALUES(?1,?2)",
                        params![iid, summary.id],
                    )
                    .map_err(err)?;
                }
                tx.execute("DELETE FROM service_evidence WHERE incident_id=?1 AND summary_id NOT IN (SELECT e.summary_id FROM service_evidence e JOIN service_summaries s ON s.id=e.summary_id WHERE e.incident_id=?1 ORDER BY s.at DESC,s.rowid DESC LIMIT 5)",[&iid]).map_err(err)?;
            } else {
                tx.execute("UPDATE incidents SET payload=json_set(payload,'$.freshUntil',?2,'$.healthyStreak',0) WHERE id=?1",params![iid,at-1]).map_err(err)?;
            }
        }
        let incidents: Vec<Incident> = Self::list(&tx, "incidents")?;
        let active: Vec<_> = incidents
            .iter()
            .filter(|i| {
                i.server_id == server.id && i.check.starts_with("nginx:") && i.status == "open"
            })
            .collect();
        let status = if summary.findings.iter().any(|i| i.severity == "critical")
            || active.iter().any(|i| i.severity == "critical")
        {
            "critical"
        } else if !summary.findings.is_empty() || !active.is_empty() {
            "warning"
        } else if !summary.data.detected {
            "not_detected"
        } else if summary.data.service == "active"
            || summary.data.status.is_some()
            || !summary.data.coverage.sources.is_empty()
        {
            "healthy"
        } else {
            "unknown"
        };
        state.card = Card {
            detected: summary.data.detected,
            status: status.into(),
            rps: summary.data.rps,
            rps_source: summary.data.rps_source.clone(),
            at: Some(at),
        };
        state.revision += 1;
        state.last_success = Some(at);
        state.error = None;
        state.failures = 0;
        state.next_check =
            at + if summary.data.detected {
                interval as i64
            } else {
                21600
            } + (server.id.bytes().map(u64::from).sum::<u64>() % 30) as i64;
        tx.execute(
            "UPDATE service_state SET payload=?2 WHERE kind='nginx' AND server_id=?1",
            params![server.id, serde_json::to_string(&state).map_err(err)?],
        )
        .map_err(err)?;
        tx.execute("DELETE FROM service_evidence WHERE summary_id IN (SELECT id FROM service_summaries WHERE kind='nginx') AND incident_id IN (SELECT id FROM incidents WHERE json_extract(payload,'$.status')='resolved' AND json_extract(payload,'$.updatedAt')<?1)",[at-30*86400]).map_err(err)?;
        crate::services::trim_instance(&tx, &server.id, "nginx", crate::instances::DEFAULT, at)?;
        tx.commit().map_err(err)?;
        Ok(summary)
    }
    fn nginx_error(&self, id: &str, expected: &Checkpoint) -> Result<()> {
        let mut db = self.0.lock().map_err(err)?;
        crate::storage::admit(&db)?;
        let tx = db.transaction().map_err(err)?;
        crate::monitoring::check_commit(&tx)?;
        let raw: Option<String> = tx
            .query_row(
                "SELECT payload FROM service_state WHERE kind='nginx' AND server_id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        if let Some(raw) = raw {
            let mut s: Checkpoint = serde_json::from_str(&raw).map_err(err)?;
            if s.revision == expected.revision && s.salt == expected.salt {
                s.failures = s.failures.saturating_add(1);
                s.error = Some("Nginx log collection is incomplete. The saved position is unchanged.".into());
                s.streaks.clear();
                s.next_check = now()
                    + (crate::monitoring::effective(&tx, "nginx", id, "")?
                        .values
                        .interval_seconds
                        .saturating_mul(2u64.saturating_pow(s.failures.min(5)))
                        .min(3600)) as i64;
                tx.execute(
                    "UPDATE service_state SET payload=?2 WHERE kind='nginx' AND server_id=?1",
                    params![id, serde_json::to_string(&s).map_err(err)?],
                )
                .map_err(err)?;
                tx.execute("UPDATE incidents SET payload=json_set(payload,'$.freshUntil',?2,'$.healthyStreak',0) WHERE server_id=?1 AND json_extract(payload,'$.check') LIKE 'nginx:%'",params![id,now()-1]).map_err(err)?;
            }
        }
        tx.commit().map_err(err)
    }
}
pub(crate) async fn collect(state: Arc<AppState>, id: String) -> Result<Summary> {
    crate::monitoring::run(
        &state.store,
        "nginx",
        &id,
        "",
        collect_inner(state.clone(), id.clone()),
    )
    .await
}
async fn collect_inner(state: Arc<AppState>, id: String) -> Result<Summary> {
    let mut _activity_span = crate::activity::begin("server", "nginx.collect", Some(id.clone()));
    let _activity_result = (async {
        let _guard = state.collectors.acquire(&id, &state.store).await?;
        let snapshot = state.store.snapshot()?;
        let server = snapshot
            .servers
            .into_iter()
            .find(|s| s.id == id)
            .ok_or("The server is remote")?;
        let checkpoint = state.store.nginx_state(&id)?;
        let policy = crate::monitoring::effective_values(&state.store, "nginx", &id, "")?;
        let result = async {
            ssh::deploy(&server.endpoint, &state.collector).await?;
            let bytes = ssh::service_sample(
                &server.endpoint,
                "nginx",
                crate::instances::DEFAULT,
                Value::Null,
                json!({"state":checkpoint.cursor,"salt":checkpoint.salt}),
                thresholds::collector_values("nginx", &policy.thresholds),
            )
            .await?;
            state
                .store
                .record_nginx(&server, &checkpoint, &bytes, now())
        }
        .await;
        if result.is_err() {
            state.store.nginx_error(&id, &checkpoint)?;
        }
        result
    })
    .await;
    _activity_span.result(&_activity_result);
    _activity_result
}

fn check_input(field: &str, sample: &Value) -> crate::services::CheckSample {
    let value = match field {
        "nginx_rps" => sample["rps"].as_f64(),
        "nginx_requests" => sample["counts"]["requests"].as_f64().or(Some(0.0)),
        "nginx_5xx" => sample["counts"]["5xx"].as_f64().or(Some(0.0)),
        "nginx_upstream_timeout" => sample["counts"]["upstream_timeout"].as_f64().or(Some(0.0)),
        "nginx_upstream_connect" => sample["counts"]["upstream_connect"].as_f64().or(Some(0.0)),
        "nginx_request_mean_ms" | "nginx_upstream_mean_ms" => {
            let t = &sample[if field == "nginx_request_mean_ms" {
                "requestTime"
            } else {
                "upstreamTime"
            }];
            t["samples"]
                .as_f64()
                .filter(|s| *s > 0.0)
                .and_then(|n| t["sumMs"].as_f64().map(|v| v / n))
        }
        _ => None,
    };
    (
        value,
        sample["receivedAt"].as_i64(),
        sample["coverage"]["complete"] == true && sample["detected"] == true,
    )
}

pub(crate) fn worker_capability(activation: &crate::ai_actions::Activation) -> String {
    use crate::ai_actions::Activation;
    let activation = match activation {
        Activation::None => "none",
        Activation::Reload => "reload",
        Activation::Restart => "restart",
    };
    format!("nginx_workers:{activation}")
}

pub(crate) fn validate_workers(value: &str) -> Result<()> {
    if value != "auto"
        && (value
            .parse::<u16>()
            .ok()
            .is_none_or(|number| !(1..=128).contains(&number))
            || value.starts_with('0'))
    {
        return Err("Set Nginx worker_processes to auto or a whole number from 1 to 128.".into());
    }
    Ok(())
}

pub(crate) const BACKEND: crate::services::ServiceBackend = crate::services::ServiceBackend {
    view: |store, id, _| {
        let view = store.nginx_view(id)?;
        let mut value = serde_json::to_value(&view).map_err(err)?;
        value["status"] = json!(view.card.status);
        value["detected"] = json!(view.card.detected);
        Ok(value)
    },
    configure: None,
    refresh: |state, id, _| {
        Box::pin(async move { serde_json::to_value(collect(state, id).await?).map_err(err) })
    },
    init: |id, _, _| serde_json::to_string(&Checkpoint::new(id)).map_err(err),
    cards: |db, names| {
        Store::nginx_cards(db, 0).map(|cards| {
            cards
                .into_iter()
                .map(|(id, card)| {
                    let kind = "nginx";
                    let instance = crate::instances::DEFAULT;
                    let name = names.name(&id, kind, instance);
                    (
                        id,
                        crate::services::Card {
                            availability: None,
                            instance_id: instance.into(),
                            kind: kind.into(),
                            name,
                            detected: card.detected,
                            status: card.status,
                            at: card.at,
                            metric: card
                                .rps
                                .map(|value| crate::services::CardMetric { value, unit: "rps" }),
                        },
                    )
                })
                .collect()
        })
    },
    incident_title: |_, _| None,
    invalidate: Some(|db, id| {
        db.execute("UPDATE service_state SET payload=json_set(payload,'$.card.status','unknown','$.card.at',NULL,'$.card.rps',NULL) WHERE server_id=?1 AND kind='nginx'", [id]).map_err(err)?;
        Ok(())
    }),
    configure_smoke: None,
    check_input: Some(check_input),
    mutation: Some(crate::services::ServiceMutation {
        schema: || {
            json!({
                "type":"object", "additionalProperties":false,
                "description":"Changes only Nginx worker_processes (auto or 1..128), with backup, validation and optional reload/restart. Python result must equal {workerProcesses: requested value}.",
                "properties":{"kind":{"const":"nginx_workers"},"workerProcesses":{"type":"string"},"activation":{"enum":["none","reload","restart"]}},
                "required":["kind","workerProcesses","activation"],
            })
        },
        prepare_issue: |issue| match issue {
            "nginx_root_required" => {
                Some("Changing Nginx requires connecting over SSH as root.")
            }
            "systemd_restart_unavailable" => {
                Some("Restarting nginx.service requires an accessible systemd")
            }
            _ => None,
        },
        session_capabilities: &[
            "nginx_workers:none",
            "nginx_workers:reload",
            "nginx_workers:restart",
        ],
    }),
    source: include_str!("nginx.rs"),
};

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Store, Server) {
        let db = Store::open(std::path::Path::new(":memory:")).unwrap();
        let source = Source {
            id: "s".into(),
            name: "s".into(),

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
        (db, server)
    }
    fn wire(failures: u64) -> Vec<u8> {
        let timing = json!({"samples":0,"sumMs":0,"maxMs":0,"slow":0,"histogram":[0,0,0,0,0,0,0,0,0,0,0,0,0,0]});
        serde_json::to_vec(&json!({"version":1,"at":100,"detected":true,"service":"active","windowSeconds":600,"coverage":{"complete":true,"initial":false,"sources":["access","error"],"gaps":[]},"accessComplete":true,"errorComplete":true,"missing":["stub_status","request_time","upstream_response_time"],"rps":0.16667,"rpsSource":"access_log","status":null,"counts":{"requests":100,"5xx":failures,"4xx":100-failures},"statuses":{"503":failures,"404":100-failures},"requestTime":timing,"upstreamTime":timing,"examples":[],"bytesRead":10000,"durationMs":10,"nextState":{"at":100,"files":{}}})).unwrap()
    }
    fn record(db: &Store, s: &Server, n: u64, at: i64) -> Summary {
        let c = db.nginx_state(&s.id).unwrap();
        db.record_nginx(s, &c, &wire(n), at).unwrap()
    }
    #[test]
    fn manually_closed_nginx_episode_needs_healthy_windows_before_reopening() {
        let (db, s) = fixture();
        let at = now();
        record(&db, &s, 20, at);
        record(&db, &s, 20, at + 600);
        let i = db.snapshot().unwrap().incidents.remove(0);
        db.resolve_incident(&i.id, &i.episode, at + 601).unwrap();
        record(&db, &s, 20, at + 1200);
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "resolved");
        record(&db, &s, 0, at + 1800);
        record(&db, &s, 0, at + 2400);
        assert!(!db.snapshot().unwrap().incidents[0].manual_resolution_pending);
        record(&db, &s, 20, at + 3000);
        record(&db, &s, 20, at + 3600);
        assert_ne!(db.snapshot().unwrap().incidents[0].episode, i.episode);
    }
    #[test]
    fn noise_no_auto_and_persistent_errors_one_episode() {
        let (db, s) = fixture();
        db.save_settings(&Settings {
            mode: "auto".into(),
            daily_run_limit: Some(5),
            daily_token_limit: Some(100000),
            ..Default::default()
        })
        .unwrap();
        let at = now();
        record(&db, &s, 0, at);
        db.reconcile_auto(at).unwrap();
        assert_eq!(db.auto_status(at).unwrap().queued, 0);
        assert!(record(&db, &s, 20, at + 1).findings.is_empty());
        record(&db, &s, 20, at + 2);
        let episode = db.snapshot().unwrap().incidents[0].episode.clone();
        for t in 3..12 {
            record(&db, &s, 20, at + t);
            db.reconcile_auto(at + t).unwrap();
        }
        assert_eq!(db.auto_status(at + 12).unwrap().queued, 1);
        assert_eq!(db.snapshot().unwrap().incidents[0].episode, episode);
        let count: i64 =
            db.0.lock()
                .unwrap()
                .query_row("SELECT count(*) FROM service_evidence", [], |r| r.get(0))
                .unwrap();
        assert_eq!(count, 5);
        assert_eq!(db.nginx_view(&s.id).unwrap().evidence.len(), 5);
        assert_eq!(
            db.snapshot().unwrap().services[&s.id]
                .iter()
                .find(|card| card.kind == "nginx")
                .unwrap()
                .status,
            "warning"
        );
        assert_eq!(
            db.nginx_view(&s.id)
                .unwrap()
                .summary
                .unwrap()
                .data
                .next_state,
            json!({})
        );
    }
    #[test]
    fn partial_window_neither_recovers_nor_keeps_auto_evidence_fresh() {
        let (db, s) = fixture();
        let at = now();
        let mut partial: Value = serde_json::from_slice(&wire(0)).unwrap();
        partial["coverage"]["complete"] = json!(false);
        partial["accessComplete"] = json!(false);
        partial["rps"] = Value::Null;
        let bytes = serde_json::to_vec(&partial).unwrap();
        let state = db.nginx_state(&s.id).unwrap();
        db.record_nginx(&s, &state, &bytes, at - 1).unwrap();
        assert_eq!(db.nginx_view(&s.id).unwrap().card.status, "healthy");
        record(&db, &s, 20, at);
        record(&db, &s, 20, at + 1);
        record(&db, &s, 0, at + 2);
        let state = db.nginx_state(&s.id).unwrap();
        db.record_nginx(&s, &state, &bytes, at + 3).unwrap();
        let i = &db.snapshot().unwrap().incidents[0];
        assert_eq!(i.status, "open");
        assert_eq!(i.healthy_streak, 0);
        assert_eq!(i.fresh_until, Some(at + 2));
        record(&db, &s, 0, at + 4);
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "open");
        record(&db, &s, 0, at + 5);
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "resolved");
    }
    #[test]
    fn latency_and_upstream_need_two_complete_windows() {
        let mut w: Wire = serde_json::from_slice(&wire(0)).unwrap();
        w.request_time = Timing {
            samples: 50,
            sum_ms: 100000.0,
            max_ms: 2000.0,
            slow: 50,
            histogram: vec![0, 0, 0, 0, 0, 0, 0, 0, 50, 0, 0, 0, 0, 0],
        };
        w.counts.insert("upstream_timeout".into(), 10);
        let mut s = Checkpoint::new("s");
        let thresholds = crate::monitoring::Book::default().resolve(&crate::monitoring::scope("nginx", None, None)).unwrap().values.thresholds;
        assert!(evaluate(&w, &mut s, &thresholds).is_empty());
        let f = evaluate(&w, &mut s, &thresholds);
        assert_eq!(f.len(), 2);
        assert!(f.iter().any(|f| f.check == "nginx:latency"));
        w.access_complete = false;
        w.error_complete = false;
        assert!(evaluate(&w, &mut s, &thresholds).is_empty());
        w.access_complete = true;
        w.error_complete = true;
        assert!(evaluate(&w, &mut s, &thresholds).is_empty());
        w.service = "failed".into();
        assert!(evaluate(&w, &mut s, &thresholds)
            .iter()
            .any(|f| f.check == "nginx:service_failed"));
    }
    #[test]
    fn http_error_alert_uses_both_configured_boundaries() {
        let (db, server) = fixture();
        let scope = crate::monitoring::scope("nginx", Some(&server.id), None);
        let policy = db.monitoring_policy(&scope).unwrap();
        db.set_monitoring(&scope, crate::monitoring::Overrides {
            thresholds: [("http_5xx".into(), [("warning".into(), 7.), ("share".into(), 9.)].into())].into(),
            ..policy.overrides
        }, policy.revision).unwrap();
        let at = now();
        for (offset, count) in [(0, 8), (60, 8), (120, 9)] {
            assert!(record(&db, &server, count, at + offset).findings.is_empty());
        }
        assert_eq!(record(&db, &server, 9, at + 180).findings[0].check, "nginx:http_5xx");
    }
    #[test]
    fn duplicate_response_endpoint_change_and_rollback_do_not_advance() {
        let (db, s) = fixture();
        let state = db.nginx_state(&s.id).unwrap();
        db.record_nginx(&s, &state, &wire(0), now()).unwrap();
        assert!(db.record_nginx(&s, &state, &wire(20), now()).is_err());
        let state = db.nginx_state(&s.id).unwrap();
        db.0.lock().unwrap().execute_batch("CREATE TRIGGER reject_nginx BEFORE INSERT ON service_summaries BEGIN SELECT RAISE(ABORT,'disk unavailable'); END;").unwrap();
        assert!(db.record_nginx(&s, &state, &wire(20), now()).is_err());
        assert_eq!(db.nginx_state(&s.id).unwrap().revision, 1);
        db.0.lock()
            .unwrap()
            .execute_batch("DROP TRIGGER reject_nginx;")
            .unwrap();
        let src = db.snapshot().unwrap().sources.remove(0);
        let mut hosts = crate::inventory::parse_manual(&src.location).unwrap();
        hosts[0].endpoint.port = 2222;
        db.import(&src, hosts).unwrap();
        let fresh = db.nginx_state(&s.id).unwrap();
        assert_eq!(fresh.revision, 0);
        assert_ne!(fresh.salt, state.salt);
        assert!(db.record_nginx(&s, &state, &wire(20), now()).is_err());
        db.delete_source(&src.id).unwrap();
        assert!(db.record_nginx(&s, &fresh, &wire(20), now()).is_err());
    }
    #[test]
    fn rejects_raw_messages_unbounded_output_and_unknown_schema() {
        let (db, s) = fixture();
        let state = db.nginx_state(&s.id).unwrap();
        let mut w: Value = serde_json::from_slice(&wire(0)).unwrap();
        w["examples"] = json!([{"at":100,"category":"upstream_timeout","message":"secret"}]);
        assert!(db
            .record_nginx(&s, &state, &serde_json::to_vec(&w).unwrap(), now())
            .is_err());
        assert!(db
            .record_nginx(&s, &state, &vec![b' '; 32769], now())
            .is_err());
        assert_eq!(db.nginx_state(&s.id).unwrap().revision, 0);
    }
    #[test]
    fn migration_and_restart_preserve_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        {
            let old = rusqlite::Connection::open(&path).unwrap();
            old.execute_batch("PRAGMA user_version=4;").unwrap();
        }
        let db = Store::open(&path).unwrap();
        let src = Source {
            id: "s".into(),
            name: "s".into(),

            kind: "manual".into(),
            location: "ops@host".into(),
            last_sync: None,
            error: None,
        };
        db.import(&src, crate::inventory::parse_manual(&src.location).unwrap())
            .unwrap();
        let s = db.snapshot().unwrap().servers.remove(0);
        record(&db, &s, 20, now());
        drop(db);
        let restored = Store::open(&path).unwrap();
        assert_eq!(restored.nginx_state(&s.id).unwrap().revision, 1);
        assert_eq!(record(&restored, &s, 20, now()).findings.len(), 1);
        assert_eq!(
            restored
                .0
                .lock()
                .unwrap()
                .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            18
        );
    }
    #[tokio::test]
    async fn mcp_is_cache_only_and_manual_collection_shares_gate() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::create_state(dir.path().to_owned()).unwrap();
        let src = Source {
            id: "s".into(),
            name: "s".into(),

            kind: "manual".into(),
            location: "ops@127.0.0.1:1".into(),
            last_sync: None,
            error: None,
        };
        state
            .store
            .import(&src, crate::inventory::parse_manual(&src.location).unwrap())
            .unwrap();
        let id = state.store.snapshot().unwrap().servers[0].id.clone();
        let m = crate::mcp::McpServer::start(state.clone(), std::slice::from_ref(&id))
            .await
            .unwrap();
        let value = crate::mcp::call(
            &m.scope,
            "get_service_summary",
            json!({"serverId":id,"kind":"nginx"}),
        )
        .await
        .unwrap();
        assert!(value["summary"].is_null());
        assert_eq!(m.scope.remote.load(std::sync::atomic::Ordering::SeqCst), 0);
        let _busy = state.collectors.try_background(&id, 1).unwrap().unwrap();
        assert!(
            crate::monitoring::trigger("schedule", collect(state.clone(), id))
                .await
                .err()
                .unwrap()
                .contains("busy")
        );
    }
}
