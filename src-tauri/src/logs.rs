use crate::monitoring::thresholds::{self, Thresholds};
use crate::{inventory::stable_id, model::*, ssh, store::Store, AppState};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{cmp::Reverse, collections::BTreeMap, sync::Arc};
type Result<T> = std::result::Result<T, String>;
const MIN_HEALTH_INTERVAL_SECONDS: u64 = 60;
const MAX_LOG_EXCERPT: usize = 240;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
const RULES: &[(&str, &str, &str)] = &[
    ("oom", "Out-of-memory events in system logs", "critical"),
    ("disk_io", "Disk or file system errors", "critical"),
    ("service_crash", "Process or service failure", "warning"),
    ("protection_failure", "Fail2ban Error", "warning"),
    (
        "ssh_suspicious_success",
        "Suspicious SSH login after failed attempts",
        "warning",
    ),
    (
        "system_error_spike",
        "Persistent surge in system errors",
        "warning",
    ),
    (
        "new_error_pattern",
        "A new recurring error pattern",
        "warning",
    ),
];
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogCoverage {
    pub complete: bool,
    pub sources: Vec<String>,
    pub gaps: Vec<LogGap>,
    pub initial: bool,
}
impl LogCoverage {
    /// Older collectors encoded an analysis limit as a gap in the log stream.
    fn take_legacy_ssh_limit(&mut self) -> bool {
        let count = self.gaps.len();
        self.gaps.retain(|gap| gap.reason != "correlation_limit");
        let limited = count != self.gaps.len();
        if limited && self.gaps.is_empty() {
            self.complete = true;
        }
        limited
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogGap {
    pub reason: String,
    pub source: String,
    pub from_time: Option<i64>,
    pub to_time: Option<i64>,
    pub from_offset: Option<u64>,
    pub to_offset: Option<u64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogExample {
    pub at: i64,
    pub category: String,
    pub template: String,
    pub peer: Option<String>,
    pub account: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogExcerpt {
    at: i64,
    source: String,
    text: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireSummary {
    version: u32,
    at: i64,
    window_seconds: u64,
    coverage: LogCoverage,
    #[serde(default)]
    ssh_correlation_limited: bool,
    counts: BTreeMap<String, u64>,
    patterns: BTreeMap<String, u64>,
    examples: Vec<LogExample>,
    #[serde(default)]
    excerpts: BTreeMap<String, LogExcerpt>,
    bytes_read: u64,
    duration_ms: u64,
    next_state: Value,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogFinding {
    pub check: String,
    pub count: u64,
    pub severity: String,
    pub title: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogSummary {
    pub id: String,
    pub at: i64,
    pub remote_at: i64,
    pub window_seconds: u64,
    pub coverage: LogCoverage,
    #[serde(default)]
    pub ssh_correlation_limited: bool,
    pub counts: BTreeMap<String, u64>,
    pub patterns: BTreeMap<String, u64>,
    pub examples: Vec<LogExample>,
    pub bytes_read: u64,
    pub bytes_received: usize,
    pub duration_ms: u64,
    pub findings: Vec<LogFinding>,
    pub learning: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredLogSummary {
    #[serde(flatten)]
    summary: LogSummary,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    finding_examples: BTreeMap<String, LogExcerpt>,
}
impl StoredLogSummary {
    fn from_saved(raw: &str) -> Result<Self> {
        let mut stored: Self = serde_json::from_str(raw).map_err(err)?;
        let summary = &mut stored.summary;
        summary.ssh_correlation_limited |= summary.coverage.take_legacy_ssh_limit();
        Ok(stored)
    }
}
#[derive(Clone, Serialize, Deserialize, Default)]
struct Pattern {
    seen: i64,
    candidate: bool,
    streak: u32,
    #[serde(default)]
    alerted: bool,
}
#[derive(Clone, Serialize, Deserialize, Default)]
struct Baseline {
    since: Option<i64>,
    windows: u64,
    rates: Vec<f64>,
    patterns: BTreeMap<String, Pattern>,
    spike: u32,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogState {
    #[serde(default)]
    pub coverage_complete: Option<bool>,
    #[serde(default)]
    readable: Option<bool>,
    #[serde(default)]
    pub severity: Option<String>,
    pub revision: u64,
    pub next_check: i64,
    pub last_success: Option<i64>,
    pub error: Option<String>,
    pub failures: u32,
    salt: String,
    cursor: Value,
    baseline: Baseline,
}
impl LogState {
    pub(crate) fn request(&self, policy: &crate::monitoring::Values) -> Value {
        json!({
            "kind": "logs", "state": self.cursor, "salt": self.salt,
            "interval": policy.interval_seconds,
            "thresholds": thresholds::collector_values("logs", &policy.thresholds)
        })
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogView {
    pub monitoring: crate::monitoring::Values,
    pub summary: Option<LogSummary>,
    pub severity: Option<String>,
    pub short_check: bool,
    pub last_incomplete: Option<LogCoveragePeriod>,
    pub last_success: Option<i64>,
    pub next_check: i64,
    pub error: Option<String>,
    pub fresh: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopLogView {
    #[serde(flatten)]
    view: LogView,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    finding_examples: BTreeMap<String, LogExcerpt>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogCoveragePeriod {
    remote_at: i64,
    window_seconds: u64,
    gaps: Vec<LogGap>,
}
impl LogState {
    fn new(server: &str) -> Self {
        Self {
            coverage_complete: None,
            readable: None,
            severity: None,
            revision: 0,
            next_check: now()
                + i64::from(
                    server
                        .bytes()
                        .fold(0u16, |a, b| a.wrapping_mul(31).wrapping_add(u16::from(b)))
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
            baseline: Baseline::default(),
        }
    }
}
fn valid_hash(s: &str) -> bool {
    s.len() == 24
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn validate(w: &WireSummary) -> Result<()> {
    let sources = ["all", "journal", "auth", "syslog", "kern", "fail2ban"];
    let reasons = [
        "backlog_skipped",
        "clock_changed",
        "unknown_timestamp",
        "dedupe_limit",
        "correlation_limit",
        "pattern_limit",
        "rotation_tail_lost",
        "source_unavailable",
        "file_rewritten",
        "file_truncated",
        "long_line",
        "incomplete_line",
        "invalid_encoding",
        "read_limit",
        "journal_error",
        "journal_reboot",
        "journal_message_unavailable",
        "journal_format",
        "journal_cursor_lost",
        "source_changed",
        "output_limit",
    ];
    let counts = [
        "oom",
        "disk_io",
        "service_crash",
        "protection_failure",
        "ssh_suspicious_success",
        "system_error",
        "ssh_failed",
        "ssh_accepted",
        "ssh_noise",
        "ssh_blocked",
        "ssh_banned",
        "ssh_failures_mitigated",
    ];
    let templates = [
        "Memory exhaustion",
        "Storage or filesystem error",
        "Process or service failure",
        "SSH protection failure",
        "Successful SSH login after repeated failures",
    ];
    let protection_templates = [
        "Fail2ban log source missing",
        "Fail2ban startup failed",
        "Fail2ban blocking action failed",
    ];
    if w.version != 1
        || w.window_seconds > 3600
        || w.bytes_read > 2 * 1024 * 1024
        || w.duration_ms > 16000
        || w.coverage.sources.len() > 4
        || w.coverage.gaps.len() > 16
        || w.coverage.complete && !w.coverage.gaps.is_empty()
        || w.coverage
            .sources
            .iter()
            .any(|s| !sources.contains(&s.as_str()) || s == "all")
        || w.coverage
            .gaps
            .iter()
            .any(|g| !sources.contains(&g.source.as_str()) || !reasons.contains(&g.reason.as_str()))
        || w.counts
            .iter()
            .any(|(k, v)| !counts.contains(&k.as_str()) || *v > 2_097_152)
        || w.patterns.len() > 64
        || w.patterns
            .iter()
            .any(|(k, v)| !valid_hash(k) || *v > 2_097_152)
        || w.excerpts.iter().any(|(key, excerpt)| {
            !(w.patterns.contains_key(key)
                || RULES[..5]
                    .iter()
                    .any(|(category, _, _)| *category == key.as_str())
                    && w.counts.get(key).is_some_and(|n| *n > 0))
                || !sources[1..].contains(&excerpt.source.as_str())
                || excerpt.text.trim().is_empty()
                || excerpt.text.chars().count() > MAX_LOG_EXCERPT
                || excerpt.text.chars().any(char::is_control)
        })
        || w.examples.len() > 10
        || w.examples.iter().any(|e| {
            !RULES[..5].iter().any(|(k, _, _)| *k == e.category)
                || !(templates.contains(&e.template.as_str())
                    || e.category == "protection_failure"
                        && protection_templates.contains(&e.template.as_str()))
                || e.peer.as_ref().is_some_and(|s| !valid_hash(s))
                || e.account.as_ref().is_some_and(|s| !valid_hash(s))
                || serde_json::to_vec(e).map_or(true, |b| b.len() > 384)
        })
        || serde_json::to_vec(&w.next_state).map_or(true, |b| b.len() > 12000)
        || !w.next_state.is_object()
    {
        return Err("Invalid or oversized log summary".into());
    }
    Ok(())
}
fn median(v: &[f64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    let mut v = v.to_vec();
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}
fn evaluate(
    w: &WireSummary,
    b: &mut Baseline,
    at: i64,
    thresholds: &Thresholds,
) -> (Vec<LogFinding>, bool, BTreeMap<String, LogExcerpt>) {
    b.patterns.retain(|_, v| v.seen >= at - 7 * 86400);
    let trained = b.windows >= 72 && b.since.is_some_and(|s| at - s >= 86400);
    let complete = w.coverage.complete
        && !w.coverage.initial
        && w.window_seconds >= MIN_HEALTH_INTERVAL_SECONDS;
    let immediate = RULES[..5]
        .iter()
        .any(|(k, _, _)| w.counts.get(*k).copied().unwrap_or(0) > 0);
    let rate = w.counts.get("system_error").copied().unwrap_or(0) as f64 * 600.0
        / w.window_seconds.max(1) as f64;
    let middle = median(&b.rates);
    let mad = median(
        &b.rates
            .iter()
            .map(|v| (v - middle).abs())
            .collect::<Vec<_>>(),
    );
    let spike_limits = &thresholds["system_error_spike"];
    let spike = trained
        && rate
            > spike_limits["rate"]
                .max(middle * spike_limits["medianMultiplier"])
                .max(middle + spike_limits["deviationMultiplier"] * mad.max(1.0));
    b.spike = if complete && spike {
        b.spike.saturating_add(1)
    } else {
        0
    };
    let mut novelty = 0;
    let mut novel_example = None;
    let pattern_minimum = thresholds["new_error_pattern"]["warning"] as u64;
    if complete {
        for (hash, n) in &w.patterns {
            // A known dangerous event must not teach new fingerprints as normal.
            if immediate && !b.patterns.contains_key(hash) {
                continue;
            }
            if !b.patterns.contains_key(hash) && b.patterns.len() >= 512 {
                if let Some(oldest) = b
                    .patterns
                    .iter()
                    .min_by_key(|(_, p)| p.seen)
                    .map(|(h, _)| h.clone())
                {
                    b.patterns.remove(&oldest);
                }
            }
            let p = b.patterns.entry(hash.clone()).or_insert(Pattern {
                seen: at,
                candidate: trained,
                streak: 0,
                alerted: false,
            });
            if p.candidate && *n >= pattern_minimum {
                p.streak = p.streak.saturating_add(1);
                if p.streak >= 2 {
                    p.alerted = true;
                    p.candidate = false;
                }
            } else if *n < pattern_minimum {
                p.streak = 0;
                p.alerted = false;
            }
            if p.alerted && *n >= pattern_minimum {
                novelty += *n;
                if let Some(excerpt) = w.excerpts.get(hash) {
                    if novel_example.is_none_or(|(count, _)| *n > count) {
                        novel_example = Some((*n, excerpt));
                    }
                }
            }
            p.seen = at;
        }
        for (hash, p) in &mut b.patterns {
            if !w.patterns.contains_key(hash) {
                p.streak = 0;
                p.alerted = false;
            }
        }
    } else {
        for p in b.patterns.values_mut() {
            p.streak = 0;
        }
    }
    // Do not teach a spike, a new suspicious pattern, or a known fault as normal.
    if complete && !immediate && !spike && novelty == 0 {
        b.since.get_or_insert(at);
        b.windows = b.windows.saturating_add(1);
        b.rates.push(rate);
        if b.rates.len() > 144 {
            b.rates.remove(0);
        }
    }
    let mut finding_examples = BTreeMap::new();
    let findings = RULES
        .iter()
        .filter_map(|(key, title, severity)| {
            let count = match *key {
                "system_error_spike" => {
                    if b.spike >= 2 {
                        w.counts.get("system_error").copied().unwrap_or(0)
                    } else {
                        0
                    }
                }
                "new_error_pattern" => novelty,
                _ => w
                    .counts
                    .get(*key)
                    .copied()
                    .filter(|n| *n as f64 >= thresholds::activation(&thresholds[*key]))
                    .unwrap_or(0),
            };
            if count == 0 {
                return None;
            }
            let check = format!("logs:{key}");
            let excerpt = match *key {
                "system_error_spike" => w
                    .patterns
                    .iter()
                    .max_by_key(|(hash, n)| (**n, Reverse(hash.as_str())))
                    .and_then(|(hash, _)| w.excerpts.get(hash)),
                "new_error_pattern" => novel_example.map(|(_, excerpt)| excerpt),
                _ => w.excerpts.get(*key),
            };
            if let Some(excerpt) = excerpt {
                finding_examples.insert(check.clone(), excerpt.clone());
            }
            Some(LogFinding {
                check,
                title: (*title).into(),
                severity: (*severity).into(),
                count,
            })
        })
        .collect();
    (findings, !trained, finding_examples)
}
impl Store {
    pub(crate) fn log_statuses(
        db: &rusqlite::Connection,
        _interval: u64,
    ) -> Result<BTreeMap<String, String>> {
        let book = crate::monitoring::Book::load(db)?;
        let mut stmt=db.prepare("SELECT server_id,json_extract(payload,'$.lastSuccess'),coalesce(json_extract(payload,'$.readable'),json_extract(payload,'$.coverageComplete')),json_extract(payload,'$.severity'),json_extract(payload,'$.error') FROM log_state").map_err(err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<i64>>(1)?,
                    r.get::<_, Option<bool>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            })
            .map_err(err)?;
        rows.map(|r| {
            let (id, at, readable, severity, error) = r.map_err(err)?;
            let policy = book
                .resolve(&crate::monitoring::scope("logs", Some(&id), None))?
                .values;
            let interval = policy.interval_seconds;
            let status = if !policy.enabled || error.is_some() || at.is_none() {
                "unknown"
            } else if at.is_some_and(|t| now() - t > (interval * 2 + 30) as i64) {
                "stale"
            } else if let Some(s) = severity.as_deref() {
                s
            } else if readable == Some(true) {
                "healthy"
            } else {
                "unknown"
            };
            Ok((id, status.to_owned()))
        })
        .collect()
    }
    fn read_log_state(db: &rusqlite::Connection, id: &str) -> Result<Option<LogState>> {
        let found: Option<String> = db
            .query_row(
                "SELECT payload FROM log_state WHERE server_id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        found
            .map(|raw| serde_json::from_str(&raw).map_err(err))
            .transpose()
    }
    pub(crate) fn log_state(&self, id: &str) -> Result<LogState> {
        let db = self.0.lock().map_err(err)?;
        if let Some(state) = Self::read_log_state(&db, id)? {
            return Ok(state);
        }
        let state = LogState::new(id);
        db.execute(
            "INSERT INTO log_state VALUES(?1,?2)",
            params![id, serde_json::to_string(&state).map_err(err)?],
        )
        .map_err(err)?;
        Ok(state)
    }
    pub(crate) fn log_view(&self, id: &str) -> Result<LogView> {
        Ok(self.desktop_log_view(id)?.view)
    }
    pub(crate) fn desktop_log_view(&self, id: &str) -> Result<DesktopLogView> {
        let db = self.0.lock().map_err(err)?;
        let state = Self::read_log_state(&db, id)?.unwrap_or_else(|| LogState::new(id));
        let v:Option<String>=db.query_row("SELECT payload FROM log_summaries WHERE server_id=?1 ORDER BY at DESC,rowid DESC LIMIT 1",[id],|r|r.get(0)).optional().map_err(err)?;
        let (summary, finding_examples) = v
            .as_deref()
            .map(StoredLogSummary::from_saved)
            .transpose()?
            .map(|stored| (Some(stored.summary), stored.finding_examples))
            .unwrap_or_default();
        let last_incomplete = if summary.as_ref().is_some_and(|s| s.coverage.complete) {
            let previous: Option<String> = db
                .query_row(
                    "SELECT payload FROM log_summaries WHERE server_id=?1 AND at>=?2
                     AND json_extract(payload,'$.coverage.complete')=0
                     AND (json_array_length(payload,'$.coverage.gaps')=0 OR EXISTS (
                         SELECT 1 FROM json_each(payload,'$.coverage.gaps')
                         WHERE json_extract(value,'$.reason') IS NOT 'correlation_limit'
                     ))
                     ORDER BY at DESC,rowid DESC LIMIT 1",
                    params![id, now() - 7 * 86400],
                    |r| r.get(0),
                )
                .optional()
                .map_err(err)?;
            previous
                .map(|raw| {
                    let s = StoredLogSummary::from_saved(&raw)?.summary;
                    Ok::<_, String>(LogCoveragePeriod {
                        remote_at: s.remote_at,
                        window_seconds: s.window_seconds,
                        gaps: s.coverage.gaps,
                    })
                })
                .transpose()?
        } else {
            None
        };
        let policy = crate::monitoring::effective(&db, "logs", id, "")?.values;
        let interval = policy.interval_seconds;
        Ok(DesktopLogView {
            view: LogView {
                short_check: summary
                    .as_ref()
                    .is_some_and(|s| s.window_seconds < MIN_HEALTH_INTERVAL_SECONDS),
                last_incomplete,
                fresh: policy.enabled
                    && state.error.is_none()
                    && state
                        .last_success
                        .is_some_and(|t| now() - t <= (interval * 2 + 30) as i64),
                summary,
                severity: state.severity,
                last_success: state.last_success,
                next_check: state.next_check,
                error: state.error,
                monitoring: policy,
            },
            finding_examples,
        })
    }
    pub(crate) fn record_logs(
        &self,
        server: &Server,
        expected: &LogState,
        bytes: &[u8],
        at: i64,
    ) -> Result<LogSummary> {
        if bytes.len() > 32768 {
            return Err("Log summary exceeds 32 KiB".into());
        }
        let mut wire: WireSummary = serde_json::from_slice(bytes)
            .map_err(|_| "Incompatible response from the log collector")?;
        validate(&wire)?;
        wire.ssh_correlation_limited |= wire.coverage.take_legacy_ssh_limit();
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
                "SELECT payload FROM log_state WHERE server_id=?1",
                [&server.id],
                |r| r.get(0),
            )
            .map_err(err)?;
        let mut state: LogState = serde_json::from_str(&stored).map_err(err)?;
        if state.revision != expected.revision || state.salt != expected.salt {
            return Err("The summary was already applied or the log position changed".into());
        }
        let policy = crate::monitoring::effective(&tx, "logs", &server.id, "")?.values;
        let interval = policy.interval_seconds;
        let (findings, learning, finding_examples) =
            evaluate(&wire, &mut state.baseline, at, &policy.thresholds);
        let summary = LogSummary {
            id: uuid::Uuid::new_v4().to_string(),
            at,
            remote_at: wire.at,
            window_seconds: wire.window_seconds,
            coverage: wire.coverage,
            ssh_correlation_limited: wire.ssh_correlation_limited,
            counts: wire.counts,
            patterns: wire.patterns,
            examples: wire.examples,
            bytes_read: wire.bytes_read,
            bytes_received: bytes.len(),
            duration_ms: wire.duration_ms,
            findings,
            learning,
        };
        let stored = StoredLogSummary {
            summary,
            finding_examples,
        };
        tx.execute(
            "INSERT INTO log_summaries VALUES(?1,?2,?3,?4)",
            params![
                stored.summary.id,
                server.id,
                at,
                serde_json::to_string(&stored).map_err(err)?
            ],
        )
        .map_err(err)?;
        let summary = stored.summary;
        let long_enough = summary.window_seconds >= MIN_HEALTH_INTERVAL_SECONDS;
        for (key, title, severity) in RULES {
            let coverage = &summary.coverage;
            let covered = if *key == "protection_failure" {
                // File fallback uses the Fail2ban log as the primary source for these events.
                coverage.complete
                    || !coverage.gaps.is_empty()
                        && coverage.sources.iter().any(|source| source == "fail2ban")
                        && coverage
                            .gaps
                            .iter()
                            .all(|gap| matches!(gap.source.as_str(), "auth" | "syslog" | "kern"))
            } else {
                coverage.complete
                    && (*key != "ssh_suspicious_success" || !summary.ssh_correlation_limited)
            };
            let check = format!("logs:{key}");
            let finding = summary.findings.iter().find(|f| f.check == check);
            if finding.is_none() {
                let old_status: Option<String> = tx
                    .query_row(
                        "SELECT CASE WHEN json_extract(payload,'$.manualResolutionPending')=1 THEN 'open' ELSE json_extract(payload,'$.status') END FROM incidents WHERE id=?1",
                        [stable_id(&server.id, &check)],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(err)?;
                if old_status.as_deref() == Some("resolved") {
                    continue;
                }
            }
            if finding.is_some() || covered && long_enough && !summary.coverage.initial {
                Self::incident(
                    &tx,
                    &server.id,
                    &check,
                    finding.map(|f| {
                        format!("{}: {} events; summary {}", f.title, f.count, summary.id)
                    }),
                    title,
                    severity,
                    at,
                )?;
                let iid = stable_id(&server.id, &check);
                let payload: Option<String> = tx
                    .query_row("SELECT payload FROM incidents WHERE id=?1", [&iid], |r| {
                        r.get(0)
                    })
                    .optional()
                    .map_err(err)?;
                if let Some(payload) = payload {
                    let mut incident: Incident = serde_json::from_str(&payload).map_err(err)?;
                    incident.fresh_until = Some(at + (interval * 2 + 30) as i64);
                    tx.execute(
                        "UPDATE incidents SET payload=?2 WHERE id=?1",
                        params![iid, serde_json::to_string(&incident).map_err(err)?],
                    )
                    .map_err(err)?;
                    if finding.is_some() {
                        tx.execute(
                            "INSERT OR IGNORE INTO log_evidence VALUES(?1,?2)",
                            params![iid, summary.id],
                        )
                        .map_err(err)?;
                    }
                    tx.execute("DELETE FROM log_evidence WHERE incident_id=?1 AND summary_id NOT IN (SELECT e.summary_id FROM log_evidence e JOIN log_summaries s ON s.id=e.summary_id WHERE e.incident_id=?1 ORDER BY s.at DESC,s.rowid DESC LIMIT 5)",[&iid]).map_err(err)?;
                }
            } else if !covered || summary.coverage.initial {
                // Missing coverage cannot advance or preserve a recovery streak.
                let iid = stable_id(&server.id, &check);
                tx.execute("UPDATE incidents SET payload=json_set(payload,'$.healthyStreak',0,'$.freshUntil',?2) WHERE id=?1",params![iid,at-1]).map_err(err)?;
            }
        }
        if long_enough || !summary.coverage.complete {
            state.coverage_complete = Some(summary.coverage.complete);
        }
        state.readable = Some(!summary.coverage.sources.is_empty());
        let active: Vec<Incident> = Self::list(&tx, "incidents")?;
        state.severity = if summary.findings.iter().any(|i| i.severity == "critical")
            || active.iter().any(|i| {
                i.server_id == server.id
                    && i.check.starts_with("logs:")
                    && i.status == "open"
                    && i.severity == "critical"
            }) {
            Some("critical".into())
        } else if !summary.findings.is_empty()
            || active.iter().any(|i| {
                i.server_id == server.id && i.check.starts_with("logs:") && i.status == "open"
            })
        {
            Some("warning".into())
        } else {
            None
        };
        state.revision += 1;
        state.cursor = wire.next_state;
        state.last_success = Some(at);
        state.error = None;
        state.failures = 0;
        state.next_check =
            at + interval as i64 + (server.id.bytes().map(u64::from).sum::<u64>() % 30) as i64;
        tx.execute(
            "UPDATE log_state SET payload=?2 WHERE server_id=?1",
            params![server.id, serde_json::to_string(&state).map_err(err)?],
        )
        .map_err(err)?;
        crate::storage::trim_server_logs(&tx, &server.id)?;
        tx.commit().map_err(err)?;
        Ok(summary)
    }
    pub(crate) fn log_error(&self, server: &Server, expected: &LogState) -> Result<()> {
        let mut db = self.0.lock().map_err(err)?;
        crate::storage::admit(&db)?;
        let tx = db.transaction().map_err(err)?;
        crate::monitoring::check_commit(&tx)?;
        let stored: Option<String> = tx
            .query_row(
                "SELECT payload FROM log_state WHERE server_id=?1",
                [&server.id],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        if let Some(v) = stored {
            let mut state: LogState = serde_json::from_str(&v).map_err(err)?;
            if state.revision == expected.revision && state.salt == expected.salt {
                state.failures = state.failures.saturating_add(1);
                state.error = Some(
                    "Log collection is incomplete. Cyberbot kept the saved position and will retry after a longer interval."
                        .into(),
                );
                state.next_check = now()
                    + (crate::monitoring::effective(&tx, "logs", &server.id, "")?
                        .values
                        .interval_seconds
                        .saturating_mul(2u64.saturating_pow(state.failures.min(5)))
                        .min(3600)) as i64;
                tx.execute(
                    "UPDATE log_state SET payload=?2 WHERE server_id=?1",
                    params![server.id, serde_json::to_string(&state).map_err(err)?],
                )
                .map_err(err)?;
                tx.execute("UPDATE incidents SET payload=json_set(payload,'$.freshUntil',?2,'$.healthyStreak',0) WHERE server_id=?1 AND json_extract(payload,'$.check') LIKE 'logs:%'",params![server.id,now()-1]).map_err(err)?;
            }
        }
        tx.commit().map_err(err)
    }
}
pub(crate) async fn collect(state: Arc<AppState>, id: String) -> Result<LogSummary> {
    crate::monitoring::run(
        &state.store,
        "logs",
        &id,
        "",
        collect_inner(state.clone(), id.clone()),
    )
    .await
}
async fn collect_inner(state: Arc<AppState>, id: String) -> Result<LogSummary> {
    let mut _activity_span = crate::activity::begin("server", "logs.collect", Some(id.clone()));
    let _activity_result=(async {
    let _guard = state.collectors.acquire(&id, &state.store).await?;
    let snapshot = state.store.snapshot()?;
    let server = snapshot
        .servers
        .into_iter()
        .find(|s| s.id == id)
        .ok_or("The server is remote")?;
    let policy = crate::monitoring::effective_values(&state.store, "logs", &id, "")?;
    let interval = policy.interval_seconds;
    let limits = thresholds::collector_values("logs", &policy.thresholds);
    let checkpoint = state.store.log_state(&id)?;
    let result=async{ssh::deploy(&server.endpoint,&state.collector).await?;
        let request=json!({"kind":"logs","state":checkpoint.cursor,"salt":checkpoint.salt,"interval":interval,"thresholds":limits});
        if request.to_string().len()>16384{return Err("Log state exceeds the request size limit".into());}
        let bytes=ssh::run_collector(&server.endpoint,&request,32768).await?;
        state.store.record_logs(&server,&checkpoint,&bytes,now())
    }.await;
    if result.is_err() {
        state.store.log_error(&server, &checkpoint)?;
    }
    result

    }).await;
    _activity_span.result(&_activity_result);
    _activity_result
}

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
    fn wire(counts: Value, complete: bool) -> Vec<u8> {
        serde_json::to_vec(&json!({"version":1,"at":100,"windowSeconds":600,"coverage":{"complete":complete,"sources":["auth","syslog"],"gaps":if complete{json!([])}else{json!([{"reason":"read_limit","source":"auth"}])},"initial":false},"counts":counts,"patterns":{},"examples":[],"bytesRead":1000,"durationMs":10,"nextState":{"at":100}})).unwrap()
    }
    #[test]
    fn manually_closed_log_finding_stays_closed_until_two_complete_windows() {
        let (db, s) = fixture();
        let at = now();
        let sample = |counts: Value, complete: bool, t: i64| {
            let cp = db.log_state(&s.id).unwrap();
            db.record_logs(&s, &cp, &wire(counts, complete), t).unwrap();
        };
        sample(json!({"oom":1}), true, at);
        let i = db.snapshot().unwrap().incidents.remove(0);
        db.resolve_incident(&i.id, &i.episode, at + 1).unwrap();
        sample(json!({"oom":2}), true, at + 600);
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "resolved");
        sample(json!({}), false, at + 1200);
        assert!(db.snapshot().unwrap().incidents[0].manual_resolution_pending);
        sample(json!({}), true, at + 1800);
        sample(json!({}), true, at + 2400);
        assert!(!db.snapshot().unwrap().incidents[0].manual_resolution_pending);
        sample(json!({"oom":1}), true, at + 3000);
        assert_ne!(db.snapshot().unwrap().incidents[0].episode, i.episode);
    }
    #[test]
    fn noise_is_not_incident_or_auto_job_and_commit_is_idempotent() {
        let (db, s) = fixture();
        db.save_settings(&Settings {
            mode: "auto".into(),
            daily_run_limit: Some(5),
            daily_token_limit: Some(100000),
            ..Settings::default()
        })
        .unwrap();
        let state = db.log_state(&s.id).unwrap();
        let bytes = wire(
            json!({"ssh_failed":100000,"ssh_banned":1000,"ssh_blocked":50000}),
            false,
        );
        db.record_logs(&s, &state, &bytes, now()).unwrap();
        assert!(db.record_logs(&s, &state, &bytes, now()).is_err());
        db.reconcile_auto(now()).unwrap();
        let snapshot = db.snapshot().unwrap();
        assert!(snapshot.incidents.is_empty());
        assert_eq!(snapshot.log_status[&s.id], "healthy");
        assert_eq!(db.auto_status(now()).unwrap().queued, 0);
        assert_eq!(db.log_state(&s.id).unwrap().revision, 1);
    }
    #[test]
    fn limited_ssh_matching_does_not_prevent_system_log_recovery() {
        let (db, server) = fixture();
        let at = now();
        let record = |bytes: &[u8], t| {
            let state = db.log_state(&server.id).unwrap();
            db.record_logs(&server, &state, bytes, t).unwrap()
        };
        record(&wire(json!({"oom":1,"ssh_suspicious_success":1}), true), at);
        let mut limited: Value = serde_json::from_slice(&wire(json!({}), true)).unwrap();
        limited["sshCorrelationLimited"] = json!(true);
        let limited = serde_json::to_vec(&limited).unwrap();
        record(&limited, at + 600);
        let summary = record(&limited, at + 1200);
        assert!(summary.coverage.complete && summary.ssh_correlation_limited);
        assert_eq!(db.log_state(&server.id).unwrap().baseline.windows, 2);
        let incidents = db.snapshot().unwrap().incidents;
        let status = |check| {
            incidents
                .iter()
                .find(|i| i.check == check)
                .unwrap()
                .status
                .as_str()
        };
        assert_eq!(status("logs:oom"), "resolved");
        assert_eq!(status("logs:ssh_suspicious_success"), "open");
    }
    #[test]
    fn saved_correlation_limit_is_not_displayed_as_a_previous_read_gap() {
        let (db, server) = fixture();
        let at = now();
        let state = db.log_state(&server.id).unwrap();
        let summary = db
            .record_logs(&server, &state, &wire(json!({}), true), at)
            .unwrap();
        let mut legacy = serde_json::to_value(&summary).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("sshCorrelationLimited");
        legacy["coverage"]["complete"] = json!(false);
        legacy["coverage"]["gaps"] = json!([{"reason":"correlation_limit","source":"auth"}]);
        db.0.lock()
            .unwrap()
            .execute(
                "UPDATE log_summaries SET payload=?1 WHERE id=?2",
                params![legacy.to_string(), summary.id],
            )
            .unwrap();
        let view = db.log_view(&server.id).unwrap().summary.unwrap();
        assert!(view.coverage.complete && view.ssh_correlation_limited);
        assert!(view.coverage.gaps.is_empty());
        let state = db.log_state(&server.id).unwrap();
        db.record_logs(&server, &state, &wire(json!({}), true), at + 600)
            .unwrap();
        assert!(db.log_view(&server.id).unwrap().last_incomplete.is_none());
    }
    #[test]
    fn short_refresh_preserves_previous_gaps_and_does_not_confirm_recovery() {
        let (db, s) = fixture();
        let at = now();
        let record = |bytes: &[u8], t: i64| {
            let cp = db.log_state(&s.id).unwrap();
            db.record_logs(&s, &cp, bytes, t).unwrap();
        };
        record(&wire(json!({"oom":1}), false), at);
        let mut brief: Value = serde_json::from_slice(&wire(json!({}), true)).unwrap();
        for (i, seconds) in [0, 12].into_iter().enumerate() {
            brief["windowSeconds"] = json!(seconds);
            record(&serde_json::to_vec(&brief).unwrap(), at + 1 + i as i64);
        }
        let view = db.log_view(&s.id).unwrap();
        assert!(view.short_check);
        let previous = view.last_incomplete.unwrap();
        assert_eq!(previous.window_seconds, 600);
        assert_eq!(previous.gaps[0].reason, "read_limit");
        assert_eq!(db.log_state(&s.id).unwrap().coverage_complete, Some(false));
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "open");
        record(&wire(json!({}), true), at + 600);
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "open");
        record(&wire(json!({}), true), at + 1200);
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "resolved");
        assert_eq!(db.log_state(&s.id).unwrap().coverage_complete, Some(true));
    }
    #[test]
    fn incident_coverage_recovery_freshness_and_evidence() {
        let (db, s) = fixture();
        let at = now();
        let a = db.log_state(&s.id).unwrap();
        db.record_logs(&s, &a, &wire(json!({"oom":1}), true), at)
            .unwrap();
        let i = db.snapshot().unwrap().incidents.remove(0);
        assert_eq!(i.fresh_until, Some(at + 390));
        assert_eq!(i.check, "logs:oom");
        let ep = i.episode;
        for complete in [true, false, true] {
            let a = db.log_state(&s.id).unwrap();
            db.record_logs(&s, &a, &wire(json!({}), complete), at + 1)
                .unwrap();
            assert_eq!(db.snapshot().unwrap().incidents[0].status, "open");
        }
        let a = db.log_state(&s.id).unwrap();
        db.record_logs(&s, &a, &wire(json!({}), true), at + 2)
            .unwrap();
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "resolved");
        assert_eq!(db.snapshot().unwrap().incidents[0].episode, ep);
        let n: i64 =
            db.0.lock()
                .unwrap()
                .query_row("SELECT count(*) FROM log_evidence", [], |r| r.get(0))
                .unwrap();
        assert_eq!(n, 1);
    }
    #[test]
    fn fail2ban_recovery_uses_its_own_log_coverage() {
        let (db, server) = fixture();
        let at = now();
        let record = |wire: &[u8], at| {
            let state = db.log_state(&server.id).unwrap();
            db.record_logs(&server, &state, wire, at).unwrap();
        };
        record(&wire(json!({"protection_failure":1,"oom":1}), true), at);
        let mut summary: Value = serde_json::from_slice(&wire(json!({}), false)).unwrap();
        summary["coverage"]["sources"] = json!(["fail2ban"]);
        let clean = serde_json::to_vec(&summary).unwrap();
        record(&clean, at + 600);
        summary["coverage"]["gaps"][0]["source"] = json!("fail2ban");
        record(&serde_json::to_vec(&summary).unwrap(), at + 1200);
        record(&clean, at + 1800);
        assert!(db
            .snapshot()
            .unwrap()
            .incidents
            .iter()
            .all(|i| i.status == "open"));
        record(&clean, at + 2400);
        for incident in db.snapshot().unwrap().incidents {
            assert_eq!(
                incident.status,
                if incident.check == "logs:protection_failure" {
                    "resolved"
                } else {
                    "open"
                }
            );
        }
    }
    #[test]
    fn rollback_bad_reply_changed_endpoint_and_deleted_server() {
        let (db, s) = fixture();
        let a = db.log_state(&s.id).unwrap();
        assert!(db.record_logs(&s, &a, b"invalid", now()).is_err());
        assert_eq!(db.log_state(&s.id).unwrap().revision, 0);
        let src = db.snapshot().unwrap().sources.remove(0);
        let mut hosts = crate::inventory::parse_manual(&src.location).unwrap();
        hosts[0].endpoint.port = 2222;
        db.import(&src, hosts).unwrap();
        db.log_state(&s.id).unwrap();
        assert!(db
            .record_logs(&s, &a, &wire(json!({"oom":1}), true), now())
            .is_err());
        db.delete_source(&src.id).unwrap();
        assert!(db
            .record_logs(&s, &a, &wire(json!({}), true), now())
            .is_err());
        assert!(db.snapshot().unwrap().incidents.is_empty());
    }
    #[test]
    fn transaction_failure_does_not_advance_cursor() {
        let (db, s) = fixture();
        let a = db.log_state(&s.id).unwrap();
        db.0.lock().unwrap().execute_batch("CREATE TRIGGER reject_log BEFORE INSERT ON log_summaries BEGIN SELECT RAISE(ABORT,'disk unavailable'); END;").unwrap();
        assert!(db
            .record_logs(&s, &a, &wire(json!({"oom":1}), true), now())
            .is_err());
        assert_eq!(db.log_state(&s.id).unwrap().revision, 0);
        assert!(db.snapshot().unwrap().incidents.is_empty());
    }
    #[test]
    fn baseline_warmup_and_two_window_anomalies() {
        let thresholds = crate::monitoring::Book::default()
            .resolve(&crate::monitoring::scope("logs", None, None))
            .unwrap()
            .values
            .thresholds;
        let mut b = Baseline::default();
        let normal: WireSummary =
            serde_json::from_slice(&wire(json!({"system_error":1}), true)).unwrap();
        for n in 0..145 {
            assert!(evaluate(&normal, &mut b, n * 600, &thresholds).0.is_empty());
        }
        let mut high: WireSummary =
            serde_json::from_slice(&wire(json!({"system_error":50}), true)).unwrap();
        high.patterns.insert("a".repeat(24), 10);
        assert!(evaluate(&high, &mut b, 87000, &thresholds).0.is_empty());
        let f = evaluate(&high, &mut b, 87600, &thresholds).0;
        assert!(f.iter().any(|f| f.check == "logs:system_error_spike"));
        assert!(f.iter().any(|f| f.check == "logs:new_error_pattern"));
        let trained = b.windows;
        high.coverage.complete = false;
        assert!(evaluate(&high, &mut b, 88200, &thresholds).0.is_empty());
        assert_eq!(b.windows, trained);
        assert!(evaluate(&high, &mut b, 88800, &thresholds).0.is_empty());
        let mut dangerous = normal.clone();
        dangerous.counts.insert("oom".into(), 1);
        dangerous.patterns.insert("c".repeat(24), 1);
        evaluate(&dangerous, &mut b, 89400, &thresholds);
        assert_eq!(b.windows, trained);
        assert!(!b.patterns.contains_key(&"c".repeat(24)));
    }
    #[test]
    fn new_pattern_example_excludes_known_patterns_and_prefers_the_largest_match() {
        let thresholds = crate::monitoring::Book::default()
            .resolve(&crate::monitoring::scope("logs", None, None))
            .unwrap()
            .values
            .thresholds;
        let mut baseline = Baseline {
            since: Some(0),
            windows: 72,
            ..Default::default()
        };
        let known = "a".repeat(24);
        let new = "b".repeat(24);
        let rarer = "c".repeat(24);
        baseline.patterns.insert(known.clone(), Pattern::default());
        let mut w: WireSummary =
            serde_json::from_slice(&wire(json!({"system_error":251}), true)).unwrap();
        for (key, count, text) in [
            (known, 220, "Known error"),
            (new, 25, "New worker error"),
            (rarer, 6, "New database error"),
        ] {
            w.patterns.insert(key.clone(), count);
            w.excerpts.insert(
                key,
                LogExcerpt {
                    at: w.at,
                    source: "journal".into(),
                    text: text.into(),
                },
            );
        }
        assert!(evaluate(&w, &mut baseline, 90000, &thresholds).0.is_empty());
        let (findings, _, examples) = evaluate(&w, &mut baseline, 90600, &thresholds);
        let check = "logs:new_error_pattern";
        assert_eq!(
            findings.iter().find(|f| f.check == check).unwrap().count,
            31
        );
        assert_eq!(examples[check].text, "New worker error");
        assert_eq!(examples["logs:system_error_spike"].text, "Known error");
    }
    #[test]
    fn known_error_does_not_become_new_again_after_recovery() {
        let thresholds = crate::monitoring::Book::default()
            .resolve(&crate::monitoring::scope("logs", None, None))
            .unwrap()
            .values
            .thresholds;
        let mut b = Baseline {
            since: Some(0),
            windows: 72,
            ..Default::default()
        };
        let quiet: WireSummary = serde_json::from_slice(&wire(json!({}), true)).unwrap();
        let mut error = quiet.clone();
        error.patterns.insert("b".repeat(24), 5);
        assert!(evaluate(&error, &mut b, 90000, &thresholds).0.is_empty());
        assert_eq!(evaluate(&error, &mut b, 90600, &thresholds).0.len(), 1);
        assert_eq!(evaluate(&error, &mut b, 91200, &thresholds).0.len(), 1);
        evaluate(&quiet, &mut b, 91800, &thresholds);
        evaluate(&quiet, &mut b, 92400, &thresholds);
        assert!(evaluate(&error, &mut b, 93000, &thresholds).0.is_empty());
        assert!(evaluate(&error, &mut b, 93600, &thresholds).0.is_empty());
        for n in 0..520 {
            error.patterns.clear();
            error.patterns.insert(format!("{n:024x}"), 1);
            evaluate(&error, &mut b, 94200 + n, &thresholds);
        }
        assert_eq!(b.patterns.len(), 512);
        assert!(b.patterns.contains_key(&format!("{:024x}", 519)));
    }
    #[test]
    fn configured_counts_and_anomaly_limits_gate_findings() {
        let mut thresholds = crate::monitoring::Book::default()
            .resolve(&crate::monitoring::scope("logs", None, None))
            .unwrap()
            .values
            .thresholds;
        thresholds
            .get_mut("oom")
            .unwrap()
            .insert("critical".into(), 2.);
        thresholds
            .get_mut("system_error_spike")
            .unwrap()
            .insert("rate".into(), 100.);
        let mut baseline = Baseline {
            since: Some(0),
            windows: 72,
            rates: vec![1.; 72],
            ..Default::default()
        };
        let sample = |oom, errors| {
            serde_json::from_slice(&wire(json!({"oom":oom,"system_error":errors}), true)).unwrap()
        };
        assert!(evaluate(&sample(1, 99), &mut baseline, 90000, &thresholds)
            .0
            .is_empty());
        assert!(evaluate(&sample(1, 100), &mut baseline, 90600, &thresholds)
            .0
            .is_empty());
        let findings = evaluate(&sample(2, 101), &mut baseline, 91200, &thresholds).0;
        assert_eq!(
            findings
                .iter()
                .map(|f| f.check.as_str())
                .collect::<Vec<_>>(),
            ["logs:oom"]
        );
        let findings = evaluate(&sample(0, 101), &mut baseline, 91800, &thresholds).0;
        assert_eq!(
            findings
                .iter()
                .map(|f| f.check.as_str())
                .collect::<Vec<_>>(),
            ["logs:system_error_spike"]
        );
    }
    #[test]
    fn unknown_messages_cannot_leak_through_examples() {
        let mut w: WireSummary = serde_json::from_slice(&wire(json!({}), true)).unwrap();
        w.examples.push(LogExample {
            at: 1,
            category: "oom".into(),
            template: "secret=password".into(),
            peer: None,
            account: None,
        });
        assert!(validate(&w).is_err());
        w.examples[0].template = "Fail2ban log source missing".into();
        assert!(validate(&w).is_err());
        w.examples[0].category = "protection_failure".into();
        assert!(validate(&w).is_ok());
    }
    #[test]
    fn durable_checkpoint_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_owned();
        let state = crate::create_state(root.clone()).unwrap();
        let src = Source {
            id: "s".into(),
            name: "s".into(),

            kind: "manual".into(),
            location: "ops@host".into(),
            last_sync: None,
            error: None,
        };
        state
            .store
            .import(&src, crate::inventory::parse_manual(&src.location).unwrap())
            .unwrap();
        let s = state.store.snapshot().unwrap().servers.remove(0);
        let a = state.store.log_state(&s.id).unwrap();
        state
            .store
            .record_logs(&s, &a, &wire(json!({}), true), now())
            .unwrap();
        drop(state);
        let restored = crate::create_state(root).unwrap();
        let b = restored.store.log_state(&s.id).unwrap();
        assert_eq!(b.revision, 1);
        assert_eq!(b.salt, a.salt);
        assert_eq!(b.cursor["at"], 100);
    }
    #[tokio::test]
    async fn mcp_reads_saved_logs_without_remote_calls() {
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
            "get_log_summary",
            json!({"serverId":id,"kind":"logs"}),
        )
        .await
        .unwrap();
        assert!(value["summary"].is_null());

        let server = state.store.snapshot().unwrap().servers.remove(0);
        let checkpoint = state.store.log_state(&id).unwrap();
        let mut sample: Value = serde_json::from_slice(&wire(json!({"oom":1}), true)).unwrap();
        sample["excerpts"] = json!({"oom":{
            "at":100, "source":"syslog", "text":"Out of memory: fixture process 42"
        }});
        let summary = state
            .store
            .record_logs(
                &server,
                &checkpoint,
                &serde_json::to_vec(&sample).unwrap(),
                now(),
            )
            .unwrap();
        let desktop = serde_json::to_value(state.store.desktop_log_view(&id).unwrap()).unwrap();
        assert_eq!(
            desktop["findingExamples"]["logs:oom"],
            sample["excerpts"]["oom"]
        );
        let value = crate::mcp::call(
            &m.scope,
            "get_log_summary",
            json!({"serverId":id,"kind":"logs"}),
        )
        .await
        .unwrap();
        assert_eq!(value["summary"], serde_json::to_value(summary).unwrap());
        assert!(!value.to_string().contains("fixture process"));
        assert!(value.get("findingExamples").is_none());
        assert_eq!(m.scope.remote.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
