//! Shared connector lifecycle. Plugins provide only fixed collection and metric contracts.
use crate::instances::{self, DEFAULT};
use crate::monitoring::thresholds::{self, Thresholds};
use crate::{inventory::stable_id, model::*, ssh, store::Store, AppState};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, LazyLock},
};
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Spec {
    #[serde(default)]
    pub multiple: bool,
    #[serde(default)]
    pub reports_availability: bool,
    #[serde(default)]
    pub replication: bool,
    #[serde(default)]
    pub panel: Option<String>,
    #[serde(default)]
    pub instance_credentials: Option<String>,
    #[serde(default)]
    pub units: Vec<String>,
    #[serde(default)]
    pub hide_units: bool,
    #[serde(default)]
    pub preferred: bool,
    #[serde(default = "enabled_by_default")]
    pub refresh_on_discovery: bool,
    #[serde(default = "enabled_by_default")]
    pub scope_instances: bool,
    #[serde(default)]
    pub legacy_log_interval: bool,
    #[serde(default = "service_namespace")]
    pub incident_namespace: String,
    #[serde(default)]
    pub unix_socket_name: Option<String>,
    #[serde(default = "default_interval")]
    pub factory_interval: u64,
    #[serde(default)]
    pub monitoring: Option<ServiceDescription>,
    #[serde(default)]
    pub check_inputs: Vec<String>,
    pub actions: Vec<String>,
    pub name: String,
    pub endpoint: String,
    pub endpoints: Vec<String>,
    pub port: u16,
    pub credentials: String,
    pub rights: String,
    pub metrics: Vec<MetricSpec>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct MetricSpec {
    pub key: String,
    pub label: String,
    pub unit: String,
    pub rule: Option<Rule>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Rule {
    pub threshold: f64,
    pub critical: Option<f64>,
    pub mode: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ServiceDescription {
    pub purpose: String,
    pub reads: String,
    pub commands: String,
    pub rights: String,
    pub limits: String,
    pub schedule: String,
}

fn default_interval() -> u64 {
    180
}
fn enabled_by_default() -> bool {
    true
}
fn service_namespace() -> String {
    "service:".into()
}

pub(crate) type Collection =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send>>;
pub(crate) struct ServiceBackend {
    pub view: fn(&Store, &str, &str) -> Result<serde_json::Value>,
    pub configure: Option<fn(&Store, &str, &str, serde_json::Value) -> Result<()>>,
    pub refresh: fn(Arc<AppState>, String, String) -> Collection,
    pub init: fn(&str, &str, Option<u16>) -> Result<String>,
    pub cards: fn(&Connection, &instances::Names) -> Result<Vec<(String, Card)>>,
    pub incident_title: fn(&str, &str) -> Option<String>,
    pub invalidate: Option<fn(&Connection, &str) -> Result<()>>,
    pub check_input: Option<fn(&str, &serde_json::Value) -> CheckSample>,
    pub configure_smoke: Option<fn(&Store, &str, &str) -> Result<()>>,
    pub mutation: Option<ServiceMutation>,
    pub source: &'static str,
}

pub(crate) struct ServiceMutation {
    pub schema: fn() -> serde_json::Value,
    pub prepare_issue: fn(&str) -> Option<&'static str>,
    pub session_capabilities: &'static [&'static str],
}

include!(concat!(env!("OUT_DIR"), "/service_backends.rs"));

pub(crate) fn backend(kind: &str) -> Option<&'static ServiceBackend> {
    SERVICE_BACKENDS
        .iter()
        .find_map(|(id, adapter)| (*id == kind).then_some(adapter))
}

static ALL_CATALOG: LazyLock<BTreeMap<String, Spec>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../../collectors/connectors/catalog.json"))
        .expect("Embedded connector catalog")
});
static CATALOG: LazyLock<BTreeMap<String, Spec>> = LazyLock::new(|| {
    ALL_CATALOG
        .iter()
        .filter(|(kind, _)| backend(kind).is_none())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
});
pub(crate) fn descriptor(kind: &str) -> Option<&'static Spec> {
    ALL_CATALOG.get(kind)
}
pub fn catalog() -> BTreeMap<String, Spec> {
    ALL_CATALOG.clone()
}
pub(crate) fn snapshot_for(
    store: &Store,
    id: &str,
    kind: &str,
    instance: &str,
) -> Result<serde_json::Value> {
    instances::validate(instance)?;
    let descriptor = descriptor(kind).ok_or("Unknown connector")?;
    if !descriptor.multiple && instance != DEFAULT {
        return Err("Unknown service instance".into());
    }
    let mut value = if let Some(adapter) = backend(kind) {
        (adapter.view)(store, id, instance)?
    } else {
        serde_json::to_value(store.service_view_for(id, kind, instance)?).map_err(err)?
    };
    value["kind"] = json!(kind);
    let db = store.0.lock().map_err(err)?;
    value["instanceId"] = json!(instance);
    value["instanceName"] = json!(instances::name(&db, id, kind, instance)?);
    Ok(value)
}
pub(crate) fn configure_for(
    store: &Store,
    id: &str,
    kind: &str,
    instance: &str,
    raw: serde_json::Value,
) -> Result<()> {
    instances::validate(instance)?;
    let spec = descriptor(kind).ok_or("Unknown connector")?;
    if !spec.multiple && instance != DEFAULT {
        return Err("Unknown service instance".into());
    }
    if let Some(adapter) = backend(kind) {
        let configure = adapter
            .configure
            .ok_or("The service does not have a separate connection profile")?;
        configure(store, id, instance, raw)
    } else {
        store.configure_service_for(
            id,
            kind,
            instance,
            serde_json::from_value(raw).map_err(err)?,
        )
    }
}
pub(crate) async fn refresh_for(
    state: Arc<AppState>,
    id: String,
    kind: String,
    instance: String,
) -> Result<serde_json::Value> {
    instances::validate(&instance)?;
    let spec = descriptor(&kind).ok_or("Unknown connector")?;
    if !spec.multiple && instance != DEFAULT {
        return Err("Unknown service instance".into());
    }
    if let Some(adapter) = backend(&kind) {
        (adapter.refresh)(state, id, instance).await
    } else {
        serde_json::to_value(collect_for(state, id, kind, instance).await?).map_err(err)
    }
}

fn mutations() -> impl Iterator<Item = &'static ServiceMutation> {
    SERVICE_BACKENDS
        .iter()
        .filter_map(|(_, adapter)| adapter.mutation.as_ref())
}

pub(crate) fn action_schemas() -> impl Iterator<Item = serde_json::Value> {
    mutations().map(|mutation| (mutation.schema)())
}

pub(crate) fn action_prepare_issue(issue: &str) -> Option<&'static str> {
    mutations().find_map(|mutation| (mutation.prepare_issue)(issue))
}

pub(crate) fn session_capabilities() -> impl Iterator<Item = &'static str> {
    mutations().flat_map(|mutation| mutation.session_capabilities.iter().copied())
}

pub(crate) type CheckSample = (Option<f64>, Option<i64>, bool);

pub(crate) fn check_samples(
    db: &Connection,
    server: &str,
    fields: &[String],
) -> Result<BTreeMap<String, CheckSample>> {
    let mut out = BTreeMap::new();
    for (kind, adapter) in SERVICE_BACKENDS {
        let Some(extract) = adapter.check_input else {
            continue;
        };
        let Some(spec) = descriptor(kind) else {
            continue;
        };
        let mut matching = fields
            .iter()
            .filter(|field| spec.check_inputs.contains(field))
            .peekable();
        if matching.peek().is_none() {
            continue;
        }
        let raw: Option<String> = db.query_row(
            "SELECT payload FROM service_summaries WHERE server_id=?1 AND kind=?2 AND instance_id='default' ORDER BY at DESC,rowid DESC LIMIT 1",
            params![server, kind], |row| row.get(0),
        ).optional().map_err(err)?;
        let value = raw
            .map(|raw| serde_json::from_str(&raw).map_err(err))
            .transpose()?
            .unwrap_or(serde_json::Value::Null);
        out.extend(matching.map(|field| (field.clone(), extract(field, &value))));
    }
    Ok(out)
}

pub(crate) fn configure_smoke(store: &Store, id: &str, kind: &str, instance: &str) -> Result<()> {
    if let Some(adapter) = backend(kind) {
        return adapter
            .configure_smoke
            .map_or(Ok(()), |configure| configure(store, id, instance));
    }
    let mut config = Config::default_for(kind)?;
    config.enabled = true;
    if let Ok(port) = std::env::var("CYBERBOT_TEST_INSTANCE_PORT") {
        config.port = port.parse().map_err(err)?;
    }
    config.interval_seconds = 60;
    config.expected_peers = std::env::var("CYBERBOT_TEST_SERVICE_PEERS")
        .unwrap_or("0".into())
        .parse()
        .map_err(err)?;
    config.auto_endpoint = Some(config.automatic(kind, instance));
    if store.service_state_for(id, kind, instance)?.config != config {
        store.configure_service_for(id, kind, instance, config)?;
    }
    Ok(())
}

fn spec(kind: &str) -> Result<&'static Spec> {
    CATALOG.get(kind).ok_or_else(|| "Unknown connector".into())
}
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_endpoint: Option<bool>,
    pub endpoint: String,
    pub port: u16,
    pub user: String,
    pub interval_seconds: u64,
    pub expected_peers: u32,
    pub expect_replica: bool,
}
impl Config {
    pub(crate) fn automatic(&self, kind: &str, instance: &str) -> bool {
        self.auto_endpoint.unwrap_or_else(|| {
            instance == DEFAULT
                && spec(kind).is_ok_and(|default| {
                    self.endpoint == default.endpoint && self.port == default.port
                })
        })
    }
    pub(crate) fn default_for(kind: &str) -> Result<Self> {
        let s = spec(kind)?;
        Ok(Self {
            enabled: false,
            auto_endpoint: None,
            endpoint: s.endpoint.clone(),
            port: s.port,
            user: String::new(),
            interval_seconds: 180,
            expected_peers: 0,
            expect_replica: false,
        })
    }
    fn validate(&self, kind: &str) -> Result<()> {
        let spec = spec(kind)?;
        let valid_endpoint = spec.endpoints.contains(&self.endpoint)
            || spec.endpoints.iter().any(|v| v == "127.0.0.1") && literal_address(&self.endpoint);
        if !valid_endpoint
            || self.port == 0
            || !(30..=86400).contains(&self.interval_seconds)
            || self.expected_peers > 64
            || self.user.len() > 63
            || !self.user.bytes().enumerate().all(|(i, b)| {
                b.is_ascii_alphabetic()
                    || b == b'_'
                    || i > 0 && (b.is_ascii_digit() || b == b'.' || b == b'-')
            })
        {
            return Err("Invalid local connector profile".into());
        }
        Ok(())
    }
}

pub(crate) fn literal_address(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok_and(|ip| {
        !ip.is_unspecified()
            && !ip.is_multicast()
            && match ip {
                std::net::IpAddr::V4(ip) => !ip.is_broadcast() && !ip.is_link_local(),
                std::net::IpAddr::V6(ip) => !ip.is_unicast_link_local(),
            }
    })
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Checkpoint {
    #[serde(default = "instances::default_id")]
    pub(crate) instance_id: String,
    revision: u64,
    epoch: String,
    pub config: Config,
    pub(crate) next_check: i64,
    last_success: Option<i64>,
    last_sample: Option<i64>,
    error: Option<String>,
    failures: u32,
    identity: Option<String>,
    previous: Option<Sample>,
    streaks: BTreeMap<String, u32>,
    #[serde(default)]
    escalating: BTreeSet<String>,
    status: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct Sample {
    at: i64,
    uptime: Option<f64>,
    metrics: BTreeMap<String, Option<f64>>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Wire {
    version: u32,
    detected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    availability: Option<Availability>,
    connected: bool,
    complete: bool,
    issues: Vec<String>,
    metrics: BTreeMap<String, Option<f64>>,
    identity: Option<String>,
    uptime: Option<f64>,
    duration_ms: u64,
}
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Availability {
    Running,
    Stopped,
    Unknown,
}
impl Availability {
    fn observed(value: Option<Self>, current: bool) -> Self {
        value.filter(|_| current).unwrap_or(Self::Unknown)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Finding {
    key: String,
    title: String,
    severity: String,
    value: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    at: Option<i64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    id: String,
    at: i64,
    data: Wire,
    rates: BTreeMap<String, Option<f64>>,
    findings: Vec<Finding>,
    #[serde(default)]
    pending_findings: Option<Vec<Finding>>,
    bytes_received: usize,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Deviation {
    key: String,
    title: String,
    severity: String,
    value: Option<f64>,
    threshold: f64,
    at: i64,
    pending: bool,
    recovering: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub monitoring: crate::monitoring::Values,
    pub kind: String,
    config: Config,
    summary: Option<Summary>,
    evidence: Vec<Summary>,
    deviations: Vec<Deviation>,
    error: Option<String>,
    fresh: bool,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    availability: Option<Availability>,
    next_check: i64,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Card {
    pub(crate) instance_id: String,
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) detected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) availability: Option<Availability>,
    pub(crate) status: String,
    pub(crate) at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) metric: Option<CardMetric>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CardMetric {
    pub value: f64,
    pub unit: &'static str,
}
const ISSUES: &[&str] = &[
    "endpoint_ambiguous",
    "endpoint_not_local",
    "profile_disabled",
    "not_detected",
    "client_missing",
    "unsupported_version",
    "credentials_unavailable",
    "connection_denied",
    "source_unavailable",
    "partial_coverage",
    "query_timeout",
    "response_limit",
    "counter_warmup",
    "replication_lag_unknown",
];
fn validate(kind: &str, w: &Wire) -> Result<()> {
    let s = spec(kind)?;
    if w.version != 1
        || w.duration_ms > 15000
        || w.issues.len() > 16
        || w.issues.iter().any(|s| !ISSUES.contains(&s.as_str()))
        || w.connected && !w.detected
        || !w.detected
            && matches!(
                w.availability,
                Some(Availability::Running | Availability::Stopped)
            )
        || w.connected && w.availability == Some(Availability::Stopped)
        || w.complete && (!w.connected || !w.issues.is_empty())
        || w.metrics.len() != s.metrics.len()
        || s.metrics.iter().any(|m| !w.metrics.contains_key(&m.key))
        || w.metrics
            .values()
            .flatten()
            .any(|v| !v.is_finite() || *v < 0. || *v > 1e18)
        || w.uptime
            .is_some_and(|v| !v.is_finite() || v < 0. || v > 1e12)
        || w.identity
            .as_ref()
            .is_some_and(|v| v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()))
        || !w.connected && w.metrics.values().any(Option::is_some)
    {
        return Err("Invalid connector summary".into());
    }
    Ok(())
}
fn read(db: &Connection, id: &str, kind: &str, instance: &str) -> Result<Checkpoint> {
    let raw: String = db
        .query_row(
            "SELECT payload FROM service_state WHERE server_id=?1 AND kind=?2 AND instance_id=?3",
            params![id, kind, instance],
            |r| r.get(0),
        )
        .map_err(err)?;
    let mut s: Checkpoint = serde_json::from_str(&raw).map_err(err)?;
    s.instance_id = instance.into();
    s.config.auto_endpoint = Some(s.config.automatic(kind, instance));
    let p = crate::monitoring::effective(db, kind, id, instance)?.values;
    s.config.interval_seconds = p.interval_seconds;
    s.config.enabled = p.diagnostic_enabled;
    s.config.expected_peers = p.expected_peers;
    s.config.expect_replica = p.expect_replica;
    Ok(s)
}
fn write(db: &Connection, id: &str, kind: &str, s: &Checkpoint) -> Result<()> {
    db.execute(
        "UPDATE service_state SET payload=?3 WHERE server_id=?1 AND kind=?2 AND instance_id=?4",
        params![
            id,
            kind,
            serde_json::to_string(s).map_err(err)?,
            s.instance_id
        ],
    )
    .map_err(err)?;
    Ok(())
}
fn prefix(kind: &str, instance: &str) -> String {
    instances::prefix(kind, instance)
}
fn stale(db: &Connection, id: &str, kind: &str, instance: &str, check: Option<&str>) -> Result<()> {
    db.execute("UPDATE incidents SET payload=json_set(payload,'$.freshUntil',0,'$.autoEligible',json('false'),'$.healthyStreak',0) WHERE server_id=?1 AND json_extract(payload,'$.check') LIKE ?2 AND (?3 IS NULL OR json_extract(payload,'$.check')=?3)",params![id,prefix(kind,instance),check]).map_err(err)?;
    Ok(())
}
fn fresh(s: &Checkpoint, at: i64) -> bool {
    s.error.is_none()
        && s.last_success.is_some_and(|t| {
            at - t
                <= (if s.config.enabled && s.status != "not_detected" {
                    s.config.interval_seconds * 2 + 30
                } else {
                    43230
                }) as i64
        })
}
fn rates(w: &Wire, s: &Checkpoint, at: i64, advance: bool) -> BTreeMap<String, Option<f64>> {
    let mut out = BTreeMap::new();
    for (key, value) in &w.metrics {
        let delta = s.previous.as_ref().and_then(|p| {
            let elapsed = at - p.at;
            if !advance
                || elapsed < 60
                || elapsed > (s.config.interval_seconds * 3 + 30) as i64
                || w.uptime.zip(p.uptime).is_some_and(|(a, b)| a < b)
                || w.metrics
                    .get("uptimeFlush")
                    .copied()
                    .flatten()
                    .zip(p.metrics.get("uptimeFlush").copied().flatten())
                    .is_some_and(|(a, b)| a < b)
            {
                return None;
            }
            let old = p.metrics.get(key).copied().flatten()?;
            let new = (*value)?;
            if new < old {
                return None;
            }
            Some((new - old) * 600. / elapsed as f64)
        });
        out.insert(key.clone(), delta);
    }
    out
}

fn latest_summary(
    db: &Connection,
    id: &str,
    kind: &str,
    instance: &str,
) -> Result<Option<Summary>> {
    let raw: Option<String> = db.query_row(
        "SELECT payload FROM service_summaries WHERE server_id=?1 AND kind=?2 AND instance_id=?3 ORDER BY at DESC,rowid DESC LIMIT 1",
        params![id, kind, instance], |r| r.get(0),
    ).optional().map_err(err)?;
    raw.map(|v| serde_json::from_str(&v).map_err(err))
        .transpose()
}

fn service_incidents(
    db: &Connection,
    id: &str,
    kind: &str,
    instance: &str,
) -> Result<BTreeMap<String, Incident>> {
    let mut q = db.prepare(
        "SELECT payload FROM incidents WHERE server_id=?1 AND json_extract(payload,'$.check') LIKE ?2
         AND (json_extract(payload,'$.status')='open' OR json_extract(payload,'$.manualResolutionPending')=1)",
    ).map_err(err)?;
    let rows = q
        .query_map(params![id, prefix(kind, instance)], |r| {
            r.get::<_, String>(0)
        })
        .map_err(err)?;
    rows.map(|row| {
        let incident: Incident = serde_json::from_str(&row.map_err(err)?).map_err(err)?;
        Ok((incident.check.clone(), incident))
    })
    .collect()
}

fn metric_value(
    rule: &Rule,
    key: &str,
    wire: &Wire,
    rates: &BTreeMap<String, Option<f64>>,
) -> Option<f64> {
    let values = if rule.mode == "delta_per_10m" {
        rates
    } else {
        &wire.metrics
    };
    values.get(key).copied().flatten()
}

fn absent(wire: &Wire, config: &Config) -> bool {
    if wire.availability.is_some() {
        return !wire.detected && wire.issues.iter().any(|issue| issue == "not_detected");
    }
    !wire.detected
        && (!config.enabled
            || config.auto_endpoint == Some(true)
                && wire.issues.iter().all(|issue| issue == "not_detected"))
}

fn assessment(
    kind: &str,
    state: &Checkpoint,
    summary: &Summary,
    incidents: &BTreeMap<String, Incident>,
    thresholds: &Thresholds,
) -> Result<(&'static str, Vec<Deviation>)> {
    let mut deviations = Vec::new();
    for metric in &spec(kind)?.metrics {
        let Some(rule) = &metric.rule else { continue };
        let limits = &thresholds[&metric.key];
        let activation = thresholds::activation(limits);
        let key = format!(
            "service:{}:{}",
            instances::scope(kind, &state.instance_id),
            metric.key
        );
        let incident = incidents.get(&key);
        let confirmed = summary.findings.iter().find(|finding| finding.key == key);
        let value = metric_value(rule, &metric.key, &summary.data, &summary.rates);
        // Old summaries stored the measured value even when the first breach had no finding.
        let legacy_pending = if summary.pending_findings.is_none() && confirmed.is_none() {
            value.filter(|v| *v >= activation).map(|value| Finding {
                key: key.clone(),
                title: metric.label.clone(),
                severity: thresholds::severity(limits, value).into(),
                value,
                at: None,
            })
        } else {
            None
        };
        let pending = summary
            .pending_findings
            .as_ref()
            .and_then(|findings| findings.iter().find(|finding| finding.key == key))
            .or(legacy_pending.as_ref());
        let suppressed = incident.is_some_and(|i| i.manual_resolution_pending);
        let confirmed = confirmed.filter(|_| !suppressed);
        let pending = pending.filter(|f| {
            !suppressed || f.severity == "critical" && state.escalating.contains(&metric.key)
        });
        let fresh_open = incident
            .filter(|i| i.status == "open" && i.fresh_until.is_some_and(|t| t >= summary.at));
        let (title, level, measured, at, pending, recovering) = if let Some(finding) = confirmed {
            (
                &finding.title,
                &finding.severity,
                Some(finding.value),
                summary.at,
                false,
                false,
            )
        } else if let Some(i) = fresh_open {
            (
                &i.title,
                &i.severity,
                value,
                i.updated_at,
                false,
                i.healthy_streak > 0,
            )
        } else if let Some(finding) = pending {
            (
                &finding.title,
                &finding.severity,
                Some(finding.value),
                finding.at.unwrap_or(summary.at),
                true,
                false,
            )
        } else {
            continue;
        };
        deviations.push(Deviation {
            key,
            title: title.clone(),
            severity: level.clone(),
            value: measured,
            threshold: limits.get(level).copied().unwrap_or(activation),
            at,
            pending,
            recovering,
        });
    }
    let status = if deviations
        .iter()
        .any(|d| !d.pending && d.severity == "critical")
    {
        "critical"
    } else if !deviations.is_empty() {
        "warning"
    } else if incidents.values().any(|i| i.status == "open") {
        "unknown"
    } else if summary.data.connected && summary.data.metrics.values().any(Option::is_some) {
        "healthy"
    } else if absent(&summary.data, &state.config) {
        "not_detected"
    } else {
        "unknown"
    };
    Ok((status, deviations))
}

pub(crate) fn resolve_deviation(db: &Connection, incident: &Incident) -> Result<()> {
    let Some((scope, metric)) = incident
        .check
        .strip_prefix("service:")
        .and_then(|s| s.split_once(':'))
    else {
        return Ok(());
    };
    let (kind, instance) = scope.split_once('@').unwrap_or((scope, DEFAULT));
    if !CATALOG.get(kind).is_some_and(|s| {
        s.metrics
            .iter()
            .any(|m| m.key == metric && m.rule.is_some())
    }) {
        return Ok(());
    }
    let Some(summary) = latest_summary(db, &incident.server_id, kind, instance)? else {
        return Ok(());
    };
    let mut state = read(db, &incident.server_id, kind, instance)?;
    state.revision += 1;
    state.streaks.remove(metric);
    state.escalating.remove(metric);
    if state.last_success.is_some() && state.error.is_none() {
        let incidents = service_incidents(db, &incident.server_id, kind, instance)?;
        let policy = crate::monitoring::effective(db, kind, &incident.server_id, instance)?;
        state.status = assessment(
            kind,
            &state,
            &summary,
            &incidents,
            &policy.values.thresholds,
        )?
        .0
        .into();
    }
    write(db, &incident.server_id, kind, &state)
}

pub(crate) fn reconcile_resolved_deviations(db: &Connection) -> Result<()> {
    if db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM maintenance WHERE id=7)",
            [],
            |r| r.get(0),
        )
        .map_err(err)?
    {
        return Ok(());
    }
    let tx = db.unchecked_transaction().map_err(err)?;
    if tx
        .execute(
            "INSERT OR IGNORE INTO maintenance VALUES(7,unixepoch())",
            [],
        )
        .map_err(err)?
        != 0
    {
        let mut q = tx.prepare(
            "SELECT payload FROM incidents WHERE json_extract(payload,'$.check') GLOB 'service:*'
             AND json_extract(payload,'$.status')='resolved' AND json_extract(payload,'$.manualResolutionPending')=1",
        ).map_err(err)?;
        let rows = q.query_map([], |r| r.get::<_, String>(0)).map_err(err)?;
        for row in rows {
            resolve_deviation(&tx, &serde_json::from_str(&row.map_err(err)?).map_err(err)?)?;
        }
    }
    tx.commit().map_err(err)
}

pub(crate) fn initial_payload(
    server: &str,
    kind: &str,
    instance: &str,
    port: Option<u16>,
) -> Result<String> {
    if let Some(adapter) = backend(kind) {
        (adapter.init)(server, instance, port)
    } else {
        serde_json::to_string(&initial_state(server, kind, instance, port)?).map_err(err)
    }
}

pub(crate) fn schedule_observed_units(
    db: &Connection,
    server: &Server,
    observation: &Observation,
    refresh_known: bool,
    at: i64,
) -> Result<()> {
    let changed = |unit: &ServiceStatus| {
        matches!(unit.state.as_str(), "active" | "inactive" | "failed")
            && (refresh_known
                || !server.observation.as_ref().is_some_and(|previous| {
                    previous
                        .services
                        .iter()
                        .any(|old| old.name == unit.name && old.state == unit.state)
                }))
    };
    for (kind, spec) in ALL_CATALOG
        .iter()
        .filter(|(_, spec)| spec.reports_availability && spec.refresh_on_discovery)
    {
        let found = observation
            .services
            .iter()
            .filter(|unit| changed(unit))
            .any(|unit| {
                unit.name
                    .strip_suffix(".service")
                    .is_some_and(|name| spec.units.iter().any(|alias| alias == name))
            });
        if !found
            || !crate::monitoring::effective(db, kind, &server.id, DEFAULT)?
                .values
                .enabled
        {
            continue;
        }
        let updated = db.execute(
            "UPDATE service_state SET payload=json_set(payload,'$.nextCheck',min(json_extract(payload,'$.nextCheck'),?4))
             WHERE server_id=?1 AND kind=?2 AND instance_id=?3",
            params![server.id, kind, DEFAULT, at],
        ).map_err(err)?;
        if updated == 0 {
            instances::ensure(db, &server.id, kind, DEFAULT)?;
            db.execute(
                "INSERT INTO service_state(server_id,kind,instance_id,payload)
                 VALUES(?1,?2,?3,json_set(?4,'$.nextCheck',?5))",
                params![
                    server.id,
                    kind,
                    DEFAULT,
                    initial_payload(&server.id, kind, DEFAULT, None)?,
                    at
                ],
            )
            .map_err(err)?;
        }
    }
    Ok(())
}

pub(crate) fn initial_state(
    id: &str,
    kind: &str,
    instance: &str,
    port: Option<u16>,
) -> Result<Checkpoint> {
    let mut config = Config::default_for(kind)?;
    if let Some(port) = port {
        config.port = port;
        if spec(kind)?.endpoints.iter().any(|v| v == "127.0.0.1") {
            config.endpoint = "127.0.0.1".into();
        }
    }
    config.validate(kind)?;
    Ok(Checkpoint {
        instance_id: instance.into(),
        revision: 0,
        epoch: uuid::Uuid::new_v4().to_string(),
        config,
        next_check: now()
            + stable_id(id, &instances::scope(kind, instance))
                .bytes()
                .map(i64::from)
                .sum::<i64>()
                % 600,
        last_success: None,
        last_sample: None,
        error: None,
        failures: 0,
        identity: None,
        previous: None,
        streaks: BTreeMap::new(),
        escalating: BTreeSet::new(),
        status: "unknown".into(),
    })
}

impl Store {
    #[cfg(test)]
    pub(crate) fn service_state(&self, id: &str, kind: &str) -> Result<Checkpoint> {
        self.service_state_for(id, kind, DEFAULT)
    }
    pub(crate) fn service_state_for(
        &self,
        id: &str,
        kind: &str,
        instance: &str,
    ) -> Result<Checkpoint> {
        spec(kind)?;
        let db = self.0.lock().map_err(err)?;
        let exists: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM servers WHERE id=?1)",
                [id],
                |r| r.get(0),
            )
            .map_err(err)?;
        if !exists {
            return Err("The server is remote".into());
        }
        instances::ensure(&db, id, kind, instance)?;
        let state = initial_state(id, kind, instance, None)?;
        db.execute(
            "INSERT OR IGNORE INTO service_state(server_id,kind,payload,instance_id) VALUES(?1,?2,?3,?4)",
            params![id, kind, serde_json::to_string(&state).map_err(err)?,instance],
        )
        .map_err(err)?;
        read(&db, id, kind, instance)
    }
    #[cfg(test)]
    pub(crate) fn configure_service(&self, id: &str, kind: &str, config: Config) -> Result<()> {
        self.configure_service_for(id, kind, DEFAULT, config)
    }
    pub(crate) fn configure_service_for(
        &self,
        id: &str,
        kind: &str,
        instance: &str,
        config: Config,
    ) -> Result<()> {
        config.validate(kind)?;
        self.service_state_for(id, kind, instance)?;
        let mut db = self.0.lock().map_err(err)?;
        crate::storage::admit(&db)?;
        let tx = db.transaction().map_err(err)?;
        crate::monitoring::check_commit(&tx)?;
        let mut s = read(&tx, id, kind, instance)?;
        if (
            s.config.endpoint.as_str(),
            s.config.port,
            s.config.automatic(kind, instance),
        ) != (
            config.endpoint.as_str(),
            config.port,
            config.automatic(kind, instance),
        ) {
            tx.execute("DELETE FROM ai_jobs WHERE incident_id IN (SELECT id FROM incidents WHERE server_id=?1 AND json_extract(payload,'$.check') LIKE ?2)",params![id,prefix(kind,instance)]).map_err(err)?;
            tx.execute("DELETE FROM incidents WHERE server_id=?1 AND json_extract(payload,'$.check') LIKE ?2",params![id,prefix(kind,instance)]).map_err(err)?;
            tx.execute(
                "DELETE FROM service_summaries WHERE server_id=?1 AND kind=?2 AND instance_id=?3",
                params![id, kind, instance],
            )
            .map_err(err)?;
        }
        let old = crate::monitoring::effective(&tx, kind, id, instance)?.values;
        let new = crate::monitoring::Values {
            enabled: old.enabled,
            interval_seconds: config.interval_seconds,
            diagnostic_enabled: config.enabled,
            expected_peers: config.expected_peers,
            expect_replica: config.expect_replica,
            ..old.clone()
        };
        crate::monitoring::legacy_service(&tx, kind, id, instance, &old, &new)?;
        s.config = config;
        s.epoch = uuid::Uuid::new_v4().to_string();
        s.revision += 1;
        s.streaks.clear();
        s.escalating.clear();
        s.previous = None;
        s.last_sample = None;
        s.last_success = None;
        s.identity = None;
        s.error = None;
        s.failures = 0;
        s.status = "unknown".into();
        s.next_check = now();
        stale(&tx, id, kind, instance, None)?;
        write(&tx, id, kind, &s)?;
        tx.commit().map_err(err)
    }
    #[cfg(test)]
    pub(crate) fn service_schedule(
        &self,
        servers: &[Server],
    ) -> Result<Vec<(i64, String, String, String)>> {
        let db = self.0.lock().map_err(err)?;
        let mut rows = db.prepare(
            "SELECT server_id,kind,instance_id,json_extract(payload,'$.nextCheck') FROM service_state"
        ).map_err(err)?;
        let mut due = rows
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })
            .map_err(err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err)?;
        let existing = due
            .iter()
            .filter(|(_, _, _, instance)| instance == DEFAULT)
            .map(|(_, server, kind, _)| (server.clone(), kind.clone()))
            .collect::<BTreeSet<_>>();
        for server in servers {
            for kind in ALL_CATALOG.keys() {
                if !existing.contains(&(server.id.clone(), kind.clone())) {
                    instances::ensure(&db, &server.id, kind, DEFAULT)?;
                    let payload = initial_payload(&server.id, kind, DEFAULT, None)?;
                    let state: serde_json::Value = serde_json::from_str(&payload).map_err(err)?;
                    let next = state["nextCheck"]
                        .as_i64()
                        .ok_or("No diagnostic deadline")?;
                    db.execute(
                        "INSERT OR IGNORE INTO service_state(server_id,kind,instance_id,payload) VALUES(?1,?2,?3,?4)",
                        params![server.id, kind, DEFAULT, payload],
                    ).map_err(err)?;
                    due.push((next, server.id.clone(), kind.clone(), DEFAULT.into()));
                }
            }
        }
        due.retain(|(_, _, kind, _)| descriptor(kind).is_some());
        for (next, _, _, instance) in &mut due {
            if instance != DEFAULT {
                *next = (*next).clamp(0, now() + 86400);
            }
        }
        Ok(due)
    }
    pub(crate) fn service_cards(db: &Connection) -> Result<BTreeMap<String, Vec<Card>>> {
        let book = crate::monitoring::Book::load(db)?;
        let names = instances::Names::load(db, None)?;
        let mut q = db
            .prepare(
                "SELECT s.server_id, s.kind, json_extract(s.payload,'$.status'),
                    json_extract(s.payload,'$.lastSuccess'), json_extract(s.payload,'$.error'),
                    s.instance_id, COALESCE(json_extract(x.payload,'$.data.detected'), 0),
                    json_quote(json_extract(x.payload,'$.data.availability'))
             FROM service_state s
             LEFT JOIN service_summaries x ON x.rowid=(
                 SELECT y.rowid FROM service_summaries y
                 WHERE y.server_id=s.server_id AND y.kind=s.kind AND y.instance_id=s.instance_id
                 ORDER BY y.at DESC, y.rowid DESC LIMIT 1
             )",
            )
            .map_err(err)?;
        let rows = q
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, bool>(6)?,
                    r.get::<_, String>(7)?,
                ))
            })
            .map_err(err)?;
        let mut out: BTreeMap<String, Vec<Card>> = BTreeMap::new();
        for row in rows {
            let (id, kind, status, at, error, instance, detected, availability) =
                row.map_err(err)?;
            let Some(spec) = CATALOG.get(&kind) else {
                continue;
            };
            let policy = book
                .resolve(&crate::monitoring::scope(&kind, Some(&id), Some(&instance)))?
                .values;
            let status = status.unwrap_or_else(|| "unknown".into());
            let enabled = policy.diagnostic_enabled;
            let interval = policy.interval_seconds as i64;
            let valid = policy.enabled
                && error.is_none()
                && at.is_some_and(|t| {
                    now() - t
                        <= if enabled && status != "not_detected" {
                            interval * 2 + 30
                        } else {
                            43230
                        }
                });
            let availability = spec.reports_availability.then(|| {
                Availability::observed(serde_json::from_str(&availability).ok().flatten(), valid)
            });
            let name = names.name(&id, &kind, &instance);
            out.entry(id).or_default().push(Card {
                instance_id: instance,
                kind,
                name,
                detected,
                availability,
                status: if valid { status } else { "unknown".into() },
                at,
                metric: None,
            });
        }
        for (_, adapter) in SERVICE_BACKENDS {
            for (server, card) in (adapter.cards)(db, &names)? {
                out.entry(server).or_default().push(card);
            }
        }
        Ok(out)
    }
    #[cfg(test)]
    pub(crate) fn service_view(&self, id: &str, kind: &str) -> Result<View> {
        self.service_view_for(id, kind, DEFAULT)
    }
    pub(crate) fn service_view_for(&self, id: &str, kind: &str, instance: &str) -> Result<View> {
        self.service_state_for(id, kind, instance)?;
        let db = self.0.lock().map_err(err)?;
        let state = read(&db, id, kind, instance)?;
        let mut summary = latest_summary(&db, id, kind, instance)?;
        let mut q=db.prepare("SELECT DISTINCT s.payload FROM service_summaries s JOIN service_evidence e ON e.summary_id=s.id JOIN incidents i ON i.id=e.incident_id WHERE s.server_id=?1 AND s.kind=?2 AND s.instance_id=?3 AND json_extract(i.payload,'$.status')='open' ORDER BY s.at DESC LIMIT 5").map_err(err)?;
        let mut evidence = q
            .query_map(params![id, kind, instance], |r| r.get::<_, String>(0))
            .map_err(err)?
            .map(|r| serde_json::from_str(&r.map_err(err)?).map_err(err))
            .collect::<Result<Vec<_>>>()?;
        let monitoring = crate::monitoring::effective(&db, kind, id, instance)?.values;
        let current = monitoring.enabled && fresh(&state, now());
        let names = instances::Names::load(&db, Some(id))?;
        for summary in summary.iter_mut().chain(evidence.iter_mut()) {
            for finding in &mut summary.findings {
                finding.title = names.incident_title(id, &finding.key, &finding.title);
            }
        }
        let (status, mut deviations) = if let Some(summary) = summary.as_ref().filter(|_| current) {
            let incidents = service_incidents(&db, id, kind, instance)?;
            assessment(kind, &state, summary, &incidents, &monitoring.thresholds)?
        } else {
            ("unknown", Vec::new())
        };
        for deviation in &mut deviations {
            deviation.title = names.incident_title(id, &deviation.key, &deviation.title);
        }
        let availability = spec(kind)?.reports_availability.then(|| {
            Availability::observed(
                summary.as_ref().and_then(|sample| sample.data.availability),
                current,
            )
        });
        Ok(View {
            monitoring,
            kind: kind.into(),
            config: state.config,
            summary,
            evidence,
            deviations,
            error: state.error,
            fresh: current,
            status: status.into(),
            availability,
            next_check: state.next_check,
        })
    }
    pub(crate) fn record_service(
        &self,
        server: &Server,
        kind: &str,
        expected: &Checkpoint,
        bytes: &[u8],
        at: i64,
    ) -> Result<Summary> {
        if bytes.len() > 32768 {
            return Err("Summary exceeds 32 KiB".into());
        }
        let wire: Wire = serde_json::from_slice(bytes).map_err(|_| "Incorrect summary format")?;
        validate(kind, &wire)?;
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
        let instance = &expected.instance_id;
        let mut s = read(&tx, &server.id, kind, instance)?;
        let policy = crate::monitoring::effective(&tx, kind, &server.id, instance)?;
        let thresholds = &policy.values.thresholds;
        if serde_json::to_value(current.endpoint).map_err(err)?
            != serde_json::to_value(&server.endpoint).map_err(err)?
            || s.epoch != expected.epoch
            || s.revision != expected.revision
            || !s.config.enabled && wire.connected
        {
            return Err("The connection or profile has changed".into());
        }
        if s.identity != wire.identity
            || s.previous.as_ref().is_some_and(|p| {
                let elapsed = at - p.at;
                elapsed < 0
                    || elapsed > (s.config.interval_seconds * 3 + 30) as i64
                    || wire
                        .uptime
                        .zip(p.uptime)
                        .is_some_and(|(a, b)| a < b || a + 30. < b + elapsed as f64)
            })
        {
            s.streaks.clear();
            s.escalating.clear();
            s.previous = None;
            s.last_sample = None;
            stale(&tx, &server.id, kind, instance, None)?;
        }
        s.identity = wire.identity.clone();
        if s.last_sample.is_none() {
            s.escalating.clear();
        }
        let advance = s.last_sample.is_none_or(|t| at - t >= 60);
        let rates = rates(&wire, &s, at, advance);
        let id = uuid::Uuid::new_v4().to_string();
        let incidents = service_incidents(&tx, &server.id, kind, instance)?;
        let previous = if advance {
            None
        } else {
            latest_summary(&tx, &server.id, kind, instance)?
        };
        let previous_pending = match previous {
            Some(previous) => match previous.pending_findings {
                Some(findings) => findings,
                None => assessment(kind, &s, &previous, &incidents, thresholds)?
                    .1
                    .into_iter()
                    .filter(|d| d.pending)
                    .filter_map(|d| {
                        Some(Finding {
                            key: d.key,
                            title: d.title,
                            severity: d.severity,
                            value: d.value?,
                            at: Some(d.at),
                        })
                    })
                    .collect(),
            },
            None => Vec::new(),
        };
        let mut findings = Vec::new();
        let mut pending_findings = Vec::new();
        for metric in &spec(kind)?.metrics {
            let Some(rule) = &metric.rule else { continue };
            let limits = &thresholds[&metric.key];
            let check = format!(
                "service:{}:{}",
                instances::scope(kind, instance),
                metric.key
            );
            let incident = incidents.get(&check);
            let suppressed = incident.filter(|i| i.manual_resolution_pending);
            let counter = rule.mode == "delta_per_10m";
            // A quick refresh is neither a counter observation nor evidence of escalation.
            if !advance && (counter || suppressed.is_some()) && wire.metrics[&metric.key].is_some()
            {
                let reset = counter
                    && s.previous
                        .as_ref()
                        .and_then(|sample| sample.metrics.get(&metric.key).copied().flatten())
                        .zip(wire.metrics[&metric.key])
                        .is_some_and(|(old, new)| new < old);
                if !reset {
                    pending_findings
                        .extend(previous_pending.iter().filter(|f| f.key == check).cloned());
                    continue;
                }
            }
            let Some(value) = metric_value(rule, &metric.key, &wire, &rates) else {
                s.streaks.remove(&metric.key);
                s.escalating.remove(&metric.key);
                stale(&tx, &server.id, kind, instance, Some(&check))?;
                continue;
            };
            let bad = value >= thresholds::activation(limits);
            let severity = thresholds::severity(limits, value);
            let n = if let Some(suppressed) = suppressed {
                if bad && !(severity == "critical" && suppressed.severity == "warning") {
                    s.streaks.remove(&metric.key);
                    s.escalating.remove(&metric.key);
                    stale(&tx, &server.id, kind, instance, Some(&check))?;
                    continue;
                }
                if bad {
                    if s.escalating.insert(metric.key.clone()) {
                        stale(&tx, &server.id, kind, instance, Some(&check))?;
                        1
                    } else {
                        // The new severity is confirmed. Reuse the normal episode and notification path.
                        tx.execute("UPDATE incidents SET payload=json_set(payload,'$.manualResolutionPending',json('false')) WHERE id=?1", [&suppressed.id]).map_err(err)?;
                        s.escalating.remove(&metric.key);
                        s.streaks.insert(metric.key.clone(), 2);
                        2
                    }
                } else {
                    s.escalating.remove(&metric.key);
                    s.streaks.remove(&metric.key);
                    0
                }
            } else if advance {
                let n = s.streaks.entry(metric.key.clone()).or_default();
                *n = if bad { n.saturating_add(1) } else { 0 };
                *n
            } else {
                s.streaks.get(&metric.key).copied().unwrap_or(0)
            };
            let firing = bad && n >= 2;
            let title = format!(
                "{}: {}",
                instances::name(&tx, &server.id, kind, instance)?,
                metric.label,
            );
            if bad {
                let finding = Finding {
                    key: check.clone(),
                    title: title.clone(),
                    severity: severity.into(),
                    value,
                    at: (!firing).then_some(at),
                };
                if firing {
                    findings.push(finding);
                } else {
                    pending_findings.push(finding);
                }
            }
            if advance && (firing || !bad && incident.is_some()) {
                Self::incident(
                    &tx,
                    &server.id,
                    &check,
                    if firing {
                        Some(format!("{title}: {value}; summary {id}"))
                    } else {
                        None
                    },
                    &title,
                    severity,
                    at,
                )?;
                let iid = stable_id(&server.id, &check);
                tx.execute("UPDATE incidents SET payload=json_set(payload,'$.freshUntil',?2,'$.autoEligible',CASE WHEN json_extract(payload,'$.status')='open' THEN json(?3) ELSE json('false') END) WHERE id=?1",params![iid,at+(s.config.interval_seconds*2+30) as i64,if firing{"true"}else{"false"}]).map_err(err)?;
            } else if incident.is_some() && suppressed.is_none() && !firing {
                stale(&tx, &server.id, kind, instance, Some(&check))?;
            }
        }
        let summary = Summary {
            id,
            at,
            data: wire,
            rates,
            findings,
            pending_findings: Some(pending_findings),
            bytes_received: bytes.len(),
        };
        tx.execute(
            "INSERT INTO service_summaries(id,server_id,kind,at,payload,instance_id) VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                summary.id,
                server.id,
                kind,
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
            s.previous = Some(Sample {
                at,
                uptime: summary.data.uptime,
                metrics: summary.data.metrics.clone(),
            });
        }
        s.revision += 1;
        s.last_success = Some(at);
        s.error = None;
        let absent = absent(&summary.data, &s.config);
        let availability_confirmed = matches!(
            summary.data.availability,
            Some(Availability::Running | Availability::Stopped)
        );
        s.failures =
            if s.config.enabled && !absent && !summary.data.connected && !availability_confirmed {
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
        let incidents = service_incidents(&tx, &server.id, kind, instance)?;
        s.status = assessment(kind, &s, &summary, &incidents, thresholds)?
            .0
            .into();
        write(&tx, &server.id, kind, &s)?;
        crate::storage::trim_service_instance(&tx, &server.id, kind, instance)?;
        tx.commit().map_err(err)?;
        Ok(summary)
    }
    pub(crate) fn service_error(&self, id: &str, kind: &str, expected: &Checkpoint) -> Result<()> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        crate::monitoring::check_commit(&tx)?;
        let instance = &expected.instance_id;
        if let Ok(mut s) = read(&tx, id, kind, instance) {
            if s.revision == expected.revision && s.epoch == expected.epoch {
                s.revision += 1;
                s.failures = s.failures.saturating_add(1);
                s.error = Some("No summary received. Check the connection and permissions.".into());
                s.status = "unknown".into();
                s.streaks.clear();
                s.escalating.clear();
                s.previous = None;
                s.next_check = now()
                    + (s.config
                        .interval_seconds
                        .saturating_mul(2u64.saturating_pow(s.failures.min(5)))
                        .min(3600)) as i64;
                stale(&tx, id, kind, instance, None)?;
                write(&tx, id, kind, &s)?;
            }
        }
        tx.commit().map_err(err)
    }
}
pub(crate) async fn collect_for(
    state: Arc<AppState>,
    id: String,
    kind: String,
    instance: String,
) -> Result<Summary> {
    crate::monitoring::run(
        &state.store,
        &kind,
        &id,
        &instance,
        collect_for_inner(state.clone(), id.clone(), kind.clone(), instance.clone()),
    )
    .await
}
async fn collect_for_inner(
    state: Arc<AppState>,
    id: String,
    kind: String,
    instance: String,
) -> Result<Summary> {
    let mut _activity_span =
        crate::activity::begin("server", "services.collect_for", Some(id.clone()));
    let _activity_result = (async {
        spec(&kind)?;
        let _guard = state.collectors.acquire(&id, &state.store).await?;
        let snap = state.store.snapshot()?;
        let server = snap
            .servers
            .into_iter()
            .find(|s| s.id == id)
            .ok_or("The server is remote")?;
        let cp = state.store.service_state_for(&id, &kind, &instance)?;
        let policy = crate::monitoring::effective_values(&state.store, &kind, &id, &instance)?;
        let result = async {
            ssh::deploy(&server.endpoint, &state.collector).await?;
            let bytes = ssh::service_sample(
                &server.endpoint,
                &kind,
                &instance,
                json!(cp.config),
                serde_json::Value::Null,
                thresholds::collector_values(&kind, &policy.thresholds),
            )
            .await?;
            state
                .store
                .record_service(&server, &kind, &cp, &bytes, now())
        }
        .await;
        if result.is_err() {
            state.store.service_error(&id, &kind, &cp)?;
        }
        result
    })
    .await;
    _activity_span.result(&_activity_result);
    _activity_result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Store, Server) {
        let db = Store::open(std::path::Path::new(":memory:")).unwrap();
        let source = Source {
            id: "services".into(),
            name: "test".into(),

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
        let s = db.snapshot().unwrap().servers.remove(0);
        for kind in CATALOG.keys() {
            let mut c = Config::default_for(kind).unwrap();
            c.enabled = true;
            c.interval_seconds = 60;
            db.configure_service(&s.id, kind, c).unwrap();
        }
        (db, s)
    }
    fn wire(kind: &str, at: i64) -> serde_json::Value {
        let metrics = spec(kind)
            .unwrap()
            .metrics
            .iter()
            .map(|m| (m.key.clone(), Some(0.)))
            .collect::<BTreeMap<_, _>>();
        json!({"version":1,"detected":true,"connected":true,"complete":true,"issues":[],"metrics":metrics,"identity":null,"uptime":at,"durationMs":1})
    }
    fn record(db: &Store, s: &Server, kind: &str, v: serde_json::Value, at: i64) -> Summary {
        let cp = db.service_state(&s.id, kind).unwrap();
        db.record_service(s, kind, &cp, &serde_json::to_vec(&v).unwrap(), at)
            .unwrap()
    }
    #[test]
    fn service_cards_report_detection_independently_of_health() {
        let (db, server) = fixture();
        let card = || {
            db.snapshot().unwrap().services[&server.id]
                .iter()
                .find(|c| c.kind == "redis")
                .map(|c| (c.detected, c.status.clone(), c.at))
                .unwrap()
        };
        assert_eq!(card(), (false, "unknown".into(), None));

        let at = now();
        let mut sample = wire("redis", at);
        sample["detected"] = json!(false);
        sample["connected"] = json!(false);
        sample["complete"] = json!(false);
        sample["issues"] = json!(["connection_denied"]);
        for value in sample["metrics"].as_object_mut().unwrap().values_mut() {
            *value = serde_json::Value::Null;
        }
        record(&db, &server, "redis", sample.clone(), at);
        assert_eq!(card(), (false, "unknown".into(), Some(at)));

        sample["detected"] = json!(true);
        record(&db, &server, "redis", sample, at + 1);
        assert_eq!(card(), (true, "unknown".into(), Some(at + 1)));
    }
    #[test]
    fn service_availability_is_independent_of_metrics_and_expires() {
        let (db, server) = fixture();
        let card = || {
            db.snapshot().unwrap().services[&server.id]
                .iter()
                .find(|card| card.kind == "caddy")
                .unwrap()
                .availability
        };
        let at = now() - 400;
        let mut sample = wire("caddy", at);
        sample["connected"] = json!(false);
        sample["complete"] = json!(false);
        sample["issues"] = json!(["source_unavailable"]);
        sample["metrics"] = json!({"rss": null, "goroutines": null});
        sample["availability"] = json!("running");
        record(&db, &server, "caddy", sample.clone(), at);
        assert_eq!(card(), Some(Availability::Unknown));
        assert_eq!(
            db.service_view(&server.id, "caddy").unwrap().availability,
            Some(Availability::Unknown)
        );

        sample["availability"] = json!("stopped");
        record(&db, &server, "caddy", sample.clone(), now());
        let view = db.service_view(&server.id, "caddy").unwrap();
        assert_eq!(view.status, "unknown");
        assert!(!view.summary.unwrap().data.connected);
        assert_eq!(view.availability, Some(Availability::Stopped));
        assert_eq!(card(), Some(Availability::Stopped));
        assert!(db.snapshot().unwrap().incidents.is_empty());

        sample.as_object_mut().unwrap().remove("availability");
        record(&db, &server, "caddy", sample, now() + 1);
        assert_eq!(card(), Some(Availability::Unknown));
    }
    #[test]
    fn running_service_keeps_its_poll_interval_when_statistics_are_unavailable() {
        let (db, server) = fixture();
        let kind = "qdrant";
        let interval = db
            .service_state(&server.id, kind)
            .unwrap()
            .config
            .interval_seconds as i64;
        let at = now() - 3 * interval;
        let mut sample = wire(kind, at);
        sample["connected"] = json!(false);
        sample["complete"] = json!(false);
        sample["issues"] = json!(["source_unavailable"]);
        for value in sample["metrics"].as_object_mut().unwrap().values_mut() {
            *value = serde_json::Value::Null;
        }
        sample["availability"] = json!("running");

        for time in [at + interval, at + 2 * interval, at + 3 * interval] {
            record(&db, &server, kind, sample.clone(), time);
            let state = db.service_state(&server.id, kind).unwrap();
            assert_eq!(state.failures, 0);
            assert!((time + interval..time + interval + 30).contains(&state.next_check));
            let view = db.service_view(&server.id, kind).unwrap();
            assert_eq!(view.availability, Some(Availability::Running));
            assert_eq!(view.status, "unknown");
            assert_eq!(view.summary.unwrap().data.issues, ["source_unavailable"]);
        }

        sample["availability"] = json!("unknown");
        let time = at + 4 * interval;
        record(&db, &server, kind, sample.clone(), time);
        let state = db.service_state(&server.id, kind).unwrap();
        assert_eq!(state.failures, 1);
        assert!((time + 2 * interval..time + 2 * interval + 30).contains(&state.next_check));
        assert_eq!(
            db.service_view(&server.id, kind).unwrap().availability,
            Some(Availability::Unknown)
        );
        let time = state.next_check;
        record(&db, &server, kind, sample, time);
        let state = db.service_state(&server.id, kind).unwrap();
        assert_eq!(state.failures, 2);
        assert!((time + 4 * interval..time + 4 * interval + 30).contains(&state.next_check));
        assert!(!fresh(&state, state.next_check));
    }
    #[test]
    fn stopped_service_recovers_from_backoff_and_keeps_its_poll_interval() {
        let (db, server) = fixture();
        let kind = "fail2ban";
        let interval = db
            .service_state(&server.id, kind)
            .unwrap()
            .config
            .interval_seconds as i64;
        let at = now() - 2 * interval;
        let mut sample = wire(kind, at);
        sample["availability"] = json!("unknown");
        sample["connected"] = json!(false);
        sample["complete"] = json!(false);
        sample["issues"] = json!(["source_unavailable"]);
        sample["metrics"] = json!({"jails":null,"currentlyBanned":null,"totalBanned":null});
        record(&db, &server, kind, sample.clone(), at);
        assert_eq!(db.service_state(&server.id, kind).unwrap().failures, 1);

        sample["availability"] = json!("stopped");
        for time in [at + interval, at + 2 * interval] {
            record(&db, &server, kind, sample.clone(), time);
            let state = db.service_state(&server.id, kind).unwrap();
            assert_eq!(state.failures, 0);
            assert!((time + interval..time + interval + 30).contains(&state.next_check));
            assert_eq!(
                db.service_view(&server.id, kind).unwrap().availability,
                Some(Availability::Stopped)
            );
        }

        let mut running = wire(kind, at + 2 * interval + 1);
        running["availability"] = json!("running");
        record(&db, &server, kind, running, at + 2 * interval + 1);
        assert_eq!(
            db.service_view(&server.id, kind).unwrap().availability,
            Some(Availability::Running)
        );
    }
    #[test]
    fn manually_closed_service_stays_hidden_until_recovery_then_recurrence() {
        let (db, s) = fixture();
        let at = now();
        let sample = |bad: bool, t: i64| {
            let mut v = wire("redis", t);
            v["metrics"]["blocked"] = json!(if bad { 2 } else { 0 });
            record(&db, &s, "redis", v, t);
        };
        sample(true, at);
        sample(true, at + 60);
        let i = db.snapshot().unwrap().incidents.remove(0);
        db.resolve_incident(&i.id, &i.episode, at + 61).unwrap();
        let view = db.service_view(&s.id, "redis").unwrap();
        assert_eq!(view.status, "healthy");
        assert!(view.deviations.is_empty());
        assert_eq!(view.summary.unwrap().data.metrics["blocked"], Some(2.));
        assert_eq!(
            db.snapshot().unwrap().services[&s.id]
                .iter()
                .find(|c| c.kind == "redis")
                .unwrap()
                .status,
            "healthy"
        );
        {
            let conn = db.0.lock().unwrap();
            conn.execute(
                "UPDATE service_state SET payload=json_set(payload,'$.status','warning') WHERE server_id=?1 AND kind='redis'",
                [&s.id],
            ).unwrap();
            conn.execute("DELETE FROM maintenance WHERE id=7", [])
                .unwrap();
            reconcile_resolved_deviations(&conn).unwrap();
        }
        assert_eq!(db.service_state(&s.id, "redis").unwrap().status, "healthy");
        sample(true, at + 120);
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "resolved");
        assert!(!db.snapshot().unwrap().incidents[0].auto_eligible);
        assert!(db
            .service_view(&s.id, "redis")
            .unwrap()
            .deviations
            .is_empty());
        sample(false, at + 180);
        sample(false, at + 240);
        assert!(!db.snapshot().unwrap().incidents[0].manual_resolution_pending);
        sample(true, at + 300);
        sample(true, at + 360);
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "open");
        assert_ne!(db.snapshot().unwrap().incidents[0].episode, i.episode);
    }

    #[test]
    fn cockroach_explains_first_breach_in_saved_and_new_summaries() {
        let (db, server) = fixture();
        let kind = "cockroach";
        let at = now();
        db.configure_service(
            &server.id,
            kind,
            Config {
                interval_seconds: 180,
                enabled: true,
                ..Config::default_for(kind).unwrap()
            },
        )
        .unwrap();
        let sample = |seconds, count| {
            let mut v = wire(kind, at + seconds);
            v["metrics"]["errors"] = json!(count);
            record(&db, &server, kind, v, at + seconds)
        };
        sample(0, 59_813_066);
        let first = sample(201, 59_813_473);
        let check = |observed| {
            let view = db.service_view(&server.id, kind).unwrap();
            assert_eq!(view.status, "warning");
            assert!(db.snapshot().unwrap().incidents.is_empty());
            let [reason] = view.deviations.as_slice() else {
                panic!("expected one reason");
            };
            assert_eq!(reason.title, "CockroachDB: SQL errors");
            assert_eq!(reason.threshold, 20.);
            assert_eq!(reason.at, observed);
            assert!((reason.value.unwrap() - 1214.925373).abs() < 0.001);
            assert!(reason.pending);
        };
        assert!(first.findings.is_empty());
        check(at + 201);
        db.0.lock().unwrap().execute(
            "UPDATE service_summaries SET payload=json_remove(payload,'$.pendingFindings') WHERE id=?1",
            [&first.id],
        ).unwrap();
        check(at + 201);
        sample(202, 59_813_475);
        check(at + 201);
        sample(403, 59_813_814);
        let view = db.service_view(&server.id, kind).unwrap();
        let [reason] = view.deviations.as_slice() else {
            panic!("expected one reason");
        };
        assert!(!reason.pending);
        assert!((reason.value.unwrap() - 1012.871287).abs() < 0.001);
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "open");
    }
    #[test]
    fn redis_memory_uses_configured_warning_and_critical_boundaries() {
        let (db, server) = fixture();
        let kind = "redis";
        let scope = crate::monitoring::scope(kind, Some(&server.id), Some(DEFAULT));
        let policy = db.monitoring_policy(&scope).unwrap();
        let old = db.service_state(&server.id, kind).unwrap();
        db.set_monitoring(
            &scope,
            crate::monitoring::Overrides {
                thresholds: [(
                    "memoryUsage".into(),
                    [("warning".into(), 99.), ("critical".into(), 100.)].into(),
                )]
                .into(),
                ..policy.overrides
            },
            policy.revision,
        )
        .unwrap();
        let at = now();
        let sample = |seconds, usage: Option<f64>| {
            let mut v = wire(kind, at + seconds);
            v["metrics"]["memoryUsage"] = json!(usage);
            v
        };
        assert!(db
            .record_service(
                &server,
                kind,
                &old,
                &serde_json::to_vec(&sample(0, Some(100.))).unwrap(),
                at
            )
            .is_err());
        let observe =
            |seconds, usage| record(&db, &server, kind, sample(seconds, usage), at + seconds);
        let view = || db.service_view(&server.id, kind).unwrap();
        observe(0, Some(98.9));
        assert_eq!(view().status, "healthy");
        observe(60, Some(99.));
        let pending = view().deviations.remove(0);
        assert_eq!(pending.threshold, 99.);
        assert!(pending.pending);
        observe(120, None);
        assert!(view().deviations.is_empty());
        assert!(observe(180, Some(99.)).findings.is_empty());
        assert_eq!(observe(240, Some(99.)).findings[0].severity, "warning");
        assert_eq!(observe(300, Some(100.)).findings[0].severity, "critical");
        assert_eq!(view().deviations[0].threshold, 100.);
        assert_eq!(db.snapshot().unwrap().incidents[0].severity, "critical");
    }

    #[test]
    fn escalation_after_resolution_requires_two_independent_critical_samples() {
        let (db, server) = fixture();
        let at = now();
        let kind = "mysql";
        let sample = |seconds, usage, other| {
            let mut v = wire(kind, at + seconds);
            v["metrics"]["connectionUsage"] = json!(usage);
            v["metrics"]["longQueries"] = json!(other);
            record(&db, &server, kind, v, at + seconds)
        };
        let incident = || {
            db.snapshot()
                .unwrap()
                .incidents
                .into_iter()
                .find(|i| i.check == "service:mysql:connectionUsage")
                .unwrap()
        };
        let view = || db.service_view(&server.id, kind).unwrap();
        sample(0, Some(91), 0);
        sample(60, Some(92), 2);
        let first = incident();
        db.resolve_incident(&first.id, &first.episode, at + 61)
            .unwrap();
        let other = view();
        assert_eq!(other.status, "warning");
        assert_eq!(other.deviations[0].key, "service:mysql:longQueries");
        sample(120, Some(96), 0);
        assert!(view().deviations.is_empty());
        sample(121, Some(99), 0);
        assert!(view().deviations.is_empty());
        sample(180, Some(99), 0);
        assert!(view().deviations[0].pending);
        assert_eq!(view().deviations[0].threshold, 97.);
        sample(181, Some(99), 0);
        assert_eq!(view().deviations[0].at, at + 180);
        assert_eq!(incident().status, "resolved");
        sample(240, None, 0);
        assert!(view().deviations.is_empty());
        sample(300, Some(98), 0);
        assert!(view().deviations[0].pending);
        sample(360, Some(99), 0);
        let new = incident();
        assert_ne!(new.episode, first.episode);
        assert_eq!(
            (new.status.as_str(), new.severity.as_str()),
            ("open", "critical")
        );
        assert_eq!(view().status, "critical");
        assert!(!view().deviations[0].pending);
        db.resolve_incident(&new.id, &new.episode, at + 361)
            .unwrap();
        sample(420, Some(100), 0);
        sample(480, Some(100), 0);
        assert!(view().deviations.is_empty());
        assert_eq!(incident().episode, new.episode);
    }

    #[test]
    fn bulk_resolution_clears_only_selected_service_instances() {
        let (db, server) = fixture();
        let kind = "redis";
        let extra = db.add_service_instance(&server.id, kind, None).unwrap();
        let at = now();
        for t in [at, at + 60] {
            for instance in [DEFAULT, extra.id.as_str()] {
                let mut v = wire(kind, t);
                v["metrics"]["blocked"] = json!(2);
                v["metrics"]["persistenceErrors"] = json!(1);
                let state = db.service_state_for(&server.id, kind, instance).unwrap();
                db.record_service(&server, kind, &state, &serde_json::to_vec(&v).unwrap(), t)
                    .unwrap();
            }
        }
        let incidents = db.snapshot().unwrap().incidents;
        let items: Vec<crate::incidents::IncidentEpisode> =
            serde_json::from_value(json!(incidents
                .iter()
                .filter(|i| i.check.starts_with("service:redis:"))
                .map(|i| json!({"id": i.id, "episode": i.episode}))
                .collect::<Vec<_>>()))
            .unwrap();
        assert_eq!(items.len(), 2);
        db.resolve_incidents(&items, at + 61).unwrap();
        let cleared = db.service_view(&server.id, kind).unwrap();
        assert_eq!(cleared.status, "healthy");
        assert!(cleared.deviations.is_empty());
        assert_eq!(
            db.service_view_for(&server.id, kind, &extra.id)
                .unwrap()
                .deviations
                .len(),
            2
        );
    }
    #[test]
    fn independent_redis_instances_settings_incidents_and_late_results() {
        let (db, server) = fixture();
        let a = db.add_service_instance(&server.id, "redis", None).unwrap();
        let b = db.add_service_instance(&server.id, "redis", None).unwrap();
        let at = now();
        for (id, port) in [(&a.id, 6380), (&b.id, 6381)] {
            let mut c = Config::default_for("redis").unwrap();
            c.enabled = true;
            c.port = port;
            c.interval_seconds = 60;
            db.configure_service_for(&server.id, "redis", id, c)
                .unwrap();
        }
        db.save_settings(&Settings {
            mode: "auto".into(),
            daily_run_limit: Some(10),
            daily_token_limit: Some(1000000),
            ..Settings::default()
        })
        .unwrap();
        for t in [at, at + 60, at + 120] {
            for id in [&a.id, &b.id] {
                let cp = db.service_state_for(&server.id, "redis", id).unwrap();
                let mut v = wire("redis", t);
                v["metrics"]["blocked"] = json!(2);
                db.record_service(&server, "redis", &cp, &serde_json::to_vec(&v).unwrap(), t)
                    .unwrap();
            }
            db.reconcile_auto(t).unwrap();
        }
        assert_eq!(db.auto_status(at + 120).unwrap().queued, 2);
        assert_eq!(db.snapshot().unwrap().incidents.len(), 2);
        let late = db.service_state_for(&server.id, "redis", &a.id).unwrap();
        let before = db.service_view_for(&server.id, "redis", &b.id).unwrap();
        assert_eq!(before.config.port, 6381);
        assert_eq!(before.evidence.len(), 2);
        let mut c = late.config.clone();
        c.port = 6390;
        db.configure_service_for(&server.id, "redis", &a.id, c)
            .unwrap();
        assert!(db
            .service_view_for(&server.id, "redis", &a.id)
            .unwrap()
            .summary
            .is_none());
        assert_eq!(
            db.service_view_for(&server.id, "redis", &b.id)
                .unwrap()
                .summary
                .unwrap()
                .id,
            before.summary.unwrap().id
        );
        assert_eq!(db.snapshot().unwrap().incidents.len(), 1);
        assert!(db
            .record_service(
                &server,
                "redis",
                &late,
                &serde_json::to_vec(&wire("redis", at + 180)).unwrap(),
                at + 180
            )
            .is_err());
        let pending = db.service_state_for(&server.id, "redis", &b.id).unwrap();
        db.remove_service_instance(&server.id, "redis", &b.id)
            .unwrap();
        assert!(db.service_state_for(&server.id, "redis", &b.id).is_err());
        assert!(db
            .record_service(
                &server,
                "redis",
                &pending,
                &serde_json::to_vec(&wire("redis", at + 180)).unwrap(),
                at + 180
            )
            .is_err());
        assert!(db.snapshot().unwrap().incidents.is_empty());
        assert!(db
            .extra_instance_schedule()
            .unwrap()
            .iter()
            .any(|(_, _, _, id)| id == &a.id));
    }
    #[test]
    fn instance_registry_is_bounded_and_fixed_sources_cannot_be_duplicated() {
        let (db, server) = fixture();
        for kind in ["nginx", "docker", "asterisk"] {
            assert!(db.add_service_instance(&server.id, kind, None).is_err());
        }
        let defaults = catalog().len();
        for _ in defaults..64 {
            db.add_service_instance(&server.id, "redis", None).unwrap();
        }
        assert_eq!(db.service_instances(&server.id).unwrap().len(), 64);
        assert!(db
            .add_service_instance(&server.id, "postgresql", None)
            .is_err());
        assert!(db.add_service_instance("deleted", "redis", None).is_err());
    }
    #[test]
    fn instance_credentials_identity_and_retention_are_separate() {
        let (db, server) = fixture();
        let i = db.add_service_instance(&server.id, "redis", None).unwrap();
        let mut c = Config::default_for("redis").unwrap();
        c.enabled = true;
        db.configure_service_for(&server.id, "redis", &i.id, c)
            .unwrap();
        let cp = db.service_state_for(&server.id, "redis", &i.id).unwrap();
        let at = now();
        db.record_service(
            &server,
            "redis",
            &cp,
            &serde_json::to_vec(&wire("redis", at)).unwrap(),
            at,
        )
        .unwrap();
        record(&db, &server, "redis", wire("redis", at), at);
        let old = db
            .service_view_for(&server.id, "redis", &i.id)
            .unwrap()
            .summary
            .unwrap()
            .id;

        assert_eq!(
            db.service_view_for(&server.id, "redis", &i.id)
                .unwrap()
                .summary
                .unwrap()
                .id,
            old
        );
        assert!(db
            .remove_service_instance(&server.id, "redis", DEFAULT)
            .is_err());
        assert!(db.service_view_for(&server.id, "mysql", &i.id).is_err());
        assert!(db
            .service_view_for(&server.id, "redis", "../secret")
            .is_err());
        db.maintain_storage().unwrap();
        assert_eq!(
            db.service_view_for(&server.id, "redis", &i.id)
                .unwrap()
                .summary
                .unwrap()
                .id,
            old
        );
    }
    #[test]
    fn simultaneous_services_isolated_and_deduplicated() {
        let (db, s) = fixture();
        let at = now();
        for t in [at, at + 60, at + 120] {
            for (kind, key) in [("redis", "blocked"), ("mysql", "longQueries")] {
                let mut v = wire(kind, t);
                v["metrics"][key] = json!(10);
                record(&db, &s, kind, v, t);
            }
            let mut docker = wire("docker", t);
            docker["complete"] = json!(false);
            docker["issues"] = json!(["partial_coverage"]);
            record(&db, &s, "docker", docker, t);
        }
        let snap = db.snapshot().unwrap();
        assert_eq!(snap.incidents.len(), 2);
        assert_eq!(db.service_view(&s.id, "docker").unwrap().status, "healthy");
        let mut c = Config::default_for("mysql").unwrap();
        c.endpoint = "127.0.0.1".into();
        db.configure_service(&s.id, "mysql", c).unwrap();
        assert_eq!(db.snapshot().unwrap().incidents.len(), 1);
        assert!(db.service_view(&s.id, "redis").unwrap().summary.is_some());
    }
    #[test]
    fn auto_queue_one_episode_per_service() {
        let (db, s) = fixture();
        let at = now();
        db.save_settings(&Settings {
            mode: "auto".into(),
            daily_run_limit: Some(10),
            daily_token_limit: Some(1000000),
            ..Settings::default()
        })
        .unwrap();
        for t in [at, at + 60, at + 120] {
            for (kind, key) in [("redis", "blocked"), ("mysql", "longQueries")] {
                let mut v = wire(kind, t);
                v["metrics"][key] = json!(10);
                record(&db, &s, kind, v, t);
            }
            db.reconcile_auto(t).unwrap();
        }
        assert_eq!(db.auto_status(at + 120).unwrap().queued, 2);
        assert_eq!(db.auto_status(at + 120).unwrap().runs, 0);
        assert_eq!(db.snapshot().unwrap().incidents.len(), 2);
    }
    #[test]
    fn replay_and_profile_cas() {
        let (db, s) = fixture();
        let cp = db.service_state(&s.id, "redis").unwrap();
        let bytes = serde_json::to_vec(&wire("redis", now())).unwrap();
        db.record_service(&s, "redis", &cp, &bytes, now()).unwrap();
        assert!(db.record_service(&s, "redis", &cp, &bytes, now()).is_err());
        let cp = db.service_state(&s.id, "redis").unwrap();
        db.configure_service(&s.id, "redis", cp.config.clone())
            .unwrap();
        assert!(db.record_service(&s, "redis", &cp, &bytes, now()).is_err());
    }
    #[test]
    fn unknown_is_not_recovery_two_complete_samples_recover() {
        let (db, s) = fixture();
        let at = now();
        for t in [at, at + 60] {
            let mut v = wire("redis", t);
            v["metrics"]["blocked"] = json!(2);
            record(&db, &s, "redis", v, t);
        }
        let mut partial = wire("redis", at + 120);
        partial["complete"] = json!(false);
        partial["issues"] = json!(["partial_coverage"]);
        partial["metrics"]["blocked"] = json!(null);
        record(&db, &s, "redis", partial, at + 120);
        let i = db.snapshot().unwrap().incidents.remove(0);
        assert_eq!(i.status, "open");
        assert!(!i.auto_eligible);
        for t in [at + 180, at + 240] {
            record(&db, &s, "redis", wire("redis", t), t);
        }
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "resolved");
    }
    #[test]
    fn counters_manual_refresh_and_restart() {
        let (db, s) = fixture();
        let at = now();
        for (t, count) in [(at, 100), (at + 60, 110), (at + 120, 120)] {
            let mut v = wire("redis", t);
            v["metrics"]["evictions"] = json!(count);
            record(&db, &s, "redis", v, t);
        }
        assert_eq!(db.snapshot().unwrap().incidents.len(), 1);
        let mut v = wire("redis", at + 121);
        v["metrics"]["evictions"] = json!(120);
        record(&db, &s, "redis", v, at + 121);
        assert!(db.snapshot().unwrap().incidents[0].auto_eligible);
        let mut v = wire("redis", at + 180);
        v["uptime"] = json!(1);
        v["metrics"]["evictions"] = json!(500);
        record(&db, &s, "redis", v, at + 180);
        assert!(!db.snapshot().unwrap().incidents[0].auto_eligible);
    }
    #[test]
    fn closed_contract_and_output_limits() {
        let (db, s) = fixture();
        let cp = db.service_state(&s.id, "docker").unwrap();
        let mut v = wire("docker", now());
        v["metrics"]["rawCommand"] = json!(1);
        assert!(db
            .record_service(&s, "docker", &cp, &serde_json::to_vec(&v).unwrap(), now())
            .is_err());
        let mut c = cp.config.clone();
        c.endpoint = "http://external".into();
        assert!(db.configure_service(&s.id, "docker", c).is_err());
        assert!(db
            .record_service(&s, "docker", &cp, &vec![b' '; 32769], now())
            .is_err());
    }
    #[test]
    fn retention_is_bounded() {
        let (db, s) = fixture();
        let dbconn = db.0.lock().unwrap();
        for n in 0..1010 {
            dbconn
                .execute(
                    "INSERT INTO service_summaries(id,server_id,kind,at,payload) VALUES(?1,?2,'redis',?3,'{}')",
                    params![format!("old{n}"), s.id, now() - 864000 + n],
                )
                .unwrap();
        }
        drop(dbconn);
        record(&db, &s, "redis", wire("redis", now()), now());
        let count = || {
            db.0.lock()
                .unwrap()
                .query_row("SELECT count(*) FROM service_summaries", [], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap()
        };
        assert_eq!(count(), 1000);
        db.maintain_storage().unwrap();
        assert_eq!(count(), 1);
    }
}
