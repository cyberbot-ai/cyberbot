use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Endpoint {
    pub host: String,
    pub user: String,
    pub port: u16,
    pub identity_file: Option<String>,
    pub jump_host: Option<String>,
    #[serde(default)]
    pub known_hosts_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Server {
    pub id: String,
    pub source_id: String,
    pub name: String,

    pub endpoint: Endpoint,
    pub observation: Option<Observation>,
    pub last_error: Option<String>,
    pub last_attempt: Option<i64>,
    pub next_check: i64,
    pub failures: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_runtime: Vec<crate::instances::RuntimeIdentity>,
    #[serde(default)]
    pub service_runtime_complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<crate::platform::LinuxPlatform>,
    pub at: i64,
    pub cpu_percent: Option<f64>,
    pub memory_percent: Option<f64>,
    pub swap_percent: Option<f64>,
    pub load: Option<f64>,
    pub uptime: Option<f64>,
    pub disks: Vec<Disk>,
    pub services: Vec<ServiceStatus>,
    pub missing: Vec<String>,
    pub bytes_received: usize,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Disk {
    pub mount: String,
    pub used_percent: f64,
    pub inode_percent: Option<f64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceStatus {
    pub name: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    pub id: String,
    pub name: String,

    pub kind: String,
    pub location: String,
    pub last_sync: Option<i64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Incident {
    #[serde(default)]
    pub resolved_by_user_at: Option<i64>,
    #[serde(default)]
    pub manual_resolution_pending: bool,
    #[serde(default = "default_auto_eligible")]
    pub auto_eligible: bool,
    #[serde(default)]
    pub fresh_until: Option<i64>,
    #[serde(default)]
    pub episode: String,
    #[serde(default)]
    pub occurrences: u64,
    #[serde(default)]
    pub healthy_streak: u32,
    pub id: String,
    pub server_id: String,
    pub check: String,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub opened_at: i64,
    pub updated_at: i64,
    pub evidence: String,
}

fn default_auto_eligible() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    pub mode: String,
    pub daily_run_limit: Option<u32>,
    #[serde(default)]
    pub daily_token_limit: Option<u64>,
    #[serde(default)]
    pub run_token_limit: u64,
    #[serde(default = "default_agent")]
    pub auto_agent: String,
    #[serde(default = "default_log_interval")]
    pub log_poll_seconds: u64,
    pub poll_seconds: u64,
    pub concurrency: usize,
    pub paused: bool,
    #[serde(default)]
    pub(crate) connectivity_probe: crate::connectivity::ProbeHosts,
}
fn default_log_interval() -> u64 {
    600
}
fn default_agent() -> String {
    "codex".into()
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettingsPatch {
    pub mode: Option<String>,
    #[serde(default, deserialize_with = "present_nullable")]
    pub daily_run_limit: Option<Option<u32>>,
    #[serde(default, deserialize_with = "present_nullable")]
    pub daily_token_limit: Option<Option<u64>>,
    pub run_token_limit: Option<u64>,
    pub auto_agent: Option<String>,
    pub log_poll_seconds: Option<u64>,
    pub poll_seconds: Option<u64>,
    pub concurrency: Option<usize>,
    pub paused: Option<bool>,
    pub(crate) connectivity_probe: Option<crate::connectivity::ProbeHosts>,
}

fn present_nullable<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

impl SettingsPatch {
    pub fn apply(self, settings: &mut Settings) {
        if let Some(value) = self.mode {
            settings.mode = value;
        }
        if let Some(value) = self.daily_run_limit {
            settings.daily_run_limit = value;
        }
        if let Some(value) = self.daily_token_limit {
            settings.daily_token_limit = value;
        }
        if let Some(value) = self.run_token_limit {
            settings.run_token_limit = value;
        }
        if let Some(value) = self.auto_agent {
            settings.auto_agent = value;
        }
        if let Some(value) = self.log_poll_seconds {
            settings.log_poll_seconds = value;
        }
        if let Some(value) = self.poll_seconds {
            settings.poll_seconds = value;
        }
        if let Some(value) = self.concurrency {
            settings.concurrency = value;
        }
        if let Some(value) = self.paused {
            settings.paused = value;
        }
        if let Some(value) = self.connectivity_probe {
            settings.connectivity_probe = value;
        }
    }
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: "manual".into(),
            daily_run_limit: Some(0),
            daily_token_limit: Some(0),
            run_token_limit: 0,
            auto_agent: default_agent(),
            log_poll_seconds: 600,
            poll_seconds: 180,
            concurrency: 4,
            paused: false,
            connectivity_probe: Default::default(),
        }
    }
}
impl Settings {
    pub(crate) fn daily_runs_cap(&self) -> Option<u32> {
        self.daily_run_limit.filter(|&limit| limit != 0)
    }
    pub(crate) fn daily_tokens_cap(&self) -> Option<u64> {
        self.daily_token_limit.filter(|&limit| limit != 0)
    }
    pub fn validate(&self) -> Result<(), String> {
        if !["manual", "auto"].contains(&self.mode.as_str()) {
            return Err("Unknown automation mode".into());
        }
        if !["codex", "claude"].contains(&self.auto_agent.as_str()) {
            return Err("Choose Codex or Claude".into());
        }
        // Match the integer precision of the JavaScript settings API.
        if self.run_token_limit > (1u64 << 53) - 1 {
            return Err(
                "Enter a whole number of tokens per run within the supported range.".into(),
            );
        }
        if self.daily_runs_cap().is_some_and(|v| v > 1000)
            || self
                .daily_tokens_cap()
                .is_some_and(|v| !(1_000..=1_000_000_000).contains(&v))
        {
            return Err("Enter 1 to 1,000 runs per day or 1,000 to 1,000,000 tokens per day. Set either limit to 0 for no limit.".into());
        }
        if !(60..=86400).contains(&self.log_poll_seconds) {
            return Err("Enter a log check interval from 60 to 86,400 seconds.".into());
        }
        if !(30..=86400).contains(&self.poll_seconds) || !(1..=16).contains(&self.concurrency) {
            return Err("Interval: 30–86400 seconds; parallelism: 1–16".into());
        }
        self.connectivity_probe.validate()
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub offline: bool,
    pub awaiting_first_check: Vec<String>,
    pub pending_actions: u64,
    pub monitoring: std::collections::BTreeMap<String, crate::monitoring::Values>,
    pub services: std::collections::BTreeMap<String, Vec<crate::services::Card>>,
    pub check_status: std::collections::BTreeMap<String, String>,
    pub vulnerabilities: std::collections::BTreeMap<String, crate::vulnerabilities::Card>,
    pub log_status: std::collections::BTreeMap<String, String>,
    pub servers: Vec<Server>,
    pub sources: Vec<Source>,
    pub incidents: Vec<Incident>,
    pub settings: Settings,
    pub collected_at: i64,
}
