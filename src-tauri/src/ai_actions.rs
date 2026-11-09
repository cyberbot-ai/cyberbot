//! Immutable supervised action requests. Neither the model nor a grant can bypass these gates.
use std::sync::OnceLock;
use tauri::Emitter;
static EVENTS: OnceLock<tauri::AppHandle> = OnceLock::new();
pub(crate) fn install_events(app: tauri::AppHandle) {
    let _ = EVENTS.set(app);
}
pub(crate) fn changed(id: &str) {
    if let Some(app) = EVENTS.get() {
        let _ = app.emit("action-changed", id);
        let _ = app.emit("state-changed", ());
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Storage {
    pub bytes: u64,
    pub limit_bytes: u64,
    pub records: u64,
    pub active: u64,
    pub history_days: u64,
}
pub(crate) fn storage(db: &Connection) -> Result<Storage> {
    let (bytes,records,active)=db.query_row("SELECT coalesce(sum(length(CAST(payload AS BLOB))),0),count(*),coalesce(sum(state IN('proposed','validating','reviewing','awaitingApproval','approved','queued','running','rollbackRunning')),0) FROM ai_requests",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(err)?;
    Ok(Storage {
        bytes,
        limit_bytes: ARTIFACT_LIMIT as u64,
        records,
        active,
        history_days: 7,
    })
}
mod window;
pub(crate) use window::{approval_label, open_approval};
mod runtime;
mod smoke;
use crate::{
    agents::Investigation,
    ai_models::Selection,
    model::{now, Server},
    store::Store,
};
pub(crate) use runtime::{cached, reconcile, rollback, submit};
pub use runtime::{Runtime, WaitClock};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
pub(crate) use smoke::approval_fixture;
pub(crate) use smoke::run as smoke;
use std::collections::BTreeMap;
pub const RULES: &str = "actions-v1";
const ACTIVE_LIMIT: usize = 20;
const ARTIFACT_LIMIT: usize = 32 * 1024 * 1024;
const ROW_LIMIT: usize = 98304;
pub const WAIT_SECONDS: i64 = 600;
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Diagnostic,
    Shell,
    NginxWorkers {
        #[serde(rename = "workerProcesses")]
        worker_processes: String,
        activation: Activation,
    },
}
impl Action {
    pub fn capability(&self) -> String {
        match self {
            Self::Diagnostic => "diagnostic".into(),
            Self::Shell => "shell".into(),
            Self::NginxWorkers { activation, .. } => crate::nginx::worker_capability(activation),
        }
    }
    fn supports_rollback(&self) -> bool {
        matches!(self, Self::NginxWorkers { .. })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Activation {
    None,
    Reload,
    Restart,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Input {
    Metrics,
    Logs,
    Nginx,
    Service {
        service: String,
        #[serde(rename = "instanceId")]
        instance_id: String,
    },
    Postgresql {
        #[serde(rename = "instanceId")]
        instance_id: String,
    },
}
impl Input {
    fn service_target(&self) -> Option<(&str, &str)> {
        match self {
            Self::Metrics | Self::Logs => None,
            Self::Service {
                service,
                instance_id,
            } => Some((service, instance_id)),
            // Preserve the serialized names in saved and signed artifacts.
            Self::Nginx => Some(("nginx", crate::instances::DEFAULT)),
            Self::Postgresql { instance_id } => Some(("postgresql", instance_id)),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Spec {
    pub server_id: String,
    pub goal: String,
    pub code: String,
    pub inputs: Vec<Input>,
    pub action: Action,
    pub rollback_plan: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ShellSpec {
    server_id: String,
    goal: String,
    script: String,
}

impl From<ShellSpec> for Spec {
    fn from(shell: ShellSpec) -> Self {
        Self {
            server_id: shell.server_id,
            goal: shell.goal,
            code: shell.script,
            inputs: Vec::new(),
            action: Action::Shell,
            rollback_plan: String::new(),
        }
    }
}
impl Spec {
    pub fn validate(&self) -> Result<()> {
        if self.goal.trim().is_empty()
            || self.goal.len() > 1000
            || self.code.trim().is_empty()
            || self.code.len() > 16384
            || self.rollback_plan.len() > 1000
            || self.inputs.len() > 4
            || self.server_id.len() > 128
            || serde_json::to_vec(self).map_err(err)?.len() > 24576
        {
            return Err(
                "Request: target up to 1000 bytes, script up to 16 KiB, up to 4 sources".into(),
            );
        }
        if matches!(self.action, Action::Shell)
            && (!self.inputs.is_empty() || !self.rollback_plan.is_empty() || self.code.chars().any(|c| {
                c.is_control() && !matches!(c, '\n' | '\t') || matches!(c, '\u{061c}' | '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            }))
        {
            return Err("The shell request contains invalid parameters".into());
        }
        for (service, instance) in self.inputs.iter().filter_map(Input::service_target) {
            if crate::services::descriptor(service).is_none() || instance.len() > 64 {
                return Err("Unknown service or instance".into());
            }
        }
        if let Action::NginxWorkers {
            worker_processes, ..
        } = &self.action
        {
            crate::nginx::validate_workers(worker_processes)?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Artifact {
    #[serde(default)]
    pub transport: Option<crate::ssh_authorization::Stamp>,
    #[serde(default)]
    pub scope_transport_hash: String,
    pub run_id: String,
    pub scope_endpoints: BTreeMap<String, String>,
    pub rules: String,
    pub provider: String,
    pub profile: Selection,
    pub endpoint: String,
    pub spec: Spec,
    pub inputs: Value,
    pub prepared: Value,
    pub isolation: Value,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    pub id: String,
    pub run_id: String,
    pub server_id: String,
    pub server_label: String,
    pub intent_hash: String,
    pub artifact_hash: String,
    pub artifact: Artifact,
    pub state: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub updated_at: i64,
    pub review: Option<Review>,
    pub decision: Option<String>,
    pub result: Option<Value>,
    pub error: Option<String>,
    pub notified: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Verdict {
    pub decision: Decision,
    pub explanation: String,
    pub effects: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Confirm,
    Deny,
    Uncertain,
}
impl Decision {
    fn allows_approval(&self) -> bool {
        matches!(self, Self::Allow | Self::Confirm)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Review {
    #[serde(default)]
    pub duration_ms: u64,
    pub id: String,
    pub verdict: Verdict,
    pub model: Option<String>,
    pub usage: Value,
    pub usage_complete: bool,
    pub tokens: u64,
}
#[derive(Clone, Serialize, Deserialize)]
struct Grant {
    run_id: String,
    endpoints: BTreeMap<String, String>,
    profile_revision: u64,
    capabilities: Vec<String>,
    #[serde(default)]
    transport_hash: String,
    rules: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Card {
    pub id: String,
    pub run_id: String,
    pub server_id: String,
    pub server_label: String,
    pub goal: String,
    pub state: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub action: Action,
    pub review: Option<Review>,
    pub artifact_hash: String,
    pub error: Option<String>,
    pub session_granted: bool,
}
fn active(state: &str) -> bool {
    matches!(
        state,
        "proposed"
            | "validating"
            | "reviewing"
            | "awaitingApproval"
            | "approved"
            | "queued"
            | "running"
            | "rollbackRunning"
    )
}
fn digest(v: &impl Serialize) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(v).map_err(err)?)
    ))
}
pub fn migrate(db: &Connection) -> Result<()> {
    db.execute_batch("BEGIN IMMEDIATE;
 CREATE TABLE IF NOT EXISTS ai_requests(id TEXT PRIMARY KEY,run_id TEXT NOT NULL,server_id TEXT NOT NULL,intent_hash TEXT NOT NULL,state TEXT NOT NULL,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,payload TEXT NOT NULL,UNIQUE(run_id,intent_hash));
 CREATE INDEX IF NOT EXISTS ai_requests_state ON ai_requests(state,updated_at);
 CREATE TABLE IF NOT EXISTS ai_action_grants(run_id TEXT PRIMARY KEY,payload TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS ai_children(id TEXT PRIMARY KEY REFERENCES ai_ledger(id) ON DELETE CASCADE,parent_id TEXT NOT NULL,request_id TEXT NOT NULL UNIQUE);
 PRAGMA user_version=16; COMMIT;").map_err(err)
}
fn read(db: &Connection, id: &str) -> Result<Request> {
    if uuid::Uuid::parse_str(id).is_err() {
        return Err("Invalid request ID".into());
    }
    let payload: String = db
        .query_row("SELECT payload FROM ai_requests WHERE id=?1", [id], |r| {
            r.get(0)
        })
        .map_err(|_| "The request no longer exists")?;
    serde_json::from_str(&payload).map_err(err)
}
fn active_rows(db: &Connection) -> Result<Vec<Request>> {
    let mut statement=db.prepare("SELECT payload FROM ai_requests WHERE state IN('proposed','validating','reviewing','awaitingApproval','approved','queued','running','rollbackRunning')").map_err(err)?;
    let result = statement
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(err)?
        .map(|r| serde_json::from_str(&r.map_err(err)?).map_err(err))
        .collect();
    result
}
fn persist(db: &Connection, r: &Request) -> Result<()> {
    let payload = serde_json::to_string(r).map_err(err)?;
    if payload.len() > ROW_LIMIT {
        return Err("Action data exceeds 96 KiB".into());
    }
    db.execute("INSERT INTO ai_requests VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(id) DO UPDATE SET state=excluded.state,updated_at=excluded.updated_at,payload=excluded.payload",params![r.id,r.run_id,r.server_id,r.intent_hash,r.state,r.created_at,r.expires_at,r.updated_at,payload]).map_err(err)?;
    Ok(())
}
fn context(db: &Connection, r: &Request, at: i64) -> Result<Investigation> {
    context_with_ttl(db, r, at, true)
}
fn context_with_ttl(
    db: &Connection,
    r: &Request,
    at: i64,
    check_ttl: bool,
) -> Result<Investigation> {
    if check_ttl && r.expires_at <= at || r.artifact.rules != RULES {
        return Err("The request expired or the action policy changed".into());
    }
    let payload: String = db
        .query_row(
            "SELECT payload FROM investigations WHERE id=?1",
            [&r.run_id],
            |row| row.get(0),
        )
        .map_err(|_| "The AI run was removed")?;
    let run: Investigation = serde_json::from_str(&payload).map_err(err)?;
    if run.started_at.saturating_add(900) <= at
        || run.status != "running"
        || run.authoring_id.is_some()
        || matches!(r.artifact.spec.action, Action::Shell) && run.origin != "manual"
        || run.agent != r.artifact.provider
        || run.scope_endpoints.get(&r.server_id) != Some(&r.artifact.endpoint)
        || run.id != r.artifact.run_id
        || run.scope_endpoints != r.artifact.scope_endpoints
    {
        return Err("The AI run has an invalid server list".into());
    }
    if !r.artifact_hash.is_empty() && digest(&r.artifact)? != r.artifact_hash {
        return Err("Artifact hash doesn’t match".into());
    }
    for (id, expected) in &run.scope_endpoints {
        let payload: String = db
            .query_row("SELECT payload FROM servers WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .map_err(|_| "A server in scope was removed")?;
        let server: Server = serde_json::from_str(&payload).map_err(err)?;
        if serde_json::to_string(&server.endpoint).map_err(err)? != *expected {
            return Err("Connection settings changed for a server in scope".into());
        }
    }
    let server: Option<String> = db
        .query_row(
            "SELECT payload FROM servers WHERE id=?1",
            [&r.server_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(err)?;
    let server: Server =
        serde_json::from_str(&server.ok_or("The server is remote")?).map_err(err)?;
    if serde_json::to_string(&server.endpoint).map_err(err)? != r.artifact.endpoint {
        return Err("The server connection has changed".into());
    }
    let unknown:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM ai_requests WHERE run_id=?1 AND id!=?2 AND state IN('unknown','rollbackUnknown'))",params![r.run_id,r.id],|row|row.get(0)).map_err(err)?;
    if unknown {
        return Err(
            "This run has an action with an unconfirmed result. Check its saved result.".into(),
        );
    }
    if r.artifact.transport.as_ref().is_none_or(|s| !s.unchanged()) {
        return Err("The SSH context changed or was not saved".into());
    }
    let profile = crate::ai_models::read(db)?;
    if profile.revision != r.artifact.profile.revision
        || profile.providers.get(&run.agent).and_then(|p| p.get("low"))
            != Some(&r.artifact.profile.low)
    {
        return Err("The review profile changed. Start a new run.".into());
    }
    Ok(run)
}
fn granted(db: &Connection, r: &Request, at: i64) -> Result<bool> {
    let Some(payload) = db
        .query_row(
            "SELECT payload FROM ai_action_grants WHERE run_id=?1",
            [&r.run_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(err)?
    else {
        return Ok(false);
    };
    let grant: Grant = serde_json::from_str(&payload).map_err(err)?;
    let run = context_with_ttl(db, r, at, false)?;
    Ok(grant.rules == RULES
        && grant.profile_revision == r.artifact.profile.revision
        && grant.endpoints == run.scope_endpoints
        && grant.transport_hash == r.artifact.scope_transport_hash
        && grant
            .capabilities
            .contains(&r.artifact.spec.action.capability()))
}
pub(crate) fn trim(db: &Connection, at: i64) -> Result<()> {
    let rows = active_rows(db)?;
    for mut r in rows
        .into_iter()
        .filter(|r| active(&r.state) && r.expires_at <= at)
    {
        r.state = if matches!(r.state.as_str(), "running" | "rollbackRunning") {
            "unknown"
        } else {
            "expired"
        }
        .into();
        r.updated_at = at;
        r.error = Some("The request expired and cannot be run again".into());
        persist(db, &r)?;
    }
    db.execute("DELETE FROM ai_requests WHERE id IN(SELECT id FROM ai_requests WHERE state NOT IN('proposed','validating','reviewing','awaitingApproval','approved','queued','running','rollbackRunning') AND (updated_at<?1 OR id NOT IN(SELECT id FROM ai_requests ORDER BY updated_at DESC,rowid DESC LIMIT 1000)) LIMIT 100)",[at-7*86400]).map_err(err)?;
    db.execute("DELETE FROM ai_action_grants WHERE run_id NOT IN(SELECT id FROM investigations WHERE json_extract(payload,'$.status')='running')",[]).map_err(err)?;
    loop {
        let bytes:i64=db.query_row("SELECT coalesce(sum(CASE WHEN state IN('proposed','validating','reviewing','awaitingApproval','approved','queued','running','rollbackRunning') THEN 98304 ELSE length(CAST(payload AS BLOB)) END),0) FROM ai_requests",[],|r|r.get(0)).map_err(err)?;
        if bytes as usize <= ARTIFACT_LIMIT - ROW_LIMIT {
            break;
        }
        let deleted=db.execute("DELETE FROM ai_requests WHERE id IN(SELECT id FROM ai_requests WHERE state NOT IN('proposed','validating','reviewing','awaitingApproval','approved','queued','running','rollbackRunning') ORDER BY updated_at,rowid LIMIT 1)",[]).map_err(err)?;
        if deleted == 0 {
            return Err("AI action storage limit of 32 MiB reached".into());
        }
    }
    Ok(())
}
impl Store {
    pub(crate) fn action_request(&self, id: &str) -> Result<Request> {
        read(&*self.0.lock().map_err(err)?, id)
    }
    pub(crate) fn action_cards(
        &self,
        run: Option<&str>,
        server: Option<&str>,
    ) -> Result<Vec<Card>> {
        let db = self.0.lock().map_err(err)?;
        let mut statement = db
            .prepare(
                "SELECT payload FROM ai_requests
                 WHERE (?1 IS NULL OR run_id=?1) AND (?2 IS NULL OR server_id=?2)
                 ORDER BY CASE WHEN ?1 IS NULL AND ?2 IS NULL AND state='awaitingApproval'
                               THEN 0 ELSE 1 END,
                          created_at DESC, rowid DESC
                 LIMIT 50",
            )
            .map_err(err)?;
        let rows = statement
            .query_map(params![run, server], |r| r.get::<_, String>(0))
            .map_err(err)?
            .map(|r| serde_json::from_str::<Request>(&r.map_err(err)?).map_err(err))
            .collect::<Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|r| {
                Ok(Card {
                    id: r.id.clone(),
                    run_id: r.run_id.clone(),
                    server_id: r.server_id.clone(),
                    server_label: r.server_label.clone(),
                    goal: r.artifact.spec.goal.clone(),
                    state: r.state.clone(),
                    created_at: r.created_at,
                    expires_at: r.expires_at,
                    action: r.artifact.spec.action.clone(),
                    review: r.review.clone(),
                    artifact_hash: r.artifact_hash.clone(),
                    error: r.error.clone(),
                    session_granted: granted(&db, &r, now()).unwrap_or(false),
                })
            })
            .collect()
    }
    pub(crate) fn action_propose(
        &self,
        run: &Investigation,
        spec: Spec,
        inputs: Value,
        transport: crate::ssh_authorization::Stamp,
        scope_transport_hash: String,
        at: i64,
    ) -> Result<(Request, bool)> {
        spec.validate()?;
        if serde_json::to_vec(&inputs).map_err(err)?.len() > 24576 {
            return Err("Script inputs exceed 24KB; select fewer sources".into());
        }
        let profile = run
            .model_profile
            .clone()
            .ok_or("This run has no model profile")?;
        let endpoint = run
            .scope_endpoints
            .get(&spec.server_id)
            .ok_or("The server is outside this run’s scope")?
            .clone();
        let intent = if matches!(spec.action, Action::Shell) {
            digest(&json!({"shell":spec.code,"endpoint":endpoint,"profile":profile,"rules":RULES}))?
        } else {
            digest(&json!({"spec":spec,"endpoint":endpoint,"profile":profile,"rules":RULES}))?
        };
        let mut db = self.0.lock().map_err(err)?;
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(err)?;
        if let Some(payload) = tx
            .query_row(
                "SELECT payload FROM ai_requests WHERE run_id=?1 AND intent_hash=?2",
                params![run.id, intent],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(err)?
        {
            return Ok((serde_json::from_str(&payload).map_err(err)?, false));
        }
        trim(&tx, at)?;
        let count:i64=tx.query_row("SELECT count(*) FROM ai_requests WHERE state IN('proposed','validating','reviewing','awaitingApproval','approved','queued','running','rollbackRunning')",[],|r|r.get(0)).map_err(err)?;
        if count as usize >= ACTIVE_LIMIT {
            return Err("No more than 20 active requests".into());
        }
        let r = Request {
            id: uuid::Uuid::new_v4().to_string(),
            run_id: run.id.clone(),
            server_id: spec.server_id.clone(),
            server_label: String::new(),
            intent_hash: intent,
            artifact_hash: String::new(),
            artifact: Artifact {
                transport: Some(transport),
                scope_transport_hash,
                run_id: run.id.clone(),
                scope_endpoints: run.scope_endpoints.clone(),
                rules: RULES.into(),
                provider: run.agent.clone(),
                profile,
                endpoint,
                spec,
                inputs,
                prepared: Value::Null,
                isolation: Value::Null,
            },
            state: "proposed".into(),
            created_at: at,
            expires_at: at + WAIT_SECONDS,
            updated_at: at,
            review: None,
            decision: None,
            result: None,
            error: None,
            notified: false,
        };
        context(&tx, &r, at)?;
        let mut r = r;
        let server: String = tx
            .query_row(
                "SELECT payload FROM servers WHERE id=?1",
                [&r.server_id],
                |row| row.get(0),
            )
            .map_err(err)?;
        let server: Server = serde_json::from_str(&server).map_err(err)?;
        r.server_label = format!("{} · {}", server.name, crate::ssh::target(&server.endpoint));
        persist(&tx, &r)?;
        tx.commit().map_err(err)?;
        Ok((r, true))
    }
    pub(crate) fn action_freeze(
        &self,
        id: &str,
        prepared: Value,
        isolation: Value,
        at: i64,
    ) -> Result<Request> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        let mut r = read(&tx, id)?;
        context(&tx, &r, at)?;
        if r.state != "proposed" {
            return Err("The request is already under review".into());
        }
        if prepared["kind"] != serde_json::to_value(&r.artifact.spec.action).map_err(err)?["kind"] {
            return Err("The action plan changed".into());
        }
        let valid = if matches!(r.artifact.spec.action, Action::Shell) {
            isolation
                == json!({"engine":"ssh-shell-v1","rules":RULES,"wallSeconds":15,"outputBytes":8192})
                && prepared["uid"].as_u64().is_some()
                && prepared["user"]
                    .as_str()
                    .is_some_and(|user| !user.is_empty() && user.len() <= 128)
        } else {
            isolation["available"] == true
                && isolation["engine"] == "python-seccomp-v1"
                && isolation["rules"] == RULES
                && isolation["files"] == false
                && isolation["network"] == false
                && isolation["processes"] == false
                && isolation["wallSeconds"] == 8
                && isolation["cpuSeconds"] == 4
                && isolation["outputBytes"] == 16384
                && isolation["memoryBytes"] == 100663296
        };
        if !valid || prepared.to_string().len() > 8192 {
            return Err("The server did not confirm the execution parameters".into());
        }
        r.artifact.prepared = prepared;
        r.artifact.isolation = isolation;
        r.artifact_hash = digest(&r.artifact)?;
        r.state = "reviewing".into();
        r.updated_at = at;
        persist(&tx, &r)?;
        tx.commit().map_err(err)?;
        Ok(r)
    }
    pub(crate) fn action_reviewed(&self, id: &str, review: Review, at: i64) -> Result<Request> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        let mut r = read(&tx, id)?;
        context(&tx, &r, at)?;
        if r.state != "reviewing" {
            return Err("Request validation cancelled".into());
        }
        if review.verdict.explanation.len() > 2000
            || review.verdict.effects.len() > 16
            || review.verdict.effects.iter().any(|x| x.len() > 384)
        {
            return Err("Risk review response is too large".into());
        }
        r.state = match review.verdict.decision {
            Decision::Allow if granted(&tx, &r, at)? => "approved",
            Decision::Allow | Decision::Confirm => "awaitingApproval",
            Decision::Deny | Decision::Uncertain => "denied",
        }
        .into();
        r.review = Some(review);
        r.updated_at = at;
        persist(&tx, &r)?;
        tx.commit().map_err(err)?;
        Ok(r)
    }
    pub(crate) fn action_decide(
        &self,
        id: &str,
        hash: &str,
        decision: &str,
        at: i64,
    ) -> Result<Request> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(err)?;
        let mut r = read(&tx, id)?;
        let run = context(&tx, &r, at)?;
        if r.artifact_hash != hash || r.state != "awaitingApproval" {
            return Err("The request has changed or the decision has been made".into());
        }
        let verdict = &r
            .review
            .as_ref()
            .ok_or("Risk review result is missing")?
            .verdict
            .decision;
        if !verdict.allows_approval() {
            return Err("The risk review did not clear this action for approval".into());
        }
        if !matches!(decision, "deny" | "once" | "session") {
            return Err("Unknown approval decision".into());
        }
        if decision == "session" && *verdict == Decision::Confirm {
            return Err("This action requires one-time approval".into());
        }
        if decision == "session" {
            let capabilities = if matches!(r.artifact.spec.action, Action::Shell) {
                vec!["shell".into()]
            } else {
                std::iter::once("diagnostic".into())
                    .chain(crate::services::session_capabilities().map(str::to_owned))
                    .collect()
            };
            let mut grant = Grant {
                run_id: r.run_id.clone(),
                endpoints: run.scope_endpoints,
                profile_revision: r.artifact.profile.revision,
                transport_hash: r.artifact.scope_transport_hash.clone(),
                capabilities,
                rules: RULES.into(),
            };
            let prior: Option<String> = tx
                .query_row(
                    "SELECT payload FROM ai_action_grants WHERE run_id=?1",
                    [&r.run_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(err)?;
            if let Some(prior) = prior {
                let prior: Grant = serde_json::from_str(&prior).map_err(err)?;
                if prior.rules == grant.rules
                    && prior.profile_revision == grant.profile_revision
                    && prior.endpoints == grant.endpoints
                    && prior.transport_hash == grant.transport_hash
                {
                    grant.capabilities.extend(prior.capabilities);
                    grant.capabilities.sort();
                    grant.capabilities.dedup();
                }
            }
            tx.execute("INSERT INTO ai_action_grants VALUES(?1,?2) ON CONFLICT(run_id) DO UPDATE SET payload=excluded.payload",params![r.run_id,serde_json::to_string(&grant).map_err(err)?]).map_err(err)?;
        }
        r.state = if decision == "deny" {
            "denied"
        } else {
            "approved"
        }
        .into();
        r.decision = Some(decision.into());
        r.updated_at = at;
        persist(&tx, &r)?;
        tx.commit().map_err(err)?;
        Ok(r)
    }
    pub(crate) fn action_transition(
        &self,
        id: &str,
        from: &str,
        to: &str,
        at: i64,
    ) -> Result<Request> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        let mut r = read(&tx, id)?;
        context(&tx, &r, at)?;
        if r.state != from
            || !matches!(
                (from, to),
                ("approved", "queued") | ("queued", "running") | ("succeeded", "rollbackRunning")
            )
        {
            return Err("The status of the request has changed".into());
        }
        if matches!(to, "queued" | "running")
            && !r.review.as_ref().is_some_and(|v| match v.verdict.decision {
                Decision::Allow => true,
                Decision::Confirm => r.decision.as_deref() == Some("once"),
                Decision::Deny | Decision::Uncertain => false,
            })
        {
            return Err("This action lacks a passing risk review".into());
        }
        r.state = to.into();
        r.updated_at = at;
        persist(&tx, &r)?;
        tx.commit().map_err(err)?;
        Ok(r)
    }
    pub(crate) fn action_result(
        &self,
        id: &str,
        state: &str,
        result: Option<Value>,
        error: Option<String>,
        at: i64,
    ) -> Result<Request> {
        if !matches!(
            state,
            "succeeded"
                | "failed"
                | "denied"
                | "cancelled"
                | "expired"
                | "unknown"
                | "rolledBack"
                | "rollbackUnknown"
        ) {
            return Err("Expected outcome".into());
        }
        self.finish_action(id, result, error, at, |_| state)
            .map(|(request, _)| request)
    }
    pub(crate) fn interrupt_action(
        &self,
        id: &str,
        before_start: &str,
        error: String,
        at: i64,
    ) -> Result<(Request, bool)> {
        self.finish_action(id, None, Some(error), at, |request| {
            match request.state.as_str() {
                "running" => "unknown",
                "rollbackRunning" => "rollbackUnknown",
                _ => before_start,
            }
        })
    }
    fn finish_action<'a>(
        &self,
        id: &str,
        result: Option<Value>,
        error: Option<String>,
        at: i64,
        terminal_state: impl FnOnce(&Request) -> &'a str,
    ) -> Result<(Request, bool)> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        let mut r = read(&tx, id)?;
        if !active(&r.state) {
            return Ok((r, false));
        }
        let state = terminal_state(&r);
        if result.as_ref().is_some_and(|v| v.to_string().len() > 32768) {
            return Err("The response is more than 32 kB".into());
        }
        if matches!(state, "unknown" | "rollbackUnknown") {
            tx.execute("DELETE FROM ai_action_grants WHERE run_id=?1", [&r.run_id])
                .map_err(err)?;
        }
        r.state = state.into();
        r.result = result;
        r.error = error.map(|e| e.chars().take(1000).collect());
        r.updated_at = at;
        persist(&tx, &r)?;
        trim(&tx, at)?;
        tx.commit().map_err(err)?;
        Ok((r, true))
    }
    pub(crate) fn action_revoke(&self, run_id: &str, at: i64) -> Result<Vec<String>> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        tx.execute("DELETE FROM ai_action_grants WHERE run_id=?1", [run_id])
            .map_err(err)?;
        let rows = active_rows(&tx)?;
        let mut ids = Vec::new();
        for mut r in rows
            .into_iter()
            .filter(|r| r.run_id == run_id && active(&r.state) && r.state != "rollbackRunning")
        {
            r.state = if matches!(r.state.as_str(), "running" | "rollbackRunning") {
                "unknown"
            } else {
                "cancelled"
            }
            .into();
            r.error = Some(
                "Approval was revoked. Verify the effects of any action that already started."
                    .into(),
            );
            r.updated_at = at;
            persist(&tx, &r)?;
            ids.push(r.id);
        }
        tx.commit().map_err(err)?;
        Ok(ids)
    }
    pub(crate) fn recover_actions(&self) -> Result<()> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        tx.execute("DELETE FROM ai_action_grants", [])
            .map_err(err)?;
        for mut r in active_rows(&tx)?.into_iter().filter(|r| active(&r.state)) {
            r.state = if matches!(r.state.as_str(), "running" | "rollbackRunning") {
                "unknown"
            } else {
                "cancelled"
            }
            .into();
            r.error =
                Some("Cyberbot restarted. The action will not run again automatically.".into());
            r.updated_at = now();
            persist(&tx, &r)?;
        }
        tx.execute("UPDATE ai_ledger SET state='uncertain',charged=max(charged,reserved) WHERE state='running' AND id IN(SELECT id FROM ai_children)",[]).map_err(err)?;
        trim(&tx, now())?;
        tx.commit().map_err(err)
    }
    pub(crate) fn action_context(&self, id: &str, at: i64) -> Result<()> {
        let db = self.0.lock().map_err(err)?;
        context(&db, &read(&db, id)?, at).map(|_| ())
    }
}

mod budget;
pub(crate) use budget::review_charged;

impl Store {
    pub(crate) fn mark_action_notified(&self, id: &str) -> Result<bool> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        let mut r = read(&tx, id)?;
        if r.state != "awaitingApproval" || r.notified {
            return Ok(false);
        }
        r.notified = true;
        persist(&tx, &r)?;
        tx.commit().map_err(err)?;
        Ok(true)
    }
    pub(crate) fn action_reconciled(
        &self,
        id: &str,
        state: &str,
        result: Value,
        at: i64,
    ) -> Result<Request> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        let mut r = read(&tx, id)?;
        if !matches!(r.state.as_str(), "unknown" | "rollbackUnknown")
            || !matches!(
                state,
                "unknown" | "succeeded" | "failed" | "rolledBack" | "rollbackUnknown"
            )
        {
            return Err("The result is already saved or unknown".into());
        }
        r.state = if state == "unknown" && r.state == "rollbackUnknown" {
            "rollbackUnknown"
        } else {
            state
        }
        .into();
        r.result = Some(result);
        r.updated_at = at;
        r.error = matches!(state, "unknown" | "rollbackUnknown").then(|| {
            "The action broker has not confirmed the result. Check the saved result before taking further action.".into()
        });
        persist(&tx, &r)?;
        trim(&tx, at)?;
        tx.commit().map_err(err)?;
        Ok(r)
    }
    pub(crate) fn begin_action_rollback(&self, id: &str, hash: &str, at: i64) -> Result<Request> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(err)?;
        let mut r = read(&tx, id)?;
        if r.state != "succeeded"
            || r.artifact_hash != hash
            || digest(&r.artifact)? != hash
            || r.artifact.rules != RULES
            || !r.artifact.spec.action.supports_rollback()
            || r.result
                .as_ref()
                .is_none_or(|v| v["effect"]["rollbackAvailable"] != true)
            || r.updated_at < at - 7 * 86400
        {
            return Err("Rollback is unavailable or expired, or the saved result changed".into());
        }
        let payload: String = tx
            .query_row(
                "SELECT payload FROM servers WHERE id=?1",
                [&r.server_id],
                |row| row.get(0),
            )
            .map_err(|_| "The server is remote")?;
        let server: Server = serde_json::from_str(&payload).map_err(err)?;
        if serde_json::to_string(&server.endpoint).map_err(err)? != r.artifact.endpoint {
            return Err("The connection changed, so rollback was blocked".into());
        }
        r.state = "rollbackRunning".into();
        r.expires_at = at + 60;
        r.updated_at = at;
        tx.execute("DELETE FROM ai_action_grants WHERE run_id=?1", [&r.run_id])
            .map_err(err)?;
        persist(&tx, &r)?;
        tx.commit().map_err(err)?;
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Store, Investigation) {
        fixture_with_limit(50_000)
    }
    fn fixture_with_limit(run_token_limit: u64) -> (Store, Investigation) {
        let db = Store::open(std::path::Path::new(":memory:")).unwrap();
        db.save_settings(&crate::model::Settings {
            run_token_limit,
            ..crate::model::Settings::default()
        })
        .unwrap();
        let source = crate::model::Source {
            id: "fixture".into(),
            name: "fixture".into(),
            kind: "manual".into(),
            location: "ops@node".into(),
            last_sync: None,
            error: None,
        };
        db.import(&source, crate::inventory::parse_manual("ops@node").unwrap())
            .unwrap();
        let server = db.snapshot().unwrap().servers.remove(0);
        let run = Investigation {
            usage_started: false,
            scope_endpoints: [(
                server.id.clone(),
                serde_json::to_string(&server.endpoint).unwrap(),
            )]
            .into(),
            group_id: None,
            authoring_id: None,
            origin: "manual".into(),
            usage_complete: false,
            id: uuid::Uuid::new_v4().to_string(),
            agent: "codex".into(),
            server_ids: vec![server.id],
            question: "check".into(),
            status: "running".into(),
            started_at: 100,
            ended_at: None,
            text: String::new(),
            error: None,
            usage: json!({}),
            audit: vec![],
            chat: None,
            session_id: None,
            model_profile: Some(db.ai_selection("codex", "medium").unwrap()),
            actual_model: None,
        };
        db.admit(&run, None).unwrap();
        (db, run)
    }
    fn spec(run: &Investigation, goal: &str) -> Spec {
        Spec {
            server_id: run.server_ids[0].clone(),
            goal: goal.into(),
            code: "result = sum(inputs['values'])".into(),
            inputs: vec![Input::Metrics],
            action: Action::Diagnostic,
            rollback_plan: "Host is unchanged".into(),
        }
    }
    fn freeze(db: &Store, run: &Investigation, goal: &str) -> Request {
        let r = db
            .action_propose(
                run,
                spec(run, goal),
                json!({"values":[2,3]}),
                crate::ssh_authorization::fixture(),
                "fixture".into(),
                101,
            )
            .unwrap()
            .0;
        db.action_freeze(&r.id,json!({"kind":"diagnostic"}),json!({"available":true,"engine":"python-seccomp-v1","rules":RULES,"files":false,"network":false,"processes":false,"wallSeconds":8,"cpuSeconds":4,"outputBytes":16384,"memoryBytes":100663296}),102).unwrap()
    }
    fn review(db: &Store, r: &Request, decision: Decision) -> Request {
        db.action_reviewed(
            &r.id,
            Review {
                id: uuid::Uuid::new_v4().to_string(),
                verdict: Verdict {
                    decision,
                    explanation: "bounded".into(),
                    effects: vec![],
                },
                model: Some("test-low".into()),
                usage: json!({"inputTokens":10}),
                usage_complete: true,
                tokens: 10,
                duration_ms: 0,
            },
            103,
        )
        .unwrap()
    }
    #[test]
    fn interruption_uses_the_current_state_and_preserves_terminal_results() {
        let (db, run) = fixture();
        let queue = |goal| {
            let request = review(&db, &freeze(&db, &run, goal), Decision::Allow);
            db.action_decide(&request.id, &request.artifact_hash, "once", 104)
                .unwrap();
            db.action_transition(&request.id, "approved", "queued", 105)
                .unwrap()
        };
        let queued = queue("queued");
        let (cancelled, changed) = db
            .interrupt_action(&queued.id, "cancelled", "cancelled".into(), 106)
            .unwrap();
        assert!(changed);
        assert_eq!(cancelled.state, "cancelled");
        assert!(db
            .action_transition(&queued.id, "queued", "running", 107)
            .is_err());

        let queued = queue("running");
        db.action_transition(&queued.id, "queued", "running", 106)
            .unwrap();
        let (unknown, changed) = db
            .interrupt_action(&queued.id, "cancelled", "cancelled".into(), 107)
            .unwrap();
        assert!(changed);
        assert_eq!(unknown.state, "unknown");
        let result = json!({"effect":{"verified":true}});
        db.action_reconciled(&queued.id, "succeeded", result.clone(), 108)
            .unwrap();
        let (completed, changed) = db
            .interrupt_action(&queued.id, "cancelled", "cancelled".into(), 109)
            .unwrap();
        assert!(!changed);
        assert_eq!(completed.state, "succeeded");
        assert_eq!(completed.result, Some(result));

        let rollback = queue("rollback");
        db.0.lock().unwrap().execute(
            "UPDATE ai_requests SET state='rollbackRunning',payload=json_set(payload,'$.state','rollbackRunning') WHERE id=?1",
            [&rollback.id],
        ).unwrap();
        let (unknown, _) = db
            .interrupt_action(&rollback.id, "cancelled", "cancelled".into(), 110)
            .unwrap();
        assert_eq!(unknown.state, "rollbackUnknown");
    }
    #[test]
    fn global_action_list_keeps_older_pending_requests_ahead_of_history() {
        let (db, run) = fixture();
        let pending = review(&db, &freeze(&db, &run, "pending"), Decision::Allow);
        assert_eq!(pending.state, "awaitingApproval");
        {
            let conn = db.0.lock().unwrap();
            for index in 1..=51 {
                let mut completed = pending.clone();
                completed.id = uuid::Uuid::new_v4().to_string();
                completed.intent_hash = format!("completed-{index}");
                completed.created_at += index;
                completed.state = "succeeded".into();
                persist(&conn, &completed).unwrap();
            }
        }

        let global = db.action_cards(None, None).unwrap();
        assert_eq!(global.len(), 50);
        assert_eq!(global[0].id, pending.id);
        assert_eq!(global[1].created_at, pending.created_at + 51);
        let scoped = db.action_cards(Some(&run.id), None).unwrap();
        assert_eq!(scoped.len(), 50);
        assert!(scoped.iter().all(|request| request.id != pending.id));
    }

    #[test]
    fn shell_grants_are_explicit_and_each_script_requires_review() {
        let (db, run) = fixture();
        let typed = review(&db, &freeze(&db, &run, "typed"), Decision::Allow);
        db.action_decide(&typed.id, &typed.artifact_hash, "session", 104)
            .unwrap();
        let shell =
            |code: &str| {
                let spec = Spec {
                    action: Action::Shell,
                    code: code.into(),
                    inputs: vec![],
                    rollback_plan: String::new(),
                    ..spec(&run, "shell")
                };
                let r = db
                    .action_propose(
                        &run,
                        spec,
                        json!([]),
                        crate::ssh_authorization::fixture(),
                        "fixture".into(),
                        101,
                    )
                    .unwrap()
                    .0;
                db.action_freeze(&r.id, json!({"kind":"shell","uid":0,"user":"root"}),
                json!({"engine":"ssh-shell-v1","rules":RULES,"wallSeconds":15,"outputBytes":8192}),
                102).unwrap()
            };
        let denied = review(&db, &shell("printf denied"), Decision::Allow);
        assert_eq!(denied.state, "awaitingApproval");
        let denied = db
            .action_decide(&denied.id, &denied.artifact_hash, "deny", 104)
            .unwrap();
        assert_eq!(denied.state, "denied");
        assert!(db
            .action_transition(&denied.id, "approved", "queued", 105)
            .is_err());
        let first = review(&db, &shell("printf one"), Decision::Allow);
        assert_eq!(first.state, "awaitingApproval");
        db.action_decide(&first.id, &first.artifact_hash, "session", 104)
            .unwrap();
        let second = shell("printf two");
        assert_eq!(second.state, "reviewing");
        assert_eq!(review(&db, &second, Decision::Allow).state, "approved");
        let update = review(
            &db,
            &shell("apt-get update && apt-get install --only-upgrade --no-remove python3.11"),
            Decision::Confirm,
        );
        assert_eq!(update.state, "awaitingApproval");
        assert!(db
            .action_decide(&update.id, &update.artifact_hash, "session", 104)
            .is_err());
        assert!(db.action_decide(&update.id, "wrong", "once", 104).is_err());
        assert!(db
            .action_transition(&update.id, "awaitingApproval", "queued", 104)
            .is_err());
        let update = db
            .action_decide(&update.id, &update.artifact_hash, "once", 104)
            .unwrap();
        assert_eq!(update.state, "approved");
        db.action_transition(&update.id, "approved", "queued", 105)
            .unwrap();
        db.action_transition(&update.id, "queued", "running", 106)
            .unwrap();
        for (code, decision) in [
            ("rm /srv/app.db", Decision::Deny),
            ("ufw allow from any to any port 5432", Decision::Deny),
            ("sh /tmp/uninspected-script", Decision::Uncertain),
        ] {
            let blocked = review(&db, &shell(code), decision);
            assert_eq!(blocked.state, "denied");
            assert!(db
                .action_decide(&blocked.id, &blocked.artifact_hash, "once", 104)
                .is_err());
            assert!(db
                .action_transition(&blocked.id, "approved", "queued", 105)
                .is_err());
        }
    }

    #[test]
    fn immutable_hash_once_cas_and_no_execution_without_both_gates() {
        let (db, run) = fixture();
        let r = freeze(&db, &run, "first");
        let duplicate = db
            .action_propose(
                &run,
                spec(&run, "first"),
                json!({"values":[999]}),
                crate::ssh_authorization::fixture(),
                "fixture".into(),
                104,
            )
            .unwrap();
        assert!(!duplicate.1);
        assert_eq!(duplicate.0.artifact.inputs, r.artifact.inputs);
        assert_eq!(duplicate.0.artifact_hash, r.artifact_hash);
        assert!(db
            .action_transition(&r.id, "reviewing", "running", 103)
            .is_err());
        let r = review(&db, &r, Decision::Allow);
        assert_eq!(r.state, "awaitingApproval");
        assert!(db.action_decide(&r.id, "wrong", "session", 104).is_err());
        let r = db
            .action_decide(&r.id, &r.artifact_hash, "once", 104)
            .unwrap();
        assert_eq!(r.state, "approved");
        assert!(db
            .action_decide(&r.id, &r.artifact_hash, "once", 104)
            .is_err());
        db.action_transition(&r.id, "approved", "queued", 105)
            .unwrap();
        db.action_transition(&r.id, "queued", "running", 106)
            .unwrap();
        assert!(db
            .action_transition(&r.id, "queued", "running", 106)
            .is_err());
    }
    #[test]
    fn deny_uncertain_and_profile_changes_cannot_be_overridden() {
        let (db, run) = fixture();
        for (goal, decision) in [("deny", Decision::Deny), ("uncertain", Decision::Uncertain)] {
            let r = review(&db, &freeze(&db, &run, goal), decision);
            assert_eq!(r.state, "denied");
            assert!(db
                .action_decide(&r.id, &r.artifact_hash, "session", 104)
                .is_err());
        }
        let r = review(&db, &freeze(&db, &run, "pending"), Decision::Allow);
        let config = db.ai_profiles().unwrap();
        db.configure_ai_profiles(config).unwrap();
        assert!(db
            .action_decide(&r.id, &r.artifact_hash, "once", 104)
            .is_err());
    }
    #[test]
    fn session_does_not_skip_review_or_survive_recovery() {
        let (db, run) = fixture();
        let r = review(&db, &freeze(&db, &run, "first"), Decision::Allow);
        db.action_decide(&r.id, &r.artifact_hash, "session", 104)
            .unwrap();
        let second = freeze(&db, &run, "second");
        assert_eq!(second.state, "reviewing");
        let second = review(&db, &second, Decision::Allow);
        assert_eq!(second.state, "approved");
        db.action_transition(&second.id, "approved", "queued", 105)
            .unwrap();
        db.action_transition(&second.id, "queued", "running", 106)
            .unwrap();
        db.recover_actions().unwrap();
        assert_eq!(db.action_request(&second.id).unwrap().state, "unknown");
        assert!(db
            .action_transition(&second.id, "queued", "running", 107)
            .is_err());
        assert_eq!(
            db.0.lock()
                .unwrap()
                .query_row("SELECT count(*) FROM ai_action_grants", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            0
        );
    }
    #[test]
    fn session_does_not_authorize_a_different_ssh_context() {
        let (db, run) = fixture();
        let first = review(&db, &freeze(&db, &run, "first"), Decision::Allow);
        db.action_decide(&first.id, &first.artifact_hash, "session", 104)
            .unwrap();
        let mut second = freeze(&db, &run, "changed transport");
        second.artifact.scope_transport_hash = "different trust files".into();
        second.artifact_hash = digest(&second.artifact).unwrap();
        persist(&db.0.lock().unwrap(), &second).unwrap();
        let second = review(&db, &second, Decision::Allow);
        assert_eq!(second.state, "awaitingApproval");
    }
    #[test]
    fn approval_notification_click_only_selects_the_saved_request() {
        let (db, run) = fixture();
        let request = review(&db, &freeze(&db, &run, "notification"), Decision::Allow);
        assert!(db.mark_action_notified(&request.id).unwrap());
        assert!(!db.mark_action_notified(&request.id).unwrap());
        let target = db
            .notification_target(&format!("action:{}", request.id))
            .unwrap();
        assert!(target.open_actions);
        assert_eq!(
            target.action_request_id.as_deref(),
            Some(request.id.as_str())
        );
        assert_eq!(
            db.action_request(&request.id).unwrap().state,
            "awaitingApproval"
        );
        let missing = db
            .notification_target(&format!("action:{}", uuid::Uuid::new_v4()))
            .unwrap();
        assert!(missing.open_actions);
        assert!(missing.action_request_id.is_none());
    }
    #[test]
    fn expires_scope_change_and_transaction_failure_do_not_grant() {
        let (db, run) = fixture();
        let r = review(&db, &freeze(&db, &run, "first"), Decision::Allow);
        assert!(db
            .action_decide(&r.id, &r.artifact_hash, "once", r.expires_at)
            .is_err());
        db.0.lock().unwrap().execute_batch("CREATE TRIGGER fail_request BEFORE UPDATE ON ai_requests BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
        assert!(db
            .action_decide(&r.id, &r.artifact_hash, "session", 104)
            .is_err());
        assert_eq!(
            db.0.lock()
                .unwrap()
                .query_row("SELECT count(*) FROM ai_action_grants", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            0
        );
        db.0.lock().unwrap().execute_batch("DROP TRIGGER fail_request; UPDATE servers SET payload=json_set(payload,'$.endpoint.host','new-host');").unwrap();
        assert!(db
            .action_decide(&r.id, &r.artifact_hash, "once", 104)
            .is_err());
    }
    #[test]
    fn reviewer_budget_is_part_of_parent_reserve_and_single_child() {
        let (db, mut run) = fixture();
        let r = freeze(&db, &run, "first");
        let (id, reserved) = db.admit_review(&r, 103).unwrap();
        let r2 = freeze(&db, &run, "second");
        assert!(db.admit_review(&r2, 103).is_err());
        assert!(reserved >= 4096);
        let status = db.auto_status(103).unwrap();
        assert_eq!(status.charged_tokens, 50000);
        assert_eq!(status.reserved_tokens, 50000);
        assert_eq!(status.runs, 2);
        db.settle_review(
            &id,
            json!({"inputTokens":100,"outputTokens":10,"totalTokens":110}),
            true,
        )
        .unwrap();
        assert_eq!(db.review_charged(&run.id).unwrap(), 110);
        assert!(db.admit_review(&r, 104).is_err());
        run.status = "completed".into();
        run.usage = json!({"inputTokens":200,"outputTokens":20,"totalTokens":220});
        run.usage_complete = true;
        db.settle(&run).unwrap();
        let status = db.auto_status(104).unwrap();
        assert_eq!(status.charged_tokens, 330);
        assert_eq!(status.actual_tokens, 330);
    }
    #[test]
    fn active_queue_and_retention_are_bounded() {
        let (db, run) = fixture();
        for n in 0..ACTIVE_LIMIT {
            freeze(&db, &run, &format!("request {n}"));
        }
        assert!(db
            .action_propose(
                &run,
                spec(&run, "overflow"),
                json!({}),
                crate::ssh_authorization::fixture(),
                "fixture".into(),
                105
            )
            .is_err());
        {
            let sql = db.0.lock().unwrap();
            trim(&sql, 1000).unwrap();
            assert_eq!(
                Store::list::<Request>(&sql, "ai_requests")
                    .unwrap()
                    .iter()
                    .filter(|r| active(&r.state))
                    .count(),
                0
            );
            trim(&sql, 1000 + 8 * 86400).unwrap();
            assert_eq!(
                Store::list::<Request>(&sql, "ai_requests").unwrap().len(),
                0
            );
        }
    }
    #[test]
    fn incomplete_review_and_parent_do_not_double_reserve() {
        let (db, mut run) = fixture();
        let r = freeze(&db, &run, "uncertain cost");
        let (id, reserved) = db.admit_review(&r, 103).unwrap();
        db.settle_review(&id, json!({}), false).unwrap();
        assert_eq!(db.review_charged(&run.id).unwrap(), reserved);
        assert_eq!(
            db.settle_review(&id, json!({"totalTokens":1}), true)
                .unwrap(),
            reserved
        );
        run.status = "cancelled".into();
        db.settle(&run).unwrap();
        assert_eq!(db.auto_status(104).unwrap().charged_tokens, 50000);
    }
    #[test]
    fn uncapped_session_can_review_and_keeps_the_parent_usage() {
        let (db, mut run) = fixture_with_limit(0);
        run.usage = json!({"totalTokens":100});
        db.save_investigation(&run).unwrap();
        let request = freeze(&db, &run, "uncapped session");
        let (review, reserved) = db.admit_review(&request, 103).unwrap();
        assert_eq!(db.auto_status(103).unwrap().charged_tokens, 100 + reserved);
        db.settle_review(&review, json!({"totalTokens":200}), true)
            .unwrap();
        let status = db.auto_status(104).unwrap();
        assert_eq!(status.charged_tokens, 300);
        assert_eq!(status.reserved_tokens, 0);
        run.usage_complete = true;
        run.status = "completed".into();
        db.settle(&run).unwrap();
        assert!(db.auto_status(104).unwrap().blocked_reason.is_none());
    }
    #[test]
    fn low_calls_count_toward_daily_run_limit() {
        let (db, run) = fixture();
        let mut settings = db.settings().unwrap();
        settings.daily_run_limit = Some(1);
        db.save_settings(&settings).unwrap();
        let r = freeze(&db, &run, "one run only");
        assert!(db.admit_review(&r, 103).is_err());
        assert_eq!(db.auto_status(103).unwrap().runs, 1);
    }
}
