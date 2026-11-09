//! Durable admission, episode deduplication and conservative token accounting.
use crate::{agents::Investigation, model::*, store::Store};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
pub(crate) const COOLDOWN: i64 = 6 * 3600;
const MAX_QUEUE: i64 = 500;
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Job {
    pub id: String,
    #[serde(default)]
    pub group_id: Option<String>,
    pub incident_id: String,
    pub server_id: String,
    pub title: String,
    pub evidence: String,
    pub severity: String,
    pub occurrences: u64,
    pub state: String,
    pub created_at: i64,
    pub not_before: i64,
    pub run_id: Option<String>,
    #[serde(default)]
    pub dispatched_at: Option<i64>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoStatus {
    pub day: i64,
    pub runs: u64,
    pub actual_tokens: u64,
    pub charged_tokens: u64,
    pub reserved_tokens: u64,
    pub uncertain_runs: u64,
    pub blocked_reason: Option<String>,
    pub waiting_reason: Option<String>,
    pub queued: u64,
    pub jobs: Vec<Job>,
}
// Cached input is included in Codex total; Claude reports it separately.
pub fn tokens(agent: &str, value: &Value) -> Option<u64> {
    if agent == "codex" {
        value["totalTokens"].as_u64()
    } else if agent == "claude" {
        value["input_tokens"]
            .as_u64()?
            .checked_add(value["output_tokens"].as_u64()?)?
            .checked_add(value["cache_creation_input_tokens"].as_u64()?)?
            .checked_add(value["cache_read_input_tokens"].as_u64()?)
    } else {
        None
    }
}
pub(crate) fn episode(i: &Incident) -> String {
    if i.episode.is_empty() {
        format!("{}:{}", i.id, i.opened_at)
    } else {
        i.episode.clone()
    }
}
fn write_job(db: &Connection, j: &Job) -> Result<()> {
    db.execute("INSERT INTO ai_jobs VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(id) DO UPDATE SET incident_id=excluded.incident_id,server_id=excluded.server_id,state=excluded.state,not_before=excluded.not_before,run_id=excluded.run_id,payload=excluded.payload",params![j.id,j.incident_id,j.server_id,j.state,j.created_at,j.not_before,j.run_id,serde_json::to_string(j).map_err(err)?]).map_err(err)?;
    Ok(())
}
fn totals(db: &Connection, day: i64) -> Result<(u64, u64, u64, u64, u64)> {
    db.query_row("SELECT count(*),coalesce(sum(actual),0),CAST(total(charged) AS INTEGER),coalesce(sum(CASE WHEN state='running' AND reserved>0 THEN charged ELSE 0 END),0),coalesce(sum(CASE WHEN state='uncertain' THEN 1 ELSE 0 END),0) FROM ai_ledger WHERE day=?1", [day], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).map_err(err)
}
fn reason(db: &Connection) -> Result<Option<String>> {
    db.query_row("SELECT reason FROM ai_control WHERE id=1", [], |r| r.get(0))
        .map_err(err)
}
// Zero reservation represents an uncapped session. A daily cap alone still
// bounds the session by the remaining daily balance.
fn budget_reservation(db: &Connection, s: &Settings, at: i64) -> Result<Result<u64>> {
    let (runs, _, charged, _, _) = totals(db, at.div_euclid(86400))?;
    if s.daily_runs_cap().is_some_and(|n| runs >= u64::from(n)) {
        return Ok(Err("Daily AI run limit reached (UTC)".into()));
    }
    let Some(daily) = s.daily_tokens_cap() else {
        return Ok(Ok(s.run_token_limit));
    };
    let remaining = daily.saturating_sub(charged);
    let reservation = if s.run_token_limit == 0 {
        remaining
    } else {
        s.run_token_limit.min(daily)
    };
    if reservation == 0 || reservation > remaining {
        return Ok(Err(
            "Not enough tokens left in the daily budget for this run (UTC)".into(),
        ));
    }
    Ok(Ok(reservation))
}
impl Store {
    pub(crate) fn backfill_ledger(&self) -> Result<()> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        let settings = Self::read_settings(&tx)?;
        let runs: Vec<Investigation> = Self::list(&tx, "investigations")?;
        for r in runs {
            let actual = tokens(&r.agent, &r.usage);
            let complete = r.status == "completed" && actual.is_some();
            let charged = if complete {
                actual.unwrap_or(0)
            } else {
                settings.run_token_limit.max(actual.unwrap_or(0))
            };
            tx.execute(
                "INSERT OR IGNORE INTO ai_ledger VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    r.id,
                    r.started_at.div_euclid(86400),
                    settings.run_token_limit,
                    actual,
                    charged,
                    if r.status == "running" {
                        "running"
                    } else if complete {
                        "settled"
                    } else {
                        "uncertain"
                    }
                ],
            )
            .map_err(err)?;
        }
        tx.commit().map_err(err)
    }
    /// Reconcile in one transaction. Completed episodes remain deduplicated even
    /// after the 50-report history rotates. In manual mode no jobs are added.
    pub(crate) fn reconcile_auto(&self, at: i64) -> Result<()> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(err)?;
        let settings = Self::read_settings(&tx)?;
        let incidents: Vec<Incident> = Self::list(&tx, "incidents")?;
        let mut jobs: Vec<Job> = Self::list(&tx, "ai_jobs")?;
        let servers: Vec<Server> = Self::list(&tx, "servers")?;
        crate::correlation::trim(&tx, at)?;
        let assigned = crate::correlation::reconcile(&tx, &incidents, &servers, &jobs, at)?;
        let mut slots = MAX_QUEUE - jobs.iter().filter(|j| j.state == "queued").count() as i64;
        for j in &mut jobs {
            let was_queued = j.state == "queued";
            let before = serde_json::to_string(j).map_err(err)?;
            if let Some(group) = &j.group_id {
                if let Ok(g) = crate::correlation::read(&tx, group) {
                    if let Some(current) = crate::correlation::job(&tx, &g, at)? {
                        j.server_id = current.server_id;
                        j.incident_id = current.incident_id;
                        j.title = current.title;
                        j.evidence = current.evidence;
                        j.severity = current.severity;
                        j.occurrences = current.occurrences;
                    }
                    if ["queued", "suppressed"].contains(&j.state.as_str()) {
                        j.state = if g.status != "open" {
                            "obsolete"
                        } else if (was_queued || slots > 0)
                            && crate::correlation::eligible(&tx, group, &settings, at)?
                        {
                            "queued"
                        } else {
                            "suppressed"
                        }
                        .into();
                    }
                } else if ["queued", "suppressed"].contains(&j.state.as_str()) {
                    j.state = "obsolete".into();
                }
            } else if assigned.contains_key(&j.id) {
                if ["queued", "suppressed"].contains(&j.state.as_str()) {
                    j.state = "merged".into();
                }
            } else if let Some(i) = incidents.iter().find(|i| episode(i) == j.id) {
                j.occurrences = i.occurrences;
                j.evidence = i.evidence.clone();
                j.severity = i.severity.clone();
                if i.status != "open" && ["queued", "suppressed"].contains(&j.state.as_str()) {
                    j.state = "obsolete".into();
                } else if i.status == "open" && !i.auto_eligible && j.state == "queued" {
                    j.state = "suppressed".into();
                }
            } else if ["queued", "suppressed"].contains(&j.state.as_str()) {
                j.state = "obsolete".into();
            }
            if was_queued && j.state != "queued" {
                slots += 1;
            } else if !was_queued && j.state == "queued" {
                slots -= 1;
            }
            if before != serde_json::to_string(j).map_err(err)? {
                write_job(&tx, j)?;
            }
        }
        let mut count = jobs.iter().filter(|j| j.state == "queued").count() as i64;
        if settings.mode == "auto" {
            for j in jobs
                .iter_mut()
                .filter(|j| j.state == "suppressed" && j.run_id.is_none() && j.group_id.is_none())
            {
                if count < MAX_QUEUE
                    && !assigned.contains_key(&j.id)
                    && incidents
                        .iter()
                        .any(|i| episode(i) == j.id && i.status == "open" && i.auto_eligible)
                {
                    j.state = "queued".into();
                    write_job(&tx, j)?;
                    count += 1;
                }
            }
            for i in incidents
                .iter()
                .filter(|i| i.status == "open" && i.auto_eligible)
            {
                let id = episode(i);
                if assigned.contains_key(&id)
                    || jobs.iter().any(|j| j.id == id)
                    || count >= MAX_QUEUE
                {
                    continue;
                }
                let last:Option<i64>=tx.query_row("SELECT max(at) FROM (SELECT coalesce(json_extract(payload,'$.dispatchedAt'),created_at) AS at FROM ai_jobs WHERE incident_id=?1 AND run_id IS NOT NULL UNION ALL SELECT json_extract(g.payload,'$.dispatchedAt') AS at FROM incident_groups g JOIN incident_group_members m ON m.group_id=g.id WHERE m.incident_id=?1)",[&i.id],|r|r.get(0)).map_err(err)?;
                let j = Job {
                    id,
                    group_id: None,
                    incident_id: i.id.clone(),
                    server_id: i.server_id.clone(),
                    title: i.title.clone(),
                    evidence: i.evidence.clone(),
                    severity: i.severity.clone(),
                    occurrences: i.occurrences,
                    state: "queued".into(),
                    created_at: at,
                    not_before: last.map_or(at, |v| at.max(v + COOLDOWN)).max(
                        if crate::correlation::hold(i, &servers) {
                            i.opened_at + crate::correlation::SETTLE
                        } else {
                            at
                        },
                    ),
                    run_id: None,
                    dispatched_at: None,
                };
                write_job(&tx, &j)?;
                jobs.push(j);
                count += 1;
            }
        }
        if settings.mode == "auto" {
            let groups: Vec<crate::correlation::Group> = Self::list(&tx, "incident_groups")?;
            for g in groups
                .iter()
                .filter(|g| g.status == "open" && g.auto_state.is_none())
            {
                if count >= MAX_QUEUE || jobs.iter().any(|j| j.id == g.id) {
                    continue;
                }
                if crate::correlation::eligible(&tx, &g.id, &settings, at)? {
                    if let Some(j) = crate::correlation::job(&tx, g, at)? {
                        write_job(&tx, &j)?;
                        jobs.push(j);
                        count += 1;
                    }
                }
            }
        }
        // Never prune the current episode's tombstone; it is the dedupe key.
        for j in jobs.iter().filter(|j| {
            j.state != "running" && j.state != "queued" && j.created_at < at - 30 * 86400
        }) {
            if j.group_id
                .as_ref()
                .is_none_or(|id| crate::correlation::read(&tx, id).is_err())
                && !incidents.iter().any(|i| episode(i) == j.id)
            {
                tx.execute("DELETE FROM ai_jobs WHERE id=?1", [&j.id])
                    .map_err(err)?;
            }
        }
        tx.execute(
            "DELETE FROM ai_ledger WHERE day < ?1 AND state!='running'",
            [at.div_euclid(86400) - 90],
        )
        .map_err(err)?;
        tx.commit().map_err(err)
    }
    pub(crate) fn next_auto(&self, at: i64) -> Result<Option<Job>> {
        let db = self.0.lock().map_err(err)?;
        let s = Self::read_settings(&db)?;
        if s.mode != "auto"
            || s.paused
            || reason(&db)?.is_some()
            || budget_reservation(&db, &s, at)?.is_err()
        {
            return Ok(None);
        }
        let incidents: Vec<Incident> = Self::list(&db, "incidents")?;
        let mut jobs: Vec<Job> = Self::list(&db, "ai_jobs")?;
        jobs.retain(|j| {
            j.state == "queued"
                && j.not_before <= at
                && job_eligible(&db, &incidents, j, &s, at).unwrap_or(false)
        });
        // Critical first; after an hour waiting a warning has equal priority.
        jobs.sort_by_key(|j| {
            (
                j.severity != "critical" && at - j.created_at < 3600,
                j.created_at,
                j.id.clone(),
            )
        });
        Ok(jobs.into_iter().next())
    }
    /// Persist the reservation, run and queue claim before any model process.
    /// Includes manual runs: toggling the mode cannot reset or bypass a budget.
    pub(crate) fn admit(&self, run: &Investigation, job_id: Option<&str>) -> Result<u64> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(err)?;
        let s = Self::read_settings(&tx)?;
        s.validate()?;
        if run.agent != s.auto_agent {
            return Err("AI agent has changed. Start a new run.".into());
        }
        if let Some(selection) = &run.model_profile {
            let profiles = crate::ai_models::read(&tx)?;
            let roles = profiles
                .providers
                .get(&run.agent)
                .ok_or("Unknown AI Agent")?;
            if selection.revision != profiles.revision
                || roles.get(&selection.alias) != Some(&selection.primary)
                || roles.get("low") != Some(&selection.low)
            {
                return Err("Model profile has changed. Start a new run.".into());
            }
        }
        if tx
            .query_row(
                "SELECT count(*) FROM ai_ledger WHERE state='running'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map_err(err)?
            > 0
        {
            return Err("An AI run is already in progress".into());
        }
        let reservation = budget_reservation(&tx, &s, run.started_at)??;
        if !run.scope_endpoints.is_empty() {
            let current: Vec<Server> = Self::list(&tx, "servers")?;
            if run.server_ids.len() != run.scope_endpoints.len()
                || run.server_ids.iter().any(|id| {
                    !current.iter().any(|server| {
                        server.id == *id
                            && serde_json::to_string(&server.endpoint).ok().as_ref()
                                == run.scope_endpoints.get(id)
                    })
                })
            {
                return Err(
                    "Connection settings changed before the run could reserve tokens".into(),
                );
            }
        }
        if let Some(id) = job_id {
            if s.mode != "auto" || s.paused {
                return Err("Automatic investigations paused".into());
            }
            if let Some(r) = reason(&tx)? {
                return Err(r);
            }
            let payload: String = tx
                .query_row("SELECT payload FROM ai_jobs WHERE id=?1", [id], |r| {
                    r.get(0)
                })
                .map_err(err)?;
            let mut job: Job = serde_json::from_str(&payload).map_err(err)?;
            let incidents: Vec<Incident> = Self::list(&tx, "incidents")?;
            if job.state != "queued"
                || job.not_before > run.started_at
                || run.agent != s.auto_agent
                || run.group_id != job.group_id
                || run.server_ids != job_targets(&tx, &job)?
                || !job_eligible(&tx, &incidents, &job, &s, run.started_at)?
            {
                return Err(
                    "The incident was already processed or resolved, or its data is stale".into(),
                );
            }
            if let Some(group) = &job.group_id {
                crate::correlation::mark_run(&tx, group, "running", Some(&run.id), run.started_at)?;
            }
            job.dispatched_at = Some(run.started_at);
            job.state = "running".into();
            job.run_id = Some(run.id.clone());
            write_job(&tx, &job)?;
        }
        tx.execute(
            "INSERT INTO ai_ledger VALUES(?1,?2,?3,NULL,?3,'running')",
            params![run.id, run.started_at.div_euclid(86400), reservation],
        )
        .map_err(err)?;
        tx.execute(
            "INSERT INTO investigations VALUES(?1,?2,?3)",
            params![
                run.id,
                run.started_at,
                serde_json::to_string(run).map_err(err)?
            ],
        )
        .map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(reservation)
    }
    pub(crate) fn settle(&self, run: &Investigation) -> Result<()> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(err)?;
        let reservation: Option<(u64, String)> = tx
            .query_row(
                "SELECT reserved,state FROM ai_ledger WHERE id=?1",
                [&run.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(err)?;
        if let Some((reserved, state)) = reservation {
            if state == "running" {
                let actual = tokens(&run.agent, &run.usage);
                let exact = run.usage_complete && actual.is_some();
                let charged = if exact {
                    actual.unwrap_or(0)
                } else {
                    reserved
                        .saturating_sub(crate::ai_actions::review_charged(&tx, &run.id)?)
                        .max(actual.unwrap_or(0))
                };
                tx.execute(
                    "UPDATE ai_ledger SET actual=?2,charged=?3,state=?4 WHERE id=?1",
                    params![
                        run.id,
                        actual,
                        charged,
                        if exact { "settled" } else { "uncertain" }
                    ],
                )
                .map_err(err)?;
                if !exact || reserved != 0 && charged >= reserved {
                    tx.execute("UPDATE ai_control SET reason=?1 WHERE id=1",[if !exact {"Check the CLI before resuming automatic investigations."} else {"The run reached its token reservation. Review the budget before resuming automatic investigations."}]).map_err(err)?;
                } else if run.origin == "auto" && run.status != "completed" {
                    tx.execute("UPDATE ai_control SET reason='An automatic investigation did not finish. Review its error before resuming.' WHERE id=1",[]).map_err(err)?;
                }
            }
        }
        let jobs: Vec<Job> = Self::list(&tx, "ai_jobs")?;
        for mut job in jobs
            .into_iter()
            .filter(|j| j.run_id.as_deref() == Some(&run.id))
        {
            job.state = run.status.clone();
            if let Some(group) = &job.group_id {
                if crate::correlation::read(&tx, group).is_ok() {
                    crate::correlation::mark_run(&tx, group, &run.status, None, run.started_at)?;
                }
            }
            write_job(&tx, &job)?;
        }
        // The queue's anchor server may have been removed while the process was running.
        for group in Self::list::<crate::correlation::Group>(&tx, "incident_groups")?
            .into_iter()
            .filter(|g| g.run_id.as_deref() == Some(&run.id))
        {
            crate::correlation::mark_run(&tx, &group.id, &run.status, None, run.started_at)?;
        }
        tx.execute("INSERT INTO investigations VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",params![run.id,run.started_at,serde_json::to_string(run).map_err(err)?]).map_err(err)?;
        tx.execute("DELETE FROM investigations WHERE id NOT IN (SELECT id FROM investigations ORDER BY started_at DESC,rowid DESC LIMIT 50)",[]).map_err(err)?;
        tx.commit().map_err(err)
    }
    pub(crate) fn auto_status(&self, at: i64) -> Result<AutoStatus> {
        let db = self.0.lock().map_err(err)?;
        let s = Self::read_settings(&db)?;
        let day = at.div_euclid(86400);
        let (runs, actual_tokens, charged_tokens, reserved_tokens, uncertain_runs) =
            totals(&db, day)?;
        let mut jobs: Vec<Job> = Self::list(&db, "ai_jobs")?;
        let queued = jobs.iter().filter(|j| j.state == "queued").count() as u64;
        jobs.sort_by_key(|j| {
            (
                j.state != "running",
                j.state != "queued",
                std::cmp::Reverse(j.created_at),
            )
        });
        jobs.truncate(100);
        Ok(AutoStatus {
            day,
            runs,
            actual_tokens,
            charged_tokens,
            reserved_tokens,
            uncertain_runs,
            blocked_reason: reason(&db)?,
            waiting_reason: budget_reservation(&db, &s, at)?.err(),
            queued,
            jobs,
        })
    }
    pub(crate) fn resume_auto(&self) -> Result<()> {
        let db = self.0.lock().map_err(err)?;
        db.execute("UPDATE ai_control SET reason=NULL WHERE id=1", [])
            .map_err(err)?;
        Ok(())
    }
    pub(crate) fn dismiss_job(&self, id: &str) -> Result<()> {
        let db = self.0.lock().map_err(err)?;
        let data: String = db
            .query_row("SELECT payload FROM ai_jobs WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .map_err(err)?;
        let mut j: Job = serde_json::from_str(&data).map_err(err)?;
        if j.state != "queued" {
            return Err("The task has already started or completed".into());
        }
        j.state = "dismissed".into();
        if let Some(group) = &j.group_id {
            crate::correlation::mark_run(&db, group, "dismissed", None, now())?;
        }
        write_job(&db, &j)
    }
    pub(crate) fn block_auto(&self, message: &str) -> Result<()> {
        self.0
            .lock()
            .map_err(err)?
            .execute("UPDATE ai_control SET reason=?1 WHERE id=1", [message])
            .map_err(err)?;
        Ok(())
    }
}
pub(crate) fn fresh(i: &Incident, s: &Settings, at: i64) -> bool {
    i.auto_eligible
        && i.status == "open"
        && i.healthy_streak == 0
        && i.fresh_until.map_or(
            i.updated_at >= at - (s.poll_seconds * 2 + 30) as i64,
            |until| until >= at,
        )
}
fn job_eligible(
    db: &Connection,
    incidents: &[Incident],
    j: &Job,
    s: &Settings,
    at: i64,
) -> Result<bool> {
    if let Some(group) = &j.group_id {
        return crate::correlation::eligible(db, group, s, at);
    }
    let assigned: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM incident_group_members WHERE episode=?1)",
            [&j.id],
            |r| r.get(0),
        )
        .map_err(err)?;
    Ok(!assigned
        && incidents
            .iter()
            .any(|i| episode(i) == j.id && fresh(i, s, at)))
}
pub(crate) fn job_targets(db: &Connection, j: &Job) -> Result<Vec<String>> {
    match &j.group_id {
        Some(g) => crate::correlation::targets(db, g),
        None => Ok(vec![j.server_id.clone()]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::parse_manual;
    use serde_json::json;
    use std::path::Path;
    const AT: i64 = 10 * 86400 + 100;
    fn fixture() -> (Store, String) {
        let db = Store::open(Path::new(":memory:")).unwrap();
        let source = Source {
            id: "source".into(),
            name: "test".into(),

            kind: "manual".into(),
            location: "ops@node".into(),
            last_sync: None,
            error: None,
        };
        db.import(&source, parse_manual(&source.location).unwrap())
            .unwrap();
        let id = db.snapshot().unwrap().servers[0].id.clone();
        db.save_settings(&Settings {
            mode: "auto".into(),
            daily_run_limit: Some(5),
            daily_token_limit: Some(5000),
            run_token_limit: 1000,
            ..Settings::default()
        })
        .unwrap();
        (db, id)
    }
    fn incident(db: &Store, server: &str, ep: &str, status: &str, at: i64, occurrences: u64) {
        let i = Incident {
            resolved_by_user_at: None,
            manual_resolution_pending: false,
            auto_eligible: true,
            fresh_until: None,
            id: "incident".into(),
            episode: ep.into(),
            server_id: server.into(),
            check: "cpu".into(),
            title: "CPU".into(),
            severity: "warning".into(),
            status: status.into(),
            opened_at: at,
            updated_at: at,
            evidence: "95%".into(),
            occurrences,
            healthy_streak: 0,
        };
        db.0.lock().unwrap().execute("INSERT INTO incidents VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",params![i.id,i.server_id,serde_json::to_string(&i).unwrap()]).unwrap();
    }
    fn run(id: &str, server: &str, at: i64, auto: bool) -> Investigation {
        Investigation {
            usage_started: false,
            model_profile: None,
            actual_model: None,
            scope_endpoints: Default::default(),
            group_id: None,
            authoring_id: None,
            id: id.into(),
            agent: "codex".into(),
            server_ids: vec![server.into()],
            question: "test".into(),
            origin: if auto { "auto" } else { "manual" }.into(),
            status: "running".into(),
            started_at: at,
            ended_at: None,
            text: String::new(),
            error: None,
            usage: json!({}),
            usage_complete: false,
            audit: vec![],
            chat: None,
            session_id: None,
        }
    }
    fn finish(db: &Store, mut r: Investigation, n: u64) {
        r.status = "completed".into();
        r.usage = json!({"totalTokens":n});
        r.usage_complete = true;
        db.settle(&r).unwrap();
    }
    #[test]
    fn repeated_event_one_launch_even_after_cancel_and_resume() {
        let (db, id) = fixture();
        for n in 1..=100 {
            incident(&db, &id, "episode", "open", AT, n);
            db.reconcile_auto(AT).unwrap();
        }
        let j = db.next_auto(AT).unwrap().unwrap();
        assert_eq!(j.occurrences, 100);
        assert_eq!(db.auto_status(AT).unwrap().queued, 1);
        let mut r = run("r", &id, AT, true);
        db.admit(&r, Some(&j.id)).unwrap();
        assert!(db
            .admit(&run("duplicate", &id, AT, true), Some(&j.id))
            .is_err());
        r.status = "cancelled".into();
        db.settle(&r).unwrap();
        db.settle(&r).unwrap();
        let status = db.auto_status(AT).unwrap();
        assert_eq!(status.charged_tokens, 1000);
        assert_eq!(status.runs, 1);
        assert_eq!(status.uncertain_runs, 1);
        assert!(status.blocked_reason.is_some());
        db.resume_auto().unwrap();
        db.reconcile_auto(AT + 10).unwrap();
        assert!(db.next_auto(AT + 10).unwrap().is_none());
        assert_eq!(db.auto_status(AT).unwrap().runs, 1);
    }
    #[test]
    fn manual_and_paused_modes_do_not_admit_auto() {
        let (db, id) = fixture();
        let mut s = db.settings().unwrap();
        s.mode = "manual".into();
        db.save_settings(&s).unwrap();
        incident(&db, &id, "e", "open", AT, 1);
        db.reconcile_auto(AT).unwrap();
        assert_eq!(db.auto_status(AT).unwrap().queued, 0);
        s.mode = "auto".into();
        db.save_settings(&s).unwrap();
        db.reconcile_auto(AT).unwrap();
        let j = db.next_auto(AT).unwrap().unwrap();
        s.paused = true;
        db.save_settings(&s).unwrap();
        assert!(db.next_auto(AT).unwrap().is_none());
        assert!(db.admit(&run("r", &id, AT, true), Some(&j.id)).is_err());
        s.paused = false;
        s.mode = "manual".into();
        db.save_settings(&s).unwrap();
        assert!(db.admit(&run("r", &id, AT, true), Some(&j.id)).is_err());
        assert_eq!(db.auto_status(AT).unwrap().runs, 0);
    }
    #[test]
    fn zero_limits_allow_auto_and_charge_only_the_reported_usage() {
        let (db, id) = fixture();
        let settings = Settings {
            mode: "auto".into(),
            ..Settings::default()
        };
        assert_eq!(
            (
                settings.daily_run_limit,
                settings.daily_token_limit,
                settings.run_token_limit
            ),
            (Some(0), Some(0), 0)
        );
        db.save_settings(&settings).unwrap();
        incident(&db, &id, "unlimited", "open", AT, 1);
        db.reconcile_auto(AT).unwrap();
        let job = db.next_auto(AT).unwrap().unwrap();
        let mut r = run("unlimited-auto", &id, AT, true);
        assert_eq!(db.admit(&r, Some(&job.id)).unwrap(), 0);
        r.usage = json!({"totalTokens":1000});
        db.save_investigation(&r).unwrap();
        assert_eq!(db.auto_status(AT).unwrap().reserved_tokens, 0);
        finish(&db, r, 80_000);
        let status = db.auto_status(AT).unwrap();
        assert_eq!(status.charged_tokens, 80_000);
        assert!(status.blocked_reason.is_none() && status.waiting_reason.is_none());
    }
    #[test]
    fn unlimited_session_reserves_only_the_remaining_daily_budget() {
        let (db, id) = fixture();
        let settings = Settings {
            daily_token_limit: Some(1500),
            ..Settings::default()
        };
        db.save_settings(&settings).unwrap();
        let r = run("first", &id, AT, false);
        assert_eq!(db.admit(&r, None).unwrap(), 1500);
        finish(&db, r, 600);
        let r = run("second", &id, AT, false);
        assert_eq!(db.admit(&r, None).unwrap(), 900);
        finish(&db, r, 900);
        assert!(db.admit(&run("third", &id, AT, false), None).is_err());
    }
    #[test]
    fn budget_counts_manual_and_never_admits_unfunded_run() {
        let (db, id) = fixture();
        let mut s = db.settings().unwrap();
        s.daily_token_limit = Some(1500);
        db.save_settings(&s).unwrap();
        let r = run("manual", &id, AT, false);
        assert_eq!(db.admit(&r, None).unwrap(), 1000);
        let mut partial = r.clone();
        partial.usage = json!({"totalTokens":200});
        db.save_investigation(&partial).unwrap();
        let live = db.auto_status(AT).unwrap();
        assert_eq!(live.actual_tokens, 200);
        assert_eq!(live.charged_tokens, 1000);
        assert_eq!(live.reserved_tokens, 1000);
        finish(&db, r, 600);
        let status = db.auto_status(AT).unwrap();
        assert_eq!(status.actual_tokens, 600);
        assert_eq!(status.charged_tokens, 600);
        assert!(status.waiting_reason.is_some());
        assert!(db.admit(&run("again", &id, AT, false), None).is_err());
        s.mode = "manual".into();
        db.save_settings(&s).unwrap();
        assert!(db.admit(&run("toggle", &id, AT, false), None).is_err());
        assert_eq!(db.auto_status(AT).unwrap().runs, 1);
    }
    #[test]
    fn late_settlement_is_charged_to_start_day_and_run_limit_is_separate() {
        let (db, id) = fixture();
        let mut s = db.settings().unwrap();
        s.daily_run_limit = Some(1);
        db.save_settings(&s).unwrap();
        let r = run("r", &id, AT, false);
        db.admit(&r, None).unwrap();
        assert!(db
            .admit(&run("next", &id, AT + 86400, false), None)
            .is_err());
        finish(&db, r, 20);
        assert_eq!(db.auto_status(AT).unwrap().charged_tokens, 20);
        assert!(db.admit(&run("same", &id, AT, false), None).is_err());
        db.admit(&run("next", &id, AT + 86400, false), None)
            .unwrap();
        assert_eq!(db.auto_status(AT + 86400).unwrap().runs, 1);
    }
    #[test]
    fn resolved_stale_and_removed_servers_do_not_launch() {
        let (db, id) = fixture();
        incident(&db, &id, "e", "open", AT, 1);
        db.reconcile_auto(AT).unwrap();
        let j = db.next_auto(AT).unwrap().unwrap();
        assert!(db.next_auto(AT + 1000).unwrap().is_none());
        assert!(db
            .admit(&run("stale", &id, AT + 1000, true), Some(&j.id))
            .is_err());
        incident(&db, &id, "e", "resolved", AT + 10, 1);
        assert!(db
            .admit(&run("resolved", &id, AT + 10, true), Some(&j.id))
            .is_err());
        db.reconcile_auto(AT + 10).unwrap();
        assert_eq!(db.auto_status(AT).unwrap().jobs[0].state, "obsolete");
        db.delete_source("source").unwrap();
        assert!(db.auto_status(AT).unwrap().jobs.is_empty());
    }
    #[test]
    fn recurrence_waits_after_actual_dispatch_and_dismissal_is_durable() {
        let (db, id) = fixture();
        incident(&db, &id, "first", "open", AT, 1);
        db.reconcile_auto(AT).unwrap();
        incident(&db, &id, "first", "open", AT + 3600, 2);
        let r = run("r", &id, AT + 3600, true);
        db.admit(&r, Some("first")).unwrap();
        finish(&db, r, 100);
        incident(&db, &id, "second", "open", AT + 3601, 1);
        db.reconcile_auto(AT + 3601).unwrap();
        assert!(db.next_auto(AT + 3601).unwrap().is_none());
        incident(&db, &id, "second", "open", AT + 3600 + COOLDOWN, 2);
        let j = db.next_auto(AT + 3600 + COOLDOWN).unwrap().unwrap();
        assert_eq!(j.id, "second");
        db.dismiss_job(&j.id).unwrap();
        db.reconcile_auto(AT + 3600 + COOLDOWN).unwrap();
        assert!(db.next_auto(AT + 3600 + COOLDOWN).unwrap().is_none());
    }
    #[test]
    fn provider_usage_is_not_double_counted_and_unknown_fails_closed() {
        assert_eq!(
            tokens("codex", &json!({"totalTokens":100,"cachedInputTokens":70})),
            Some(100)
        );
        assert_eq!(
            tokens(
                "claude",
                &json!({"input_tokens":6,"output_tokens":952,"cache_creation_input_tokens":6910,"cache_read_input_tokens":12587})
            ),
            Some(20455)
        );
        assert_eq!(tokens("claude", &json!({"input_tokens":6})), None);
        assert_eq!(tokens("codex", &json!({"totalTokens":-1})), None);
        let (db, id) = fixture();
        let r = run("r", &id, AT, false);
        db.admit(&r, None).unwrap();
        finish(&db, r, 1500);
        assert_eq!(db.auto_status(AT).unwrap().charged_tokens, 1500);
        assert!(db.auto_status(AT).unwrap().blocked_reason.is_some());
    }
    #[test]
    fn atomic_admission_across_connections() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db");
        let db = Store::open(&path).unwrap();
        db.save_settings(&Settings {
            daily_run_limit: Some(1),
            daily_token_limit: Some(1000),
            run_token_limit: 1000,
            ..Settings::default()
        })
        .unwrap();
        drop(db);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut threads = vec![];
        for n in 0..2 {
            let db = Store::open(&path).unwrap();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                db.admit(&run(&format!("r{n}"), "s", AT, false), None)
                    .is_ok()
            }));
        }
        assert_eq!(
            threads
                .into_iter()
                .map(|t| usize::from(t.join().unwrap()))
                .sum::<usize>(),
            1
        );
    }
    #[test]
    fn mass_incident_queue_is_bounded_and_backfills_without_loss() {
        let (db, id) = fixture();
        {
            let db = db.0.lock().unwrap();
            for n in 0..510 {
                let i = Incident {
                    resolved_by_user_at: None,
                    manual_resolution_pending: false,
                    auto_eligible: true,
                    fresh_until: None,
                    id: format!("i{n}"),
                    episode: format!("e{n}"),
                    server_id: id.clone(),
                    check: format!("disk:{n}"),
                    title: "disk".into(),
                    severity: "warning".into(),
                    status: "open".into(),
                    opened_at: AT,
                    updated_at: AT,
                    evidence: "95%".into(),
                    occurrences: 1,
                    healthy_streak: 0,
                };
                db.execute(
                    "INSERT INTO incidents VALUES(?1,?2,?3)",
                    params![i.id, id, serde_json::to_string(&i).unwrap()],
                )
                .unwrap();
            }
        }
        db.reconcile_auto(AT).unwrap();
        assert_eq!(db.auto_status(AT).unwrap().queued, 500);
        let j = db.next_auto(AT).unwrap().unwrap();
        db.dismiss_job(&j.id).unwrap();
        db.reconcile_auto(AT).unwrap();
        assert_eq!(db.auto_status(AT).unwrap().queued, 500);
        db.reconcile_auto(AT).unwrap();
        assert_eq!(db.auto_status(AT).unwrap().queued, 500);
    }
    #[test]
    fn report_retention_does_not_reset_budget_or_episode_dedupe() {
        let (db, id) = fixture();
        incident(&db, &id, "first", "open", AT, 1);
        db.reconcile_auto(AT).unwrap();
        let first = run("auto", &id, AT, true);
        db.admit(&first, Some("first")).unwrap();
        finish(&db, first, 10);
        let mut s = db.settings().unwrap();
        s.mode = "manual".into();
        s.daily_run_limit = None;
        s.daily_token_limit = None;
        db.save_settings(&s).unwrap();
        for n in 1..=55 {
            let r = run(&format!("m{n}"), &id, AT + n, false);
            db.admit(&r, None).unwrap();
            finish(&db, r, 10);
        }
        assert_eq!(db.investigations().unwrap().len(), 50);
        assert_eq!(db.auto_status(AT).unwrap().runs, 56);
        assert_eq!(db.auto_status(AT).unwrap().charged_tokens, 560);
        s.mode = "auto".into();
        s.daily_run_limit = Some(100);
        s.daily_token_limit = Some(100000);
        db.save_settings(&s).unwrap();
        db.reconcile_auto(AT + 60).unwrap();
        assert!(db.next_auto(AT + 60).unwrap().is_none());
    }
    #[test]
    fn endpoint_replacement_removes_old_incident_and_queue() {
        let (db, id) = fixture();
        incident(&db, &id, "old", "open", AT, 1);
        db.reconcile_auto(AT).unwrap();
        let source = db.snapshot().unwrap().sources[0].clone();
        let mut hosts = parse_manual(&source.location).unwrap();
        hosts[0].endpoint.port = 2222;
        db.import(&source, hosts).unwrap();
        assert!(db.snapshot().unwrap().incidents.is_empty());
        assert!(db.auto_status(AT).unwrap().jobs.is_empty());
    }
    #[test]
    fn crash_preserves_reservation_and_single_instance_lock() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_owned();
        let state = crate::create_state(root.clone()).unwrap();
        assert!(crate::create_state(root.clone()).is_err());
        state
            .store
            .save_settings(&Settings {
                run_token_limit: 50_000,
                ..Settings::default()
            })
            .unwrap();
        let r = run("crashed", "server", now(), false);
        state.store.admit(&r, None).unwrap();
        drop(state);
        let restored = crate::create_state(root).unwrap();
        assert_eq!(
            restored.investigator.get("crashed").unwrap().status,
            "interrupted"
        );
        let status = restored.store.auto_status(now()).unwrap();
        assert_eq!(status.runs, 1);
        assert_eq!(status.charged_tokens, 50000);
        assert_eq!(status.reserved_tokens, 0);
        assert!(status.blocked_reason.is_some());
    }
    #[test]
    fn admission_pins_the_global_agent_and_profile_without_rewriting_a_running_session() {
        let db = Store::open(std::path::Path::new(":memory:")).unwrap();
        let mut first = run("global-first", "server", AT, false);
        first.model_profile = Some(db.current_ai_selection("low").unwrap().1);
        db.update_settings(
            serde_json::from_value(serde_json::json!({"autoAgent":"claude"})).unwrap(),
        )
        .unwrap();
        assert!(db
            .admit(&first, None)
            .unwrap_err()
            .contains("AI agent has changed"));
        assert_eq!(db.auto_status(AT).unwrap().runs, 0);
        let (agent, profile) = db.current_ai_selection("low").unwrap();
        first.agent = agent;
        first.model_profile = Some(profile.clone());
        db.admit(&first, None).unwrap();
        db.update_settings(
            serde_json::from_value(serde_json::json!({"autoAgent":"codex"})).unwrap(),
        )
        .unwrap();
        let saved = db.investigations().unwrap().remove(0);
        assert_eq!(saved.agent, "claude");
        assert_eq!(saved.model_profile.unwrap().primary, profile.primary);
        first.status = "completed".into();
        first.usage = serde_json::json!({"input_tokens":1,"output_tokens":1});
        first.usage_complete = true;
        db.settle(&first).unwrap();
        let mut second = run("global-second", "server", AT, false);
        second.model_profile = Some(db.current_ai_selection("medium").unwrap().1);
        let mut changed = db.ai_profiles().unwrap();
        changed
            .providers
            .get_mut("codex")
            .unwrap()
            .get_mut("medium")
            .unwrap()
            .model = "different-model".into();
        db.configure_ai_profiles(changed).unwrap();
        assert!(db
            .admit(&second, None)
            .unwrap_err()
            .contains("Model profile has changed"));
        second.model_profile = Some(db.current_ai_selection("medium").unwrap().1);
        db.admit(&second, None).unwrap();
    }
    #[test]
    fn a_queued_auto_job_uses_the_new_global_agent_at_admission() {
        let (db, id) = fixture();
        incident(&db, &id, "queued-global", "open", AT, 1);
        db.reconcile_auto(AT).unwrap();
        let job = db.next_auto(AT).unwrap().unwrap();
        db.update_settings(serde_json::from_value(json!({"autoAgent":"claude"})).unwrap())
            .unwrap();
        let mut r = run("queued-run", &id, AT, true);
        assert!(db
            .admit(&r, Some(&job.id))
            .unwrap_err()
            .contains("AI agent has changed"));
        assert_eq!(db.auto_status(AT).unwrap().queued, 1);
        let (agent, profile) = db.current_ai_selection("medium").unwrap();
        r.agent = agent;
        r.model_profile = Some(profile);
        db.admit(&r, Some(&job.id)).unwrap();
        let saved = db.investigations().unwrap().remove(0);
        assert_eq!(saved.agent, "claude");
        assert_eq!(saved.model_profile.unwrap().alias, "medium");
        assert_eq!(db.auto_status(AT).unwrap().queued, 0);
    }
}
