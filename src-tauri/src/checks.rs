use crate::{
    check_engine::{self, Report, Request, Response, Spec, Status, ENGINE},
    inventory::stable_id,
    model::{now, Server},
    store::Store,
    AppState,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Arc};
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn digest<T: Serialize>(v: &T) -> String {
    crate::packages::digest(v)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tested {
    pub engine: u32,
    pub at: i64,
    pub report: Report,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    pub id: String,
    pub check_id: String,
    pub at: i64,
    pub spec: Spec,
    pub report: Option<Tested>,
    pub author: String,
    pub error: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    pub id: String,
    pub version_id: String,
    pub at: i64,
    pub input_id: String,
    pub fresh_until: i64,
    pub status: Status,
    pub values: BTreeMap<String, Option<f64>>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Binding {
    pub server_id: String,
    pub check_id: String,
    pub version_id: String,
    pub previous_version_id: Option<String>,
    pub revision: u64,
    pub enabled: bool,
    pub next_check: i64,
    pub input_id: String,
    pub bad_streak: u32,
    pub last: Option<Run>,
    pub error: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    pub id: String,
    pub endpoint: String,
    pub fresh_until: i64,
    pub values: BTreeMap<String, Option<f64>>,
    pub missing: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Preview {
    pub token: String,
    pub version_id: String,
    pub server_id: String,
    pub revision: u64,
    pub at: i64,
    pub input: Input,
    pub response: Response,
    pub before: Option<Spec>,
    pub after: Spec,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Definition {
    pub id: String,
    pub name: String,
    pub versions: Vec<Version>,
    pub binding: Option<Binding>,
    pub events: Vec<Value>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub definitions: Vec<Definition>,
    pub fields: &'static [String],
    pub example: Spec,
    pub engine: u32,
}
fn read_json<T: serde::de::DeserializeOwned>(raw: Option<String>) -> Result<Option<T>> {
    raw.map(|s| serde_json::from_str(&s).map_err(err))
        .transpose()
}
fn version(db: &Connection, id: &str) -> Result<Version> {
    let row = db
        .query_row(
            "SELECT id,check_id,at,spec,report,author,blocked FROM check_versions WHERE id=?1",
            [id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, Option<String>>(6)?,
                ))
            },
        )
        .map_err(err)?;
    let v = Version {
        id: row.0,
        check_id: row.1,
        at: row.2,
        spec: serde_json::from_str(&row.3).map_err(err)?,
        report: read_json(row.4)?,
        author: row.5,
        error: row.6,
    };
    check_engine::validate(&v.spec)?;
    if digest(&json!({"check":v.check_id,"spec":v.spec})) != v.id {
        return Err("Hash version of the check didn’t match".into());
    }
    Ok(v)
}
fn binding(db: &Connection, server: &str, check: &str) -> Result<Option<Binding>> {
    read_json(
        db.query_row(
            "SELECT payload FROM check_bindings WHERE server_id=?1 AND check_id=?2",
            params![server, check],
            |r| r.get(0),
        )
        .optional()
        .map_err(err)?,
    )
}
fn write_binding(db: &Connection, b: &Binding) -> Result<()> {
    db.execute("INSERT INTO check_bindings VALUES(?1,?2,?3) ON CONFLICT(server_id,check_id) DO UPDATE SET payload=excluded.payload",params![b.server_id,b.check_id,serde_json::to_string(b).map_err(err)?]).map_err(err)?;
    Ok(())
}
fn event(
    db: &Connection,
    check: &str,
    server: Option<&str>,
    action: &str,
    version: &str,
) -> Result<()> {
    db.execute(
        "INSERT INTO check_events(check_id,server_id,at,payload) VALUES(?1,?2,?3,?4)",
        params![
            check,
            server,
            now(),
            json!({"at":now(),"action":action,"versionId":version,"serverId":server}).to_string()
        ],
    )
    .map_err(err)?;
    db.execute("DELETE FROM check_events WHERE check_id=?1 AND id NOT IN (SELECT id FROM check_events WHERE check_id=?1 ORDER BY id DESC LIMIT 100)",[check]).map_err(err)?;
    Ok(())
}
fn stale_incident(db: &Connection, server: &str, check: &str) -> Result<()> {
    db.execute("UPDATE incidents SET payload=json_set(payload,'$.autoEligible',json('false'),'$.freshUntil',0,'$.healthyStreak',0) WHERE id=?1",[stable_id(server,&format!("custom:{check}"))]).map_err(err)?;
    Ok(())
}
fn input(db: &Connection, server_id: &str, spec: &Spec) -> Result<Input> {
    let raw: String = db
        .query_row(
            "SELECT payload FROM servers WHERE id=?1",
            [server_id],
            |r| r.get(0),
        )
        .map_err(err)?;
    let server: Server = serde_json::from_str(&raw).map_err(err)?;
    let settings = Store::read_settings(db)?;
    let endpoint = digest(&server.endpoint);
    let observation = serde_json::to_value(&server.observation).map_err(err)?;
    let load = |table: &str| -> Result<Value> {
        let raw:Option<String>=db.query_row(&format!("SELECT payload FROM {table} WHERE server_id=?1 ORDER BY at DESC,rowid DESC LIMIT 1"),[server_id],|r|r.get(0)).optional().map_err(err)?;
        Ok(read_json(raw)?.unwrap_or(Value::Null))
    };
    let logs = if spec.inputs.iter().any(|s| s.starts_with("logs_")) {
        load("log_summaries")?
    } else {
        Value::Null
    };
    let service_samples = crate::services::check_samples(db, server_id, &spec.inputs)?;
    let mut values = BTreeMap::new();
    let mut stamps = BTreeMap::new();
    let mut missing = vec![];
    let mut fresh_until = i64::MAX;
    for field in &spec.inputs {
        let (value, at, ttl, complete) = if field.starts_with("logs_") {
            let count = field.trim_start_matches("logs_");
            (
                logs["counts"][count].as_f64().or(Some(0.0)),
                logs["at"].as_i64(),
                settings.log_poll_seconds * 2 + 30,
                logs["coverage"]["complete"] == true,
            )
        } else if let Some((value, at, complete)) = service_samples.get(field) {
            (*value, *at, settings.log_poll_seconds * 2 + 30, *complete)
        } else {
            let v = match field.as_str() {
                "cpu_percent" => observation["cpuPercent"].as_f64(),
                "memory_percent" => observation["memoryPercent"].as_f64(),
                "swap_percent" => observation["swapPercent"].as_f64(),
                "uptime_seconds" => observation["uptime"].as_f64(),
                "disk_max_percent" | "inode_max_percent" => {
                    let key = if field == "disk_max_percent" {
                        "usedPercent"
                    } else {
                        "inodePercent"
                    };
                    observation["disks"]
                        .as_array()
                        .filter(|a| !a.is_empty() && a.iter().all(|d| d[key].is_number()))
                        .and_then(|a| a.iter().filter_map(|d| d[key].as_f64()).reduce(f64::max))
                }
                "failed_services" => {
                    let missing = observation["missing"]
                        .as_array()
                        .is_some_and(|a| a.iter().any(|v| v == "services"));
                    if missing {
                        None
                    } else {
                        observation["services"]
                            .as_array()
                            .filter(|a| !a.is_empty())
                            .map(|a| a.iter().filter(|s| s["state"] == "failed").count() as f64)
                    }
                }
                _ => None,
            };
            (
                v,
                observation["at"].as_i64(),
                settings.poll_seconds * 2 + 30,
                server.last_error.is_none(),
            )
        };
        let expiry = at.unwrap_or(0) + ttl as i64;
        let valid = complete && at.is_some_and(|t| t <= now() + 30) && expiry >= now();
        let value = value.filter(|v| valid && v.is_finite() && v.abs() <= 1e12);
        if value.is_none() {
            missing.push(field.clone());
        }
        fresh_until = fresh_until.min(expiry);
        values.insert(field.clone(), value);
        stamps.insert(field.clone(), at);
    }
    let id = digest(&json!({"endpoint":endpoint,"values":values,"stamps":stamps}));
    Ok(Input {
        id,
        endpoint,
        fresh_until,
        values,
        missing,
    })
}
impl Store {
    pub(crate) fn new_check(&self) -> Result<String> {
        let db = self.0.lock().map_err(err)?;
        crate::storage::admit(&db)?;
        let count: i64 = db
            .query_row("SELECT count(*) FROM check_definitions", [], |r| r.get(0))
            .map_err(err)?;
        if count >= 50 {
            return Err("Limit 50 checks; remove unused".into());
        }
        let id = uuid::Uuid::new_v4().to_string();
        db.execute(
            "INSERT INTO check_definitions VALUES(?1,?2,'New verification')",
            params![id, now()],
        )
        .map_err(err)?;
        Ok(id)
    }
    pub(crate) fn check_version(&self, id: &str) -> Result<Version> {
        let db = self.0.lock().map_err(err)?;
        version(&db, id)
    }
    pub(crate) fn propose_check(&self, check: &str, spec: Spec, author: &str) -> Result<Version> {
        check_engine::validate(&spec)?;
        if !["user", "codex", "claude"].contains(&author) {
            return Err("Unknown author".into());
        }
        let id = digest(&json!({"check":check,"spec":spec}));
        let mut db = self.0.lock().map_err(err)?;
        crate::storage::admit(&db)?;
        let tx = db.transaction().map_err(err)?;
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM check_definitions WHERE id=?1)",
                [check],
                |r| r.get(0),
            )
            .map_err(err)?;
        if !exists {
            return Err("Verification removed".into());
        }
        if tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM check_versions WHERE id=?1)",
                [&id],
                |r| r.get::<_, bool>(0),
            )
            .map_err(err)?
        {
            return version(&tx, &id);
        }
        let count: i64 = tx
            .query_row(
                "SELECT count(*) FROM check_versions WHERE check_id=?1",
                [check],
                |r| r.get(0),
            )
            .map_err(err)?;
        if count >= 20 {
            return Err("Limit 20 versions; remove unused draft".into());
        }
        tx.execute(
            "INSERT INTO check_versions VALUES(?1,?2,?3,?4,NULL,?5,NULL)",
            params![
                id,
                check,
                now(),
                serde_json::to_string(&spec).map_err(err)?,
                author
            ],
        )
        .map_err(err)?;
        tx.execute(
            "UPDATE check_definitions SET name=?2 WHERE id=?1",
            params![check, spec.name],
        )
        .map_err(err)?;
        event(&tx, check, None, "draft", &id)?;
        let v = version(&tx, &id)?;
        tx.commit().map_err(err)?;
        Ok(v)
    }
    pub(crate) fn check_view(&self, server: &str, selected: Option<&str>) -> Result<View> {
        let db = self.0.lock().map_err(err)?;
        let exists: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM servers WHERE id=?1)",
                [server],
                |r| r.get(0),
            )
            .map_err(err)?;
        if !exists {
            return Err("The server is remote".into());
        }
        let mut defs = db
            .prepare("SELECT id,name FROM check_definitions ORDER BY at DESC,rowid DESC")
            .map_err(err)?;
        let rows = defs
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(err)?;
        let mut definitions = vec![];
        for row in rows {
            let (id, name) = row.map_err(err)?;
            let mut q=db.prepare("SELECT id FROM check_versions WHERE check_id=?1 ORDER BY at DESC,rowid DESC LIMIT 20").map_err(err)?;
            let versions = if selected == Some(id.as_str()) {
                q.query_map([&id], |r| r.get::<_, String>(0))
                    .map_err(err)?
                    .map(|r| version(&db, &r.map_err(err)?))
                    .collect::<Result<Vec<_>>>()?
            } else {
                vec![]
            };
            let mut q=db.prepare("SELECT payload FROM check_events WHERE check_id=?1 AND (server_id IS NULL OR server_id=?2) ORDER BY id DESC LIMIT 20").map_err(err)?;
            let events = q
                .query_map(params![id, server], |r| r.get::<_, String>(0))
                .map_err(err)?
                .map(|r| serde_json::from_str(&r.map_err(err)?).map_err(err))
                .collect::<Result<Vec<_>>>()?;
            definitions.push(Definition {
                binding: binding(&db, server, &id)?,
                id,
                name,
                versions,
                events,
            });
        }
        Ok(View {
            definitions,
            fields: check_engine::fields(),
            example: check_engine::example(),
            engine: ENGINE,
        })
    }
    fn check_input(&self, server: &str, spec: &Spec) -> Result<Input> {
        let db = self.0.lock().map_err(err)?;
        input(&db, server, spec)
    }
    fn save_test(&self, id: &str, response: &Response) -> Result<Tested> {
        let report = response.report.clone().ok_or("No test results")?;
        if report.engine != ENGINE {
            return Err("Obsolete performer".into());
        }
        let tested = Tested {
            engine: ENGINE,
            at: now(),
            report,
        };
        let db = self.0.lock().map_err(err)?;
        crate::storage::admit(&db)?;
        let v = version(&db, id)?;
        db.execute("UPDATE check_versions SET report=?2,blocked=CASE WHEN ?3 THEN NULL ELSE blocked END WHERE id=?1",params![id,serde_json::to_string(&tested).map_err(err)?,tested.report.passed]).map_err(err)?;
        event(&db, &v.check_id, None, "test", id)?;
        Ok(tested)
    }
    fn save_preview(
        &self,
        version: &Version,
        server: &str,
        original: Input,
        response: Response,
    ) -> Result<Preview> {
        let mut db = self.0.lock().map_err(err)?;
        crate::storage::admit(&db)?;
        let tx = db.transaction().map_err(err)?;
        let current = input(&tx, server, &version.spec)?;
        if current.id != original.id {
            return Err("Data changed during the test; repeat".into());
        }
        let b = binding(&tx, server, &version.check_id)?;
        let before = b
            .as_ref()
            .map(|b| crate::checks::version(&tx, &b.version_id).map(|v| v.spec))
            .transpose()?;
        let preview = Preview {
            token: uuid::Uuid::new_v4().to_string(),
            version_id: version.id.clone(),
            server_id: server.into(),
            revision: b.map_or(0, |b| b.revision),
            at: now(),
            input: original,
            response,
            before,
            after: version.spec.clone(),
        };
        tx.execute("DELETE FROM check_reviews WHERE at<?1", [now() - 900])
            .map_err(err)?;
        let count: i64 = tx
            .query_row("SELECT count(*) FROM check_reviews", [], |r| r.get(0))
            .map_err(err)?;
        if count >= 1000 {
            return Err("Limit views; wait for the old ones to expire".into());
        }
        tx.execute("INSERT INTO check_reviews VALUES(?1,?2,?3,?4) ON CONFLICT(server_id,version_id) DO UPDATE SET at=excluded.at,payload=excluded.payload",params![server,version.id,preview.at,serde_json::to_string(&preview).map_err(err)?]).map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(preview)
    }
    pub(crate) fn activate_check(&self, server: &str, id: &str, token: &str) -> Result<()> {
        let mut db = self.0.lock().map_err(err)?;
        crate::storage::admit(&db)?;
        let tx = db.transaction().map_err(err)?;
        let v = version(&tx, id)?;
        if v.error.is_some()
            || !v
                .report
                .as_ref()
                .is_some_and(|r| r.engine == ENGINE && r.report.passed && now() - r.at <= 86400)
        {
            return Err("Successful isolated tests of the current version are required".into());
        }
        let raw: String = tx
            .query_row(
                "SELECT payload FROM check_reviews WHERE server_id=?1 AND version_id=?2",
                params![server, id],
                |r| r.get(0),
            )
            .map_err(|_| "First, watch the trial run")?;
        let p: Preview = serde_json::from_str(&raw).map_err(err)?;
        let current = input(&tx, server, &v.spec)?;
        let old = binding(&tx, server, &v.check_id)?;
        if p.token != token
            || p.version_id != v.id
            || p.server_id != server
            || now() - p.at > 900
            || p.revision != old.as_ref().map_or(0, |b| b.revision)
            || p.input.id != current.id
            || !p
                .response
                .report
                .as_ref()
                .is_some_and(|r| r.passed && r.engine == ENGINE)
        {
            return Err("View outdated; perform a sample and check the changes again".into());
        }
        let count: i64 = tx
            .query_row("SELECT count(*) FROM check_bindings", [], |r| r.get(0))
            .map_err(err)?;
        if old.is_none() && count >= 1000 {
            return Err("Limit of 1000 connection checks".into());
        }
        let rollback = old
            .as_ref()
            .is_some_and(|b| b.previous_version_id.as_deref() == Some(id));
        let previous = old.as_ref().and_then(|b| {
            if b.version_id != id {
                Some(b.version_id.clone())
            } else {
                b.previous_version_id.clone()
            }
        });
        let b = Binding {
            server_id: server.into(),
            check_id: v.check_id.clone(),
            version_id: id.into(),
            previous_version_id: previous,
            revision: p.revision + 1,
            enabled: true,
            next_check: now() + server.bytes().map(i64::from).sum::<i64>() % 60,
            input_id: String::new(),
            bad_streak: 0,
            last: None,
            error: None,
        };
        write_binding(&tx, &b)?;
        stale_incident(&tx, server, &v.check_id)?;
        event(
            &tx,
            &v.check_id,
            Some(server),
            if rollback { "rollback" } else { "activate" },
            id,
        )?;
        tx.execute(
            "DELETE FROM check_reviews WHERE server_id=?1 AND version_id=?2",
            params![server, id],
        )
        .map_err(err)?;
        tx.commit().map_err(err)
    }
    pub(crate) fn disable_check(&self, server: &str, check: &str) -> Result<()> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        let mut b = binding(&tx, server, check)?.ok_or("Check’s not connected")?;
        b.enabled = false;
        b.revision += 1;
        b.bad_streak = 0;
        write_binding(&tx, &b)?;
        stale_incident(&tx, server, check)?;
        event(&tx, check, Some(server), "disable", &b.version_id)?;
        tx.commit().map_err(err)
    }
    pub(crate) fn discard_check_version(&self, id: &str) -> Result<()> {
        let db = self.0.lock().map_err(err)?;
        let v = version(&db, id)?;
        let pinned:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM check_bindings WHERE json_extract(payload,'$.versionId')=?1 OR json_extract(payload,'$.previousVersionId')=?1) OR EXISTS(SELECT 1 FROM check_runs r JOIN check_evidence e ON e.run_id=r.id WHERE r.version_id=?1)",[id],|r|r.get(0)).map_err(err)?;
        if pinned {
            return Err("Version used or contains evidence of an incident".into());
        }
        db.execute("DELETE FROM check_versions WHERE id=?1", [id])
            .map_err(err)?;
        event(&db, &v.check_id, None, "discard", id)
    }
    pub(crate) fn delete_check(&self, id: &str) -> Result<()> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        let active:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM check_bindings WHERE check_id=?1 AND json_extract(payload,'$.enabled')=1)",[id],|r|r.get(0)).map_err(err)?;
        let evidence:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM check_runs r JOIN check_evidence e ON e.run_id=r.id WHERE r.check_id=?1)",[id],|r|r.get(0)).map_err(err)?;
        if evidence {
            return Err("Evidence of the incident persists; deletion not yet available".into());
        }
        if active {
            return Err("First, disable verification on all servers".into());
        }
        tx.execute("UPDATE incidents SET payload=json_set(payload,'$.autoEligible',json('false'),'$.freshUntil',0) WHERE json_extract(payload,'$.check')=?1",[format!("custom:{id}")]).map_err(err)?;
        tx.execute("DELETE FROM check_definitions WHERE id=?1", [id])
            .map_err(err)?;
        tx.commit().map_err(err)
    }
}
pub(crate) async fn test_version(app: Arc<AppState>, id: String) -> Result<Tested> {
    let v = app.store.check_version(&id)?;
    let response = app
        .check_runtime
        .execute(
            &app.root,
            &Request {
                spec: v.spec,
                values: BTreeMap::new(),
                test: true,
            },
        )
        .await
        .inspect_err(|e| {
            let _ = app.store.block_check_version(&id, e);
        })?;
    app.store.save_test(&id, &response)
}
pub(crate) async fn preview_version(
    app: Arc<AppState>,
    server: String,
    id: String,
) -> Result<Preview> {
    let v = app.store.check_version(&id)?;
    let values = app.store.check_input(&server, &v.spec)?;
    let response = app
        .check_runtime
        .execute(
            &app.root,
            &Request {
                spec: v.spec.clone(),
                values: values.values.clone(),
                test: true,
            },
        )
        .await
        .inspect_err(|e| {
            let _ = app.store.block_check_version(&id, e);
        })?;
    app.store.save_test(&id, &response)?;
    app.store.save_preview(&v, &server, values, response)
}

#[derive(Clone)]
struct Pending {
    binding: Binding,
    version: Version,
    input: Input,
}
impl Store {
    fn pending_checks(&self, server: Option<&str>) -> Result<Vec<Pending>> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        let mut q=tx.prepare("SELECT payload FROM check_bindings WHERE json_extract(payload,'$.enabled')=1 AND (?1 IS NULL OR server_id=?1) AND (?1 IS NOT NULL OR json_extract(payload,'$.nextCheck')<=?2) ORDER BY json_extract(payload,'$.nextCheck') LIMIT 32").map_err(err)?;
        let rows = q
            .query_map(params![server, now()], |r| r.get::<_, String>(0))
            .map_err(err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err)?;
        drop(q);
        let mut result = vec![];
        for raw in rows {
            let mut b: Binding = serde_json::from_str(&raw).map_err(err)?;
            let v = version(&tx, &b.version_id)?;
            let i = input(&tx, &b.server_id, &v.spec)?;
            if v.error.is_some() {
                continue;
            }
            if i.id == b.input_id {
                b.next_check = now() + v.spec.interval_seconds as i64;
                write_binding(&tx, &b)?;
                continue;
            }
            result.push(Pending {
                binding: b,
                version: v,
                input: i,
            });
        }
        tx.commit().map_err(err)?;
        Ok(result)
    }
    fn block_check_version(&self, id: &str, error: &str) -> Result<()> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        tx.execute(
            "UPDATE check_versions SET blocked=?2,report=NULL WHERE id=?1",
            params![id, error.chars().take(500).collect::<String>()],
        )
        .map_err(err)?;
        let mut q = tx
            .prepare(
                "SELECT payload FROM check_bindings WHERE json_extract(payload,'$.versionId')=?1",
            )
            .map_err(err)?;
        let rows = q
            .query_map([id], |r| r.get::<_, String>(0))
            .map_err(err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err)?;
        drop(q);
        for raw in rows {
            let mut b: Binding = serde_json::from_str(&raw).map_err(err)?;
            b.enabled = false;
            b.revision += 1;
            b.error = Some(error.chars().take(500).collect());
            b.bad_streak = 0;
            write_binding(&tx, &b)?;
            stale_incident(&tx, &b.server_id, &b.check_id)?;
            event(&tx, &b.check_id, Some(&b.server_id), "blocked", id)?;
        }
        tx.execute("DELETE FROM check_reviews WHERE version_id=?1", [id])
            .map_err(err)?;
        tx.commit().map_err(err)
    }
    fn commit_check(&self, p: &Pending, response: &Response) -> Result<bool> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        crate::storage::admit(&tx)?;
        let Some(mut b) = binding(&tx, &p.binding.server_id, &p.binding.check_id)? else {
            return Ok(false);
        };
        if !b.enabled
            || b.revision != p.binding.revision
            || b.version_id != p.version.id
            || b.input_id == p.input.id
        {
            return Ok(false);
        }
        if version(&tx, &b.version_id)?.error.is_some() {
            return Ok(false);
        }
        let current = input(&tx, &b.server_id, &p.version.spec)?;
        if current.id != p.input.id || current.endpoint != p.input.endpoint {
            return Ok(false);
        }
        if response.engine != ENGINE
            || !matches!(
                response.status,
                check_engine::Status::Healthy | check_engine::Status::Unknown
            ) && response.status != p.version.spec.severity
        {
            return Err("Incorrect result of the performer".into());
        }
        let run = Run {
            id: uuid::Uuid::new_v4().to_string(),
            version_id: b.version_id.clone(),
            at: now(),
            input_id: p.input.id.clone(),
            fresh_until: if response.status == check_engine::Status::Unknown {
                0
            } else {
                p.input.fresh_until
            },
            status: response.status.clone(),
            values: p.input.values.clone(),
        };
        let firing = matches!(
            run.status,
            check_engine::Status::Warning | check_engine::Status::Critical
        );
        b.bad_streak = if firing {
            b.bad_streak.saturating_add(1)
        } else {
            0
        };
        let key = format!("custom:{}", b.check_id);
        let incident = stable_id(&b.server_id, &key);
        let was_open = crate::incidents::needs_observation(&tx, &incident)?;
        if firing && b.bad_streak >= p.version.spec.bad_windows {
            let evidence=serde_json::to_string(&json!({"versionId":b.version_id,"runId":run.id,"values":run.values,"condition":p.version.spec.condition})).map_err(err)?;
            Store::incident(
                &tx,
                &b.server_id,
                &key,
                Some(evidence),
                &p.version.spec.name,
                if run.status == check_engine::Status::Critical {
                    "critical"
                } else {
                    "warning"
                },
                now(),
            )?;
            tx.execute("UPDATE incidents SET payload=json_set(payload,'$.autoEligible',CASE WHEN json_extract(payload,'$.status')='open' THEN json('true') ELSE json('false') END,'$.freshUntil',?2) WHERE id=?1",params![incident,run.fresh_until]).map_err(err)?;
        } else if run.status == check_engine::Status::Healthy && was_open {
            Store::incident(
                &tx,
                &b.server_id,
                &key,
                None,
                &p.version.spec.name,
                "warning",
                now(),
            )?;
            tx.execute("UPDATE incidents SET payload=json_set(payload,'$.autoEligible',json('false'),'$.freshUntil',?2) WHERE id=?1",params![incident,run.fresh_until]).map_err(err)?;
        } else {
            stale_incident(&tx, &b.server_id, &b.check_id)?;
        }
        tx.execute("INSERT INTO check_runs(id,server_id,check_id,version_id,at,payload) VALUES(?1,?2,?3,?4,?5,?6)",params![run.id,b.server_id,b.check_id,b.version_id,run.at,serde_json::to_string(&run).map_err(err)?]).map_err(err)?;
        if firing && b.bad_streak >= p.version.spec.bad_windows
            || was_open && run.status == Status::Healthy
        {
            tx.execute("INSERT INTO check_evidence(incident_id,run_id) SELECT id,?2 FROM incidents WHERE id=?1",params![incident,run.id]).map_err(err)?;
        }
        tx.execute("DELETE FROM check_evidence WHERE incident_id=?1 AND run_id NOT IN (SELECT e.run_id FROM check_evidence e JOIN check_runs r ON r.id=e.run_id WHERE e.incident_id=?1 ORDER BY r.at DESC,r.rowid DESC LIMIT 5)",[&incident]).map_err(err)?;
        b.input_id = p.input.id.clone();
        b.next_check = now() + p.version.spec.interval_seconds as i64;
        b.last = Some(run);
        b.error = None;
        write_binding(&tx, &b)?;
        trim_runs(&tx)?;
        tx.commit().map_err(err)?;
        Ok(true)
    }
}
pub(crate) fn trim_runs(db: &Connection) -> Result<()> {
    db.execute("DELETE FROM check_versions WHERE id IN (SELECT v.id FROM check_versions v WHERE v.at<?1 AND v.id!=(SELECT id FROM check_versions WHERE check_id=v.check_id ORDER BY at DESC,rowid DESC LIMIT 1) AND NOT EXISTS(SELECT 1 FROM check_bindings b WHERE json_extract(b.payload,'$.versionId')=v.id OR json_extract(b.payload,'$.previousVersionId')=v.id) AND NOT EXISTS(SELECT 1 FROM check_runs r JOIN check_evidence e ON e.run_id=r.id WHERE r.version_id=v.id) LIMIT 50)",[now()-30*86400]).map_err(err)?;

    db.execute("DELETE FROM check_reviews WHERE at<?1", [now() - 900])
        .map_err(err)?;
    db.execute("DELETE FROM check_evidence WHERE incident_id IN (SELECT id FROM incidents WHERE json_extract(payload,'$.status')='resolved' AND json_extract(payload,'$.updatedAt')<?1)",[now()-30*86400]).map_err(err)?;
    db.execute("DELETE FROM check_runs WHERE id IN (SELECT id FROM (SELECT id,at,row_number() OVER(ORDER BY at DESC,rowid DESC) AS total,row_number() OVER(PARTITION BY server_id,check_id ORDER BY at DESC,rowid DESC) AS per_check FROM check_runs WHERE id NOT IN (SELECT run_id FROM check_evidence)) WHERE at<?1 OR total>10000 OR per_check>100 LIMIT 500)",[now()-7*86400]).map_err(err)?;
    Ok(())
}
pub(crate) async fn run_pending(app: Arc<AppState>, server: Option<String>) -> Result<bool> {
    crate::monitoring::run(
        &app.store,
        "custom",
        server.as_deref().unwrap_or(""),
        "",
        run_pending_inner(app.clone(), server.clone()),
    )
    .await
}
async fn run_pending_inner(app: Arc<AppState>, server: Option<String>) -> Result<bool> {
    let pending = app.store.pending_checks(server.as_deref())?;
    let mut changed = false;
    for batch in pending.chunks(8) {
        if app.stop.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        let requests = batch
            .iter()
            .map(|p| Request {
                spec: p.version.spec.clone(),
                values: p.input.values.clone(),
                test: false,
            })
            .collect::<Vec<_>>();
        match app.check_runtime.execute_many(&app.root, &requests).await {
            Ok(responses) => {
                for (p, r) in batch.iter().zip(responses) {
                    changed |= app.store.commit_check(p, &r)?;
                }
            }
            Err(e) => {
                for p in batch {
                    app.store.block_check_version(&p.version.id, &e)?;
                }
                return Err(e);
            }
        }
    }
    Ok(changed)
}

pub(crate) fn statuses(db: &Connection) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::<String, String>::new();
    let bindings: Vec<Binding> = Store::list(db, "check_bindings")?;
    fn rank(s: &str) -> u8 {
        match s {
            "critical" => 4,
            "warning" => 3,
            "unknown" => 2,
            _ => 1,
        }
    }
    for b in bindings {
        if !b.enabled && b.error.is_none() {
            continue;
        }
        let state = if b.error.is_some() {
            "unknown"
        } else if let Some(r) = &b.last {
            if r.fresh_until < now() {
                "unknown"
            } else {
                match r.status {
                    Status::Healthy => "healthy",
                    Status::Warning => "warning",
                    Status::Critical => "critical",
                    Status::Unknown => "unknown",
                }
            }
        } else {
            "unknown"
        };
        if result
            .get(&b.server_id)
            .is_none_or(|old| rank(old) < rank(state))
        {
            result.insert(b.server_id, state.into());
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Observation, Settings, Source};
    fn fixture() -> (tempfile::TempDir, Store, String, Source) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.sqlite")).unwrap();
        let source = Source {
            id: "checks".into(),
            name: "Test".into(),

            kind: "manual".into(),
            location: "tester@127.0.0.1:1".into(),
            last_sync: None,
            error: None,
        };
        store
            .import(
                &source,
                crate::inventory::parse_manual(&source.location).unwrap(),
            )
            .unwrap();
        let id = store.snapshot().unwrap().servers[0].id.clone();
        (dir, store, id, source)
    }
    fn sample(store: &Store, id: &str, value: f64, at: i64) {
        let mut server = store
            .snapshot()
            .unwrap()
            .servers
            .into_iter()
            .find(|s| s.id == id)
            .unwrap();
        server.observation = Some(Observation {
            service_runtime: Vec::new(),
            service_runtime_complete: false,
            platform: None,
            at,
            cpu_percent: Some(1.0),
            memory_percent: Some(value),
            swap_percent: Some(0.0),
            load: None,
            uptime: Some(1.0),
            disks: vec![],
            services: vec![],
            missing: vec![],
            bytes_received: 0,
            duration_ms: 0,
        });
        store
            .0
            .lock()
            .unwrap()
            .execute(
                "UPDATE servers SET payload=?2 WHERE id=?1",
                params![id, serde_json::to_string(&server).unwrap()],
            )
            .unwrap();
    }
    fn draft(store: &Store) -> Version {
        let id = store.new_check().unwrap();
        store
            .propose_check(&id, check_engine::example(), "user")
            .unwrap()
    }
    fn preview(store: &Store, id: &str, v: &Version) -> Preview {
        let i = store.check_input(id, &v.spec).unwrap();
        let r = check_engine::execute(Request {
            spec: v.spec.clone(),
            values: i.values.clone(),
            test: true,
        })
        .unwrap();
        store.save_test(&v.id, &r).unwrap();
        store.save_preview(v, id, i, r).unwrap()
    }
    fn run(store: &Store, id: &str) -> bool {
        let mut changed = false;
        for p in store.pending_checks(Some(id)).unwrap() {
            let r = check_engine::execute(Request {
                spec: p.version.spec.clone(),
                values: p.input.values.clone(),
                test: false,
            })
            .unwrap();
            changed |= store.commit_check(&p, &r).unwrap();
        }
        changed
    }
    #[test]
    fn immutable_versions_review_scope_and_rollback() {
        let (_d, s, id, _) = fixture();
        sample(&s, &id, 95.0, now());
        let v = draft(&s);
        assert_eq!(
            s.propose_check(&v.check_id, v.spec.clone(), "codex")
                .unwrap()
                .id,
            v.id
        );
        assert!(s.activate_check(&id, &v.id, "none").is_err());
        let p = preview(&s, &id, &v);
        assert!(s.activate_check(&id, &v.id, "wrong").is_err());
        s.activate_check(&id, &v.id, &p.token).unwrap();
        assert!(s.activate_check(&id, &v.id, &p.token).is_err());
        let mut spec = v.spec.clone();
        spec.name = "Version 2".into();
        let v2 = s.propose_check(&v.check_id, spec, "claude").unwrap();
        let p = preview(&s, &id, &v2);
        sample(&s, &id, 96.0, now());
        assert!(s.activate_check(&id, &v2.id, &p.token).is_err());
        let p = preview(&s, &id, &v2);
        s.activate_check(&id, &v2.id, &p.token).unwrap();
        assert!(s.discard_check_version(&v.id).is_err());
        let p = preview(&s, &id, &v);
        s.activate_check(&id, &v.id, &p.token).unwrap();
        let b = binding(&s.0.lock().unwrap(), &id, &v.check_id)
            .unwrap()
            .unwrap();
        assert_eq!(b.version_id, v.id);
        assert_eq!(b.previous_version_id, Some(v2.id));
    }
    #[test]
    fn manual_custom_resolution_survives_bad_inputs_and_allows_a_new_episode_after_recovery() {
        let (_d, s, id, _) = fixture();
        let at = now();
        sample(&s, &id, 95.0, at);
        let v = draft(&s);
        let p = preview(&s, &id, &v);
        s.activate_check(&id, &v.id, &p.token).unwrap();
        run(&s, &id);
        sample(&s, &id, 96.0, at + 1);
        run(&s, &id);
        let i = s.snapshot().unwrap().incidents.remove(0);
        s.resolve_incident(&i.id, &i.episode, at + 2).unwrap();
        sample(&s, &id, 97.0, at + 3);
        run(&s, &id);
        assert_eq!(s.snapshot().unwrap().incidents[0].status, "resolved");
        assert!(!s.snapshot().unwrap().incidents[0].auto_eligible);
        sample(&s, &id, 50.0, at + 4);
        run(&s, &id);
        sample(&s, &id, 51.0, at + 5);
        run(&s, &id);
        assert!(!s.snapshot().unwrap().incidents[0].manual_resolution_pending);
        sample(&s, &id, 96.0, at + 6);
        run(&s, &id);
        sample(&s, &id, 97.0, at + 7);
        run(&s, &id);
        assert_ne!(s.snapshot().unwrap().incidents[0].episode, i.episode);
    }
    #[test]
    fn distinct_windows_dedupe_unknown_recovery_and_auto() {
        let (_d, s, id, _) = fixture();
        let at = now();
        sample(&s, &id, 95.0, at);
        let v = draft(&s);
        let p = preview(&s, &id, &v);
        s.activate_check(&id, &v.id, &p.token).unwrap();
        s.save_settings(&Settings {
            mode: "auto".into(),
            daily_run_limit: Some(10),
            daily_token_limit: Some(1000000),
            ..Settings::default()
        })
        .unwrap();
        assert!(run(&s, &id));
        assert!(!run(&s, &id));
        assert!(s.snapshot().unwrap().incidents.is_empty());
        sample(&s, &id, 96.0, at + 1);
        run(&s, &id);
        s.reconcile_auto(now()).unwrap();
        assert_eq!(s.auto_status(now()).unwrap().queued, 1);
        let incident = s.snapshot().unwrap().incidents[0].clone();
        for n in 2..8 {
            sample(&s, &id, 97.0, at + n);
            run(&s, &id);
            s.reconcile_auto(now()).unwrap();
        }
        assert_eq!(s.auto_status(now()).unwrap().queued, 1);
        assert_eq!(s.snapshot().unwrap().incidents[0].episode, incident.episode);
        sample(&s, &id, 1.0, at - 86400);
        run(&s, &id);
        assert_eq!(s.snapshot().unwrap().incidents[0].status, "open");
        assert!(!s.snapshot().unwrap().incidents[0].auto_eligible);
        sample(&s, &id, 50.0, at + 8);
        run(&s, &id);
        assert_eq!(s.snapshot().unwrap().incidents[0].status, "open");
        assert!(!run(&s, &id));
        sample(&s, &id, 51.0, at + 9);
        run(&s, &id);
        assert_eq!(s.snapshot().unwrap().incidents[0].status, "resolved");
        assert_eq!(s.auto_status(now()).unwrap().runs, 0);
        let db = s.0.lock().unwrap();
        let n: i64 = db
            .query_row("SELECT count(*) FROM check_evidence", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 5);
    }
    #[test]
    fn stale_results_endpoint_change_and_runtime_failure() {
        let (_d, s, id, source) = fixture();
        sample(&s, &id, 95.0, now());
        let v = draft(&s);
        let p = preview(&s, &id, &v);
        s.activate_check(&id, &v.id, &p.token).unwrap();
        let pending = s.pending_checks(Some(&id)).unwrap().pop().unwrap();
        s.disable_check(&id, &v.check_id).unwrap();
        let response = check_engine::execute(Request {
            spec: v.spec.clone(),
            values: pending.input.values.clone(),
            test: false,
        })
        .unwrap();
        assert!(!s.commit_check(&pending, &response).unwrap());
        let p = preview(&s, &id, &v);
        s.activate_check(&id, &v.id, &p.token).unwrap();
        s.block_check_version(&v.id, "timeout").unwrap();
        assert!(
            !binding(&s.0.lock().unwrap(), &id, &v.check_id)
                .unwrap()
                .unwrap()
                .enabled
        );
        assert!(s.activate_check(&id, &v.id, &p.token).is_err());
        let p = preview(&s, &id, &v);
        let mut hosts = crate::inventory::parse_manual(&source.location).unwrap();
        hosts[0].endpoint.port = 2;
        s.import(&source, hosts).unwrap();
        assert!(s.activate_check(&id, &v.id, &p.token).is_err());
        assert!(s.check_view(&id, Some(&v.check_id)).unwrap().definitions[0]
            .binding
            .is_none());
    }
    #[test]
    fn transaction_failure_does_not_advance_check_or_incident() {
        let (_d, s, id, _) = fixture();
        sample(&s, &id, 95.0, now());
        let mut spec = check_engine::example();
        spec.bad_windows = 1;
        let check = s.new_check().unwrap();
        let v = s.propose_check(&check, spec, "user").unwrap();
        let p = preview(&s, &id, &v);
        s.activate_check(&id, &v.id, &p.token).unwrap();
        let pending = s.pending_checks(Some(&id)).unwrap().pop().unwrap();
        let r = check_engine::execute(Request {
            spec: v.spec.clone(),
            values: pending.input.values.clone(),
            test: false,
        })
        .unwrap();
        s.0.lock().unwrap().execute_batch("CREATE TRIGGER fail_check BEFORE INSERT ON check_runs BEGIN SELECT RAISE(ABORT,'fixture failure'); END;").unwrap();
        assert!(s.commit_check(&pending, &r).is_err());
        assert!(s.snapshot().unwrap().incidents.is_empty());
        assert!(binding(&s.0.lock().unwrap(), &id, &check)
            .unwrap()
            .unwrap()
            .input_id
            .is_empty());
        s.0.lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_check")
            .unwrap();
        assert!(s.commit_check(&pending, &r).unwrap());
        assert!(!s.commit_check(&pending, &r).unwrap());
    }
    #[test]
    fn closed_evidence_expires_despite_continued_healthy_checks() {
        let (_d, s, id, _) = fixture();
        let at = now();
        sample(&s, &id, 95.0, at);
        let v = draft(&s);
        let p = preview(&s, &id, &v);
        s.activate_check(&id, &v.id, &p.token).unwrap();
        run(&s, &id);
        sample(&s, &id, 96.0, at + 1);
        run(&s, &id);
        sample(&s, &id, 50.0, at + 2);
        run(&s, &id);
        sample(&s, &id, 51.0, at + 3);
        run(&s, &id);
        let closed = now() - 31 * 86400;
        {
            let db = s.0.lock().unwrap();
            db.execute(
                "UPDATE incidents SET payload=json_set(payload,'$.updatedAt',?1)",
                [closed],
            )
            .unwrap();
            db.execute("UPDATE check_runs SET at=?1", [closed]).unwrap();
        }
        sample(&s, &id, 52.0, at + 4);
        run(&s, &id);
        assert_eq!(s.snapshot().unwrap().incidents[0].updated_at, closed);
        let db = s.0.lock().unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM check_evidence", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM check_runs", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    #[test]
    fn retention_and_version_quota() {
        let (_d, s, id, _) = fixture();
        let v = draft(&s);
        let mut latest = v.id.clone();
        for n in 1..20 {
            let mut spec = v.spec.clone();
            spec.name = format!("Draft {n}");
            latest = s.propose_check(&v.check_id, spec, "user").unwrap().id;
        }
        let mut spec = v.spec.clone();
        spec.name = "too many".into();
        assert!(s.propose_check(&v.check_id, spec, "user").is_err());
        {
            let db = s.0.lock().unwrap();
            db.execute("UPDATE check_versions SET at=?1", [now() - 31 * 86400])
                .unwrap();
            for n in 0..130 {
                db.execute(
                    "INSERT INTO check_runs VALUES(?1,?2,?3,?4,?5,'{}')",
                    params![n.to_string(), id, v.check_id, latest, now()],
                )
                .unwrap();
            }
            trim_runs(&db).unwrap();
            let count: i64 = db
                .query_row("SELECT count(*) FROM check_runs", [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, 100);
            let count: i64 = db
                .query_row("SELECT count(*) FROM check_versions", [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, 1);
        }
        s.delete_source("checks").unwrap();
        let db = s.0.lock().unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM check_runs", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    #[tokio::test]
    #[ignore = "Runs real macOS Seatbelt; execute outside nested tool sandbox"]
    async fn real_isolated_worker_and_pipeline() {
        let dir = tempfile::tempdir().unwrap();
        let app = crate::create_state(dir.path().to_owned()).unwrap();
        let source = Source {
            id: "runtime".into(),
            name: "Test".into(),

            kind: "manual".into(),
            location: "tester@127.0.0.1:1".into(),
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
        sample(&app.store, &id, 95.0, now());
        let v = draft(&app.store);
        let p = preview_version(app.clone(), id.clone(), v.id.clone())
            .await
            .unwrap();
        assert!(p.response.report.unwrap().passed);
        app.store.activate_check(&id, &v.id, &p.token).unwrap();
        assert!(run_pending(app.clone(), Some(id.clone())).await.unwrap());
        assert!(!run_pending(app.clone(), Some(id.clone())).await.unwrap());
        sample(&app.store, &id, 96.0, now() + 1);
        assert!(run_pending(app.clone(), Some(id)).await.unwrap());
        assert_eq!(app.store.snapshot().unwrap().incidents.len(), 1);
        assert!(app.store.investigations().unwrap().is_empty());
    }
}
