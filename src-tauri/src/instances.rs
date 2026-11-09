//! Stable identity with derived port/PID labels; legacy SQL names are never displayed.
use crate::{services, store::Store};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
pub const DEFAULT: &str = "default";
pub fn default_id() -> String {
    DEFAULT.into()
}
pub fn validate(id: &str) -> Result<()> {
    if id == DEFAULT || uuid::Uuid::parse_str(id).is_ok_and(|u| u.to_string() == id) {
        Ok(())
    } else {
        Err("Invalid connection ID".into())
    }
}
pub fn scope(kind: &str, id: &str) -> String {
    if id == DEFAULT {
        kind.into()
    } else {
        format!("{kind}@{id}")
    }
}
pub fn prefix(kind: &str, id: &str) -> String {
    let namespace =
        services::descriptor(kind).map_or("service:", |spec| spec.incident_namespace.as_str());
    format!("{namespace}{}:%", scope(kind, id))
}
pub fn supports(kind: &str) -> bool {
    services::descriptor(kind).is_some_and(|spec| spec.multiple)
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Instance {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub can_add: bool,
    pub can_remove: bool,
}
pub fn ensure(db: &Connection, server: &str, kind: &str, id: &str) -> Result<()> {
    validate(id)?;
    if services::descriptor(kind).is_none() {
        return Err("Unknown connector".into());
    }
    if id == DEFAULT {
        db.execute("INSERT OR IGNORE INTO service_instances(server_id,kind,id,name) SELECT ?1,?2,'default','' WHERE EXISTS(SELECT 1 FROM servers WHERE id=?1)",params![server,kind]).map_err(err)?;
    }
    if !db.query_row("SELECT EXISTS(SELECT 1 FROM service_instances WHERE server_id=?1 AND kind=?2 AND id=?3)",params![server,kind,id],|r|r.get::<_,bool>(0)).map_err(err)?{return Err("The connection or server was removed".into());}
    Ok(())
}
pub fn name(db: &Connection, server: &str, kind: &str, id: &str) -> Result<String> {
    Ok(Names::load(db, Some(server))?.name(server, kind, id))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeIdentity {
    pub kind: String,
    pub pid: u32,
    pub ports: Vec<u16>,
    pub sockets: Vec<String>,
    pub complete: bool,
}

pub(crate) struct Names(std::collections::BTreeMap<(String, String, String), String>);
impl Names {
    pub fn load(db: &Connection, server: Option<&str>) -> Result<Self> {
        use std::collections::BTreeMap;
        let catalog = services::catalog();
        let mut runtime: BTreeMap<String, Vec<RuntimeIdentity>> = BTreeMap::new();
        let mut q=db.prepare("SELECT id,json_extract(payload,'$.observation.serviceRuntime'),coalesce(json_extract(payload,'$.observation.serviceRuntimeComplete'),0) FROM servers WHERE (?1 IS NULL OR id=?1)").map_err(err)?;
        let rows = q
            .query_map([server], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, bool>(2)?,
                ))
            })
            .map_err(err)?;
        for row in rows {
            let (id, data, complete) = row.map_err(err)?;
            if complete {
                let records: Vec<RuntimeIdentity> = data
                    .and_then(|v| serde_json::from_str(&v).ok())
                    .unwrap_or_default();
                if records.len() <= 64 {
                    runtime.insert(id, records);
                }
            }
        }
        let mut targets: BTreeMap<(String, String, String), (String, u16)> = BTreeMap::new();
        let mut q=db.prepare("SELECT server_id,kind,instance_id,coalesce(json_extract(payload,'$.config.endpoint'),json_extract(payload,'$.config.host')),json_extract(payload,'$.config.port') FROM service_state WHERE (?1 IS NULL OR server_id=?1) AND json_type(payload,'$.config')='object'").map_err(err)?;
        let rows = q
            .query_map([server], |r| {
                Ok(((r.get(0)?, r.get(1)?, r.get(2)?), (r.get(3)?, r.get(4)?)))
            })
            .map_err(err)?;
        for row in rows {
            let (key, target) = row.map_err(err)?;
            targets.insert(key, target);
        }
        let mut groups: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
        let mut q=db.prepare("SELECT server_id,kind,id FROM service_instances WHERE (?1 IS NULL OR server_id=?1) ORDER BY server_id,kind,CASE WHEN id='default' THEN 0 ELSE 1 END,id").map_err(err)?;
        let rows = q
            .query_map([server], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })
            .map_err(err)?;
        for row in rows {
            let (server, kind, id) = row.map_err(err)?;
            groups.entry((server, kind)).or_default().push(id);
        }
        let mut names = BTreeMap::new();
        for ((server, kind), ids) in groups {
            let Some(spec) = catalog.get(&kind) else {
                continue;
            };
            for id in &ids {
                let mut label = spec.name.clone();
                if ids.len() > 1 {
                    let (endpoint, port) = targets
                        .get(&(server.clone(), kind.clone(), id.clone()))
                        .cloned()
                        .unwrap_or((spec.endpoint.clone(), spec.port));
                    let canonical = |v: &str| v.replacen("/var/run/", "/run/", 1);
                    let candidates = runtime
                        .get(&server)
                        .into_iter()
                        .flatten()
                        .filter(|r| {
                            r.kind == kind
                                && r.complete
                                && r.pid > 0
                                && r.ports.len() <= 16
                                && r.sockets.len() <= 4
                                && r.ports.iter().all(|p| *p > 0)
                                && if endpoint.starts_with('/') {
                                    let expected = spec.unix_socket_name.as_ref().map_or_else(
                                        || endpoint.clone(),
                                        |filename| {
                                            format!(
                                                "{}/{}",
                                                endpoint.trim_end_matches('/'),
                                                filename.replace("{port}", &port.to_string())
                                            )
                                        },
                                    );
                                    r.sockets
                                        .iter()
                                        .any(|p| canonical(p) == canonical(&expected))
                                } else {
                                    r.ports.contains(&port)
                                }
                        })
                        .collect::<Vec<_>>();
                    if candidates.len() == 1 {
                        let r = candidates[0];
                        label = if let Some(port) = r.ports.iter().min() {
                            format!("{label}:{port}")
                        } else {
                            format!("{label} · PID {}", r.pid)
                        };
                    } else {
                        label = format!("{label}:—");
                    }
                }
                names.insert((server.clone(), kind.clone(), id.clone()), label);
            }
        }
        Ok(Self(names))
    }
    pub fn decorate_incident(&self, incident: &mut crate::model::Incident) {
        let title = self.incident_title(&incident.server_id, &incident.check, &incident.title);
        if title != incident.title {
            if let Some(tail) = incident.evidence.strip_prefix(&incident.title) {
                incident.evidence = format!("{title}{tail}");
            }
            incident.title = title;
        }
    }
    pub fn incident_title(&self, server: &str, check: &str, old: &str) -> String {
        let (scope, metric) = if let Some(key) = check.strip_prefix("service:") {
            key.split_once(':').unwrap_or(("", ""))
        } else {
            check.split_once(':').unwrap_or(("", ""))
        };
        let (kind, id) = scope.split_once('@').unwrap_or((scope, DEFAULT));
        if let Some(title) = services::backend(kind)
            .and_then(|adapter| (adapter.incident_title)(metric, &self.name(server, kind, id)))
        {
            return title;
        }
        if let Some(label) = services::descriptor(kind).and_then(|spec| {
            spec.metrics
                .iter()
                .find(|m| m.key == metric)
                .map(|m| &m.label)
        }) {
            return format!("{}: {}", self.name(server, kind, id), label);
        }
        old.into()
    }
    pub fn name(&self, server: &str, kind: &str, id: &str) -> String {
        self.0
            .get(&(server.into(), kind.into(), id.into()))
            .cloned()
            .unwrap_or_else(|| {
                services::catalog()
                    .get(kind)
                    .map(|s| s.name.clone())
                    .unwrap_or_else(|| kind.into())
            })
    }
}
impl Store {
    pub(crate) fn service_instances(&self, server: &str) -> Result<Vec<Instance>> {
        let db = self.0.lock().map_err(err)?;
        for kind in services::catalog().keys() {
            ensure(&db, server, kind, DEFAULT)?;
        }
        let mut q=db.prepare("SELECT id,kind FROM service_instances WHERE server_id=?1 ORDER BY kind,CASE WHEN id='default' THEN 0 ELSE 1 END,id").map_err(err)?;
        let names = Names::load(&db, Some(server))?;
        let rows = q
            .query_map([server], |r| {
                let id: String = r.get(0)?;
                let kind: String = r.get(1)?;
                Ok(Instance {
                    can_add: supports(&kind),
                    can_remove: id != DEFAULT,
                    name: names.name(server, &kind, &id),
                    id,
                    kind,
                })
            })
            .map_err(err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err)
    }
    pub(crate) fn add_service_instance(
        &self,
        server: &str,
        kind: &str,
        port: Option<u16>,
    ) -> Result<Instance> {
        if !supports(kind) {
            return Err("This service supports one diagnostic connection".into());
        }
        if port == Some(0) {
            return Err("The port must be between 1 and 65535".into());
        }
        let mut db = self.0.lock().map_err(err)?;
        crate::storage::admit(&db)?;
        let tx = db.transaction().map_err(err)?;
        for kind in services::catalog().keys() {
            ensure(&tx, server, kind, DEFAULT)?;
        }
        let count: i64 = tx
            .query_row(
                "SELECT count(*) FROM service_instances WHERE server_id=?1",
                [server],
                |r| r.get(0),
            )
            .map_err(err)?;
        if count >= 64 {
            return Err("No more than 64 service connections per server".into());
        }
        let id = uuid::Uuid::new_v4().to_string();
        tx.execute(
            "INSERT INTO service_instances VALUES(?1,?2,?3,?4)",
            params![server, kind, id, ""],
        )
        .map_err(err)?;
        let payload = services::initial_payload(server, kind, &id, port)?;
        tx.execute(
            "INSERT INTO service_state(server_id,kind,payload,instance_id) VALUES(?1,?2,?3,?4)",
            params![server, kind, payload, id],
        )
        .map_err(err)?;
        let name = name(&tx, server, kind, &id)?;
        tx.commit().map_err(err)?;
        Ok(Instance {
            id,
            kind: kind.into(),
            name,
            can_add: true,
            can_remove: true,
        })
    }
    pub(crate) fn remove_service_instance(&self, server: &str, kind: &str, id: &str) -> Result<()> {
        validate(id)?;
        if id == DEFAULT {
            return Err("You can disable diagnostics in the connection settings".into());
        }
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        ensure(&tx, server, kind, id)?;
        tx.execute("DELETE FROM monitoring_overrides WHERE server_id=?1 AND definition_id=?2 AND instance_id=?3",params![server,kind,id]).map_err(err)?;
        tx.execute(
            "UPDATE monitoring_control SET revision=revision+1 WHERE id=1",
            [],
        )
        .map_err(err)?;
        let p = prefix(kind, id);
        tx.execute("DELETE FROM ai_jobs WHERE incident_id IN (SELECT id FROM incidents WHERE server_id=?1 AND json_extract(payload,'$.check') LIKE ?2)",params![server,p]).map_err(err)?;
        tx.execute(
            "DELETE FROM incidents WHERE server_id=?1 AND json_extract(payload,'$.check') LIKE ?2",
            params![server, p],
        )
        .map_err(err)?;
        for table in ["service_state", "service_summaries"] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE server_id=?1 AND kind=?2 AND instance_id=?3"),
                params![server, kind, id],
            )
            .map_err(err)?;
        }
        tx.execute(
            "DELETE FROM service_instances WHERE server_id=?1 AND kind=?2 AND id=?3",
            params![server, kind, id],
        )
        .map_err(err)?;
        tx.commit().map_err(err)
    }
    #[cfg(test)]
    pub(crate) fn extra_instance_schedule(&self) -> Result<Vec<(i64, String, String, String)>> {
        Ok(self
            .service_schedule(&[])?
            .into_iter()
            .filter(|(_, _, _, id)| id != DEFAULT)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn setup() -> (Store, String) {
        let db = Store::open(std::path::Path::new(":memory:")).unwrap();
        let source = crate::model::Source {
            id: "s".into(),
            name: "s".into(),
            kind: "manual".into(),
            location: "root@host".into(),
            last_sync: None,
            error: None,
        };
        db.import(
            &source,
            crate::inventory::parse_manual(&source.location).unwrap(),
        )
        .unwrap();
        let id = db.snapshot().unwrap().servers[0].id.clone();
        db.service_instances(&id).unwrap();
        (db, id)
    }
    fn runtime(db: &Store, id: &str, records: serde_json::Value, complete: bool) {
        let value = json!({"at":crate::model::now(),"cpuPercent":1,"memoryPercent":1,"swapPercent":0,"load":0,"uptime":1,"disks":[],"services":[],"missing":[],"bytesReceived":100,"durationMs":1,"serviceRuntime":records,"serviceRuntimeComplete":complete});
        db.0.lock()
            .unwrap()
            .execute(
                "UPDATE servers SET payload=json_set(payload,'$.observation',json(?2)) WHERE id=?1",
                params![id, value.to_string()],
            )
            .unwrap();
    }
    #[test]
    fn single_has_no_alias_multiple_uses_lowest_owned_port_and_keeps_identity() {
        let (db, id) = setup();
        db.0.lock()
            .unwrap()
            .execute(
                "UPDATE service_instances SET name='Legacy main' WHERE server_id=?1",
                [&id],
            )
            .unwrap();
        assert_eq!(
            name(&db.0.lock().unwrap(), &id, "redis", DEFAULT).unwrap(),
            "Redis"
        );
        let extra = db.add_service_instance(&id, "redis", Some(6380)).unwrap();
        runtime(
            &db,
            &id,
            json!([{ "kind":"redis","pid":100,"ports":[16379,6379],"sockets":[],"complete":true},{"kind":"redis","pid":200,"ports":[16380,6380],"sockets":[],"complete":true}]),
            true,
        );
        let labels = db.service_instances(&id).unwrap();
        assert_eq!(
            labels
                .iter()
                .find(|i| i.kind == "redis" && i.id == DEFAULT)
                .unwrap()
                .name,
            "Redis:6379"
        );
        assert_eq!(
            labels.iter().find(|i| i.id == extra.id).unwrap().name,
            "Redis:6380"
        );
        assert_eq!(
            db.service_state_for(&id, "redis", &extra.id)
                .unwrap()
                .config
                .port,
            6380
        );
        let title = Names::load(&db.0.lock().unwrap(), Some(&id))
            .unwrap()
            .incident_title(
                &id,
                &format!("service:redis@{}:blocked", extra.id),
                "Redis · Sessions: old",
            );
        assert_eq!(title, "Redis:6380: Blocked clients");
        db.remove_service_instance(&id, "redis", &extra.id).unwrap();
        assert_eq!(
            name(&db.0.lock().unwrap(), &id, "redis", DEFAULT).unwrap(),
            "Redis"
        );
    }
    #[test]
    fn unix_only_postgresql_uses_pid_and_incomplete_metadata_does_not_invent_ports() {
        let (db, id) = setup();
        let extra = db
            .add_service_instance(&id, "postgresql", Some(5433))
            .unwrap();
        runtime(
            &db,
            &id,
            json!([{ "kind":"postgresql","pid":100,"ports":[],"sockets":["/run/postgresql/.s.PGSQL.5432"],"complete":true},{"kind":"postgresql","pid":200,"ports":[],"sockets":["/var/run/postgresql/.s.PGSQL.5433"],"complete":true}]),
            true,
        );
        assert_eq!(
            name(&db.0.lock().unwrap(), &id, "postgresql", DEFAULT).unwrap(),
            "PostgreSQL · PID 100"
        );
        assert_eq!(
            name(&db.0.lock().unwrap(), &id, "postgresql", &extra.id).unwrap(),
            "PostgreSQL · PID 200"
        );
        runtime(
            &db,
            &id,
            json!([{ "kind":"postgresql","pid":100,"ports":[5432],"sockets":["/run/postgresql/.s.PGSQL.5432"],"complete":false}]),
            true,
        );
        assert_eq!(
            name(&db.0.lock().unwrap(), &id, "postgresql", DEFAULT).unwrap(),
            "PostgreSQL:—"
        );
    }
    #[test]
    fn secondary_sql_port_does_not_hide_a_smaller_listener() {
        let (db, id) = setup();
        db.add_service_instance(&id, "cockroach", Some(26258))
            .unwrap();
        runtime(
            &db,
            &id,
            json!([{ "kind":"cockroach","pid":101,"ports":[26257,8080],"sockets":[],"complete":true}]),
            true,
        );
        assert_eq!(
            name(&db.0.lock().unwrap(), &id, "cockroach", DEFAULT).unwrap(),
            "CockroachDB:8080"
        );
    }
    #[test]
    fn runtime_metadata_is_latest_state_and_not_duplicated_in_metric_history() {
        let (db, id) = setup();
        runtime(
            &db,
            &id,
            json!([{ "kind":"redis","pid":100,"ports":[6379],"sockets":[],"complete":true}]),
            true,
        );
        let server: crate::model::Server = {
            let sql = db.0.lock().unwrap();
            let payload: String = sql
                .query_row("SELECT payload FROM servers WHERE id=?1", [&id], |r| {
                    r.get(0)
                })
                .unwrap();
            serde_json::from_str(&payload).unwrap()
        };
        let observation = server.observation.clone().unwrap();
        db.record(&server, Ok(observation), 180).unwrap();
        let saved: String =
            db.0.lock()
                .unwrap()
                .query_row("SELECT payload FROM servers WHERE id=?1", [&id], |r| {
                    r.get(0)
                })
                .unwrap();
        assert!(saved.contains("serviceRuntime\""));
        assert!(db.snapshot().unwrap().servers[0]
            .observation
            .as_ref()
            .unwrap()
            .service_runtime
            .is_empty());
        let data: String =
            db.0.lock()
                .unwrap()
                .query_row("SELECT payload FROM observations LIMIT 1", [], |r| r.get(0))
                .unwrap();
        assert!(!data.contains("serviceRuntime\""));
    }
}
