use crate::{model::*, package_refresh, ssh, store::Store, AppState};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};
pub type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
pub const INTERVAL: i64 = 21600;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Package {
    pub name: String,
    pub arch: String,
    pub version: String,
    pub source: String,
    pub source_version: String,
    pub status: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub distro: String,
    pub release: String,
    pub version: String,
    pub architecture: String,
    pub kernel: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub revision: u64,
    pub token: String,
    pub next_check: i64,
    pub last_success: Option<i64>,
    pub failures: u32,
    pub error: Option<String>,
    pub root: Option<String>,
    pub previous: Option<String>,
    pub metadata: Option<Metadata>,
    pub checks: u64,
    pub stage: Option<Manifest>,
    pub pending: Vec<u8>,
    pub offset: usize,
    pub stage_at: i64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub root: String,
    pub metadata: Metadata,
    pub hashes: Vec<String>,
    pub count: usize,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Reply {
    version: u32,
    at: i64,
    metadata: Metadata,
    root: String,
    count: usize,
    kind: String,
    #[serde(default)]
    hashes: Vec<String>,
    #[serde(default)]
    groups: Vec<Group>,
    next: Option<Page>,
    #[serde(default)]
    candidates: Vec<Value>,
    cache_at: Option<i64>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    bucket: u8,
    offset: usize,
    rows: Vec<Package>,
    complete: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    buckets: Vec<u8>,
    offset: usize,
}
pub fn digest<T: Serialize>(v: &T) -> String {
    format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&serde_json::to_value(v).expect("serializable inventory"))
                .expect("serializable inventory")
        )
    )
}
fn hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn bucket(p: &Package) -> u8 {
    Sha256::digest(format!("{}:{}", p.name, p.arch).as_bytes())[0] % 128
}
fn valid_package(p: &Package) -> bool {
    let name = |s: &str| {
        !s.is_empty()
            && s.len() <= 200
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+.-".contains(&b))
    };
    let version = |s: &str| {
        !s.is_empty()
            && s.len() <= 256
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".+:~_-".contains(&b))
    };
    name(&p.name)
        && name(&p.source)
        && !p.arch.is_empty()
        && p.arch.len() <= 32
        && p.arch
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && version(&p.version)
        && version(&p.source_version)
        && [
            "installed",
            "unpacked",
            "half-configured",
            "half-installed",
            "triggers-awaited",
            "triggers-pending",
        ]
        .contains(&p.status.as_str())
}
impl State {
    fn new(id: &str) -> Self {
        Self {
            revision: 0,
            token: uuid::Uuid::new_v4().to_string(),
            next_check: now() + id.bytes().map(i64::from).sum::<i64>() % 600,
            last_success: None,
            failures: 0,
            error: None,
            root: None,
            previous: None,
            metadata: None,
            checks: 0,
            stage: None,
            pending: vec![],
            offset: 0,
            stage_at: 0,
        }
    }
}
pub(crate) fn read_buckets(
    db: &rusqlite::Connection,
    id: &str,
    root: &str,
) -> Result<Vec<Package>> {
    let mut query = db
        .prepare(
            "SELECT payload FROM package_buckets WHERE server_id=?1 AND root=?2 ORDER BY bucket",
        )
        .map_err(err)?;
    let rows = query
        .query_map(params![id, root], |row| row.get::<_, String>(0))
        .map_err(err)?;
    let mut packages = Vec::new();
    for row in rows {
        packages.extend(serde_json::from_str::<Vec<Package>>(&row.map_err(err)?).map_err(err)?);
    }
    Ok(packages)
}

fn saved_state(db: &rusqlite::Connection, id: &str) -> Result<Option<State>> {
    let raw: Option<String> = db
        .query_row(
            "SELECT payload FROM package_state WHERE server_id=?1",
            [id],
            |r| r.get(0),
        )
        .optional()
        .map_err(err)?;
    raw.map(|raw| serde_json::from_str(&raw).map_err(err))
        .transpose()
}
impl Store {
    pub(crate) fn package_state(&self, id: &str) -> Result<State> {
        let db = self.0.lock().map_err(err)?;
        if let Some(state) = saved_state(&db, id)? {
            return Ok(state);
        }
        let state = State::new(id);
        db.execute(
            "INSERT INTO package_state VALUES(?1,?2)",
            params![id, serde_json::to_string(&state).map_err(err)?],
        )
        .map_err(err)?;
        Ok(state)
    }
    pub(crate) fn package_schedule(&self, servers: &[Server]) -> Result<BTreeMap<String, i64>> {
        let mut result = {
            let db = self.0.lock().map_err(err)?;
            let mut q = db
                .prepare("SELECT server_id,json_extract(payload,'$.nextCheck') FROM package_state")
                .map_err(err)?;
            let rows = q
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(err)?;
            rows.collect::<std::result::Result<BTreeMap<_, _>, _>>()
                .map_err(err)?
        };
        for s in servers {
            if !result.contains_key(&s.id) {
                result.insert(s.id.clone(), self.package_state(&s.id)?.next_check);
            }
        }
        Ok(result)
    }
    pub(crate) fn package_snapshot(&self, id: &str) -> Result<(State, Vec<Package>)> {
        let db = self.0.lock().map_err(err)?;
        let state = saved_state(&db, id)?.unwrap_or_else(|| State::new(id));
        let rows = match state.root.as_deref() {
            Some(root) => read_buckets(&db, id, root)?,
            None => vec![],
        };
        Ok((state, rows))
    }
    pub(crate) fn cached_package_state(&self, id: &str) -> Result<State> {
        Ok(saved_state(&*self.0.lock().map_err(err)?, id)?.unwrap_or_else(|| State::new(id)))
    }
    fn package_transaction_complete(&self, id: &str, state: &State) -> Result<bool> {
        let db = self.0.lock().map_err(err)?;
        db.query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM package_buckets b, json_each(b.payload) p
             WHERE b.server_id=?1 AND b.root=?2 AND json_extract(p.value,'$.status')!='installed')",
            params![id, state.root],
            |r| r.get(0),
        )
        .map_err(err)
    }
    pub(crate) fn record_packages(
        &self,
        server: &Server,
        expected: &State,
        bytes: &[u8],
        at: i64,
    ) -> Result<State> {
        if bytes.len() > 32768 {
            return Err("Package response greater than 32 KiB".into());
        }
        let reply: Reply =
            serde_json::from_slice(bytes).map_err(|_| "Incorrect response of packages")?;
        if reply.version != 1
            || !hash(&reply.root)
            || reply.count > 20000
            || reply.metadata.kernel.len() > 256
            || [
                &reply.metadata.distro,
                &reply.metadata.release,
                &reply.metadata.version,
                &reply.metadata.architecture,
            ]
            .iter()
            .any(|s| {
                s.is_empty()
                    || s.len() > 64
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
            || reply.at.abs_diff(at) > 86400
            || !reply.candidates.is_empty()
            || reply.cache_at.is_some()
        {
            return Err("Incompatible package shot".into());
        }
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
        if serde_json::to_value(current.endpoint).map_err(err)?
            != serde_json::to_value(&server.endpoint).map_err(err)?
        {
            return Err("Connection has changed".into());
        }
        let raw: String = tx
            .query_row(
                "SELECT payload FROM package_state WHERE server_id=?1",
                [&server.id],
                |r| r.get(0),
            )
            .map_err(err)?;
        let mut state: State = serde_json::from_str(&raw).map_err(err)?;
        if state.revision != expected.revision || state.token != expected.token {
            return Err("The position of the packages has already changed".into());
        }
        let old_root = state.root.clone();
        let mut complete = false;
        match reply.kind.as_str() {
            "unchanged" => {
                if state.root.as_deref() != Some(&reply.root)
                    || state.metadata.as_ref() != Some(&reply.metadata)
                    || state.stage.is_some()
                {
                    return Err("Misconfirmation of the image".into());
                }
                complete = true;
            }
            "manifest" => {
                if reply.hashes.len() != 128
                    || reply.hashes.iter().any(|s| !hash(s))
                    || digest(&json!({"metadata":reply.metadata,"hashes":reply.hashes}))
                        != reply.root
                {
                    return Err("Wrong manifesto".into());
                }
                tx.execute(
                    "DELETE FROM package_buckets WHERE server_id=?1 AND root NOT IN (?2,?3)",
                    params![server.id, state.root, state.previous],
                )
                .map_err(err)?;
                // Delete explicitly too when either old root is NULL (SQL NOT IN null is unknown).
                tx.execute("DELETE FROM package_buckets WHERE server_id=?1 AND root!=coalesce(?2,'') AND root!=coalesce(?3,'')",params![server.id,state.root,state.previous]).map_err(err)?;
                state.pending.clear();
                state.offset = 0;
                for b in 0..128u8 {
                    let old:Option<(String,String)>=tx.query_row("SELECT hash,payload FROM package_buckets WHERE server_id=?1 AND root=?2 AND bucket=?3",params![server.id,state.root,b],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(err)?;
                    if let Some((h, p)) = old.filter(|(h, _)| h == &reply.hashes[b as usize]) {
                        tx.execute(
                            "INSERT OR REPLACE INTO package_buckets VALUES(?1,?2,?3,?4,?5)",
                            params![server.id, reply.root, b, h, p],
                        )
                        .map_err(err)?;
                    } else {
                        state.pending.push(b);
                    }
                }
                state.stage = Some(Manifest {
                    root: reply.root,
                    metadata: reply.metadata,
                    hashes: reply.hashes,
                    count: reply.count,
                });
                state.stage_at = at;
            }
            "page" => {
                let stage = state.stage.as_ref().ok_or("No package transfer")?;
                if stage.root != reply.root
                    || stage.metadata != reply.metadata
                    || stage.count != reply.count
                    || reply.groups.is_empty()
                {
                    return Err("The picture changed during the broadcast".into());
                }
                for (index, g) in reply.groups.iter().enumerate() {
                    if state.pending.first() != Some(&g.bucket)
                        || g.offset != state.offset
                        || g.rows
                            .iter()
                            .any(|p| !valid_package(p) || bucket(p) != g.bucket)
                    {
                        return Err("Wrong package page".into());
                    }
                    let previous:Option<String>=tx.query_row("SELECT payload FROM package_buckets WHERE server_id=?1 AND root=?2 AND bucket=?3",params![server.id,stage.root,g.bucket],|r|r.get(0)).optional().map_err(err)?;
                    let mut rows: Vec<Package> = previous
                        .map(|s| serde_json::from_str(&s).map_err(err))
                        .transpose()?
                        .unwrap_or_default();
                    if rows.len() != g.offset {
                        return Err("Shifting packages has changed".into());
                    }
                    rows.extend(g.rows.clone());
                    if rows.len() > 512
                        || rows
                            .windows(2)
                            .any(|w| (&w[0].name, &w[0].arch) >= (&w[1].name, &w[1].arch))
                    {
                        return Err("Limit or duplicate packages".into());
                    }
                    let h = digest(&rows);
                    if g.complete && h != stage.hashes[g.bucket as usize] {
                        return Err("The hash of the packages didn’t match".into());
                    }
                    tx.execute(
                        "INSERT OR REPLACE INTO package_buckets VALUES(?1,?2,?3,?4,?5)",
                        params![
                            server.id,
                            stage.root,
                            g.bucket,
                            h,
                            serde_json::to_string(&rows).map_err(err)?
                        ],
                    )
                    .map_err(err)?;
                    if g.complete {
                        state.pending.remove(0);
                        state.offset = 0;
                    } else {
                        if index + 1 != reply.groups.len() {
                            return Err("Incomplete intermediate group".into());
                        }
                        state.offset = rows.len();
                    }
                }
                match reply.next {
                    Some(p) if p.buckets == state.pending && p.offset == state.offset => {}
                    None if state.pending.is_empty() => {}
                    _ => return Err("Incorrect continuation of packages".into()),
                }
            }
            "changed" => {
                state.stage = None;
                state.pending.clear();
                state.offset = 0;
                state.failures = state.failures.saturating_add(1);
                state.error = Some("Packages changed during transmission; repeat later".into());
            }
            _ => return Err("Unexpected response of packages".into()),
        }
        let staged_bytes:u64=tx.query_row("SELECT coalesce(sum(length(payload)),0) FROM package_buckets WHERE server_id=?1 AND root=?2",params![server.id,state.stage.as_ref().map(|s|&s.root)],|r|r.get(0)).map_err(err)?;
        if staged_bytes > 8 * 1024 * 1024 {
            return Err("Package image exceeds 8 MiB".into());
        }
        if state.stage.is_some() && state.pending.is_empty() {
            let stage = state.stage.take().unwrap();
            let count:i64=tx.query_row("SELECT coalesce(sum(json_array_length(payload)),0) FROM package_buckets WHERE server_id=?1 AND root=?2",params![server.id,stage.root],|r|r.get(0)).map_err(err)?;
            if count as usize != stage.count {
                return Err("Incomplete packages".into());
            }
            state.previous = state.root.take();
            state.root = Some(stage.root);
            state.metadata = Some(stage.metadata);
            complete = true;
        }
        if complete {
            state.last_success = Some(at);
            state.checks += 1;
            state.failures = 0;
            state.error = None;
            state.next_check = at + INTERVAL + server.id.bytes().map(i64::from).sum::<i64>() % 60;
            tx.execute("DELETE FROM package_buckets WHERE server_id=?1 AND root!=coalesce(?2,'') AND root!=coalesce(?3,'')",params![server.id,state.root,state.previous]).map_err(err)?;
            if state.root != old_root {
                tx.execute(
                    "UPDATE advisory_sources SET payload=json_set(payload,'$.nextCheck',0)
                     WHERE ((?3='debian' AND id='debian') OR (?3='ubuntu' AND id IN ('ubuntu-cve:'||?2,'ubuntu-usn:'||?2)))
                     AND json_extract(payload,'$.error') IS NULL
                     AND NOT EXISTS(SELECT 1 FROM json_each(advisory_sources.payload,'$.roots') WHERE value=?1)",
                    params![state.root,state.metadata.as_ref().map(|m|&m.release),state.metadata.as_ref().map(|m|&m.distro)],
                ).map_err(err)?;
            }
            tx.execute(
                "INSERT INTO vulnerability_pending VALUES(?1) ON CONFLICT DO NOTHING",
                [&server.id],
            )
            .map_err(err)?;
        } else {
            state.next_check = at
                + if state.failures > 0 {
                    (60 * 2i64.pow(state.failures.min(6))).min(3600)
                } else {
                    5
                };
        }
        state.revision += 1;
        tx.execute(
            "UPDATE package_state SET payload=?2 WHERE server_id=?1",
            params![server.id, serde_json::to_string(&state).map_err(err)?],
        )
        .map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(state)
    }
    fn package_error(&self, id: &str, expected: &State) -> Result<()> {
        let db = self.0.lock().map_err(err)?;
        crate::monitoring::check_commit(&db)?;
        let raw: Option<String> = db
            .query_row(
                "SELECT payload FROM package_state WHERE server_id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        if let Some(raw) = raw {
            let mut s: State = serde_json::from_str(&raw).map_err(err)?;
            if s.revision == expected.revision && s.token == expected.token {
                s.failures = s.failures.saturating_add(1);
                s.next_check = now() + (60 * 2i64.pow(s.failures.min(6))).min(3600);
                s.error =
                    Some("Package composition unconfirmed; last successful snapshot saved".into());
                if now() - s.stage_at > 3600 {
                    s.stage = None;
                    s.pending.clear();
                    s.offset = 0;
                }
                db.execute(
                    "UPDATE package_state SET payload=?2 WHERE server_id=?1",
                    params![id, serde_json::to_string(&s).map_err(err)?],
                )
                .map_err(err)?;
                db.execute("UPDATE incidents SET payload=json_set(payload,'$.autoEligible',json('false'),'$.freshUntil',?2,'$.healthyStreak',0) WHERE server_id=?1 AND json_extract(payload,'$.check') LIKE 'vuln:%'",params![id,now()-1]).map_err(err)?;
            }
        }
        Ok(())
    }
}
pub(crate) async fn collect(state: Arc<AppState>, id: String) -> Result<State> {
    crate::monitoring::run(&state.store, "packages", &id, "", async {
        collect_inner(state.clone(), id.clone(), false, None)
            .await
            .map(|(state, _)| state)
    })
    .await
}
pub(crate) async fn rescan(state: Arc<AppState>, id: String) -> Result<State> {
    crate::monitoring::run(&state.store, "packages", &id, "", async {
        collect_inner(state.clone(), id.clone(), true, None)
            .await
            .map(|(state, _)| state)
    })
    .await
}
const ENDPOINT_CHANGED: &str = "Connection has changed";
const PAUSED: &str = "Monitoring on pause";
const STORAGE_BLOCKED: &str = "Storage is full";

pub(crate) async fn refresh_after_ssh(state: Arc<AppState>, id: String, job: package_refresh::Job) {
    use package_refresh::Outcome;
    let scan = crate::monitoring::run(&state.store, "packages", &id, "", async {
        collect_inner(state.clone(), id.clone(), true, Some(&job.endpoint)).await
    })
    .await;
    let outcome = match scan {
        Ok((checkpoint, changed)) => {
            let stable_change = changed
                && state
                    .store
                    .package_transaction_complete(&id, &checkpoint)
                    .unwrap_or(false);
            if stable_change {
                if let Ok(Some(source)) = state.store.package_scope_source(&checkpoint) {
                    state.package_refresh.prioritize_advisory(source);
                }
            }
            Outcome::Collected {
                checks: checkpoint.checks,
                changed: stable_change,
            }
        }
        Err(error) if error == ENDPOINT_CHANGED || error == "The server is remote" => {
            Outcome::Obsolete
        }
        Err(error)
            if matches!(
                error.as_str(),
                crate::collector_queue::BUSY
                    | PAUSED
                    | STORAGE_BLOCKED
                    | crate::monitoring::POLICY_CHANGED
            ) =>
        {
            Outcome::Contended
        }
        Err(error) if error == ssh::PACKAGE_DATABASE_BUSY => Outcome::Busy,
        Err(_) => {
            let seconds = state
                .store
                .cached_package_state(&id)
                .map_or(120, |s| (s.next_check - now()).clamp(10, 3600));
            Outcome::Failed(Duration::from_secs(seconds as u64))
        }
    };
    state
        .package_refresh
        .finish(&id, job, outcome, Instant::now());
}

async fn collect_inner(
    state: Arc<AppState>,
    id: String,
    complete_scan: bool,
    expected_endpoint: Option<&Endpoint>,
) -> Result<(State, bool)> {
    let mut _activity_span = crate::activity::begin("server", "packages.collect", Some(id.clone()));
    let _activity_result = (async {
        let _guard = state.collectors.acquire(&id, &state.store).await?;
        let snapshot = state.store.snapshot()?;
        let server = snapshot
            .servers
            .into_iter()
            .find(|s| s.id == id)
            .ok_or("The server is remote")?;
        if let Some(endpoint) = expected_endpoint {
            if server.endpoint != *endpoint {
                return Err(ENDPOINT_CHANGED.into());
            }
            if snapshot.settings.paused {
                return Err(PAUSED.into());
            }
        }
        if state.store.storage_status()?.blocked {
            return Err(STORAGE_BLOCKED.into());
        }
        let mut checkpoint = state.store.package_state(&id)?;
        let old_root = checkpoint.root.clone();
        let result = async {
            ssh::deploy(&server.endpoint, &state.collector).await?;
            let mut restarted = false;
            for _ in 0..512 {
                let input = if let Some(stage) = &checkpoint.stage {
                    json!({"root":stage.root,"buckets":checkpoint.pending,"offset":checkpoint.offset})
                } else {
                    json!({"root":checkpoint.root})
                };
                let bytes = ssh::run_collector(
                    &server.endpoint,
                    &json!({"kind":"packages","state":input}),
                    32768,
                )
                .await?;
                checkpoint = state
                    .store
                    .record_packages(&server, &checkpoint, &bytes, now())?;
                if !complete_scan {
                    return Ok((checkpoint.clone(), checkpoint.root != old_root));
                }
                if checkpoint.stage.is_none() {
                    match &checkpoint.error {
                        None => return Ok((checkpoint.clone(), checkpoint.root != old_root)),
                        Some(_) if restarted && expected_endpoint.is_some() => return Err(ssh::PACKAGE_DATABASE_BUSY.into()),
                        Some(error) if restarted => return Err(error.clone()),
                        Some(_) => restarted = true,
                    }
                }
            }
            Err("Failed to complete the transfer of the package list in one check".into())
        }
        .await;
        if result.as_ref().is_err_and(|error| expected_endpoint.is_none() || !matches!(error.as_str(), ssh::PACKAGE_DATABASE_BUSY | ENDPOINT_CHANGED | crate::monitoring::POLICY_CHANGED)) {
            state.store.package_error(&id, &checkpoint)?;
        }
        result
    })
    .await;
    _activity_span.result(&_activity_result);
    _activity_result
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Candidate {
    pub package: String,
    pub version: Option<String>,
    pub source: Option<String>,
    pub source_version: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Apt {
    pub candidate: Candidate,
    pub cache_at: Option<i64>,
    pub at: i64,
    pub root: String,
}
impl Store {
    pub(crate) fn apt_targets(&self, id: &str) -> Result<Vec<String>> {
        let state = self.package_state(id)?;
        let db = self.0.lock().map_err(err)?;
        let mut q=db.prepare("SELECT DISTINCT json_extract(p.value,'$.name') AS name FROM vulnerability_groups f,json_each(f.payload,'$.packages') p WHERE f.server_id=?1 AND f.hidden_at IS NULL AND json_extract(f.payload,'$.state')='affected' AND NOT EXISTS(SELECT 1 FROM vulnerability_apt a WHERE a.server_id=?1 AND a.package=json_extract(p.value,'$.name') AND a.root=?2 AND a.at>?3) LIMIT 8").map_err(err)?;
        let rows = q
            .query_map(params![id, state.root, now() - 21600], |r| r.get(0))
            .map_err(err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err)
    }
    pub(crate) fn apt_cached(&self, id: &str) -> Result<BTreeMap<String, Apt>> {
        let db = self.0.lock().map_err(err)?;
        let mut q = db
            .prepare("SELECT package,payload FROM vulnerability_apt WHERE server_id=?1")
            .map_err(err)?;
        let rows = q
            .query_map([id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(err)?;
        rows.map(|r| {
            let (k, v) = r.map_err(err)?;
            Ok((k, serde_json::from_str(&v).map_err(err)?))
        })
        .collect()
    }
}
pub(crate) async fn collect_apt(app: Arc<AppState>, id: String) -> Result<()> {
    crate::monitoring::run(
        &app.store,
        "apt",
        &id,
        "",
        collect_apt_inner(app.clone(), id.clone()),
    )
    .await
}
async fn collect_apt_inner(app: Arc<AppState>, id: String) -> Result<()> {
    let mut _activity_span =
        crate::activity::begin("server", "packages.collect_apt", Some(id.clone()));
    let _activity_result=(async {
    let _guard = app.collectors.acquire(&id, &app.store).await?;
    let snapshot = app.store.snapshot()?;
    let server = snapshot
        .servers
        .into_iter()
        .find(|s| s.id == id)
        .ok_or("The server is remote")?;
    let expected = app.store.package_state(&id)?;
    if expected.stage.is_some() {
        return Err("Wait until the list of installed packages is completed.".into());
    }
    if expected.root.is_none() {
        return Err("First, rescan the list of installed packages.".into());
    }
    let targets = app.store.apt_targets(&id)?;
    if targets.is_empty() {
        return Ok(());
    }
    ssh::deploy(&server.endpoint, &app.collector).await?;
    let bytes = ssh::run_collector(
        &server.endpoint,
        &json!({"kind":"packages","state":{"root":expected.root,"apt":targets}}),
        32768,
    )
    .await?;
    let reply: Reply = serde_json::from_slice(&bytes).map_err(err)?;
    if reply.kind == "changed" {
        return Err("The package composition on the server has changed. First, scan the list of packages installed.".into());
    }
    if reply.kind != "apt"
        || reply.version != 1
        || Some(&reply.root) != expected.root.as_ref()
        || Some(&reply.metadata) != expected.metadata.as_ref()
        || reply.candidates.len() > targets.len()
    {
        return Err("The server returned an unexpected APT check result.".into());
    }
    let mut candidates = BTreeMap::new();
    for c in reply.candidates {
        let c: Candidate = serde_json::from_value(c).map_err(err)?;
        if !targets.contains(&c.package)
            || c.version
                .as_ref()
                .is_some_and(|v| crate::debversion::compare(v, v).is_none())
            || c.source_version
                .as_ref()
                .is_some_and(|v| crate::debversion::compare(v, v).is_none())
            || c.source.as_ref().is_some_and(|s| {
                s.len() > 200
                    || !s.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b"+.-".contains(&b)
                    })
            })
        {
            return Err("Incorrect APT candidate".into());
        }
        candidates.insert(c.package.clone(), c);
    }
    let mut db = app.store.0.lock().map_err(err)?;
    crate::storage::admit(&db)?;
    let tx = db.transaction().map_err(err)?;
        crate::monitoring::check_commit(&tx)?;
    let raw: String = tx
        .query_row(
            "SELECT payload FROM package_state WHERE server_id=?1",
            [&id],
            |r| r.get(0),
        )
        .map_err(err)?;
    let current: State = serde_json::from_str(&raw).map_err(err)?;
    if current.token != expected.token || current.revision != expected.revision {
        return Err("Picture replaced".into());
    }
    for name in targets {
        let candidate = candidates.remove(&name).unwrap_or(Candidate {
            package: name.clone(),
            version: None,
            source: None,
            source_version: None,
        });
        let entry = Apt {
            candidate,
            cache_at: reply.cache_at.filter(|t| *t <= now() + 300),
            at: now(),
            root: reply.root.clone(),
        };
        tx.execute("INSERT INTO vulnerability_apt VALUES(?1,?2,?3,?4,?5) ON CONFLICT(server_id,package) DO UPDATE SET root=excluded.root,at=excluded.at,payload=excluded.payload",params![id,name,reply.root,entry.at,serde_json::to_string(&entry).map_err(err)?]).map_err(err)?;
    }
    tx.execute(
        "DELETE FROM vulnerability_apt WHERE server_id=?1 AND root!=?2",
        params![id, reply.root],
    )
    .map_err(err)?;
    tx.commit().map_err(err)

    }).await;
    _activity_span.result(&_activity_result);
    _activity_result
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub fn fixture() -> (Store, Server) {
        let db = Store::open(std::path::Path::new(":memory:")).unwrap();
        let source = Source {
            id: "s".into(),
            name: "test".into(),

            kind: "manual".into(),
            location: "ops@node".into(),
            last_sync: None,
            error: None,
        };
        db.import(
            &source,
            crate::inventory::parse_manual(&source.location).unwrap(),
        )
        .unwrap();
        let s = db.snapshot().unwrap().servers.remove(0);
        (db, s)
    }
    pub fn package() -> Package {
        Package {
            name: "openssl".into(),
            arch: "amd64".into(),
            version: "3.0.0-1".into(),
            source: "openssl".into(),
            source_version: "3.0.0-1".into(),
            status: "installed".into(),
        }
    }
    pub fn install(db: &Store, s: &Server, rows: Vec<Package>) -> State {
        let meta = Metadata {
            distro: "debian".into(),
            release: "bookworm".into(),
            version: "12".into(),
            architecture: "x86_64".into(),
            kernel: "6.1.0".into(),
        };
        let mut buckets = vec![vec![]; 128];
        for row in rows {
            buckets[bucket(&row) as usize].push(row);
        }
        for b in &mut buckets {
            b.sort_by(|a, b| (&a.name, &a.arch).cmp(&(&b.name, &b.arch)));
        }
        let hashes = buckets.iter().map(digest).collect::<Vec<_>>();
        let root = digest(&json!({"metadata":meta,"hashes":hashes}));
        let count = buckets.iter().map(Vec::len).sum::<usize>();
        let st = db.package_state(&s.id).unwrap();
        let manifest = json!({"version":1,"at":now(),"metadata":meta,"root":root,"count":count,"kind":"manifest","hashes":hashes});
        let st = db
            .record_packages(s, &st, &serde_json::to_vec(&manifest).unwrap(), now())
            .unwrap();
        if st.stage.is_none() {
            return st;
        }
        let groups = st
            .pending
            .iter()
            .map(|b| json!({"bucket":b,"offset":0,"rows":buckets[*b as usize],"complete":true}))
            .collect::<Vec<_>>();
        let page = json!({"version":1,"at":now(),"metadata":meta,"root":root,"count":count,"kind":"page","groups":groups,"next":null});
        db.record_packages(s, &st, &serde_json::to_vec(&page).unwrap(), now())
            .unwrap()
    }
    #[test]
    fn snapshots_are_atomic_idempotent_and_bounded() {
        let (db, s) = fixture();
        let first = install(&db, &s, vec![package()]);
        assert!(first.root.is_some());
        assert!(first.stage.is_none());
        let reply = json!({"version":1,"at":now(),"metadata":first.metadata,"root":first.root,"count":1,"kind":"unchanged"});
        let bytes = serde_json::to_vec(&reply).unwrap();
        db.record_packages(&s, &first, &bytes, now()).unwrap();
        assert!(db.record_packages(&s, &first, &bytes, now()).is_err());
        let mut p = package();
        p.version = "3.0.1-1".into();
        install(&db, &s, vec![p.clone()]);
        p.version = "3.0.2-1".into();
        install(&db, &s, vec![p]);
        let conn = db.0.lock().unwrap();
        let roots: i64 = conn
            .query_row(
                "SELECT count(DISTINCT root) FROM package_buckets",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(roots, 2);
    }
    #[test]
    fn failed_transaction_and_changed_endpoint_keep_checkpoint() {
        let (db, s) = fixture();
        let state = install(&db, &s, vec![package()]);
        let reply = json!({"version":1,"at":now(),"metadata":state.metadata,"root":state.root,"count":1,"kind":"unchanged"});
        let bytes = serde_json::to_vec(&reply).unwrap();
        {
            let conn = db.0.lock().unwrap();
            conn.execute_batch("CREATE TRIGGER fail BEFORE UPDATE ON package_state BEGIN SELECT RAISE(ABORT,'disk full'); END;").unwrap();
        }
        assert!(db.record_packages(&s, &state, &bytes, now()).is_err());
        assert_eq!(db.package_state(&s.id).unwrap().revision, state.revision);
        {
            let conn = db.0.lock().unwrap();
            conn.execute_batch("DROP TRIGGER fail;").unwrap();
        }
        let mut other = s.clone();
        other.endpoint.port = 22 + 1;
        assert!(db.record_packages(&other, &state, &bytes, now()).is_err());
        assert_eq!(db.package_state(&s.id).unwrap().checks, state.checks);
    }
}
