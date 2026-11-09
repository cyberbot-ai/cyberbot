//! Deterministic correlation of local incident episodes, never an assertion of root cause.
use crate::{
    automation::{self, Job},
    inventory::stable_id,
    model::*,
    store::Store,
};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
pub const WINDOW: i64 = 600;
pub const SETTLE: i64 = 120;
pub const MAX_SERVERS: usize = 500;
const MAX_DEPENDENCIES: usize = 64;
const MAX_MEMBERS: usize = 1000;
pub const PAGE: usize = 20;
fn clip(s: &str, n: usize) -> String {
    let mut end = s.len().min(n);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].into()
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub id: String,
    pub key: String,

    pub title: String,
    pub reason: String,
    pub basis: String,
    pub opened_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub closed_at: Option<i64>,
    pub status: String,
    pub severity: String,
    pub member_count: usize,
    pub server_count: usize,
    pub removed_members: usize,
    pub auto_state: Option<String>,
    pub run_id: Option<String>,
    pub dispatched_at: Option<i64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    pub incident: Incident,
    pub server_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_address: Option<String>,
    pub joined_at: i64,
    pub truncated: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub group: Group,
    pub members: Vec<Member>,
    pub total: usize,
    pub offset: usize,
    pub next_offset: Option<usize>,
    pub dependencies: Vec<(String, String)>,
    pub dependencies_truncated: bool,
    pub fresh: usize,
    pub open: usize,
    pub outside_scope: usize,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Overview {
    pub groups: Vec<Group>,
    pub total: usize,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Dependencies {
    pub depends_on: Vec<String>,
    pub available: Vec<Node>,
}
#[derive(Serialize)]
pub struct Node {
    pub id: String,
    pub name: String,
    pub host: String,
    pub address: String,
}
pub(crate) fn members(db: &Connection, id: &str) -> Result<Vec<Member>> {
    let mut q=db.prepare("SELECT payload FROM incident_group_members WHERE group_id=?1 ORDER BY opened_at,episode").map_err(err)?;
    let rows = q.query_map([id], |r| r.get::<_, String>(0)).map_err(err)?;
    rows.map(|r| serde_json::from_str(&r.map_err(err)?).map_err(err))
        .collect()
}
pub(crate) fn read(db: &Connection, id: &str) -> Result<Group> {
    let raw: String = db
        .query_row(
            "SELECT payload FROM incident_groups WHERE id=?1",
            [id],
            |r| r.get(0),
        )
        .map_err(err)?;
    serde_json::from_str(&raw).map_err(err)
}
fn write(db: &Connection, g: &Group) -> Result<()> {
    db.execute("INSERT INTO incident_groups VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(id) DO UPDATE SET correlation_key=excluded.correlation_key,status=excluded.status,updated_at=excluded.updated_at,payload=excluded.payload",params![g.id,g.key,g.opened_at,g.status,g.updated_at,serde_json::to_string(g).map_err(err)?]).map_err(err)?;
    Ok(())
}
fn member_write(db: &Connection, g: &str, m: &Member) -> Result<()> {
    db.execute("INSERT INTO incident_group_members VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(episode) DO UPDATE SET payload=excluded.payload",params![automation::episode(&m.incident),g,m.incident.id,m.incident.server_id,m.incident.opened_at,serde_json::to_string(m).map_err(err)?]).map_err(err)?;
    Ok(())
}
fn capture(i: &Incident, s: &Server, at: i64) -> Member {
    let truncated =
        i.evidence.len() > 384 || i.title.len() > 160 || i.check.len() > 512 || s.name.len() > 128;
    let mut i = i.clone();
    i.check = clip(&i.check, 512);
    i.evidence = clip(&i.evidence, 384);
    i.title = clip(&i.title, 160);
    Member {
        incident: i,
        server_name: clip(&s.name, 128),
        server_address: Some(clip(&crate::ssh::target(&s.endpoint), 240)),
        joined_at: at,
        truncated,
    }
}
pub(crate) fn operational(check: &str) -> Option<String> {
    if matches!(
        check,
        "connection" | "cpu" | "memory" | "logs:oom" | "logs:disk_io" | "logs:service_crash"
    ) || check.starts_with("disk:")
    {
        return Some(check.into());
    }
    let bare = check.strip_prefix("service:").unwrap_or(check);
    let kind = bare.split([':', '@']).next()?;
    if crate::services::descriptor(kind).is_some() {
        if let Some((kind, tail)) = check.split_once('@') {
            return tail
                .split_once(':')
                .map(|(_, metric)| format!("{kind}:{metric}"));
        }
        return Some(check.into());
    }
    None
}
fn topology(db: &Connection, servers: &[Server]) -> Result<BTreeMap<String, String>> {
    let mut adjacency: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let index: BTreeMap<_, _> = servers.iter().map(|s| (&s.id, s)).collect();
    let mut q = db
        .prepare("SELECT server_id,depends_on FROM server_dependencies")
        .map_err(err)?;
    let rows = q
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(err)?;
    for row in rows {
        let (a, b) = row.map_err(err)?;
        if index.contains_key(&a) && index.contains_key(&b) {
            adjacency.entry(a.clone()).or_default().push(b.clone());
            adjacency.entry(b).or_default().push(a);
        }
    }
    let mut result = BTreeMap::new();
    for seed in adjacency.keys() {
        if result.contains_key(seed) {
            continue;
        }
        let mut stack = vec![seed.clone()];
        let mut component = BTreeSet::new();
        while let Some(id) = stack.pop() {
            if component.insert(id.clone()) {
                stack.extend(adjacency.get(&id).cloned().unwrap_or_default());
            }
        }
        let key = component.first().cloned().unwrap();
        for id in component {
            result.insert(id, key.clone());
        }
    }
    Ok(result)
}
/// One Ansible inventory file declares one dependency component. Servers are
/// linked as a star to a hub of that file: the whole inventory on its first
/// link, afterwards only servers that are new or changed their endpoint, so
/// links the operator removed by hand are not restored by periodic syncs.
pub(crate) fn link_inventory(
    db: &Connection,
    source: &str,
    ids: &[String],
    fresh: &BTreeSet<String>,
) -> Result<()> {
    // A larger component could not be investigated as one group anyway.
    if ids.len() > MAX_SERVERS {
        return Ok(());
    }
    let seeded = db
        .execute("INSERT OR IGNORE INTO inventory_links VALUES(?1)", [source])
        .map_err(err)?
        == 0;
    let link: Vec<&String> = ids
        .iter()
        .filter(|id| !seeded || fresh.contains(*id))
        .collect();
    if ids.len() < 2 || link.is_empty() {
        return Ok(());
    }
    // Keep the hub the operator's star already uses, otherwise the first host.
    let mut incoming: BTreeMap<String, usize> = BTreeMap::new();
    let mut q = db
        .prepare("SELECT d.depends_on FROM server_dependencies d JOIN servers s ON s.id=d.server_id WHERE s.source_id=?1")
        .map_err(err)?;
    for row in q
        .query_map([source], |r| r.get::<_, String>(0))
        .map_err(err)?
    {
        *incoming.entry(row.map_err(err)?).or_default() += 1;
    }
    let hub = ids
        .iter()
        .enumerate()
        .max_by_key(|(n, id)| {
            (
                incoming.get(*id).copied().unwrap_or(0),
                std::cmp::Reverse(*n),
            )
        })
        .map(|(_, id)| id)
        .unwrap();
    for id in link.into_iter().filter(|id| *id != hub) {
        let declared: usize = db
            .query_row(
                "SELECT count(*) FROM server_dependencies WHERE server_id=?1",
                [id],
                |r| r.get(0),
            )
            .map_err(err)?;
        if declared < MAX_DEPENDENCIES {
            db.execute(
                "INSERT OR IGNORE INTO server_dependencies VALUES(?1,?2)",
                params![id, hub],
            )
            .map_err(err)?;
        }
    }
    Ok(())
}
fn signature(
    i: &Incident,
    s: &Server,
    topology: &BTreeMap<String, String>,
) -> Option<(String, String)> {
    let check = operational(&i.check)?;
    let (scope, reason) = if let Some(component) = topology.get(&s.id) {
        (
            format!("dependency:{component}"),
            "A clearly defined dependency; the start of events within 10 minutes",
        )
    } else if i.check == "connection" && s.endpoint.jump_host.is_some() {
        (
            format!("bastion:{}", s.endpoint.jump_host.as_ref().unwrap()),
            "General ProxyJump and connection errors within 10 minutes",
        )
    } else {
        (
            format!("cohort:source:{}:{check}", s.source_id),
            "One check on one server list; start within 10 minutes",
        )
    };
    Some((stable_id("correlation:v2", &scope), reason.into()))
}
/// Re-key existing groups without changing their identity, evidence or dispatch
/// history. A mixed legacy cohort stays sealed instead of admitting new nodes.
pub(crate) fn migrate_flat_servers(db: &Connection) -> Result<()> {
    let servers: Vec<Server> = Store::list(db, "servers")?;
    let graph = topology(db, &servers)?;
    let index: BTreeMap<_, _> = servers.iter().map(|s| (&s.id, s)).collect();
    for mut group in Store::list::<Group>(db, "incident_groups")? {
        let signals: BTreeSet<_> = members(db, &group.id)?
            .iter()
            .filter_map(|m| {
                index
                    .get(&m.incident.server_id)
                    .and_then(|s| signature(&m.incident, s, &graph))
            })
            .collect();
        if signals.len() == 1 {
            let (key, reason) = signals.into_iter().next().unwrap();
            group.key = key;
            group.reason = reason;
        } else {
            group.key = stable_id("legacy-incident-group", &group.id);
            group.reason =
                "Events combined in the previous version; composition and history of the investigation are preserved"
                    .into();
        }
        write(db, &group)?;
    }
    Ok(())
}
pub(crate) fn hold(i: &Incident, servers: &[Server]) -> bool {
    operational(&i.check).is_some()
        && servers.len() > 1
        && servers.iter().any(|s| s.id == i.server_id)
}
pub(crate) fn reconcile(
    db: &Connection,
    incidents: &[Incident],
    servers: &[Server],
    jobs: &[Job],
    at: i64,
) -> Result<BTreeMap<String, String>> {
    let topology = topology(db, servers)?;
    let si: BTreeMap<_, _> = servers.iter().map(|s| (&s.id, s)).collect();
    let ii: BTreeMap<_, _> = incidents.iter().map(|i| (&i.id, i)).collect();
    let mut groups: Vec<Group> = Store::list(db, "incident_groups")?;
    let mut assigned = BTreeMap::new();
    let mut cached: BTreeMap<String, Vec<Member>> = BTreeMap::new();
    for g in &mut groups {
        let rows = members(db, &g.id)?;
        let lost = g.member_count.saturating_sub(rows.len());
        g.removed_members += lost;
        let mut updated = Vec::new();
        for mut m in rows {
            let before = serde_json::to_string(&m).map_err(err)?;
            let ep = automation::episode(&m.incident);
            if !si.contains_key(&m.incident.server_id) {
                assigned.insert(ep, g.id.clone());
                if m.incident.status != "withdrawn" {
                    g.removed_members += 1;
                    m.incident.status = "withdrawn".into();
                    m.incident.auto_eligible = false;
                    member_write(db, &g.id, &m)?;
                }
                updated.push(m);
                continue;
            }
            assigned.insert(ep.clone(), g.id.clone());
            if let Some(i) = ii.get(&m.incident.id) {
                if automation::episode(i) == ep {
                    if let Some(s) = si.get(&i.server_id) {
                        m = capture(i, s, m.joined_at);
                    }
                } else {
                    m.incident.status = "resolved".into();
                    m.incident.auto_eligible = false;
                }
            }
            if before != serde_json::to_string(&m).map_err(err)? {
                member_write(db, &g.id, &m)?;
            }
            updated.push(m);
        }
        if updated.iter().all(|m| m.incident.status != "open") && g.closed_at.is_none() {
            g.closed_at = Some(at);
        }
        cached.insert(g.id.clone(), updated);
    }
    let mut candidates: BTreeMap<String, Vec<(&Incident, &Server, String)>> = BTreeMap::new();
    for i in incidents.iter().filter(|i| i.status == "open") {
        let ep = automation::episode(i);
        if assigned.contains_key(&ep) {
            continue;
        }
        if let Some(s) = si.get(&i.server_id) {
            if let Some((key, reason)) = signature(i, s, &topology) {
                candidates.entry(key).or_default().push((i, s, reason));
            }
        }
    }
    for (key, mut items) in candidates {
        items.sort_by_key(|(i, _, _)| (i.opened_at, i.id.clone()));
        let mut pending = Vec::new();
        for (i, s, reason) in items {
            let existing = groups.iter().position(|g| {
                g.key == key
                    && g.closed_at.is_none()
                    && i.opened_at >= g.opened_at
                    && i.opened_at <= g.opened_at + WINDOW
            });
            if let Some(index) = existing {
                let g = &groups[index];
                let rows = cached.get_mut(&g.id).unwrap();
                let m = capture(i, s, at);
                member_write(db, &g.id, &m)?;
                rows.push(m);
                assigned.insert(automation::episode(i), g.id.clone());
            } else {
                pending.push((i, s, reason));
            }
        }
        while !pending.is_empty() {
            let first = pending[0].0.opened_at;
            let end = pending
                .iter()
                .position(|(i, _, _)| i.opened_at > first + WINDOW)
                .unwrap_or(pending.len());
            let batch: Vec<_> = pending.drain(..end).collect();
            if batch
                .iter()
                .map(|(_, s, _)| &s.id)
                .collect::<BTreeSet<_>>()
                .len()
                < 2
            {
                continue;
            }
            if groups.len() >= 5000 {
                return Err(
                    "Limit of 5,000 incident groups: Automobile stopped before clearing history"
                        .into(),
                );
            }
            let id = format!("group:{}", uuid::Uuid::new_v4());
            let previous = jobs
                .iter()
                .filter(|j| {
                    j.run_id.is_some()
                        && batch.iter().any(|(i, _, _)| automation::episode(i) == j.id)
                })
                .min_by_key(|j| j.dispatched_at);
            let g = Group {
                id: id.clone(),
                key: key.clone(),

                title: clip(&batch[0].0.title, 160),
                reason: batch[0].2.clone(),
                basis: if topology.contains_key(&batch[0].1.id) {
                    "dependency"
                } else if batch[0].0.check == "connection"
                    && batch[0].1.endpoint.jump_host.is_some()
                {
                    "bastion"
                } else {
                    "cohort"
                }
                .into(),
                opened_at: first,
                created_at: at,
                updated_at: at,
                closed_at: None,
                status: "open".into(),
                severity: "warning".into(),
                member_count: 0,
                server_count: 0,
                removed_members: 0,
                auto_state: previous.map(|j| j.state.clone()),
                run_id: previous.and_then(|j| j.run_id.clone()),
                dispatched_at: previous.and_then(|j| j.dispatched_at),
            };
            write(db, &g)?;
            let mut rows = Vec::new();
            for (i, s, _) in batch {
                let m = capture(i, s, at);
                member_write(db, &id, &m)?;
                rows.push(m);
                assigned.insert(automation::episode(i), id.clone());
            }
            cached.insert(id, rows);
            groups.push(g);
        }
    }
    let mut total = 0;
    for mut g in groups {
        let rows = &cached[&g.id];
        total += rows.len();
        let servers = rows
            .iter()
            .map(|m| &m.incident.server_id)
            .collect::<BTreeSet<_>>()
            .len();
        if rows.len() > MAX_MEMBERS || servers > MAX_SERVERS || total > 100000 {
            return Err(
                "Correlation limit: 500 servers/1000 events per crash, 100,000 connections in total".into(),
            );
        }
        let before = read(db, &g.id)?;
        g.member_count = rows.len();
        g.server_count = servers;
        g.severity = if rows
            .iter()
            .any(|m| m.incident.status == "open" && m.incident.severity == "critical")
        {
            "critical"
        } else {
            "warning"
        }
        .into();
        g.status = if rows.iter().any(|m| m.incident.status == "open") {
            "open"
        } else if g.removed_members > 0 || rows.is_empty() {
            "withdrawn"
        } else {
            "resolved"
        }
        .into();
        if g.status != "open" && g.closed_at.is_none() {
            g.closed_at = Some(at);
        }
        g.updated_at = rows
            .iter()
            .map(|m| m.incident.updated_at)
            .max()
            .unwrap_or(at)
            .max(g.updated_at);
        if serde_json::to_string(&before).map_err(err)? != serde_json::to_string(&g).map_err(err)? {
            write(db, &g)?;
        }
    }
    Ok(assigned)
}
pub(crate) fn eligible(db: &Connection, id: &str, s: &Settings, at: i64) -> Result<bool> {
    let mut q=db.prepare("SELECT i.payload,m.episode FROM incident_group_members m JOIN incidents i ON i.id=m.incident_id WHERE m.group_id=?1").map_err(err)?;
    let rows = q
        .query_map([id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .map_err(err)?;
    read(db, id)?;
    let servers: Vec<Server> = Store::list(db, "servers")?;
    for row in rows {
        let (raw, ep) = row.map_err(err)?;
        let i: Incident = serde_json::from_str(&raw).map_err(err)?;
        if automation::episode(&i) == ep
            && automation::fresh(&i, s, at)
            && servers.iter().any(|server| server.id == i.server_id)
        {
            return Ok(true);
        }
    }
    Ok(false)
}
pub(crate) fn targets(db: &Connection, id: &str) -> Result<Vec<String>> {
    let g = read(db, id)?;
    let servers: Vec<Server> = Store::list(db, "servers")?;
    let valid: BTreeSet<_> = servers.iter().map(|s| s.id.clone()).collect();
    let mut ids: BTreeSet<_> = members(db, id)?
        .into_iter()
        .map(|m| m.incident.server_id)
        .filter(|id| valid.contains(id))
        .collect();
    if g.basis == "dependency" {
        let graph = topology(db, &servers)?;
        let components: BTreeSet<_> = ids.iter().filter_map(|id| graph.get(id)).collect();
        ids.extend(
            graph
                .iter()
                .filter(|(id, component)| valid.contains(*id) && components.contains(component))
                .map(|(id, _)| id.clone()),
        );
    }
    if ids.len() > MAX_SERVERS {
        return Err("The incident group and its dependencies exceed 500 servers".into());
    }
    Ok(ids.into_iter().collect())
}
pub(crate) fn mark_run(
    db: &Connection,
    id: &str,
    state: &str,
    run: Option<&str>,
    at: i64,
) -> Result<()> {
    let mut g = read(db, id)?;
    g.auto_state = Some(state.into());
    if let Some(run) = run {
        g.run_id = Some(run.into());
        g.dispatched_at = Some(at);
    }
    write(db, &g)
}
pub(crate) fn job(db: &Connection, g: &Group, at: i64) -> Result<Option<Job>> {
    let rows = members(db, &g.id)?;
    let Some(first) = rows.first() else {
        return Ok(None);
    };
    let occurrences = rows
        .iter()
        .fold(0u64, |n, m| n.saturating_add(m.incident.occurrences));
    let last:Option<i64>=db.query_row("SELECT max(json_extract(payload,'$.dispatchedAt')) FROM incident_groups WHERE correlation_key=?1 AND id!=?2",params![g.key,g.id],|r|r.get(0)).map_err(err)?;
    Ok(Some(Job {
        id: g.id.clone(),
        group_id: Some(g.id.clone()),
        incident_id: first.incident.id.clone(),
        server_id: first.incident.server_id.clone(),
        title: format!("{} · {} server", g.title, g.server_count),
        evidence: format!(
            "{} events. {}. Common cause not yet proven.",
            g.member_count, g.reason
        ),
        severity: g.severity.clone(),
        occurrences,
        state: "queued".into(),
        created_at: g.created_at,
        not_before: (g.opened_at + SETTLE).max(last.map_or(at, |v| v + automation::COOLDOWN)),
        run_id: None,
        dispatched_at: None,
    }))
}
pub(crate) fn trim(db: &Connection, at: i64) -> Result<()> {
    db.execute("DELETE FROM incident_groups WHERE id IN (SELECT g.id FROM incident_groups g WHERE g.status!='open' AND g.updated_at<?1 AND NOT EXISTS(SELECT 1 FROM incident_group_members m JOIN incidents i ON i.id=m.incident_id WHERE m.group_id=g.id AND json_extract(i.payload,'$.status')='open' AND m.episode=coalesce(nullif(json_extract(i.payload,'$.episode'),''),i.id||':'||json_extract(i.payload,'$.openedAt'))) LIMIT 100)",[at-30*86400]).map_err(err)?;
    Ok(())
}
impl Store {
    pub(crate) fn incident_groups(&self, include_closed: bool, offset: usize) -> Result<Overview> {
        let db = self.0.lock().map_err(err)?;
        let mut groups: Vec<Group> = Self::list(&db, "incident_groups")?;
        groups.retain(|g| include_closed || g.status == "open");
        groups.sort_by_key(|g| {
            (
                g.status != "open",
                g.severity != "critical",
                std::cmp::Reverse(g.opened_at),
            )
        });
        let total = groups.len();
        Ok(Overview {
            groups: groups.into_iter().skip(offset).take(50).collect(),
            total,
        })
    }
    pub(crate) fn incident_group(
        &self,
        id: &str,
        offset: usize,
        allowed: Option<&BTreeSet<String>>,
    ) -> Result<View> {
        let db = self.0.lock().map_err(err)?;
        let group = read(&db, id)?;
        let s = Self::read_settings(&db)?;
        let all = members(&db, id)?;
        let before = all.len();
        let rows: Vec<_> = all
            .into_iter()
            .filter(|m| allowed.is_none_or(|a| a.contains(&m.incident.server_id)))
            .collect();
        let fresh = rows
            .iter()
            .filter(|m| automation::fresh(&m.incident, &s, now()))
            .count();
        let open = rows.iter().filter(|m| m.incident.status == "open").count();
        let total = rows.len();
        let mut v = View {
            group,
            members: rows.into_iter().skip(offset).take(PAGE).collect(),
            total,
            offset,
            next_offset: None,
            fresh,
            open,
            outside_scope: before - total,
            dependencies: Vec::new(),
            dependencies_truncated: false,
        };
        let names = crate::instances::Names::load(&db, None)?;
        for member in &mut v.members {
            names.decorate_incident(&mut member.incident);
        }
        let target_ids = targets(&db, id)?;
        let mut q=db.prepare("SELECT server_id,depends_on FROM server_dependencies ORDER BY server_id,depends_on").map_err(err)?;
        let edges = q
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(err)?;
        for edge in edges {
            let (a, b) = edge.map_err(err)?;
            if v.members.iter().any(|m| m.incident.server_id == a)
                && target_ids.contains(&b)
                && allowed.is_none_or(|scope| scope.contains(&b))
            {
                if v.dependencies.len() < 64 {
                    v.dependencies.push((a, b));
                } else {
                    v.dependencies_truncated = true;
                }
            }
        }
        while serde_json::to_vec(&v).map_err(err)?.len() > 30000 {
            if !v.dependencies.is_empty() {
                v.dependencies.pop();
                v.dependencies_truncated = true;
            } else if v.members.pop().is_none() {
                return Err("Incident group summary exceeds the limit".into());
            }
        }
        v.next_offset = if offset + v.members.len() < total {
            Some(offset + v.members.len())
        } else {
            None
        };
        Ok(v)
    }

    pub(crate) fn group_targets(&self, id: &str) -> Result<Vec<String>> {
        targets(&*self.0.lock().map_err(err)?, id)
    }
    pub(crate) fn server_dependencies(&self, id: &str) -> Result<Dependencies> {
        let db = self.0.lock().map_err(err)?;
        let servers: Vec<Server> = Self::list(&db, "servers")?;
        servers
            .iter()
            .find(|s| s.id == id)
            .ok_or("The server is remote")?;
        let mut q = db
            .prepare(
                "SELECT depends_on FROM server_dependencies WHERE server_id=?1 ORDER BY depends_on",
            )
            .map_err(err)?;
        let depends_on = q
            .query_map([id], |r| r.get::<_, String>(0))
            .map_err(err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err)?;
        Ok(Dependencies {
            depends_on,
            available: servers
                .iter()
                .filter(|s| s.id != id)
                .map(|s| Node {
                    id: s.id.clone(),
                    name: s.name.clone(),
                    host: s.endpoint.host.clone(),
                    address: crate::ssh::target(&s.endpoint),
                })
                .collect(),
        })
    }
    pub(crate) fn save_dependencies(&self, id: &str, depends_on: Vec<String>) -> Result<()> {
        if depends_on.len() > MAX_DEPENDENCIES {
            return Err(format!(
                "Nothing more {MAX_DEPENDENCIES} server dependencies"
            ));
        }
        let mut db = self.0.lock().map_err(err)?;
        crate::storage::admit(&db)?;
        let tx = db.transaction().map_err(err)?;
        let servers: Vec<Server> = Self::list(&tx, "servers")?;
        servers
            .iter()
            .find(|s| s.id == id)
            .ok_or("The server is remote")?;
        if depends_on
            .iter()
            .any(|d| d == id || !servers.iter().any(|s| s.id == *d))
        {
            return Err("The dependency must refer to another existing server".into());
        }
        tx.execute("DELETE FROM server_dependencies WHERE server_id=?1", [id])
            .map_err(err)?;
        for d in depends_on.into_iter().collect::<BTreeSet<_>>() {
            tx.execute(
                "INSERT INTO server_dependencies VALUES(?1,?2)",
                params![id, d],
            )
            .map_err(err)?;
        }
        tx.commit().map_err(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{agents::Investigation, inventory::parse_manual};
    use serde_json::json;
    use std::path::Path;
    const AT: i64 = 10 * 86400 + 100;
    fn populate(db: &Store, n: usize) -> Vec<Server> {
        let source = Source {
            id: "fleet".into(),
            name: "fleet".into(),

            kind: "manual".into(),
            location: (0..n)
                .map(|n| format!("ops@node-{n:03}"))
                .collect::<Vec<_>>()
                .join("\n"),
            last_sync: None,
            error: None,
        };
        db.import(&source, parse_manual(&source.location).unwrap())
            .unwrap();
        db.save_settings(&Settings {
            mode: "auto".into(),
            daily_run_limit: Some(1000),
            daily_token_limit: Some(1000000),
            run_token_limit: 1000,
            ..Settings::default()
        })
        .unwrap();
        db.snapshot().unwrap().servers
    }
    fn fixture(n: usize) -> (Store, Vec<Server>) {
        let db = Store::open(Path::new(":memory:")).unwrap();
        let servers = populate(&db, n);
        (db, servers)
    }
    #[test]
    fn v11_labels_are_removed_without_losing_servers_or_replaying_a_group() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("legacy.sqlite");
        let db = Store::open(&path).unwrap();
        let servers = populate(&db, 3);
        for server in &servers[..2] {
            event(&db, server, "cpu", AT, true);
        }
        db.reconcile_auto(AT).unwrap();
        let job = db.next_auto(AT + 120).unwrap().unwrap();
        let group = job.id.clone();
        let mut investigation = run(&db, &group, AT + 120);
        db.admit(&investigation, Some(&job.id)).unwrap();
        investigation.status = "completed".into();
        investigation.usage = json!({"totalTokens":77});
        investigation.usage_complete = true;
        db.settle(&investigation).unwrap();
        {
            let sql = db.0.lock().unwrap();
            sql.execute(
                "UPDATE sources SET payload=json_set(payload,'$.project','legacy')",
                [],
            )
            .unwrap();
            sql.execute("UPDATE servers SET payload=json_set(payload,'$.project','legacy','$.groups',json('[\"web\"]'))",[]).unwrap();
            let mut payload = serde_json::to_value(read(&sql, &group).unwrap()).unwrap();
            payload["project"] = json!("legacy");
            payload["projectKey"] = json!(stable_id("legacy", "project"));
            payload["key"] = json!("previous-correlation-key");
            sql.execute(
                "UPDATE incident_groups SET correlation_key=?2,payload=?3 WHERE id=?1",
                params![group, "previous-correlation-key", payload.to_string()],
            )
            .unwrap();
            sql.execute_batch("PRAGMA user_version=11").unwrap();
        }
        drop(db);
        let db = Store::open(&path).unwrap();
        let snapshot = db.snapshot().unwrap();
        assert_eq!(snapshot.servers.len(), 3);
        for original in &servers {
            let restored = snapshot
                .servers
                .iter()
                .find(|s| s.id == original.id)
                .unwrap();
            assert_eq!(
                serde_json::to_value(&restored.endpoint).unwrap(),
                serde_json::to_value(&original.endpoint).unwrap()
            );
        }
        {
            let sql = db.0.lock().unwrap();
            assert_eq!(
                sql.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                    .unwrap(),
                18
            );
            for table in ["servers", "sources", "incident_groups"] {
                let mut q = sql
                    .prepare(&format!("SELECT payload FROM {table}"))
                    .unwrap();
                for raw in q.query_map([], |r| r.get::<_, String>(0)).unwrap() {
                    let value: serde_json::Value = serde_json::from_str(&raw.unwrap()).unwrap();
                    assert!(
                        value.get("project").is_none()
                            && value.get("groups").is_none()
                            && value.get("projectKey").is_none()
                    );
                }
            }
        }
        event(&db, &servers[2], "cpu", AT + 150, true);
        db.reconcile_auto(AT + 150).unwrap();
        let groups = db.incident_groups(false, 0).unwrap();
        assert_eq!(groups.total, 1);
        assert_eq!(groups.groups[0].id, group);
        assert_eq!(groups.groups[0].member_count, 3);
        assert_eq!(groups.groups[0].run_id, Some(investigation.id));
        let status = db.auto_status(AT + 150).unwrap();
        assert_eq!(status.runs, 1);
        assert_eq!(status.charged_tokens, 77);
        assert_eq!(status.queued, 0);
    }
    #[test]
    fn mixed_legacy_cohort_keeps_its_members_without_accepting_late_nodes() {
        let (db, mut servers) = fixture(3);
        for server in &servers[..2] {
            event(&db, server, "cpu", AT, true);
        }
        db.reconcile_auto(AT).unwrap();
        let original = db.incident_groups(false, 0).unwrap().groups.remove(0);
        let source = Source {
            id: "other".into(),
            name: "other inventory".into(),
            kind: "manual".into(),
            location: "ops@other".into(),
            last_sync: None,
            error: None,
        };
        servers[1].source_id = source.id.clone();
        {
            let sql = db.0.lock().unwrap();
            sql.execute(
                "INSERT INTO sources VALUES(?1,?2)",
                params![source.id, serde_json::to_string(&source).unwrap()],
            )
            .unwrap();
            sql.execute(
                "UPDATE servers SET source_id=?2,payload=?3 WHERE id=?1",
                params![
                    servers[1].id,
                    source.id,
                    serde_json::to_string(&servers[1]).unwrap()
                ],
            )
            .unwrap();
            migrate_flat_servers(&sql).unwrap();
            let restored = read(&sql, &original.id).unwrap();
            assert_ne!(restored.key, original.key);
            let indexed: String = sql
                .query_row(
                    "SELECT correlation_key FROM incident_groups WHERE id=?1",
                    [&original.id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(indexed, restored.key);
        }
        event(&db, &servers[2], "cpu", AT + 60, true);
        db.reconcile_auto(AT + 60).unwrap();
        let groups = db.incident_groups(false, 0).unwrap();
        assert_eq!(groups.total, 1);
        assert_eq!(groups.groups[0].id, original.id);
        assert_eq!(groups.groups[0].member_count, 2);
        assert_eq!(db.group_targets(&original.id).unwrap().len(), 2);
    }
    #[test]
    fn failed_v12_migration_rolls_back_label_cleanup_and_version() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("broken.sqlite");
        let db = Store::open(&path).unwrap();
        let servers = populate(&db, 2);
        for server in &servers {
            event(&db, server, "cpu", AT, true);
        }
        db.reconcile_auto(AT).unwrap();
        db.0.lock().unwrap().execute_batch("UPDATE sources SET payload=json_set(payload,'$.project','legacy'); UPDATE servers SET payload=json_set(payload,'$.project','legacy'); UPDATE incident_groups SET payload='{}'; PRAGMA user_version=11").unwrap();
        drop(db);
        assert!(Store::open(&path).is_err());
        let sql = Connection::open(&path).unwrap();
        assert_eq!(
            sql.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            11
        );
        let label: String = sql
            .query_row(
                "SELECT json_extract(payload,'$.project') FROM servers LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(label, "legacy");
    }
    fn event(db: &Store, s: &Server, check: &str, at: i64, active: bool) {
        Store::incident(
            &db.0.lock().unwrap(),
            &s.id,
            check,
            active.then(|| "diagnostic evidence; summary id".into()),
            check,
            "warning",
            at,
        )
        .unwrap();
    }
    fn run(db: &Store, g: &str, at: i64) -> Investigation {
        let snap = db.snapshot().unwrap();
        let ids = db.group_targets(g).unwrap();
        Investigation {
            usage_started: false,
            model_profile: None,
            actual_model: None,
            scope_endpoints: snap
                .servers
                .iter()
                .filter(|s| ids.contains(&s.id))
                .map(|s| (s.id.clone(), serde_json::to_string(&s.endpoint).unwrap()))
                .collect(),
            group_id: Some(g.into()),
            authoring_id: None,
            id: uuid::Uuid::new_v4().to_string(),
            agent: "codex".into(),
            server_ids: ids,
            question: "group test".into(),
            origin: "auto".into(),
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
    #[test]
    fn five_hundred_servers_produce_one_bounded_investigation_and_one_charge() {
        let (db, servers) = fixture(500);
        let start = std::time::Instant::now();
        for (n, s) in servers.iter().enumerate() {
            event(&db, s, "connection", AT + (n % 30) as i64, true);
        }
        db.reconcile_auto(AT + 30).unwrap();
        assert_eq!(db.snapshot().unwrap().incidents.len(), 500);
        assert_eq!(db.incident_groups(false, 0).unwrap().total, 1);
        assert_eq!(db.auto_status(AT + 30).unwrap().queued, 1);
        assert!(db.next_auto(AT + 119).unwrap().is_none());
        let job = db.next_auto(AT + 150).unwrap().unwrap();
        let group = job.group_id.clone().unwrap();
        let view = db.incident_group(&group, 0, None).unwrap();
        assert_eq!(view.total, 500);
        assert_eq!(view.members.len(), 20);
        assert!(serde_json::to_vec(&view).unwrap().len() <= 32768);
        let mut r = run(&db, &group, AT + 150);
        assert_eq!(r.server_ids.len(), 500);
        db.admit(&r, Some(&job.id)).unwrap();
        for s in &servers {
            event(&db, s, "connection", AT + 160, true);
        }
        db.reconcile_auto(AT + 160).unwrap();
        assert_eq!(db.auto_status(AT + 160).unwrap().queued, 0);
        r.status = "completed".into();
        r.usage = json!({"totalTokens":77});
        r.usage_complete = true;
        db.settle(&r).unwrap();
        for _ in 0..5 {
            db.reconcile_auto(AT + 180).unwrap();
        }
        let status = db.auto_status(AT + 180).unwrap();
        assert_eq!(status.runs, 1);
        assert_eq!(status.charged_tokens, 77);
        assert_eq!(status.queued, 0);
        println!(
            "500 servers: {} ms; bounded group page {} bytes; one run",
            start.elapsed().as_millis(),
            serde_json::to_vec(&view).unwrap().len()
        );
    }
    #[test]
    fn unrelated_checks_security_and_time_windows_remain_separate() {
        let (db, s) = fixture(4);
        event(&db, &s[0], "cpu", AT, true);
        event(&db, &s[1], "memory", AT, true);
        event(&db, &s[2], "logs:ssh_suspicious_success", AT, true);
        event(&db, &s[3], "logs:ssh_suspicious_success", AT, true);
        db.reconcile_auto(AT).unwrap();
        assert_eq!(db.incident_groups(false, 0).unwrap().total, 0);
        assert_eq!(db.auto_status(AT).unwrap().queued, 4);
        event(&db, &s[1], "cpu", AT + WINDOW + 1, true);
        db.reconcile_auto(AT + WINDOW + 1).unwrap();
        assert_eq!(db.incident_groups(false, 0).unwrap().total, 0);
    }
    #[test]
    fn separate_sources_do_not_merge_without_a_signal_but_allow_dependencies() {
        let (db, mut s) = fixture(2);
        let source = Source {
            id: "other".into(),
            name: "other inventory".into(),
            kind: "manual".into(),
            location: "ops@other".into(),
            last_sync: None,
            error: None,
        };
        s[1].source_id = source.id.clone();
        {
            let sql = db.0.lock().unwrap();
            sql.execute(
                "INSERT INTO sources VALUES(?1,?2)",
                params![source.id, serde_json::to_string(&source).unwrap()],
            )
            .unwrap();
            sql.execute(
                "UPDATE servers SET source_id=?2,payload=?3 WHERE id=?1",
                params![s[1].id, source.id, serde_json::to_string(&s[1]).unwrap()],
            )
            .unwrap();
        }
        for server in &s {
            event(&db, server, "cpu", AT, true);
        }
        db.reconcile_auto(AT).unwrap();
        assert_eq!(db.incident_groups(false, 0).unwrap().total, 0);
        assert!(db
            .server_dependencies(&s[0].id)
            .unwrap()
            .available
            .iter()
            .any(|node| node.id == s[1].id));
        db.save_dependencies(&s[0].id, vec![s[1].id.clone()])
            .unwrap();
        db.reconcile_auto(AT + 10).unwrap();
        assert_eq!(db.incident_groups(false, 0).unwrap().total, 1);
    }
    #[test]
    fn declared_dependencies_correlate_different_operational_symptoms() {
        let (db, s) = fixture(2);
        db.save_dependencies(&s[0].id, vec![s[1].id.clone()])
            .unwrap();
        event(&db, &s[0], "nginx:upstream", AT, true);
        event(&db, &s[1], "postgresql:connections", AT + 20, true);
        db.reconcile_auto(AT + 20).unwrap();
        let groups = db.incident_groups(false, 0).unwrap();
        assert_eq!(groups.total, 1);
        let view = db.incident_group(&groups.groups[0].id, 0, None).unwrap();
        assert_eq!(view.dependencies, vec![(s[0].id.clone(), s[1].id.clone())]);
        assert!(view.group.reason.contains("dependency"));
    }
    #[test]
    fn manual_mode_groups_without_ai_and_admission_rechecks_live_recovery() {
        let (db, s) = fixture(2);
        let mut settings = db.settings().unwrap();
        settings.mode = "manual".into();
        db.save_settings(&settings).unwrap();
        for server in &s {
            event(&db, server, "cpu", AT, true);
        }
        db.reconcile_auto(AT).unwrap();
        assert_eq!(db.incident_groups(false, 0).unwrap().total, 1);
        assert_eq!(db.auto_status(AT).unwrap().queued, 0);
        settings.mode = "auto".into();
        db.save_settings(&settings).unwrap();
        db.reconcile_auto(AT + 120).unwrap();
        let job = db.next_auto(AT + 120).unwrap().unwrap();
        let r = run(&db, &job.id, AT + 120);
        for server in &s {
            event(&db, server, "cpu", AT + 121, false);
            event(&db, server, "cpu", AT + 122, false);
        }
        // No reconciliation yet: admission must read live episodes, not stale member snapshots.
        assert!(db.admit(&r, Some(&job.id)).is_err());
        assert_eq!(db.auto_status(AT + 122).unwrap().runs, 0);
        db.reconcile_auto(AT + 122).unwrap();
        assert_eq!(
            db.incident_group(&job.id, 0, None).unwrap().group.status,
            "resolved"
        );
        // A new outage gets a new group even within the old ten-minute correlation window.
        for server in &s {
            event(&db, server, "cpu", AT + 130, true);
        }
        db.reconcile_auto(AT + 130).unwrap();
        let groups = db.incident_groups(false, 0).unwrap();
        assert_eq!(groups.total, 1);
        assert_ne!(groups.groups[0].id, job.id);
    }
    #[test]
    fn loss_of_coverage_is_not_recovery_and_anchor_deletion_does_not_repeat() {
        let (db, s) = fixture(2);
        for server in &s {
            event(&db, server, "cpu", AT, true);
        }
        db.reconcile_auto(AT).unwrap();
        let job = db.next_auto(AT + 120).unwrap().unwrap();
        let mut r = run(&db, &job.id, AT + 120);
        db.admit(&r, Some(&job.id)).unwrap();
        r.status = "completed".into();
        r.usage = json!({"totalTokens":5});
        r.usage_complete = true;
        db.settle(&r).unwrap();
        let other = s.iter().find(|s| s.id != job.server_id).unwrap();
        db.0.lock()
            .unwrap()
            .execute("DELETE FROM servers WHERE id=?1", [&job.server_id])
            .unwrap();
        db.reconcile_auto(AT + 150).unwrap();
        assert_eq!(db.auto_status(AT + 150).unwrap().queued, 0);
        assert_eq!(
            db.incident_group(&job.id, 0, None)
                .unwrap()
                .group
                .removed_members,
            1
        );
        db.reconcile_auto(AT + 1000).unwrap();
        assert_eq!(
            db.incident_group(&job.id, 0, None).unwrap().group.status,
            "open"
        );
        assert!(db.next_auto(AT + 1000).unwrap().is_none());
        event(&db, other, "cpu", AT + 1001, false);
        event(&db, other, "cpu", AT + 1002, false);
        db.reconcile_auto(AT + 1002).unwrap();
        assert_eq!(
            db.incident_group(&job.id, 0, None).unwrap().group.status,
            "withdrawn"
        );
        trim(&db.0.lock().unwrap(), AT + 1002 + 31 * 86400).unwrap();
        assert_eq!(db.incident_groups(true, 0).unwrap().total, 0);
    }
    #[test]
    fn restart_and_completed_tombstone_survive_migration_and_report_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        let db = Store::open(&path).unwrap();
        let servers = populate(&db, 2);
        for s in &servers {
            event(&db, s, "memory", AT, true);
        }
        db.reconcile_auto(AT).unwrap();
        let job = db.next_auto(AT + 120).unwrap().unwrap();
        let mut r = run(&db, &job.id, AT + 120);
        db.admit(&r, Some(&job.id)).unwrap();
        r.status = "cancelled".into();
        db.settle(&r).unwrap();
        db.0.lock()
            .unwrap()
            .execute("DELETE FROM investigations", [])
            .unwrap();
        drop(db);
        let db = Store::open(&path).unwrap();
        db.resume_auto().unwrap();
        db.reconcile_auto(AT + 150).unwrap();
        assert_eq!(db.auto_status(AT + 150).unwrap().runs, 1);
        assert_eq!(db.auto_status(AT + 150).unwrap().queued, 0);
        assert_eq!(db.incident_groups(false, 0).unwrap().total, 1);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v10.sqlite");
        let db = Store::open(&path).unwrap();
        let s = populate(&db, 1);
        event(&db, &s[0], "cpu", AT, true);
        db.reconcile_auto(AT).unwrap();
        let original = db.next_auto(AT).unwrap().unwrap().id;
        db.0.lock().unwrap().execute_batch("DROP TABLE incident_group_members; DROP TABLE incident_groups; DROP TABLE server_dependencies; UPDATE ai_jobs SET payload=json_remove(payload,'$.groupId'); PRAGMA user_version=10;").unwrap();
        drop(db);
        let db = Store::open(&path).unwrap();
        db.reconcile_auto(AT).unwrap();
        assert_eq!(db.next_auto(AT).unwrap().unwrap().id, original);
        assert_eq!(db.snapshot().unwrap().incidents.len(), 1);
    }
    #[test]
    fn unchanged_dependencies_are_in_scope_even_without_their_own_incident() {
        let (db, s) = fixture(3);
        db.save_dependencies(&s[0].id, vec![s[2].id.clone()])
            .unwrap();
        db.save_dependencies(&s[1].id, vec![s[2].id.clone()])
            .unwrap();
        for node in &s[..2] {
            event(&db, node, "nginx:upstream", AT, true);
        }
        db.reconcile_auto(AT).unwrap();
        let g = &db.incident_groups(false, 0).unwrap().groups[0];
        assert_eq!(g.server_count, 2);
        assert_eq!(db.group_targets(&g.id).unwrap().len(), 3);
        assert_eq!(
            db.incident_group(&g.id, 0, None)
                .unwrap()
                .dependencies
                .len(),
            2
        );
    }
    #[test]
    fn endpoint_change_and_membership_race_cannot_spend_a_reservation() {
        let (db, s) = fixture(3);
        for node in &s[..2] {
            event(&db, node, "connection", AT, true);
        }
        db.reconcile_auto(AT).unwrap();
        let j = db.next_auto(AT + 120).unwrap().unwrap();
        let r = run(&db, &j.id, AT + 150);
        event(&db, &s[2], "connection", AT + 140, true);
        db.reconcile_auto(AT + 140).unwrap();
        assert!(db.admit(&r, Some(&j.id)).is_err());
        assert_eq!(db.auto_status(AT + 150).unwrap().runs, 0);
        let r = run(&db, &j.id, AT + 150);
        let mut changed = s[0].clone();
        changed.endpoint.port = 2222;
        db.0.lock()
            .unwrap()
            .execute(
                "UPDATE servers SET payload=?2 WHERE id=?1",
                params![changed.id, serde_json::to_string(&changed).unwrap()],
            )
            .unwrap();
        assert!(db.admit(&r, Some(&j.id)).is_err());
        assert_eq!(db.auto_status(AT + 150).unwrap().charged_tokens, 0);
    }
    #[test]
    fn deleting_anchor_during_run_still_settles_group_and_preserves_cooldown() {
        let (db, s) = fixture(2);
        for node in &s {
            event(&db, node, "memory", AT, true);
        }
        db.reconcile_auto(AT).unwrap();
        let j = db.next_auto(AT + 120).unwrap().unwrap();
        let mut r = run(&db, &j.id, AT + 120);
        db.admit(&r, Some(&j.id)).unwrap();
        db.0.lock()
            .unwrap()
            .execute("DELETE FROM servers WHERE id=?1", [&j.server_id])
            .unwrap();
        r.status = "completed".into();
        r.usage = json!({"totalTokens":10});
        r.usage_complete = true;
        db.settle(&r).unwrap();
        db.reconcile_auto(AT + 150).unwrap();
        assert_eq!(
            db.incident_group(&j.id, 0, None)
                .unwrap()
                .group
                .auto_state
                .as_deref(),
            Some("completed")
        );
        let other = s.iter().find(|s| s.id != j.server_id).unwrap();
        for at in [AT + 151, AT + 152] {
            event(&db, other, "memory", at, false);
        }
        db.reconcile_auto(AT + 152).unwrap();
        event(&db, other, "memory", AT + 160, true);
        db.reconcile_auto(AT + 160).unwrap();
        assert!(db.next_auto(AT + 160).unwrap().is_none());
        assert!(db
            .auto_status(AT + 160)
            .unwrap()
            .jobs
            .iter()
            .any(|j| j.state == "queued" && j.not_before >= AT + 120 + automation::COOLDOWN));
    }
    #[test]
    fn escaped_evidence_pages_are_bounded_and_do_not_skip_records() {
        let (db, s) = fixture(30);
        for node in &s {
            event(&db, node, "cpu", AT, true);
        }
        db.0.lock()
            .unwrap()
            .execute(
                "UPDATE incidents SET payload=json_set(payload,'$.evidence',?1)",
                ["\u{0001}".repeat(3000)],
            )
            .unwrap();
        db.reconcile_auto(AT).unwrap();
        let id = db.incident_groups(false, 0).unwrap().groups[0].id.clone();
        let mut offset = 0;
        let mut seen = BTreeSet::new();
        loop {
            let page = db.incident_group(&id, offset, None).unwrap();
            assert!(serde_json::to_vec(&page).unwrap().len() <= 32768);
            for m in &page.members {
                assert!(m.truncated);
                assert!(seen.insert(m.incident.id.clone()));
            }
            match page.next_offset {
                Some(next) => {
                    assert!(next > offset);
                    offset = next
                }
                None => break,
            }
        }
        assert_eq!(seen.len(), 30);
    }
    #[test]
    fn suppressed_group_respects_queue_capacity_when_freshness_returns() {
        let (db, s) = fixture(2);
        for node in &s {
            event(&db, node, "cpu", AT, true);
        }
        db.reconcile_auto(AT).unwrap();
        let group = db.incident_groups(false, 0).unwrap().groups[0].id.clone();
        db.0.lock()
            .unwrap()
            .execute(
                "UPDATE incidents SET payload=json_set(payload,'$.autoEligible',json('false'))",
                [],
            )
            .unwrap();
        db.reconcile_auto(AT).unwrap();
        for n in 0..500 {
            event(&db, &s[0], &format!("custom:{n}"), AT, true);
        }
        db.reconcile_auto(AT).unwrap();
        assert_eq!(db.auto_status(AT).unwrap().queued, 500);
        db.0.lock()
            .unwrap()
            .execute(
                "UPDATE incidents SET payload=json_set(payload,'$.autoEligible',json('true'))",
                [],
            )
            .unwrap();
        db.reconcile_auto(AT + 120).unwrap();
        assert_eq!(db.auto_status(AT + 120).unwrap().queued, 500);
        let job = db.next_auto(AT + 120).unwrap().unwrap();
        assert_ne!(job.id, group);
        db.dismiss_job(&job.id).unwrap();
        db.reconcile_auto(AT + 120).unwrap();
        assert_eq!(db.auto_status(AT + 120).unwrap().queued, 500);
        let raw: String =
            db.0.lock()
                .unwrap()
                .query_row("SELECT state FROM ai_jobs WHERE id=?1", [group], |r| {
                    r.get(0)
                })
                .unwrap();
        assert_eq!(raw, "queued");
    }
    #[test]
    fn legacy_labels_do_not_restrict_scope_or_replay_episodes() {
        let (db, s) = fixture(2);
        for node in &s {
            event(&db, node, "cpu", AT, true);
        }
        db.reconcile_auto(AT).unwrap();
        let group = db.incident_groups(false, 0).unwrap().groups[0].id.clone();
        for (index, node) in s.iter().enumerate() {
            let mut payload = serde_json::to_value(node).unwrap();
            payload["project"] = json!(format!("old-{index}"));
            payload["groups"] = json!([format!("tag-{index}")]);
            db.0.lock()
                .unwrap()
                .execute(
                    "UPDATE servers SET payload=?2 WHERE id=?1",
                    params![node.id, payload.to_string()],
                )
                .unwrap();
        }
        db.reconcile_auto(AT + 120).unwrap();
        assert_eq!(db.group_targets(&group).unwrap().len(), 2);
        assert_eq!(db.auto_status(AT + 120).unwrap().queued, 1);
        assert_eq!(db.incident_groups(false, 0).unwrap().groups[0].id, group);
    }
    #[tokio::test]
    async fn mcp_group_scope_is_frozen_and_budget_does_not_expand_with_late_members() {
        let dir = tempfile::tempdir().unwrap();
        let app = crate::create_state(dir.path().into()).unwrap();
        let servers = populate(&app.store, 3);
        for s in &servers[..2] {
            event(&app.store, s, "connection", AT, true);
        }
        app.store.reconcile_auto(AT).unwrap();
        let job = app.store.next_auto(AT + 120).unwrap().unwrap();
        let r = run(&app.store, &job.id, AT + 120);
        app.store.admit(&r, Some(&job.id)).unwrap();
        let mcp = crate::mcp::McpServer::start_scoped(
            app.clone(),
            &r.server_ids,
            None,
            "codex".into(),
            Some(job.id.clone()),
        )
        .await
        .unwrap();
        let schema = crate::mcp::tools()
            .into_iter()
            .find(|t| t["name"] == "list_servers")
            .unwrap();
        assert_eq!(
            schema["inputSchema"]["properties"]["offset"]["maximum"],
            1000
        );
        let page = crate::mcp::call(&mcp.scope, "list_servers", json!({"offset":1}))
            .await
            .unwrap();
        assert_eq!(page["total"], 2);
        assert_eq!(page["servers"].as_array().unwrap().len(), 1);
        event(&app.store, &servers[2], "connection", AT + 140, true);
        app.store.reconcile_auto(AT + 140).unwrap();
        let result = crate::mcp::call(&mcp.scope, "get_incident_group", json!({}))
            .await
            .unwrap();
        assert_eq!(result["total"], 2);
        assert_eq!(result["outsideScope"], 1);
        assert!(!result.to_string().contains(&servers[2].id));
        assert!(
            crate::mcp::call(&mcp.scope, "get_server", json!({"serverId":servers[2].id}))
                .await
                .is_err()
        );
        assert!(crate::mcp::call(
            &mcp.scope,
            "get_incident_group",
            json!({"groupId":"foreign"})
        )
        .await
        .is_err());
        assert_eq!(
            mcp.scope.remote.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(app.store.auto_status(AT + 140).unwrap().queued, 0);
        assert_eq!(app.store.auto_status(AT + 140).unwrap().runs, 1);
    }
    fn ansible(db: &Store, hosts: &[&str]) -> Vec<String> {
        let source = Source {
            id: "inventory".into(),
            name: "hosts.ini".into(),
            kind: "ansible".into(),
            location: "/tmp/hosts.ini".into(),
            last_sync: None,
            error: None,
        };
        db.import(&source, parse_manual(&hosts.join("\n")).unwrap())
            .unwrap();
        hosts
            .iter()
            .map(|h| {
                crate::inventory::stable_id("inventory", &parse_manual(h).unwrap()[0].identity)
            })
            .collect()
    }
    fn links(db: &Store) -> Vec<(String, String)> {
        let db = db.0.lock().unwrap();
        let mut q = db
            .prepare("SELECT server_id,depends_on FROM server_dependencies ORDER BY server_id,depends_on")
            .unwrap();
        let rows = q
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        rows
    }
    #[test]
    fn ansible_inventory_links_its_servers_once_and_keeps_manual_edits() {
        let db = Store::open(Path::new(":memory:")).unwrap();
        let ids = ansible(&db, &["ops@a", "ops@b", "ops@c"]);
        let mut expected = vec![
            (ids[1].clone(), ids[0].clone()),
            (ids[2].clone(), ids[0].clone()),
        ];
        expected.sort();
        assert_eq!(links(&db), expected);
        // The operator detaches c; a periodic re-read must not restore the link.
        db.save_dependencies(&ids[2], vec![]).unwrap();
        ansible(&db, &["ops@a", "ops@b", "ops@c"]);
        assert_eq!(links(&db), vec![(ids[1].clone(), ids[0].clone())]);
        // A host added to the file joins the existing hub.
        let ids = ansible(&db, &["ops@a", "ops@b", "ops@c", "ops@d"]);
        let mut expected = vec![
            (ids[1].clone(), ids[0].clone()),
            (ids[3].clone(), ids[0].clone()),
        ];
        expected.sort();
        assert_eq!(links(&db), expected);
        // Removing the hub re-attaches its former dependents and new hosts, not c.
        let ids = ansible(&db, &["ops@b", "ops@c", "ops@d", "ops@e"]);
        let mut expected = vec![
            (ids[2].clone(), ids[0].clone()),
            (ids[3].clone(), ids[0].clone()),
        ];
        expected.sort();
        assert_eq!(links(&db), expected);
    }
    #[test]
    fn new_hosts_follow_the_hub_the_operator_kept() {
        let db = Store::open(Path::new(":memory:")).unwrap();
        let ids = ansible(&db, &["ops@a", "ops@b", "ops@c"]);
        db.save_dependencies(&ids[1], vec![ids[2].clone()]).unwrap();
        db.save_dependencies(&ids[0], vec![ids[2].clone()]).unwrap();
        let ids = ansible(&db, &["ops@a", "ops@b", "ops@c", "ops@d"]);
        assert!(links(&db).contains(&(ids[3].clone(), ids[2].clone())));
    }
    #[test]
    fn manual_lists_and_oversized_inventories_are_not_linked() {
        let (db, _) = fixture(3);
        assert!(links(&db).is_empty());
        let db = Store::open(Path::new(":memory:")).unwrap();
        let hosts: Vec<String> = (0..=MAX_SERVERS).map(|n| format!("ops@node-{n}")).collect();
        ansible(&db, &hosts.iter().map(String::as_str).collect::<Vec<_>>());
        assert!(links(&db).is_empty());
    }
    #[test]
    fn one_inventory_correlates_different_symptoms() {
        let db = Store::open(Path::new(":memory:")).unwrap();
        ansible(&db, &["ops@a", "ops@b", "ops@c"]);
        db.save_settings(&Settings {
            mode: "auto".into(),
            daily_run_limit: Some(1000),
            daily_token_limit: Some(1000000),
            run_token_limit: 1000,
            ..Settings::default()
        })
        .unwrap();
        let s = db.snapshot().unwrap().servers;
        event(&db, &s[1], "nginx:upstream", AT, true);
        event(&db, &s[2], "postgresql:connections", AT + 20, true);
        db.reconcile_auto(AT + 20).unwrap();
        let groups = db.incident_groups(false, 0).unwrap();
        assert_eq!(groups.total, 1);
        assert_eq!(db.group_targets(&groups.groups[0].id).unwrap().len(), 3);
    }
}
