use super::{target, Scope};
use crate::{
    model::{now, Incident},
    store::Store,
    web_evidence,
};
use rusqlite::params;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use std::sync::atomic::Ordering;

const PAGE_SIZE: usize = 20;
const PAGE_BYTES: usize = 30 * 1024;

fn args<T: DeserializeOwned>(value: Value) -> Result<T, String> {
    serde_json::from_value(value).map_err(|_| "Incorrect parameters".into())
}

fn trim(text: &mut String, bytes: usize) {
    if text.len() > bytes {
        let mut end = bytes;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push('…');
    }
}

fn next(offset: usize, len: usize, total: usize) -> Option<usize> {
    (offset + len < total).then_some(offset + len)
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    #[default]
    Open,
    Resolved,
    All,
}
impl Status {
    fn filter(&self) -> Option<&'static str> {
        match self {
            Self::Open => Some("open"),
            Self::Resolved => Some("resolved"),
            Self::All => None,
        }
    }
}

pub(super) fn incident_page(
    store: &Store,
    id: &str,
    status: Option<&str>,
    offset: usize,
    limit: usize,
) -> Result<Value, String> {
    const FILTER: &str =
        "FROM incidents WHERE server_id=?1 AND (?2 IS NULL OR json_extract(payload,'$.status')=?2)";
    let db = store.0.lock().map_err(|e| e.to_string())?;
    let total: usize = db
        .query_row(
            &format!("SELECT count(*) {FILTER}"),
            params![id, status],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    let mut query = db.prepare(&format!("SELECT payload {FILTER} ORDER BY json_extract(payload,'$.updatedAt') DESC,id LIMIT ?3 OFFSET ?4")).map_err(|e| e.to_string())?;
    let rows = query
        .query_map(params![id, status, limit, offset], |r| {
            r.get::<_, String>(0)
        })
        .map_err(|e| e.to_string())?;
    let mut incidents = Vec::new();
    let mut bytes = 0;
    for row in rows {
        let mut incident: Incident =
            serde_json::from_str(&row.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        trim(&mut incident.evidence, 1024);
        let len = serde_json::to_vec(&incident)
            .map_err(|e| e.to_string())?
            .len()
            + 1;
        if bytes + len > PAGE_BYTES - 1024 {
            if incidents.is_empty() {
                return Err("Retained incident exceeds response limit".into());
            }
            break;
        }
        bytes += len;
        incidents.push(incident);
    }
    Ok(
        json!({"serverId":id,"offset":offset,"nextOffset":next(offset,incidents.len(),total),"total":total,"incidents":incidents}),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Incidents {
    server_id: String,
    #[serde(default)]
    offset: u32,
    #[serde(default)]
    status: Status,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Packages {
    server_id: String,
    #[serde(default)]
    offset: u32,
    name: Option<String>,
}

fn packages(store: &Store, p: &Packages) -> Result<Value, String> {
    if p.name
        .as_ref()
        .is_some_and(|name| name.is_empty() || name.len() > 160)
    {
        return Err("Incorrect package name".into());
    }
    let (state, mut packages) = store.package_snapshot(&p.server_id)?;
    if let Some(name) = &p.name {
        packages.retain(|package| package.name == *name || package.source == *name);
    }
    packages.sort_unstable_by(|a, b| {
        (&a.name, &a.arch, &a.version).cmp(&(&b.name, &b.arch, &b.version))
    });
    let total = packages.len();
    let offset = p.offset as usize;
    let packages = packages
        .into_iter()
        .skip(offset)
        .take(PAGE_SIZE)
        .collect::<Vec<_>>();
    let policy = store
        .monitoring_policy(&crate::monitoring::scope(
            "packages",
            Some(&p.server_id),
            None,
        ))?
        .values;
    let fresh = policy.enabled
        && state.root.is_some()
        && state.error.is_none()
        && state
            .last_success
            .is_some_and(|at| now().saturating_sub(at) <= (policy.interval_seconds * 2) as i64);
    Ok(
        json!({"serverId":p.server_id,"offset":offset,"nextOffset":next(offset,packages.len(),total),"total":total,"packages":packages,
        "observedAt":state.last_success,"fresh":fresh,"collecting":state.stage.is_some(),"metadata":state.metadata,"monitoring":policy}),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Vulnerabilities {
    server_id: String,
    #[serde(default)]
    offset: usize,
    #[serde(default)]
    include_hidden: bool,
    cve: Option<String>,
}

fn vulnerabilities(store: &Store, p: &Vulnerabilities) -> Result<Value, String> {
    let cve = p.cve.as_deref().map(str::to_ascii_uppercase);
    if cve
        .as_deref()
        .is_some_and(|cve| !crate::advisories::valid_cve(cve))
    {
        return Err("Incorrect CVE identifier".into());
    }
    let mut view = store.vulnerability_page(
        &p.server_id,
        p.offset,
        p.include_hidden,
        cve.as_deref(),
        false,
    )?;
    let sources = view.sources.drain(..).map(|source| json!({
        "id":source.id,"kind":source.kind,"release":source.release,"scope":source.scope,
        "checkedAt":source.checked_at,"nextCheck":source.next_check,"hasError":source.error.is_some()
    })).collect::<Vec<_>>();
    let mut truncated = false;
    loop {
        let mut value = serde_json::to_value(&view).map_err(|e| e.to_string())?;
        value["sources"] = json!(sources);
        value["serverId"] = json!(p.server_id);
        value["nextOffset"] = json!(next(p.offset, view.findings.len(), view.total));
        value["evidenceTruncated"] = json!(truncated);
        if value.to_string().len() <= PAGE_BYTES {
            return Ok(value);
        }
        if view.findings.len() > 1 {
            view.findings.pop();
        } else if let Some(finding) = view.findings.first_mut().map(|f| &mut f.finding) {
            if finding.description.len() > 1024 {
                trim(&mut finding.description, 1000);
            } else if finding.packages.len() > 1 {
                finding
                    .packages
                    .truncate(finding.packages.len().div_ceil(2));
            } else {
                return Err("Vulnerabilities exceed the response limit".into());
            }
            truncated = true;
        } else {
            return Err("Vulnerability Report Exceeds Response Limit".into());
        }
        let keys = view
            .findings
            .iter()
            .flat_map(|f| {
                f.finding.packages.iter().map(|package| {
                    format!("{}:{}:{}", f.finding.source, f.finding.cve, package.name)
                })
            })
            .collect::<std::collections::HashSet<_>>();
        view.fixes.retain(|key, _| keys.contains(key));
    }
}

pub(super) fn read(scope: &Scope, name: &str, value: Value) -> Result<Value, String> {
    let id = value["serverId"]
        .as_str()
        .ok_or("ServerId is expected")?
        .to_owned();
    target(scope, &id)?;
    let store = &scope.app.store;
    let result = match name {
        "list_server_incidents" => {
            let p: Incidents = args(value)?;
            incident_page(
                store,
                &p.server_id,
                p.status.filter(),
                p.offset as usize,
                PAGE_SIZE,
            )?
        }
        "list_server_packages" => packages(store, &args(value)?)?,
        "get_vulnerability_summary" => vulnerabilities(store, &args(value)?)?,
        _ => return Err("Tool banned".into()),
    };
    target(scope, &id)?;
    Ok(result)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Link {
    url: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Advisory {
    server_id: String,
    cve: String,
}

pub(super) async fn web(scope: &Scope, name: &str, value: Value) -> Result<Value, String> {
    let web = scope
        .web
        .as_ref()
        .ok_or("Access to the web is allowed only when manually running")?;
    if web.calls.fetch_add(1, Ordering::SeqCst) >= 8 {
        return Err("The limit of eight readings of public pages is exhausted".into());
    }
    if name == "read_web_page" {
        let link: Link = args(value)?;
        let url = web_evidence::requested_url(&link.url, &web.links)?;
        let page = web_evidence::read(url).await?;
        return serde_json::to_value(page).map_err(|e| e.to_string());
    }
    let advisory: Advisory = args(value)?;
    let server = target(scope, &advisory.server_id)?;
    let platform = server
        .observation
        .as_ref()
        .and_then(|o| o.platform.as_ref());
    let state = scope.app.store.cached_package_state(&server.id)?;
    let distro = platform
        .map(|p| p.distro.as_str())
        .or_else(|| state.metadata.as_ref().map(|m| m.distro.as_str()));
    let release = platform
        .map(|p| p.release.as_str())
        .or_else(|| state.metadata.as_ref().map(|m| m.release.as_str()));
    let provider = match distro {
        Some("debian") => "debian",
        Some("ubuntu") => "ubuntu",
        _ => "general",
    };
    let cve = advisory.cve.to_ascii_uppercase();
    let url = web_evidence::advisory_url(provider, &cve)?;
    let page = web_evidence::read(url).await?;
    target(scope, &advisory.server_id)?;
    Ok(
        json!({"cve":cve,"serverId":server.id,"distribution":distro,"release":release,"advisoryScope":provider,"page":page}),
    )
}
