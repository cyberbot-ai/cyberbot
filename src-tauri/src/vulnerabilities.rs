//! Saved package snapshots are matched locally. No model or SSH is involved here.
use crate::{
    advisories::{self, Assessment, Match},
    inventory::stable_id,
    model::{now, Incident},
    packages::{Apt, Result, State},
    store::Store,
    AppState,
};
use rusqlite::{params, OptionalExtension};
#[path = "vulnerability_groups.rs"]
mod groups;
pub(crate) fn migrate_groups(db: &rusqlite::Connection) -> Result<()> {
    groups::migrate(db)
}
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedFinding {
    #[serde(flatten)]
    finding: Match,
    #[serde(default)]
    hidden_at: Option<i64>,
    #[serde(default)]
    first_seen_at: Option<i64>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    #[serde(flatten)]
    pub(crate) finding: Match,
    pub fingerprint: String,
    pub hidden_at: Option<i64>,
}
#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub affected: usize,
    pub critical: usize,
    pub unknown: usize,
    pub hidden: usize,
}
fn fingerprint(f: &Match) -> String {
    let mut packages: Vec<_> = f
        .packages
        .iter()
        .map(|p| (&p.name, &p.version, &p.fixed_version))
        .collect();
    packages.sort();
    crate::packages::digest(&(
        "vulnerability-v1",
        &f.source,
        &f.cve,
        &f.state,
        &f.severity,
        packages,
    ))
}
fn server_scope(db: &rusqlite::Connection, id: &str) -> Result<String> {
    let endpoint: String = db
        .query_row(
            "SELECT json_extract(payload,'$.endpoint') FROM servers WHERE id=?1",
            [id],
            |r| r.get(0),
        )
        .map_err(err)?;
    Ok(crate::packages::digest(&(id, endpoint)))
}
fn scoped_fingerprint(scope: &str, signature: Option<&str>, f: &Match) -> String {
    crate::packages::digest(&(scope, signature, fingerprint(f)))
}
fn counts(db: &rusqlite::Connection, server: Option<&str>) -> Result<BTreeMap<String, Counts>> {
    let clause = if server.is_some() {
        "AND server_id=?1"
    } else {
        ""
    };
    let sql = format!(
        "SELECT server_id,
         sum(hidden_at IS NULL AND json_extract(payload,'$.state')='affected'),
         sum(hidden_at IS NULL AND json_extract(payload,'$.state')='affected' AND json_extract(payload,'$.severity')='critical'),
         sum(hidden_at IS NULL AND json_extract(payload,'$.state')='unknown'),
         sum(hidden_at IS NOT NULL)
         FROM vulnerability_groups WHERE payload IS NOT NULL {clause} GROUP BY server_id"
    );
    let mut q = db.prepare(&sql).map_err(err)?;
    let rows = q
        .query_map(rusqlite::params_from_iter(server), |r| {
            Ok((
                r.get(0)?,
                Counts {
                    affected: r.get(1)?,
                    critical: r.get(2)?,
                    unknown: r.get(3)?,
                    hidden: r.get(4)?,
                },
            ))
        })
        .map_err(err)?;
    rows.collect::<std::result::Result<_, _>>().map_err(err)
}
fn incident_detail(finding: &Match) -> String {
    format!("Package {}: {}", finding.source, finding.cve)
}
fn incident_severity(finding: &Match) -> &'static str {
    if finding.severity == "critical" {
        "critical"
    } else {
        "warning"
    }
}
pub(crate) fn hide_incident_findings(
    db: &rusqlite::Connection,
    incident: &Incident,
    at: i64,
) -> Result<()> {
    if let Some(source) = incident.check.strip_prefix("vuln:") {
        db.execute(
            "UPDATE vulnerability_groups SET hidden_at=coalesce(hidden_at,?3) WHERE server_id=?1 AND source=?2",
            params![incident.server_id,source,at],
        ).map_err(err)?;
    }
    Ok(())
}
pub(crate) fn backfill_hidden(db: &rusqlite::Connection) -> Result<()> {
    let mut q=db.prepare("SELECT payload FROM incidents WHERE json_extract(payload,'$.check') LIKE 'vuln:%' AND json_extract(payload,'$.resolvedByUserAt') IS NOT NULL AND json_extract(payload,'$.manualResolutionPending')=1").map_err(err)?;
    let rows = q.query_map([], |r| r.get::<_, String>(0)).map_err(err)?;
    for raw in rows {
        let i: Incident = serde_json::from_str(&raw.map_err(err)?).map_err(err)?;
        db.execute("UPDATE vulnerability_findings SET payload=json_set(payload,'$.hiddenAt',?3,'$.firstSeenAt',?3) WHERE server_id=?1 AND source=?2 AND resolved_at IS NULL AND json_extract(payload,'$.firstSeenAt') IS NULL AND json_extract(payload,'$.hiddenAt') IS NULL",params![i.server_id,i.check.trim_start_matches("vuln:"),i.resolved_by_user_at]).map_err(err)?;
    }
    Ok(())
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evaluation {
    #[serde(default)]
    pub retry_after: i64,
    #[serde(default)]
    selection_pending: bool,
    pub at: i64,
    pub root: String,
    pub checks: u64,
    pub fresh_until: i64,
    pub coverage: Vec<String>,
    pub generations: BTreeMap<String, String>,
    pub affected: usize,
    pub critical: usize,
    pub unknown: usize,
    pub error: Option<String>,
}
impl Evaluation {
    fn has_result(&self) -> bool {
        !self.coverage.iter().any(|code| {
            matches!(
                code.as_str(),
                "unsupported_distribution" | "package_scope_pending" | "missing:debian"
            ) || code.starts_with("missing:ubuntu-cve:")
        })
    }

    fn verified_at(&self, at: i64) -> bool {
        self.error.is_none() && self.fresh_until >= at && complete_coverage(&self.coverage)
    }
}
fn complete_coverage(coverage: &[String]) -> bool {
    coverage.iter().all(|code| {
        code == "coverage_list_truncated" || advisories::is_package_coverage_detail(code)
    })
}
const SUPERSEDED: &str = "package snapshot or vulnerability database changed during matching";
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub active: Counts,
    pub hidden_count: usize,
    pub monitoring: crate::monitoring::Values,
    pub evaluation: Option<Evaluation>,
    pub fresh: bool,
    pub collecting: bool,
    pub assessment_pending: bool,
    pub last_success: Option<i64>,
    pub next_check: i64,
    pub error: Option<String>,
    pub total: usize,
    pub offset: usize,
    pub findings: Vec<Finding>,
    pub fixes: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bulk_fix: Option<BulkFix>,
    pub sources: Vec<advisories::Source>,
    pub cvss_queue: advisories::CvssQueue,
}
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkFix {
    pub finding_count: usize,
    pub packages: Vec<String>,
    pub has_unverified: bool,
}

fn package_fix_status(
    state: &State,
    apt: &BTreeMap<String, Apt>,
    source: &str,
    package: &advisories::PackageEvidence,
    at: i64,
) -> &'static str {
    apt.get(&package.name)
        .filter(|entry| {
            Some(&entry.root) == state.root.as_ref()
                && at - entry.at <= 86400
                && entry.cache_at.is_some_and(|t| at - t <= 86400)
        })
        .and_then(|entry| {
            let fixed = package.fixed_version.as_ref()?;
            let actual = if state.metadata.as_ref()?.distro == "debian" {
                if entry.candidate.source.as_deref() != Some(source) {
                    return None;
                }
                entry.candidate.source_version.as_ref()?
            } else {
                entry.candidate.version.as_ref()?
            };
            crate::debversion::compare(actual, fixed).map(|order| {
                if order.is_lt() {
                    "not_available"
                } else {
                    "available"
                }
            })
        })
        .unwrap_or("unknown")
}

fn apt_package_argument(name: &str) -> bool {
    let (package, arch) = name
        .split_once(':')
        .map_or((name, None), |(p, a)| (p, Some(a)));
    let alphanumeric = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    package.bytes().next().is_some_and(alphanumeric)
        && package
            .bytes()
            .all(|b| alphanumeric(b) || b"+.-".contains(&b))
        && if let Some(arch) = arch {
            arch.bytes().next().is_some_and(alphanumeric)
                && arch.bytes().all(|b| alphanumeric(b) || b == b'-')
                && !arch.ends_with('-')
        } else {
            // APT treats a trailing + or - as a change to the requested action.
            !package.ends_with(['+', '-'])
        }
}

fn bulk_fix(
    db: &rusqlite::Connection,
    id: &str,
    state: &State,
    apt: &BTreeMap<String, Apt>,
    at: i64,
) -> Result<Option<BulkFix>> {
    let mut query = db
        .prepare(
            "SELECT payload FROM vulnerability_groups
             WHERE server_id=?1 AND hidden_at IS NULL
               AND json_extract(payload,'$.state')='affected'
               AND json_extract(payload,'$.fixPublished')=1",
        )
        .map_err(err)?;
    let rows = query
        .query_map([id], |row| row.get::<_, String>(0))
        .map_err(err)?;
    let mut finding_count = 0;
    let mut has_unverified = false;
    let mut packages = BTreeSet::new();
    for row in rows {
        let finding: Match = serde_json::from_str(&row.map_err(err)?).map_err(err)?;
        if finding.packages.is_empty() {
            continue;
        }
        let mut unverified = false;
        let eligible = finding.packages.iter().all(|p| {
            if !apt_package_argument(&p.name) {
                return false;
            }
            let status = package_fix_status(state, apt, &finding.source, p, at);
            unverified |= status == "unknown";
            status != "not_available"
        });
        if eligible {
            finding_count += 1;
            has_unverified |= unverified;
            packages.extend(finding.packages.into_iter().map(|p| p.name));
        }
    }
    Ok((finding_count >= 2).then(|| BulkFix {
        finding_count,
        packages: packages.into_iter().collect(),
        has_unverified,
    }))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Card {
    pub hidden_count: usize,
    pub status: String,
    pub affected: usize,
    pub critical: usize,
    pub at: Option<i64>,
}
impl Store {
    pub(crate) fn vulnerability_cards(db: &rusqlite::Connection) -> Result<BTreeMap<String, Card>> {
        let mut q=db.prepare("SELECT s.id,e.payload,p.payload FROM servers s LEFT JOIN vulnerability_evaluations e ON e.server_id=s.id LEFT JOIN package_state p ON p.server_id=s.id").map_err(err)?;
        let rows = q
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            })
            .map_err(err)?;
        let book = crate::monitoring::Book::load(db)?;
        let mut cards = BTreeMap::new();
        let mut active = counts(db, None)?;
        for row in rows {
            let (id, raw, package) = row.map_err(err)?;
            let visible = active.remove(&id).unwrap_or_default();
            let e: Option<Evaluation> = raw
                .map(|s| serde_json::from_str(&s).map_err(err))
                .transpose()?;
            let p: Option<State> = package
                .map(|s| serde_json::from_str(&s).map_err(err))
                .transpose()?;
            let status = e
                .as_ref()
                .map(|e| {
                    if !book.enabled("packages", &id, "default")
                        || p.as_ref().is_none_or(|p| p.last_success.is_none())
                    {
                        "unknown"
                    } else if visible.critical > 0 {
                        "critical"
                    } else if visible.affected > 0 {
                        "warning"
                    } else if e.error.is_some()
                        || e.fresh_until < now()
                        || !e.has_result()
                        || p.as_ref()
                            .is_none_or(|p| p.error.is_some() || p.root.as_deref() != Some(&e.root))
                    {
                        "unknown"
                    } else {
                        "healthy"
                    }
                })
                .unwrap_or("unknown");
            cards.insert(
                id,
                Card {
                    hidden_count: visible.hidden,
                    status: status.into(),
                    affected: visible.affected,
                    critical: visible.critical,
                    at: e.map(|e| e.at),
                },
            );
        }
        let mut q=db.prepare("SELECT server_id,json_extract(payload,'$.severity') FROM incidents WHERE json_extract(payload,'$.status')='open' AND json_extract(payload,'$.check') LIKE 'vuln:%'").map_err(err)?;
        for row in q
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(err)?
        {
            let (id, severity) = row.map_err(err)?;
            if let Some(c) = cards.get_mut(&id) {
                if severity == "critical" {
                    c.status = "critical".into();
                } else if c.status != "critical" {
                    c.status = "warning".into();
                }
            }
        }
        Ok(cards)
    }

    pub(crate) fn vulnerability_view(&self, id: &str, offset: usize) -> Result<View> {
        self.vulnerability_view_filtered(id, offset, false)
    }
    pub(crate) fn vulnerability_view_filtered(
        &self,
        id: &str,
        offset: usize,
        include_hidden: bool,
    ) -> Result<View> {
        self.vulnerability_page(id, offset, include_hidden, None, true, true)
    }
    pub(crate) fn vulnerability_page(
        &self,
        id: &str,
        offset: usize,
        include_hidden: bool,
        cve: Option<&str>,
        clamp_offset: bool,
        include_bulk_fix: bool,
    ) -> Result<View> {
        if offset > 20000 {
            return Err("Invalid page".into());
        }
        let state = self.cached_package_state(id)?;
        let apt = self.apt_cached(id)?;
        let required = state
            .metadata
            .as_ref()
            .map(advisories::required)
            .unwrap_or_default();
        let sources = self
            .advisory_sources()?
            .into_iter()
            .filter(|s| required.contains(&s.id))
            .collect();
        let cvss_queue = self.cvss_queue()?;
        let db = self.0.lock().map_err(err)?;
        let scope = server_scope(&db, id)?;
        let raw: Option<String> = db
            .query_row(
                "SELECT payload FROM vulnerability_evaluations WHERE server_id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        let active = counts(&db, Some(id))?.remove(id).unwrap_or_default();
        let evaluation: Option<Evaluation> = raw
            .map(|s| {
                let mut result: Evaluation = serde_json::from_str(&s).map_err(err)?;
                result.affected = active.affected;
                result.critical = active.critical;
                result.unknown = active.unknown;
                Ok::<_, String>(result)
            })
            .transpose()?;
        let at = now();
        let bulk_fix = if include_bulk_fix && active.affected >= 2 {
            bulk_fix(&db, id, &state, &apt, at)?
        } else {
            None
        };
        // The general page is grouped. An explicit CVE lookup can still
        // retrieve exact evidence without counting it as another package.
        let selection = if cve.is_some() {
            "SELECT f.source,f.payload,coalesce(g.hidden_at,json_extract(f.payload,'$.hiddenAt')) AS hidden_at,g.signature
             FROM vulnerability_findings f JOIN vulnerability_groups g USING (server_id,source)
             WHERE f.server_id=?1 AND f.resolved_at IS NULL AND f.cve=?3
               AND g.payload IS NOT NULL AND (?2 OR (g.hidden_at IS NULL AND json_extract(f.payload,'$.hiddenAt') IS NULL))"
        } else {
            "SELECT source,payload,hidden_at,signature FROM vulnerability_groups
             WHERE server_id=?1 AND (?2 OR hidden_at IS NULL) AND payload IS NOT NULL AND ?3 IS NULL"
        };
        let total: usize = db
            .query_row(
                &format!("SELECT count(*) FROM ({selection})"),
                params![id, include_hidden, cve],
                |r| r.get(0),
            )
            .map_err(err)?;
        let offset = if clamp_offset {
            offset.min(total.saturating_sub(1) / 20 * 20)
        } else {
            offset
        };
        let mut q = db
            .prepare(&format!(
                "SELECT payload,hidden_at,signature FROM ({selection})
             ORDER BY hidden_at IS NOT NULL,json_extract(payload,'$.state')='affected' DESC,
               json_extract(payload,'$.severity')='critical' DESC,source LIMIT 20 OFFSET ?4",
            ))
            .map_err(err)?;
        let rows = q
            .query_map(params![id, include_hidden, cve, offset], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<i64>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            })
            .map_err(err)?;
        let findings: Vec<Finding> = rows
            .map(|row| {
                let (payload, hidden_at, signature) = row.map_err(err)?;
                let finding: Match = serde_json::from_str(&payload).map_err(err)?;
                Ok(Finding {
                    fingerprint: scoped_fingerprint(&scope, signature.as_deref(), &finding),
                    finding,
                    hidden_at,
                })
            })
            .collect::<Result<_>>()?;
        let mut fixes = BTreeMap::new();
        for f in &findings {
            for p in &f.finding.packages {
                let key = format!("{}:{}:{}", f.finding.source, f.finding.cve, p.name);
                let status = package_fix_status(&state, &apt, &f.finding.source, p, at);
                fixes.insert(key, status.into());
            }
        }
        let fresh = state.last_success.is_some()
            && crate::monitoring::effective(&db, "packages", id, "")?
                .values
                .enabled
            && state.error.is_none()
            && evaluation.as_ref().is_some_and(|e| {
                e.error.is_none()
                    && e.fresh_until >= now()
                    && e.has_result()
                    && !e.selection_pending
                    && Some(&e.root) == state.root.as_ref()
            });
        let assessment_pending = state.root.as_ref().is_some_and(|root| {
            evaluation.as_ref().is_some_and(|result| {
                &result.root != root
                    || result.selection_pending
                    || result
                        .coverage
                        .iter()
                        .any(|code| code == "package_scope_pending")
            })
        });
        Ok(View {
            hidden_count: active.hidden,
            active,
            monitoring: crate::monitoring::effective(&db, "packages", id, "")?.values,
            evaluation,
            fresh,
            collecting: state.stage.is_some(),
            assessment_pending,
            last_success: state.last_success,
            next_check: state.next_check,
            error: state.error,
            total,
            offset,
            findings,
            fixes,
            bulk_fix,
            sources,
            cvss_queue,
        })
    }
    pub(crate) fn set_vulnerability_hidden(
        &self,
        id: &str,
        source: &str,
        cve: &str,
        expected: &str,
        hidden: bool,
        at: i64,
    ) -> Result<Vec<String>> {
        if id.len() > 128
            || source.len() > 256
            || cve.len() > 80
            || expected.len() != 64
            || !expected.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("Invalid vulnerability parameters".into());
        }
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        let current: Option<(String, Option<String>, Option<i64>)> = tx.query_row(
            "SELECT payload,signature,hidden_at FROM vulnerability_groups WHERE server_id=?1 AND source=?2 AND payload IS NOT NULL",
            params![id,source], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).optional().map_err(err)?;
        let (payload, signature, hidden_at) =
            current.ok_or("The vulnerability is no longer relevant.")?;
        let finding: Match = serde_json::from_str(&payload).map_err(err)?;
        if finding.cve != cve
            || scoped_fingerprint(&server_scope(&tx, id)?, signature.as_deref(), &finding)
                != expected
        {
            return Err("Vulnerabilities have changed. Update the list.".into());
        }
        if hidden_at.is_some() == hidden {
            return Ok(vec![]);
        }
        tx.execute(
            "UPDATE vulnerability_groups SET hidden_at=?3 WHERE server_id=?1 AND source=?2",
            params![id, source, hidden.then_some(at)],
        )
        .map_err(err)?;
        if !hidden {
            tx.execute("UPDATE vulnerability_findings SET payload=json_remove(payload,'$.hiddenAt') WHERE server_id=?1 AND source=?2", params![id,source]).map_err(err)?;
        }
        let check = format!("vuln:{source}");
        let incident_id = stable_id(id, &check);
        let raw: Option<String> = tx
            .query_row(
                "SELECT payload FROM incidents WHERE id=?1",
                [&incident_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        let old: Option<Incident> = raw
            .map(|s| serde_json::from_str(&s).map_err(err))
            .transpose()?;
        let mut cancel = Vec::new();
        if hidden {
            if let Some(open) = old.filter(|i| i.status == "open") {
                cancel = crate::incidents::resolve_in_transaction(
                    &tx,
                    &open.id,
                    &crate::automation::episode(&open),
                    at,
                    false,
                )?;
            }
        } else if finding.state == "affected" {
            tx.execute("UPDATE incidents SET payload=json_set(payload,'$.manualResolutionPending',json('false')) WHERE id=?1", [&incident_id]).map_err(err)?;
            Store::incident(
                &tx,
                id,
                &check,
                Some(incident_detail(&finding)),
                &format!("Vulnerabilities {source}"),
                incident_severity(&finding),
                at,
            )?;
            // The matcher verifies freshness before AUTO can use a restored finding.
            tx.execute("UPDATE incidents SET payload=json_set(payload,'$.autoEligible',json('false'),'$.freshUntil',?2) WHERE id=?1", params![incident_id, at-1]).map_err(err)?;
            if crate::monitoring::effective(&tx, "packages", id, "")?
                .values
                .enabled
            {
                tx.execute(
                    "INSERT OR IGNORE INTO vulnerability_pending VALUES(?1)",
                    [id],
                )
                .map_err(err)?;
            }
        }
        tx.commit().map_err(err)?;
        Ok(cancel)
    }
    #[cfg(test)]
    fn save_assessment(&self, id: &str, expected: &State, assessment: Assessment) -> Result<()> {
        let (_, packages) = self.package_snapshot(id)?;
        self.commit_assessment(id, expected, assessment, &groups::versions(&packages))
    }

    fn commit_assessment(
        &self,
        id: &str,
        expected: &State,
        assessment: Assessment,
        versions: &BTreeMap<String, String>,
    ) -> Result<()> {
        let mut unique: BTreeMap<(String, String), Match> = BTreeMap::new();
        for finding in assessment.findings {
            let key = (finding.source.clone(), finding.cve.clone());
            match unique.get_mut(&key) {
                Some(old) => {
                    if old.state != "affected" && finding.state == "affected" {
                        *old = finding;
                    } else if old.state == finding.state {
                        for p in finding.packages {
                            if !old
                                .packages
                                .iter()
                                .any(|o| o.name == p.name && o.version == p.version)
                            {
                                old.packages.push(p);
                            }
                        }
                    }
                }
                None => {
                    unique.insert(key, finding);
                }
            }
        }
        let mut write_bytes = 0usize;
        for f in unique.values() {
            let size = serde_json::to_vec(f).map_err(err)?.len();
            if size > 16384 {
                return Err("CVE evidence exceeds 16 KiB".into());
            }
            write_bytes += size;
        }
        if write_bytes > 8 * 1024 * 1024 {
            return Err("Vulnerability summary exceeds 8 MiB".into());
        }
        let mut db = self.0.lock().map_err(err)?;
        crate::storage::admit(&db)?;
        let tx = db.transaction().map_err(err)?;
        if !crate::monitoring::effective(&tx, "packages", id, "")?
            .values
            .enabled
        {
            return Err("package monitoring turned off".into());
        }
        let raw: String = tx
            .query_row(
                "SELECT payload FROM package_state WHERE server_id=?1",
                [id],
                |r| r.get(0),
            )
            .map_err(err)?;
        let state: State = serde_json::from_str(&raw).map_err(err)?;
        if state.token != expected.token || state.revision != expected.revision {
            return Err(SUPERSEDED.into());
        }
        // Feed replacement is concurrent with matching: do not commit results of a superseded generation.
        for (source, expected_generation) in &assessment.generations {
            let actual = if source == "cvss_revision" {
                tx.query_row("SELECT at FROM maintenance WHERE id=2", [], |r| {
                    r.get::<_, u64>(0)
                })
                .optional()
                .map_err(err)?
                .unwrap_or(0)
                .to_string()
            } else {
                let raw: Option<String> = tx
                    .query_row(
                        "SELECT payload FROM advisory_sources WHERE id=?1",
                        [source],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(err)?;
                raw.map(|s| {
                    serde_json::from_str::<advisories::Source>(&s)
                        .map(|s| crate::packages::digest(&s))
                        .map_err(err)
                })
                .transpose()?
                .unwrap_or("missing".into())
            };
            if &actual != expected_generation {
                return Err(SUPERSEDED.into());
            }
        }
        let old: Option<String> = tx
            .query_row(
                "SELECT payload FROM vulnerability_evaluations WHERE server_id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        let old: Option<Evaluation> = old
            .map(|s| serde_json::from_str(&s).map_err(err))
            .transpose()?;
        let at = now();
        let fresh_until = assessment
            .fresh_until
            .min(state.last_success.unwrap_or(0) + 86400);
        let authoritative =
            state.error.is_none() && fresh_until >= at && complete_coverage(&assessment.coverage);
        // A pass waiting for coverage has not yet verified this package read.
        let independent = old
            .as_ref()
            .is_none_or(|o| o.checks < state.checks || !o.verified_at(o.at));
        let mut previous_groups = groups::read(&tx, id)?;
        if authoritative {
            tx.execute("UPDATE vulnerability_findings SET resolved_at=?2 WHERE server_id=?1 AND resolved_at IS NULL",params![id,at]).map_err(err)?;
        }
        let mut candidates = BTreeMap::<String, Vec<SavedFinding>>::new();
        for finding in unique.into_values() {
            let old: Option<String> = tx.query_row(
                "SELECT payload FROM vulnerability_findings WHERE server_id=?1 AND source=?2 AND cve=?3",
                params![id,finding.source,finding.cve], |r| r.get(0),
            ).optional().map_err(err)?;
            let old: Option<SavedFinding> = old
                .map(|raw| serde_json::from_str(&raw).map_err(err))
                .transpose()?;
            let old = old.filter(|old| fingerprint(&old.finding) == fingerprint(&finding));
            let changed = (authoritative || finding.state == "affected")
                && previous_groups.get(&finding.source).is_some_and(|group| {
                    group
                        .signature
                        .as_ref()
                        .is_some_and(|old| Some(old) != versions.get(&finding.source))
                });
            let saved = SavedFinding {
                finding,
                hidden_at: old.as_ref().filter(|_| !changed).and_then(|f| f.hidden_at),
                first_seen_at: Some(old.and_then(|f| f.first_seen_at).unwrap_or(at)),
            };
            tx.execute(
                "INSERT INTO vulnerability_findings VALUES(?1,?2,?3,NULL,?4)
                 ON CONFLICT(server_id,source,cve) DO UPDATE SET resolved_at=NULL,payload=excluded.payload",
                params![id,saved.finding.source,saved.finding.cve,serde_json::to_string(&saved).map_err(err)?],
            ).map_err(err)?;
            candidates
                .entry(saved.finding.source.clone())
                .or_default()
                .push(saved);
        }
        let sources: std::collections::BTreeSet<_> = previous_groups
            .keys()
            .chain(candidates.keys())
            .cloned()
            .collect();
        let mut grouped = BTreeMap::new();
        for source in sources {
            let prior = previous_groups.remove(&source);
            let selected = groups::select(
                prior,
                versions.get(&source).cloned(),
                candidates.get(&source).map_or(&[], Vec::as_slice),
                authoritative,
            );
            if let Some(selected) = selected {
                groups::write(&tx, id, &source, &selected)?;
                grouped.insert(source, selected);
            } else {
                tx.execute(
                    "DELETE FROM vulnerability_groups WHERE server_id=?1 AND source=?2",
                    params![id, source],
                )
                .map_err(err)?;
            }
        }
        let visible = counts(&tx, Some(id))?.remove(id).unwrap_or_default();
        let evaluation = Evaluation {
            retry_after: 0,
            selection_pending: grouped.iter().any(|(source, group)| {
                group.finding.is_some() && group.signature.as_ref() != versions.get(source)
            }),
            at,
            root: state.root.clone().unwrap_or_default(),
            checks: state.checks,
            fresh_until,
            coverage: assessment.coverage,
            generations: assessment.generations,
            affected: visible.affected,
            critical: visible.critical,
            unknown: visible.unknown,
            error: None,
        };
        let previous: Vec<Incident> = {
            let mut q=tx.prepare("SELECT payload FROM incidents WHERE server_id=?1 AND json_extract(payload,'$.check') LIKE 'vuln:%' AND (json_extract(payload,'$.status')='open' OR json_extract(payload,'$.manualResolutionPending')=1)").map_err(err)?;
            let rows = q.query_map([id], |r| r.get::<_, String>(0)).map_err(err)?;
            rows.map(|r| serde_json::from_str(&r.map_err(err)?).map_err(err))
                .collect::<Result<_>>()?
        };
        for (source, group) in &grouped {
            let Some(finding) = &group.finding else {
                continue;
            };
            let check = format!("vuln:{source}");
            let incident_id = stable_id(id, &check);
            let verified = group.signature.as_ref() == versions.get(source)
                && candidates.get(source).is_some_and(|rows| {
                    rows.iter().any(|row| {
                        row.finding.cve == finding.cve
                            && row.finding.state == finding.state
                            && row.finding.severity == finding.severity
                    })
                });
            if group.hidden_at.is_none() && verified && finding.state == "affected" {
                tx.execute("UPDATE incidents SET payload=json_set(payload,'$.manualResolutionPending',json('false')) WHERE id=?1 AND json_extract(payload,'$.status')='resolved'",[&incident_id]).map_err(err)?;
                let detail = incident_detail(finding);
                let severity = incident_severity(finding);
                Store::incident(
                    &tx,
                    id,
                    &check,
                    Some(detail.clone()),
                    &format!("Vulnerabilities {source}"),
                    severity,
                    at,
                )?;
                tx.execute(
                    "UPDATE incidents SET payload=json_set(payload,'$.autoEligible',CASE WHEN json_extract(payload,'$.status')='open' THEN json(?2) ELSE json('false') END,'$.freshUntil',?3) WHERE id=?1",
                    params![incident_id, if severity == "critical" && authoritative { "true" } else { "false" }, fresh_until],
                ).map_err(err)?;
                tx.execute("UPDATE ai_jobs SET payload=json_set(payload,'$.evidence',?2,'$.severity',?3) WHERE incident_id=?1 AND state IN ('queued','suppressed')",params![incident_id,detail,severity]).map_err(err)?;
                let evidence = serde_json::json!({"root":state.root,"at":at,"generations":evaluation.generations,"count":1,"cves":[finding.cve]});
                tx.execute(
                    "INSERT INTO vulnerability_evidence VALUES(?1,?2,?3,?4)",
                    params![
                        uuid::Uuid::new_v4().to_string(),
                        incident_id,
                        at,
                        evidence.to_string()
                    ],
                )
                .map_err(err)?;
                tx.execute("DELETE FROM vulnerability_evidence WHERE incident_id=?1 AND id NOT IN (SELECT id FROM vulnerability_evidence WHERE incident_id=?1 ORDER BY at DESC,rowid DESC LIMIT 5)",[incident_id]).map_err(err)?;
            } else {
                tx.execute("UPDATE incidents SET payload=json_set(payload,'$.autoEligible',json('false'),'$.healthyStreak',0,'$.freshUntil',?2) WHERE id=?1",params![incident_id,at-1]).map_err(err)?;
            }
        }
        for incident in previous {
            let source = incident.check.trim_start_matches("vuln:");
            if grouped.get(source).is_some_and(|g| g.finding.is_some()) {
                continue;
            }
            if authoritative
                && independent
                && !evaluation.coverage.iter().any(|c| {
                    c == &format!("uncovered_package:{source}")
                        || c == &format!("critical_severity_pending:{source}")
                })
            {
                Store::incident(
                    &tx,
                    id,
                    &incident.check,
                    None,
                    &incident.title,
                    &incident.severity,
                    at,
                )?;
            } else if !authoritative {
                tx.execute("UPDATE incidents SET payload=json_set(payload,'$.healthyStreak',0) WHERE id=?1",[&incident.id]).map_err(err)?;
            }
            tx.execute("UPDATE incidents SET payload=json_set(payload,'$.autoEligible',json('false'),'$.freshUntil',?2) WHERE id=?1",params![incident.id,if authoritative{fresh_until}else{at-1}]).map_err(err)?;
        }
        tx.execute("INSERT INTO vulnerability_evaluations VALUES(?1,?2) ON CONFLICT(server_id) DO UPDATE SET payload=excluded.payload",params![id,serde_json::to_string(&evaluation).map_err(err)?]).map_err(err)?;
        tx.execute("DELETE FROM vulnerability_pending WHERE server_id=?1", [id])
            .map_err(err)?;
        tx.commit().map_err(err)
    }
    pub(crate) fn evaluate_vulnerabilities(&self, id: &str, root: &std::path::Path) -> Result<()> {
        let (state, packages) = self.package_snapshot(id)?;
        let meta = state
            .metadata
            .as_ref()
            .ok_or("Installed package scan is incomplete")?;
        let assessment = advisories::assess(
            self,
            root,
            meta,
            &packages,
            state.root.as_deref().unwrap_or(""),
        )?;
        self.commit_assessment(id, &state, assessment, &groups::versions(&packages))
    }
    pub(crate) fn vulnerability_recovery_pending(
        &self,
        id: &str,
        min_checks: u64,
    ) -> Result<Option<bool>> {
        let db = self.0.lock().map_err(err)?;
        let (open, first_at): (bool, Option<i64>) = db
            .query_row(
                "SELECT count(*)>0, max(CASE WHEN json_extract(payload,'$.healthyStreak')=1
                                           THEN json_extract(payload,'$.updatedAt') END)
             FROM incidents WHERE server_id=?1 AND json_extract(payload,'$.status')='open'
             AND json_extract(payload,'$.check') LIKE 'vuln:%'",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(err)?;
        if !open {
            return Ok(Some(false));
        }
        let raw: Option<(String, Option<i64>)> = db
            .query_row(
                "SELECT e.payload, json_extract(p.payload,'$.lastSuccess')
             FROM vulnerability_evaluations e JOIN package_state p USING(server_id)
             WHERE e.server_id=?1 AND json_extract(e.payload,'$.checks')>=?2
             AND json_extract(e.payload,'$.checks')=json_extract(p.payload,'$.checks')
             AND json_extract(e.payload,'$.root')=json_extract(p.payload,'$.root')",
                params![id, min_checks],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(err)?;
        let Some((raw, read_at)) = raw else {
            return Ok(None);
        };
        let evaluation: Evaluation = serde_json::from_str(&raw).map_err(err)?;
        Ok(evaluation.verified_at(now()).then(|| {
            first_at
                .zip(read_at)
                .is_some_and(|(first, read)| first >= read)
        }))
    }
    fn vulnerability_error(&self, id: &str) -> Result<()> {
        let db = self.0.lock().map_err(err)?;
        db.execute("UPDATE incidents SET payload=json_set(payload,'$.autoEligible',json('false'),'$.freshUntil',?2,'$.healthyStreak',0) WHERE server_id=?1 AND json_extract(payload,'$.check') LIKE 'vuln:%'",params![id,now()-1]).map_err(err)?;
        let raw: Option<String> = db
            .query_row(
                "SELECT payload FROM vulnerability_evaluations WHERE server_id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        let mut evaluation: Evaluation = raw
            .map(|s| serde_json::from_str(&s).map_err(err))
            .transpose()?
            .unwrap_or_default();
        evaluation.error = Some("Package matching is incomplete. Try again in 5 minutes.".into());
        evaluation.fresh_until = 0;
        evaluation.retry_after = now() + 300;
        db.execute("INSERT INTO vulnerability_evaluations VALUES(?1,?2) ON CONFLICT(server_id) DO UPDATE SET payload=excluded.payload",params![id,serde_json::to_string(&evaluation).map_err(err)?]).map_err(err)?;
        Ok(())
    }
}
pub(crate) async fn process_pending(app: Arc<AppState>) -> Result<bool> {
    let priority = app.package_refresh.awaiting_assessment();
    let ids = {
        let db = app.store.0.lock().map_err(err)?;
        let book = crate::monitoring::Book::load(&db)?;
        let mut q = db
            .prepare("SELECT p.server_id FROM vulnerability_pending p LEFT JOIN vulnerability_evaluations e ON e.server_id=p.server_id WHERE coalesce(json_extract(e.payload,'$.retryAfter'),0)<=?1 ORDER BY p.rowid ")
            .map_err(err)?;
        let r = q
            .query_map([now()], |r| r.get::<_, String>(0))
            .map_err(err)?;
        let mut ids = r
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err)?
            .into_iter()
            .filter(|id| book.enabled("packages", id, "default"))
            .collect::<Vec<_>>();
        ids.sort_by_key(|id| !priority.contains(id));
        ids.truncate(8);
        ids
    };
    let did_work = !ids.is_empty();
    for id in ids {
        if !crate::monitoring::enabled(&app.store, "packages", &id, "")? {
            continue;
        }
        let app = app.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let result = app
                .store
                .evaluate_vulnerabilities(&id, &app.root.join("advisories"));
            // A superseded generation stays pending and is matched again on the next pass.
            if result.as_ref().is_err_and(|e| e != SUPERSEDED) {
                app.store.vulnerability_error(&id)?;
            }
            result
        })
        .await
        .map_err(err)?;
    }
    Ok(did_work)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Settings;
    use crate::packages::tests::{fixture, install, package};
    fn assessment(severity: &str) -> Assessment {
        Assessment {
            findings: if severity.is_empty() {
                vec![]
            } else {
                vec![Match {
                    source: "openssl".into(),
                    cve: "CVE-2025-10000".into(),
                    state: "affected".into(),
                    severity: severity.into(),
                    severity_source: "test".into(),
                    packages: vec![],
                    description: "fixture".into(),
                    url: "https://security-tracker.debian.org/tracker/CVE-2025-10000".into(),
                    reason: None,
                    fix_published: true,
                }]
            },
            coverage: vec![],
            generations: BTreeMap::new(),
            fresh_until: now() + 86400,
        }
    }
    #[test]
    fn manually_closed_vulnerability_needs_two_independent_recoveries() {
        let (db, s) = fixture();
        let state = install(&db, &s, vec![package()]);
        db.save_assessment(&s.id, &state, assessment("critical"))
            .unwrap();
        let i = db.snapshot().unwrap().incidents.remove(0);
        db.resolve_incident(&i.id, &i.episode, now()).unwrap();
        db.save_assessment(&s.id, &state, assessment("critical"))
            .unwrap();
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "resolved");
        assert!(db.vulnerability_view(&s.id, 0).unwrap().findings.is_empty());
        assert_eq!(db.vulnerability_view(&s.id, 0).unwrap().hidden_count, 1);
        assert!(!db.snapshot().unwrap().incidents[0].auto_eligible);
        for _ in 0..2 {
            let st = install(&db, &s, vec![package()]);
            db.save_assessment(&s.id, &st, assessment("")).unwrap();
        }
        assert!(!db.snapshot().unwrap().incidents[0].manual_resolution_pending);
        let st = install(&db, &s, vec![package()]);
        db.save_assessment(&s.id, &st, assessment("critical"))
            .unwrap();
        assert_eq!(db.snapshot().unwrap().incidents[0].episode, i.episode);
        assert!(db.vulnerability_view(&s.id, 0).unwrap().findings.is_empty());
    }
    #[test]
    fn critical_only_grouped_dedup_and_two_independent_recoveries() {
        let (db, s) = fixture();
        let state = install(&db, &s, vec![package()]);
        db.save_settings(&Settings {
            mode: "auto".into(),
            daily_run_limit: Some(5),
            daily_token_limit: Some(500000),
            ..Settings::default()
        })
        .unwrap();
        db.save_assessment(&s.id, &state, assessment("high"))
            .unwrap();
        db.reconcile_auto(now()).unwrap();
        assert!(db.next_auto(now()).unwrap().is_none());
        db.save_assessment(&s.id, &state, assessment("critical"))
            .unwrap();
        db.reconcile_auto(now()).unwrap();
        assert!(db.next_auto(now()).unwrap().is_some());
        let ep = db.snapshot().unwrap().incidents[0].episode.clone();
        let mut a = assessment("critical");
        let mut f = a.findings[0].clone();
        f.cve = "CVE-2025-10001".into();
        a.findings.push(f);
        db.save_assessment(&s.id, &state, a).unwrap();
        db.reconcile_auto(now()).unwrap();
        assert_eq!(db.snapshot().unwrap().incidents.len(), 1);
        assert_eq!(db.snapshot().unwrap().incidents[0].episode, ep);
        assert_eq!(db.auto_status(now()).unwrap().queued, 1);
        db.save_assessment(&s.id, &state, assessment("")).unwrap();
        assert_eq!(db.snapshot().unwrap().incidents[0].healthy_streak, 0);
        let st = install(&db, &s, vec![package()]);
        db.save_assessment(&s.id, &st, assessment("")).unwrap();
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "open");
        db.save_assessment(&s.id, &st, assessment("")).unwrap();
        assert_eq!(db.snapshot().unwrap().incidents[0].healthy_streak, 1);
        let st = install(&db, &s, vec![package()]);
        db.save_assessment(&s.id, &st, assessment("")).unwrap();
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "resolved");
    }
    #[test]
    fn current_partial_assessment_is_healthy_when_there_are_no_findings() {
        let (db, s) = fixture();
        let state = install(&db, &s, vec![package()]);
        let mut partial = assessment("");
        partial.coverage = vec!["critical_severity_pending:openssl".into()];
        db.save_assessment(&s.id, &state, partial).unwrap();
        assert_eq!(
            db.snapshot().unwrap().vulnerabilities[&s.id].status,
            "healthy"
        );
        let mut unavailable = assessment("");
        unavailable.coverage = vec!["missing:debian".into()];
        db.save_assessment(&s.id, &state, unavailable).unwrap();
        assert_eq!(
            db.snapshot().unwrap().vulnerabilities[&s.id].status,
            "unknown"
        );
        assert!(!db.vulnerability_view(&s.id, 0).unwrap().fresh);
    }
    #[test]
    fn truncated_package_notes_do_not_keep_fixed_findings_after_a_rescan() {
        let (db, s) = fixture();
        let state = install(&db, &s, vec![package()]);
        db.save_assessment(&s.id, &state, assessment("critical"))
            .unwrap();

        let mut updated = package();
        updated.version = "3.0.2-1".into();
        updated.source_version = updated.version.clone();
        let state = install(&db, &s, vec![updated]);
        let pending = db.vulnerability_view(&s.id, 0).unwrap();
        assert!(pending.assessment_pending);
        assert_eq!(pending.findings.len(), 1);

        let mut result = assessment("");
        result.coverage = vec![
            "uncovered_package_total:200".into(),
            "coverage_list_truncated".into(),
        ];
        db.save_assessment(&s.id, &state, result).unwrap();
        let view = db.vulnerability_view(&s.id, 0).unwrap();
        assert!(!view.assessment_pending);
        assert!(view.findings.is_empty());
        assert_eq!(view.active.affected, 0);
    }

    #[test]
    fn unknown_or_missing_coverage_does_not_recover_or_admit() {
        let (db, s) = fixture();
        let state = install(&db, &s, vec![package()]);
        db.save_assessment(&s.id, &state, assessment("critical"))
            .unwrap();
        let mut a = assessment("");
        a.coverage.push("stale_or_failed:debian".into());
        let st = install(&db, &s, vec![package()]);
        db.save_assessment(&s.id, &st, a).unwrap();
        let incident = &db.snapshot().unwrap().incidents[0];
        assert_eq!(incident.status, "open");
        assert!(!incident.auto_eligible);
        assert_eq!(incident.healthy_streak, 0);
        assert_eq!(db.vulnerability_view(&s.id, 0).unwrap().findings.len(), 1);
    }
    #[tokio::test]
    async fn mcp_vulnerabilities_are_cached_scoped_and_not_remote() {
        let dir = tempfile::tempdir().unwrap();
        let app = crate::create_state(dir.path().to_owned()).unwrap();
        let source = crate::model::Source {
            id: "s".into(),
            name: "test".into(),

            kind: "manual".into(),
            location: "ops@127.0.0.1:1".into(),
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
        let m = crate::mcp::McpServer::start(app.clone(), std::slice::from_ref(&id))
            .await
            .unwrap();
        let result = crate::mcp::call(
            &m.scope,
            "get_vulnerability_summary",
            serde_json::json!({"serverId":id}),
        )
        .await
        .unwrap();
        assert!(result["evaluation"].is_null());
        assert_eq!(m.scope.remote.load(std::sync::atomic::Ordering::SeqCst), 0);
        for args in [
            serde_json::json!({"serverId":"outside"}),
            serde_json::json!({"serverId":id,"path":"/etc/shadow"}),
            serde_json::json!({"serverId":id,"offset":20001}),
        ] {
            assert!(
                crate::mcp::call(&m.scope, "get_vulnerability_summary", args)
                    .await
                    .is_err()
            );
        }
        let _busy = app.collectors.try_background(&id, 1).unwrap().unwrap();
        assert!(
            crate::monitoring::trigger("schedule", crate::packages::collect(app.clone(), id))
                .await
                .err()
                .unwrap()
                .contains("busy")
        );
    }
    #[test]
    fn changed_severity_generation_cannot_commit_old_result() {
        let (db, s) = fixture();
        let state = install(&db, &s, vec![package()]);
        let mut a = assessment("critical");
        a.generations.insert("cvss_revision".into(), "0".into());
        {
            let c = db.0.lock().unwrap();
            c.execute("INSERT INTO maintenance VALUES(2,1)", [])
                .unwrap();
        }
        assert!(db.save_assessment(&s.id, &state, a).is_err());
        assert!(db.snapshot().unwrap().incidents.is_empty());
    }
    fn set_hidden(db: &Store, id: &str, cve: &str, hidden: bool) {
        let view = db.vulnerability_view_filtered(id, 0, true).unwrap();
        let f = view.findings.iter().find(|f| f.finding.cve == cve).unwrap();
        db.set_vulnerability_hidden(id, &f.finding.source, cve, &f.fingerprint, hidden, now())
            .unwrap();
    }
    #[test]
    fn a_package_counts_once_and_the_same_episode_uses_one_stable_cve() {
        let (db, s) = fixture();
        let state = install(&db, &s, vec![package()]);
        db.save_settings(&Settings {
            mode: "auto".into(),
            daily_run_limit: Some(5),
            daily_token_limit: Some(500000),
            ..Default::default()
        })
        .unwrap();
        let mut a = assessment("critical");
        a.findings.clear();
        for n in 0..125 {
            let mut finding = assessment("critical").findings.remove(0);
            finding.cve = format!("CVE-2025-{}", 20000 + n);
            finding.fix_published = n > 0;
            a.findings.push(finding);
        }
        db.save_assessment(&s.id, &state, a).unwrap();
        db.reconcile_auto(now()).unwrap();
        let representative = "CVE-2025-20001";
        let view = db.vulnerability_view(&s.id, 0).unwrap();
        assert_eq!(view.total, 1);
        assert_eq!(view.active.critical, 1);
        assert_eq!(view.evaluation.unwrap().critical, 1);
        assert_eq!(view.findings[0].finding.cve, representative);
        assert_eq!(db.snapshot().unwrap().vulnerabilities[&s.id].affected, 1);
        let episode = db.snapshot().unwrap().incidents[0].episode.clone();
        let job = db.next_auto(now()).unwrap().unwrap();
        assert!(job.evidence.contains(representative));
        assert!(!job.evidence.contains("CVE-2025-20000"));
        let raw: usize = db.0.lock().unwrap().query_row(
            "SELECT count(*) FROM vulnerability_findings WHERE server_id=?1 AND resolved_at IS NULL",
            [&s.id], |row| row.get(0),
        ).unwrap();
        assert_eq!(raw, 125);

        let mut next = assessment("critical");
        let mut prior = next.findings[0].clone();
        prior.cve = representative.into();
        next.findings.push(prior);
        db.save_assessment(&s.id, &state, next).unwrap();
        assert_eq!(
            db.vulnerability_view(&s.id, 0).unwrap().findings[0]
                .finding
                .cve,
            representative
        );
        assert_eq!(db.snapshot().unwrap().incidents[0].episode, episode);
        assert_eq!(db.auto_status(now()).unwrap().queued, 1);

        set_hidden(&db, &s.id, representative, true);
        let view = db.vulnerability_view(&s.id, 0).unwrap();
        assert_eq!(view.total, 0);
        assert_eq!(view.hidden_count, 1);
        assert_eq!(db.snapshot().unwrap().vulnerabilities[&s.id].affected, 0);
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "resolved");
        assert_eq!(db.auto_status(now()).unwrap().queued, 0);
        set_hidden(&db, &s.id, representative, false);
        assert_eq!(db.vulnerability_view(&s.id, 0).unwrap().total, 1);
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "open");
    }
    #[test]
    fn resolving_an_incident_hides_the_package_until_its_installed_version_changes() {
        let (db, s) = fixture();
        let state = install(&db, &s, vec![package()]);
        db.save_assessment(&s.id, &state, assessment("critical"))
            .unwrap();
        let old = db.snapshot().unwrap().incidents.remove(0);
        db.resolve_incident(&old.id, &old.episode, now()).unwrap();
        let another_cve = || {
            let mut a = assessment("critical");
            a.findings[0].cve = "CVE-2025-10002".into();
            a
        };
        let mut other = package();
        other.name = "other".into();
        other.source = "other".into();
        let unchanged = install(&db, &s, vec![package(), other.clone()]);
        db.save_assessment(&s.id, &unchanged, another_cve())
            .unwrap();
        let view = db.vulnerability_view(&s.id, 0).unwrap();
        assert_eq!(view.total, 0);
        assert_eq!(view.hidden_count, 1);
        assert_eq!(db.snapshot().unwrap().incidents[0].episode, old.episode);

        let mut upgrade = package();
        upgrade.version = "3.0.0-2".into();
        upgrade.source_version = upgrade.version.clone();
        let updated = install(&db, &s, vec![upgrade.clone(), other]);
        assert!(db.vulnerability_view(&s.id, 0).unwrap().assessment_pending);
        let mut pending = assessment("");
        pending.coverage.push("package_scope_pending".into());
        db.save_assessment(&s.id, &updated, pending).unwrap();
        assert_eq!(db.vulnerability_view(&s.id, 0).unwrap().hidden_count, 1);
        db.save_assessment(&s.id, &updated, another_cve()).unwrap();
        let view = db.vulnerability_view(&s.id, 0).unwrap();
        assert_eq!(view.total, 1);
        assert_eq!(view.findings[0].finding.cve, "CVE-2025-10002");
        assert_eq!(view.hidden_count, 0);
        let incident = &db.snapshot().unwrap().incidents[0];
        assert_eq!(incident.status, "open");
        assert_ne!(incident.episode, old.episode);
        let mut fixed = upgrade;
        fixed.version = "3.0.0-3".into();
        fixed.source_version = fixed.version.clone();
        let fixed = install(&db, &s, vec![fixed]);
        db.save_assessment(&s.id, &fixed, assessment("")).unwrap();
        assert_eq!(db.vulnerability_view(&s.id, 0).unwrap().active.affected, 0);
    }
    #[test]
    fn hiding_is_atomic_with_incident_queue_and_notification_updates() {
        let (db, s) = fixture();
        let state = install(&db, &s, vec![package()]);
        db.save_settings(&Settings {
            mode: "auto".into(),
            daily_run_limit: Some(5),
            daily_token_limit: Some(500000),
            ..Default::default()
        })
        .unwrap();
        db.save_assessment(&s.id, &state, assessment("critical"))
            .unwrap();
        db.reconcile_auto(now()).unwrap();
        let view = db.vulnerability_view(&s.id, 0).unwrap();
        let f = &view.findings[0];
        db.0.lock().unwrap().execute_batch("CREATE TRIGGER fail_hide BEFORE UPDATE ON ai_jobs BEGIN SELECT RAISE(ABORT,'fixture failure'); END").unwrap();
        assert!(db
            .set_vulnerability_hidden(
                &s.id,
                &f.finding.source,
                &f.finding.cve,
                &f.fingerprint,
                true,
                now()
            )
            .is_err());
        assert_eq!(db.vulnerability_view(&s.id, 0).unwrap().total, 1);
        assert_eq!(db.vulnerability_view(&s.id, 0).unwrap().hidden_count, 0);
        assert_eq!(db.snapshot().unwrap().incidents[0].status, "open");
        assert_eq!(db.auto_status(now()).unwrap().queued, 1);
        assert_eq!(db.notification_settings().unwrap().queued, 1);
        let i = db.snapshot().unwrap().incidents.remove(0);
        assert!(db.resolve_incident(&i.id, &i.episode, now()).is_err());
        assert_eq!(db.vulnerability_view(&s.id, 0).unwrap().hidden_count, 0);
    }
    #[test]
    fn hidden_findings_and_legacy_incident_resolution_survive_restart() {
        let (db, s) = fixture();
        let state = install(&db, &s, vec![package()]);
        db.save_assessment(&s.id, &state, assessment("critical"))
            .unwrap();
        let i = db.snapshot().unwrap().incidents.remove(0);
        db.resolve_incident(&i.id, &i.episode, now()).unwrap();
        db.0.lock().unwrap().execute_batch(
            "UPDATE vulnerability_findings SET payload=json_remove(payload,'$.hiddenAt','$.firstSeenAt');
             DROP TABLE vulnerability_groups;
             PRAGMA user_version=16;"
        ).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("copy.sqlite");
        db.0.lock()
            .unwrap()
            .execute("VACUUM INTO ?1", [file.to_str().unwrap()])
            .unwrap();
        let reopened = Store::open(&file).unwrap();
        assert_eq!(reopened.vulnerability_view(&s.id, 0).unwrap().total, 0);
        assert_eq!(
            reopened.vulnerability_view(&s.id, 0).unwrap().hidden_count,
            1
        );
        reopened
            .save_assessment(&s.id, &state, assessment("critical"))
            .unwrap();
        assert_eq!(reopened.vulnerability_view(&s.id, 0).unwrap().total, 0);
    }
    #[test]
    fn a_changed_package_fingerprint_reappears_and_stale_actions_are_rejected() {
        let (db, s) = fixture();
        let state = install(&db, &s, vec![package()]);
        let mut a = assessment("critical");
        a.findings[0].packages.push(advisories::PackageEvidence {
            name: "libssl".into(),
            version: "1".into(),
            fixed_version: Some("3".into()),
        });
        db.save_assessment(&s.id, &state, a).unwrap();
        let old = db.vulnerability_view(&s.id, 0).unwrap().findings.remove(0);
        set_hidden(&db, &s.id, &old.finding.cve, true);
        let mut changed = assessment("critical");
        changed.findings[0]
            .packages
            .push(advisories::PackageEvidence {
                name: "libssl".into(),
                version: "2".into(),
                fixed_version: Some("3".into()),
            });
        let mut updated = package();
        updated.version = "3.0.0-2".into();
        updated.source_version = updated.version.clone();
        let updated = install(&db, &s, vec![updated]);
        db.save_assessment(&s.id, &updated, changed).unwrap();
        assert_eq!(db.vulnerability_view(&s.id, 0).unwrap().total, 1);
        assert!(db
            .set_vulnerability_hidden(
                &s.id,
                &old.finding.source,
                &old.finding.cve,
                &old.fingerprint,
                true,
                now()
            )
            .is_err());
        db.delete_source(&s.source_id).unwrap();
        assert!(db
            .set_vulnerability_hidden(
                &s.id,
                &old.finding.source,
                &old.finding.cve,
                &old.fingerprint,
                true,
                now()
            )
            .is_err());
    }
    #[test]
    fn bulk_fix_uses_eligible_findings_across_pages_and_ignores_hidden_findings() {
        let (db, s) = fixture();
        assert!(db.vulnerability_view(&s.id, 0).unwrap().bulk_fix.is_none());

        let mut installed = Vec::new();
        let mut assessment = assessment("critical");
        let template = assessment.findings.remove(0);
        let evidence = |p: &crate::packages::Package| advisories::PackageEvidence {
            name: format!("{}:{}", p.name, p.arch),
            version: p.version.clone(),
            fixed_version: Some("4".into()),
        };
        for n in 0..23 {
            let source = format!("fixture-{n:02}");
            let mut p = package();
            p.source = source.clone();
            p.name = source.clone();
            installed.push(p.clone());

            let mut f = template.clone();
            f.source = source;
            f.cve = format!("CVE-2025-{}", 21000 + n);
            f.fix_published = matches!(n, 0..=3 | 5 | 22);
            if n != 5 {
                f.packages.push(evidence(&p));
            }
            if n == 0 {
                f.packages.push(evidence(&p));
                p.arch = "i386".into();
                f.packages.push(evidence(&p));
                installed.push(p);
            } else if n == 2 {
                p.name = "fixture-extra".into();
                f.packages.insert(0, evidence(&p));
                installed.push(p);
            }
            if n == 3 {
                f.state = "unknown".into();
            }
            assessment.findings.push(f);
        }
        let state = install(&db, &s, installed);
        db.save_assessment(&s.id, &state, assessment).unwrap();
        let cache_candidate = |source: &str, name: &str, source_version: &str| {
            let at = now();
            let root = state.root.as_ref().unwrap();
            let entry = Apt {
                candidate: crate::packages::Candidate {
                    package: name.into(),
                    version: Some("3".into()),
                    source: Some(source.into()),
                    source_version: Some(source_version.into()),
                },
                cache_at: Some(at),
                at,
                root: root.clone(),
            };
            db.0.lock()
                .unwrap()
                .execute(
                    "INSERT INTO vulnerability_apt VALUES(?1,?2,?3,?4,?5)",
                    params![s.id, name, root, at, serde_json::to_string(&entry).unwrap()],
                )
                .unwrap();
        };
        cache_candidate("fixture-00", "fixture-00:amd64", "4");
        cache_candidate("fixture-00", "fixture-00:i386", "4");
        cache_candidate("fixture-02", "fixture-02:amd64", "3");
        let hide = |f: &Finding| {
            db.set_vulnerability_hidden(
                &s.id,
                &f.finding.source,
                &f.finding.cve,
                &f.fingerprint,
                true,
                now(),
            )
            .unwrap();
        };
        let first = db.vulnerability_view(&s.id, 0).unwrap();
        hide(
            first
                .findings
                .iter()
                .find(|f| f.finding.source == "fixture-01")
                .unwrap(),
        );

        let first = db.vulnerability_view(&s.id, 0).unwrap();
        let second = db.vulnerability_view(&s.id, 20).unwrap();
        assert_eq!(first.findings.len(), 20);
        assert_eq!(second.findings[0].finding.source, "fixture-22");
        assert_eq!(
            first.fixes["fixture-02:CVE-2025-21002:fixture-02:amd64"],
            "not_available"
        );
        let expected = Some(BulkFix {
            finding_count: 2,
            packages: vec![
                "fixture-00:amd64".into(),
                "fixture-00:i386".into(),
                "fixture-22:amd64".into(),
            ],
            has_unverified: true,
        });
        assert_eq!(first.bulk_fix, expected);
        assert_eq!(second.bulk_fix, expected);
        assert_eq!(
            db.vulnerability_view_filtered(&s.id, 0, true)
                .unwrap()
                .bulk_fix,
            expected
        );
        let mcp_page = db
            .vulnerability_page(&s.id, 0, false, None, false, false)
            .unwrap();
        assert!(serde_json::to_value(mcp_page)
            .unwrap()
            .get("bulkFix")
            .is_none());

        cache_candidate("fixture-22", "fixture-22:amd64", "4");
        assert!(
            !db.vulnerability_view(&s.id, 0)
                .unwrap()
                .bulk_fix
                .unwrap()
                .has_unverified
        );
        hide(&second.findings[0]);
        assert!(db
            .vulnerability_view_filtered(&s.id, 0, true)
            .unwrap()
            .bulk_fix
            .is_none());
    }
    #[test]
    fn hidden_pagination_is_bounded_and_does_not_resurrect_empty_pages() {
        let (db, s) = fixture();
        let mut installed = Vec::new();
        let mut a = assessment("");
        for n in 0..21 {
            let mut p = package();
            p.name = format!("fixture-{n:02}");
            p.source = p.name.clone();
            let mut f = assessment("critical").findings.remove(0);
            f.source = p.source.clone();
            f.cve = format!("CVE-2025-{}", 20000 + n);
            installed.push(p);
            a.findings.push(f);
        }
        let state = install(&db, &s, installed);
        db.save_assessment(&s.id, &state, a).unwrap();
        let view = db.vulnerability_view(&s.id, 20).unwrap();
        assert_eq!(view.findings.len(), 1);
        let f = &view.findings[0];
        db.set_vulnerability_hidden(
            &s.id,
            &f.finding.source,
            &f.finding.cve,
            &f.fingerprint,
            true,
            now(),
        )
        .unwrap();
        let view = db.vulnerability_view(&s.id, 20).unwrap();
        assert_eq!(view.offset, 0);
        assert_eq!(view.total, 20);
        assert_eq!(view.hidden_count, 1);
        for i in db.snapshot().unwrap().incidents {
            db.resolve_incident(&i.id, &i.episode, now()).unwrap();
        }
        let hidden = db.vulnerability_view_filtered(&s.id, 0, true).unwrap();
        assert_eq!(hidden.findings.len(), 20);
        assert_eq!(hidden.total, 21);
        assert_eq!(hidden.hidden_count, 21);
    }
    #[test]
    fn unknown_findings_can_be_hidden_without_creating_incidents_or_affecting_other_servers() {
        let (db, s) = fixture();
        let state = install(&db, &s, vec![package()]);
        let mut a = assessment("critical");
        a.findings[0].state = "unknown".into();
        db.save_assessment(&s.id, &state, a).unwrap();
        let source = crate::model::Source {
            id: "second".into(),
            name: "second".into(),
            kind: "manual".into(),
            location: "root@second.invalid".into(),
            last_sync: None,
            error: None,
        };
        db.import(
            &source,
            crate::inventory::parse_manual(&source.location).unwrap(),
        )
        .unwrap();
        let other = db
            .snapshot()
            .unwrap()
            .servers
            .into_iter()
            .find(|v| v.source_id == source.id)
            .unwrap();
        let state2 = install(&db, &other, vec![package()]);
        db.save_assessment(&other.id, &state2, assessment("critical"))
            .unwrap();
        set_hidden(&db, &s.id, "CVE-2025-10000", true);
        assert_eq!(db.vulnerability_view(&s.id, 0).unwrap().total, 0);
        assert_eq!(db.vulnerability_view(&other.id, 0).unwrap().total, 1);
        assert!(db
            .snapshot()
            .unwrap()
            .incidents
            .iter()
            .all(|i| i.server_id == other.id));
        set_hidden(&db, &s.id, "CVE-2025-10000", false);
        assert_eq!(db.vulnerability_view(&s.id, 0).unwrap().active.unknown, 1);
        assert!(db
            .snapshot()
            .unwrap()
            .incidents
            .iter()
            .all(|i| i.server_id == other.id));
    }
}
