//! Distribution-authoritative applicability; optional CNA CVSS never changes package applicability.
use crate::{
    debversion,
    model::now,
    oval,
    packages::{Metadata, Package, Result},
    store::Store,
    AppState,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{
    de::{self, DeserializeSeed, MapAccess, Visitor},
    Deserialize, Serialize,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufReader, Read},
    path::{Path, PathBuf},
    sync::Arc,
};
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
pub fn valid_cve(s: &str) -> bool {
    let p = s.split('-').collect::<Vec<_>>();
    p.len() == 3
        && p[0] == "CVE"
        && p[1].len() == 4
        && p[1].bytes().all(|b| b.is_ascii_digit())
        && (4..=10).contains(&p[2].len())
        && p[2].bytes().all(|b| b.is_ascii_digit())
}
pub(crate) fn cve_record_url(cve: &str) -> Option<String> {
    if !valid_cve(cve) {
        return None;
    }
    let (year, digits) = cve.strip_prefix("CVE-")?.split_once('-')?;
    let prefix = &digits[..digits.len() - 3];
    Some(format!("https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{prefix}xxx/{cve}.json"))
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub roots: BTreeSet<String>,
    pub id: String,
    pub kind: String,
    pub release: String,
    pub checked_at: Option<i64>,
    pub next_check: i64,
    pub hash: Option<String>,
    pub file: Option<String>,
    pub previous: Option<String>,
    pub etag: Option<String>,
    pub modified: Option<String>,
    pub error: Option<String>,
    pub bytes: u64,
}
impl Source {
    fn new(id: &str) -> Result<Self> {
        let parts = id.split(':').collect::<Vec<_>>();
        let (kind, release) = match parts.as_slice() {
            ["debian"] | ["debian-releases"] | ["ubuntu-releases"] => (parts[0], ""),
            [kind, release]
                if ["ubuntu-cve", "ubuntu-usn"].contains(kind)
                    && !release.is_empty()
                    && release.len() <= 32
                    && release.bytes().all(|b| b.is_ascii_lowercase() || b == b'-') =>
            {
                (*kind, *release)
            }
            _ => return Err("Unknown set of advisories".into()),
        };
        Ok(Self {
            scope: String::new(),
            roots: BTreeSet::new(),
            id: id.into(),
            kind: kind.into(),
            release: release.into(),
            checked_at: None,
            next_check: 0,
            hash: None,
            file: None,
            previous: None,
            etag: None,
            modified: None,
            error: None,
            bytes: 0,
        })
    }
    fn url(&self) -> Result<String> {
        Ok(match self.kind.as_str() {
            "debian" => "https://security-tracker.debian.org/tracker/data/json".into(),
            "debian-releases" => {
                "https://salsa.debian.org/debian/distro-info-data/-/raw/main/debian.csv".into()
            }
            "ubuntu-releases" => {
                "https://salsa.debian.org/debian/distro-info-data/-/raw/main/ubuntu.csv".into()
            }
            "ubuntu-cve" | "ubuntu-usn" => format!(
                "https://security-metadata.canonical.com/oval/com.ubuntu.{}.{}.oval.xml.bz2",
                self.release,
                if self.kind == "ubuntu-cve" {
                    "cve"
                } else {
                    "usn"
                }
            ),
            _ => return Err("The advisory URL is blocked".into()),
        })
    }
    pub fn fresh(&self) -> bool {
        self.error.is_none()
            && self.checked_at.is_some_and(|t| now() - t <= 86400)
            && self.file.is_some()
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cvss {
    #[serde(default)]
    pub created_at: i64,
    pub cve: String,
    pub score: Option<f64>,
    pub version: Option<String>,
    pub checked_at: Option<i64>,
    pub next_check: i64,
    pub etag: Option<String>,
    pub error: Option<String>,
    pub rejected: bool,
    /// 2: confirmed applicability with a published fix, 1: confirmed applicability, 0: unknown.
    #[serde(default)]
    pub priority: u8,
}
/// Upper bound of remembered CVE severity records.
const CVSS_CAP: i64 = 20000;
/// Bytes reserved before each CVE record request; reconciled to the received size afterwards.
const CVSS_RESERVE: u64 = 64 * 1024;
/// Daily CVE record traffic in the steady state and while a large backlog is drained.
const CVSS_DAILY: u64 = 32 * 1024 * 1024;
const CVSS_BACKLOG_DAILY: u64 = 192 * 1024 * 1024;
/// Never-checked records above which the backlog budget and batch size apply.
const CVSS_BACKLOG: i64 = 64;
const CVSS_BATCH: i64 = 16;
const CVSS_BACKLOG_BATCH: i64 = 128;
const CVSS_PARALLEL: usize = 4;
const CATALOG_METADATA_CAP: i64 = 20000;
// Catalog enrichment leaves most of the steady-state budget for verdicts.
const CATALOG_METADATA_BUDGET: u64 = 8 * 1024 * 1024;
/// Rechecks happen before the 24 h freshness of a score expires.
const CVSS_RECHECK: i64 = 72000;
/// maintenance rows: CVE service pause deadline and the last time the record cap rejected a CVE.
const CVSS_PAUSE_ID: i64 = 3;
const CVSS_OVERFLOW_ID: i64 = 4;
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssQueue {
    pub total: i64,
    pub waiting: i64,
    pub unavailable: i64,
    pub paused_until: Option<i64>,
    pub budget_exhausted: bool,
    pub eta_seconds: Option<i64>,
    pub overflow: bool,
}
/// Severity class as seen by matching; a change requires re-evaluating servers.
fn cvss_class(c: Option<&Cvss>) -> &'static str {
    match c {
        None => "pending",
        Some(c) if c.rejected => "rejected",
        Some(c) if c.error.is_some() || !c.checked_at.is_some_and(|t| now() - t <= 86400) => {
            "pending"
        }
        Some(c) => match c.score {
            None => "unscored",
            Some(s) if s >= 9.0 => "critical",
            Some(_) => "below",
        },
    }
}
pub fn cvss_record(cve: &str, v: &Value, at: i64) -> Result<Cvss> {
    if v["cveMetadata"]["cveId"] != cve {
        return Err("CVE ID doesn’t match".into());
    }
    let rejected = v["cveMetadata"]["state"] == "REJECTED";
    let mut chosen = None;
    for version in ["4.0", "3.1", "3.0"] {
        let key = match version {
            "4.0" => "cvssV4_0",
            "3.1" => "cvssV3_1",
            _ => "cvssV3_0",
        };
        let scores = v["containers"]["cna"]["metrics"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|m| {
                let score = m[key]["baseScore"].as_f64()?;
                let vector = m[key]["vectorString"].as_str()?;
                if score.is_finite()
                    && (0.0..=10.0).contains(&score)
                    && m[key]["version"] == version
                    && vector.starts_with(&format!("CVSS:{version}/"))
                {
                    Some(score)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if let Some(score) = scores.into_iter().reduce(f64::max) {
            chosen = Some((score, version.to_owned()));
            break;
        }
    }
    Ok(Cvss {
        created_at: at,
        cve: cve.into(),
        score: chosen.as_ref().map(|p| p.0),
        version: chosen.map(|p| p.1),
        checked_at: Some(at),
        next_check: at + CVSS_RECHECK,
        etag: None,
        error: None,
        rejected,
        priority: 0,
    })
}
pub fn required(meta: &Metadata) -> Vec<String> {
    match meta.distro.as_str() {
        "ubuntu" => vec![
            "ubuntu-releases".into(),
            format!("ubuntu-cve:{}", meta.release),
            format!("ubuntu-usn:{}", meta.release),
        ],
        "debian" => vec!["debian-releases".into(), "debian".into()],
        _ => vec![],
    }
}
fn primary_source(meta: &Metadata) -> Option<String> {
    match meta.distro.as_str() {
        "debian" => Some("debian".into()),
        "ubuntu" => Some(format!("ubuntu-cve:{}", meta.release)),
        _ => None,
    }
}
impl Store {
    pub(crate) fn advisory_sources(&self) -> Result<Vec<Source>> {
        let db = self.0.lock().map_err(err)?;
        Self::list(&db, "advisory_sources")
    }
    pub(crate) fn ensure_sources(&self, meta: &Metadata) -> Result<()> {
        let db = self.0.lock().map_err(err)?;
        for id in required(meta) {
            let source = Source::new(&id)?;
            db.execute(
                "INSERT OR IGNORE INTO advisory_sources VALUES(?1,?2)",
                params![id, serde_json::to_string(&source).map_err(err)?],
            )
            .map_err(err)?;
        }
        Ok(())
    }
    pub(crate) fn package_scope_source(
        &self,
        state: &crate::packages::State,
    ) -> Result<Option<String>> {
        let (Some(root), Some(source)) = (
            &state.root,
            state.metadata.as_ref().and_then(primary_source),
        ) else {
            return Ok(None);
        };
        let db = self.0.lock().map_err(err)?;
        let due = db.query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM json_each(payload,'$.roots') WHERE value=?2)
                    AND (json_extract(payload,'$.error') IS NULL OR json_extract(payload,'$.nextCheck')<=?3)
             FROM advisory_sources WHERE id=?1",
            params![source, root, now()],
            |r| r.get::<_, bool>(0),
        ).optional().map_err(err)?.unwrap_or(true);
        Ok(due.then_some(source))
    }
    fn save_source(&self, s: &Source, changed: bool) -> Result<()> {
        let mut db = self.0.lock().map_err(err)?;
        crate::storage::admit(&db)?;
        let tx = db.transaction().map_err(err)?;
        let distro = if s.kind.starts_with("ubuntu") {
            "ubuntu"
        } else {
            "debian"
        };
        tx.execute("INSERT INTO advisory_sources VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",params![s.id,serde_json::to_string(s).map_err(err)?]).map_err(err)?;
        // A package snapshot can commit after the index has chosen its filter.
        if s.error.is_none() && s.file.is_some() && !s.kind.ends_with("releases") {
            tx.execute(
                "UPDATE advisory_sources SET payload=json_set(payload,'$.nextCheck',0) WHERE id=?1 AND EXISTS(
                    SELECT 1 FROM package_state p WHERE json_extract(p.payload,'$.metadata.distro')=?2
                    AND (?3='' OR json_extract(p.payload,'$.metadata.release')=?3)
                    AND json_extract(p.payload,'$.root') IS NOT NULL
                    AND NOT EXISTS(SELECT 1 FROM json_each(advisory_sources.payload,'$.roots') WHERE value=json_extract(p.payload,'$.root'))
                )",
                params![s.id, distro, s.release],
            ).map_err(err)?;
        }
        if changed || s.checked_at.is_some() {
            tx.execute("INSERT OR IGNORE INTO vulnerability_pending SELECT server_id FROM package_state WHERE json_extract(payload,'$.metadata.distro')=?1 AND (?2='' OR json_extract(payload,'$.metadata.release')=?2)",params![distro,s.release]).map_err(err)?;
        }
        if !s.fresh() {
            tx.execute("UPDATE incidents SET payload=json_set(payload,'$.autoEligible',json('false'),'$.freshUntil',?1) WHERE json_extract(payload,'$.check') LIKE 'vuln:%' AND server_id IN (SELECT server_id FROM package_state WHERE json_extract(payload,'$.metadata.distro')=?2)",params![now()-1,distro]).map_err(err)?;
        }
        tx.commit().map_err(err)
    }
    pub(crate) fn cvss(&self, cve: &str) -> Result<Option<Cvss>> {
        let db = self.0.lock().map_err(err)?;
        let raw: Option<String> = db
            .query_row(
                "SELECT payload FROM advisory_cvss WHERE cve=?1",
                [cve],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        raw.map(|s| serde_json::from_str(&s).map_err(err))
            .transpose()
    }
    pub(crate) fn request_cvss(&self, cve: &str, priority: u8) -> Result<()> {
        if !valid_cve(cve) {
            return Ok(());
        }
        let db = self.0.lock().map_err(err)?;
        let known: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM advisory_cvss WHERE cve=?1)",
                [cve],
                |r| r.get(0),
            )
            .map_err(err)?;
        if known {
            db.execute("UPDATE advisory_cvss SET payload=json_set(payload,'$.priority',?2) WHERE cve=?1 AND coalesce(json_extract(payload,'$.priority'),0)<?2",params![cve,priority]).map_err(err)?;
            return Ok(());
        }
        let count: i64 = db
            .query_row("SELECT count(*) FROM advisory_cvss", [], |r| r.get(0))
            .map_err(err)?;
        if count >= CVSS_CAP {
            db.execute("INSERT INTO maintenance VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET at=excluded.at",params![CVSS_OVERFLOW_ID,now()]).map_err(err)?;
            return Ok(());
        }
        let s = Cvss {
            created_at: now(),
            cve: cve.into(),
            score: None,
            version: None,
            checked_at: None,
            next_check: 0,
            etag: None,
            error: None,
            rejected: false,
            priority,
        };
        db.execute(
            "INSERT OR IGNORE INTO advisory_cvss VALUES(?1,?2)",
            params![cve, serde_json::to_string(&s).map_err(err)?],
        )
        .map_err(err)?;
        Ok(())
    }
    /// Reserves traffic for one CVE record request within the daily budget.
    fn reserve_cvss(&self, budget: u64) -> Result<Option<i64>> {
        let db = self.0.lock().map_err(err)?;
        let day = now() / 86400;
        let used: u64 = db
            .query_row(
                "SELECT coalesce(sum(bytes),0) FROM advisory_network WHERE day=?1",
                [day],
                |r| r.get(0),
            )
            .map_err(err)?;
        if used + CVSS_RESERVE > budget {
            return Ok(None);
        }
        db.execute("INSERT INTO advisory_network VALUES(?1,?2) ON CONFLICT(day) DO UPDATE SET bytes=bytes+excluded.bytes",params![day,CVSS_RESERVE]).map_err(err)?;
        Ok(Some(day))
    }

    fn catalog_metadata_slot(&self, cve: &str) -> Result<bool> {
        let db = self.0.lock().map_err(err)?;
        db.query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM advisory_cve_metadata WHERE cve=?1)
                    AND (SELECT count(*) FROM advisory_cve_metadata)<?2",
            params![cve, CATALOG_METADATA_CAP],
            |row| row.get(0),
        )
        .map_err(err)
    }

    fn save_catalog_metadata(&self, cve: &str, record: Option<&Value>, delay: i64) -> Result<()> {
        let at = now();
        let db = self.0.lock().map_err(err)?;
        crate::storage::admit(&db)?;
        let (title, published_on) = if let Some(record) = record {
            let title = record["containers"]["cna"]["title"]
                .as_str()
                .map(|title| title.split_whitespace().collect::<Vec<_>>().join(" "))
                .filter(|title| !title.is_empty())
                .map(|title| title.chars().take(160).collect::<String>());
            let published_on = record["cveMetadata"]["datePublished"]
                .as_str()
                .filter(|value| value.as_bytes().get(10) == Some(&b'T'))
                .map(|value| {
                    db.query_row("SELECT date(?1)", [value], |row| {
                        row.get::<_, Option<String>>(0)
                    })
                })
                .transpose()
                .map_err(err)?
                .flatten();
            (title, published_on)
        } else {
            (None, None)
        };
        db.execute(
            "INSERT INTO advisory_cve_metadata(cve,title,published_on,checked_at,next_check)
             SELECT ?1,?2,?3,?4,?5
             WHERE EXISTS(SELECT 1 FROM advisory_cve_metadata WHERE cve=?1)
                OR (SELECT count(*) FROM advisory_cve_metadata)<?6
             ON CONFLICT(cve) DO UPDATE SET
                title=CASE WHEN ?7 THEN excluded.title ELSE title END,
                published_on=CASE WHEN ?7 THEN excluded.published_on ELSE published_on END,
                checked_at=excluded.checked_at,next_check=excluded.next_check",
            params![
                cve,
                title,
                published_on,
                at,
                at + delay,
                CATALOG_METADATA_CAP,
                record.is_some()
            ],
        )
        .map_err(err)?;
        Ok(())
    }
    fn pause_cvss(&self, until: i64) -> Result<()> {
        let db = self.0.lock().map_err(err)?;
        db.execute("INSERT INTO maintenance VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET at=max(at,excluded.at)",params![CVSS_PAUSE_ID,until]).map_err(err)?;
        Ok(())
    }
    /// One generation bump per batch: matching started before it is superseded and re-queued.
    fn cvss_changed(&self) -> Result<()> {
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        tx.execute(
            "INSERT INTO maintenance VALUES(2,1) ON CONFLICT(id) DO UPDATE SET at=at+1",
            [],
        )
        .map_err(err)?;
        tx.execute("INSERT OR IGNORE INTO vulnerability_pending SELECT server_id FROM package_state WHERE json_extract(payload,'$.metadata.distro')='debian'",[]).map_err(err)?;
        tx.commit().map_err(err)
    }
    /// Due CVE records in download order with the applicable daily budget; None while paused.
    fn cvss_due(&self) -> Result<Option<(Vec<Cvss>, u64)>> {
        let db = self.0.lock().map_err(err)?;
        let paused: i64 = db
            .query_row(
                "SELECT at FROM maintenance WHERE id=?1",
                [CVSS_PAUSE_ID],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?
            .unwrap_or(0);
        if paused > now() {
            return Ok(None);
        }
        let waiting: i64 = db
            .query_row("SELECT count(*) FROM advisory_cvss WHERE json_extract(payload,'$.checkedAt') IS NULL AND json_extract(payload,'$.error') IS NULL",[],|r| r.get(0))
            .map_err(err)?;
        let (limit, budget) = if waiting > CVSS_BACKLOG {
            (CVSS_BACKLOG_BATCH, CVSS_BACKLOG_DAILY)
        } else {
            (CVSS_BATCH, CVSS_DAILY)
        };
        // Rechecks of open findings keep current verdicts fresh; then never-checked records by priority.
        let mut q=db.prepare("SELECT payload FROM advisory_cvss WHERE coalesce(json_extract(payload,'$.nextCheck'),0)<=?1 ORDER BY CASE WHEN json_extract(payload,'$.checkedAt') IS NOT NULL AND cve IN (SELECT cve FROM vulnerability_findings WHERE resolved_at IS NULL) THEN 0 WHEN json_extract(payload,'$.checkedAt') IS NULL THEN 1 ELSE 2 END,coalesce(json_extract(payload,'$.priority'),0) DESC,json_extract(payload,'$.nextCheck') LIMIT ?2").map_err(err)?;
        let rows = q
            .query_map(params![now(), limit], |r| r.get::<_, String>(0))
            .map_err(err)?;
        let c = rows
            .map(|r| serde_json::from_str::<Cvss>(&r.map_err(err)?).map_err(err))
            .collect::<Result<Vec<_>>>()?;
        Ok(Some((c, budget)))
    }
    pub(crate) fn cvss_queue(&self) -> Result<CvssQueue> {
        let db = self.0.lock().map_err(err)?;
        let (total, waiting, unavailable): (i64, i64, i64) = db
            .query_row("SELECT count(*),coalesce(sum(json_extract(payload,'$.checkedAt') IS NULL AND json_extract(payload,'$.error') IS NULL),0),coalesce(sum(json_extract(payload,'$.error') IS NOT NULL),0) FROM advisory_cvss",[],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))
            .map_err(err)?;
        let marker = |id: i64| -> Result<i64> {
            db.query_row("SELECT at FROM maintenance WHERE id=?1", [id], |r| r.get(0))
                .optional()
                .map_err(err)
                .map(|v| v.unwrap_or(0))
        };
        let paused = marker(CVSS_PAUSE_ID)?;
        let overflow = marker(CVSS_OVERFLOW_ID)?;
        let used: u64 = db
            .query_row(
                "SELECT coalesce(sum(bytes),0) FROM advisory_network WHERE day=?1",
                [now() / 86400],
                |r| r.get(0),
            )
            .map_err(err)?;
        let budget = if waiting > CVSS_BACKLOG {
            CVSS_BACKLOG_DAILY
        } else {
            CVSS_DAILY
        };
        let budget_exhausted = used + CVSS_RESERVE > budget;
        let paused_until = (paused > now()).then_some(paused);
        let batch = if waiting > CVSS_BACKLOG {
            CVSS_BACKLOG_BATCH
        } else {
            CVSS_BATCH
        };
        Ok(CvssQueue {
            total,
            waiting,
            unavailable,
            paused_until,
            budget_exhausted,
            eta_seconds: (waiting > 0 && !budget_exhausted && paused_until.is_none())
                .then(|| (waiting + batch - 1) / batch * 60),
            overflow: now() - overflow <= 86400,
        })
    }
    /// Saves a record and reports whether its severity class changed for matching.
    fn save_cvss(&self, c: &Cvss, bytes: u64) -> Result<bool> {
        let mut db = self.0.lock().map_err(err)?;
        crate::storage::admit(&db)?;
        let tx = db.transaction().map_err(err)?;
        let old: Option<String> = tx
            .query_row(
                "SELECT payload FROM advisory_cvss WHERE cve=?1",
                [&c.cve],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        let old: Option<Cvss> = old
            .map(|s| serde_json::from_str(&s).map_err(err))
            .transpose()?;
        if c.score.is_some_and(|v| v >= 9.0)
            && old
                .as_ref()
                .is_some_and(|o| o.rejected || o.score.is_some_and(|s| s < 9.0))
        {
            tx.execute("UPDATE advisory_sources SET payload=json_set(payload,'$.nextCheck',0,'$.error','Criticality class has changed; applicability needs to be updated') WHERE id='debian'",[]).map_err(err)?;
        }
        let changed = cvss_class(old.as_ref()) != cvss_class(Some(c));
        tx.execute("INSERT INTO advisory_cvss VALUES(?1,?2) ON CONFLICT(cve) DO UPDATE SET payload=excluded.payload",params![c.cve,serde_json::to_string(c).map_err(err)?]).map_err(err)?;
        // Rechecks extend the freshness of verdicts that already rely on this CVE.
        tx.execute("INSERT OR IGNORE INTO vulnerability_pending SELECT DISTINCT server_id FROM vulnerability_findings WHERE cve=?1",[&c.cve]).map_err(err)?;
        tx.execute("INSERT INTO advisory_network VALUES(?1,?2) ON CONFLICT(day) DO UPDATE SET bytes=bytes+excluded.bytes",params![now()/86400,bytes]).map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(changed)
    }
}
fn cache_bytes(root: &Path) -> Result<u64> {
    let mut bytes = 0;
    for e in std::fs::read_dir(root).map_err(err)? {
        let m = e.map_err(err)?.metadata().map_err(err)?;
        if m.is_file() {
            bytes += m.len();
        }
    }
    Ok(bytes)
}
pub fn file(root: &Path, s: &Source) -> Result<PathBuf> {
    let name = s
        .file
        .as_ref()
        .ok_or("Advisories have not been downloaded yet")?;
    if name.contains('/') || name.contains('\\') || name.starts_with('.') || name.len() > 160 {
        return Err("Invalid advisory file".into());
    }
    Ok(root.join(name))
}
fn cache_admit(root: &Path, extra: u64) -> Result<()> {
    if cache_bytes(root)? + extra > 128 * 1024 * 1024 {
        Err("The advisory cache reached its 128 MiB limit".into())
    } else {
        Ok(())
    }
}
fn reader(path: &Path) -> Result<Box<dyn std::io::BufRead>> {
    let mut probe = std::fs::File::open(path).map_err(err)?;
    let mut magic = [0; 3];
    let _ = probe.read(&mut magic).map_err(err)?;
    let file = std::fs::File::open(path).map_err(err)?;
    let input: Box<dyn Read> = if magic[..2] == [31, 139] {
        Box::new(flate2::read::GzDecoder::new(file))
    } else if magic == *b"BZh" {
        Box::new(bzip2::read::BzDecoder::new(file))
    } else {
        Box::new(file)
    };
    Ok(Box::new(BufReader::new(input.take(512 * 1024 * 1024 + 1))))
}
#[derive(Default, Serialize)]
struct Filter {
    packages: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    binaries: BTreeSet<String>,
    roots: BTreeSet<String>,
    cvss: BTreeMap<String, Option<f64>>,
}
fn installed_filter(store: &Store, source: &Source) -> Result<Filter> {
    if source.kind.ends_with("releases") {
        return Ok(Filter::default());
    }
    let states = {
        let db = store.0.lock().map_err(err)?;
        let mut q = db
            .prepare("SELECT server_id,payload FROM package_state")
            .map_err(err)?;
        let rows = q
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err)?
    };
    let mut filter = Filter::default();
    let distro = if source.kind.starts_with("ubuntu") {
        "ubuntu"
    } else {
        "debian"
    };
    let matches_source = |meta: &Metadata| {
        meta.distro == distro && (source.release.is_empty() || meta.release == source.release)
    };
    for (id, raw) in states {
        let state: crate::packages::State = serde_json::from_str(&raw).map_err(err)?;
        if !state.metadata.as_ref().is_some_and(matches_source) {
            continue;
        }
        let (state, rows) = store.package_snapshot(&id)?;
        let Some(meta) = state.metadata.as_ref().filter(|meta| matches_source(meta)) else {
            continue;
        };
        if let Some(root) = state.root {
            filter.roots.insert(root);
        }
        for p in rows {
            filter.binaries.insert(p.name);
            filter
                .packages
                .entry(p.source)
                .or_default()
                .entry(meta.release.clone())
                .or_default()
                .insert(p.source_version);
        }
        if serde_json::to_vec(&filter).map_err(err)?.len() > 8 * 1024 * 1024 {
            return Err("Advisory processing limits exceeded".into());
        }
    }
    if source.kind == "debian" {
        let db = store.0.lock().map_err(err)?;
        for c in Store::list::<Cvss>(&db, "advisory_cvss")? {
            if c.error.is_none() && c.checked_at.is_some_and(|at| now() - at <= 86400) {
                filter
                    .cvss
                    .insert(c.cve, if c.rejected { Some(0.0) } else { c.score });
            }
        }
    }
    Ok(filter)
}
#[cfg(test)]
fn prepare_debian(path: &Path, out: &Path) -> Result<()> {
    let filter = Filter {
        packages: BTreeMap::from([(
            "openssl".into(),
            BTreeMap::from([("bookworm".into(), BTreeSet::from(["0".into()]))]),
        )]),
        ..Filter::default()
    };
    prepare_debian_scoped(path, out, &filter)
}
fn prepare_debian_scoped(path: &Path, out: &Path, filter: &Filter) -> Result<()> {
    let db = Connection::open(out).map_err(err)?;
    db.execute_batch("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA max_page_count=8192; CREATE TABLE packages(source TEXT PRIMARY KEY);CREATE TABLE advisories(source TEXT,cve TEXT,release TEXT,status TEXT,fixed TEXT,urgency TEXT,nodsa TEXT,description TEXT,PRIMARY KEY(source,cve,release));").map_err(err)?;
    struct Top<'a>(&'a Connection, &'a Filter);
    struct PackageSeed<'a> {
        db: &'a Connection,
        source: String,
        filter: &'a Filter,
    }
    impl<'de> DeserializeSeed<'de> for Top<'_> {
        type Value = ();
        fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> std::result::Result<(), D::Error> {
            d.deserialize_map(self)
        }
    }
    impl<'de> Visitor<'de> for Top<'_> {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("Debian source package map")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
            let mut count = 0;
            while let Some(source) = map.next_key::<String>()? {
                count += 1;
                if count > 100000 || source.len() > 200 {
                    return Err(de::Error::custom("Feed package limit"));
                }
                if !self.1.packages.contains_key(&source) {
                    map.next_value::<de::IgnoredAny>()?;
                    continue;
                }
                self.0
                    .execute("INSERT INTO packages VALUES(?1)", [&source])
                    .map_err(de::Error::custom)?;
                map.next_value_seed(PackageSeed {
                    db: self.0,
                    source,
                    filter: self.1,
                })?;
            }
            Ok(())
        }
    }
    impl<'de> DeserializeSeed<'de> for PackageSeed<'_> {
        type Value = ();
        fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> std::result::Result<(), D::Error> {
            d.deserialize_map(self)
        }
    }
    impl<'de> Visitor<'de> for PackageSeed<'_> {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("Debian CVE map")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
            let mut count = 0;
            while let Some((cve, value)) = map.next_entry::<String, Value>()? {
                count += 1;
                if count > 100000 {
                    return Err(de::Error::custom("CVE package limit"));
                }
                if !valid_cve(&cve)
                    || self
                        .filter
                        .cvss
                        .get(&cve)
                        .is_some_and(|s| s.is_some_and(|v| v < 9.0))
                {
                    continue;
                }
                let description = value["description"]
                    .as_str()
                    .unwrap_or("")
                    .chars()
                    .take(512)
                    .collect::<String>();
                if let Some(releases) = value["releases"].as_object() {
                    if releases.len() > 64 {
                        return Err(de::Error::custom("Limit of releases"));
                    }
                    for (release, v) in releases {
                        let Some(versions) = self
                            .filter
                            .packages
                            .get(&self.source)
                            .and_then(|r| r.get(release))
                        else {
                            continue;
                        };
                        let status = v["status"].as_str().unwrap_or("undetermined");
                        let fixed = v["fixed_version"].as_str();
                        let urgency = v["urgency"].as_str().unwrap_or("unknown");
                        let nodsa = v["nodsa_reason"].as_str().unwrap_or("");
                        if fixed == Some("0") || urgency == "unimportant" {
                            continue;
                        }
                        if fixed.is_some_and(|f| {
                            versions
                                .iter()
                                .all(|v| debversion::compare(v, f).is_some_and(|o| !o.is_lt()))
                        }) {
                            continue;
                        }
                        if release.len() > 64 || fixed.is_some_and(|s| s.len() > 256) {
                            return Err(de::Error::custom("Inadmissible feed fields"));
                        }
                        self.db
                            .execute(
                                "INSERT INTO advisories VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                                params![
                                    self.source,
                                    cve,
                                    release,
                                    status,
                                    fixed,
                                    urgency,
                                    nodsa,
                                    description
                                ],
                            )
                            .map_err(de::Error::custom)?;
                    }
                }
            }
            Ok(())
        }
    }
    let mut deserializer = serde_json::Deserializer::from_reader(reader(path)?);
    Top(&db, filter)
        .deserialize(&mut deserializer)
        .map_err(err)?;
    deserializer.end().map_err(err)?;
    let count: i64 = db
        .query_row("SELECT count(*) FROM packages", [], |r| r.get(0))
        .map_err(err)?;
    let _ = count; // A valid feed may have no relevant critical candidates.
    Ok(())
}
fn civil_days(date: &str) -> Option<i64> {
    let p = date
        .split('-')
        .map(str::parse::<i64>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .ok()?;
    if p.len() != 3 || !(1..=12).contains(&p[1]) || !(1..=31).contains(&p[2]) {
        return None;
    }
    let mut y = p[0];
    let m = p[1];
    y -= i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + p[2] - 1;
    Some(era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468)
}
pub fn release_support(csv: &str, meta: &Metadata) -> Option<&'static str> {
    let mut lines = csv.lines();
    let headers = lines.next()?.split(',').collect::<Vec<_>>();
    let series = headers.iter().position(|s| *s == "series")?;
    for line in lines {
        let row = line.split(',').collect::<Vec<_>>();
        if row.get(series).copied() != Some(meta.release.as_str()) {
            continue;
        }
        let get = |name: &str| {
            headers
                .iter()
                .position(|s| *s == name)
                .and_then(|i| row.get(i))
                .and_then(|s| civil_days(s))
        };
        let day = now() / 86400;
        if get("release").is_none_or(|d| d > day) {
            return Some("development_release");
        }
        if get("eol").is_some_and(|d| d >= day)
            || meta.distro == "debian" && get("eol-lts").is_some_and(|d| d >= day)
        {
            return Some("supported");
        }
        if meta.distro == "ubuntu" && get("eol-esm").is_some_and(|d| d >= day) {
            return Some("esm_entitlement_unknown");
        }
        return Some("unsupported_release");
    }
    None
}
fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(120))
        .user_agent("Cyberbot/0.1 advisory-cache")
        .build()
        .map_err(err)
}
async fn update_source(app: &Arc<AppState>, source: &mut Source) -> Result<()> {
    let mut _activity_span = crate::activity::begin("app", "update_source", None);
    let _activity_result = (async {
        let filter = installed_filter(&app.store, source)?;
        let filter_hash = crate::packages::digest(&filter);
        let same_scope = source.scope == filter_hash;
        let root = app.root.join("advisories");
        std::fs::create_dir_all(&root).map_err(err)?;
        cache_admit(&root, 1048576)?;
        let mut request = client()?.get(source.url()?);
        if same_scope
            && source
                .file
                .as_ref()
                .is_some_and(|_| file(&root, source).is_ok_and(|p| p.exists()))
        {
            if let Some(etag) = &source.etag {
                request = request.header(reqwest::header::IF_NONE_MATCH, etag);
            } else if let Some(modified) = &source.modified {
                request = request.header(reqwest::header::IF_MODIFIED_SINCE, modified);
            }
        }
        if source.kind == "debian" {
            request = request.header(reqwest::header::ACCEPT_ENCODING, "gzip");
        }
        let mut response = request.send().await.map_err(|_| "Advisories unavailable")?;
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            if !file(&root, source).is_ok_and(|p| p.exists()) {
                return Err("The advisory server returned 304, but no cached copy exists".into());
            }
            source.checked_at = Some(now());
            source.error = None;
            source.next_check = now() + 21600;
            app.store.save_source(source, false)?;
            return Ok(());
        }
        if !response.status().is_success() {
            return Err(format!(
                "The advisory service returned HTTP {}",
                response.status().as_u16()
            ));
        }
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let modified = response
            .headers()
            .get(reqwest::header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let temp = root.join(format!("{}.part", uuid::Uuid::new_v4()));
        let index = root.join(format!("{}.building", uuid::Uuid::new_v4()));
        let result = async {
            let mut output = std::fs::File::create(&temp).map_err(err)?;
            let mut bytes = 0u64;
            let mut sha = Sha256::new();
            let cap = if source.kind.ends_with("releases") {
                524288
            } else {
                128 * 1024 * 1024
            };
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| "Advisory download interrupted")?
            {
                if app.stop.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err("Update cancelled".into());
                }
                bytes += chunk.len() as u64;
                if bytes > cap {
                    return Err("Feed size limit".into());
                }
                cache_admit(&root, chunk.len() as u64)?;
                std::io::Write::write_all(&mut output, &chunk).map_err(err)?;
                sha.update(&chunk);
            }
            drop(output);
            let hash = format!("{:x}", sha.finalize());
            if same_scope
                && source.hash.as_deref() == Some(&hash)
                && file(&root, source).is_ok_and(|p| p.exists())
            {
                source.checked_at = Some(now());
                source.next_check = now() + 21600;
                source.error = None;
                source.etag = etag;
                source.modified = modified;
                app.store.save_source(source, false)?;
                return Ok(());
            }
            let kind = source.kind.clone();
            let roots = filter.roots.clone();
            let tmp = temp.clone();
            let idx = index.clone();
            let parse_root = root.clone();
            // Old cache generations are expendable; the active generation remains until promotion.
            if cache_admit(&root, 32 * 1024 * 1024).is_err() {
                for mut old in app.store.advisory_sources()? {
                    if let Some(name) = old.previous.take() {
                        if !name.contains('/') && !name.contains('\\') {
                            let _ = std::fs::remove_file(root.join(&name));
                        }
                        app.store.save_source(&old, false)?;
                    }
                }
                source.previous = None;
            }
            cache_admit(&root, 32 * 1024 * 1024)?; // enough for the compiler's hard SQLite page ceiling
            tokio::task::spawn_blocking(move || {
                if kind == "debian" {
                    prepare_debian_scoped(&tmp, &idx, &filter)?;
                } else if kind.ends_with("releases") {
                    let text = std::fs::read_to_string(&tmp).map_err(err)?;
                    if !text.starts_with("version,codename,series,") {
                        return Err("Unknown advisory source".into());
                    }
                    std::fs::copy(&tmp, &idx).map_err(err)?;
                } else {
                    oval::prepare_scoped(reader(&tmp)?, &idx, Some(&filter.binaries))?;
                }
                cache_admit(&parse_root, 0)
            })
            .await
            .map_err(err)??;
            let filename = format!(
                "{}-{}-{}.{}",
                source.id.replace(':', "-"),
                &hash[..16],
                &filter_hash[..16],
                if source.kind.ends_with("releases") {
                    "csv"
                } else {
                    "sqlite"
                }
            );
            let final_path = root.join(&filename);
            if final_path.exists() {
                std::fs::remove_file(&index).map_err(err)?;
            } else {
                std::fs::rename(&index, &final_path).map_err(err)?;
            }
            let changed = source.hash.as_deref() != Some(&hash) || !same_scope;
            source.scope = filter_hash;
            source.roots = roots;
            if changed {
                source.previous = source.file.take();
            }
            source.file = Some(filename);
            source.hash = Some(hash);
            source.bytes = bytes;
            source.etag = etag;
            source.modified = modified;
            source.checked_at = Some(now());
            source.next_check = now() + 21600;
            source.error = None;
            app.store.save_source(source, changed)?;
            Ok(())
        }
        .await;
        let _ = std::fs::remove_file(temp);
        let _ = std::fs::remove_file(index);
        result
    })
    .await;
    _activity_span.result(&_activity_result);
    if _activity_result.is_ok() {
        app.package_refresh.wake.notify_one();
    }
    _activity_result
}
/// Result of one CVE record request.
enum CvssStep {
    /// The record was saved; `true` when its severity class changed.
    Saved(bool),
    /// The service refused or was unreachable: pause the whole queue for this many seconds.
    Pause(i64),
}
fn retry_after(r: &reqwest::Response, default: i64) -> i64 {
    r.headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(default)
        .clamp(60, 21600)
}
enum CveDownload {
    Record(Value, Option<String>),
    NotModified,
    Pause(i64),
}

async fn download_cve(
    store: &Store,
    cve: &str,
    etag: Option<&str>,
    charged_day: i64,
    metadata_only: bool,
) -> std::result::Result<CveDownload, (String, i64)> {
    let mut received = 0u64;
    let result = async {
        let url = cve_record_url(cve).ok_or_else(|| ("Invalid CVE ID".into(), 21600))?;
        let mut request = client().map_err(|error| (error, 3600))?.get(url);
        if metadata_only {
            request = request.timeout(std::time::Duration::from_secs(15));
        }
        if let Some(etag) = etag {
            request = request.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        let Ok(mut response) = request.send().await else {
            return Ok(CveDownload::Pause(300));
        };
        let status = response.status();
        if status == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(CveDownload::NotModified);
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS
            || status == reqwest::StatusCode::FORBIDDEN
        {
            return Ok(CveDownload::Pause(retry_after(&response, 900)));
        }
        if status.is_server_error() {
            return Ok(CveDownload::Pause(retry_after(&response, 300)));
        }
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(("The CVE record has not been published yet".into(), 21600));
        }
        if !status.is_success() {
            return Err((
                format!("The CVE service returned HTTP {}", status.as_u16()),
                21600,
            ));
        }
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut bytes = Vec::new();
        loop {
            let Ok(chunk) = response.chunk().await else {
                return Ok(CveDownload::Pause(300));
            };
            let Some(chunk) = chunk else { break };
            received += chunk.len() as u64;
            if bytes.len() + chunk.len() > 1048576 {
                return Err(("CVE record size limit reached".into(), 86400));
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| ("Invalid CVE record".to_string(), 3600))?;
        if value["cveMetadata"]["cveId"] != cve {
            return Err(("CVE ID doesn’t match".into(), 3600));
        }
        Ok(CveDownload::Record(value, etag))
    }
    .await;
    let db = store.0.lock().map_err(|error| (err(error), 3600))?;
    db.execute(
        "UPDATE advisory_network SET bytes=max(0,bytes-?3+?2) WHERE day=?1",
        params![charged_day, received, CVSS_RESERVE],
    )
    .map_err(|error| (err(error), 3600))?;
    result
}

async fn update_cvss(app: Arc<AppState>, mut c: Cvss, day: i64) -> Result<CvssStep> {
    let mut span = crate::activity::begin("app", "update_cvss", None);
    let result = async {
        // Existing installations may already have an ETag but no catalog metadata.
        let etag = c
            .etag
            .as_deref()
            .filter(|_| !app.store.catalog_metadata_slot(&c.cve).unwrap_or(false));
        match download_cve(&app.store, &c.cve, etag, day, false).await {
            Ok(CveDownload::Pause(delay)) => return Ok(CvssStep::Pause(delay)),
            Ok(CveDownload::NotModified) => {
                c.checked_at = Some(now());
                c.next_check = now() + CVSS_RECHECK;
                c.error = None;
            }
            Ok(CveDownload::Record(value, etag)) => {
                let mut updated = cvss_record(&c.cve, &value, now())?;
                updated.etag = etag;
                updated.created_at = c.created_at;
                updated.priority = c.priority;
                let changed = app.store.save_cvss(&updated, 0)?;
                // Display metadata is auxiliary to the applicability verdict.
                let _ = app
                    .store
                    .save_catalog_metadata(&updated.cve, Some(&value), 30 * 86400);
                return Ok(CvssStep::Saved(changed));
            }
            Err((message, delay)) => {
                c.next_check = now() + delay;
                c.error = Some(message);
            }
        }
        app.store.save_cvss(&c, 0).map(CvssStep::Saved)
    }
    .await;
    span.result(&result);
    result
}

async fn refresh_catalog_metadata(app: &Arc<AppState>) -> Result<()> {
    // A verdict backlog, shared backoff or shutdown takes precedence over enrichment.
    let Some((pending, _)) = app.store.cvss_due()? else {
        return Ok(());
    };
    if !pending.is_empty() || app.stop.load(std::sync::atomic::Ordering::Relaxed) {
        return Ok(());
    }
    let slots = {
        let db = app.store.0.lock().map_err(err)?;
        let count: i64 = db
            .query_row("SELECT count(*) FROM advisory_cve_metadata", [], |r| {
                r.get(0)
            })
            .map_err(err)?;
        (CATALOG_METADATA_CAP - count).clamp(0, CVSS_PARALLEL as i64) as usize
    };
    if slots == 0 {
        return Ok(());
    }
    let state = app.clone();
    let candidates = tokio::task::spawn_blocking(move || {
        crate::vulnerability_catalog::metadata_candidates(
            &state.store,
            &state.root.join("advisories"),
            slots,
        )
    })
    .await
    .map_err(err)??;

    let mut jobs = tokio::task::JoinSet::new();
    for cve in candidates {
        let Some(day) = app.store.reserve_cvss(CATALOG_METADATA_BUDGET)? else {
            break;
        };
        let state = app.clone();
        jobs.spawn(async move {
            let result = match download_cve(&state.store, &cve, None, day, true).await {
                Ok(CveDownload::Pause(delay)) => state.store.pause_cvss(now() + delay),
                Ok(CveDownload::Record(record, _)) => {
                    state
                        .store
                        .save_catalog_metadata(&cve, Some(&record), 30 * 86400)
                }
                Ok(CveDownload::NotModified) => {
                    state.store.save_catalog_metadata(&cve, None, 86400)
                }
                Err((_, delay)) => state.store.save_catalog_metadata(&cve, None, delay),
            };
            result
        });
    }
    let mut outcome = Ok(());
    while let Some(job) = jobs.join_next().await {
        if let Err(error) = job.map_err(err).and_then(|result| result) {
            outcome = Err(error);
        }
    }
    outcome
}

/// Downloads due CVE severity records: verdict-relevant ones first, in parallel within the daily budget.
async fn refresh_cvss(app: &Arc<AppState>) -> Result<()> {
    let Some((candidates, budget)) = app.store.cvss_due()? else {
        return Ok(());
    };
    let mut changed = false;
    let mut outcome = Ok(());
    'batch: for chunk in candidates.chunks(CVSS_PARALLEL) {
        if app.stop.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        let mut jobs = tokio::task::JoinSet::new();
        let mut exhausted = false;
        for c in chunk {
            let Some(day) = app.store.reserve_cvss(budget)? else {
                exhausted = true;
                break;
            };
            jobs.spawn(update_cvss(app.clone(), c.clone(), day));
        }
        let mut pause = 0;
        while let Some(job) = jobs.join_next().await {
            match job.map_err(err).and_then(|r| r) {
                Ok(CvssStep::Saved(c)) => changed |= c,
                Ok(CvssStep::Pause(s)) => pause = pause.max(s),
                Err(e) => outcome = Err(e),
            }
        }
        if pause > 0 {
            app.store.pause_cvss(now() + pause)?;
        }
        if exhausted || pause > 0 || outcome.is_err() {
            break 'batch;
        }
    }
    if changed {
        app.store.cvss_changed()?;
    }
    outcome
}
pub(crate) async fn refresh(app: Arc<AppState>, force: bool) -> Result<()> {
    refresh_prioritized(app, force, BTreeSet::new()).await
}

const REFRESH_BUSY: &str = "Vulnerability database is being updated";

pub(crate) async fn refresh_prioritized(
    app: Arc<AppState>,
    force: bool,
    priority: BTreeSet<String>,
) -> Result<()> {
    let result = crate::monitoring::run(
        &app.store,
        "advisories",
        "",
        "",
        refresh_inner(app.clone(), force, &priority),
    )
    .await;
    if result.as_ref().is_err_and(|error| error == REFRESH_BUSY) {
        app.package_refresh.defer_advisories(priority);
    }
    result
}
async fn refresh_inner(app: Arc<AppState>, force: bool, priority: &BTreeSet<String>) -> Result<()> {
    let _guard = if force {
        let guard = app.advisory_refresh.lock().await;
        crate::monitoring::check_commit(&*app.store.0.lock().map_err(err)?)?;
        guard
    } else {
        app.advisory_refresh.try_lock().map_err(|_| REFRESH_BUSY)?
    };
    let states = {
        let db = app.store.0.lock().map_err(err)?;
        Store::list::<crate::packages::State>(&db, "package_state")?
    };
    let mut needed = BTreeSet::new();
    for s in states {
        if let Some(m) = s.metadata {
            needed.extend(required(&m));
            app.store.ensure_sources(&m)?;
        }
    }
    {
        let db = app.store.0.lock().map_err(err)?;
        for source in app_source_ids(&db)? {
            if !needed.contains(&source) {
                db.execute("DELETE FROM advisory_sources WHERE id=?1", [source])
                    .map_err(err)?;
            }
        }
    }
    cleanup(&app)?;
    let mut sources = app.store.advisory_sources()?;
    sources.sort_by_key(|s| {
        (
            !priority.contains(&s.id),
            !s.kind.ends_with("releases"),
            s.next_check,
        )
    });
    let mut due = sources
        .into_iter()
        .filter(|s| force || s.next_check <= now());
    for mut source in due.by_ref().take(if force { 16 } else { 2 }) {
        if let Err(message) = update_source(&app, &mut source).await {
            source.error = Some(message);
            source.next_check = now() + 3600;
            app.store.save_source(&source, false)?;
        }
    }
    app.package_refresh
        .defer_advisories(due.filter(|s| priority.contains(&s.id)).map(|s| s.id));
    refresh_cvss(&app).await?;
    prune_classified(&app)?;
    cleanup(&app)?;
    refresh_catalog_metadata(&app).await
}
fn prune_classified(app: &AppState) -> Result<()> {
    let negatives = {
        let db = app.store.0.lock().map_err(err)?;
        Store::list::<Cvss>(&db, "advisory_cvss")?
            .into_iter()
            .filter(|c| {
                c.error.is_none()
                    && c.checked_at.is_some_and(|t| now() - t <= 86400)
                    && (c.rejected || c.score.is_some_and(|s| s < 9.0))
            })
            .map(|c| c.cve)
            .collect::<Vec<_>>()
    };
    if negatives.is_empty() {
        return Ok(());
    }
    let root = app.root.join("advisories");
    for source in app
        .store
        .advisory_sources()?
        .iter()
        .filter(|s| s.kind == "debian" && s.file.is_some())
    {
        let path = file(&root, source)?;
        if !path.exists() {
            continue;
        }
        cache_admit(&root, std::fs::metadata(&path).map_err(err)?.len())?;
        let mut db = Connection::open(&path).map_err(err)?;
        db.execute_batch("PRAGMA busy_timeout=1000;PRAGMA journal_mode=DELETE;")
            .map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        let mut deleted = 0;
        for id in &negatives {
            deleted += tx
                .execute("DELETE FROM advisories WHERE cve=?1", [id])
                .map_err(err)?;
        }
        tx.commit().map_err(err)?;
        if deleted > 0 {
            db.execute_batch("VACUUM;").map_err(err)?;
        }
    }
    Ok(())
}
pub(crate) fn cleanup(app: &AppState) -> Result<()> {
    let root = app.root.join("advisories");
    if !root.exists() {
        return Ok(());
    }
    let sources = app.store.advisory_sources()?;
    let keep: BTreeSet<String> = sources
        .iter()
        .flat_map(|s| [s.file.clone(), s.previous.clone()])
        .flatten()
        .collect();
    for e in std::fs::read_dir(&root).map_err(err)? {
        let e = e.map_err(err)?;
        let name = e.file_name().to_string_lossy().to_string();
        if !keep.contains(&name)
            && e.file_type().map_err(err)?.is_file()
            && e.metadata()
                .map_err(err)?
                .modified()
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|d| d.as_secs() > 3600)
        {
            let _ = std::fs::remove_file(e.path());
        }
    }
    let db = app.store.0.lock().map_err(err)?;
    db.execute(
        "DELETE FROM advisory_cve_metadata WHERE rowid IN (
           SELECT rowid FROM advisory_cve_metadata WHERE checked_at<?1 LIMIT 500
         )",
        [now() - 90 * 86400],
    )
    .map_err(err)?;
    db.execute("DELETE FROM advisory_cvss WHERE cve NOT IN (SELECT cve FROM vulnerability_findings WHERE resolved_at IS NULL) AND coalesce(json_extract(payload,'$.checkedAt'),json_extract(payload,'$.createdAt'),0)<?1",[now()-7*86400]).map_err(err)?;
    db.execute(
        "DELETE FROM advisory_network WHERE day<?1",
        [now() / 86400 - 7],
    )
    .map_err(err)?;
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Match {
    pub source: String,
    pub cve: String,
    pub state: String,
    pub severity: String,
    pub severity_source: String,
    pub packages: Vec<PackageEvidence>,
    pub description: String,
    pub url: String,
    pub reason: Option<String>,
    pub fix_published: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageEvidence {
    pub name: String,
    pub version: String,
    pub fixed_version: Option<String>,
}
pub struct Assessment {
    pub findings: Vec<Match>,
    pub coverage: Vec<String>,
    pub generations: BTreeMap<String, String>,
    pub fresh_until: i64,
}
fn severity(s: &str) -> String {
    match s.to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" | "moderate" => "medium",
        "low" | "negligible" => "low",
        _ => "unknown",
    }
    .into()
}
pub fn assess(
    store: &Store,
    root: &Path,
    meta: &Metadata,
    packages: &[Package],
    package_root: &str,
) -> Result<Assessment> {
    let sources = store.advisory_sources()?;
    let cvss_revision = {
        let db = store.0.lock().map_err(err)?;
        db.query_row("SELECT at FROM maintenance WHERE id=2", [], |r| {
            r.get::<_, u64>(0)
        })
        .optional()
        .map_err(err)?
        .unwrap_or(0)
    };
    let mut assessment = Assessment {
        findings: vec![],
        coverage: vec![],
        generations: BTreeMap::new(),
        fresh_until: now() + 86400,
    };
    assessment
        .generations
        .insert("cvss_revision".into(), cvss_revision.to_string());
    for id in required(meta) {
        assessment.generations.insert(
            id.clone(),
            sources
                .iter()
                .find(|s| s.id == id)
                .map(crate::packages::digest)
                .unwrap_or("missing".into()),
        );
    }
    if !["ubuntu", "debian"].contains(&meta.distro.as_str()) {
        assessment.coverage.push("unsupported_distribution".into());
        return Ok(assessment);
    }
    let primary = primary_source(meta).expect("supported distribution has an advisory source");
    let release_id = format!("{}-releases", meta.distro);
    for id in [&primary, &release_id] {
        let Some(source) = sources.iter().find(|s| &s.id == id && s.file.is_some()) else {
            assessment.coverage.push(format!("missing:{id}"));
            continue;
        };
        if !source.fresh() {
            assessment.coverage.push(format!("stale_or_failed:{id}"));
        }
        assessment.fresh_until = assessment
            .fresh_until
            .min(source.checked_at.unwrap_or(0) + 86400);
    }
    if let Some(s) = sources.iter().find(|s| s.id == release_id) {
        if let Ok(path) = file(root, s) {
            if let Ok(csv) = std::fs::read_to_string(path) {
                let support = release_support(&csv, meta).unwrap_or("unknown_release");
                if support != "supported" {
                    assessment.coverage.push(support.into());
                }
            }
        }
    }
    if packages.iter().any(|p| p.status != "installed") {
        assessment
            .coverage
            .push("incomplete_package_transaction".into());
    }
    let Some(source) = sources.iter().find(|s| s.id == primary && s.file.is_some()) else {
        return Ok(assessment);
    };
    if !source.roots.contains(package_root) {
        assessment.coverage.push("package_scope_pending".into());
        return Ok(assessment);
    }
    let db = Connection::open_with_flags(
        file(root, source)?,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(err)?;
    if meta.distro == "debian" {
        let mut groups: BTreeMap<&str, Vec<&Package>> = BTreeMap::new();
        for p in packages {
            groups.entry(&p.source).or_default().push(p);
        }
        let mut q=db.prepare("SELECT cve,status,fixed,urgency,nodsa,description FROM advisories WHERE source=?1 AND release=?2").map_err(err)?;
        for (name, installed) in groups {
            let known: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM packages WHERE source=?1)",
                    [name],
                    |r| r.get(0),
                )
                .map_err(err)?;
            if !known {
                assessment
                    .coverage
                    .push(format!("uncovered_package:{name}"));
                continue;
            }
            let rows = q
                .query_map(params![name, meta.release], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                    ))
                })
                .map_err(err)?;
            for row in rows {
                let (cve, status, fixed, urgency, nodsa, description) = row.map_err(err)?;
                if fixed.as_deref() == Some("0") || urgency == "unimportant" {
                    continue;
                }
                let mut relevant = vec![];
                let mut unknown =
                    status == "undetermined" || !matches!(status.as_str(), "open" | "resolved");
                for p in &installed {
                    let foreign = p.source_version.contains("~bpo")
                        || p.source_version.contains("ppa")
                        || p.source_version.contains("custom");
                    let affected = if foreign || p.status != "installed" {
                        unknown = true;
                        true
                    } else if let Some(fix) = &fixed {
                        match debversion::compare(&p.source_version, fix) {
                            Some(c) => c.is_lt(),
                            None => {
                                unknown = true;
                                true
                            }
                        }
                    } else if status == "resolved" {
                        unknown = true;
                        true
                    } else {
                        true
                    };
                    if affected {
                        relevant.push(PackageEvidence {
                            name: format!("{}:{}", p.name, p.arch),
                            version: p.version.clone(),
                            fixed_version: None,
                        });
                    }
                }
                if relevant.is_empty() {
                    continue;
                }
                store.request_cvss(
                    &cve,
                    if unknown {
                        0
                    } else if fixed.is_some() {
                        2
                    } else {
                        1
                    },
                )?;
                let cvss = store.cvss(&cve)?;
                let mut sev = "unknown".to_string();
                let mut reason = if unknown {
                    Some("unknown_applicability".into())
                } else {
                    None
                };
                if let Some(c) = cvss {
                    if c.rejected {
                        unknown = true;
                        reason = Some("conflicting_rejected_cve".into());
                    } else if c.error.is_none()
                        && c.checked_at.is_some_and(|at| now() - at <= 86400)
                    {
                        if let Some(score) = c.score {
                            sev = if score >= 9.0 {
                                "critical"
                            } else if score >= 7.0 {
                                "high"
                            } else if score >= 4.0 {
                                "medium"
                            } else {
                                "low"
                            }
                            .into();
                            assessment.fresh_until = assessment
                                .fresh_until
                                .min(c.checked_at.unwrap_or(0) + 86400);
                        }
                    } else {
                        reason.get_or_insert("severity_pending_or_stale".into());
                    }
                }
                if sev != "critical" {
                    if sev == "unknown" {
                        assessment
                            .coverage
                            .push(format!("critical_severity_pending:{name}"));
                    }
                    continue;
                }
                // Source-package fixed versions cannot be compared with an arbitrary binary candidate.
                // Preserve the source version separately in the description and use matching source metadata later.
                for p in &mut relevant {
                    p.fixed_version = fixed.clone();
                }
                assessment.findings.push(Match {
                    source: name.into(),
                    cve: cve.clone(),
                    state: if unknown { "unknown" } else { "affected" }.into(),
                    severity: sev,
                    severity_source: "CVE CNA CVSS".into(),
                    packages: relevant,
                    description,
                    url: format!("https://security-tracker.debian.org/tracker/{cve}"),
                    reason: reason
                        .or_else(|| (!nodsa.is_empty()).then(|| format!("debian:{nodsa}"))),
                    fix_published: fixed.is_some(),
                });
            }
        }
    } else {
        let mut ids: BTreeMap<String, Vec<&Package>> = BTreeMap::new();
        let mut q = db
            .prepare("SELECT id FROM targets WHERE name=?1")
            .map_err(err)?;
        for p in packages {
            let rows = q
                .query_map([&p.name], |r| r.get::<_, String>(0))
                .map_err(err)?;
            for id in rows {
                ids.entry(id.map_err(err)?).or_default().push(p);
            }
        }
        for id in q.query_map(["*"], |r| r.get::<_, String>(0)).map_err(err)? {
            ids.entry(id.map_err(err)?).or_default();
        }
        let mut evaluator = oval::Evaluator::new(&db, meta, packages);
        let mut defs = db
            .prepare("SELECT cve,severity,description FROM definitions WHERE id=?1")
            .map_err(err)?;
        let usn = sources
            .iter()
            .find(|s| s.id == format!("ubuntu-usn:{}", meta.release) && s.fresh())
            .and_then(|s| file(root, s).ok())
            .and_then(|p| {
                Connection::open_with_flags(p, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).ok()
            });
        for (id, related) in ids {
            let mut evaluated = evaluator.definition(&id)?;
            if evaluated.truth == oval::Truth::No {
                continue;
            }
            if evaluated.truth == oval::Truth::Unknown && evaluated.hits.is_empty() {
                for p in related {
                    evaluated.hits.push(oval::Hit {
                        source: p.source.clone(),
                        binary: format!("{}:{}", p.name, p.arch),
                        installed: p.version.clone(),
                        fixed: None,
                        unknown: true,
                    });
                }
            }
            if evaluated.truth == oval::Truth::Unknown && evaluated.hits.is_empty() {
                assessment
                    .coverage
                    .push("unsupported_oval_condition".into());
            }
            let records = defs
                .query_map([&id], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })
                .map_err(err)?;
            for record in records {
                let (cve, sev, description) = record.map_err(err)?;
                let mut groups: BTreeMap<String, Vec<oval::Hit>> = BTreeMap::new();
                for hit in &evaluated.hits {
                    groups
                        .entry(hit.source.clone())
                        .or_default()
                        .push(hit.clone());
                }
                for (source, hits) in groups {
                    let unknown = hits.iter().all(|h| h.unknown)
                        || packages.iter().filter(|p| p.source == source).any(|p| {
                            p.version.contains("ppa")
                                || p.version.contains("custom")
                                || p.version.contains("~bpo")
                        });
                    let fix_published = usn.as_ref().is_some_and(|d| {
                        d.query_row(
                            "SELECT EXISTS(SELECT 1 FROM definitions d JOIN targets t ON t.id=d.id WHERE d.cve=?1 AND t.name=?2)",
                            params![cve,hits[0].binary.split(':').next().unwrap_or("")],
                            |r| r.get::<_, bool>(0),
                        )
                        .unwrap_or(false)
                    });
                    assessment.findings.push(Match {
                        source,
                        cve: cve.clone(),
                        state: if unknown { "unknown" } else { "affected" }.into(),
                        severity: severity(&sev),
                        severity_source: "Ubuntu".into(),
                        packages: hits
                            .into_iter()
                            .map(|h| PackageEvidence {
                                name: h.binary,
                                version: h.installed,
                                fixed_version: h.fixed,
                            })
                            .collect(),
                        description: description.clone(),
                        url: format!("https://ubuntu.com/security/{cve}"),
                        reason: unknown.then(|| "unknown_oval_condition_or_package_origin".into()),
                        fix_published,
                    });
                }
            }
        }
    }
    if assessment.findings.len() > 20000 {
        return Err("Server finding limit reached".into());
    }
    if meta.distro == "debian" {
        let overflow: Option<i64> = {
            let db = store.0.lock().map_err(err)?;
            db.query_row(
                "SELECT at FROM maintenance WHERE id=?1",
                [CVSS_OVERFLOW_ID],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?
        };
        if overflow.is_some_and(|at| now() - at <= 86400) {
            assessment.coverage.push("cvss_queue_full".into());
        }
    }
    finish_coverage(&mut assessment.coverage);
    Ok(assessment)
}

/// Sorts and bounds coverage codes; exact totals go first so truncating
/// per-package details never hides the real scale.
pub(crate) fn is_package_coverage_detail(code: &str) -> bool {
    code.starts_with("uncovered_package") || code.starts_with("critical_severity_pending")
}

fn finish_coverage(coverage: &mut Vec<String>) {
    coverage.sort();
    coverage.dedup();
    let mut totals = vec![];
    for prefix in ["critical_severity_pending:", "uncovered_package:"] {
        let n = coverage.iter().filter(|c| c.starts_with(prefix)).count();
        if n > 0 {
            totals.push(format!("{}_total:{n}", &prefix[..prefix.len() - 1]));
        }
    }
    // Keep reasons that can block recovery ahead of potentially thousands of package names.
    let (limits, packages): (Vec<_>, Vec<_>) = coverage
        .drain(..)
        .partition(|code| !is_package_coverage_detail(code));
    totals.extend(limits);
    totals.extend(packages);
    *coverage = totals;
    if coverage.len() > 128 {
        coverage.truncate(127);
        coverage.push("coverage_list_truncated".into());
    }
}
fn app_source_ids(db: &Connection) -> Result<Vec<String>> {
    let mut q = db.prepare("SELECT id FROM advisory_sources").map_err(err)?;
    let rows = q.query_map([], |r| r.get(0)).map_err(err)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_publication_metadata_without_a_severity_record() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("db")).unwrap();
        let cve = "CVE-2026-1000";
        let record = serde_json::json!({
            "cveMetadata": {"datePublished":"2026-10-21T23:30:00-02:00"},
            "containers": {"cna": {"title":"  Buffer\n  overread "}},
        });
        store
            .save_catalog_metadata(cve, Some(&record), 86400)
            .unwrap();
        store.save_catalog_metadata(cve, None, 3600).unwrap();
        let db = store.0.lock().unwrap();
        let (title, published_on): (String, String) = db
            .query_row(
                "SELECT title,published_on FROM advisory_cve_metadata WHERE cve=?1",
                [cve],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(title, "Buffer overread");
        assert_eq!(published_on, "2026-10-22");
        assert_eq!(
            db.query_row("SELECT count(*) FROM advisory_cvss", [], |row| row
                .get::<_, usize>(0))
                .unwrap(),
            0
        );
    }
    #[test]
    fn cna_only_cvss_and_rejected_conflicts() {
        let v = serde_json::json!({"cveMetadata":{"cveId":"CVE-2025-1000","state":"PUBLISHED"},"containers":{"cna":{"metrics":[{"cvssV3_1":{"version":"3.1","vectorString":"CVSS:3.1/AV:N","baseScore":9.8}}]},"adp":[{"metrics":[{"cvssV4_0":{"baseScore":10}}]}]}});
        let c = cvss_record("CVE-2025-1000", &v, now()).unwrap();
        assert_eq!(c.score, Some(9.8));
        assert_eq!(c.version.as_deref(), Some("3.1"));
        assert!(cvss_record("CVE-2025-9999", &v, now()).is_err());
        let mut v = v;
        v["containers"]["cna"] = serde_json::json!({});
        assert_eq!(cvss_record("CVE-2025-1000", &v, now()).unwrap().score, None);
        v["cveMetadata"]["state"] = serde_json::json!("REJECTED");
        assert!(cvss_record("CVE-2025-1000", &v, now()).unwrap().rejected);
    }
    #[test]
    fn distribution_fixed_zero_undetermined_and_epoch() {
        let (store, server) = crate::packages::tests::fixture();
        let state = crate::packages::tests::install(
            &store,
            &server,
            vec![crate::packages::tests::package()],
        );
        let dir = tempfile::tempdir().unwrap();
        let json_path = dir.path().join("input.json");
        let mut entries = serde_json::Map::new();
        for (id, status, fix) in [
            ("CVE-2025-1000", "resolved", Some("0")),
            ("CVE-2025-1001", "resolved", Some("3.0.1-1")),
            ("CVE-2025-1002", "undetermined", None),
            ("CVE-2025-1003", "resolved", Some("2.0-1")),
        ] {
            entries.insert(id.into(),serde_json::json!({"releases":{"bookworm":{"status":status,"fixed_version":fix,"urgency":"not yet assigned"}}}));
        }
        std::fs::write(
            &json_path,
            serde_json::json!({"openssl":entries}).to_string(),
        )
        .unwrap();
        prepare_debian(&json_path, &dir.path().join("debian.sqlite")).unwrap();
        std::fs::write(
            dir.path().join("releases.csv"),
            "version,codename,series,release,eol\n12,Bookworm,bookworm,2023-01-01,2099-01-01\n",
        )
        .unwrap();
        for (id, file) in [
            ("debian", "debian.sqlite"),
            ("debian-releases", "releases.csv"),
        ] {
            let mut s = Source::new(id).unwrap();
            s.file = Some(file.into());
            s.hash = Some("fixture".into());
            s.roots.insert(state.root.clone().unwrap());
            s.checked_at = Some(now());
            store.save_source(&s, true).unwrap();
        }
        for id in ["CVE-2025-1001", "CVE-2025-1002"] {
            let c = Cvss {
                created_at: now(),
                cve: id.into(),
                score: Some(9.8),
                version: Some("3.1".into()),
                checked_at: Some(now()),
                next_check: now() + 86400,
                etag: None,
                error: None,
                rejected: false,
                priority: 2,
            };
            store.save_cvss(&c, 0).unwrap();
        }
        let packages = vec![crate::packages::tests::package()];
        let result = assess(
            &store,
            dir.path(),
            state.metadata.as_ref().unwrap(),
            &packages,
            state.root.as_deref().unwrap(),
        )
        .unwrap();
        assert!(result.coverage.is_empty());
        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.findings[0].cve, "CVE-2025-1001");
        assert_eq!(result.findings[0].state, "affected");
        assert_eq!(result.findings[0].severity, "critical");
        assert_eq!(result.findings[1].state, "unknown");
        let mut p = packages[0].clone();
        p.source_version = "3.0.0-1~bpo12+1".into();
        let result = assess(
            &store,
            dir.path(),
            state.metadata.as_ref().unwrap(),
            &[p],
            state.root.as_deref().unwrap(),
        )
        .unwrap();
        assert!(result.findings.iter().all(|f| f.state == "unknown"));
    }
    #[test]
    fn support_dates_and_cache_bound() {
        assert_eq!(civil_days("1970-01-01"), Some(0));
        let meta = Metadata {
            distro: "ubuntu".into(),
            release: "noble".into(),
            version: "24.04".into(),
            architecture: "x86_64".into(),
            kernel: "6.8".into(),
        };
        assert_eq!(release_support("version,codename,series,release,eol,eol-esm\n24.04,Noble,noble,2024-04-25,2025-01-01,2099-01-01\n",&meta),Some("esm_entitlement_unknown"));
        let dir = tempfile::tempdir().unwrap();
        let f = std::fs::File::create(dir.path().join("large")).unwrap();
        f.set_len(1024 * 1024 * 1024).unwrap();
        assert!(cache_admit(dir.path(), 1).is_err());
    }
    #[test]
    fn irrelevant_packages_and_known_noncritical_cves_never_enter_index() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        let out = dir.path().join("index");
        let cve = serde_json::json!({"CVE-2025-1000":{"releases":{"bookworm":{"status":"open","urgency":"not yet assigned"}}}});
        std::fs::write(
            &input,
            serde_json::json!({"openssl":cve,"uninstalled":cve}).to_string(),
        )
        .unwrap();
        let filter = Filter {
            packages: BTreeMap::from([(
                "openssl".into(),
                BTreeMap::from([("bookworm".into(), BTreeSet::from(["3.0".into()]))]),
            )]),
            cvss: BTreeMap::from([("CVE-2025-1000".into(), Some(7.5))]),
            ..Filter::default()
        };
        prepare_debian_scoped(&input, &out, &filter).unwrap();
        let db = Connection::open(out).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM advisories", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT source FROM packages", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "openssl"
        );
    }
    fn scored(cve: &str, score: Option<f64>, checked: Option<i64>, priority: u8) -> Cvss {
        Cvss {
            created_at: now(),
            cve: cve.into(),
            score,
            version: score.map(|_| "3.1".into()),
            checked_at: checked,
            next_check: checked.map_or(0, |t| t + CVSS_RECHECK),
            etag: None,
            error: None,
            rejected: false,
            priority,
        }
    }
    #[test]
    fn cvss_queue_orders_by_verdict_relevance_and_raises_priority() {
        let (store, server) = crate::packages::tests::fixture();
        store.request_cvss("CVE-2025-0001", 0).unwrap();
        store.request_cvss("CVE-2025-0002", 1).unwrap();
        store.request_cvss("CVE-2025-0003", 0).unwrap();
        // A later server with confirmed applicability and a fix raises the priority, never lowers it.
        store.request_cvss("CVE-2025-0003", 2).unwrap();
        store.request_cvss("CVE-2025-0003", 0).unwrap();
        assert_eq!(store.cvss("CVE-2025-0003").unwrap().unwrap().priority, 2);
        // Due rechecks: one backs an open finding, one does not.
        let old = now() - 90000;
        store
            .save_cvss(&scored("CVE-2025-0004", Some(5.0), Some(old), 2), 0)
            .unwrap();
        store
            .save_cvss(&scored("CVE-2025-0005", Some(9.8), Some(old), 0), 0)
            .unwrap();
        {
            let db = store.0.lock().unwrap();
            db.execute(
                "INSERT INTO vulnerability_findings VALUES(?1,'openssl','CVE-2025-0005',NULL,'{}')",
                [&server.id],
            )
            .unwrap();
        }
        let (due, budget) = store.cvss_due().unwrap().unwrap();
        let order = due.iter().map(|c| c.cve.as_str()).collect::<Vec<_>>();
        assert_eq!(
            order,
            [
                "CVE-2025-0005",
                "CVE-2025-0003",
                "CVE-2025-0002",
                "CVE-2025-0001",
                "CVE-2025-0004"
            ]
        );
        assert_eq!(budget, CVSS_DAILY);
        let q = store.cvss_queue().unwrap();
        assert_eq!((q.total, q.waiting, q.unavailable), (5, 3, 0));
        assert_eq!(q.eta_seconds, Some(60));
        store.pause_cvss(now() + 600).unwrap();
        assert!(store.cvss_due().unwrap().is_none());
        let q = store.cvss_queue().unwrap();
        assert!(q.paused_until.is_some() && q.eta_seconds.is_none());
    }
    #[test]
    fn cvss_backlog_budget_reservation_and_overflow() {
        let (store, _) = crate::packages::tests::fixture();
        {
            let db = store.0.lock().unwrap();
            db.execute("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO advisory_cvss SELECT printf('CVE-2024-%05d',i),json_object('createdAt',0,'cve',printf('CVE-2024-%05d',i),'score',NULL,'version',NULL,'checkedAt',NULL,'nextCheck',0,'etag',NULL,'error',NULL,'rejected',json('false')) FROM n",[CVSS_CAP]).unwrap();
        }
        let (due, budget) = store.cvss_due().unwrap().unwrap();
        assert_eq!(due.len() as i64, CVSS_BACKLOG_BATCH);
        assert_eq!(budget, CVSS_BACKLOG_DAILY);
        assert_eq!(
            store.cvss_queue().unwrap().eta_seconds,
            Some(CVSS_CAP / CVSS_BACKLOG_BATCH * 60 + 60)
        );
        // A full table rejects new CVEs visibly instead of silently.
        assert!(!store.cvss_queue().unwrap().overflow);
        store.request_cvss("CVE-2026-0001", 2).unwrap();
        assert!(store.cvss("CVE-2026-0001").unwrap().is_none());
        assert!(store.cvss_queue().unwrap().overflow);
        // Reservations stop at the daily budget.
        let reservations = (CVSS_DAILY / CVSS_RESERVE) as usize;
        for _ in 0..reservations {
            assert!(store.reserve_cvss(CVSS_DAILY).unwrap().is_some());
        }
        assert!(!store.reserve_cvss(CVSS_DAILY).unwrap().is_some());
        assert!(store.reserve_cvss(CVSS_BACKLOG_DAILY).unwrap().is_some());
    }
    #[test]
    fn coverage_totals_survive_truncation() {
        let mut coverage = (0..200)
            .map(|i| format!("uncovered_package:p{i:03}"))
            .chain((0..150).map(|i| format!("critical_severity_pending:z{i:03}")))
            .chain(["stale_or_failed:debian".to_string()])
            .collect::<Vec<_>>();
        coverage.push("uncovered_package:p000".into());
        finish_coverage(&mut coverage);
        assert_eq!(coverage.len(), 128);
        assert_eq!(coverage[0], "critical_severity_pending_total:150");
        assert_eq!(coverage[1], "uncovered_package_total:200");
        assert_eq!(coverage[2], "stale_or_failed:debian");
        assert_eq!(coverage[127], "coverage_list_truncated");
    }
    #[test]
    fn cvss_save_reports_class_changes_and_batches_one_generation() {
        let (store, _) = crate::packages::tests::fixture();
        store.request_cvss("CVE-2025-0001", 1).unwrap();
        let fresh = scored("CVE-2025-0001", Some(7.5), Some(now()), 1);
        assert!(store.save_cvss(&fresh, 0).unwrap());
        // 304 recheck keeps the class: no re-evaluation needed.
        assert!(!store.save_cvss(&fresh, 0).unwrap());
        assert!(store
            .save_cvss(&scored("CVE-2025-0001", Some(9.1), Some(now()), 1), 0)
            .unwrap());
        let mut failed = scored("CVE-2025-0001", Some(9.1), Some(now()), 1);
        failed.error = Some("The CVE record has not been published yet".into());
        assert!(store.save_cvss(&failed, 0).unwrap());
        let revision = |store: &Store| -> i64 {
            let db = store.0.lock().unwrap();
            db.query_row(
                "SELECT coalesce((SELECT at FROM maintenance WHERE id=2),0)",
                [],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(revision(&store), 0);
        store.cvss_changed().unwrap();
        assert_eq!(revision(&store), 1);
        assert_eq!(store.cvss_queue().unwrap().unavailable, 1);
    }
    #[test]
    #[ignore = "Explicit official Debian feed; set CYBERBOT_DEBIAN_FIXTURE"]
    fn official_debian_feed() {
        let input = std::env::var("CYBERBOT_DEBIAN_FIXTURE").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.sqlite");
        let start = std::time::Instant::now();
        prepare_debian(Path::new(&input), &path).unwrap();
        let db = Connection::open(&path).unwrap();
        let count: i64 = db
            .query_row("SELECT count(*) FROM advisories", [], |r| r.get(0))
            .unwrap();
        assert!(count > 0);
        assert!(count < 1000);
        println!(
            "official Debian: {count} rows, {} bytes, {} ms",
            std::fs::metadata(path).unwrap().len(),
            start.elapsed().as_millis()
        );
    }
}
