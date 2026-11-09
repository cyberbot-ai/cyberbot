//! Declarative OVAL evaluator. Unknown constructs never cause remote execution.
use crate::{
    debversion,
    packages::{Metadata, Package, Result},
};
use quick_xml::{events::Event, Reader};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io::BufRead,
    path::Path,
};
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Node {
    pub tag: String,
    pub attrs: BTreeMap<String, String>,
    pub text: String,
    pub children: Vec<Node>,
}
impl Node {
    fn a(&self, k: &str) -> &str {
        self.attrs.get(k).map(String::as_str).unwrap_or("")
    }
    fn child(&self, k: &str) -> Option<&Node> {
        self.children.iter().find(|n| n.tag == k)
    }
    fn value(&self, k: &str) -> &str {
        self.child(k).map(|n| n.text.as_str()).unwrap_or("")
    }
    fn descendants<'a>(&'a self, tag: &str, out: &mut Vec<&'a Node>) {
        if self.tag == tag {
            out.push(self);
        }
        for c in &self.children {
            c.descendants(tag, out);
        }
    }
}
#[cfg(test)]
pub fn prepare<R: BufRead>(input: R, path: &Path) -> Result<()> {
    prepare_scoped(input, path, None)
}
pub fn prepare_scoped<R: BufRead>(
    input: R,
    path: &Path,
    scope: Option<&BTreeSet<String>>,
) -> Result<()> {
    let db = Connection::open(path).map_err(err)?;
    db.execute_batch("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA max_page_count=8192; CREATE TABLE nodes(id TEXT PRIMARY KEY,kind TEXT,payload TEXT); CREATE TABLE definitions(id TEXT,cve TEXT,severity TEXT,description TEXT,PRIMARY KEY(id,cve)); CREATE TABLE targets(name TEXT,id TEXT,PRIMARY KEY(name,id));").map_err(err)?;
    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(false);
    reader.config_mut().expand_empty_elements = true;
    let mut buf = Vec::new();
    let mut stack: Vec<Node> = vec![];
    let mut nodes = 0u64;
    let mut dependencies: BTreeMap<String, Node> = BTreeMap::new();
    let mut dependency_bytes = 0usize;
    loop {
        let event = reader.read_event_into(&mut buf).map_err(err)?;
        let expanded = reader.buffer_position();
        if expanded > 512 * 1024 * 1024 {
            return Err("Limit of unpacked Oval".into());
        }
        match event {
            Event::Start(e) => {
                let mut n = Node {
                    tag: String::from_utf8_lossy(e.local_name().as_ref()).into(),
                    ..Default::default()
                };
                for a in e.attributes() {
                    let a = a.map_err(err)?;
                    let key = String::from_utf8_lossy(a.key.local_name().as_ref()).to_string();
                    let value = a
                        .decode_and_unescape_value(reader.decoder())
                        .map_err(err)?
                        .into_owned();
                    if value.len() > 4096 {
                        return Err("Oval attribute limit".into());
                    }
                    if key == "comment" {
                        if value.contains("might be affected") || value.contains("needs-triage") {
                            n.attrs.insert("uncertain".into(), "true".into());
                        }
                    } else {
                        n.attrs.insert(key, value);
                    }
                }
                stack.push(n);
                if stack.len() > 64 {
                    return Err("Depth of Oval".into());
                }
            }
            Event::Text(t) => {
                if let Some(n) = stack.last_mut() {
                    let value = t.decode().map_err(err)?;
                    if n.text.len() + value.len() > 1048576 {
                        return Err("Limit of Oval text".into());
                    }
                    n.text.push_str(&value);
                }
            }
            Event::CData(t) => {
                if let Some(n) = stack.last_mut() {
                    n.text.push_str(&t.decode().map_err(err)?);
                }
            }
            Event::GeneralRef(t) => {
                let escaped = format!("&{};", t.decode().map_err(err)?);
                let value = quick_xml::escape::unescape(&escaped).map_err(err)?;
                if let Some(n) = stack.last_mut() {
                    n.text.push_str(&value);
                }
            }
            Event::End(_) => {
                let mut n = stack.pop().ok_or("Non-consensual XML")?;
                n.text = n.text.trim().to_string();
                if n.tag == "description" {
                    n.text = n.text.chars().take(512).collect();
                }
                if n.tag == "rights" {
                    n.text.clear();
                }
                if n.a("id").starts_with("oval:") {
                    nodes += 1;
                    if nodes > 500000 {
                        return Err("Limit of Oval facilities".into());
                    }
                    let payload = serde_json::to_string(&n).map_err(err)?;
                    if payload.len() > 1048576 {
                        return Err("Limit of the Oval facility".into());
                    }
                    if n.tag == "definition" && ["vulnerability", "patch"].contains(&n.a("class")) {
                        let mut refs = vec![];
                        n.descendants("reference", &mut refs);
                        let mut cves: BTreeMap<String, String> = refs
                            .iter()
                            .filter(|r| r.a("source") == "CVE")
                            .map(|r| (r.a("ref_id").to_owned(), "unknown".into()))
                            .collect();
                        let mut items = vec![];
                        n.descendants("cve", &mut items);
                        for c in items {
                            cves.insert(c.text.clone(), c.a("priority").to_lowercase());
                        }
                        let mut selected = false;
                        for (cve, priority) in cves {
                            if !crate::advisories::valid_cve(&cve) {
                                continue;
                            }
                            let metadata = n.child("metadata");
                            let severity = if priority.is_empty() || priority == "unknown" {
                                metadata
                                    .and_then(|m| m.child("advisory"))
                                    .map(|a| a.value("severity").to_lowercase())
                                    .unwrap_or("unknown".into())
                            } else {
                                priority
                            };
                            if severity != "critical" {
                                continue;
                            }
                            selected = true;
                            let description =
                                metadata.map(|m| m.value("description")).unwrap_or("");
                            db.execute(
                                "INSERT OR IGNORE INTO definitions VALUES(?1,?2,?3,?4)",
                                params![n.a("id"), cve, severity, description],
                            )
                            .map_err(err)?;
                        }
                        if selected {
                            db.execute(
                                "INSERT INTO nodes VALUES(?1,?2,?3)",
                                params![n.a("id"), n.tag, payload],
                            )
                            .map_err(err)?;
                        }
                    } else {
                        dependency_bytes += payload.len();
                        if dependency_bytes > 32 * 1024 * 1024 {
                            return Err("Limit of Dependencies of Critical Oval".into());
                        }
                        dependencies.insert(n.a("id").to_string(), n);
                    }
                } else if let Some(parent) = stack.last_mut() {
                    parent.children.push(n);
                    if parent.children.len() > 10000 {
                        return Err("Oval Branch Limit".into());
                    }
                }
            }
            Event::DocType(_) => return Err("DTD banned in Oval".into()),
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    if !stack.is_empty() || nodes == 0 {
        return Err("Incomplete Oval".into());
    }
    // Only the transitive dependencies of critical definitions enter the persistent index.
    fn refs(n: &Node, out: &mut BTreeSet<String>) {
        for key in [
            "test_ref",
            "definition_ref",
            "object_ref",
            "state_ref",
            "var_ref",
        ] {
            if !n.a(key).is_empty() {
                out.insert(n.a(key).into());
            }
        }
        if n.tag == "var_ref" {
            out.insert(n.text.clone());
        }
        for c in &n.children {
            refs(c, out);
        }
    }
    let mut pending = BTreeSet::new();
    {
        let mut q = db.prepare("SELECT payload FROM nodes").map_err(err)?;
        for raw in q.query_map([], |r| r.get::<_, String>(0)).map_err(err)? {
            let n: Node = serde_json::from_str(&raw.map_err(err)?).map_err(err)?;
            refs(&n, &mut pending);
        }
    }
    let mut visited = BTreeSet::new();
    while let Some(id) = pending.pop_first() {
        if !visited.insert(id.clone()) {
            continue;
        }
        if let Some(n) = dependencies.remove(&id) {
            refs(&n, &mut pending);
            db.execute(
                "INSERT OR IGNORE INTO nodes VALUES(?1,?2,?3)",
                params![id, n.tag, serde_json::to_string(&n).map_err(err)?],
            )
            .map_err(err)?;
        }
    }
    drop(dependencies);
    let mut q = db
        .prepare("SELECT DISTINCT id FROM definitions")
        .map_err(err)?;
    let ids = q.query_map([], |r| r.get::<_, String>(0)).map_err(err)?;
    let mut cache = HashMap::new();
    for id in ids {
        let id = id.map_err(err)?;
        let mut names = BTreeSet::new();
        gather(&db, &id, &mut cache, &mut BTreeSet::new(), &mut names, 0)?;
        if names.is_empty() {
            names.insert("*".into());
        }
        if scope.is_some_and(|scope| !names.contains("*") && names.is_disjoint(scope)) {
            db.execute("DELETE FROM definitions WHERE id=?1", [&id])
                .map_err(err)?;
            continue;
        }
        for name in names {
            db.execute(
                "INSERT OR IGNORE INTO targets VALUES(?1,?2)",
                params![name, id],
            )
            .map_err(err)?;
        }
    }
    drop(q);
    // Remove dependencies of discarded packages and compact before promotion.
    let mut needed = BTreeSet::new();
    let mut pending = BTreeSet::new();
    {
        let mut q = db
            .prepare("SELECT DISTINCT id FROM definitions")
            .map_err(err)?;
        for id in q.query_map([], |r| r.get::<_, String>(0)).map_err(err)? {
            pending.insert(id.map_err(err)?);
        }
    }
    while let Some(id) = pending.pop_first() {
        if needed.insert(id.clone()) {
            if let Some(n) = node(&db, &id, &mut cache)? {
                refs(&n, &mut pending);
            }
        }
    }
    let all = {
        let mut q = db.prepare("SELECT id FROM nodes").map_err(err)?;
        let rows = q.query_map([], |r| r.get::<_, String>(0)).map_err(err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err)?
    };
    for id in all {
        if !needed.contains(&id) {
            db.execute("DELETE FROM nodes WHERE id=?1", [id])
                .map_err(err)?;
        }
    }
    db.execute_batch("VACUUM;").map_err(err)?;
    Ok(())
}
fn node(db: &Connection, id: &str, cache: &mut HashMap<String, Node>) -> Result<Option<Node>> {
    if let Some(n) = cache.get(id) {
        return Ok(Some(n.clone()));
    }
    let raw: Option<String> = db
        .query_row("SELECT payload FROM nodes WHERE id=?1", [id], |r| r.get(0))
        .optional()
        .map_err(err)?;
    let n: Option<Node> = raw
        .map(|s| serde_json::from_str(&s).map_err(err))
        .transpose()?;
    if let Some(n) = &n {
        if cache.len() >= 8000 {
            cache.clear();
        }
        cache.insert(id.into(), n.clone());
    }
    Ok(n)
}
fn gather(
    db: &Connection,
    id: &str,
    cache: &mut HashMap<String, Node>,
    visited: &mut BTreeSet<String>,
    names: &mut BTreeSet<String>,
    depth: usize,
) -> Result<()> {
    if depth > 48 || visited.len() > 10000 {
        return Err("The cycle or complexity of Oval".into());
    }
    if !visited.insert(id.into()) {
        return Ok(());
    }
    let Some(n) = node(db, id, cache)? else {
        return Ok(());
    };
    if n.tag == "constant_variable" {
        for v in &n.children {
            if v.tag == "value" && v.text.len() <= 200 {
                names.insert(v.text.clone());
            }
        }
    }
    if n.tag == "dpkginfo_object" {
        if let Some(v) = n.child("name") {
            if !v.text.is_empty() {
                if v.a("operation") == "pattern match" {
                    names.insert("*".into());
                } else {
                    names.insert(v.text.clone());
                }
            }
        }
    }
    fn walk(
        db: &Connection,
        n: &Node,
        c: &mut HashMap<String, Node>,
        v: &mut BTreeSet<String>,
        names: &mut BTreeSet<String>,
        depth: usize,
    ) -> Result<()> {
        for key in ["definition_ref", "test_ref", "object_ref", "var_ref"] {
            if !n.a(key).is_empty() {
                gather(db, n.a(key), c, v, names, depth + 1)?;
            }
        }
        if n.tag == "var_ref" {
            gather(db, &n.text, c, v, names, depth + 1)?;
        }
        for child in &n.children {
            walk(db, child, c, v, names, depth)?;
        }
        Ok(())
    }
    walk(db, &n, cache, visited, names, depth)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Truth {
    Yes,
    No,
    Unknown,
}
fn combine(values: &[Truth], or: bool) -> Truth {
    if values.is_empty() {
        return Truth::Unknown;
    }
    if or {
        if values.contains(&Truth::Yes) {
            Truth::Yes
        } else if values.contains(&Truth::Unknown) {
            Truth::Unknown
        } else {
            Truth::No
        }
    } else if values.contains(&Truth::No) {
        Truth::No
    } else if values.contains(&Truth::Unknown) {
        Truth::Unknown
    } else {
        Truth::Yes
    }
}
#[derive(Clone, Debug)]
pub struct Hit {
    pub source: String,
    pub binary: String,
    pub installed: String,
    pub fixed: Option<String>,
    pub unknown: bool,
}
#[derive(Clone, Debug)]
pub struct Evaluation {
    pub truth: Truth,
    pub hits: Vec<Hit>,
}
impl Evaluation {
    fn plain(truth: Truth) -> Self {
        Self {
            truth,
            hits: vec![],
        }
    }
}
fn condition(actual: &str, expected: &Node) -> Truth {
    if !expected.a("var_ref").is_empty() {
        return Truth::Unknown;
    }
    let operation = if expected.a("operation").is_empty() {
        "equals"
    } else {
        expected.a("operation")
    };
    if operation == "pattern match" {
        return regex::RegexBuilder::new(&expected.text)
            .size_limit(1048576)
            .build()
            .map(|r| {
                if r.is_match(actual) {
                    Truth::Yes
                } else {
                    Truth::No
                }
            })
            .unwrap_or(Truth::Unknown);
    }
    let cmp = if expected.a("datatype") == "debian_evr_string" {
        debversion::compare(actual, &expected.text)
    } else if ["", "string"].contains(&expected.a("datatype")) {
        Some(actual.cmp(&expected.text))
    } else {
        return Truth::Unknown;
    };
    let Some(cmp) = cmp else {
        return Truth::Unknown;
    };
    let result = match operation {
        "equals" => cmp.is_eq(),
        "not equal" => !cmp.is_eq(),
        "less than" => cmp.is_lt(),
        "less than or equal" => !cmp.is_gt(),
        "greater than" => cmp.is_gt(),
        "greater than or equal" => !cmp.is_lt(),
        _ => return Truth::Unknown,
    };
    if result {
        Truth::Yes
    } else {
        Truth::No
    }
}
pub struct Evaluator<'a> {
    pub db: &'a Connection,
    pub metadata: &'a Metadata,
    pub packages: &'a [Package],
    cache: HashMap<String, Node>,
    visiting: BTreeSet<String>,
}
impl<'a> Evaluator<'a> {
    pub fn new(db: &'a Connection, metadata: &'a Metadata, packages: &'a [Package]) -> Self {
        Self {
            db,
            metadata,
            packages,
            cache: HashMap::new(),
            visiting: BTreeSet::new(),
        }
    }
    fn fetch(&mut self, id: &str) -> Result<Option<Node>> {
        node(self.db, id, &mut self.cache)
    }
    pub fn definition(&mut self, id: &str) -> Result<Evaluation> {
        if self.visiting.len() > 48 || !self.visiting.insert(id.into()) {
            return Ok(Evaluation::plain(Truth::Unknown));
        }
        let result = match self.fetch(id)? {
            Some(n) => match n.child("criteria") {
                Some(c) => self.criteria(c),
                None => Ok(Evaluation::plain(Truth::Unknown)),
            },
            None => Ok(Evaluation::plain(Truth::Unknown)),
        };
        self.visiting.remove(id);
        result
    }
    fn criteria(&mut self, n: &Node) -> Result<Evaluation> {
        let mut result = match n.tag.as_str() {
            "extend_definition" => self.definition(n.a("definition_ref"))?,
            "criterion" => {
                let mut e = self.test(n.a("test_ref"))?;
                if n.a("uncertain") == "true" && e.truth != Truth::No {
                    e.truth = Truth::Unknown;
                    for h in &mut e.hits {
                        h.unknown = true;
                    }
                }
                e
            }
            "criteria" => {
                let or = match n.a("operator") {
                    "" | "AND" => false,
                    "OR" => true,
                    _ => return Ok(Evaluation::plain(Truth::Unknown)),
                };
                let mut children = vec![];
                for child in &n.children {
                    children.push(self.criteria(child)?);
                }
                let truth = combine(&children.iter().map(|v| v.truth).collect::<Vec<_>>(), or);
                let hits = if truth == Truth::No {
                    vec![]
                } else {
                    children
                        .into_iter()
                        .filter(|c| c.truth != Truth::No)
                        .flat_map(|c| c.hits)
                        .map(|mut h| {
                            h.unknown |= truth == Truth::Unknown;
                            h
                        })
                        .collect()
                };
                Evaluation { truth, hits }
            }
            _ => Evaluation::plain(Truth::Unknown),
        };
        if n.a("negate") == "true" {
            result.truth = match result.truth {
                Truth::Yes => Truth::No,
                Truth::No => Truth::Yes,
                Truth::Unknown => Truth::Unknown,
            };
            result.hits.clear();
        }
        Ok(result)
    }
    fn variable(&mut self, id: &str, depth: usize) -> Result<Option<Vec<String>>> {
        if depth > 16 {
            return Ok(None);
        }
        let Some(n) = self.fetch(id)? else {
            return Ok(None);
        };
        match n.tag.as_str() {
            "constant_variable" => Ok(Some(
                n.children
                    .iter()
                    .filter(|n| n.tag == "value")
                    .map(|n| n.text.clone())
                    .collect(),
            )),
            "local_variable" => {
                if n.children.len() == 1 {
                    self.component(&n.children[0], depth + 1)
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }
    fn component(&mut self, n: &Node, depth: usize) -> Result<Option<Vec<String>>> {
        if depth > 16 {
            return Ok(None);
        }
        match n.tag.as_str() {
            "literal_component" => Ok(Some(vec![n.text.clone()])),
            "object_component" => {
                let obj = self.fetch(n.a("object_ref"))?;
                if obj.is_some_and(|o| o.tag == "uname_object") && n.a("item_field") == "os_release"
                {
                    Ok(Some(vec![self.metadata.kernel.clone()]))
                } else {
                    Ok(None)
                }
            }
            "variable_component" => self.variable(n.a("var_ref"), depth + 1),
            "concat" => {
                let mut out = String::new();
                for c in &n.children {
                    let Some(values) = self.component(c, depth + 1)? else {
                        return Ok(None);
                    };
                    if values.len() != 1 {
                        return Ok(None);
                    }
                    out.push_str(&values[0]);
                    if out.len() > 1024 {
                        return Ok(None);
                    }
                }
                Ok(Some(vec![out]))
            }
            "regex_capture" => {
                if n.children.len() != 1 {
                    return Ok(None);
                }
                let Some(values) = self.component(&n.children[0], depth + 1)? else {
                    return Ok(None);
                };
                let Ok(regex) = regex::RegexBuilder::new(n.a("pattern"))
                    .size_limit(1048576)
                    .build()
                else {
                    return Ok(None);
                };
                Ok(values
                    .iter()
                    .map(|s| {
                        regex
                            .captures(s)
                            .and_then(|c| c.get(1))
                            .map(|m| m.as_str().to_owned())
                    })
                    .collect())
            }
            _ => Ok(None),
        }
    }
    fn test(&mut self, id: &str) -> Result<Evaluation> {
        let Some(test) = self.fetch(id)? else {
            return Ok(Evaluation::plain(Truth::Unknown));
        };
        let Some(object_ref) = test.child("object") else {
            return Ok(Evaluation::plain(Truth::Unknown));
        };
        let Some(object) = self.fetch(object_ref.a("object_ref"))? else {
            return Ok(Evaluation::plain(Truth::Unknown));
        };
        let mut states = vec![];
        for s in test.children.iter().filter(|n| n.tag == "state") {
            let Some(s) = self.fetch(s.a("state_ref"))? else {
                return Ok(Evaluation::plain(Truth::Unknown));
            };
            states.push(s);
        }
        let mut items: Vec<(String, Option<Package>)> = vec![];
        match test.tag.as_str() {
            "dpkginfo_test" => {
                if object.tag != "dpkginfo_object"
                    || object.children.iter().any(|c| c.tag != "name")
                {
                    return Ok(Evaluation::plain(Truth::Unknown));
                }
                let Some(name) = object.child("name") else {
                    return Ok(Evaluation::plain(Truth::Unknown));
                };
                let names = if !name.a("var_ref").is_empty() {
                    self.variable(name.a("var_ref"), 0)?
                } else {
                    Some(vec![name.text.clone()])
                };
                let Some(names) = names else {
                    return Ok(Evaluation::plain(Truth::Unknown));
                };
                if names.is_empty() {
                    return Ok(Evaluation::plain(Truth::Unknown));
                }
                for p in self.packages {
                    let outcomes = names
                        .iter()
                        .map(|s| {
                            let mut cond = name.clone();
                            cond.text = s.clone();
                            cond.attrs.remove("var_ref");
                            condition(&p.name, &cond)
                        })
                        .collect::<Vec<_>>();
                    if outcomes.contains(&Truth::Unknown) {
                        return Ok(Evaluation::plain(Truth::Unknown));
                    }
                    if outcomes.contains(&Truth::Yes) {
                        items.push((p.version.clone(), Some(p.clone())));
                    }
                }
            }
            "family_test" => items.push(("unix".into(), None)),
            "uname_test" => items.push((self.metadata.kernel.clone(), None)),
            "variable_test" => {
                if let Some(values) = self.variable(object.value("var_ref"), 0)? {
                    items.extend(values.into_iter().map(|s| (s, None)));
                } else {
                    return Ok(Evaluation::plain(Truth::Unknown));
                }
            }
            "textfilecontent54_test" => {
                let path = if !object.value("filepath").is_empty() {
                    object.value("filepath").to_string()
                } else {
                    format!("{}/{}", object.value("path"), object.value("filename"))
                };
                let content = match path.as_str() {
                    "/etc/lsb-release" => format!(
                        "DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE={}\nDISTRIB_CODENAME={}\n",
                        self.metadata.version, self.metadata.release
                    ),
                    "/etc/os-release" => format!(
                        "ID={}\nVERSION_ID=\"{}\"\nVERSION_CODENAME={}\n",
                        self.metadata.distro, self.metadata.version, self.metadata.release
                    ),
                    _ => return Ok(Evaluation::plain(Truth::Unknown)),
                };
                let Ok(re) = regex::RegexBuilder::new(object.value("pattern"))
                    .multi_line(true)
                    .size_limit(1048576)
                    .build()
                else {
                    return Ok(Evaluation::plain(Truth::Unknown));
                };
                for capture in re.captures_iter(&content).take(32) {
                    if let Some(v) = capture.get(1) {
                        items.push((v.as_str().into(), None));
                    }
                }
            }
            _ => return Ok(Evaluation::plain(Truth::Unknown)),
        }
        let existence = match test.a("check_existence") {
            "" | "at_least_one_exists" => !items.is_empty(),
            "none_exist" => {
                return Ok(Evaluation::plain(if items.is_empty() {
                    Truth::Yes
                } else {
                    Truth::No
                }))
            }
            "only_one_exists" => items.len() == 1,
            _ => return Ok(Evaluation::plain(Truth::Unknown)),
        };
        if !existence {
            return Ok(Evaluation::plain(Truth::No));
        }
        let mut outcomes = vec![];
        let mut hits = vec![];
        for (value, pkg) in items {
            let mut state_outcomes = vec![];
            let mut fixed = None;
            for s in &states {
                let mut checks = vec![];
                for entity in &s.children {
                    let actual = match (test.tag.as_str(), entity.tag.as_str()) {
                        ("dpkginfo_test", "evr") => Some(value.as_str()),
                        ("dpkginfo_test", "arch") => pkg.as_ref().map(|p| p.arch.as_str()),
                        ("dpkginfo_test", "name") => pkg.as_ref().map(|p| p.name.as_str()),
                        ("family_test", "family")
                        | ("uname_test", "os_release")
                        | ("variable_test", "value")
                        | ("textfilecontent54_test", "subexpression") => Some(value.as_str()),
                        _ => None,
                    };
                    checks.push(
                        actual
                            .map(|a| condition(a, entity))
                            .unwrap_or(Truth::Unknown),
                    );
                    if entity.tag == "evr" && entity.a("operation") == "less than" {
                        fixed = Some(entity.text.clone());
                    }
                }
                state_outcomes.push(if s.a("operator").is_empty() || s.a("operator") == "AND" {
                    combine(&checks, false)
                } else if s.a("operator") == "OR" {
                    combine(&checks, true)
                } else {
                    Truth::Unknown
                });
            }
            let mut truth = if states.is_empty() {
                Truth::Yes
            } else if test.a("state_operator").is_empty() || test.a("state_operator") == "AND" {
                combine(&state_outcomes, false)
            } else if test.a("state_operator") == "OR" {
                combine(&state_outcomes, true)
            } else {
                Truth::Unknown
            };
            if pkg.as_ref().is_some_and(|p| p.status != "installed") {
                truth = Truth::Unknown;
            }
            if test.a("uncertain") == "true" && truth != Truth::No {
                truth = Truth::Unknown;
            }
            if truth != Truth::No {
                if let Some(p) = pkg {
                    hits.push(Hit {
                        source: p.source,
                        binary: format!("{}:{}", p.name, p.arch),
                        installed: p.version,
                        fixed,
                        unknown: truth == Truth::Unknown,
                    });
                } else if ["variable_test", "uname_test"].contains(&test.tag.as_str()) {
                    for p in self.packages.iter().filter(|p| {
                        p.name == format!("linux-image-{}", self.metadata.kernel)
                            || p.name == format!("linux-image-unsigned-{}", self.metadata.kernel)
                    }) {
                        hits.push(Hit {
                            source: p.source.clone(),
                            binary: format!("{}:{}", p.name, p.arch),
                            installed: p.version.clone(),
                            fixed: None,
                            unknown: truth == Truth::Unknown,
                        });
                    }
                }
            }
            outcomes.push(truth);
        }
        let truth = match test.a("check") {
            "" | "all" => combine(&outcomes, false),
            "at least one" => combine(&outcomes, true),
            "none satisfy" => match combine(&outcomes, true) {
                Truth::Yes => Truth::No,
                Truth::No => Truth::Yes,
                Truth::Unknown => Truth::Unknown,
            },
            "only one" => {
                if outcomes.contains(&Truth::Unknown) {
                    Truth::Unknown
                } else if outcomes.iter().filter(|v| **v == Truth::Yes).count() == 1 {
                    Truth::Yes
                } else {
                    Truth::No
                }
            }
            _ => Truth::Unknown,
        };
        if truth == Truth::No {
            hits.clear();
        }
        if truth == Truth::Unknown {
            for h in &mut hits {
                h.unknown = true;
            }
        }
        Ok(Evaluation { truth, hits })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn xml(criteria: &str) -> String {
        format!(
            r#"<oval_definitions><definitions><definition id="oval:test:def:1" class="vulnerability"><metadata><reference source="CVE" ref_id="CVE-2025-1000"/><advisory><severity>Critical</severity></advisory></metadata>{criteria}</definition></definitions><tests><dpkginfo_test id="oval:test:tst:1" check="at least one"><object object_ref="oval:test:obj:1"/><state state_ref="oval:test:ste:1"/></dpkginfo_test><file_test id="oval:test:tst:2"><object object_ref="oval:test:obj:2"/></file_test></tests><objects><dpkginfo_object id="oval:test:obj:1"><name>openssl</name></dpkginfo_object><file_object id="oval:test:obj:2"><filepath>/etc/shadow</filepath></file_object></objects><states><dpkginfo_state id="oval:test:ste:1"><evr datatype="debian_evr_string" operation="less than">3.0.1-1</evr></dpkginfo_state></states></oval_definitions>"#
        )
    }
    #[test]
    fn and_or_negation_and_unsupported_condition() {
        let dir = tempfile::tempdir().unwrap();
        let meta = Metadata {
            distro: "ubuntu".into(),
            release: "noble".into(),
            version: "24.04".into(),
            architecture: "x86_64".into(),
            kernel: "6.8.0".into(),
        };
        let packages = vec![crate::packages::tests::package()];
        for (n, criteria, expected) in [
            (
                0,
                r#"<criteria><criterion test_ref="oval:test:tst:1"/></criteria>"#,
                Truth::Yes,
            ),
            (
                1,
                r#"<criteria operator="AND"><criterion test_ref="oval:test:tst:1"/><criterion test_ref="oval:test:tst:2"/></criteria>"#,
                Truth::Unknown,
            ),
            (
                2,
                r#"<criteria operator="OR"><criterion test_ref="oval:test:tst:1"/><criterion test_ref="oval:test:tst:2"/></criteria>"#,
                Truth::Yes,
            ),
            (
                3,
                r#"<criteria negate="true"><criterion test_ref="oval:test:tst:1"/></criteria>"#,
                Truth::No,
            ),
            (
                4,
                r#"<criteria><criterion test_ref="oval:test:tst:1" comment="might be affected and may need fixing"/></criteria>"#,
                Truth::Unknown,
            ),
        ] {
            let path = dir.path().join(format!("{n}.sqlite"));
            prepare(std::io::Cursor::new(xml(criteria)), &path).unwrap();
            let db = Connection::open(path).unwrap();
            let mut evaluator = Evaluator::new(&db, &meta, &packages);
            let result = evaluator.definition("oval:test:def:1").unwrap();
            assert_eq!(result.truth, expected);
            if expected == Truth::No {
                assert!(result.hits.is_empty());
            } else {
                assert_eq!(result.hits.len(), 1);
                assert_eq!(result.hits[0].unknown, expected == Truth::Unknown);
            }
        }
    }
    #[test]
    fn fixed_backport_and_external_entities() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("feed");
        assert!(prepare(
            std::io::Cursor::new(
                "<!DOCTYPE foo [<!ENTITY secret SYSTEM 'file:///etc/shadow'>]><foo>&secret;</foo>"
            ),
            &path
        )
        .is_err());
        let n = Node {
            attrs: BTreeMap::from([
                ("datatype".into(), "debian_evr_string".into()),
                ("operation".into(), "less than".into()),
            ]),
            text: "1.0-1+deb12u2".into(),
            ..Node::default()
        };
        assert_eq!(condition("1.0-1+deb12u3", &n), Truth::No);
    }
    #[test]
    fn only_critical_and_relevant_dependencies_are_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let criteria = r#"<criteria><criterion test_ref="oval:test:tst:1"/></criteria>"#;
        for (name, input, scope) in [
            ("low", xml(criteria).replace("Critical", "High"), None),
            (
                "uninstalled",
                xml(criteria),
                Some(BTreeSet::from(["curl".into()])),
            ),
        ] {
            let path = dir.path().join(name);
            prepare_scoped(std::io::Cursor::new(input), &path, scope.as_ref()).unwrap();
            let db = Connection::open(path).unwrap();
            assert_eq!(
                db.query_row("SELECT count(*) FROM definitions", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
            assert_eq!(
                db.query_row("SELECT count(*) FROM nodes", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }
    #[test]
    fn unsupported_selector_is_unknown_not_an_empty_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("feed");
        let input = xml(r#"<criteria><criterion test_ref="oval:test:tst:1"/></criteria>"#).replace(
            "<name>openssl</name>",
            r#"<name operation="pattern match">(?=openssl)</name>"#,
        );
        prepare(std::io::Cursor::new(input), &path).unwrap();
        let db = Connection::open(path).unwrap();
        let meta = Metadata {
            distro: "ubuntu".into(),
            release: "noble".into(),
            version: "24.04".into(),
            architecture: "x86_64".into(),
            kernel: "6.8".into(),
        };
        let packages = vec![crate::packages::tests::package()];
        assert_eq!(
            Evaluator::new(&db, &meta, &packages)
                .definition("oval:test:def:1")
                .unwrap()
                .truth,
            Truth::Unknown
        );
    }
    #[test]
    #[ignore = "Explicit downloaded official feed acceptance; set CYBERBOT_OVAL_FIXTURE"]
    fn official_feed() {
        let input = std::env::var("CYBERBOT_OVAL_FIXTURE").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let start = std::time::Instant::now();
        let decoder = bzip2::read::BzDecoder::new(std::fs::File::open(input).unwrap());
        let path = dir.path().join("index.sqlite");
        prepare(std::io::BufReader::new(decoder), &path).unwrap();
        let db = Connection::open(&path).unwrap();
        let count: i64 = db
            .query_row("SELECT count(*) FROM definitions", [], |r| r.get(0))
            .unwrap();
        assert!(count > 0);
        assert!(count < 1000);
        println!(
            "official OVAL: {count} definitions, {} bytes, {} ms",
            std::fs::metadata(path).unwrap().len(),
            start.elapsed().as_millis()
        );
    }
}
