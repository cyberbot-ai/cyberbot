//! Bounded operational journal. Only structured, non-secret metadata is accepted.
//! Three append-only segments together never exceed LIMIT; no SQLite/WAL growth.
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    fs::{File, OpenOptions},
    future::Future,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock, RwLock,
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

pub const LIMIT: u64 = 30 * 1024 * 1024;
const MAX_RECORD: usize = 2048;
const MAX_POLL_RECORD: usize = 8192;
const BLOCK: u64 = 65536;
const SCAN_LIMIT: u64 = 2 * 1024 * 1024;
static GLOBAL: OnceLock<Result<Arc<Journal>, String>> = OnceLock::new();
static LOST: AtomicU64 = AtomicU64::new(0);
tokio::task_local! { static POLL_TRANSPORT: (); }
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn clean(value: &str, limit: usize) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .scan(0usize, |size, c| {
            *size += c.len_utf8();
            (*size <= limit).then_some(c)
        })
        .collect()
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ServerContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    pub address: String,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ActionAudit {
    pub request_id: String,
    pub artifact_hash: String,
    pub rules: String,
    pub provider: String,
    pub model: String,
    pub effort: String,
    pub state: String,
    pub tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub goal: Option<String>,
}
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum PollTransport {
    Completed,
    Failed,
    NoResults,
    Interrupted,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PollCheck {
    pub definition_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    pub succeeded: bool,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PollAudit {
    pub trigger: String,
    pub version: String,
    pub revision: i64,
    pub transport: PollTransport,
    pub checks: Vec<PollCheck>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_action: Option<ActionAudit>,
    pub id: String,
    pub at: u64,
    pub category: String,
    pub action: String,
    pub phase: String,
    pub operation_id: String,
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<ServerContext>,
    pub run_id: Option<String>,
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitoring: Option<crate::monitoring::Execution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) poll: Option<PollAudit>,
}

impl Event {
    fn limit(&self) -> usize {
        if self.poll.is_some() {
            MAX_POLL_RECORD
        } else {
            MAX_RECORD
        }
    }

    fn matches_definition(&self, id: &str) -> bool {
        self.monitoring
            .as_ref()
            .is_some_and(|m| m.definition_id == id)
            || self
                .poll
                .as_ref()
                .is_some_and(|poll| poll.checks.iter().any(|check| check.definition_id == id))
    }
}
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub bytes: u64,
    pub limit_bytes: u64,
    pub dropped: u64,
    pub error: Option<String>,
}
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    pub before: Option<String>,
    pub definition_id: Option<String>,
    pub category: Option<String>,
    pub phase: Option<String>,
    pub search: Option<String>,
}
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    pub events: Vec<Event>,
    pub next: Option<String>,
    pub expired: bool,
    pub skipped: usize,
    pub storage: Status,
}
struct Segment {
    id: u64,
    path: PathBuf,
    bytes: u64,
}
struct Writer {
    segments: VecDeque<Segment>,
    file: Option<File>,
    error: Option<String>,
}
#[derive(Default)]
struct ServerIndex {
    by_id: HashMap<String, ServerContext>,
    by_address: HashMap<String, Option<String>>,
}
pub struct Journal {
    dir: PathBuf,
    segment_limit: u64,
    writer: Mutex<Writer>,
    servers: RwLock<ServerIndex>,
}
impl Journal {
    pub fn open(dir: &Path) -> Result<Self, String> {
        Self::with_limit(dir, LIMIT)
    }
    fn with_limit(dir: &Path, limit: u64) -> Result<Self, String> {
        if limit < 3 * MAX_RECORD as u64 {
            return Err("The activity log size limit is too small".into());
        }
        std::fs::create_dir_all(dir).map_err(err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(err)?;
        }
        let mut segments = Vec::new();
        for entry in std::fs::read_dir(dir).map_err(err)? {
            let entry = entry.map_err(err)?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.len() != 26 || !name.ends_with(".jsonl") {
                continue;
            }
            let Ok(id) = name[..20].parse::<u64>() else {
                continue;
            };
            let meta = std::fs::symlink_metadata(entry.path()).map_err(err)?;
            if !meta.is_file() {
                return Err("Invalid activity log file".into());
            }
            if meta.len() > limit / 3 {
                std::fs::remove_file(entry.path()).map_err(err)?;
                continue;
            }
            segments.push(Segment {
                id,
                path: entry.path(),
                bytes: meta.len(),
            });
        }
        segments.sort_by_key(|s| s.id);
        let mut segments: VecDeque<_> = segments.into();
        while segments.len() > 3 {
            std::fs::remove_file(&segments.pop_front().unwrap().path).map_err(err)?;
        }
        // A killed writer can leave an incomplete final line. Never join it to a new record.
        if let Some(last) = segments.back_mut() {
            if last.bytes > 0 {
                let mut f = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&last.path)
                    .map_err(err)?;
                let start = last.bytes.saturating_sub(MAX_POLL_RECORD as u64);
                f.seek(SeekFrom::Start(start)).map_err(err)?;
                let mut tail = Vec::new();
                f.read_to_end(&mut tail).map_err(err)?;
                let valid = tail
                    .iter()
                    .rposition(|b| *b == b'\n')
                    .map_or(0, |i| start + i as u64 + 1);
                f.set_len(valid).map_err(err)?;
                last.bytes = valid;
            }
        }
        Ok(Self {
            dir: dir.into(),
            segment_limit: limit / 3,
            servers: RwLock::new(ServerIndex::default()),
            writer: Mutex::new(Writer {
                segments,
                file: None,
                error: None,
            }),
        })
    }
    fn set_servers(&self, servers: &[crate::model::Server]) {
        let mut contexts = ServerIndex::default();
        for server in servers {
            let address = crate::ssh::target(&server.endpoint);
            contexts
                .by_address
                .entry(address.clone())
                .and_modify(|entry| *entry = None)
                .or_insert_with(|| Some(server.id.clone()));
            contexts.by_id.insert(
                server.id.clone(),
                ServerContext {
                    id: Some(server.id.clone()),
                    name: clean(&server.name, 160),
                    address: clean(&address, 240),
                },
            );
        }
        if let Ok(mut current) = self.servers.write() {
            // Only the current inventory is retained in memory, never an unbounded archive.
            *current = contexts;
        }
    }
    fn enrich(&self, event: &mut Event) {
        if event.server.is_some() {
            return;
        }
        if let Ok(servers) = self.servers.read() {
            let target = event.target.as_deref().unwrap_or_default();
            let id = event
                .monitoring
                .as_ref()
                .and_then(|monitoring| monitoring.server_id.as_deref());
            event.server = if let Some(id) = id {
                servers.by_id.get(id)
            } else {
                servers.by_id.get(target).or_else(|| {
                    if !matches!(event.category.as_str(), "ssh" | "server") {
                        return None;
                    }
                    let id = servers.by_address.get(target)?.as_ref()?;
                    servers.by_id.get(id)
                })
            }
            .cloned();
        }
    }
    pub fn status(&self) -> Status {
        match self.writer.lock() {
            Ok(w) => Status {
                bytes: w.segments.iter().map(|s| s.bytes).sum(),
                limit_bytes: self.segment_limit * 3,
                dropped: LOST.load(Ordering::Relaxed),
                error: w.error.clone(),
            },
            Err(_) => Status {
                bytes: 0,
                limit_bytes: self.segment_limit * 3,
                dropped: LOST.load(Ordering::Relaxed),
                error: Some("Activity log unavailable".into()),
            },
        }
    }
    fn append(&self, mut event: Event) -> Result<(), String> {
        self.enrich(&mut event);
        let mut w = self.writer.lock().map_err(err)?;
        if w.error.is_some() {
            return Err("Activity logging paused after an error. Restart Cyberbot.".into());
        }
        let result = (|| {
            let limit = event.limit();
            if w.segments
                .back()
                .is_none_or(|s| s.bytes + limit as u64 > self.segment_limit)
            {
                w.file = None;
                while w.segments.len() >= 3 {
                    let old = w.segments.front().unwrap();
                    std::fs::remove_file(&old.path).map_err(err)?;
                    w.segments.pop_front();
                }
                let id = millis().max(w.segments.back().map_or(1, |s| s.id.saturating_add(1)));
                let path = self.dir.join(format!("{id:020}.jsonl"));
                let mut options = OpenOptions::new();
                options.create_new(true).append(true).read(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let file = options.open(&path).map_err(err)?;
                w.segments.push_back(Segment { id, path, bytes: 0 });
                w.file = Some(file);
            }
            let segment = w.segments.back().ok_or("No log segment")?;
            event.id = format!("{}:{}", segment.id, segment.bytes);
            event.category = clean(&event.category, 32);
            event.action = clean(&event.action, 80);
            event.operation_id = clean(&event.operation_id, 64);
            event.target = event.target.map(|s| clean(&s, 320));
            if let Some(server) = &mut event.server {
                server.name = clean(&server.name, 160);
                server.address = clean(&server.address, 240);
                if server.id.as_deref() == event.target.as_deref()
                    || server.id.as_deref()
                        == event
                            .monitoring
                            .as_ref()
                            .and_then(|m| m.server_id.as_deref())
                {
                    server.id = None;
                }
            }
            event.run_id = event.run_id.map(|s| clean(&s, 64));
            let mut line = serde_json::to_vec(&event).map_err(err)?;
            line.push(b'\n');
            if line.len() > limit || line.len() as u64 > self.segment_limit {
                return Err("The event exceeds the activity log size limit".into());
            }
            if w.file.is_none() {
                w.file = Some(
                    OpenOptions::new()
                        .append(true)
                        .open(&segment.path)
                        .map_err(err)?,
                );
            }
            let before = w.segments.back().unwrap().bytes;
            if let Err(e) = w.file.as_mut().unwrap().write_all(&line) {
                let _ = w.file.as_ref().unwrap().set_len(before);
                return Err(e.to_string());
            }
            w.segments.back_mut().unwrap().bytes += line.len() as u64;
            Ok(())
        })();
        if result.is_err() {
            w.error = Some("Could not write to the activity log. Some events were skipped.".into());
        }
        result
    }
    pub fn page(&self, query: Query) -> Result<Page, String> {
        if let Some(id) = &query.definition_id {
            crate::monitoring::definition(id)?;
        }
        if query.search.as_ref().is_some_and(|s| s.len() > 200) {
            return Err("Enter a search term of up to 200 bytes".into());
        }
        if query
            .category
            .as_deref()
            .is_some_and(|v| !matches!(v, "ssh" | "server" | "ai" | "mcp" | "process" | "app"))
            || query.phase.as_deref().is_some_and(|v| {
                !matches!(
                    v,
                    "started" | "completed" | "failed" | "cancelled" | "interrupted" | "info"
                )
            })
        {
            return Err("Unknown activity log filter".into());
        }
        let cursor = query
            .before
            .as_deref()
            .map(|s| {
                if s.len() > 48 {
                    return Err("Invalid activity log cursor".to_string());
                }
                let (a, b) = s.split_once(':').ok_or("Invalid activity log cursor")?;
                Ok((
                    a.parse::<u64>().map_err(err)?,
                    b.parse::<u64>().map_err(err)?,
                ))
            })
            .transpose()?;
        let mut events = Vec::new();
        let mut skipped = 0;
        let mut read = 0;
        // Rotation waits for this bounded read, so deleted-but-open segments cannot exceed the disk ceiling.
        let w = self.writer.lock().map_err(err)?;
        let files = w
            .segments
            .iter()
            .map(|s| Ok((s.id, s.bytes, File::open(&s.path).map_err(err)?)))
            .collect::<Result<Vec<_>, String>>()?;
        let oldest = files.first().map(|s| s.0);
        let mut next = None;
        let expired = cursor.is_some_and(|(id, _)| !files.iter().any(|s| s.0 == id));
        if !expired {
            let search = query.search.as_deref().unwrap_or("").to_lowercase();
            'segments: for (id, size, mut file) in files.into_iter().rev() {
                if cursor.is_some_and(|(c, _)| id > c) {
                    continue;
                }
                let mut before = cursor
                    .filter(|(c, _)| *c == id)
                    .map_or(size, |(_, n)| n.min(size));
                while before > 0 {
                    let start = before.saturating_sub(BLOCK);
                    file.seek(SeekFrom::Start(start)).map_err(err)?;
                    let mut bytes = vec![0; (before - start) as usize];
                    file.read_exact(&mut bytes).map_err(err)?;
                    read += bytes.len() as u64;
                    let first = if start == 0 {
                        0
                    } else {
                        bytes
                            .iter()
                            .position(|b| *b == b'\n')
                            .map_or(bytes.len(), |n| n + 1)
                    };
                    let mut offset = before;
                    for line in bytes[first..].split_inclusive(|b| *b == b'\n').rev() {
                        offset -= line.len() as u64;
                        if line.len() > MAX_POLL_RECORD {
                            skipped += 1;
                            continue;
                        }
                        let Ok(mut event) = serde_json::from_slice::<Event>(line) else {
                            skipped += 1;
                            continue;
                        };
                        if line.len() > event.limit() {
                            skipped += 1;
                            continue;
                        }
                        // Old records stored only an ID; resolve those without rewriting segments.
                        self.enrich(&mut event);
                        if query
                            .definition_id
                            .as_ref()
                            .is_none_or(|id| event.matches_definition(id))
                            && query.category.as_ref().is_none_or(|c| c == &event.category)
                            && query.phase.as_ref().is_none_or(|p| p == &event.phase)
                            && (search.is_empty()
                                || format!(
                                    "{} {} {} {} {} {} {} {}",
                                    event.action,
                                    event.target.as_deref().unwrap_or(""),
                                    event.server.as_ref().map_or("", |s| s.name.as_str()),
                                    event.server.as_ref().map_or("", |s| s.address.as_str()),
                                    event.operation_id,
                                    event.run_id.as_deref().unwrap_or(""),
                                    event
                                        .server
                                        .as_ref()
                                        .and_then(|s| s.id.as_deref())
                                        .unwrap_or(""),
                                    event
                                        .monitoring
                                        .as_ref()
                                        .and_then(|m| m.server_id.as_deref())
                                        .unwrap_or("")
                                )
                                .to_lowercase()
                                .contains(&search))
                        {
                            events.push(event);
                        }
                        if events.len() == 100 {
                            next = (offset > 0 || Some(id) != oldest)
                                .then(|| format!("{id}:{offset}"));
                            break 'segments;
                        }
                    }
                    let older = start + first as u64;
                    if older >= before {
                        skipped += 1;
                        before = start;
                    } else {
                        before = older;
                    }
                    if read >= SCAN_LIMIT {
                        next = (before > 0 || Some(id) != oldest).then(|| format!("{id}:{before}"));
                        break 'segments;
                    }
                }
            }
        }
        Ok(Page {
            events,
            next,
            expired,
            skipped,
            storage: Status {
                bytes: w.segments.iter().map(|s| s.bytes).sum(),
                limit_bytes: self.segment_limit * 3,
                dropped: LOST.load(Ordering::Relaxed),
                error: w.error.clone(),
            },
        })
    }
}

pub fn install(root: &Path, servers: &[crate::model::Server]) {
    let _ = GLOBAL.set(Journal::open(&root.join("activity")).map(|journal| {
        journal.set_servers(servers);
        Arc::new(journal)
    }));
    info("app", "startup", None);
}
pub fn set_servers(servers: &[crate::model::Server]) {
    if let Some(Ok(journal)) = GLOBAL.get() {
        journal.set_servers(servers);
    }
}
pub fn status() -> Status {
    match GLOBAL.get() {
        Some(Ok(journal)) => journal.status(),
        Some(Err(_)) => Status {
            bytes: 0,
            limit_bytes: LIMIT,
            dropped: LOST.load(Ordering::Relaxed),
            error: Some("Could not write to the activity log".into()),
        },
        None => Status {
            bytes: 0,
            limit_bytes: LIMIT,
            dropped: 0,
            error: None,
        },
    }
}
pub fn page(query: Query) -> Result<Page, String> {
    GLOBAL
        .get()
        .ok_or("Activity logging is inactive")?
        .as_ref()
        .map_err(Clone::clone)?
        .page(query)
}
fn record(event: Event) {
    if let Some(journal) = GLOBAL.get() {
        if journal.as_ref().is_err() || journal.as_ref().is_ok_and(|j| j.append(event).is_err()) {
            LOST.fetch_add(1, Ordering::Relaxed);
        }
    }
}
pub fn info(category: &str, action: &str, target: Option<String>) {
    if !poll_transport_event(category) {
        record(new_event(category, action, target, "info"));
    }
}

pub(crate) async fn poll_transport<F: Future>(run: F) -> F::Output {
    POLL_TRANSPORT.scope((), run).await
}

fn poll_transport_event(category: &str) -> bool {
    matches!(category, "ssh" | "server") && POLL_TRANSPORT.try_with(|_| ()).is_ok()
}

fn new_event(category: &str, action: &str, target: Option<String>, phase: &str) -> Event {
    Event {
        ai_action: None,
        id: String::new(),
        at: millis(),
        category: category.into(),
        action: action.into(),
        phase: phase.into(),
        operation_id: uuid::Uuid::new_v4().to_string(),
        target,
        server: None,
        run_id: None,
        duration_ms: None,
        monitoring: crate::monitoring::context(),
        poll: None,
    }
}
pub(crate) fn action(request: &crate::ai_actions::Request, phase: &str) {
    record(Event {
        ai_action: Some(ActionAudit {
            request_id: request.id.clone(),
            artifact_hash: if request.artifact_hash.is_empty() {
                request.intent_hash.clone()
            } else {
                request.artifact_hash.clone()
            },
            rules: request.artifact.rules.clone(),
            provider: request.artifact.provider.clone(),
            model: request
                .review
                .as_ref()
                .and_then(|r| r.model.clone())
                .unwrap_or_else(|| request.artifact.profile.low.model.clone()),
            effort: request.artifact.profile.low.effort.clone(),
            state: request.state.clone(),
            tokens: request.review.as_ref().map(|r| r.tokens),
            goal: matches!(
                request.artifact.spec.action,
                crate::ai_actions::Action::Shell
            )
            .then(|| clean(&request.artifact.spec.goal, 240)),
        }),
        id: String::new(),
        at: millis(),
        category: "ai".into(),
        action: phase.into(),
        phase: "info".into(),
        operation_id: uuid::Uuid::new_v4().to_string(),
        target: Some(request.server_id.clone()),
        server: None,
        run_id: Some(request.run_id.clone()),
        duration_ms: request.review.as_ref().map(|r| r.duration_ms),
        monitoring: None,
        poll: None,
    });
}
pub struct Span {
    event: Option<Event>,
    start: Instant,
    sink: Option<Arc<Journal>>,
}
pub fn id_target(value: &str) -> Option<String> {
    ((value.len() == 24 && value.bytes().all(|c| c.is_ascii_hexdigit()))
        || uuid::Uuid::parse_str(value).is_ok())
    .then(|| value.to_owned())
}

pub fn begin(category: &str, action: &str, target: Option<String>) -> Span {
    begin_run(category, action, target, None)
}
pub fn begin_run(
    category: &str,
    action: &str,
    target: Option<String>,
    run_id: Option<String>,
) -> Span {
    if poll_transport_event(category) {
        return Span {
            event: None,
            start: Instant::now(),
            sink: None,
        };
    }
    Span::new(sink(), category, action, target, run_id)
}

fn sink() -> Option<Arc<Journal>> {
    GLOBAL.get().and_then(|g| g.as_ref().ok()).cloned()
}

impl Span {
    fn new(
        sink: Option<Arc<Journal>>,
        category: &str,
        action: &str,
        target: Option<String>,
        run_id: Option<String>,
    ) -> Self {
        let mut event = new_event(category, action, target, "started");
        event.run_id = run_id;
        let span = Self::capture(sink, event, Instant::now());
        span.write(span.event.as_ref().unwrap().clone());
        span
    }

    fn capture(sink: Option<Arc<Journal>>, mut event: Event, start: Instant) -> Self {
        if let Some(log) = &sink {
            // Keep both phases tied to the original endpoint, even if inventory changes mid-run.
            log.enrich(&mut event);
        }
        Self {
            event: Some(event),
            start,
            sink,
        }
    }
    fn write(&self, event: Event) {
        if let Some(log) = &self.sink {
            if log.append(event).is_err() {
                LOST.fetch_add(1, Ordering::Relaxed);
            }
        } else if GLOBAL.get().is_some() {
            LOST.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn finish(&mut self, phase: &str) {
        if let Some(mut e) = self.event.take() {
            e.at = millis();
            e.phase = phase.into();
            e.duration_ms = Some(self.start.elapsed().as_millis() as u64);
            self.write(e);
        }
    }
    pub fn finish_as(&mut self, phase: &str, action: &'static str) {
        if let Some(event) = &mut self.event {
            event.action = action.into();
        }
        self.finish(phase);
    }
    pub fn result<T>(&mut self, result: &Result<T, String>) {
        self.finish(if result.is_ok() {
            "completed"
        } else {
            "failed"
        });
    }
}

pub(crate) struct PollSpan(Span);

impl PollSpan {
    pub(crate) fn begin(
        server: &crate::model::Server,
        execution: &crate::monitoring::Execution,
        start: Instant,
    ) -> Self {
        Self::new(sink(), server, execution, start)
    }

    fn new(
        sink: Option<Arc<Journal>>,
        server: &crate::model::Server,
        execution: &crate::monitoring::Execution,
        start: Instant,
    ) -> Self {
        let mut event = new_event("server", "poll", Some(server.id.clone()), "interrupted");
        event.server = Some(ServerContext {
            id: None,
            name: server.name.clone(),
            address: crate::ssh::target(&server.endpoint),
        });
        event.poll = Some(PollAudit {
            trigger: execution.trigger.clone(),
            version: execution.version.clone(),
            revision: execution.revision,
            transport: PollTransport::Interrupted,
            checks: Vec::new(),
        });
        Self(Span::capture(sink, event, start))
    }

    pub(crate) fn finish(mut self, transport: PollTransport, checks: Vec<PollCheck>) {
        if let Some(audit) = self.0.event.as_mut().and_then(|event| event.poll.as_mut()) {
            let phase = if transport == PollTransport::Completed
                && checks.iter().all(|check| check.succeeded)
            {
                "completed"
            } else {
                "failed"
            };
            audit.transport = transport;
            audit.checks = checks;
            self.0.finish(phase);
        }
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        self.finish("interrupted");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(n: u64, category: &str) -> Event {
        Event {
            ai_action: None,
            id: String::new(),
            at: 1_700_000_000_000 + n,
            category: category.into(),
            action: format!("operation-{n}"),
            phase: if n % 2 == 0 { "completed" } else { "failed" }.into(),
            operation_id: format!("op-{n}"),
            target: Some("ops@host:22".into()),
            server: None,
            run_id: None,
            duration_ms: Some(n),
            monitoring: None,
            poll: None,
        }
    }
    fn disk(dir: &Path) -> u64 {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().metadata().unwrap().len())
            .sum()
    }

    #[test]
    fn each_poll_writes_one_terminal_event_and_matches_its_checks() {
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Journal::open(dir.path()).unwrap());
        let server = server();
        let execution = crate::monitoring::Execution {
            definition_id: "metrics".into(),
            version: "version".into(),
            trigger: "manual".into(),
            instance_id: None,
            server_id: Some(server.id.clone()),
            revision: 42,
        };
        let start = || PollSpan::new(Some(log.clone()), &server, &execution, Instant::now());
        let redis = |succeeded| PollCheck {
            definition_id: "redis".into(),
            instance_id: Some("default".into()),
            succeeded,
        };
        start().finish(PollTransport::Completed, vec![redis(true)]);
        start().finish(PollTransport::Completed, vec![redis(false)]);
        start().finish(PollTransport::Failed, vec![redis(true)]);
        drop(start());

        let page = log.page(Query::default()).unwrap();
        let phases: Vec<_> = page.events.iter().map(|e| e.phase.as_str()).collect();
        assert_eq!(phases, ["interrupted", "failed", "failed", "completed"]);
        assert!(page
            .events
            .iter()
            .all(|e| e.action == "poll" && e.duration_ms.is_some()));
        assert_eq!(
            page.events[0].poll.as_ref().unwrap().transport,
            PollTransport::Interrupted
        );
        assert_eq!(
            page.events[1].poll.as_ref().unwrap().transport,
            PollTransport::Failed
        );

        let filtered = log
            .page(Query {
                definition_id: Some("redis".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(filtered.events.len(), 3);
        let partial = filtered.events[1].poll.as_ref().unwrap();
        assert_eq!(partial.trigger, "manual");
        assert_eq!(partial.transport, PollTransport::Completed);
        assert!(!partial.checks[0].succeeded);
    }

    #[test]
    fn a_large_poll_fits_the_log_and_survives_partial_tail_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(Journal::open(dir.path()).unwrap());
        let mut server = server();
        server.name = "\"".repeat(160);
        server.endpoint.host = "\\".repeat(240);
        let execution = crate::monitoring::Execution {
            definition_id: "metrics".into(),
            version: "a".repeat(24),
            trigger: "after_action".into(),
            instance_id: None,
            server_id: Some(server.id.clone()),
            revision: i64::MAX,
        };
        let checks = (0..68)
            .map(|i| PollCheck {
                definition_id: "clickhouse".into(),
                instance_id: Some(format!("00000000-0000-0000-0000-{i:012}")),
                succeeded: false,
            })
            .collect();
        PollSpan::new(Some(log.clone()), &server, &execution, Instant::now())
            .finish(PollTransport::Failed, checks);
        let size = disk(dir.path());
        assert!(size > MAX_RECORD as u64 && size <= MAX_POLL_RECORD as u64);
        drop(log);
        let segment = std::fs::read_dir(dir.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        OpenOptions::new()
            .append(true)
            .open(segment)
            .unwrap()
            .write_all(&vec![b'x'; MAX_POLL_RECORD - 1])
            .unwrap();
        let log = Journal::open(dir.path()).unwrap();
        assert_eq!(disk(dir.path()), size);
        let page = log.page(Query::default()).unwrap();
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].poll.as_ref().unwrap().checks.len(), 68);
    }
    fn server() -> crate::model::Server {
        crate::model::Server {
            id: "57add7696be9440cd8ef78b4".into(),
            source_id: "test-source".into(),
            name: "db.production".into(),
            endpoint: crate::model::Endpoint {
                host: "10.20.1.11".into(),
                user: "ops".into(),
                port: 2222,
                identity_file: Some("/private/secret-key-path-canary".into()),
                jump_host: None,
                known_hosts_file: Some("/private/secret-trust-path-canary".into()),
            },
            observation: None,
            last_error: None,
            last_attempt: None,
            next_check: 0,
            failures: 0,
        }
    }
    #[test]
    fn legacy_ids_resolve_and_search_by_server_name_address_or_id_without_rewriting() {
        let temp = tempfile::tempdir().unwrap();
        let log = Journal::open(temp.path()).unwrap();
        let server = server();
        let mut e = event(1, "server");
        e.target = Some(server.id.clone());
        log.append(e).unwrap();
        let bytes = disk(temp.path());
        assert!(log.page(Query::default()).unwrap().events[0]
            .server
            .is_none());
        log.set_servers(&[server.clone()]);
        for search in ["DB.PRODUCTION", "10.20.1.11", "ops@", &server.id] {
            let page = log
                .page(Query {
                    search: Some(search.into()),
                    ..Default::default()
                })
                .unwrap();
            assert_eq!(page.events.len(), 1);
            let context = page.events[0].server.as_ref().unwrap();
            assert_eq!(context.name, server.name);
            assert_eq!(context.address, "ops@10.20.1.11:2222");
        }
        assert_eq!(disk(temp.path()), bytes);
        log.set_servers(&[]);
        assert!(log.servers.read().unwrap().by_id.is_empty());
        assert!(log.page(Query::default()).unwrap().events[0]
            .server
            .is_none());
        assert_eq!(
            log.page(Query::default()).unwrap().events[0]
                .target
                .as_ref(),
            Some(&server.id)
        );
    }
    #[test]
    fn ssh_addresses_link_only_when_unique_and_keep_the_captured_identity() {
        let temp = tempfile::tempdir().unwrap();
        let log = Journal::open(temp.path()).unwrap();
        let server = server();
        let mut second = server.clone();
        second.id = "another-server".into();
        let mut event = event(1, "ssh");
        event.target = Some(crate::ssh::target(&server.endpoint));
        log.append(event.clone()).unwrap();
        let bytes = disk(temp.path());
        log.set_servers(&[server.clone(), second.clone()]);
        assert!(log.page(Query::default()).unwrap().events[0]
            .server
            .is_none());

        log.set_servers(&[server.clone()]);
        let page = log
            .page(Query {
                search: Some(server.id.clone()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(page.events.len(), 1);
        assert_eq!(
            page.events[0].server.as_ref().unwrap().id.as_ref(),
            Some(&server.id)
        );
        assert_eq!(disk(temp.path()), bytes);

        log.append(event).unwrap();
        log.set_servers(&[second]);
        let page = log
            .page(Query {
                search: Some(server.id.clone()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(page.events.len(), 1);
        assert_eq!(
            page.events[0].server.as_ref().unwrap().id.as_ref(),
            Some(&server.id)
        );
    }
    #[test]
    fn captured_server_survives_rename_deletion_completion_and_restart() {
        let temp = tempfile::tempdir().unwrap();
        let log = Arc::new(Journal::open(temp.path()).unwrap());
        let mut server = server();
        log.set_servers(&[server.clone()]);
        let mut span = Span::new(
            Some(log.clone()),
            "mcp",
            "refresh_metrics",
            Some(server.id.clone()),
            None,
        );
        server.name = "renamed-db".into();
        server.endpoint.host = "10.20.1.12".into();
        log.set_servers(&[server.clone()]);
        let mut next = Span::new(
            Some(log.clone()),
            "server",
            "poll",
            Some(server.id.clone()),
            None,
        );
        log.set_servers(&[]);
        span.finish("completed");
        next.finish("failed");
        drop(span);
        drop(next);
        drop(log);
        let log = Journal::open(temp.path()).unwrap();
        for (search, expected, address) in [
            ("refresh_metrics", "db.production", "10.20.1.11"),
            ("poll", "renamed-db", "10.20.1.12"),
        ] {
            let page = log
                .page(Query {
                    search: Some(search.into()),
                    ..Default::default()
                })
                .unwrap();
            assert_eq!(page.events.len(), 2);
            for e in page.events {
                let context = e.server.unwrap();
                assert_eq!(context.name, expected);
                assert!(context.address.contains(address));
            }
        }
        let json = serde_json::to_string(&log.page(Query::default()).unwrap()).unwrap();
        assert!(!json.contains("secret-key-path-canary"));
        assert!(!json.contains("secret-trust-path-canary"));
    }
    #[test]
    fn server_metadata_stays_sanitized_and_within_the_existing_disk_cap() {
        let temp = tempfile::tempdir().unwrap();
        let limit = 24 * 1024;
        let log = Journal::with_limit(temp.path(), limit).unwrap();
        let mut server = server();
        server.name = "\"<long-name>\n".repeat(100);
        log.set_servers(&[server.clone()]);
        for n in 0..150 {
            let mut e = event(n, "app");
            e.target = Some(server.id.clone());
            log.append(e).unwrap();
            assert!(disk(temp.path()) <= limit);
        }
        let page = log.page(Query::default()).unwrap();
        assert_eq!(page.skipped, 0);
        assert!(page.storage.error.is_none());
        for e in page.events {
            let name = e.server.unwrap().name;
            assert!(name.len() <= 160);
            assert!(!name.chars().any(char::is_control));
        }
    }
    #[test]
    fn hard_cap_rotation_restart_and_private_files() {
        let temp = tempfile::tempdir().unwrap();
        let limit = 24 * 1024;
        let log = Journal::with_limit(temp.path(), limit).unwrap();
        for n in 0..600 {
            log.append(event(n, "ssh")).unwrap();
            assert!(disk(temp.path()) <= limit);
        }
        assert!(std::fs::read_dir(temp.path()).unwrap().count() <= 3);
        let first = log.page(Query::default()).unwrap();
        assert_eq!(first.events[0].action, "operation-599");
        assert!(!first.events.iter().any(|e| e.action == "operation-0"));
        let status = log.status();
        assert_eq!(status.bytes, disk(temp.path()));
        drop(log);
        let reopened = Journal::with_limit(temp.path(), limit).unwrap();
        assert_eq!(reopened.status().bytes, status.bytes);
        reopened.append(event(600, "ai")).unwrap();
        assert_eq!(
            reopened.page(Query::default()).unwrap().events[0].action,
            "operation-600"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(temp.path()).unwrap().permissions().mode() & 0o777,
                0o700
            );
            for file in std::fs::read_dir(temp.path()).unwrap() {
                assert_eq!(
                    file.unwrap().metadata().unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }
    #[test]
    fn stable_reverse_pagination_filters_and_expired_cursors() {
        let temp = tempfile::tempdir().unwrap();
        let log = Journal::with_limit(temp.path(), 300 * 1024).unwrap();
        for n in 0..350 {
            log.append(event(n, if n % 3 == 0 { "ai" } else { "ssh" }))
                .unwrap();
        }
        let first = log.page(Query::default()).unwrap();
        assert_eq!(first.events.len(), 100);
        let cursor = first.next.clone().unwrap();
        log.append(event(351, "ai")).unwrap();
        let second = log
            .page(Query {
                before: Some(cursor.clone()),
                ..Default::default()
            })
            .unwrap();
        let ids: std::collections::HashSet<_> = first
            .events
            .iter()
            .chain(&second.events)
            .map(|e| &e.id)
            .collect();
        assert_eq!(ids.len(), 200);
        assert_eq!(second.events[0].action, "operation-249");
        let filtered = log
            .page(Query {
                category: Some("ai".into()),
                phase: Some("failed".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(!filtered.events.is_empty());
        assert!(filtered
            .events
            .iter()
            .all(|e| e.category == "ai" && e.phase == "failed"));
        let found = log
            .page(Query {
                search: Some("op-300".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(found.events.len(), 1);
        assert!(log
            .page(Query {
                before: Some("../../secret".into()),
                ..Default::default()
            })
            .is_err());
        assert!(log
            .page(Query {
                category: Some("invalid".into()),
                ..Default::default()
            })
            .is_err());
        for n in 352..2200 {
            log.append(event(n, "ssh")).unwrap();
        }
        assert!(
            log.page(Query {
                before: Some(cursor),
                ..Default::default()
            })
            .unwrap()
            .expired
        );
    }
    #[test]
    fn partial_tail_recovers_without_joining_or_replaying_records() {
        let temp = tempfile::tempdir().unwrap();
        let log = Journal::open(temp.path()).unwrap();
        log.append(event(1, "app")).unwrap();
        log.append(event(2, "app")).unwrap();
        let path = log
            .writer
            .lock()
            .unwrap()
            .segments
            .back()
            .unwrap()
            .path
            .clone();
        let valid = log.status().bytes;
        drop(log);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"incomplete\":")
            .unwrap();
        let log = Journal::open(temp.path()).unwrap();
        assert_eq!(log.status().bytes, valid);
        log.append(event(3, "app")).unwrap();
        let page = log.page(Query::default()).unwrap();
        assert_eq!(page.events.len(), 3);
        assert_eq!(page.skipped, 0);
        assert_eq!(page.events[0].action, "operation-3");
    }
    #[test]
    fn spans_record_completion_failure_and_aborted_futures_without_payloads() {
        assert!(id_target("password=private").is_none());
        assert!(id_target("0123456789abcdef01234567").is_some());
        let temp = tempfile::tempdir().unwrap();
        let log = Arc::new(Journal::open(temp.path()).unwrap());
        {
            let mut span = Span::new(Some(log.clone()), "ai", "Codex", None, Some("run-1".into()));
            span.result(&Ok::<_, String>(()));
        }
        {
            let mut span = Span::new(Some(log.clone()), "mcp", "get_server", None, None);
            span.result(&Err::<(), _>("password=private; prompt=private".into()));
        }
        {
            let _span = Span::new(
                Some(log.clone()),
                "ssh",
                "SSH connection",
                Some("ops@host:22".into()),
                None,
            );
        }
        let page = log.page(Query::default()).unwrap();
        assert_eq!(page.events.len(), 6);
        assert_eq!(page.events[0].phase, "interrupted");
        assert_eq!(page.events[2].phase, "failed");
        assert_eq!(page.events[4].phase, "completed");
        for pair in page.events.chunks(2) {
            assert_eq!(pair[0].operation_id, pair[1].operation_id);
            assert!(pair[0].duration_ms.is_some());
        }
        assert!(!serde_json::to_string(&page.events)
            .unwrap()
            .contains("private"));
    }
    #[test]
    fn concurrent_writers_and_readers_remain_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let log = Arc::new(Journal::with_limit(temp.path(), 96 * 1024).unwrap());
        std::thread::scope(|scope| {
            for worker in 0..4 {
                let log = log.clone();
                scope.spawn(move || {
                    for n in 0..200 {
                        log.append(event(worker * 200 + n, "server")).unwrap();
                    }
                });
            }
            let log = log.clone();
            scope.spawn(move || {
                for _ in 0..40 {
                    assert!(log.page(Query::default()).unwrap().events.len() <= 100);
                }
            });
        });
        assert!(disk(temp.path()) <= 96 * 1024);
        assert_eq!(disk(temp.path()), log.status().bytes);
    }
    #[test]
    fn malformed_records_are_visible_as_gaps_and_failed_writes_stop_growth() {
        let temp = tempfile::tempdir().unwrap();
        let log = Journal::open(temp.path()).unwrap();
        log.append(event(1, "app")).unwrap();
        {
            let mut w = log.writer.lock().unwrap();
            w.file.as_mut().unwrap().write_all(b"not json\n").unwrap();
            w.segments.back_mut().unwrap().bytes += 9;
        }
        assert_eq!(log.page(Query::default()).unwrap().skipped, 1);
        {
            let mut w = log.writer.lock().unwrap();
            w.file = None;
            w.segments.back_mut().unwrap().path = temp.path().to_path_buf();
        }
        assert!(log.append(event(2, "app")).is_err());
        assert!(log.status().error.is_some());
        assert!(log.append(event(3, "app")).is_err());
    }
}

/// Explicit, local-only end-to-end fixture. Refuses nonempty/user data directories.
pub async fn smoke(root: &Path) -> Result<serde_json::Value, String> {
    std::fs::create_dir_all(root).map_err(err)?;
    if std::fs::read_dir(root).map_err(err)?.next().is_some() || GLOBAL.get().is_some() {
        return Err("A new empty catalog is needed to check the journal".into());
    }
    install(root, &[]);
    let output = crate::process::bounded(
        "/bin/echo",
        &["private-test-payload-never-journaled".into()],
        None,
        3,
        1024,
    )
    .await?;
    if !output.success {
        return Err("Test process not running".into());
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(err)?;
    let port = listener.local_addr().map_err(err)?.port();
    let accepted = Arc::new(AtomicU64::new(0));
    let observed = accepted.clone();
    let fixture = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        while let Ok((mut socket, _)) = listener.accept().await {
            observed.fetch_add(1, Ordering::Relaxed);
            let _ = socket.write_all(b"activity-fixture-not-ssh\n").await;
        }
    });
    let endpoint = crate::inventory::parse_manual(&format!("activity@127.0.0.1:{port}"))?
        .remove(0)
        .endpoint;
    let first = crate::ssh::isolated_activity_probe(&endpoint).await;
    let second = crate::ssh::isolated_activity_probe(&endpoint).await;
    fixture.abort();
    let _ = fixture.await;
    if accepted.load(Ordering::Relaxed) != 2 {
        return Err("SSH does not reach isolated loopback listener".into());
    }
    if first.is_ok() || second.is_ok() {
        return Err("The SSH test must end in error before authorization".into());
    }
    let initial = page(Query::default())?;
    if !initial
        .events
        .iter()
        .any(|e| e.category == "process" && e.phase == "completed")
        || !initial
            .events
            .iter()
            .any(|e| e.category == "ssh" && e.phase == "failed")
        || !initial
            .events
            .iter()
            .any(|e| e.category == "server" && e.phase == "failed")
    {
        return Err("Not all transactions made it to the journal".into());
    }
    if serde_json::to_string(&initial)
        .map_err(err)?
        .contains("private-test-payload")
    {
        return Err("The log got the payload of the process".into());
    }
    let start = Instant::now();
    for n in 0..65000 {
        info(
            "app",
            "journal_fixture",
            Some(format!("{n:06} {}", "x".repeat(300))),
        );
    }
    let status = status();
    let dir = root.join("activity");
    let mut bytes = 0;
    let mut files = 0;
    for file in std::fs::read_dir(dir).map_err(err)? {
        bytes += file.map_err(err)?.metadata().map_err(err)?.len();
        files += 1;
    }
    if bytes > LIMIT || files > 3 || status.bytes != bytes || status.error.is_some() {
        return Err("The log’s limit has been breached".into());
    }
    Ok(
        serde_json::json!({"status":"completed","sshAttempts":initial.events.iter().filter(|e|e.category=="ssh"&&e.phase=="started").count(),"privacy":true,"eventsGenerated":65000,"files":files,"bytes":bytes,"limitBytes":LIMIT,"rotationMs":start.elapsed().as_millis(),"pageEvents":page(Query::default())?.events.len()}),
    )
}
