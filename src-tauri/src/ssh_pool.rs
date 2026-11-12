//! Application-owned OpenSSH ControlMasters. No commands or sockets are exposed to MCP.
use crate::{activity, model::Endpoint, process, ssh, ssh_authorization};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    io::{self, ErrorKind, Read, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};
use tokio::sync::{Mutex as AsyncMutex, Notify, Semaphore};

pub const KEEPALIVE_SECONDS: u64 = 60;
pub const IDLE_SECONDS: u64 = 15 * 60;
pub const DEFAULT_LIMIT: usize = 32;
pub(crate) const INVENTORY_LIMIT: usize = 192;
const STARTUP_LIMIT: usize = 64;
const OPEN_LIMIT: usize = 16;
const WAIT_TIMEOUT: Duration = Duration::from_secs(25);
const MUX_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const MUX_MAINTENANCE_TIMEOUT: Duration = Duration::from_millis(200);
const MUX_RETRY_DELAYS_MS: [u64; 2] = [100, 250];
const OPEN_RETRY_DELAYS_MS: [u64; 2] = [500, 1000];
const SETTINGS_CHANGED: &str = "SSH: server or settings have changed";
const CONNECTION_SETTINGS_CHANGED: &str = "SSH settings have changed during connection";
const WITHDRAWN: &str = "SSH connection withdrawn";
static GLOBAL: OnceLock<Result<Pool, String>> = OnceLock::new();

pub fn install(pool: Pool) -> Result<(), String> {
    GLOBAL
        .set(Ok(pool))
        .map_err(|_| "The SSH pool is set up".into())
}

pub fn global() -> Result<&'static Pool, String> {
    GLOBAL
        .get_or_init(|| {
            Pool::with_capacity(Capacity::Inventory, Duration::from_secs(IDLE_SECONDS), None)
        })
        .as_ref()
        .map_err(Clone::clone)
}
pub fn shutdown_global() {
    if let Some(Ok(pool)) = GLOBAL.get() {
        pool.shutdown();
    }
}
pub fn reset_global() {
    if let Some(Ok(pool)) = GLOBAL.get() {
        pool.prune(|_| true, "SSH: recovery");
    }
}
#[cfg(target_os = "macos")]
pub(crate) fn resource_masters() -> Vec<crate::local_resources::ProcessIdentity> {
    GLOBAL
        .get()
        .and_then(|pool| pool.as_ref().ok())
        .map_or_else(Vec::new, Pool::resource_masters)
}
pub fn maintain_global(endpoints: &[Endpoint]) {
    if let Ok(pool) = global() {
        pool.retain(endpoints);
    }
}

#[derive(Clone)]
pub struct Pool(Arc<Inner>);

#[derive(Clone, Copy)]
enum Capacity {
    Fixed(usize),
    Inventory,
}

impl Capacity {
    fn limit(self, endpoints: usize) -> usize {
        match self {
            Self::Fixed(limit) => limit,
            Self::Inventory => endpoints.clamp(DEFAULT_LIMIT, INVENTORY_LIMIT),
        }
    }
}

struct Inner {
    root: PathBuf,
    capacity: Capacity,
    idle: Duration,
    config: Option<PathBuf>,
    state: Mutex<State>,
    changed: Notify,
    opening: Semaphore,
    opened: AtomicU64,
    reused: AtomicU64,
    evicted: AtomicU64,
    leases: AtomicUsize,
}
#[derive(Default)]
struct State {
    entries: HashMap<String, Arc<Entry>>,
    stopped: bool,
    allowed: Option<BTreeSet<String>>,
    startup_until: Option<Instant>,
}
impl State {
    fn limit(&self, capacity: Capacity) -> usize {
        let regular = capacity.limit(self.allowed.as_ref().map_or(0, BTreeSet::len));
        if self
            .startup_until
            .is_some_and(|until| Instant::now() < until)
        {
            regular.max(STARTUP_LIMIT)
        } else {
            regular
        }
    }
}
struct Entry {
    key: String,
    endpoint: Endpoint,
    socket: PathBuf,
    gate: AsyncMutex<()>,
    users: AtomicUsize,
    last_used: Mutex<Instant>,
    closed: AtomicBool,
    retiring: AtomicBool,
    cancel: tokio_util::sync::CancellationToken,
    files: Mutex<Option<Files>>,
    #[cfg(target_os = "macos")]
    master: Mutex<Option<crate::local_resources::ProcessIdentity>>,
}
struct Files {
    configuration_hash: String,
    authorization: Option<ssh_authorization::Stamp>,
    paths: Vec<PathBuf>,
    fingerprint: Vec<u8>,
    directories: Vec<PathBuf>,
    directory_fingerprint: Vec<u8>,
    dynamic_match: bool,
}

impl Files {
    fn same_settings(&self, current: &Self) -> bool {
        self.configuration_hash == current.configuration_hash
            && self.paths == current.paths
            && self.fingerprint == current.fingerprint
            && self.directories == current.directories
            && self.authorization == current.authorization
            && !current.dynamic_match
    }
}
pub struct Lease {
    pool: Pool,
    entry: Arc<Entry>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub limit: usize,
    pub connections: usize,
    pub opened: u64,
    pub reused: u64,
    pub evicted: u64,
}

fn key(endpoint: &Endpoint) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(endpoint).expect("endpoint serialization"))
    )
}
pub(crate) fn fingerprint(paths: &[PathBuf]) -> Vec<u8> {
    let mut hash = Sha256::new();
    for path in paths {
        hash.update(path.as_os_str().as_encoded_bytes());
        match std::fs::metadata(path) {
            Ok(m) => hash.update(format!(
                "{}:{}:{}:{}:{}:{}:{}",
                m.dev(),
                m.ino(),
                m.len(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec()
            )),
            Err(e) => hash.update(format!("{:?}", e.kind())),
        }
    }
    hash.finalize().to_vec()
}
impl Entry {
    fn files_unchanged(&self) -> bool {
        self.files.lock().is_ok_and(|files| {
            files.as_ref().is_none_or(|f| {
                fingerprint(&f.paths) == f.fingerprint
                    && (!f.dynamic_match || fingerprint(&f.directories) == f.directory_fingerprint)
            })
        })
    }
    fn close(&self, reason: &'static str) -> bool {
        if !self.closed.swap(true, Ordering::SeqCst) {
            activity::info("ssh", reason, Some(ssh::target(&self.endpoint)));
        }
        self.cancel.cancel();
        // Address only our private socket, never an old PID that the OS may reuse.
        let terminated = match control(&self.socket, true, MUX_MAINTENANCE_TIMEOUT) {
            Ok(_) => true,
            Err(error) => error.kind() == ErrorKind::ConnectionRefused,
        };
        if terminated {
            let _ = std::fs::remove_file(&self.socket);
        } else {
            // OpenSSH may exit before its queued termination reply is flushed.
            for _ in 0..4 {
                if !self.socket.exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        !self.socket.exists()
    }
}
impl Drop for Entry {
    fn drop(&mut self) {
        self.close("Close SSH connection");
    }
}
impl Drop for Inner {
    fn drop(&mut self) {
        if let Ok(state) = self.state.get_mut() {
            for entry in state.entries.values() {
                entry.close("Close SSH connection");
            }
        }
        let _ = std::fs::remove_dir(&self.root);
    }
}

impl Pool {
    /// Custom configuration is for isolated fixture pools; the desktop uses system OpenSSH config.
    pub fn new(limit: usize, idle: Duration, config: Option<PathBuf>) -> Result<Self, String> {
        Self::with_capacity(Capacity::Fixed(limit), idle, config)
    }

    fn with_capacity(
        capacity: Capacity,
        idle: Duration,
        config: Option<PathBuf>,
    ) -> Result<Self, String> {
        if !(1..=256).contains(&capacity.limit(0))
            || idle.is_zero()
            || idle > Duration::from_secs(IDLE_SECONDS)
        {
            return Err("Invalid SSH pool limits".into());
        }
        // Short paths fit sockaddr_un on macOS; the directory is private from creation.
        let base = if cfg!(target_os = "macos") {
            Path::new("/private/tmp")
        } else {
            Path::new("/tmp")
        };
        let root = base.join(format!("cb-ssh-{}", uuid::Uuid::new_v4().simple()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .map_err(|e| e.to_string())?;
        Ok(Self(Arc::new(Inner {
            root,
            capacity,
            idle,
            config,
            state: Mutex::new(State::default()),
            changed: Notify::new(),
            opening: Semaphore::new(OPEN_LIMIT),
            opened: AtomicU64::new(0),
            reused: AtomicU64::new(0),
            evicted: AtomicU64::new(0),
            leases: AtomicUsize::new(0),
        })))
    }
    pub fn stats(&self) -> Stats {
        let (limit, connections) = self
            .0
            .state
            .lock()
            .map(|s| (s.limit(self.0.capacity), s.entries.len()))
            .unwrap_or((self.0.capacity.limit(0), 0));
        Stats {
            limit,
            connections,
            opened: self.0.opened.load(Ordering::Relaxed),
            reused: self.0.reused.load(Ordering::Relaxed),
            evicted: self.0.evicted.load(Ordering::Relaxed),
        }
    }
    pub fn pids(&self) -> Vec<u32> {
        self.0
            .state
            .lock()
            .map(|s| {
                s.entries
                    .values()
                    .filter_map(|e| control(&e.socket, false, MUX_MAINTENANCE_TIMEOUT).ok())
                    .collect()
            })
            .unwrap_or_default()
    }
    #[cfg(target_os = "macos")]
    fn resource_masters(&self) -> Vec<crate::local_resources::ProcessIdentity> {
        self.0
            .state
            .lock()
            .map(|state| {
                state
                    .entries
                    .values()
                    .filter(|entry| !entry.closed.load(Ordering::Relaxed))
                    .filter_map(|entry| *entry.master.lock().ok()?)
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn shutdown(&self) {
        if let Ok(mut state) = self.0.state.lock() {
            state.stopped = true;
        }
        self.prune(|_| true, "Close SSH connections on exit");
        self.0.changed.notify_waiters();
        if self.0.leases.load(Ordering::SeqCst) == 0 {
            let _ = std::fs::remove_dir(&self.0.root);
        }
    }
    pub fn retain(&self, endpoints: &[Endpoint]) {
        let allowed = endpoints.iter().map(key).collect::<BTreeSet<_>>();
        let inventory_changed = self.0.state.lock().is_ok_and(|mut state| {
            let changed = state.allowed.as_ref() != Some(&allowed);
            if changed {
                state.allowed = Some(allowed.clone());
            }
            changed
        });
        self.prune(
            |e| !allowed.contains(&e.key) || !e.files_unchanged(),
            SETTINGS_CHANGED,
        );
        self.prune(
            |e| {
                e.users.load(Ordering::SeqCst) == 0
                    && (e.closed.load(Ordering::SeqCst)
                        || e.last_used.lock().is_ok_and(|t| t.elapsed() >= self.0.idle))
            },
            "SSH: idle",
        );
        self.trim_idle();
        if inventory_changed {
            self.0.changed.notify_waiters();
        }
    }

    pub(crate) async fn refresh_changed_directories(&self) {
        let entries = match self.0.state.lock() {
            Ok(state) => state
                .entries
                .values()
                .filter(|entry| entry.users.load(Ordering::SeqCst) > 0)
                .cloned()
                .collect::<Vec<_>>(),
            Err(_) => return,
        };
        let mut jobs = tokio::task::JoinSet::new();
        for entry in entries {
            if jobs.len() == 4 {
                let _ = jobs.join_next().await;
            }
            let pool = self.clone();
            jobs.spawn(async move {
                // A concurrent acquire or handshake checks the same settings under this gate.
                if let Ok(_gate) = entry.gate.try_lock() {
                    let _ = pool.verify_configuration(&entry).await;
                }
            });
        }
        while jobs.join_next().await.is_some() {}
    }

    async fn verify_configuration(&self, entry: &Entry) -> Result<(), String> {
        let result = tokio::select! {
            biased;
            _ = entry.cancel.cancelled() => return Err("SSH connection withdrawn".into()),
            result = self.refresh_configuration(entry) => result,
        };
        if result.is_err() {
            entry.close(SETTINGS_CHANGED);
            self.0.changed.notify_waiters();
        }
        result
    }

    // The caller holds the entry's gate so a master and its snapshot are updated together.
    async fn refresh_configuration(&self, entry: &Entry) -> Result<(), String> {
        let before = {
            let files = entry.files.lock().map_err(|e| e.to_string())?;
            let Some(files) = files.as_ref() else {
                return Ok(());
            };
            if fingerprint(&files.paths) != files.fingerprint {
                return Err(CONNECTION_SETTINGS_CHANGED.into());
            }
            let before = fingerprint(&files.directories);
            if before == files.directory_fingerprint {
                return Ok(());
            }
            if files.dynamic_match {
                return Err(CONNECTION_SETTINGS_CHANGED.into());
            }
            before
        };
        let mut current = self.configuration(&entry.endpoint).await?;
        let mut files = entry.files.lock().map_err(|e| e.to_string())?;
        if !files
            .as_ref()
            .is_some_and(|old| old.same_settings(&current))
        {
            return Err(CONNECTION_SETTINGS_CHANGED.into());
        }
        // Leave changes during the probe visible to the next check.
        current.directory_fingerprint = before;
        *files = Some(current);
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn startup_until(&self, deadline: Option<Instant>) {
        if let Ok(mut state) = self.0.state.lock() {
            state.startup_until = deadline;
        }
        self.0.changed.notify_waiters();
    }
    pub(crate) fn trim_idle(&self) {
        let Ok(state) = self.0.state.lock() else {
            return;
        };
        let retiring = state
            .entries
            .values()
            .filter(|e| e.retiring.load(Ordering::SeqCst))
            .count();
        let excess = state
            .entries
            .len()
            .saturating_sub(state.limit(self.0.capacity) + retiring);
        if excess == 0 {
            return;
        }
        let mut idle: Vec<_> = state
            .entries
            .values()
            .filter(|e| e.users.load(Ordering::SeqCst) == 0 && !e.retiring.load(Ordering::SeqCst))
            .cloned()
            .collect();
        idle.sort_by_key(|e| e.last_used.lock().map(|t| *t).ok());
        idle.truncate(excess);
        for entry in &idle {
            entry.retiring.store(true, Ordering::SeqCst);
        }
        drop(state);
        for entry in idle {
            if self.retire(&entry, "Recover SSH connection") {
                self.0.evicted.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    fn prune(&self, condition: impl Fn(&Entry) -> bool, reason: &'static str) {
        let retired = self
            .0
            .state
            .lock()
            .map(|state| {
                state
                    .entries
                    .values()
                    .filter(|e| condition(e) && !e.retiring.swap(true, Ordering::SeqCst))
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for entry in retired {
            self.retire(&entry, reason);
        }
    }
    fn retire(&self, entry: &Arc<Entry>, reason: &'static str) -> bool {
        let closed = entry.close(reason);
        if let Ok(mut state) = self.0.state.lock() {
            if closed
                && state
                    .entries
                    .get(&entry.key)
                    .is_some_and(|current| Arc::ptr_eq(current, entry))
            {
                state.entries.remove(&entry.key);
            }
            entry.retiring.store(false, Ordering::SeqCst);
        }
        if !closed {
            if let Ok(mut time) = entry.last_used.lock() {
                *time = Instant::now();
            }
        }
        self.0.changed.notify_waiters();
        closed
    }
    pub async fn acquire(&self, endpoint: &Endpoint) -> Result<Lease, String> {
        crate::inventory::validate_endpoint(endpoint)?;
        let result = tokio::time::timeout(WAIT_TIMEOUT, self.reserve(endpoint))
            .await
            .map_err(|_| "Timed out waiting for an SSH connection from the pool".to_string())??;
        result.ready().await?;
        Ok(result)
    }
    async fn reserve(&self, endpoint: &Endpoint) -> Result<Lease, String> {
        let identity = key(endpoint);
        loop {
            let wait = self.0.changed.notified();
            tokio::pin!(wait);
            wait.as_mut().enable();
            let mut retired = None;
            let mut eviction = false;
            {
                let mut state = self.0.state.lock().map_err(|e| e.to_string())?;
                if state.stopped {
                    return Err("SSH pool stopped".into());
                }
                if state
                    .allowed
                    .as_ref()
                    .is_some_and(|keys| !keys.contains(&identity))
                {
                    return Err("The server is remote or the SSH settings have changed".into());
                }
                if let Some(entry) = state.entries.get(&identity) {
                    if !entry.closed.load(Ordering::SeqCst)
                        && !entry.retiring.load(Ordering::SeqCst)
                        && entry.files_unchanged()
                    {
                        entry.users.fetch_add(1, Ordering::SeqCst);
                        self.0.leases.fetch_add(1, Ordering::SeqCst);
                        return Ok(Lease {
                            pool: self.clone(),
                            entry: entry.clone(),
                        });
                    }
                    if !entry.retiring.swap(true, Ordering::SeqCst) {
                        retired = Some(entry.clone());
                    }
                } else if state.entries.len() >= state.limit(self.0.capacity) {
                    let oldest = state
                        .entries
                        .values()
                        .filter(|e| {
                            e.users.load(Ordering::SeqCst) == 0
                                && !e.retiring.load(Ordering::SeqCst)
                        })
                        .min_by_key(|e| {
                            e.last_used
                                .lock()
                                .map(|t| *t)
                                .unwrap_or_else(|_| Instant::now())
                        })
                        .cloned();
                    if let Some(entry) = oldest {
                        entry.retiring.store(true, Ordering::SeqCst);
                        retired = Some(entry);
                        eviction = true;
                    }
                } else {
                    let entry = Arc::new(Entry {
                        key: identity.clone(),
                        endpoint: endpoint.clone(),
                        socket: self.0.root.join(uuid::Uuid::new_v4().simple().to_string()),
                        gate: AsyncMutex::new(()),
                        users: AtomicUsize::new(1),
                        last_used: Mutex::new(Instant::now()),
                        closed: AtomicBool::new(false),
                        retiring: AtomicBool::new(false),
                        cancel: tokio_util::sync::CancellationToken::new(),
                        files: Mutex::new(None),
                        #[cfg(target_os = "macos")]
                        master: Mutex::new(None),
                    });
                    state.entries.insert(identity.clone(), entry.clone());
                    self.0.leases.fetch_add(1, Ordering::SeqCst);
                    return Ok(Lease {
                        pool: self.clone(),
                        entry,
                    });
                }
            }
            if let Some(entry) = retired {
                if self.retire(&entry, "Open pooled SSH connection") {
                    if eviction {
                        self.0.evicted.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                continue;
            }
            wait.await;
        }
    }
}

impl Lease {
    pub(crate) fn configuration_hash(&self) -> Result<String, String> {
        self.entry
            .files
            .lock()
            .map_err(|_| "No SSH context")?
            .as_ref()
            .map(|f| f.configuration_hash.clone())
            .ok_or_else(|| "SSH hasn’t been tested yet".into())
    }
    pub(crate) fn authorization_hash(&self) -> Result<Option<String>, String> {
        self.entry
            .files
            .lock()
            .map_err(|e| e.to_string())?
            .as_ref()
            .map(|f| f.authorization.as_ref().map(|stamp| stamp.digest()))
            .ok_or_else(|| "No context for master SSH".into())
    }
    pub fn options(&self) -> Result<Vec<String>, String> {
        self.channel_options(false)
    }
    pub(crate) fn console_options(&self) -> Result<Vec<String>, String> {
        let mut args = self.channel_options(true)?;
        args.extend(["--".into(), self.entry.endpoint.host.clone()]);
        Ok(args)
    }
    pub(crate) async fn revoked(&self) {
        self.entry.cancel.cancelled().await;
    }
    fn channel_options(&self, tty: bool) -> Result<Vec<String>, String> {
        if self.entry.closed.load(Ordering::SeqCst) || !self.entry.files_unchanged() {
            return Err("SSH connection withdrawn".into());
        }
        let mut endpoint = self.entry.endpoint.clone();
        endpoint.jump_host = None;
        let mut args = self.pool.base_options(&endpoint, tty)?;
        // OpenSSH normally falls back to a new TCP connection when mux is gone.
        // Disable that fallback so every connection remains accounted by the pool.
        args.extend([
            format!("-oControlPath={}", self.entry.socket.display()),
            "-oControlMaster=no".into(),
            "-oControlPersist=no".into(),
            "-oProxyCommand=/usr/bin/false".into(),
            "-oProxyJump=none".into(),
        ]);
        Ok(args)
    }
    async fn ready(&self) -> Result<(), String> {
        tokio::select! {
            biased;
            _ = self.entry.cancel.cancelled() => Err(WITHDRAWN.into()),
            result = async {
                let _gate = self.entry.gate.lock().await;
                self.ready_under_gate().await
            } => result,
        }
    }
    async fn ready_under_gate(&self) -> Result<(), String> {
        if self.entry.closed.load(Ordering::SeqCst) {
            return Err(WITHDRAWN.into());
        }
        if self.entry.socket.try_exists().map_err(|e| e.to_string())? {
            match self.check_master(false).await {
                Ok(()) => {
                    self.pool.verify_configuration(&self.entry).await?;
                    self.pool.0.reused.fetch_add(1, Ordering::Relaxed);
                    activity::info(
                        "ssh",
                        "Reuse of SSH",
                        Some(ssh::target(&self.entry.endpoint)),
                    );
                    return Ok(());
                }
                Err(error) if error.kind() == ErrorKind::ConnectionRefused => {
                    // The gate prevents another opener from binding this path.
                    if let Err(error) = std::fs::remove_file(&self.entry.socket) {
                        if error.kind() != ErrorKind::NotFound {
                            return Err(format!("Removing the stale SSH socket: {error}"));
                        }
                    }
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(format!("Checking the existing SSH connection: {error}")),
            }
        }
        let mut event = activity::begin(
            "ssh",
            "SSH connection",
            Some(ssh::target(&self.entry.endpoint)),
        );
        let result = async {
            self.launch_master()
                .await
                .inspect_err(|_| self.invalidate())?;
            self.pool.0.opened.fetch_add(1, Ordering::Relaxed);
            if let Err(error) = self.check_master(true).await {
                // The launcher authenticated successfully. A busy local socket
                // can still become ready for the next request.
                if error.kind() != ErrorKind::TimedOut {
                    self.invalidate();
                }
                return Err(format!("Checking the SSH connection: {error}"));
            }
            self.pool.verify_configuration(&self.entry).await?;
            crate::connectivity::ssh_reply();
            Ok(())
        }
        .await;
        event.result(&result);
        result
    }
    async fn check_master(&self, starting: bool) -> io::Result<()> {
        let mut delays = MUX_RETRY_DELAYS_MS.into_iter();
        loop {
            let socket = self.entry.socket.clone();
            match tokio::task::spawn_blocking(move || control(&socket, false, MUX_PROBE_TIMEOUT))
                .await
                .map_err(io::Error::other)?
            {
                Ok(_pid) => {
                    #[cfg(target_os = "macos")]
                    if let Ok(mut master) = self.entry.master.lock() {
                        if master.is_none_or(|process| process.pid != _pid) {
                            *master = crate::local_resources::process_identity(_pid);
                        }
                    }
                    return Ok(());
                }
                Err(error) => {
                    let kind = error.kind();
                    let timed_out = matches!(kind, ErrorKind::WouldBlock | ErrorKind::TimedOut);
                    let retryable = timed_out
                        || kind == ErrorKind::Interrupted
                        || (starting && kind == ErrorKind::NotFound);
                    if !retryable {
                        return Err(error);
                    }
                    let Some(delay) = delays.next() else {
                        return Err(if timed_out {
                            io::Error::new(
                                ErrorKind::TimedOut,
                                "the local OpenSSH control socket did not respond in time",
                            )
                        } else {
                            error
                        });
                    };
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
            }
        }
    }
    async fn launch_master(&self) -> Result<(), String> {
        let mut args = self.pool.base_options(&self.entry.endpoint, false)?;
        args.extend([
            "-N".into(),
            "-oControlMaster=yes".into(),
            format!("-oControlPath={}", self.entry.socket.display()),
            format!("-oControlPersist={}", self.pool.0.idle.as_secs().max(1)),
            "--".into(),
            self.entry.endpoint.host.clone(),
        ]);
        let mut delays = OPEN_RETRY_DELAYS_MS.into_iter();
        let mut prepared = false;
        loop {
            let permit = tokio::time::timeout(WAIT_TIMEOUT, self.pool.0.opening.acquire())
                .await
                .map_err(|_| "Timed out waiting to open an SSH connection")?
                .map_err(|_| WITHDRAWN)?;
            if prepared {
                self.pool.verify_configuration(&self.entry).await?;
                // A launcher can detach before its final status is observed.
                if self.entry.socket.try_exists().map_err(|e| e.to_string())? {
                    break;
                }
            } else {
                let files = self.pool.configuration(&self.entry.endpoint).await?;
                *self.entry.files.lock().map_err(|e| e.to_string())? = Some(files);
                prepared = true;
            }
            if self.entry.closed.load(Ordering::SeqCst) {
                return Err(WITHDRAWN.into());
            }
            let launch = process::ssh_master(&args).await;
            drop(permit);
            let (error, retryable) = match launch {
                Ok(output) if output.success => break,
                Ok(output) => (
                    ssh::classify_error(&output.stderr),
                    output.exit_code == Some(255) && retryable_handshake(&output.stderr),
                ),
                Err(error) => (error.to_string(), error.retryable()),
            };
            if !retryable {
                return Err(error);
            }
            if self.entry.socket.try_exists().map_err(|e| e.to_string())? {
                break;
            }
            let Some(delay) = delays.next() else {
                return Err(error);
            };
            let jitter = u64::from(uuid::Uuid::new_v4().as_bytes()[0]) % 251;
            tokio::time::sleep(Duration::from_millis(delay + jitter)).await;
        }
        Ok(())
    }
    pub fn invalidate(&self) {
        self.entry.close("Verify SSH connection");
        self.pool.0.changed.notify_waiters();
    }
}

impl Pool {
    fn base_options(&self, endpoint: &Endpoint, tty: bool) -> Result<Vec<String>, String> {
        let mut args = Vec::new();
        if let Some(config) = &self.0.config {
            args.extend([
                "-F".into(),
                config.to_string_lossy().into_owned(),
                "-oIdentityAgent=none".into(),
                "-oIdentitiesOnly=yes".into(),
                "-oGlobalKnownHostsFile=/dev/null".into(),
            ]);
        }
        args.extend(ssh::options_with_pty(endpoint, tty)?);
        Ok(args)
    }

    async fn configuration(&self, endpoint: &Endpoint) -> Result<Files, String> {
        let mut args = self.base_options(endpoint, false)?;
        args.extend(["-G".into(), "-v".into(), "--".into(), endpoint.host.clone()]);
        let output = process::bounded("/usr/bin/ssh", &args, None, 10, 65536).await?;
        if !output.success {
            return Err(ssh::classify_error(&output.stderr));
        }
        let system_config = self.0.config.is_none();
        let ssh_authorization::ConfigPaths {
            files: mut paths,
            include_dirs: mut directories,
        } = ssh_authorization::config_paths(&output, system_config);
        paths.extend(
            [&endpoint.identity_file, &endpoint.known_hosts_file]
                .into_iter()
                .flatten()
                .map(PathBuf::from),
        );
        paths.extend(self.0.config.iter().cloned());
        // Record jump-specific files at master creation too. An old master must
        // never be attested against a newer bastion configuration at approval time.
        // Normal monitoring retains its wider SSH compatibility; actions require
        // a successful strict stamp through their separate authorization guard.
        let mut dynamic_match = ssh_authorization::executes_match(&output.stderr);
        let authorization = if system_config && !dynamic_match {
            match ssh_authorization::capture_from_output(&output).await {
                Ok((stamp, context)) => {
                    paths.extend(context.files);
                    directories.extend(context.include_dirs);
                    Some(stamp)
                }
                Err(error) => {
                    dynamic_match = error == ssh_authorization::DYNAMIC_MATCH;
                    None
                }
            }
        } else {
            None
        };
        directories.extend(ssh_authorization::parents(&paths));
        if paths.union(&directories).count() > 512 {
            return Err("Too many SSH settings files".into());
        }
        let paths = paths.into_iter().collect::<Vec<_>>();
        let directories = directories.into_iter().collect::<Vec<_>>();
        Ok(Files {
            fingerprint: fingerprint(&paths),
            directory_fingerprint: fingerprint(&directories),
            paths,
            directories,
            configuration_hash: format!("{:x}", Sha256::digest(&output.stdout)),
            authorization,
            dynamic_match,
        })
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut time) = self.entry.last_used.lock() {
            *time = Instant::now();
        }
        self.entry.users.fetch_sub(1, Ordering::SeqCst);
        if self.pool.0.leases.fetch_sub(1, Ordering::SeqCst) == 1
            && self.pool.0.state.lock().is_ok_and(|s| s.stopped)
        {
            let _ = std::fs::remove_dir(&self.pool.0.root);
        }
        self.pool.0.changed.notify_waiters();
    }
}

// OpenSSH reports connection and authentication errors with the same exit code.
fn retryable_handshake(stderr: &str) -> bool {
    const DNS_ERROR: &str = "ssh: Could not resolve hostname ";
    const TEMPORARY_DNS: &str = "Temporary failure in name resolution";
    if [
        "Host key verification failed",
        "REMOTE HOST IDENTIFICATION HAS CHANGED",
        "Permission denied",
        "Too many authentication failures",
        "Unable to negotiate with",
        "Bad configuration option",
        "Bad owner or permissions",
        "terminating, ",
    ]
    .into_iter()
    .any(|message| stderr.contains(message))
        || stderr.lines().any(|line| {
            line.starts_with(DNS_ERROR)
                && !line
                    .trim_end()
                    .rsplit_once(": ")
                    .is_some_and(|(_, reason)| reason.eq_ignore_ascii_case(TEMPORARY_DNS))
        })
    {
        return false;
    }
    stderr.lines().any(|line| {
        let line = line.trim_end();
        if line == "Connection timed out during banner exchange"
            || ["Connection closed by ", "Connection reset by "]
                .into_iter()
                .any(|prefix| {
                    line.strip_prefix(prefix).is_some_and(|peer| {
                        peer.rsplit_once(" port ").is_some_and(|(host, port)| {
                            host != "UNKNOWN" && port.parse::<u16>().is_ok()
                        })
                    })
                })
        {
            return true;
        }
        let Some((context, reason)) = line.rsplit_once(": ") else {
            return false;
        };
        if context.starts_with(DNS_ERROR) {
            return reason.eq_ignore_ascii_case(TEMPORARY_DNS);
        }
        let connect = context.starts_with("ssh: connect to host ")
            || (context.starts_with("channel ") && context.ends_with(": connect failed"));
        let handshake = context.starts_with("kex_exchange_identification")
            || context.starts_with("ssh_exchange_identification")
            || context.starts_with("ssh_dispatch_run_fatal: Connection to ");
        (connect || handshake)
            && matches!(
                reason,
                "Connection refused"
                    | "Operation timed out"
                    | "Connection timed out"
                    | "Connection reset by peer"
                    | "Connection closed by remote host"
            )
    })
}

// Only HELLO, ALIVE and TERMINATE from OpenSSH PROTOCOL.mux v4. No remote exec here.
fn control(path: &Path, terminate: bool, timeout: Duration) -> io::Result<u32> {
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    let address = socket2::SockAddr::unix(path)?;
    socket.connect_timeout(&address, timeout)?;
    let fd: std::os::fd::OwnedFd = socket.into();
    let mut stream = UnixStream::from(fd);
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    fn send(stream: &mut UnixStream, words: &[u32]) -> io::Result<()> {
        let mut packet = ((words.len() * 4) as u32).to_be_bytes().to_vec();
        for word in words {
            packet.extend(word.to_be_bytes());
        }
        stream.write_all(&packet)
    }
    fn invalid_packet() -> io::Error {
        io::Error::new(ErrorKind::InvalidData, "Invalid SSH multiplexing packet")
    }
    fn read_word(bytes: &mut &[u8]) -> io::Result<u32> {
        let (word, rest) = bytes.split_first_chunk().ok_or_else(invalid_packet)?;
        *bytes = rest;
        Ok(u32::from_be_bytes(*word))
    }
    fn read(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
        let mut size = [0; 4];
        stream.read_exact(&mut size)?;
        let size = u32::from_be_bytes(size) as usize;
        if !(4..=1024).contains(&size) {
            return Err(invalid_packet());
        }
        let mut bytes = vec![0; size];
        stream.read_exact(&mut bytes)?;
        Ok(bytes)
    }
    send(&mut stream, &[1, 4])?;
    let hello = read(&mut stream)?;
    let mut extensions = hello.as_slice();
    if (read_word(&mut extensions)?, read_word(&mut extensions)?) != (1, 4) {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "Unsupported version of SSH mux",
        ));
    }
    // Each extension is a pair of length-prefixed SSH strings.
    while !extensions.is_empty() {
        for _ in 0..2 {
            let size = read_word(&mut extensions)? as usize;
            let (_, rest) = extensions
                .split_at_checked(size)
                .ok_or_else(invalid_packet)?;
            extensions = rest;
        }
    }
    send(
        &mut stream,
        &[if terminate { 0x10000005 } else { 0x10000004 }, 1],
    )?;
    let response = read(&mut stream)?;
    if response.len() % 4 != 0 {
        return Err(invalid_packet());
    }
    let words: Vec<_> = response
        .chunks_exact(4)
        .map(|word| u32::from_be_bytes(word.try_into().unwrap()))
        .collect();
    match (terminate, words.as_slice()) {
        (true, [0x80000001, 1]) => Ok(0),
        (false, [0x80000005, 1, pid]) if *pid > 0 => Ok(*pid),
        _ => Err(io::Error::new(
            ErrorKind::InvalidData,
            "SSH multiplexing rejected the request",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn endpoint(port: u16) -> Endpoint {
        Endpoint {
            host: "127.0.0.1".into(),
            user: "ops".into(),
            port,
            identity_file: None,
            jump_host: None,
            known_hosts_file: None,
        }
    }

    #[tokio::test]
    async fn inventory_capacity_reuses_a_fleet_and_respects_the_ceiling() {
        let pool =
            Pool::with_capacity(Capacity::Inventory, Duration::from_secs(900), None).unwrap();
        let mut endpoints: Vec<_> = (1..=150).map(endpoint).collect();
        endpoints.push(endpoint(1));
        pool.retain(&endpoints);
        assert_eq!(pool.stats().limit, 150);
        assert_eq!(pool.stats().connections, 0);
        let mut entries = Vec::new();
        for target in &endpoints[..150] {
            entries.push(pool.reserve(target).await.unwrap().entry.clone());
        }
        for (target, entry) in endpoints.iter().zip(entries.iter()) {
            let lease = pool.reserve(target).await.unwrap();
            assert!(Arc::ptr_eq(&lease.entry, entry));
        }
        assert_eq!(pool.stats().evicted, 0);

        endpoints.extend((151..=193).map(endpoint));
        pool.retain(&endpoints);
        for target in &endpoints[151..] {
            drop(pool.reserve(target).await.unwrap());
        }
        assert_eq!(pool.stats().limit, INVENTORY_LIMIT);
        assert_eq!(pool.stats().connections, INVENTORY_LIMIT);
        assert_eq!(pool.stats().evicted, 1);

        let lease = pool.reserve(&endpoint(193)).await.unwrap();
        pool.retain(&[endpoint(193)]);
        assert_eq!(pool.stats().limit, DEFAULT_LIMIT);
        assert_eq!(pool.stats().connections, 1);
        assert!(lease.options().is_ok());
        assert!(pool.reserve(&endpoint(1)).await.is_err());
        pool.shutdown();
    }

    #[tokio::test]
    async fn bounds_capacity_keeps_active_leases_and_evicts_idle_lru() {
        let pool = Pool::new(2, Duration::from_secs(900), None).unwrap();
        let first = pool.reserve(&endpoint(1)).await.unwrap();
        let second = pool.reserve(&endpoint(2)).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), pool.reserve(&endpoint(3)))
                .await
                .is_err()
        );
        drop(second);
        let third = pool.reserve(&endpoint(3)).await.unwrap();
        assert_eq!(pool.stats().connections, 2);
        assert_eq!(pool.stats().evicted, 1);
        assert!(!first.entry.closed.load(Ordering::SeqCst));
        assert_eq!(first.entry.users.load(Ordering::SeqCst), 1);
        drop(third);
        drop(first);
        pool.shutdown();
        assert!(!pool.0.root.exists());
    }
    #[tokio::test]
    async fn expired_startup_limit_trims_idle_connections_but_keeps_active_ones() {
        let pool = Pool::new(DEFAULT_LIMIT, Duration::from_secs(900), None).unwrap();
        pool.startup_until(Some(Instant::now() + Duration::from_secs(60)));
        let mut leases = Vec::new();
        for port in 1..=34 {
            leases.push(pool.reserve(&endpoint(port)).await.unwrap());
        }
        assert_eq!(pool.stats().limit, 64);
        pool.startup_until(Some(Instant::now()));
        assert_eq!(pool.stats().limit, DEFAULT_LIMIT);
        pool.trim_idle();
        assert_eq!(pool.stats().connections, 34);
        assert!(leases.iter().all(|lease| lease.options().is_ok()));

        let shared = pool.reserve(&endpoint(34)).await.unwrap();
        assert!(Arc::ptr_eq(&leases[33].entry, &shared.entry));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), pool.reserve(&endpoint(35)))
                .await
                .is_err()
        );
        drop(shared);
        for _ in 0..2 {
            drop(leases.remove(0));
        }
        pool.retain(&(1..=34).map(endpoint).collect::<Vec<_>>());
        assert_eq!(pool.stats().connections, DEFAULT_LIMIT);
        assert!(leases.iter().all(|lease| lease.options().is_ok()));
    }
    #[tokio::test]
    async fn coalesces_same_endpoint_and_stops_waiters_on_shutdown() {
        let pool = Pool::new(1, Duration::from_secs(900), None).unwrap();
        let a = pool.reserve(&endpoint(1)).await.unwrap();
        let b = pool.reserve(&endpoint(1)).await.unwrap();
        assert!(Arc::ptr_eq(&a.entry, &b.entry));
        assert_eq!(pool.stats().connections, 1);
        let other = pool.clone();
        let waiter = tokio::spawn(async move { other.reserve(&endpoint(2)).await.err().unwrap() });
        tokio::task::yield_now().await;
        pool.shutdown();
        assert!(waiter.await.unwrap().contains("stopped"));
        assert!(a.options().is_err());
    }
    #[tokio::test]
    async fn private_sockets_no_fallback_and_endpoint_retirement() {
        let pool = Pool::new(2, Duration::from_secs(900), None).unwrap();
        assert_eq!(
            std::fs::metadata(&pool.0.root).unwrap().mode() & 0o777,
            0o700
        );
        let mut e = endpoint(22);
        e.jump_host = Some("bastion".into());
        let lease = pool.reserve(&e).await.unwrap();
        assert!(lease.entry.socket.as_os_str().len() < 100);
        let args = lease.options().unwrap();
        assert!(args.contains(&"-oProxyCommand=/usr/bin/false".into()));
        assert!(args.contains(&"-oProxyJump=none".into()));
        assert!(!args.contains(&"-J".into()));
        assert!(args.contains(&"-oServerAliveInterval=60".into()));
        pool.retain(&[]);
        assert!(lease.options().is_err());
        assert!(pool.reserve(&e).await.is_err());
    }
    #[test]
    fn keys_include_identity_and_trust_context() {
        let base = endpoint(22);
        let mut variants = vec![base.clone()];
        for field in 0..5 {
            let mut e = base.clone();
            match field {
                0 => e.user = "root".into(),
                1 => e.port = 2222,
                2 => e.identity_file = Some("/key".into()),
                3 => e.jump_host = Some("jump".into()),
                _ => e.known_hosts_file = Some("/trust".into()),
            };
            variants.push(e);
        }
        assert_eq!(variants.iter().map(key).collect::<BTreeSet<_>>().len(), 6);
    }
    #[test]
    fn detects_file_replacement_and_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("trust");
        let paths = vec![file.clone()];
        let missing = fingerprint(&paths);
        std::fs::write(&file, "trusted").unwrap();
        let trusted = fingerprint(&paths);
        assert_ne!(missing, trusted);
        let other = dir.path().join("other");
        std::fs::write(&other, "revoked").unwrap();
        std::fs::rename(other, file).unwrap();
        assert_ne!(trusted, fingerprint(&paths));
    }
    fn mux_frame(words: &[u32], tail: &[u8]) -> Vec<u8> {
        let size = (words.len() * 4 + tail.len()) as u32;
        size.to_be_bytes()
            .into_iter()
            .chain(words.iter().copied().flat_map(u32::to_be_bytes))
            .chain(tail.iter().copied())
            .collect()
    }

    fn mux_exchange(hello: &[u8], reply: Option<&[u8]>, terminate: bool) -> io::Result<u32> {
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::scope(|scope| {
            let peer = scope.spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket.set_read_timeout(Some(MUX_PROBE_TIMEOUT)).unwrap();
                let mut request = [0; 12];
                socket.read_exact(&mut request).unwrap();
                assert_eq!(request.as_slice(), mux_frame(&[1, 4], &[]));
                socket.write_all(hello).unwrap();
                match socket.read_exact(&mut request) {
                    Ok(()) => {
                        let kind = if terminate { 0x10000005 } else { 0x10000004 };
                        assert_eq!(request.as_slice(), mux_frame(&[kind, 1], &[]));
                        socket
                            .write_all(reply.expect("request after invalid HELLO"))
                            .unwrap();
                    }
                    Err(error) if error.kind() == ErrorKind::UnexpectedEof => {}
                    Err(error) => panic!("Could not read mux request: {error}"),
                }
            });
            let result = control(&path, terminate, MUX_PROBE_TIMEOUT);
            peer.join().unwrap();
            result
        })
    }

    #[test]
    fn mux_accepts_hello_with_and_without_extensions() {
        // The OpenSSH 10.3p1 master sends the SSH strings "info" and "0".
        let info = b"\0\0\0\x04info\0\0\0\x01\x30";
        let mut extended = info.to_vec();
        extended.extend_from_slice(b"\0\0\0\x06future\0\0\0\x03\0\xff\x80");
        for extensions in [info.as_slice(), &[], extended.as_slice()] {
            let hello = mux_frame(&[1, 4], extensions);
            let alive = mux_frame(&[0x80000005, 1, 42], &[]);
            let ok = mux_frame(&[0x80000001, 1], &[]);
            assert_eq!(mux_exchange(&hello, Some(&alive), false).unwrap(), 42);
            assert_eq!(mux_exchange(&hello, Some(&ok), true).unwrap(), 0);
        }
    }

    #[test]
    fn mux_rejects_oversized_or_invalid_hello() {
        for hello in [
            2048u32.to_be_bytes().to_vec(),
            mux_frame(&[1], &[]),
            mux_frame(&[2, 4], &[]),
            mux_frame(&[1, 3], &[]),
            mux_frame(&[1, 4], b"\0\0\0"),
            mux_frame(&[1, 4], b"\0\0\0\x04info"),
            mux_frame(&[1, 4], b"\0\0\0\x04info\0\0\0\x02\x30"),
        ] {
            let error = mux_exchange(&hello, None, false).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidData);
        }
    }

    #[test]
    fn mux_rejects_invalid_control_replies() {
        let hello = mux_frame(&[1, 4], &[]);
        for (terminate, reply) in [
            (false, mux_frame(&[0x80000001, 1, 42], &[])),
            (false, mux_frame(&[0x80000005, 2, 42], &[])),
            (false, mux_frame(&[0x80000005, 1, 0], &[])),
            (false, mux_frame(&[0x80000005, 1, 42], &[0])),
            (true, mux_frame(&[0x80000001, 2], &[])),
            (true, mux_frame(&[0x80000001, 1, 42], &[])),
        ] {
            let error = mux_exchange(&hello, Some(&reply), terminate).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidData);
        }
    }
    #[tokio::test]
    async fn freshly_launched_mux_can_reply_after_the_previous_retry_window() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let pool = Pool::new(1, Duration::from_secs(900), None).unwrap();
        let lease = pool.reserve(&endpoint(22)).await.unwrap();
        let listener = tokio::net::UnixListener::bind(&lease.entry.socket).unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 12];
            stream.read_exact(&mut request).await.unwrap();
            // The old probe abandoned every socket after 200 ms and gave up
            // altogether before this master's first HELLO could arrive.
            tokio::time::sleep(Duration::from_millis(1250)).await;
            stream
                .write_all(&[0, 0, 0, 8, 0, 0, 0, 1, 0, 0, 0, 4])
                .await
                .unwrap();
            stream.read_exact(&mut request).await.unwrap();
            let response = [12, 0x80000005, 1, std::process::id()]
                .into_iter()
                .flat_map(u32::to_be_bytes)
                .collect::<Vec<_>>();
            stream.write_all(&response).await.unwrap();
        });
        lease.check_master(true).await.unwrap();
        peer.await.unwrap();
        pool.shutdown();
    }

    #[tokio::test]
    async fn busy_mux_retries_and_keeps_its_master_when_opening_slots_are_full() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for stalled_checks in [1, 3] {
            let pool = Pool::new(1, Duration::from_secs(900), None).unwrap();
            let server = endpoint(22);
            let active = pool.reserve(&server).await.unwrap();
            let listener = tokio::net::UnixListener::bind(&active.entry.socket).unwrap();
            let _permits = pool
                .0
                .opening
                .acquire_many(OPEN_LIMIT as u32)
                .await
                .unwrap();
            let peer = tokio::spawn(async move {
                let mut request = [0; 12];
                for _ in 0..stalled_checks {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    stream.read_exact(&mut request).await.unwrap();
                    // Keep the socket connected until the client times out.
                    assert_eq!(stream.read(&mut request).await.unwrap(), 0);
                }
                let (mut stream, _) = listener.accept().await.unwrap();
                stream.read_exact(&mut request).await.unwrap();
                stream
                    .write_all(&[0, 0, 0, 8, 0, 0, 0, 1, 0, 0, 0, 4])
                    .await
                    .unwrap();
                stream.read_exact(&mut request).await.unwrap();
                let response = [12, 0x80000005, 1, std::process::id()]
                    .into_iter()
                    .flat_map(u32::to_be_bytes)
                    .collect::<Vec<_>>();
                stream.write_all(&response).await.unwrap();
            });
            tokio::time::timeout(Duration::from_secs(12), async {
                if stalled_checks == 3 {
                    let error = pool.acquire(&server).await.err().unwrap();
                    assert_eq!(
                        error,
                        "Checking the existing SSH connection: the local OpenSSH control socket did not respond in time"
                    );
                    assert!(active.options().is_ok());
                }
                let reused = pool.acquire(&server).await.unwrap();
                assert!(Arc::ptr_eq(&active.entry, &reused.entry));
                assert_eq!(pool.stats().opened, 0);
                assert_eq!(pool.stats().reused, 1);
                peer.await.unwrap();
            })
            .await
            .unwrap();
            pool.shutdown();
        }
    }

    #[tokio::test]
    async fn a_new_master_waits_for_an_opening_slot_and_can_be_revoked() {
        let pool = Pool::new(1, Duration::from_secs(900), None).unwrap();
        let server = endpoint(22);
        let _permits = pool
            .0
            .opening
            .acquire_many(OPEN_LIMIT as u32)
            .await
            .unwrap();
        let acquire = pool.acquire(&server);
        tokio::pin!(acquire);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut acquire)
                .await
                .is_err()
        );
        {
            let state = pool.0.state.lock().unwrap();
            let entry = state.entries.get(&key(&server)).unwrap();
            assert!(entry.files.lock().unwrap().is_none());
        }
        pool.retain(&[]);
        let error = tokio::time::timeout(Duration::from_secs(1), acquire)
            .await
            .unwrap()
            .err()
            .unwrap();
        assert_eq!(error, WITHDRAWN);
        assert_eq!(pool.stats().connections, 0);
    }

    #[test]
    fn retries_only_recognized_temporary_handshake_errors() {
        let closed = "kex_exchange_identification: Connection closed by remote host";
        for error in [
            closed,
            "Connection closed by 127.0.0.1 port 22",
            "Connection reset by 127.0.0.1 port 22",
            "Connection timed out during banner exchange",
            "kex_exchange_identification: read: Connection reset by peer",
            "ssh: connect to host fixture port 22: Operation timed out",
            "ssh: connect to host fixture port 22: Connection refused",
            "channel 0: open failed: connect failed: Connection refused",
            "ssh: Could not resolve hostname fixture: Temporary failure in name resolution",
        ] {
            assert!(retryable_handshake(error), "{error}");
        }
        for error in [
            format!("Host key verification failed.\n{closed}"),
            format!("ops@fixture: Permission denied (publickey).\n{closed}"),
            format!("config line 1: Bad configuration option: bad\n{closed}"),
            format!("ssh: Could not resolve hostname fixture: Name or service not known\n{closed}"),
            "Connection closed by UNKNOWN port 65535".into(),
            "remote command: Connection timed out".into(),
        ] {
            assert!(!retryable_handshake(&error), "{error}");
        }
    }

    #[tokio::test]
    async fn repeated_handshake_closures_exhaust_the_retry_budget() {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        std::fs::write(&config, "").unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = endpoint(listener.local_addr().unwrap().port());
        let peer = tokio::spawn(async move {
            for _ in 0..3 {
                let (stream, _) = listener.accept().await.unwrap();
                let mut banner = String::new();
                BufReader::new(stream).read_line(&mut banner).await.unwrap();
                assert!(banner.starts_with("SSH-"));
            }
        });
        let pool = Pool::new(1, Duration::from_secs(900), Some(config)).unwrap();
        let error = tokio::time::timeout(Duration::from_secs(8), pool.acquire(&server))
            .await
            .unwrap()
            .err()
            .unwrap();
        assert!(error.contains("Connection closed by "), "{error}");
        tokio::time::timeout(Duration::from_secs(1), peer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pool.stats().opened, 0);
        assert_eq!(pool.0.opening.available_permits(), OPEN_LIMIT);
        pool.shutdown();
    }

    #[tokio::test]
    async fn unresponsive_master_keeps_its_slot_until_closure_is_confirmed() {
        use std::os::unix::net::UnixListener;
        let pool = Pool::new(1, Duration::from_secs(900), None).unwrap();
        let lease = pool.reserve(&endpoint(1)).await.unwrap();
        let listener = UnixListener::bind(&lease.entry.socket).unwrap();
        drop(lease);
        let peer = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(350));
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), pool.reserve(&endpoint(2)))
                .await
                .is_err()
        );
        assert_eq!(pool.stats().connections, 1);
        assert_eq!(pool.stats().evicted, 0);
        peer.join().unwrap();
        pool.shutdown();
        assert_eq!(pool.stats().connections, 0);
    }
    #[tokio::test]
    async fn revocation_cancels_an_unfinished_handshake() {
        use tokio::io::AsyncReadExt;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        std::fs::write(&config, "").unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut e = endpoint(listener.local_addr().unwrap().port());
        e.identity_file = Some(dir.path().join("no-key").to_string_lossy().into_owned());
        let (connected, accepted) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            connected.send(()).unwrap();
            let mut buffer = [0; 1024];
            loop {
                if stream.read(&mut buffer).await.unwrap() == 0 {
                    break;
                }
            }
        });
        let pool = Pool::new(1, Duration::from_secs(900), Some(config)).unwrap();
        let connect = pool.clone();
        let task = tokio::spawn(async move { connect.acquire(&e).await.err().unwrap() });
        tokio::time::timeout(Duration::from_secs(3), accepted)
            .await
            .unwrap()
            .unwrap();
        pool.retain(&[]);
        assert!(tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .contains("withdrawn"));
        tokio::time::timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pool.stats().connections, 0);
        pool.shutdown();
    }
}
