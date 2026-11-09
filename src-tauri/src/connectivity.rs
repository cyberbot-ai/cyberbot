//! Local reachability is shared across SSH checks and is never persisted as a server failure.
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};
use tokio::{net::TcpStream, sync::watch, time::Instant};

const PEER_WAIT: Duration = Duration::from_secs(5);
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProbeHosts {
    pub host: String,
    pub backup_host: Option<String>,
}

impl Default for ProbeHosts {
    fn default() -> Self {
        Self {
            host: "cloudflare-dns.com".into(),
            backup_host: Some("www.microsoft.com".into()),
        }
    }
}

impl ProbeHosts {
    pub fn validate(&self) -> Result<(), String> {
        if [&self.host]
            .into_iter()
            .chain(&self.backup_host)
            .all(|host| {
                host.parse::<IpAddr>().is_ok()
                    || host.len() <= 253
                        && host
                            .strip_suffix('.')
                            .unwrap_or(host)
                            .split('.')
                            .all(|label| {
                                !label.is_empty()
                                    && label.len() <= 63
                                    && !label.starts_with('-')
                                    && !label.ends_with('-')
                                    && label
                                        .bytes()
                                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                            })
            })
        {
            Ok(())
        } else {
            Err("Specify the domain or IP of the control host without a URL and port".into())
        }
    }

    async fn reachable(self) -> bool {
        self.reachable_on(443).await
    }

    async fn reachable_on(self, port: u16) -> bool {
        async fn connect(host: &str, port: u16) -> bool {
            TcpStream::connect((host, port)).await.is_ok()
        }
        tokio::time::timeout(PROBE_TIMEOUT, async {
            if let Some(backup) = &self.backup_host {
                let (primary, secondary) = (connect(&self.host, port), connect(backup, port));
                tokio::pin!(primary, secondary);
                tokio::select! {
                    found = &mut primary => found || secondary.await,
                    found = &mut secondary => found || primary.await,
                }
            } else {
                connect(&self.host, port).await
            }
        })
        .await
        .unwrap_or(false)
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Status {
    pub offline: bool,
    pub recoveries: u64,
    pub probe_revision: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct Ticket {
    generation: u64,
    probe_revision: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Apply,
    Offline,
    Discard,
}

struct Round {
    until: Instant,
    result: watch::Sender<Option<bool>>,
}

impl Round {
    async fn resolved(&self) -> bool {
        let mut result = self.result.subscribe();
        result
            .wait_for(Option::is_some)
            .await
            .ok()
            .and_then(|value| *value)
            .unwrap_or(false)
    }
}

struct State {
    hosts: ProbeHosts,
    generation: u64,
    status: Status,
    last_ssh_reply: Option<Instant>,
    round: Option<Arc<Round>>,
}

impl State {
    fn finish_round(&mut self, online: bool) {
        if let Some(round) = self.round.take() {
            round.result.send_replace(Some(online));
        }
    }

    fn round(&mut self) -> Arc<Round> {
        self.round
            .get_or_insert_with(|| {
                Arc::new(Round {
                    until: Instant::now() + PEER_WAIT,
                    result: watch::channel(None).0,
                })
            })
            .clone()
    }

    fn is_current(&self, round: &Arc<Round>) -> bool {
        self.round
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, round))
    }
}

pub(crate) struct Connectivity {
    state: Mutex<State>,
    updates: watch::Sender<Status>,
    probe: tokio::sync::Mutex<()>,
}

impl Connectivity {
    pub fn new(hosts: ProbeHosts) -> Self {
        Self {
            state: Mutex::new(State {
                hosts,
                generation: 0,
                status: Status::default(),
                last_ssh_reply: None,
                round: None,
            }),
            updates: watch::channel(Status::default()).0,
            probe: tokio::sync::Mutex::new(()),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("connectivity state")
    }

    pub fn updates(&self) -> watch::Receiver<Status> {
        self.updates.subscribe()
    }

    pub fn offline(&self) -> bool {
        self.updates.borrow().offline
    }

    pub fn ticket(&self) -> Ticket {
        let state = self.state();
        Ticket {
            generation: state.generation,
            probe_revision: state.status.probe_revision,
        }
    }

    pub fn configure(&self, hosts: ProbeHosts) {
        let mut state = self.state();
        if state.hosts != hosts {
            state.hosts = hosts;
            self.invalidate(&mut state);
        }
    }

    pub fn recheck(&self) {
        self.invalidate(&mut self.state());
    }

    fn invalidate(&self, state: &mut State) {
        state.generation += 1;
        state.status.probe_revision += 1;
        state.last_ssh_reply = None;
        state.finish_round(false);
        self.updates.send_replace(state.status);
    }

    fn set_offline(&self, state: &mut State, offline: bool) {
        if state.status.offline != offline {
            state.generation += 1;
            state.status.offline = offline;
            if !offline {
                state.status.recoveries += 1;
            }
            self.updates.send_replace(state.status);
        }
    }

    fn ssh_reply(&self, ticket: Ticket) {
        let mut state = self.state();
        if state.status.probe_revision == ticket.probe_revision {
            state.last_ssh_reply = Some(Instant::now());
            self.set_offline(&mut state, false);
            state.finish_round(true);
        }
    }

    pub fn commit_guard(
        &self,
        confirmed: Option<Ticket>,
    ) -> impl std::ops::Deref<Target = Failure> + '_ {
        // Keep the connectivity verdict stable until the incident transaction commits.
        let state = self.state();
        let failure = if state.status.offline {
            Failure::Offline
        } else if confirmed.is_some_and(|ticket| ticket.generation == state.generation) {
            Failure::Apply
        } else {
            Failure::Discard
        };
        FailureGuard {
            _state: state,
            failure,
        }
    }

    pub async fn confirm_failure(&self, ticket: Ticket) -> Option<Ticket> {
        let round = {
            let mut state = self.state();
            if state.status.offline || state.generation != ticket.generation {
                return None;
            }
            state.round()
        };
        self.resolve(round, ProbeHosts::reachable)
            .await
            .then_some(ticket)
    }

    async fn resolve<F>(&self, round: Arc<Round>, probe: impl FnOnce(ProbeHosts) -> F) -> bool
    where
        F: std::future::Future<Output = bool>,
    {
        tokio::select! {
            biased;
            result = round.resolved() => return result,
            _ = tokio::time::sleep_until(round.until) => (),
        }
        let _guard = tokio::select! {
            biased;
            result = round.resolved() => return result,
            guard = self.probe.lock() => guard,
        };
        let hosts = {
            let state = self.state();
            if !state.is_current(&round) {
                return round.result.borrow().unwrap_or(false);
            }
            state.hosts.clone()
        };
        let online = tokio::select! {
            biased;
            result = round.resolved() => return result,
            result = probe(hosts) => result,
        };
        let mut state = self.state();
        if state.is_current(&round) {
            self.set_offline(&mut state, !online);
            state.finish_round(online);
        }
        let verdict = round.result.borrow().unwrap_or(false);
        verdict
    }

    pub async fn periodic(&self) {
        self.periodic_with(ProbeHosts::reachable).await;
    }

    async fn periodic_with<F>(&self, probe: impl Fn(ProbeHosts) -> F)
    where
        F: std::future::Future<Output = bool>,
    {
        let guard = self.probe.lock().await;
        let (round, generation, hosts, started) = {
            let state = self.state();
            (
                state.round.clone(),
                state.generation,
                state.hosts.clone(),
                Instant::now(),
            )
        };
        if let Some(round) = round {
            drop(guard);
            self.resolve(round, probe).await;
            return;
        }
        let online = probe(hosts).await;
        let round = {
            let mut state = self.state();
            if state.generation != generation {
                return;
            }
            if online {
                self.set_offline(&mut state, false);
                return;
            }
            if state.status.offline
                || state
                    .last_ssh_reply
                    .is_some_and(|at| started.saturating_duration_since(at) <= PEER_WAIT)
            {
                return;
            }
            state.round()
        };
        drop(guard);
        self.resolve(round, probe).await;
    }
}

struct FailureGuard<'a> {
    _state: MutexGuard<'a, State>,
    failure: Failure,
}
impl std::ops::Deref for FailureGuard<'_> {
    type Target = Failure;
    fn deref(&self) -> &Failure {
        &self.failure
    }
}

tokio::task_local! {
    static SSH_OBSERVER: (Arc<Connectivity>, Ticket);
}

pub(crate) async fn observe_ssh<T>(
    connectivity: Arc<Connectivity>,
    ticket: Ticket,
    operation: impl std::future::Future<Output = T>,
) -> T {
    SSH_OBSERVER.scope((connectivity, ticket), operation).await
}

pub(crate) fn ssh_reply() {
    let _ = SSH_OBSERVER.try_with(|(connectivity, ticket)| connectivity.ssh_reply(*ticket));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{inventory, model::Source, store::Store};
    use std::{
        future::{poll_fn, Future},
        path::Path,
        sync::atomic::{AtomicUsize, Ordering},
        task::Poll,
    };

    fn ready_round(network: &Connectivity) -> Arc<Round> {
        let round = Arc::new(Round {
            until: Instant::now(),
            result: watch::channel(None).0,
        });
        network.state().round = Some(round.clone());
        round
    }

    #[tokio::test]
    async fn fresh_peer_reply_releases_pending_errors() {
        let network = Connectivity::new(ProbeHosts::default());
        let ticket = network.ticket();
        let pending = network.confirm_failure(ticket);
        tokio::pin!(pending);
        poll_fn(|cx| {
            assert!(pending.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        network.ssh_reply(ticket);
        assert_eq!(*network.commit_guard(pending.await), Failure::Apply);
        assert!(!network.offline());
    }

    #[tokio::test]
    async fn concurrent_failures_share_one_probe_and_one_verdict() {
        for online in [true, false] {
            let network = Connectivity::new(ProbeHosts::default());
            let round = ready_round(&network);
            let calls = AtomicUsize::new(0);
            let probe = |_| async {
                calls.fetch_add(1, Ordering::Relaxed);
                tokio::task::yield_now().await;
                online
            };
            let (first, second) = tokio::join!(
                network.resolve(round.clone(), probe),
                network.resolve(round, probe)
            );
            assert_eq!((first, second), (online, online));
            assert_eq!(calls.load(Ordering::Relaxed), 1);
            assert_eq!(network.offline(), !online);
            if !online {
                network.periodic_with(|_| async { true }).await;
                assert!(!network.offline());
                assert_eq!(network.updates().borrow().recoveries, 1);
            }
        }
    }

    #[tokio::test]
    async fn settings_change_discards_an_in_flight_verdict() {
        let network = Arc::new(Connectivity::new(ProbeHosts::default()));
        let ticket = network.ticket();
        let round = ready_round(&network);
        let (started, waiting) = tokio::sync::oneshot::channel();
        let pending = tokio::spawn({
            let network = network.clone();
            async move {
                network
                    .resolve(round, |_| async {
                        started.send(()).unwrap();
                        std::future::pending::<bool>().await
                    })
                    .await
            }
        });
        waiting.await.unwrap();
        network.configure(ProbeHosts {
            host: "127.0.0.1".into(),
            backup_host: None,
        });
        assert!(!pending.await.unwrap());
        assert_eq!(*network.commit_guard(Some(ticket)), Failure::Discard);
        assert!(!network.offline());
    }

    #[tokio::test]
    async fn a_reachable_backup_is_enough() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hosts = ProbeHosts {
            host: "::1".into(),
            backup_host: Some("127.0.0.1".into()),
        };
        assert!(hosts.reachable_on(port).await);
        assert!(listener.accept().await.is_ok());
    }

    #[tokio::test]
    async fn offline_failures_do_not_open_incidents_or_queue_notifications() {
        let db = Store::open(Path::new(":memory:")).unwrap();
        let source = Source {
            id: "fleet".into(),
            name: "Fixture".into(),
            kind: "manual".into(),
            location: "ops@first.invalid\nops@second.invalid".into(),
            last_sync: None,
            error: None,
        };
        db.import(&source, inventory::parse_manual(&source.location).unwrap())
            .unwrap();
        db.0.lock()
            .unwrap()
            .execute("UPDATE notification_control SET enabled=1", [])
            .unwrap();
        let servers = db.snapshot().unwrap().servers;
        let ticket = db.connectivity().ticket();
        let fail = |server, verdict| {
            let attempt = db.begin_metrics_check(server).unwrap();
            db.record_network_metrics(&attempt, server, Err("SSH timeout".into()), verdict)
                .unwrap();
        };
        fail(&servers[0], Some(ticket));
        assert!(
            !db.connectivity()
                .resolve(ready_round(db.connectivity()), |_| async { false })
                .await
        );
        for server in &servers {
            fail(server, None);
            fail(server, None);
        }
        let snapshot = db.snapshot().unwrap();
        assert!(snapshot.offline);
        assert!(snapshot.incidents.is_empty());
        let notification_count = || {
            db.0.lock()
                .unwrap()
                .query_row("SELECT count(*) FROM notification_events", [], |row| {
                    row.get::<_, usize>(0)
                })
                .unwrap()
        };
        assert_eq!(notification_count(), 0);
        for server in &snapshot.servers {
            assert_eq!(server.failures, u32::from(server.id == servers[0].id));
        }

        db.connectivity().ssh_reply(ticket);
        assert!(!db.snapshot().unwrap().offline);
        fail(&servers[1], Some(ticket)); // This reply belongs to the old network state.
        let current = db.connectivity().ticket();
        fail(&servers[1], Some(current));
        assert!(db.snapshot().unwrap().incidents.is_empty());
        fail(&servers[1], Some(current));
        assert_eq!(db.snapshot().unwrap().incidents.len(), 1);
        assert_eq!(notification_count(), 1);
    }
}
