//! Coalesced, endpoint-bound package checks after remote shell activity.
use crate::{
    model::{Endpoint, Server},
    store::Store,
};
use std::{
    collections::{BTreeSet, HashMap},
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::sync::Notify;
use uuid::Uuid;

const SPACING: Duration = Duration::from_secs(10);
const TERMINAL_DELAYS: [u64; 5] = [5, 30, 120, 300, 600];
const RETRY_WINDOW: Duration = Duration::from_secs(600);

#[derive(Default)]
pub(crate) struct Queue {
    entries: Mutex<HashMap<String, Entry>>,
    advisories: Mutex<BTreeSet<String>>,
    pub(crate) wake: Notify,
}

struct Entry {
    endpoint: Endpoint,
    immediate: Option<(Instant, Instant)>,
    terminals: HashMap<Uuid, TerminalRetry>,
    last_start: Option<Instant>,
    backoff: Option<Instant>,
    running: bool,
    assessment: Option<u64>,
}

struct TerminalRetry {
    submitted: Instant,
    step: usize,
}

pub(crate) struct Job {
    pub(crate) endpoint: Endpoint,
    terminals: Vec<(Uuid, Instant)>,
    immediate: Option<(Instant, Instant)>,
    previous_start: Option<Instant>,
    started: Instant,
}

pub(crate) enum Outcome {
    Collected { checks: u64, changed: bool },
    Contended,
    Busy,
    Failed(Duration),
    Obsolete,
}

impl Entry {
    fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            immediate: None,
            terminals: HashMap::new(),
            last_start: None,
            backoff: None,
            running: false,
            assessment: None,
        }
    }

    fn request(&mut self, at: Instant, until: Instant) {
        let (at, until) = self.immediate.map_or((at, until), |(old, deadline)| {
            (at.min(old), until.max(deadline))
        });
        self.immediate = Some((at, until));
    }

    fn due(&self) -> Option<Instant> {
        if self.running {
            return None;
        }
        let at = self
            .immediate
            .map(|(at, _)| at)
            .into_iter()
            .chain(self.terminals.values().filter_map(TerminalRetry::due))
            .min()?;
        Some(
            self.last_start
                .map(|start| start + SPACING)
                .into_iter()
                .chain(self.backoff)
                .fold(at, Instant::max),
        )
    }
}

impl TerminalRetry {
    fn due(&self) -> Option<Instant> {
        TERMINAL_DELAYS
            .get(self.step)
            .map(|&delay| self.submitted + Duration::from_secs(delay))
    }
}

impl Queue {
    fn signal(&self, id: &str, endpoint: &Endpoint, update: impl FnOnce(&mut Entry)) {
        if let Ok(mut entries) = self.entries.lock() {
            let entry = entries
                .entry(id.into())
                .or_insert_with(|| Entry::new(endpoint.clone()));
            if entry.endpoint != *endpoint {
                *entry = Entry::new(endpoint.clone());
            }
            update(entry);
            self.wake.notify_one();
        }
    }

    pub(crate) fn command_finished(&self, id: &str, endpoint: &Endpoint) {
        let now = Instant::now();
        self.signal(id, endpoint, |entry| entry.request(now, now + RETRY_WINDOW));
    }

    pub(crate) fn terminal_submitted(&self, id: &str, endpoint: &Endpoint, session: Uuid) {
        let submitted = Instant::now();
        self.signal(id, endpoint, |entry| {
            entry
                .terminals
                .insert(session, TerminalRetry { submitted, step: 0 });
        });
    }

    pub(crate) fn terminal_finished(&self, id: &str, endpoint: &Endpoint, session: Uuid) {
        let now = Instant::now();
        self.signal(id, endpoint, |entry| {
            entry.terminals.remove(&session);
            entry.request(now, now + RETRY_WINDOW);
        });
    }

    pub(crate) fn retain(&self, servers: &[Server], enabled: impl Fn(&str) -> bool) {
        if let Ok(mut entries) = self.entries.lock() {
            if entries.is_empty() {
                return;
            }
            let endpoints: HashMap<_, _> = servers
                .iter()
                .map(|s| (s.id.as_str(), &s.endpoint))
                .collect();
            let now = Instant::now();
            entries.retain(|id, entry| {
                endpoints.get(id.as_str()) == Some(&&entry.endpoint)
                    && enabled(id)
                    && (entry.due().is_some()
                        || entry.running
                        || entry.assessment.is_some()
                        || entry.last_start.is_some_and(|at| at + SPACING > now)
                        || entry.backoff.is_some_and(|at| at > now))
            });
        }
    }

    pub(crate) fn due(&self) -> HashMap<String, Instant> {
        self.entries
            .lock()
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|(id, entry)| Some((id.clone(), entry.due()?)))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn claim(&self, id: &str, endpoint: &Endpoint, now: Instant) -> Option<Job> {
        let mut entries = self.entries.lock().ok()?;
        let entry = entries.get_mut(id)?;
        if entry.endpoint != *endpoint || entry.due()? > now {
            return None;
        }
        let immediate = entry.immediate.take_if(|(at, _)| *at <= now);
        let terminals = entry
            .terminals
            .iter_mut()
            .filter_map(|(&session, retry)| {
                if retry.due()? > now {
                    return None;
                }
                while retry.due().is_some_and(|at| at <= now) {
                    retry.step += 1;
                }
                Some((session, retry.submitted))
            })
            .collect();
        entry.running = true;
        Some(Job {
            endpoint: endpoint.clone(),
            immediate,
            terminals,
            previous_start: entry.last_start.replace(now),
            started: now,
        })
    }

    pub(crate) fn finish(&self, id: &str, job: Job, outcome: Outcome, now: Instant) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        let Some(entry) = entries.get_mut(id).filter(|entry| {
            entry.endpoint == job.endpoint && entry.running && entry.last_start == Some(job.started)
        }) else {
            return;
        };
        entry.running = false;
        match outcome {
            Outcome::Collected { checks, changed } => {
                entry.backoff = None;
                entry.assessment = Some(checks);
                if changed {
                    for (session, submitted) in job.terminals {
                        if entry
                            .terminals
                            .get(&session)
                            .is_some_and(|retry| retry.submitted == submitted)
                        {
                            entry.terminals.remove(&session);
                        }
                    }
                }
            }
            Outcome::Contended => {
                entry.last_start = job.previous_start;
                // The terminal deadline was consumed by claim even when SSH never started.
                entry.request(
                    now + Duration::from_secs(1),
                    job.immediate.map_or(now + RETRY_WINDOW, |(_, until)| until),
                );
            }
            Outcome::Busy | Outcome::Failed(_) => {
                let delay = match outcome {
                    Outcome::Failed(delay) => delay.max(SPACING),
                    _ => SPACING,
                };
                entry.backoff = Some(now + delay);
                if let Some((_, until)) = job.immediate.filter(|(_, until)| now + delay <= *until) {
                    entry.request(now + delay, until);
                }
            }
            Outcome::Obsolete => {
                entries.remove(id);
                self.wake.notify_one();
                return;
            }
        }
        entry.terminals.retain(|_, retry| retry.due().is_some());
        self.wake.notify_one();
    }

    fn assessments(&self) -> Vec<(String, Endpoint, u64)> {
        self.entries
            .lock()
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|(id, entry)| {
                        Some((id.clone(), entry.endpoint.clone(), entry.assessment?))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn awaiting_assessment(&self) -> BTreeSet<String> {
        self.entries
            .lock()
            .map(|entries| {
                entries
                    .iter()
                    .filter(|(_, entry)| entry.assessment.is_some())
                    .map(|(id, _)| id.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn assessed(&self, id: &str, endpoint: &Endpoint, checks: u64, confirm: bool, now: Instant) {
        if let Ok(mut entries) = self.entries.lock() {
            if let Some(entry) = entries
                .get_mut(id)
                .filter(|entry| entry.endpoint == *endpoint && entry.assessment == Some(checks))
            {
                entry.assessment = None;
                if confirm {
                    entry.request(now + SPACING, now + RETRY_WINDOW);
                }
            }
        }
    }

    pub(crate) fn reconcile_assessments(&self, store: &Store, now: Instant) {
        for (id, endpoint, checks) in self.assessments() {
            if let Ok(Some(confirm)) = store.vulnerability_recovery_pending(&id, checks) {
                self.assessed(&id, &endpoint, checks, confirm, now);
            }
        }
    }

    pub(crate) fn prioritize_advisory(&self, source: String) {
        if let Ok(mut sources) = self.advisories.lock() {
            sources.insert(source);
            self.wake.notify_one();
        }
    }

    pub(crate) fn defer_advisories(&self, pending: impl IntoIterator<Item = String>) {
        if let Ok(mut sources) = self.advisories.lock() {
            sources.extend(pending);
        }
    }

    pub(crate) fn take_advisories(&self) -> BTreeSet<String> {
        self.advisories
            .lock()
            .map(|mut sources| std::mem::take(&mut *sources))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> Endpoint {
        Endpoint {
            host: "host".into(),
            user: "ops".into(),
            port: 22,
            identity_file: None,
            jump_host: None,
            known_hosts_file: None,
        }
    }

    #[test]
    fn commands_coalesce_but_activity_during_collection_survives() {
        let queue = Queue::default();
        let endpoint = endpoint();
        queue.command_finished("server", &endpoint);
        queue.command_finished("server", &endpoint);
        let start = Instant::now();
        let first = queue.claim("server", &endpoint, start).unwrap();
        queue.command_finished("server", &endpoint);
        assert!(queue.claim("server", &endpoint, start + SPACING).is_none());
        queue.finish(
            "server",
            first,
            Outcome::Collected {
                checks: 1,
                changed: true,
            },
            start,
        );
        assert_eq!(queue.due()["server"], start + SPACING);
        let next = queue.claim("server", &endpoint, start + SPACING).unwrap();
        queue.finish(
            "server",
            next,
            Outcome::Collected {
                checks: 2,
                changed: false,
            },
            start + SPACING,
        );
        assert!(queue.due().is_empty());
        assert_eq!(queue.assessments()[0].2, 2);
        assert!(queue
            .claim(
                "server",
                &Endpoint {
                    port: 23,
                    ..endpoint
                },
                start + SPACING
            )
            .is_none());
        queue.retain(&[], |_| true);
        assert!(queue.assessments().is_empty());
    }

    #[test]
    fn terminal_rechecks_while_open_and_runs_a_final_check_on_close() {
        let queue = Queue::default();
        let endpoint = endpoint();
        let session = Uuid::new_v4();
        queue.terminal_submitted("server", &endpoint, session);
        let first = queue.due()["server"];
        assert!(first >= Instant::now() + Duration::from_secs(4));
        for (index, delay) in TERMINAL_DELAYS.into_iter().enumerate() {
            let at = first + Duration::from_secs(delay - TERMINAL_DELAYS[0]);
            assert_eq!(queue.due()["server"], at);
            let job = queue.claim("server", &endpoint, at).unwrap();
            let outcome = if index == 1 {
                Outcome::Busy
            } else {
                Outcome::Collected {
                    checks: index as u64,
                    changed: false,
                }
            };
            queue.finish("server", job, outcome, at);
        }
        assert!(queue.due().is_empty());
        queue.terminal_finished("server", &endpoint, session);
        assert_eq!(queue.due()["server"], first + Duration::from_secs(605));
    }

    #[test]
    fn busy_command_scan_retries_and_successful_change_clears_only_old_terminal_activity() {
        let queue = Queue::default();
        let endpoint = endpoint();
        let session = Uuid::new_v4();
        queue.command_finished("server", &endpoint);
        let start = Instant::now();
        let first = queue.claim("server", &endpoint, start).unwrap();
        queue.finish("server", first, Outcome::Busy, start);
        let at = start + SPACING;
        queue.terminal_submitted("server", &endpoint, session);
        let next = queue.claim("server", &endpoint, at).unwrap();
        let second_session = Uuid::new_v4();
        queue.terminal_submitted("server", &endpoint, second_session);
        queue.finish(
            "server",
            next,
            Outcome::Collected {
                checks: 1,
                changed: true,
            },
            at,
        );
        let entries = queue.entries.lock().unwrap();
        let terminals = &entries["server"].terminals;
        assert!(!terminals.contains_key(&session));
        assert!(terminals.contains_key(&second_session));
    }
}
