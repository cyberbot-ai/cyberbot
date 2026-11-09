use crate::{instances, model::Server, monitoring};
use std::{
    collections::{BTreeMap, HashMap},
    time::Instant,
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Priority {
    Metrics(i64),
    AfterSsh(Instant),
    Scheduled(i64),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Work {
    AfterSsh,
    Scheduled { kind: String, instance: String },
}

#[derive(Default)]
pub(crate) struct Schedule {
    pub logs: BTreeMap<String, i64>,
    pub packages: BTreeMap<String, i64>,
    pub services: Vec<(i64, String, String, String)>,
    pub after_ssh: HashMap<String, Instant>,
}

impl Schedule {
    pub(crate) fn due<'a>(
        &self,
        servers: impl IntoIterator<Item = &'a Server>,
        book: &monitoring::Book,
        now: i64,
        monotonic_now: Instant,
    ) -> impl Iterator<Item = (&'a Server, Work)> {
        let mut due: Vec<_> = servers
            .into_iter()
            .filter_map(|server| {
                let (priority, work) = self.next(server, book, now, monotonic_now)?;
                Some((priority, server, work))
            })
            .collect();
        due.sort_by_key(|(priority, _, _)| *priority);
        due.into_iter().map(|(_, server, work)| (server, work))
    }

    fn next(
        &self,
        server: &Server,
        book: &monitoring::Book,
        now: i64,
        monotonic_now: Instant,
    ) -> Option<(Priority, Work)> {
        let id = &server.id;
        if server.next_check <= now && book.enabled("metrics", id, "") {
            return Some((
                Priority::Metrics(server.next_check),
                Work::Scheduled {
                    kind: "metrics".into(),
                    instance: instances::default_id(),
                },
            ));
        }
        if let Some(&at) = self.after_ssh.get(id).filter(|&&at| at <= monotonic_now) {
            return Some((Priority::AfterSsh(at), Work::AfterSsh));
        }
        let candidates = [
            (self.logs.get(id), "logs"),
            (self.packages.get(id), "packages"),
        ]
        .into_iter()
        .filter_map(|(at, kind)| Some((*at?, kind.to_owned(), instances::default_id())))
        .chain(
            self.services
                .iter()
                .filter(|(_, server_id, _, _)| server_id == id)
                .map(|(at, _, kind, instance)| (*at, kind.clone(), instance.clone())),
        );
        let (at, kind, instance) = monitoring::next_candidate(book, id, candidates)?;
        (at <= now).then_some((Priority::Scheduled(at), Work::Scheduled { kind, instance }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{inventory, model::Source, store::Store};
    use std::{path::Path, time::Duration};

    fn fleet(count: usize) -> (Store, Vec<Server>) {
        let store = Store::open(Path::new(":memory:")).unwrap();
        let source = Source {
            id: "schedule".into(),
            name: "Schedule fixture".into(),
            kind: "manual".into(),
            location: (0..count)
                .map(|n| format!("ops@server-{n}.invalid"))
                .collect::<Vec<_>>()
                .join("\n"),
            last_sync: None,
            error: None,
        };
        store
            .import(&source, inventory::parse_manual(&source.location).unwrap())
            .unwrap();
        let servers = store.snapshot().unwrap().servers;
        assert_eq!(servers.len(), count);
        (store, servers)
    }

    #[test]
    fn metrics_stay_fresh_for_two_cycles_with_older_work_always_waiting() {
        const INTERVAL: i64 = 180;
        const FIRST_SAMPLE: i64 = 1000;
        const FLEET_SIZE: usize = 51;
        let (store, fleet) = fleet(FLEET_SIZE);
        let book = store.monitoring_book().unwrap();
        let mut schedule = Schedule::default();
        for server in &fleet {
            // Model a backlog of discovery and log checks older than every metrics deadline.
            schedule.logs.insert(server.id.clone(), FIRST_SAMPLE - 10);
            schedule.services.push((
                FIRST_SAMPLE - 20,
                server.id.clone(),
                "redis".into(),
                instances::default_id(),
            ));
        }
        let monotonic_now = Instant::now();
        for slots in [4, 10] {
            let mut servers = fleet.clone();
            let mut last_sample = [FIRST_SAMPLE; FLEET_SIZE];
            let mut collected = [0; FLEET_SIZE];
            for (index, server) in servers.iter_mut().enumerate() {
                server.next_check = FIRST_SAMPLE + INTERVAL + index as i64 % 20;
            }
            let mut service_runs = 0;
            for now in (FIRST_SAMPLE + INTERVAL..=FIRST_SAMPLE + 2 * INTERVAL + 90).step_by(5) {
                let batch = schedule
                    .due(&servers, &book, now, monotonic_now)
                    .take(slots)
                    .map(|(server, work)| (server.id.clone(), work))
                    .collect::<Vec<_>>();
                for (id, work) in batch {
                    if matches!(work, Work::Scheduled { ref kind, .. } if kind == "metrics") {
                        let index = servers.iter().position(|s| s.id == id).unwrap();
                        let server = &mut servers[index];
                        assert!(server.next_check <= now);
                        let finished_at = now + 2;
                        assert!(finished_at - last_sample[index] <= 2 * INTERVAL + 30);
                        last_sample[index] = finished_at;
                        collected[index] += 1;
                        server.next_check = finished_at + INTERVAL + index as i64 % 20;
                    } else {
                        service_runs += 1;
                    }
                }
            }
            assert_eq!(collected, [2; FLEET_SIZE], "concurrency {slots}");
            assert!(service_runs > 0, "concurrency {slots}");
        }
    }

    #[test]
    fn dispatches_due_metrics_before_package_refresh_and_keeps_other_deadlines() {
        let (store, mut servers) = fleet(5);
        let disabled = monitoring::scope("metrics", Some(&servers[2].id), None);
        let revision = store.monitoring_policy(&disabled).unwrap().revision;
        store
            .set_monitoring(
                &disabled,
                monitoring::Overrides {
                    enabled: Some(false),
                    ..Default::default()
                },
                revision,
            )
            .unwrap();
        let book = store.monitoring_book().unwrap();
        let now = Instant::now();
        for (server, at) in servers.iter_mut().zip([100, 90, 1, 101, 200]) {
            server.next_check = at;
        }
        let schedule = Schedule {
            logs: BTreeMap::from([(servers[3].id.clone(), 10), (servers[4].id.clone(), 5)]),
            services: vec![(6, servers[3].id.clone(), "redis".into(), "default".into())],
            after_ssh: HashMap::from([
                (servers[0].id.clone(), now),
                (servers[2].id.clone(), now),
                (servers[3].id.clone(), now + Duration::from_secs(1)),
            ]),
            ..Default::default()
        };
        let scheduled = |kind: &str| Work::Scheduled {
            kind: kind.into(),
            instance: instances::default_id(),
        };
        assert_eq!(
            schedule
                .due(&servers, &book, 100, now)
                .map(|(server, work)| (server.id.as_str(), work))
                .collect::<Vec<_>>(),
            vec![
                (servers[1].id.as_str(), scheduled("metrics")),
                (servers[0].id.as_str(), scheduled("metrics")),
                (servers[2].id.as_str(), Work::AfterSsh),
                (servers[4].id.as_str(), scheduled("logs")),
                (servers[3].id.as_str(), scheduled("redis")),
            ],
        );
    }
}
