//! Local desktop resource snapshots. No remote requests or journal events.
use serde::Serialize;

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Sample {
    cpu_percent: Option<f64>,
    memory_bytes: Option<u64>,
    rx_bytes: Option<u64>,
    tx_bytes: Option<u64>,
    duration_ms: u64,
}

#[cfg(target_os = "macos")]
pub(crate) use macos::{process_identity, sample, ProcessIdentity};

#[cfg(not(target_os = "macos"))]
pub(crate) async fn sample() -> Result<Sample, String> {
    Ok(Sample::default())
}

#[cfg(target_os = "macos")]
mod macos {
    use super::Sample;
    use std::{
        collections::{BTreeMap, BTreeSet, VecDeque},
        mem::{size_of, MaybeUninit},
        time::{Duration, Instant},
    };

    const WINDOW: Duration = Duration::from_secs(5);
    const TIMEOUT_SECONDS: u64 = 8;
    const MAX_PROCESSES: usize = 256;
    const NETTOP_PID_LIMIT: usize = 20;
    const OUTPUT_LIMIT: usize = 64 * 1024;
    static SAMPLING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct ProcessIdentity {
        pub(crate) pid: u32,
        started: u64,
    }

    #[derive(Clone, Copy)]
    struct Usage {
        identity: ProcessIdentity,
        cpu_ticks: u64,
        footprint: u64,
    }

    fn usage(pid: u32) -> Option<Usage> {
        let raw_pid = i32::try_from(pid).ok().filter(|pid| *pid > 0)?;
        let mut info = MaybeUninit::<libc::rusage_info_v2>::uninit();
        // The libproc ABI takes an opaque buffer for the selected rusage flavor.
        if unsafe { libc::proc_pid_rusage(raw_pid, libc::RUSAGE_INFO_V2, info.as_mut_ptr().cast()) }
            != 0
        {
            return None;
        }
        let info = unsafe { info.assume_init() };
        Some(Usage {
            identity: ProcessIdentity {
                pid,
                started: info.ri_proc_start_abstime,
            },
            cpu_ticks: info.ri_user_time.saturating_add(info.ri_system_time),
            footprint: info.ri_phys_footprint,
        })
    }

    pub(crate) fn process_identity(pid: u32) -> Option<ProcessIdentity> {
        usage(pid).map(|process| process.identity)
    }

    fn parent(pid: u32) -> Option<u32> {
        let mut info = MaybeUninit::<libc::proc_bsdinfo>::uninit();
        let size = size_of::<libc::proc_bsdinfo>() as i32;
        let read = unsafe {
            libc::proc_pidinfo(
                pid as i32,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        (read == size).then(|| unsafe { info.assume_init() }.pbi_ppid)
    }

    fn snapshot(root: u32, masters: &[ProcessIdentity]) -> BTreeMap<u32, Usage> {
        let mut processes = BTreeMap::new();
        let mut queue = VecDeque::new();
        if let Some(process) = usage(root) {
            processes.insert(root, process);
            queue.push_back(process.identity);
        }
        for &identity in masters {
            if processes.len() >= MAX_PROCESSES {
                break;
            }
            if let Some(process) = usage(identity.pid).filter(|u| u.identity == identity) {
                if processes.insert(identity.pid, process).is_none() {
                    queue.push_back(identity);
                }
            }
        }
        let mut children = [0_i32; MAX_PROCESSES];
        while let Some(identity) = queue.pop_front() {
            if processes.len() >= MAX_PROCESSES {
                break;
            }
            let count = unsafe {
                libc::proc_listchildpids(
                    identity.pid as i32,
                    children.as_mut_ptr().cast(),
                    size_of::<[i32; MAX_PROCESSES]>() as i32,
                )
            }
            .max(0) as usize;
            if process_identity(identity.pid) != Some(identity) {
                continue;
            }
            for &pid in children.iter().take(count).filter(|&&pid| pid > 0) {
                if processes.len() >= MAX_PROCESSES {
                    break;
                }
                let pid = pid as u32;
                if processes.contains_key(&pid) {
                    continue;
                }
                if let Some(process) = usage(pid).filter(|_| parent(pid) == Some(identity.pid)) {
                    processes.insert(pid, process);
                    queue.push_back(process.identity);
                }
            }
        }
        processes
    }

    #[allow(deprecated)] // Stable macOS ABI already available via libc.
    fn nanos_per_tick() -> Option<f64> {
        let mut info = libc::mach_timebase_info { numer: 0, denom: 0 };
        let result = unsafe { libc::mach_timebase_info(&mut info) };
        (result == 0 && info.numer != 0 && info.denom != 0)
            .then(|| f64::from(info.numer) / f64::from(info.denom))
    }

    fn network_delta(output: &[u8], pids: &BTreeSet<u32>) -> Option<(u64, u64)> {
        let mut frame = 0;
        let mut seen = BTreeSet::new();
        let (mut rx, mut tx) = (0_u64, 0_u64);
        for line in String::from_utf8_lossy(output).lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Piped CSV has one header per snapshot. Delta mode's first frame
            // contains the pre-existing counters, so only the second is used.
            if line == ",bytes_in,bytes_out," {
                frame += 1;
                continue;
            }
            if frame != 2 {
                continue;
            }
            let mut fields = line.strip_suffix(',')?.rsplitn(3, ',');
            let sent = fields.next()?;
            let received = fields.next()?;
            let (_, pid) = fields.next()?.trim_matches('"').rsplit_once('.')?;
            let pid = pid.parse().ok()?;
            if !pids.contains(&pid) {
                continue;
            }
            if !seen.insert(pid) {
                return None;
            }
            rx = rx.checked_add(received.parse().ok()?)?;
            tx = tx.checked_add(sent.parse().ok()?)?;
        }
        (frame == 2).then_some((rx, tx))
    }

    fn nettop_args(pids: impl ExactSizeIterator<Item = u32>, external: bool) -> Vec<String> {
        let mut args: Vec<String> = [
            "-n",
            "-P",
            "-x",
            "-d",
            "-s",
            "5",
            "-L",
            "2",
            "-J",
            "bytes_in,bytes_out",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        if external {
            args.extend(["-t".into(), "external".into()]);
        }
        // Large pools need one system-wide sample. summarize filters it by
        // process identity before any traffic is counted.
        if pids.len() <= NETTOP_PID_LIMIT {
            for pid in pids {
                args.extend(["-p".into(), pid.to_string()]);
            }
        }
        args
    }

    async fn network(pids: impl ExactSizeIterator<Item = u32>, external: bool) -> Option<Vec<u8>> {
        let output = crate::process::bounded(
            "/usr/bin/nettop",
            &nettop_args(pids, external),
            None,
            TIMEOUT_SECONDS,
            OUTPUT_LIMIT,
        )
        .await
        .ok()?;
        (output.success && output.stderr.is_empty()).then_some(output.stdout)
    }

    fn summarize(
        root: u32,
        before: &BTreeMap<u32, Usage>,
        after: &BTreeMap<u32, Usage>,
        elapsed: Duration,
        tick_ns: Option<f64>,
        nettop: Option<&[u8]>,
    ) -> Sample {
        let stable = before
            .iter()
            .filter_map(|(pid, first)| {
                let last = after
                    .get(pid)
                    .filter(|last| last.identity == first.identity)?;
                Some((*pid, last.cpu_ticks.checked_sub(first.cpu_ticks)))
            })
            .collect::<BTreeMap<_, _>>();
        let seconds = elapsed.as_secs_f64();
        let valid_window = stable.contains_key(&root)
            && elapsed >= WINDOW
            && elapsed <= Duration::from_secs(TIMEOUT_SECONDS + 1);
        let cpu_percent = if valid_window && stable[&root].is_some() {
            tick_ns.map(|ns| {
                stable.values().flatten().map(|&v| v as f64).sum::<f64>() * ns / (seconds * 1e7)
            })
        } else {
            None
        };
        let network = if valid_window {
            nettop.and_then(|raw| network_delta(raw, &stable.keys().copied().collect()))
        } else {
            None
        };
        Sample {
            cpu_percent,
            memory_bytes: after.contains_key(&root).then(|| {
                after
                    .values()
                    .fold(0_u64, |total, v| total.saturating_add(v.footprint))
            }),
            rx_bytes: network.map(|v| v.0),
            tx_bytes: network.map(|v| v.1),
            duration_ms: elapsed.as_millis().min(u64::MAX as u128) as u64,
        }
    }

    pub(crate) async fn sample() -> Result<Sample, String> {
        let _guard = SAMPLING
            .try_lock()
            .map_err(|_| "Measurement of resources is already under way")?;
        let root = std::process::id();
        let before = snapshot(root, &crate::ssh_pool::resource_masters());
        if !before.contains_key(&root) {
            return Ok(Sample::default());
        }
        let started = Instant::now();
        let (output, _) = tokio::join!(
            network(before.keys().copied(), true),
            tokio::time::sleep(WINDOW),
        );
        let after = snapshot(root, &crate::ssh_pool::resource_masters());
        Ok(summarize(
            root,
            &before,
            &after,
            started.elapsed(),
            nanos_per_tick(),
            output.as_deref(),
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn process(pid: u32, started: u64, cpu_ticks: u64) -> (u32, Usage) {
            (
                pid,
                Usage {
                    identity: ProcessIdentity { pid, started },
                    cpu_ticks,
                    footprint: 100,
                },
            )
        }

        #[test]
        fn nettop_switches_to_one_unfiltered_sample_above_twenty_pids() {
            let selected = nettop_args(1..21, true);
            let all = nettop_args(1..34, true);
            assert_eq!(selected.len(), all.len() + 40);
            assert_eq!(&selected[..all.len()], all.as_slice());
            assert_eq!(
                selected.windows(2).filter(|pair| pair[0] == "-p").count(),
                20
            );
            assert_eq!(&selected[selected.len() - 2..], ["-p", "20"]);
            assert!(!all.iter().any(|arg| arg == "-p"));
            assert!(all.windows(2).any(|pair| pair == ["-t", "external"]));
        }

        #[test]
        fn nettop_uses_only_the_delta_frame_and_preserves_directions() {
            let pids = BTreeSet::from([7, 8]);
            let output = b",bytes_in,bytes_out,\napp.7,1000,2000,\n,bytes_in,bytes_out,\n\
                app.7,15,25,\nssh.8,30,40,\nother.9,5000,6000,\n\xff.10,-,-,\n";
            assert_eq!(network_delta(output, &pids), Some((45, 65)));
            let zero = b",bytes_in,bytes_out,\n,bytes_in,bytes_out,\n";
            assert_eq!(network_delta(zero, &pids), Some((0, 0)));
            assert_eq!(network_delta(b",bytes_in,bytes_out,\n", &pids), None);
            assert_eq!(network_delta(b"", &pids), None);
            assert_eq!(
                network_delta(
                    b",bytes_in,bytes_out,\n,bytes_in,bytes_out,\napp.7,-,0,\n",
                    &pids
                ),
                None
            );
        }

        #[test]
        fn cpu_and_traffic_exclude_reused_and_disappeared_processes() {
            let before = BTreeMap::from([
                process(1, 1, 10),
                process(2, 2, 20),
                process(3, 3, 30),
                process(4, 4, 40),
            ]);
            let after = BTreeMap::from([
                process(1, 1, 1_000_000_010),
                process(2, 2, 500_000_020),
                process(3, 5, 5_000_000_000),
                process(5, 6, 5_000_000_000),
            ]);
            let output = b",bytes_in,bytes_out,\n,bytes_in,bytes_out,\n\
                app.1,1,2,\nssh.2,3,4,\nreused.3,20,30,\nexited.4,40,50,\n";
            let sample = summarize(1, &before, &after, WINDOW, Some(1.), Some(output));
            assert_eq!(sample.cpu_percent, Some(30.));
            assert_eq!(sample.memory_bytes, Some(400));
            assert_eq!((sample.rx_bytes, sample.tx_bytes), (Some(4), Some(6)));
            let failed = summarize(1, &before, &after, WINDOW, Some(1.), None);
            assert_eq!((failed.rx_bytes, failed.tx_bytes), (None, None));
            assert_eq!(failed.cpu_percent, Some(30.));
            assert_eq!(failed.duration_ms, 5000);
        }

        #[tokio::test]
        async fn overlapping_samples_are_rejected() {
            let _guard = SAMPLING.lock().await;
            assert!(sample().await.is_err());
        }

        #[tokio::test]
        #[ignore = "Requires the disposable SSH fixture and nettop on macOS"]
        async fn macos_measures_real_detached_ssh_and_child_load() {
            use std::{path::PathBuf, process::Stdio};
            let fixture = PathBuf::from(std::env::var_os("CYBERBOT_TEST_SSH_DIR").unwrap());
            let pool = crate::ssh_pool::Pool::new(
                2,
                Duration::from_secs(60),
                Some(fixture.join("config")),
            )
            .unwrap();
            crate::ssh_pool::install(pool.clone()).unwrap();
            let endpoint = crate::model::Endpoint {
                host: "127.0.0.1".into(),
                user: "ops".into(),
                port: std::env::var("CYBERBOT_TEST_SSH_PORT")
                    .unwrap()
                    .parse()
                    .unwrap(),
                identity_file: Some(fixture.join("key-0").to_string_lossy().into_owned()),
                jump_host: None,
                known_hosts_file: Some(fixture.join("known_hosts").to_string_lossy().into_owned()),
            };
            let lease = pool.acquire(&endpoint).await.unwrap();
            let masters = crate::ssh_pool::resource_masters();
            let [master] = masters.as_slice() else {
                panic!("expected cached SSH master");
            };
            let root = std::process::id();
            assert_ne!(parent(master.pid), Some(root));
            assert_eq!(process_identity(master.pid), Some(*master));
            let mut busy = tokio::process::Command::new("/bin/sh")
                .args(["-c", "while :; do :; done"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let busy_pid = busy.id().unwrap();
            let journal = tempfile::tempdir().unwrap();
            crate::activity::install(journal.path(), &[]);
            let journal_bytes = crate::activity::status().bytes;
            let before = snapshot(root, &masters);
            assert!(before.contains_key(&master.pid) && before.contains_key(&busy_pid));
            let started = Instant::now();
            let mut args = lease.options().unwrap();
            args.extend([
                "--".into(),
                endpoint.host.clone(),
                "head -c 131072 >/dev/null; head -c 8192 /dev/zero".into(),
            ]);
            let send = async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                crate::process::bounded("/usr/bin/ssh", &args, Some(&[b'x'; 131072]), 5, 16384)
                    .await
                    .unwrap()
            };
            // The disposable sshd uses loopback. Enable that interface only in the test.
            let (raw, transfer, _) = tokio::join!(
                network(std::iter::once(master.pid), false),
                send,
                tokio::time::sleep(WINDOW)
            );
            let after = snapshot(root, &masters);
            assert!(transfer.success && transfer.stdout.len() == 8192);
            let result = summarize(
                root,
                &before,
                &after,
                started.elapsed(),
                nanos_per_tick(),
                raw.as_deref(),
            );
            let cpu = result.cpu_percent.unwrap();
            let (rx, tx) = (result.rx_bytes.unwrap(), result.tx_bytes.unwrap());
            assert!(cpu > 10. && cpu < 350., "CPU % of one core: {cpu}");
            assert!(result.memory_bytes.unwrap() > after[&root].footprint);
            assert!(
                rx >= 8192 && tx >= 131072 && tx > rx,
                "received {rx}, sent {tx}"
            );
            assert_eq!(crate::activity::status().bytes, journal_bytes);
            println!(
                "CPU {cpu:.1}% of one core, RAM {} bytes, received {rx} bytes, sent {tx} bytes",
                result.memory_bytes.unwrap()
            );
            busy.kill().await.unwrap();
            let external = sample().await.unwrap();
            assert_eq!((external.rx_bytes, external.tx_bytes), (Some(0), Some(0)));
            assert_eq!(crate::activity::status().bytes, journal_bytes);
            drop(lease);
            pool.shutdown();
        }
    }
}
