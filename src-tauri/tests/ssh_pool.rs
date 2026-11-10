use cyberbot_lib::{model::Endpoint, ssh_pool::Pool};
use std::{path::PathBuf, time::Duration};

#[tokio::test]
#[ignore = "Requires disposable fixture: python3 scripts/test-ssh-pool.py"]
async fn a_dropped_handshake_recovers_and_concurrent_commands_share_the_master() {
    use tokio::{
        io::{AsyncBufReadExt, BufReader},
        net::{TcpListener, TcpStream},
    };
    let fixture = PathBuf::from(std::env::var("CYBERBOT_TEST_SSH_DIR").unwrap());
    let upstream_port: u16 = std::env::var("CYBERBOT_TEST_SSH_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    let proxy = tokio::spawn(async move {
        let (first, _) = listener.accept().await.unwrap();
        let mut banner = String::new();
        BufReader::new(first).read_line(&mut banner).await.unwrap();
        assert!(banner.starts_with("SSH-"));

        let (mut next, _) = listener.accept().await.unwrap();
        let mut upstream = TcpStream::connect(("127.0.0.1", upstream_port))
            .await
            .unwrap();
        tokio::io::copy_bidirectional(&mut next, &mut upstream)
            .await
            .unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    let trust = dir.path().join("known_hosts");
    let host_key = std::fs::read_to_string(fixture.join("known_hosts")).unwrap();
    let (_, key) = host_key.split_once(' ').unwrap();
    std::fs::write(&trust, format!("[127.0.0.1]:{proxy_port} {key}")).unwrap();
    let pool = Pool::new(1, Duration::from_secs(900), Some(fixture.join("config"))).unwrap();
    let endpoint = Endpoint {
        host: "127.0.0.1".into(),
        port: proxy_port,
        user: "ops".into(),
        identity_file: Some(fixture.join("key-0").to_string_lossy().into_owned()),
        known_hosts_file: Some(trust.to_string_lossy().into_owned()),
        jump_host: None,
    };
    let (first, second) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            command(&pool, &endpoint, "printf first"),
            command(&pool, &endpoint, "printf second")
        )
    })
    .await
    .unwrap();
    assert!(first.status.success() && second.status.success());
    assert_eq!(first.stdout, b"first");
    assert_eq!(second.stdout, b"second");
    assert_eq!(pool.stats().opened, 1);
    assert_eq!(pool.stats().reused, 1);
    pool.shutdown();
    tokio::time::timeout(Duration::from_secs(3), proxy)
        .await
        .unwrap()
        .unwrap();
}

async fn command(pool: &Pool, e: &Endpoint, command: &str) -> std::process::Output {
    let lease = pool.acquire(e).await.unwrap_or_else(|error| {
        panic!(
            "pool acquire for {command}, jump={:?}: {error}",
            e.jump_host
        )
    });
    let mut args = lease.options().unwrap();
    args.extend(["--".into(), e.host.clone(), command.into()]);
    tokio::process::Command::new("/usr/bin/ssh")
        .args(args)
        .kill_on_drop(true)
        .output()
        .await
        .unwrap()
}
#[tokio::test]
#[ignore = "Requires disposable fixture: python3 scripts/test-ssh-pool.py"]
async fn reuse_lru_trust_proxyjump_expiry_and_shutdown() {
    let fixture = PathBuf::from(std::env::var("CYBERBOT_TEST_SSH_DIR").unwrap());
    let dir = tempfile::tempdir().unwrap();
    let trust = dir.path().join("known_hosts");
    let config = dir.path().join("config");
    std::fs::copy(fixture.join("known_hosts"), &trust).unwrap();
    std::fs::write(&config, "").unwrap();
    let endpoint = |i| Endpoint {
        host: "127.0.0.1".into(),
        port: std::env::var("CYBERBOT_TEST_SSH_PORT")
            .unwrap()
            .parse()
            .unwrap(),
        user: "ops".into(),
        identity_file: Some(
            fixture
                .join(format!("key-{i}"))
                .to_string_lossy()
                .into_owned(),
        ),
        known_hosts_file: Some(trust.to_string_lossy().into_owned()),
        jump_host: None,
    };
    let pool = Pool::new(2, Duration::from_secs(900), Some(config.clone())).unwrap();
    let shared = endpoint(0);
    let (first, second) = tokio::join!(
        command(&pool, &shared, "true"),
        command(&pool, &shared, "true")
    );
    assert!(first.status.success() && second.status.success());
    assert_eq!(pool.stats().opened, 1);
    assert_eq!(pool.pids().len(), 1);
    let pid = pool.pids()[0];
    if std::env::var_os("CYBERBOT_TEST_POOL_ISOLATION").is_some() {
        let lease = pool.acquire(&endpoint(0)).await.unwrap();
        let args = lease.options().unwrap();
        let socket = args
            .iter()
            .find_map(|s| s.strip_prefix("-oControlPath="))
            .unwrap();
        let work = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let canary = tempfile::NamedTempFile::new().unwrap();
        let executable = std::path::Path::new(env!("CARGO_BIN_EXE_cyberbot"));
        let allowed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let forbidden = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let sb = work.path().join("probe.sb");
        std::fs::write(
            &sb,
            cyberbot_lib::isolation::profile(
                executable,
                work.path(),
                home.path(),
                &[allowed.local_addr().unwrap().port()],
                "probe",
            )
            .unwrap(),
        )
        .unwrap();
        let args = vec![
            "--isolation-probe".into(),
            canary.path().to_string_lossy().into_owned(),
            work.path().to_string_lossy().into_owned(),
            allowed.local_addr().unwrap().to_string(),
            forbidden.local_addr().unwrap().to_string(),
            socket.into(),
        ];
        let output = cyberbot_lib::isolation::command(executable, &args, work.path(), &sb, 1, "")
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["unixBlocked"], true);
        assert_eq!(report["passed"], true);
        println!("actual master socket Seatbelt probe: {report}");
    }
    let (a, b) = tokio::join!(pool.acquire(&shared), pool.acquire(&shared));
    drop(a.unwrap());
    drop(b.unwrap());
    assert_eq!(pool.pids(), [pid]);
    assert_eq!(pool.stats().opened, 1);
    assert_eq!(pool.stats().connections, 1);
    assert_eq!(
        command(&pool, &endpoint(0), "false").await.status.code(),
        Some(1)
    );
    assert_eq!(pool.pids(), [pid]);
    let keep = pool.acquire(&endpoint(0)).await.unwrap();
    assert!(command(&pool, &endpoint(1), "true").await.status.success());
    assert!(command(&pool, &endpoint(2), "true").await.status.success());
    assert_eq!(pool.stats().connections, 2);
    assert_eq!(pool.stats().evicted, 1);
    assert!(pool.pids().contains(&pid));
    let valid = std::fs::read(&trust).unwrap();
    let replacement = dir.path().join("new_known_hosts");
    std::fs::write(&replacement, "").unwrap();
    std::fs::rename(replacement, &trust).unwrap();
    assert!(pool.acquire(&endpoint(0)).await.is_err());
    assert!(keep.options().is_err());
    drop(keep);
    std::fs::write(&trust, &valid).unwrap();
    assert!(command(&pool, &endpoint(0), "true").await.status.success());
    assert!(!pool.pids().contains(&pid));
    pool.retain(&[endpoint(0)]);
    let crashed = pool.pids()[0];
    unsafe {
        libc::kill(crashed as i32, libc::SIGKILL);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(command(&pool, &endpoint(0), "true").await.status.success());
    let opened = pool.stats().opened;
    std::fs::write(&config, "Host *\n  User ops\n").unwrap();
    assert!(command(&pool, &endpoint(0), "true").await.status.success());
    assert_eq!(pool.stats().opened, opened + 1);
    // If a socket disappears, a passenger must not fall back to a fresh network connection.
    let lease = pool.acquire(&endpoint(0)).await.unwrap();
    let args = lease.options().unwrap();
    let socket = PathBuf::from(
        args.iter()
            .find_map(|v| v.strip_prefix("-oControlPath="))
            .unwrap(),
    );
    let moved = socket.with_extension("moved");
    std::fs::rename(&socket, &moved).unwrap();
    let mut args = lease.options().unwrap();
    args.extend(["--".into(), "127.0.0.1".into(), "true".into()]);
    let failed = tokio::process::Command::new("/usr/bin/ssh")
        .args(args)
        .output()
        .await
        .unwrap();
    std::fs::rename(&moved, &socket).unwrap();
    assert!(!failed.status.success());
    lease.invalidate();
    drop(lease);
    assert!(command(&pool, &endpoint(0), "true").await.status.success());
    pool.retain(&[]);
    assert_eq!(pool.stats().connections, 0);
    assert!(pool.acquire(&endpoint(0)).await.is_err());
    pool.shutdown();

    let jump_config=format!("Host fixture-jump\n  HostName 127.0.0.1\n  Port {}\n  User ops\n  IdentityFile {}\n  UserKnownHostsFile {}\n  StrictHostKeyChecking yes\n  IdentitiesOnly yes\n  IdentityAgent none\n  BatchMode yes\n  ControlPath none\n",endpoint(0).port,fixture.join("key-0").display(),trust.display());
    std::fs::write(&config, jump_config).unwrap();
    let key_line = String::from_utf8_lossy(&valid)
        .split_once(' ')
        .unwrap()
        .1
        .trim()
        .to_string();
    std::fs::write(
        &trust,
        format!("{}127.0.0.1 {key_line}\n", String::from_utf8_lossy(&valid)),
    )
    .unwrap();
    let jump_pool = Pool::new(1, Duration::from_secs(900), Some(config.clone())).unwrap();
    let mut jump = endpoint(0);
    jump.port = 22; // The bastion reaches the container's internal SSH port.
    jump.jump_host = Some("fixture-jump".into());
    let output = command(&jump_pool, &jump, "id -un").await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "ops");
    let pid = jump_pool.pids()[0];
    assert!(command(&jump_pool, &jump, "true").await.status.success());
    assert_eq!(jump_pool.pids(), [pid]);
    let lease = jump_pool.acquire(&jump).await.unwrap();
    let mut config_contents = std::fs::read_to_string(&config).unwrap();
    config_contents.push_str("  ServerAliveInterval 30\n");
    std::fs::write(&config, config_contents).unwrap();
    jump_pool.retain(std::slice::from_ref(&jump));
    assert!(lease.options().is_err());
    assert!(command(&jump_pool, &jump, "true").await.status.success());
    assert_ne!(jump_pool.pids(), [pid]);
    jump_pool.shutdown();

    let short = Pool::new(1, Duration::from_secs(1), Some(config)).unwrap();
    assert!(command(&short, &endpoint(0), "true").await.status.success());
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        short.pids().is_empty(),
        "native ControlPersist must expire idle masters"
    );
    short.retain(&[endpoint(0)]);
    assert_eq!(short.stats().connections, 0);
    short.shutdown();
    println!("reuse/concurrency/LRU/trust/config/no-fallback/reconnect/retirement/ProxyJump/idle/shutdown passed");
}
