use cyberbot_lib::{model::Endpoint, ssh};

#[tokio::test]
#[ignore = "Requires disposable SSH fixture: python3 scripts/test-ssh.py"]
async fn real_ssh_rsync_and_collection() {
    let dir = std::env::var("CYBERBOT_TEST_SSH_DIR").expect("fixture directory");
    let endpoint = Endpoint {
        host: "127.0.0.1".into(),
        user: "ops".into(),
        port: std::env::var("CYBERBOT_TEST_SSH_PORT")
            .unwrap()
            .parse()
            .unwrap(),
        identity_file: Some(format!("{dir}/id_ed25519")),
        known_hosts_file: Some(format!("{dir}/known_hosts")),
        jump_host: None,
    };
    let local = tempfile::tempdir().unwrap();
    let config = local.path().join("config");
    std::fs::write(&config, "").unwrap();
    cyberbot_lib::ssh_pool::install(
        cyberbot_lib::ssh_pool::Pool::new(32, std::time::Duration::from_secs(900), Some(config))
            .unwrap(),
    )
    .unwrap();
    let path = ssh::write_collector(local.path()).unwrap();
    let first = ssh::collect(&endpoint, &path)
        .await
        .expect("first SSH collection");
    assert!(first.cpu_percent.is_some());
    assert!(first.memory_percent.is_some());
    assert!(first.bytes_received <= 8192);
    let platform = first.platform.as_ref().expect("Linux capabilities");
    assert_eq!(platform.distro, "debian");
    assert_eq!(platform.package_adapter, "dpkg");
    assert!(platform.procfs);
    let second = ssh::collect(&endpoint, &path)
        .await
        .expect("cached SSH collection");
    assert!(second.bytes_received <= 8192);
    println!(
        "first={}B/{}ms cached={}B/{}ms",
        first.bytes_received, first.duration_ms, second.bytes_received, second.duration_ms
    );
    let logs = ssh::run_collector(
        &endpoint,
        &serde_json::json!({"kind":"logs","salt":"a".repeat(64)}),
        32768,
    )
    .await
    .unwrap();
    assert!(logs.len() <= 32768);
    let unknown = ssh::run_collector(
        &endpoint,
        &serde_json::json!({"kind":"exec","command":"id"}),
        32768,
    )
    .await;
    assert!(unknown.is_err());
    assert_eq!(
        cyberbot_lib::ssh_pool::global().unwrap().stats().opened,
        1,
        "rsync and every collector must share the master"
    );
    let mut untrusted = endpoint.clone();
    untrusted.known_hosts_file = Some(format!("{dir}/empty_known_hosts"));
    assert!(ssh::collect(&untrusted, &path).await.is_err());
    cyberbot_lib::ssh_pool::shutdown_global();
}
