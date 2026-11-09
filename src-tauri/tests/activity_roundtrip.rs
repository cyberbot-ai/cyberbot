#[test]
fn journal_records_real_local_processes_and_ssh_and_rotates_at_30_mib() {
    let root = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_cyberbot"))
        .arg("--activity-smoke")
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "completed");
    assert_eq!(value["privacy"], true);
    assert!(value["sshAttempts"].as_u64().unwrap() >= 1);
    assert!(value["bytes"].as_u64().unwrap() <= 30 * 1024 * 1024);
    assert!(value["files"].as_u64().unwrap() <= 3);
    assert_eq!(value["pageEvents"], 100);
    println!("{value}");
}
