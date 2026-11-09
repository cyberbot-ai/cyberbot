//! Opt-in local fixture driver. Uses the production pool, never user SSH configuration.
use cyberbot_lib::{model::Endpoint, ssh_pool::Pool};
use std::{
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = PathBuf::from(std::env::var("CYBERBOT_TEST_SSH_DIR")?);
    let port: u16 = std::env::var("CYBERBOT_TEST_SSH_PORT")?.parse()?;
    let count: usize = std::env::args().nth(1).unwrap_or("100".into()).parse()?;
    if count == 0 || count > 100 {
        return Err("fixture count must be 1..100".into());
    }
    let pool = Pool::new(count, Duration::from_secs(900), Some(dir.join("config")))?;
    let endpoint = |i: usize| Endpoint {
        host: "127.0.0.1".into(),
        port,
        user: "ops".into(),
        identity_file: Some(dir.join(format!("key-{i}")).to_string_lossy().into_owned()),
        known_hosts_file: Some(dir.join("known_hosts").to_string_lossy().into_owned()),
        jump_host: None,
    };
    let start = std::time::Instant::now();
    for i in 0..count {
        let e = endpoint(i);
        let lease = pool.acquire(&e).await?;
        let mut args = lease.options()?;
        args.extend(["--".into(), e.host.clone(), "true".into()]);
        let output = tokio::process::Command::new("/usr/bin/ssh")
            .args(args)
            .kill_on_drop(true)
            .output()
            .await?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
        }
    }
    // Verify reuse on every connection, including the same master PID.
    let before = pool.pids();
    for i in 0..count {
        let _lease = pool.acquire(&endpoint(i)).await?;
    }
    let after = pool.pids();
    if before.len() != count
        || before.iter().any(|pid| !after.contains(pid))
        || pool.stats().opened != count as u64
    {
        return Err("masters were not reused".into());
    }
    println!(
        "{}",
        serde_json::json!({"stage":"ready","driverPid":std::process::id(),"driverArchitecture":std::env::consts::ARCH,"pids":after,"stats":pool.stats(),"setupMs":start.elapsed().as_millis(),"keepaliveSeconds":60,"idleSeconds":900})
    );
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    pool.shutdown();
    println!(
        "{}",
        serde_json::json!({"stage":"closed","stats":pool.stats()})
    );
    Ok(())
}
