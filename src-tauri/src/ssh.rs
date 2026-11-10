use crate::{
    inventory::validate_endpoint,
    model::{Endpoint, Observation},
    process,
};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::Instant,
};

pub const COLLECTOR: &str = include_str!(concat!(env!("OUT_DIR"), "/collector.py"));
fn digest() -> &'static str {
    static DIGEST: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DIGEST.get_or_init(|| format!("{:x}", Sha256::digest(COLLECTOR.as_bytes())))
}
pub fn version() -> String {
    digest()[..24].into()
}
pub fn write_collector(root: &Path) -> Result<PathBuf, String> {
    let dir = root.join("collectors");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{}.py", version()));
    if !path.exists() {
        std::fs::write(&path, COLLECTOR).map_err(|e| e.to_string())?;
    }
    Ok(path)
}
pub fn options(e: &Endpoint) -> Result<Vec<String>, String> {
    options_with_pty(e, false)
}

pub(crate) fn options_with_pty(e: &Endpoint, tty: bool) -> Result<Vec<String>, String> {
    validate_endpoint(e)?;
    let mut args = vec![
        if tty { "-tt" } else { "-T" }.into(),
        "-oBatchMode=yes".into(),
        "-oStrictHostKeyChecking=yes".into(),
        "-oConnectTimeout=8".into(),
        format!(
            "-oServerAliveInterval={}",
            crate::ssh_pool::KEEPALIVE_SECONDS
        ),
        "-oServerAliveCountMax=2".into(),
        "-oForwardAgent=no".into(),
        "-oForwardX11=no".into(),
        "-oForkAfterAuthentication=no".into(),
        "-oRemoteCommand=none".into(),
        "-oClearAllForwardings=yes".into(),
        "-oPermitLocalCommand=no".into(),
        "-p".into(),
        e.port.to_string(),
    ];
    if tty {
        args.extend(["-e".into(), "none".into()]);
    }
    if !e.user.is_empty() {
        args.extend(["-l".into(), e.user.clone()]);
    }
    if let Some(key) = &e.identity_file {
        args.extend(["-i".into(), key.clone()]);
    }
    if let Some(jump) = &e.jump_host {
        args.extend(["-J".into(), jump.clone()]);
    }
    if let Some(hosts) = &e.known_hosts_file {
        args.extend(["-o".into(), format!("UserKnownHostsFile={hosts}")]);
    }
    Ok(args)
}
fn login(e: &Endpoint) -> String {
    let host = if e.host.contains(':') {
        format!("[{}]", e.host)
    } else {
        e.host.clone()
    };
    if e.user.is_empty() {
        host
    } else {
        format!("{}@{host}", e.user)
    }
}
pub(crate) fn target(e: &Endpoint) -> String {
    format!(
        "{}:{}{}",
        login(e),
        e.port,
        e.jump_host
            .as_ref()
            .map(|j| format!(" via {j}"))
            .unwrap_or_default()
    )
}
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
async fn command(
    e: &Endpoint,
    action: &str,
    remote: &str,
    input: Option<&[u8]>,
    cap: usize,
) -> Result<process::Output, String> {
    let lease = crate::ssh_pool::global()?.acquire(e).await?;
    command_on_lease(e, &lease, action, remote, input, cap).await
}
async fn command_on_lease(
    e: &Endpoint,
    lease: &crate::ssh_pool::Lease,
    action: &str,
    remote: &str,
    input: Option<&[u8]>,
    cap: usize,
) -> Result<process::Output, String> {
    crate::ssh_authorization::check(lease)?;
    let mut args = lease.options()?;
    args.extend(["--".into(), e.host.clone(), remote.into()]);
    transport(e, action, &args, input, cap, Some(lease), None).await
}
async fn transport(
    e: &Endpoint,
    action: &str,
    args: &[String],
    input: Option<&[u8]>,
    cap: usize,
    lease: Option<&crate::ssh_pool::Lease>,
    watch: Option<(
        &tokio_util::sync::CancellationToken,
        &std::sync::atomic::AtomicBool,
    )>,
) -> Result<process::Output, String> {
    let mut operation = crate::activity::begin("server", action, Some(target(e)));
    let output = match watch {
        Some((cancel, sent)) => {
            process::watched_ssh(args, input.ok_or("No shell request")?, cap, cancel, sent).await
        }
        None => process::bounded("/usr/bin/ssh", args, input, 25, cap).await,
    };
    if lease.is_some() && output.as_ref().is_ok_and(connected) {
        crate::connectivity::ssh_reply();
    }
    if !output.as_ref().is_ok_and(connected)
        && !watch.is_some_and(|(cancel, _)| cancel.is_cancelled())
    {
        if let Some(lease) = lease {
            lease.invalidate();
        }
    }
    let cache_miss = action == "Check collector version"
        && output
            .as_ref()
            .is_ok_and(|o| o.exit_code == Some(1) && o.stderr.is_empty());
    let result = output.and_then(|o| {
        if o.success {
            Ok(o)
        } else {
            Err(package_collector_error(action, &o)
                .map(str::to_owned)
                .unwrap_or_else(|| classify_error(&o.stderr)))
        }
    });
    if cache_miss {
        operation.finish_as("info", "Collector deployment required");
    } else {
        operation.result(&result);
    }
    result
}
// OpenSSH returns the remote exit status; 255 denotes transport/authentication failure.
fn connected(output: &process::Output) -> bool {
    output.exit_code.is_some_and(|code| code != 255)
}

// The journal fixture must never inherit a user's ProxyJump/ProxyCommand or credentials.
pub(crate) async fn isolated_activity_probe(e: &Endpoint) -> Result<process::Output, String> {
    if e.host != "127.0.0.1" || e.identity_file.is_some() || e.jump_host.is_some() {
        return Err("The test is only allowed on loopback".into());
    }
    let mut args = vec![
        "-F".into(),
        "/dev/null".into(),
        "-oProxyCommand=none".into(),
        "-oProxyJump=none".into(),
        "-oIdentityAgent=none".into(),
        "-oPubkeyAuthentication=no".into(),
        "-oPasswordAuthentication=no".into(),
        "-oKbdInteractiveAuthentication=no".into(),
        "-oUserKnownHostsFile=/dev/null".into(),
        "-oGlobalKnownHostsFile=/dev/null".into(),
        "-oControlPath=none".into(),
        "-oControlMaster=no".into(),
        "-oControlPersist=no".into(),
    ];
    args.extend(options(e)?);
    args.extend(["--".into(), e.host.clone(), "true".into()]);
    let mut connection = crate::activity::begin("ssh", "SSH connection", Some(target(e)));
    let result = transport(e, "Test SSH operation", &args, None, 1024, None, None).await;
    connection.result(&result);
    result
}

pub fn classify_error(message: &str) -> String {
    if message.contains("Host key verification failed")
        || message.contains("REMOTE HOST IDENTIFICATION HAS CHANGED")
    {
        "The SSH host key is unknown or has changed. Verify it with OpenSSH in a terminal.".into()
    } else if message.contains("Permission denied") {
        "SSH authentication failed or permission denied".into()
    } else if message.contains("Could not resolve") {
        "SSH could not resolve the server hostname".into()
    } else if message.contains("Connection refused") {
        "SSH connection refused".into()
    } else {
        format!("SSH: {}", message.chars().take(500).collect::<String>())
    }
}

pub(crate) const PACKAGE_DATABASE_BUSY: &str =
    "The package database changed during the check. Try again after the installation or update finishes.";

fn package_collector_error(action: &str, output: &process::Output) -> Option<&'static str> {
    if !matches!(action, "Collect installed packages" | "Check APT updates") || !connected(output) {
        return None;
    }
    let error: serde_json::Value = serde_json::from_str(&output.stderr).ok()?;
    let code = error["packageError"]
        .as_str()
        .or_else(|| error["error"].as_str())?;
    Some(match code {
        "package_adapter_unsupported" => "Package collection for this OS is not yet supported.",
        "package_database_busy" | "package_database_changed" => PACKAGE_DATABASE_BUSY,
        "package_permission_denied" => {
            "The SSH user does not have access to the installed package database."
        }
        "package_read_failed" => "The collector could not read the database of installed packages.",
        "package_format" => "The installed package database contains an unsupported record format.",
        "package_limit" => "The list of installed packages exceeded the limit of the collector.",
        "apt_unsupported" => "Checking for package updates is unsupported on this OS.",
        "apt_scope_changed" => "Rescan installed packages, then check for updates again.",
        "apt_missing" => "apt-cache is missing from the server.",
        "apt_permission_denied" => "The SSH user cannot run apt-cache.",
        "apt_timeout" => "apt-cache timed out while reading repository data.",
        "apt_memory_limit" => "APT did not have enough memory to read repository data.",
        "apt_temp_file_limit" => {
            "An APT temporary file exceeded the size limit while reading the repository index."
        }
        "apt_read_failed" => "apt-cache failed to read repository data.",
        "apt_output_limit" => "The apt-cache response exceeded the size limit.",
        _ => "The collector on the server was unable to process the data.",
    })
}
pub async fn deploy(e: &Endpoint, path: &Path) -> Result<(), String> {
    let hash = version();
    let remote = format!(".cache/cyberbot/{hash}.py");
    // A hash-named immutable target is activated only after byte verification.
    // A bounded check avoids rsync negotiation on every metric collection.
    let probe = format!("test -f \"$HOME/{remote}\" && sha256sum \"$HOME/{remote}\"");
    let expected = digest();
    let installed = {
        let lease = crate::ssh_pool::global()?.acquire(e).await?;
        command_on_lease(e, &lease, "Check collector version", &probe, None, 1024).await
    };
    if let Ok(output) = installed {
        if String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .next()
            == Some(expected)
        {
            return Ok(());
        }
    }
    command(
        e,
        "Prepare collector directory",
        "umask 077; mkdir -p \"$HOME/.cache/cyberbot\"",
        None,
        1024,
    )
    .await?;
    let lease = crate::ssh_pool::global()?.acquire(e).await?;
    crate::ssh_authorization::check(&lease)?;
    let transport = format!(
        "/usr/bin/ssh {}",
        lease
            .options()?
            .iter()
            .map(|v| quote(v))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let destination = format!("{}:{remote}", login(e));
    let args = vec![
        "--checksum".into(),
        "--perms".into(),
        "--chmod=u=rw,go=".into(),
        "--timeout=15".into(),
        "-e".into(),
        transport,
        "--".into(),
        path.to_string_lossy().into_owned(),
        destination,
    ];
    crate::activity::info("ssh", "SSH channel for rsync", Some(target(e)));
    let mut delivery =
        crate::activity::begin("server", "Deploy collector with rsync", Some(target(e)));
    let result = process::bounded("/usr/bin/rsync", &args, None, 30, 4096).await;
    let ok = result.as_ref().is_ok_and(|o| o.success);
    if !ok {
        lease.invalidate();
    }
    delivery.finish(if ok { "completed" } else { "failed" });
    let output = result?;
    if !output.success {
        return Err(format!(
            "rsync: {}",
            output.stderr.chars().take(500).collect::<String>()
        ));
    }
    let output = command(e, "Check collector version", &probe, None, 1024).await?;
    if String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        != Some(expected)
    {
        return Err("Collector checksum mismatch".into());
    }
    Ok(())
}
pub async fn collect(e: &Endpoint, path: &Path) -> Result<Observation, String> {
    let start = Instant::now();
    deploy(e, path).await?;
    let output = run_collector(e, &serde_json::json!({"kind":"metrics"}), 8192).await?;
    decode_metrics(&output, start)
}

pub(crate) fn decode_metrics(output: &[u8], start: Instant) -> Result<Observation, String> {
    if output.len() > 8192 {
        return Err("Invalid metrics response size".into());
    }
    let mut observation: Observation =
        serde_json::from_slice(output).map_err(|e| format!("Invalid collector response: {e}"))?;
    if let Some(platform) = &observation.platform {
        platform.validate()?;
    }
    if observation.service_runtime.len() > 64
        || observation.service_runtime.iter().any(|r| {
            r.pid == 0
                || r.ports.len() > 16
                || r.ports.contains(&0)
                || r.sockets.len() > 4
                || r.sockets.iter().any(|v| v.len() > 160)
                || crate::services::descriptor(&r.kind).is_none()
        })
    {
        return Err("Invalid service process summary".into());
    }
    // Scheduling and freshness use local receipt time; remote clock is untrusted.
    observation.at = crate::model::now();
    observation.bytes_received = output.len();
    observation.duration_ms = start.elapsed().as_millis() as u64;
    for v in [
        observation.cpu_percent,
        observation.memory_percent,
        observation.swap_percent,
    ]
    .into_iter()
    .flatten()
    {
        if !v.is_finite() || !(0.0..=100.0).contains(&v) {
            return Err("Invalid metric".into());
        }
    }
    Ok(observation)
}

pub(crate) async fn poll_server(
    endpoint: &Endpoint,
    collector: &Path,
    request: &[u8],
    frames: process::FrameReader<'_>,
) -> Result<(), String> {
    if request.len() > 2 * 1024 * 1024 {
        return Err("Server poll request exceeds the size limit".into());
    }
    let lease = crate::ssh_pool::global()?.acquire(endpoint).await?;
    let remote = format!(
        "f=\"$HOME/.cache/cyberbot/{}.py\"; sum=$(sha256sum \"$f\" 2>/dev/null) && [ \"${{sum%% *}}\" = '{}' ] || exit 42; exec python3 -I -B \"$f\" --server-poll",
        version(),
        digest()
    );
    for first in [true, false] {
        crate::ssh_authorization::check(&lease)?;
        let mut args = lease.options()?;
        args.extend(["--".into(), endpoint.host.clone(), remote.clone()]);
        let mut span = crate::activity::begin("server", "Collect server", Some(target(endpoint)));
        let mut received = false;
        let output = process::ssh_frames(&args, request, &mut |line| {
            if !received {
                crate::connectivity::ssh_reply();
                received = true;
            }
            frames(line)
        })
        .await;
        if first && !received && output.as_ref().is_ok_and(|out| out.exit_code == Some(42)) {
            crate::connectivity::ssh_reply();
            span.finish_as("info", "Collector deployment required");
            deploy(endpoint, collector).await?;
            continue;
        }
        if output.as_ref().is_ok_and(connected) {
            crate::connectivity::ssh_reply();
        } else if !received {
            lease.invalidate();
        }
        let result = output.and_then(|out| {
            if out.success {
                Ok(())
            } else {
                Err(classify_error(&out.stderr))
            }
        });
        span.result(&result);
        return result;
    }
    Err("Server collector unavailable".into())
}
pub async fn run_collector(
    e: &Endpoint,
    request: &serde_json::Value,
    cap: usize,
) -> Result<Vec<u8>, String> {
    let remote = format!(
        "PYTHONDONTWRITEBYTECODE=1 python3 -I -B \"$HOME/.cache/cyberbot/{}.py\"",
        version()
    );
    let data = serde_json::to_vec(request).map_err(|e| e.to_string())?;
    let kind = request["kind"].as_str().unwrap_or("");
    let service = request["state"]["kind"]
        .as_str()
        .filter(|_| kind == "service")
        .and_then(crate::services::descriptor);
    let action = if let Some(spec) = service {
        let label = format!("Diagnostics {}", spec.name);
        match request["state"]["config"]["port"].as_u64() {
            Some(port) if (1..=65535).contains(&port) => format!("{label} · :{port}"),
            _ => label,
        }
    } else {
        match kind {
            "metrics" => "Collect metrics",
            "remote_read" => "Read files via MCP",
            "logs" => "Analyze system and SSH logs",
            "packages" if request["state"].get("apt").is_some() => "Check APT updates",
            "packages" => "Collect installed packages",
            "service" => "Collect service diagnostics",
            _ => "Run built-in collector",
        }
        .to_owned()
    };
    Ok(command(e, &action, &remote, Some(&data), cap).await?.stdout)
}

pub(crate) async fn service_sample(
    endpoint: &Endpoint,
    kind: &str,
    instance: &str,
    config: serde_json::Value,
    checkpoint: serde_json::Value,
    thresholds: std::collections::BTreeMap<&'static str, u64>,
) -> Result<Vec<u8>, String> {
    let request = service_request(kind, instance, config, checkpoint, thresholds);
    if request.to_string().len() > 16384 {
        return Err("Diagnostic status exceeds the limit".into());
    }
    let bytes = run_collector(endpoint, &request, 32768).await?;
    decode_service_sample(kind, instance, &bytes)
}

pub(crate) fn service_request(
    kind: &str,
    instance: &str,
    config: serde_json::Value,
    checkpoint: serde_json::Value,
    thresholds: std::collections::BTreeMap<&'static str, u64>,
) -> serde_json::Value {
    serde_json::json!({"kind":"service","state":{
        "kind":kind,"instanceId":instance,"config":config,"checkpoint":checkpoint,"thresholds":thresholds
    }})
}

pub(crate) fn decode_service_sample(
    kind: &str,
    instance: &str,
    bytes: &[u8],
) -> Result<Vec<u8>, String> {
    use serde_json::Value;
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Response {
        version: u32,
        kind: String,
        instance_id: String,
        detected: bool,
        complete: bool,
        duration_ms: u64,
        details: Value,
    }
    if bytes.len() > 32768 {
        return Err("Invalid diagnostics response size".into());
    }
    let sample: Response = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let complete = sample.details["complete"]
        .as_bool()
        .or_else(|| sample.details["coverage"].as_bool())
        .or_else(|| sample.details["coverage"]["complete"].as_bool());
    if sample.version != 2
        || sample.kind != kind
        || sample.instance_id != instance
        || sample.duration_ms > 15000
        || sample.details["durationMs"].as_u64() != Some(sample.duration_ms)
        || sample.details["detected"].as_bool() != Some(sample.detected)
        || complete != Some(sample.complete)
    {
        return Err("Invalid diagnostics summary".into());
    }
    serde_json::to_vec(&sample.details).map_err(|e| e.to_string())
}

pub(crate) async fn run_shell_action(
    endpoint: &Endpoint,
    request: &serde_json::Value,
    cancel: &tokio_util::sync::CancellationToken,
    sent: &std::sync::atomic::AtomicBool,
) -> Result<Vec<u8>, String> {
    let lease = crate::ssh_pool::global()?.acquire(endpoint).await?;
    crate::ssh_authorization::check(&lease)?;
    let mut args = lease.options()?;
    let remote = format!(
        "PYTHONDONTWRITEBYTECODE=1 python3 -I -B \"$HOME/.cache/cyberbot/{}.py\" --watched-action",
        version()
    );
    args.extend(["--".into(), endpoint.host.clone(), remote]);
    let mut data = serde_json::to_vec(request).map_err(|e| e.to_string())?;
    data.push(b'\n');
    Ok(transport(
        endpoint,
        "Run shell command via MCP",
        &args,
        Some(&data),
        32768,
        Some(&lease),
        Some((cancel, sent)),
    )
    .await?
    .stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn apt_collector_failure_keeps_its_reason_separate_from_ssh() {
        let mut output = process::Output {
            stdout: vec![],
            stderr: r#"{"packageError":"apt_missing"}"#.into(),
            success: false,
            exit_code: Some(1),
        };
        assert_eq!(
            package_collector_error("Check APT updates", &output),
            Some("apt-cache is missing from the server.")
        );
        output.stderr = r#"{"error":"ValueError"}"#.into();
        assert_eq!(
            package_collector_error("Check APT updates", &output),
            Some("The collector on the server was unable to process the data.")
        );
        output.exit_code = Some(255);
        assert_eq!(package_collector_error("Check APT updates", &output), None);
    }

    #[test]
    fn remote_exit_status_is_not_a_connection_failure() {
        for (code, expected) in [
            (Some(0), true),
            (Some(1), true),
            (Some(2), true),
            (Some(255), false),
            (None, false),
        ] {
            let output = process::Output {
                stdout: vec![],
                stderr: String::new(),
                success: code == Some(0),
                exit_code: code,
            };
            assert_eq!(connected(&output), expected);
        }
    }
    #[test]
    fn secure_options_are_always_present() {
        let e = crate::inventory::parse_manual("root@host")
            .unwrap()
            .remove(0)
            .endpoint;
        let args = options(&e).unwrap();
        assert!(args.contains(&"-oStrictHostKeyChecking=yes".into()));
        assert!(args.contains(&"-oForwardAgent=no".into()));
        assert!(args.windows(2).any(|pair| pair == ["-l", "root"]));
    }
    #[test]
    fn bare_hosts_leave_user_resolution_to_ssh_and_rsync() {
        for (input, expected, port) in [
            ("web.example.com", "web.example.com", 22),
            ("10.20.1.10", "10.20.1.10", 22),
            ("[::1]:2222", "[::1]", 2222),
            ("ops@[::1]:2222", "ops@[::1]", 2222),
        ] {
            let endpoint = crate::inventory::parse_manual(input)
                .unwrap()
                .remove(0)
                .endpoint;
            let args = options(&endpoint).unwrap();
            assert_eq!(args.contains(&"-l".into()), !endpoint.user.is_empty());
            assert!(args.contains(&"-oStrictHostKeyChecking=yes".into()));
            assert_eq!(login(&endpoint), expected);
            assert_eq!(target(&endpoint), format!("{expected}:{port}"));
        }
    }
}
