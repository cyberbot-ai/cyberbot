//! Whole-process Seatbelt profile. Tool permissions are a second, separate layer.
use crate::process::GroupGuard;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Stdio,
};
use tokio::{io::AsyncReadExt, process::Command};

fn quoted(s: &str) -> String {
    serde_json::to_string(s).expect("string serialization")
}
fn literal(p: &Path) -> String {
    format!("(literal {})", quoted(&p.to_string_lossy()))
}
fn subtree(p: &Path) -> String {
    format!("(subpath {})", quoted(&p.to_string_lossy()))
}

pub fn profile(
    executable: &Path,
    workspace: &Path,
    home: &Path,
    ports: &[u16],
    provider: &str,
) -> Result<String, String> {
    if !cfg!(target_os = "macos") {
        return Err("Agent isolation is supported only on macOS".into());
    }
    let executable = executable.canonicalize().map_err(|e| e.to_string())?;
    let workspace = workspace.canonicalize().map_err(|e| e.to_string())?;
    let home = home.canonicalize().map_err(|e| e.to_string())?;
    let mut reads = vec![
        subtree(&workspace),
        literal(&executable),
        literal(&home.join(".CFUserTextEncoding")),
        literal(&home.join("Library/Preferences/com.apple.security.plist")),
    ];
    let mut writes = vec![subtree(&workspace), literal(Path::new("/dev/null"))];
    // Authentication is read by the trusted CLI, never exposed through MCP.
    // No broad read access to the provider home (sessions, plugins, other chats).
    if provider == "codex" {
        for f in [
            ".codex/config.toml",
            ".codex/auth.json",
            ".codex/requirements.toml",
            ".codex/installation_id",
        ] {
            reads.push(literal(&home.join(f)));
        }
        writes.push(literal(&home.join(".codex/auth.json")));
        writes.push(literal(&home.join(".codex/installation_id")));
        reads.push(subtree(&home.join(".codex/rules")));
    } else if provider == "claude" {
        reads.push(literal(&home.join(".claude.json")));
    } else if provider != "probe" {
        return Err("Unknown provider".into());
    }
    let mut executables = vec![literal(&executable)];
    if provider == "codex" {
        let helper = executable
            .parent()
            .ok_or("No CLI directory")?
            .join("codex-code-mode-host");
        // Older compatible distributions do not ship this helper. Do not make
        // packaging layout a version gate or grant a directory-wide exec rule.
        if helper.exists() {
            let helper = helper.canonicalize().map_err(|e| e.to_string())?;
            executables.push(literal(&helper));
            reads.push(literal(&helper));
        }
    }
    let network = ports
        .iter()
        .map(|p| format!("(allow network-outbound (remote ip \"localhost:{p}\"))\n"))
        .collect::<String>();
    Ok(format!(
        r#"(version 1)
(deny default)
(allow file-read-metadata)
(allow file-read* (literal "/") (subpath "/System") (subpath "/usr") (subpath "/bin") (subpath "/sbin") (subpath "/Library") (subpath "/private/etc") (subpath "/private/var/db") (subpath "/dev") {reads})
(allow file-map-executable (subpath "/System") (subpath "/usr") {executable})
(allow file-write* {writes})
(allow process-fork)
(allow process-exec {executable})
(allow signal (target self))
(allow mach-lookup)
(allow sysctl-read)
(allow ipc-posix-shm-read-data)
(allow ipc-posix-shm-write-data)
(allow ipc-posix-shm-write-create (ipc-posix-name "com.apple.AppleDatabaseChanged"))
(allow user-preference-read (preference-domain "com.apple.security") (preference-domain "kcfpreferencesanyapplication"))
{network}
"#,
        reads = reads.join(" "),
        writes = writes.join(" "),
        executable = executables.join(" ")
    ))
}

pub fn environment(workspace: &Path, proxy_port: u16, token: &str) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    // Do not inherit SSH_AUTH_SOCK, API keys, arbitrary proxy/provider overrides,
    // NODE_OPTIONS, hooks, dynamic-library injection, or any agent parent context.
    for key in ["HOME", "USER", "LOGNAME", "LANG"] {
        if let Ok(v) = std::env::var(key) {
            env.insert(key.into(), v);
        }
    }
    env.insert(
        "CLAUDE_CODE_TMPDIR".into(),
        workspace.join("tmp").to_string_lossy().into_owned(),
    );
    env.insert("PATH".into(), "/usr/bin:/bin:/usr/sbin:/sbin".into());
    env.insert(
        "TMPDIR".into(),
        workspace.join("tmp").to_string_lossy().into_owned(),
    );
    for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        env.insert(key.into(), format!("http://127.0.0.1:{proxy_port}"));
    }
    for key in ["NO_PROXY", "no_proxy"] {
        env.insert(key.into(), "127.0.0.1,localhost".into());
    }
    env.insert("CYBERBOT_MCP_TOKEN".into(), token.into());
    env.insert("MCP_TOOL_TIMEOUT".into(), "780000".into());
    env.insert("DISABLE_AUTOUPDATER".into(), "1".into());
    env.insert("DISABLE_TELEMETRY".into(), "1".into());
    env.insert("DISABLE_ERROR_REPORTING".into(), "1".into());
    env.insert(
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC".into(),
        "1".into(),
    );
    env
}

pub fn command(
    executable: &Path,
    args: &[String],
    workspace: &Path,
    profile: &Path,
    proxy_port: u16,
    token: &str,
) -> Command {
    let mut c = Command::new("/usr/bin/sandbox-exec");
    c.arg("-f")
        .arg(profile)
        .arg(executable)
        .args(args)
        .current_dir(workspace)
        .env_clear()
        .envs(environment(workspace, proxy_port, token))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    c.process_group(0);
    c
}

pub fn prepare(root: &Path) -> Result<PathBuf, String> {
    let dir = root
        .join("investigations")
        .join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(dir.join("tmp")).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
    }
    dir.canonicalize().map_err(|e| e.to_string())
}

pub async fn preflight(workspace: &Path, home: &Path) -> Result<(), String> {
    let mut _activity_span = crate::activity::begin("process", "preflight", None);
    let _activity_result = (async {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let private = workspace
            .parent()
            .ok_or("No parent of workspace")?
            .join(format!("canary-{}", uuid::Uuid::new_v4()));
        std::fs::write(&private, "CYBERBOT_PRIVATE_CANARY").map_err(|e| e.to_string())?;
        let path = workspace.join("probe.sb");
        let allowed = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let forbidden = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let allowed_addr = allowed.local_addr().map_err(|e| e.to_string())?;
        let forbidden_addr = forbidden.local_addr().map_err(|e| e.to_string())?;
        let socket = PathBuf::from(format!(
            "/private/tmp/cb-{}.sock",
            uuid::Uuid::new_v4().simple()
        ));
        #[cfg(unix)]
        let _unix = std::os::unix::net::UnixListener::bind(&socket).map_err(|e| e.to_string())?;
        std::fs::write(
            &path,
            profile(&exe, workspace, home, &[allowed_addr.port()], "probe")?,
        )
        .map_err(|e| e.to_string())?;
        let args = vec![
            "--isolation-probe".into(),
            private.to_string_lossy().into_owned(),
            workspace.to_string_lossy().into_owned(),
            allowed_addr.to_string(),
            forbidden_addr.to_string(),
            socket.to_string_lossy().into_owned(),
        ];
        let mut child = command(&exe, &args, workspace, &path, 1, "")
            .spawn()
            .map_err(|e| e.to_string())?;
        let _guard = GroupGuard::register(child.id().ok_or("No PID")?)?;
        let mut stdout = child.stdout.take().ok_or("No stdout")?;
        let mut stderr = child.stderr.take().ok_or("No stderr")?;
        let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let mut out = Vec::new();
            (&mut stdout)
                .take(4097)
                .read_to_end(&mut out)
                .await
                .map_err(|e| e.to_string())?;
            let status = child.wait().await.map_err(|e| e.to_string())?;
            let mut error = Vec::new();
            (&mut stderr)
                .take(4096)
                .read_to_end(&mut error)
                .await
                .map_err(|e| e.to_string())?;
            let value: serde_json::Value = serde_json::from_slice(&out).map_err(|_| {
                format!(
                    "Sandbox self-test failed ({status}). AI runs are blocked: {}",
                    String::from_utf8_lossy(&error)
                )
            })?;
            if status.success() && value["passed"] == true {
                Ok(())
            } else {
                Err(format!(
                    "Sandbox does not block dangerous operations: {value}"
                ))
            }
        })
        .await
        .map_err(|_| "Sandbox check timed out".to_string())
        .and_then(|v| v);
        let _ = std::fs::remove_file(private);
        let _ = std::fs::remove_file(socket);
        result
    })
    .await;
    _activity_span.result(&_activity_result);
    _activity_result
}

/// Executed only by the dedicated non-GUI subprocess under the real Seatbelt profile.
pub fn probe_main(args: &[String]) -> i32 {
    let canary = Path::new(&args[0]);
    let work = Path::new(&args[1]);
    let read_blocked = std::fs::read(canary).is_err();
    let write_blocked = std::fs::write(canary, b"MUTATED").is_err();
    let own_write = std::fs::write(work.join("probe-local"), b"ok").is_ok();
    let exec_blocked = std::process::Command::new("/bin/sh")
        .args(["-c", "exit 0"])
        .status()
        .is_err();
    // Explicit forbidden-connect test: EPERM/EACCES proves policy, refused does not.
    let network_blocked = matches!(std::net::TcpStream::connect_timeout(&args[3].parse().unwrap(),std::time::Duration::from_secs(1)),Err(e) if e.kind()==std::io::ErrorKind::PermissionDenied);
    let network_allowed = std::net::TcpStream::connect_timeout(
        &args[2].parse().unwrap(),
        std::time::Duration::from_secs(1),
    )
    .is_ok();
    #[cfg(unix)]
    let unix_blocked = matches!(std::os::unix::net::UnixStream::connect(&args[4]),Err(e) if e.kind()==std::io::ErrorKind::PermissionDenied);
    #[cfg(not(unix))]
    let unix_blocked = false;
    let passed = read_blocked
        && write_blocked
        && own_write
        && exec_blocked
        && network_blocked
        && unix_blocked
        && network_allowed;
    println!(
        "{}",
        serde_json::json!({"passed":passed,"readBlocked":read_blocked,"writeBlocked":write_blocked,"execBlocked":exec_blocked,"networkBlocked":network_blocked,"unixBlocked":unix_blocked,"workspaceWritable":own_write})
    );
    if passed {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn env_does_not_forward_secrets() {
        let env = environment(Path::new("/tmp/work"), 1234, "t");
        assert!(!env.contains_key("SSH_AUTH_SOCK"));
        assert!(!env.contains_key("ANTHROPIC_API_KEY"));
        assert!(!env.contains_key("NODE_OPTIONS"));
    }
    #[test]
    fn profile_has_no_direct_network_or_home_access() {
        let d = tempfile::tempdir().unwrap();
        let install = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let exe = install.path().join("codex");
        std::fs::write(&exe, "").unwrap();
        std::fs::write(install.path().join("codex-code-mode-host"), "").unwrap();
        let p = profile(&exe, d.path(), home.path(), &[4321], "codex").unwrap();
        assert!(p.contains("(deny default)"));
        assert!(p.contains("localhost:4321"));
        assert!(!p.contains(&subtree(&home.path().canonicalize().unwrap())));
        assert!(!p.contains(&subtree(&install.path().canonicalize().unwrap())));
    }
}
