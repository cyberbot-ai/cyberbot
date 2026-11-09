//! The evaluator has no capabilities. Seatbelt also fences its process on macOS.
use crate::{
    check_engine::{Request, Response, ENGINE},
    process::GroupGuard,
};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::Mutex,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};
#[derive(Default)]
pub struct Runtime {
    gate: tokio::sync::Mutex<()>,
    verified: Mutex<Option<String>>,
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn binary() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(err)?;
    let dir = exe.parent().ok_or("No app directory")?;
    let path = dir.join("cyberbot-check-runner");
    #[cfg(test)]
    let path = if path.exists() {
        path
    } else {
        dir.parent()
            .ok_or("No runner")?
            .join("cyberbot-check-runner")
    };
    path.canonicalize().map_err(|_| {
        "No built-in artist found. Collect the application via npm run desktop:build".into()
    })
}
pub(crate) fn profile(exe: &Path) -> String {
    let path = serde_json::to_string(&exe.to_string_lossy()).unwrap();
    format!(
        r#"(version 1)
(deny default)
(allow file-read-metadata)
(allow file-read* (literal "/") (subpath "/System/Library") (subpath "/usr/lib") (literal {path}) (literal "/dev/null"))
(allow file-map-executable (subpath "/System/Library") (subpath "/usr/lib") (literal {path}))
(allow process-exec (literal {path}))
(allow sysctl-read)
(allow signal (target self))
"#
    )
}
async fn launch(exe: &Path, args: &[String], input: &[u8]) -> Result<Vec<u8>, String> {
    let mut _activity_span = crate::activity::begin("process", "launch", None);
    let _activity_result = (async {
        if !cfg!(target_os = "macos") {
            return Err("Isolated checks are only available on macOS; launch is blocked".into());
        }
        let mut cmd = Command::new("/usr/bin/sandbox-exec");
        cmd.args(["-p", &profile(exe)])
            .arg(exe)
            .args(args)
            .env_clear()
            .env("LC_ALL", "C")
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        cmd.process_group(0);
        let mut child = cmd.spawn().map_err(err)?;
        let _guard = GroupGuard::register(child.id().ok_or("No PID performer")?)?;
        let mut stdin = child.stdin.take().ok_or("No stdin")?;
        let stdout = child.stdout.take().ok_or("No stdout")?;
        let stderr = child.stderr.take().ok_or("No stderr")?;
        tokio::time::timeout(Duration::from_secs(3), async {
            let write = async move {
                stdin.write_all(input).await.map_err(err)?;
                stdin.shutdown().await.map_err(err)?;
                drop(stdin);
                Ok::<(), String>(())
            };
            let read = async {
                let mut bytes = vec![];
                stdout
                    .take(8193)
                    .read_to_end(&mut bytes)
                    .await
                    .map_err(err)?;
                if bytes.len() > 8192 {
                    return Err("Executor’s withdrawal limit".into());
                }
                Ok(bytes)
            };
            let errors = async {
                let mut bytes = vec![];
                stderr
                    .take(4097)
                    .read_to_end(&mut bytes)
                    .await
                    .map_err(err)?;
                if bytes.len() > 4096 {
                    return Err("Performer’s stderr limit".into());
                }
                Ok(())
            };
            let ((), bytes, ()) = tokio::try_join!(write, read, errors)?;
            let status = child.wait().await.map_err(err)?;
            if !status.success() {
                return Err("Isolated performer fails or exceeds CPU/memory limit".into());
            }
            Ok(bytes)
        })
        .await
        .map_err(|_| "Contractor stopped: 3-second".to_string())?
    })
    .await;
    _activity_span.result(&_activity_result);
    _activity_result
}
impl Runtime {
    pub async fn execute(&self, root: &Path, request: &Request) -> Result<Response, String> {
        self.execute_many(root, std::slice::from_ref(request))
            .await?
            .pop()
            .ok_or("No result".into())
    }
    pub async fn execute_many(
        &self,
        root: &Path,
        requests: &[Request],
    ) -> Result<Vec<Response>, String> {
        let _gate = self.gate.lock().await;
        let exe = binary()?;
        let bytes = std::fs::read(&exe).map_err(err)?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err("The unexpected size of the performer".into());
        }
        let identity = format!("{ENGINE}:{:x}", Sha256::digest(bytes));
        if self.verified.lock().map_err(err)?.as_ref() != Some(&identity) {
            self.probe(root, &exe).await?;
            *self.verified.lock().map_err(err)? = Some(identity);
        }
        let input = serde_json::to_vec(requests).map_err(err)?;
        if input.len() > 147456 || requests.is_empty() || requests.len() > 8 {
            return Err("Entry of the performer exceeds 144 KiB".into());
        }
        let bytes = launch(&exe, &[], &input).await?;
        let value: Vec<Response> =
            serde_json::from_slice(&bytes).map_err(|_| "Incorrect response of the performer")?;
        if value.len() != requests.len() || value.iter().any(|v| v.engine != ENGINE) {
            return Err("Performer’s version didn’t match".into());
        }
        Ok(value)
    }
    async fn probe(&self, root: &Path, exe: &Path) -> Result<(), String> {
        let path = root.join(format!("check-canary-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"CYBERBOT_PRIVATE").map_err(err)?;
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
                let _ = std::fs::remove_file(format!("{}.write", self.0.display()));
            }
        }
        let _cleanup = Cleanup(path.clone());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(err)?;
        let bytes = launch(
            exe,
            &[
                "--isolation-probe".into(),
                path.to_string_lossy().into_owned(),
                listener.local_addr().map_err(err)?.to_string(),
            ],
            &[],
        )
        .await?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(err)?;
        if value["isolated"] != true
            || ["read", "write", "network", "shell", "env"]
                .iter()
                .any(|k| value[k] != false)
        {
            return Err("Isolation of performer not confirmed; inclusion prohibited".into());
        }
        Ok(())
    }
}
