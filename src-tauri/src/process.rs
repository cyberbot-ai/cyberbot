use std::{
    collections::HashSet,
    process::Stdio,
    sync::{Mutex, OnceLock},
    time::Duration,
};
use tokio::{io::AsyncReadExt, io::AsyncWriteExt, process::Command};

pub(crate) struct GroupGuard(i32);
impl GroupGuard {
    pub(crate) fn register(pid: u32) -> Result<Self, String> {
        GROUPS
            .get_or_init(Mutex::default)
            .lock()
            .map_err(|e| e.to_string())?
            .insert(pid as i32);
        Ok(Self(pid as i32))
    }
    pub(crate) fn disarm(mut self) {
        if let Ok(mut groups) = GROUPS.get_or_init(Mutex::default).lock() {
            groups.remove(&self.0);
        }
        self.0 = 0;
    }
}
static GROUPS: OnceLock<Mutex<HashSet<i32>>> = OnceLock::new();
pub fn kill_all() {
    if let Ok(groups) = GROUPS.get_or_init(Mutex::default).lock() {
        for pid in groups.iter() {
            #[cfg(unix)]
            unsafe {
                libc::kill(-*pid, libc::SIGKILL);
            }
        }
    }
}
impl Drop for GroupGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            if self.0 > 0 {
                libc::kill(-self.0, libc::SIGKILL);
            }
        }
        if let Ok(mut groups) = GROUPS.get_or_init(Mutex::default).lock() {
            groups.remove(&self.0);
        }
    }
}
#[derive(Debug)]
pub struct Output {
    pub stdout: Vec<u8>,
    pub stderr: String,
    pub success: bool,
    pub exit_code: Option<i32>,
}

pub async fn bounded(
    program: &str,
    args: &[String],
    input: Option<&[u8]>,
    seconds: u64,
    cap: usize,
) -> Result<Output, String> {
    if matches!(
        program,
        "/usr/bin/ssh" | "/usr/bin/rsync" | "/usr/bin/nettop"
    ) {
        return bounded_inner(program, args, input, seconds, cap, None).await;
    }
    let name = std::path::Path::new(program)
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("");
    let action = match name {
        "codex" => "codex --version",
        "claude" => "claude --version",
        "security" => "Reading CLI credentials",
        _ => "Local process",
    };
    let mut event = crate::activity::begin("process", action, None);
    let result = bounded_inner(program, args, input, seconds, cap, None).await;
    event.finish(if result.as_ref().is_ok_and(|o| o.success) {
        "completed"
    } else {
        "failed"
    });
    result
}

pub(crate) async fn watched_ssh(
    args: &[String],
    input: &[u8],
    cap: usize,
    cancel: &tokio_util::sync::CancellationToken,
    sent: &std::sync::atomic::AtomicBool,
) -> Result<Output, String> {
    bounded_inner(
        "/usr/bin/ssh",
        args,
        Some(input),
        25,
        cap,
        Some((cancel, sent)),
    )
    .await
}

// Only the pool may launch a daemon. Successful ControlPersist launchers detach;
// killing their original process group would also kill an active ProxyJump helper.
pub(crate) async fn ssh_master(args: &[String]) -> Result<Output, String> {
    let mut command = Command::new("/usr/bin/ssh");
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command
        .spawn()
        .map_err(|e| format!("Failed to launch SSH: {e}"))?;
    let guard = GroupGuard::register(child.id().ok_or("SSH process ID unavailable")?)?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or("SSH standard error is unavailable")?;
    let error = std::sync::Arc::new(Mutex::new(Vec::<u8>::new()));
    let saved = error.clone();
    // A ProxyJump child inherits stderr and can outlive the launcher. Drain it
    // without waiting for EOF or accumulating output beyond the first 4 KiB.
    let mut reader = tokio::spawn(async move {
        let mut buffer = [0; 1024];
        while let Ok(n) = stderr.read(&mut buffer).await {
            if n == 0 {
                break;
            }
            if let Ok(mut saved) = saved.lock() {
                let keep = n.min(4096 - saved.len());
                saved.extend_from_slice(&buffer[..keep]);
            }
        }
    });
    let status = tokio::time::timeout(Duration::from_secs(20), child.wait())
        .await
        .map_err(|_| "Timeline of SSH connection".to_string())?
        .map_err(|e| e.to_string())?;
    if status.success() {
        guard.disarm();
    } else {
        drop(guard);
        if tokio::time::timeout(Duration::from_secs(1), &mut reader)
            .await
            .is_err()
        {
            reader.abort();
        }
    }
    let stderr = error
        .lock()
        .map(|v| String::from_utf8_lossy(&v).into_owned())
        .unwrap_or_default();
    Ok(Output {
        stdout: vec![],
        stderr,
        success: status.success(),
        exit_code: status.code(),
    })
}

async fn bounded_inner(
    program: &str,
    args: &[String],
    input: Option<&[u8]>,
    seconds: u64,
    cap: usize,
    watch: Option<(
        &tokio_util::sync::CancellationToken,
        &std::sync::atomic::AtomicBool,
    )>,
) -> Result<Output, String> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command
        .spawn()
        .map_err(|e| format!("Failed to launch {program}: {e}"))?;
    let _guard = GroupGuard(child.id().ok_or("No PID process")? as i32);
    GROUPS
        .get_or_init(Mutex::default)
        .lock()
        .map_err(|e| e.to_string())?
        .insert(_guard.0);
    let stdout = child.stdout.take().ok_or("No stdout")?;
    let stderr = child.stderr.take().ok_or("No stderr")?;
    let mut stdin = child.stdin.take();
    let future = async {
        let read_out = async {
            let mut data = Vec::new();
            stdout
                .take(cap as u64 + 1)
                .read_to_end(&mut data)
                .await
                .map_err(|e| e.to_string())?;
            if data.len() > cap {
                return Err("Response limit exceeded".to_owned());
            }
            Ok::<_, String>(data)
        };
        let read_err = async {
            let mut data = Vec::new();
            stderr
                .take(4097)
                .read_to_end(&mut data)
                .await
                .map_err(|e| e.to_string())?;
            if data.len() > 4096 {
                return Err("The stderr limit is exceeded".to_owned());
            }
            Ok::<_, String>(String::from_utf8_lossy(&data).into_owned())
        };
        let write = async {
            if let (Some(pipe), Some(input)) = (stdin.as_mut(), input) {
                pipe.write_all(input).await.map_err(|e| e.to_string())?;
                if watch.is_none() {
                    pipe.shutdown().await.map_err(|e| e.to_string())?;
                    drop(stdin.take());
                }
            }
            Ok::<_, String>(())
        };
        let collect = async {
            let wait = async { child.wait().await.map_err(|e| e.to_string()) };
            tokio::try_join!(read_out, read_err, wait)
        };
        let (out, err, status) = if let Some((cancel, sent)) = watch {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err("Canceled before the script is sent".into()),
                sent = write => sent?,
            }
            sent.store(true, std::sync::atomic::Ordering::Relaxed);
            tokio::pin!(collect);
            tokio::select! {
                result = &mut collect => result?,
                _ = cancel.cancelled() => {
                    drop(stdin.take());
                    let _ = tokio::time::timeout(Duration::from_secs(2), &mut collect).await;
                    return Err("Deleted script cancelled; result unknown".into());
                }
            }
        } else {
            let ((), result) = tokio::try_join!(write, collect)?;
            result
        };
        Ok(Output {
            stdout: out,
            stderr: err,
            success: status.success(),
            exit_code: status.code(),
        })
    };
    tokio::time::timeout(Duration::from_secs(seconds), future)
        .await
        .map_err(|_| format!("timemouth {seconds} s: {program}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn watched_shell_marks_submission_even_when_the_result_is_unsuccessful() {
        let args = ["-c".into(), "read line; exit 7".into()];
        let sent = AtomicBool::new(false);
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(bounded_inner(
            "/bin/sh",
            &args,
            Some(b"frame\n"),
            2,
            100,
            Some((&cancelled, &sent))
        )
        .await
        .is_err());
        assert!(!sent.load(Ordering::Relaxed));

        let live = CancellationToken::new();
        let failed = bounded_inner(
            "/bin/sh",
            &args,
            Some(b"frame\n"),
            2,
            100,
            Some((&live, &sent)),
        )
        .await
        .unwrap();
        assert_eq!(failed.exit_code, Some(7));
        assert!(sent.load(Ordering::Relaxed));

        let sent = AtomicBool::new(false);
        let timeout = ["-c".into(), "read line; sleep 60".into()];
        assert!(bounded_inner(
            "/bin/sh",
            &timeout,
            Some(b"frame\n"),
            1,
            100,
            Some((&live, &sent))
        )
        .await
        .is_err());
        assert!(sent.load(Ordering::Relaxed));
    }
    #[tokio::test]
    async fn limits_output() {
        let r = bounded("/usr/bin/yes", &[], None, 2, 100).await;
        assert!(r.unwrap_err().contains("limit"));
    }
    #[tokio::test]
    async fn bounds_time() {
        let r = bounded("/bin/sleep", &["5".into()], None, 1, 100).await;
        assert!(r.unwrap_err().contains("timemouth"));
    }
}
