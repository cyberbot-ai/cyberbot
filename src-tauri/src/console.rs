//! Interactive SSH channels owned by desktop windows.
mod pty;

use crate::{
    activity,
    model::{Endpoint, Server},
    process, ssh, ssh_pool, AppState,
};
use pty::Pty;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tauri::{ipc::Channel, State, WebviewWindow};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const SESSION_LIMIT: usize = 8;
const CHUNK_SIZE: usize = 16 * 1024;
const INPUT_QUEUE: usize = 16;
const OUTPUT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Size {
    rows: u16,
    cols: u16,
}

impl Size {
    fn validate(self) -> Result<Self, String> {
        if (1..=512).contains(&self.rows) && (2..=1024).contains(&self.cols) {
            Ok(self)
        } else {
            Err("Invalid terminal size".into())
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum Message {
    Input { bytes: Vec<u8> },
    Resize { size: Size },
    Ack { sequence: u32 },
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(crate) enum Event {
    Ready,
    Output {
        sequence: u32,
        bytes: Vec<u8>,
    },
    End {
        code: Option<i32>,
        error: Option<String>,
    },
}

#[derive(Default)]
pub(crate) struct Sessions(Arc<Mutex<HashMap<String, Entry>>>);

struct Entry {
    id: Uuid,
    server_id: String,
    endpoint: Endpoint,
    cancel: CancellationToken,
    revoke: CancellationToken,
    input: mpsc::Sender<Vec<u8>>,
    size: watch::Sender<Size>,
    ack: watch::Sender<u32>,
}

struct Session {
    sessions: Arc<Mutex<HashMap<String, Entry>>>,
    owner: String,
    id: Uuid,
    cancel: CancellationToken,
    revoke: CancellationToken,
    terminal: Terminal,
}

struct Terminal {
    input: mpsc::Receiver<Vec<u8>>,
    size: watch::Receiver<Size>,
    ack: watch::Receiver<u32>,
    submitted: bool,
}

impl Sessions {
    fn register(
        &self,
        owner: &str,
        server_id: String,
        endpoint: Endpoint,
        size: Size,
    ) -> Result<Session, String> {
        let mut sessions = self.0.lock().map_err(|e| e.to_string())?;
        if sessions.contains_key(owner) {
            return Err("There’s already an SSH session in this window".into());
        }
        if sessions.len() >= SESSION_LIMIT {
            return Err("SSH console limit reached".into());
        }
        let (input, input_rx) = mpsc::channel(INPUT_QUEUE);
        let (size, size_rx) = watch::channel(size);
        let (ack, ack_rx) = watch::channel(0);
        let entry = Entry {
            id: Uuid::new_v4(),
            server_id,
            endpoint,
            cancel: CancellationToken::new(),
            revoke: CancellationToken::new(),
            input,
            size,
            ack,
        };
        let session = Session {
            sessions: self.0.clone(),
            owner: owner.to_owned(),
            id: entry.id,
            cancel: entry.cancel.clone(),
            revoke: entry.revoke.clone(),
            terminal: Terminal {
                input: input_rx,
                size: size_rx,
                ack: ack_rx,
                submitted: false,
            },
        };
        sessions.insert(owner.to_owned(), entry);
        Ok(session)
    }

    fn send(&self, owner: &str, id: Uuid, message: Message) -> Result<(), String> {
        let sessions = self.0.lock().map_err(|e| e.to_string())?;
        let entry = sessions
            .get(owner)
            .filter(|entry| {
                entry.id == id && !entry.cancel.is_cancelled() && !entry.revoke.is_cancelled()
            })
            .ok_or("SSH session not available")?;
        match message {
            Message::Input { bytes } => {
                if bytes.len() > CHUNK_SIZE {
                    return Err("Terminal input block is too large".into());
                }
                entry.input.try_send(bytes).map_err(|e| match e {
                    mpsc::error::TrySendError::Full(_) => "Terminal input queue is full",
                    mpsc::error::TrySendError::Closed(_) => "SSH session not available",
                })?;
            }
            Message::Resize { size } => {
                entry.size.send_replace(size.validate()?);
            }
            Message::Ack { sequence } => {
                entry.ack.send_replace(sequence);
            }
        }
        Ok(())
    }

    fn close(&self, owner: &str, id: Uuid) {
        if let Ok(sessions) = self.0.lock() {
            if let Some(entry) = sessions.get(owner).filter(|entry| entry.id == id) {
                entry.cancel.cancel();
            }
        }
    }

    pub(crate) fn close_window(&self, owner: &str) {
        if let Ok(sessions) = self.0.lock() {
            if let Some(entry) = sessions.get(owner) {
                entry.cancel.cancel();
            }
        }
    }

    pub(crate) fn retain(&self, servers: &[Server]) {
        if let Ok(sessions) = self.0.lock() {
            for entry in sessions.values() {
                if !servers
                    .iter()
                    .any(|s| s.id == entry.server_id && s.endpoint == entry.endpoint)
                {
                    entry.revoke.cancel();
                }
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            if sessions
                .get(&self.owner)
                .is_some_and(|entry| entry.id == self.id)
            {
                sessions.remove(&self.owner);
            }
        }
    }
}

fn allow_window(owner: &str, server_id: &str) -> Result<(), String> {
    if owner == "main" || owner.strip_prefix("server-") == Some(server_id) {
        Ok(())
    } else {
        Err("The console is only available in the selected server window".into())
    }
}

#[tauri::command]
pub(crate) async fn console_open(
    window: WebviewWindow,
    state: State<'_, Arc<AppState>>,
    server_id: String,
    size: Size,
    on_event: Channel<Event>,
) -> Result<Uuid, String> {
    let owner = window.label().to_owned();
    allow_window(&owner, &server_id)?;
    let size = size.validate()?;
    let endpoint = state.store.server_endpoint(&server_id)?;
    let session = state
        .consoles
        .register(&owner, server_id.clone(), endpoint.clone(), size)?;
    let id = session.id;
    if !window.is_visible().map_err(|e| e.to_string())? {
        return Err("Server window closed".into());
    }
    if state.store.server_endpoint(&server_id)? != endpoint {
        return Err("Server connection parameters have changed".into());
    }
    tauri::async_runtime::spawn(session.run(state.inner().clone(), server_id, endpoint, on_event));
    Ok(id)
}

#[tauri::command]
pub(crate) fn console_send(
    window: WebviewWindow,
    state: State<'_, Arc<AppState>>,
    id: Uuid,
    message: Message,
) -> Result<(), String> {
    state.consoles.send(window.label(), id, message)
}

#[tauri::command]
pub(crate) fn console_close(window: WebviewWindow, state: State<'_, Arc<AppState>>, id: Uuid) {
    state.consoles.close(window.label(), id);
}

impl Session {
    async fn run(
        mut self,
        state: Arc<AppState>,
        server_id: String,
        endpoint: Endpoint,
        channel: Channel<Event>,
    ) {
        let mut span = activity::begin("ssh", "SSH console", Some(ssh::target(&endpoint)));
        let session_id = self.id;
        let result = match ssh_pool::global() {
            Ok(pool) => {
                self.terminal
                    .connect(
                        pool,
                        &endpoint,
                        &self.cancel,
                        &self.revoke,
                        || {
                            state
                                .package_refresh
                                .terminal_submitted(&server_id, &endpoint, session_id);
                        },
                        |event| {
                            channel
                                .send(event)
                                .map_err(|_| "Terminal window unavailable".into())
                        },
                    )
                    .await
            }
            Err(error) => Err(error),
        };
        if self.terminal.submitted
            && !self.revoke.is_cancelled()
            && state
                .store
                .server_endpoint(&server_id)
                .as_ref()
                .is_ok_and(|current| current == &endpoint)
        {
            state
                .package_refresh
                .terminal_finished(&server_id, &endpoint, session_id);
        }
        span.finish(match result {
            Ok(None) => "cancelled",
            Ok(Some(255)) | Err(_) => "failed",
            Ok(Some(_)) => "completed",
        });
        let event = match result {
            Ok(code) => Event::End {
                code,
                error: (code == Some(255)).then(|| "The SSH channel ended with an error".into()),
            },
            Err(error) => Event::End {
                code: None,
                error: Some(error),
            },
        };
        drop(self);
        let _ = channel.send(event);
    }
}

impl Terminal {
    async fn connect(
        &mut self,
        pool: &ssh_pool::Pool,
        endpoint: &Endpoint,
        cancel: &CancellationToken,
        revoke: &CancellationToken,
        on_submission: impl Fn(),
        send: impl Fn(Event) -> Result<(), String>,
    ) -> Result<Option<i32>, String> {
        let revoked = async {
            revoke.cancelled().await;
            Err("The server was removed or its SSH settings changed".into())
        };
        tokio::pin!(revoked);
        let lease = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(None),
            result = &mut revoked => return result,
            lease = pool.acquire(endpoint) => lease?,
        };
        let (pty, mut child) = Pty::spawn(&lease.console_options()?, *self.size.borrow())
            .map_err(|e| format!("Unable to open the SSH terminal: {e}"))?;
        let guard = process::GroupGuard::register(child.id().ok_or("SSH process ID unavailable")?)?;
        let output = relay_output(&pty, &mut self.ack, &send);
        tokio::pin!(output);
        let result = async {
            send(Event::Ready)?;
            let exit = tokio::select! {
                status = child.wait() => {
                    let status = status.map_err(|e| e.to_string())?;
                    // The final prompt/output may still be in the PTY.
                    tokio::time::timeout(OUTPUT_TIMEOUT, &mut output).await
                        .map_err(|_| "Timed out while reading SSH output".to_string())??;
                    status
                }
                result = &mut output => {
                    result?;
                    tokio::time::timeout(Duration::from_secs(3), child.wait()).await
                        .map_err(|_| "Timed out waiting for SSH to exit".to_string())?
                        .map_err(|e| e.to_string())?
                }
                result = relay_input(&pty, &mut self.input, || {
                    self.submitted = true;
                    on_submission();
                }) => return result.map(|()| None),
                result = relay_size(&pty, &mut self.size) => return result.map(|()| None),
            };
            exit.code()
                .map(Some)
                .ok_or_else(|| "The SSH process was terminated by a signal".into())
        };
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Ok(None),
            result = &mut revoked => result,
            _ = lease.revoked() => Err("SSH session cancelled".into()),
            result = result => result,
        };
        if child.id().is_some() {
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
        guard.disarm();
        result
    }
}

async fn relay_output(
    pty: &Pty,
    ack: &mut watch::Receiver<u32>,
    send: &impl Fn(Event) -> Result<(), String>,
) -> Result<(), String> {
    let mut buffer = vec![0; CHUNK_SIZE];
    let mut sequence = 0u32;
    loop {
        let size = pty.read(&mut buffer).await.map_err(|e| e.to_string())?;
        if size == 0 {
            return Ok(());
        }
        sequence = sequence.wrapping_add(1);
        send(Event::Output {
            sequence,
            bytes: buffer[..size].to_vec(),
        })?;
        // Keep at most one unread chunk in IPC, even when the remote floods the PTY.
        tokio::time::timeout(OUTPUT_TIMEOUT, ack.wait_for(|value| *value == sequence))
            .await
            .map_err(|_| "Terminal did not acknowledge output".to_string())?
            .map_err(|_| "Terminal window closed".to_string())?;
    }
}

async fn relay_input(
    pty: &Pty,
    input: &mut mpsc::Receiver<Vec<u8>>,
    mut on_submission: impl FnMut(),
) -> Result<(), String> {
    while let Some(bytes) = input.recv().await {
        pty.write(&bytes).await.map_err(|e| e.to_string())?;
        if bytes.iter().any(|b| matches!(b, b'\r' | b'\n')) {
            on_submission();
        }
    }
    Ok(())
}

async fn relay_size(pty: &Pty, size: &mut watch::Receiver<Size>) -> Result<(), String> {
    while size.changed().await.is_ok() {
        pty.resize(*size.borrow_and_update())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> Endpoint {
        Endpoint {
            host: "127.0.0.1".into(),
            user: "ops".into(),
            port: 22,
            identity_file: None,
            known_hosts_file: None,
            jump_host: None,
        }
    }

    const SIZE: Size = Size { rows: 27, cols: 93 };

    #[tokio::test]
    async fn controls_are_owned_by_the_window_and_cancel_pending_connections() {
        let sessions = Sessions::default();
        let mut session = sessions
            .register("server-a", "a".into(), endpoint(), SIZE)
            .unwrap();
        assert!(allow_window("main", "a").is_ok());
        assert!(allow_window("server-a", "a").is_ok());
        assert!(allow_window("server-b", "a").is_err());
        assert!(allow_window("approval-a", "a").is_err());
        assert!(sessions
            .register("server-a", "a".into(), endpoint(), SIZE)
            .is_err());
        assert!(sessions
            .send("server-b", session.id, Message::Resize { size: SIZE })
            .is_err());
        sessions.close("server-b", session.id);
        assert!(!session.cancel.is_cancelled());
        sessions.close_window("server-a");
        let pool = ssh_pool::Pool::new(1, Duration::from_secs(1), None).unwrap();
        assert_eq!(
            session
                .terminal
                .connect(
                    &pool,
                    &endpoint(),
                    &session.cancel,
                    &session.revoke,
                    || {},
                    |_| { panic!("cancelled console sent an event") }
                )
                .await
                .unwrap(),
            None
        );
        assert_eq!(pool.stats().connections, 0);
        drop(session);
        assert!(sessions
            .register("server-a", "a".into(), endpoint(), SIZE)
            .is_ok());
    }

    async fn expect_output(
        sessions: &Sessions,
        id: Uuid,
        events: &mut mpsc::UnboundedReceiver<Event>,
        output: &mut Vec<u8>,
        needle: &str,
    ) {
        let deadline = Duration::from_secs(10);
        tokio::time::timeout(deadline, async {
            while !String::from_utf8_lossy(output).contains(needle) {
                let Some(Event::Output { sequence, bytes }) = events.recv().await else {
                    panic!(
                        "SSH closed before {needle:?}: {:?}",
                        String::from_utf8_lossy(output)
                    );
                };
                output.extend(bytes);
                sessions
                    .send("main", id, Message::Ack { sequence })
                    .unwrap();
            }
        })
        .await
        .unwrap_or_else(|_| panic!("missing {needle:?}: {:?}", String::from_utf8_lossy(output)));
    }

    #[tokio::test]
    #[ignore = "Requires disposable SSH fixture: python3 scripts/test-ssh.py"]
    async fn real_ssh_terminal() {
        let dir = std::env::var("CYBERBOT_TEST_SSH_DIR").unwrap();
        let mut endpoint = endpoint();
        endpoint.port = std::env::var("CYBERBOT_TEST_SSH_PORT")
            .unwrap()
            .parse()
            .unwrap();
        endpoint.identity_file = Some(format!("{dir}/id_ed25519"));
        endpoint.known_hosts_file = Some(format!("{dir}/known_hosts"));

        let local = tempfile::tempdir().unwrap();
        let config = local.path().join("config");
        let includes = local.path().join("includes");
        std::fs::create_dir(&includes).unwrap();
        let proxy = local.path().join("proxy.sh");
        let scratch = local.path().join("unrelated.tmp");
        std::fs::write(
            &proxy,
            format!(
                "set -e\ntouch '{}'\nrm '{}'\nexec /usr/bin/nc \"$@\"\n",
                scratch.display(),
                scratch.display(),
            ),
        )
        .unwrap();
        std::fs::write(
            &config,
            format!(
                "Include {}/*.conf\nProxyCommand /bin/sh '{}' %h %p\n",
                includes.display(),
                proxy.display(),
            ),
        )
        .unwrap();
        let empty_hosts = local.path().join("empty_known_hosts");
        std::fs::write(&empty_hosts, "").unwrap();
        let collector = ssh::write_collector(local.path()).unwrap();
        let pool = ssh_pool::Pool::new(4, Duration::from_secs(60), Some(config)).unwrap();
        ssh_pool::install(pool.clone()).unwrap();

        let sessions = Sessions::default();
        let mut session = sessions
            .register("main", "fixture".into(), endpoint.clone(), SIZE)
            .unwrap();
        let id = session.id;
        let (send, mut events) = mpsc::unbounded_channel();
        let fixture_pool = pool.clone();
        let fixture_endpoint = endpoint.clone();
        let submissions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let submitted = submissions.clone();
        let task = tokio::spawn(async move {
            session
                .terminal
                .connect(
                    &fixture_pool,
                    &fixture_endpoint,
                    &session.cancel,
                    &session.revoke,
                    || {
                        submitted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    },
                    |event| send.send(event).map_err(|_| "test receiver closed".into()),
                )
                .await
        });
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(20), events.recv())
                .await
                .unwrap(),
            Some(Event::Ready)
        ));
        let input = |bytes: &[u8]| {
            sessions
                .send(
                    "main",
                    id,
                    Message::Input {
                        bytes: bytes.to_vec(),
                    },
                )
                .unwrap();
        };
        let mut output = Vec::new();
        // Command markers are split in the input so the PTY's input echo cannot satisfy them.
        input(b"printf 'user:%s\\n' \"$(id -un)\"; stty size");
        input(b"\r");
        expect_output(&sessions, id, &mut events, &mut output, "user:ops\r\n27 93").await;
        assert_eq!(submissions.load(std::sync::atomic::Ordering::Relaxed), 1);

        std::fs::write(&scratch, "unrelated to OpenSSH").unwrap();
        pool.retain(std::slice::from_ref(&endpoint));
        pool.refresh_changed_directories().await;
        std::fs::remove_file(&scratch).unwrap();
        assert!(ssh::collect(&endpoint, &collector)
            .await
            .unwrap()
            .cpu_percent
            .is_some());
        input("printf 'Hello, %s\\n' 'SSH'\r".as_bytes());
        expect_output(&sessions, id, &mut events, &mut output, "Hello, SSH\r\n").await;

        input(b"printf 'first%s\\n' '_chunk'; sleep 1; printf 'second%s\\n' '_chunk'\r");
        expect_output(&sessions, id, &mut events, &mut output, "first_chunk").await;
        assert!(!String::from_utf8_lossy(&output).contains("second_chunk"));
        expect_output(&sessions, id, &mut events, &mut output, "second_chunk").await;

        sessions
            .send(
                "main",
                id,
                Message::Resize {
                    size: Size {
                        rows: 39,
                        cols: 108,
                    },
                },
            )
            .unwrap();
        // Ask the remote terminal to report the new size after the asynchronous window-change.
        input(b"while [ \"$(stty size)\" != '39 108' ]; do sleep 0.05; done; stty size\r");
        expect_output(&sessions, id, &mut events, &mut output, "\r\n39 108\r\n").await;

        input(b"printf 'sleep%s\\n' '_ready'; sleep 60\r");
        expect_output(&sessions, id, &mut events, &mut output, "sleep_ready").await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        input(b"\x03");
        input(b"printf 'interrupt%s\\n' '_done'\r");
        expect_output(&sessions, id, &mut events, &mut output, "interrupt_done").await;

        input(b"printf 'last%s\\n' '_line'; exit 7\r");
        expect_output(&sessions, id, &mut events, &mut output, "last_line").await;
        tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(Event::Output { sequence, .. }) = events.recv().await {
                sessions
                    .send("main", id, Message::Ack { sequence })
                    .unwrap();
            }
        })
        .await
        .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(10), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            Some(7)
        );
        assert!(ssh::collect(&endpoint, &collector)
            .await
            .unwrap()
            .cpu_percent
            .is_some());
        assert_eq!(
            pool.stats().opened,
            1,
            "monitoring must reuse the console's master"
        );

        let lease = pool.acquire(&endpoint).await.unwrap();
        std::fs::write(includes.join("new.conf"), "ServerAliveCountMax 3\n").unwrap();
        pool.refresh_changed_directories().await;
        tokio::time::timeout(Duration::from_secs(1), lease.revoked())
            .await
            .expect("a newly matched Include must withdraw the master");
        assert!(lease.options().is_err());
        drop(lease);

        endpoint.known_hosts_file = Some(empty_hosts.to_string_lossy().into_owned());
        pool.retain(std::slice::from_ref(&endpoint));
        let mut rejected = sessions
            .register("main", "fixture".into(), endpoint.clone(), SIZE)
            .unwrap();
        let error = rejected
            .terminal
            .connect(
                &pool,
                &endpoint,
                &rejected.cancel,
                &rejected.revoke,
                || {},
                |_| panic!("untrusted server opened a console"),
            )
            .await
            .unwrap_err();
        assert!(error.contains("host key"), "{error}");
        pool.shutdown();
    }
}
