//! Only the non-thinking broker can read the provider's single Keychain item.
//! Never expose refresh tokens, Keychain access or authentication output to MCP/UI.
use crate::{model::now, process};
use serde::Deserialize;
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, process::Command};
use zeroize::Zeroizing;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Credentials {
    claude_ai_oauth: Oauth,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Oauth {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: i64,
    scopes: Vec<String>,
}
async fn read() -> Result<Oauth, String> {
    let mut output = process::bounded(
        "/usr/bin/security",
        &[
            "find-generic-password".into(),
            "-s".into(),
            "Claude Code-credentials".into(),
            "-w".into(),
        ],
        None,
        10,
        65536,
    )
    .await
    .map_err(|_| "Could not read Claude Code credentials")?;
    let bytes = Zeroizing::new(std::mem::take(&mut output.stdout));
    if !output.success {
        return Err("Claude Code credentials are missing from Keychain. Run claude auth login in a terminal.".into());
    }
    serde_json::from_slice::<Credentials>(&bytes)
        .map(|v| v.claude_ai_oauth)
        .map_err(|_| "Unsupported Claude Code credential format".into())
}
pub async fn claude_token(executable: &Path) -> Result<Zeroizing<String>, String> {
    let mut _activity_span = crate::activity::begin("process", "auth.claude_token", None);
    let _activity_result = (async {
        let mut oauth = read().await?;
        if oauth.expires_at < (now() + 960) * 1000 {
            let refresh = Zeroizing::new(
                oauth
                    .refresh_token
                    .take()
                    .ok_or("Claude Code credentials expired.")?,
            );
            // This fixed CLI subcommand only renews native auth. It never starts an agent,
            // receives infrastructure data, or evaluates prompts. Auth persistence remains CLI-owned.
            let mut c = Command::new(executable);
            c.args(["auth", "login"]).env_clear();
            for key in ["HOME", "USER", "LOGNAME", "LANG"] {
                if let Some(v) = std::env::var_os(key) {
                    c.env(key, v);
                }
            }
            c.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                .env("CLAUDE_CODE_OAUTH_REFRESH_TOKEN", refresh.as_str())
                .env("CLAUDE_CODE_OAUTH_SCOPES", oauth.scopes.join(" "))
                .env("DISABLE_AUTOUPDATER", "1")
                .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .process_group(0);
            let mut child = c
                .spawn()
                .map_err(|_| "Could not refresh Claude Code credentials")?;
            let _guard = process::GroupGuard::register(child.id().ok_or("No PID")?)?;
            let out = child.stdout.take().ok_or("No stdout")?;
            let renewed = tokio::time::timeout(Duration::from_secs(40), async {
                let mut discard = Zeroizing::new(Vec::new());
                out.take(65537)
                    .read_to_end(&mut discard)
                    .await
                    .map_err(|_| ())?;
                if discard.len() > 65536 {
                    return Err(());
                }
                child
                    .wait()
                    .await
                    .map_err(|_| ())?
                    .success()
                    .then_some(())
                    .ok_or(())
            })
            .await;
            if !matches!(renewed, Ok(Ok(()))) {
                return Err("Could not refresh Claude Code credentials.".into());
            }
            oauth = read().await?;
        }
        if oauth.expires_at < (now() + 900) * 1000 || oauth.access_token.is_empty() {
            return Err(
                "Claude Code credentials expire before the run can finish. Sign in to the CLI again."
                    .into(),
            );
        }
        Ok(Zeroizing::new(std::mem::take(&mut oauth.access_token)))
    })
    .await;
    _activity_span.result(&_activity_result);
    _activity_result
}
impl Drop for Oauth {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}
