//! HTTPS CONNECT allowlist. The agent sandbox can reach only this listener and MCP.
use std::{net::IpAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
};

pub const OPENAI: &[&str] = &["chatgpt.com", "api.openai.com", "auth.openai.com"];
pub const ANTHROPIC: &[&str] = &[
    "api.anthropic.com",
    "claude.ai",
    "api.claude.ai",
    "console.anthropic.com",
];
pub fn allowed_authority(authority: &str, provider: &str) -> Option<String> {
    let host = authority.strip_suffix(":443")?;
    let allowed = match provider {
        "codex" => OPENAI,
        "claude" => ANTHROPIC,
        _ => return None,
    };
    if allowed.contains(&host) {
        Some(host.into())
    } else {
        None
    }
}
pub(crate) fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !v.is_private()
                && !v.is_loopback()
                && !v.is_link_local()
                && !v.is_unspecified()
                && !v.is_multicast()
                && !v.is_broadcast()
                && !v.is_documentation()
                && v.octets()[0] != 0
                && !(v.octets()[0] == 100 && (64..=127).contains(&v.octets()[1]))
                && !(v.octets()[0] == 198 && (18..=19).contains(&v.octets()[1]))
                && !(v.octets()[0] == 192 && v.octets()[1] == 0 && v.octets()[2] == 0)
                && !(v.octets()[0..3] == [192, 88, 99])
                && v.octets()[0] < 240
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            // Permit global unicast, excluding documentation, transition and
            // special-purpose space (which can embed private destinations).
            (s[0] & 0xe000) == 0x2000
                && s[0] != 0x2002
                && s[0] != 0x3fff
                && !(s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
        }
    }
}
pub struct Egress {
    pub port: u16,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Egress {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Egress {
    pub async fn close(&mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
    pub async fn start(provider: &str) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let provider = provider.to_owned();
        let task = tokio::spawn(async move {
            let sem = Arc::new(tokio::sync::Semaphore::new(8));
            let mut jobs = JoinSet::new();
            loop {
                tokio::select! {
                  accepted=listener.accept()=>{let Ok((socket,_))=accepted else{break};let Ok(permit)=sem.clone().try_acquire_owned()else{continue};let provider=provider.clone();jobs.spawn(async move{let _permit=permit;let _=tokio::time::timeout(std::time::Duration::from_secs(330),tunnel(socket,&provider)).await;});},
                  _=jobs.join_next(),if !jobs.is_empty()=>{}
                }
            }
        });
        Ok(Self { port, task })
    }
}
async fn tunnel(mut client: TcpStream, provider: &str) -> Result<(), String> {
    let mut header = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let b = client.read_u8().await.map_err(|e| e.to_string())?;
            header.push(b);
            if header.ends_with(b"\r\n\r\n") {
                break;
            }
            if header.len() > 8192 {
                return Err("headers too large".into());
            }
        }
        Ok::<_, String>(())
    })
    .await
    .map_err(|_| "header timeout")??;
    let head = std::str::from_utf8(&header).map_err(|e| e.to_string())?;
    let line = head.lines().next().unwrap_or("");
    let words = line.split_whitespace().collect::<Vec<_>>();
    let host = if words.len() == 3 && words[0] == "CONNECT" {
        allowed_authority(words[1], provider)
    } else {
        None
    };
    let Some(host) = host else {
        let _ = client
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        return Err("destination denied".into());
    };
    let addresses = tokio::net::lookup_host((host.as_str(), 443))
        .await
        .map_err(|e| e.to_string())?
        .collect::<Vec<_>>();
    if addresses.is_empty() || addresses.iter().any(|a| !public(a.ip())) {
        return Err("non-public DNS answer denied".into());
    }
    let mut remote = None;
    for address in addresses {
        if let Ok(Ok(socket)) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(address),
        )
        .await
        {
            remote = Some(socket);
            break;
        }
    }
    let mut remote = remote.ok_or("provider unavailable")?;
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|e| e.to_string())?;
    // Cap both directions; no unbounded model output or tunneled downloads.
    let (cr, cw) = client.split();
    let (rr, rw) = remote.split();
    let up = async {
        let mut read = cr.take(16 * 1024 * 1024);
        let mut write = rw;
        tokio::io::copy(&mut read, &mut write).await
    };
    let down = async {
        let mut read = rr.take(16 * 1024 * 1024);
        let mut write = cw;
        tokio::io::copy(&mut read, &mut write).await
    };
    tokio::select! {_=up=>{},_=down=>{}};
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_hosts_only() {
        for s in [
            "localhost:443",
            "127.0.0.1:22",
            "chatgpt.com.evil:443",
            "chatgpt.com:22",
            "user@chatgpt.com:443",
            "chatgpt.com:443/path",
        ] {
            assert!(allowed_authority(s, "codex").is_none());
        }
        assert!(allowed_authority("chatgpt.com:443", "codex").is_some());
        assert!(allowed_authority("chatgpt.com:443", "claude").is_none());
    }
    #[test]
    fn reject_private_dns() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "::1",
            "fc00::1",
            "::ffff:127.0.0.1",
            "198.18.0.1",
            "2001:db8::1",
            "2002:7f00:1::",
            "fec0::1",
        ] {
            assert!(!public(ip.parse().unwrap()));
        }
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    #[tokio::test]
    async fn denies_local_and_suffix_destinations_and_closes_on_drop() {
        let mut proxy = Egress::start("codex").await.unwrap();
        let port = proxy.port;
        for target in [
            "127.0.0.1:22",
            "localhost:443",
            "chatgpt.com.evil.invalid:443",
            "api.anthropic.com:443",
        ] {
            let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut response = Vec::new();
            s.read_to_end(&mut response).await.unwrap();
            assert!(response.starts_with(b"HTTP/1.1 403"));
        }
        proxy.close().await;
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
    }
}
