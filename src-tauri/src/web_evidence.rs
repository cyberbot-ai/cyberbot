//! The trusted broker reads public evidence without granting network access to a CLI.
use html5ever::tokenizer::{
    states::RawKind, BufferQueue, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer,
};
use reqwest::{
    dns::{Name, Resolve, Resolving},
    header,
    redirect::Policy,
    Url,
};
use serde::Serialize;
use std::{cell::RefCell, net::SocketAddr, time::Duration};

const MAX_BODY: usize = 1024 * 1024;
const MAX_TEXT: usize = 12 * 1024;
const MAX_REDIRECTS: usize = 3;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Page {
    url: String,
    read_at: i64,
    text: String,
    truncated: bool,
}

fn parse_url(raw: &str) -> Result<Url, String> {
    if raw.len() > 2048 {
        return Err("The link is too long".into());
    }
    let mut url = Url::parse(raw).map_err(|_| "Invalid URL")?;
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || !url.domain().is_some_and(|host| host.contains('.'))
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("Use a public HTTPS URL without credentials".into());
    }
    url.set_fragment(None);
    Ok(url)
}

pub(crate) fn links_in(message: &str) -> Vec<Url> {
    static LINKS: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r#"(?i)https://[^\s<>"'`]+"#).expect("HTTPS pattern")
    });
    LINKS
        .find_iter(message)
        .take(32)
        .filter_map(|m| {
            let raw = m.as_str();
            let mut end = raw.trim_end_matches(['.', ',', ';', '!', ']', '}']);
            while end.ends_with(')') && end.matches(')').count() > end.matches('(').count() {
                end = &end[..end.len() - 1];
            }
            parse_url(end).ok()
        })
        .collect()
}

pub(crate) fn requested_url(raw: &str, allowed: &[Url]) -> Result<Url, String> {
    let url = parse_url(raw)?;
    if allowed.contains(&url) {
        Ok(url)
    } else {
        Err("Use an HTTPS link from the latest user message".into())
    }
}

fn public_addresses(addresses: Vec<SocketAddr>) -> Result<Vec<SocketAddr>, String> {
    if addresses.is_empty()
        || addresses.len() > 32
        || addresses.iter().any(|a| !crate::egress::public(a.ip()))
    {
        return Err("The domain resolves to a nonpublic address".into());
    }
    Ok(addresses)
}

async fn addresses(url: &Url) -> Result<Vec<SocketAddr>, String> {
    let host = url.domain().ok_or("Public domain expected")?;
    let resolved = tokio::net::lookup_host((host, 443))
        .await
        .map_err(|_| "Failed to resolve the domain")?;
    public_addresses(resolved.take(33).collect())
}

fn redirect_url(url: &Url, location: &str) -> Result<Url, String> {
    let next = url.join(location).map_err(|_| "Invalid redirect")?;
    parse_url(next.as_str())
}

struct NoUnverifiedDns;
impl Resolve for NoUnverifiedDns {
    fn resolve(&self, _: Name) -> Resolving {
        Box::pin(async { Err(std::io::Error::other("Could not verify the destination").into()) })
    }
}

pub(crate) async fn read(url: Url) -> Result<Page, String> {
    tokio::time::timeout(Duration::from_secs(20), read_inner(url))
        .await
        .map_err(|_| "Timed out while reading the public page".to_string())?
}

async fn read_inner(mut url: Url) -> Result<Page, String> {
    for hop in 0..=MAX_REDIRECTS {
        let ips = addresses(&url).await?;
        let host = url.domain().ok_or("Public domain expected")?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(Policy::none())
            .dns_resolver(std::sync::Arc::new(NoUnverifiedDns))
            .resolve_to_addrs(host, &ips)
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| "Could not read the page")?;
        let mut response = client
            .get(url.clone())
            .header(header::USER_AGENT, "Cyberbot public evidence reader")
            .header(header::ACCEPT, "text/html, text/plain, application/json")
            .send()
            .await
            .map_err(|_| "Could not open the public page")?;
        if response.status().is_redirection() {
            if hop == MAX_REDIRECTS {
                return Err("Too many redirects".into());
            }
            let location = response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or("Redirect is missing a destination URL")?;
            url = redirect_url(&url, location)?;
            continue;
        }
        if !response.status().is_success() {
            return Err(format!(
                "The source returned HTTP {}",
                response.status().as_u16()
            ));
        }
        let mime = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if !matches!(
            mime.as_str(),
            "text/html" | "application/xhtml+xml" | "text/plain" | "application/json"
        ) {
            return Err("The source returned an unsupported content type".into());
        }
        if response
            .content_length()
            .is_some_and(|len| len > MAX_BODY as u64)
        {
            return Err("Page exceeds 1 MiB".into());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "Could not finish reading the page")?
        {
            if body.len() + chunk.len() > MAX_BODY {
                return Err("Page exceeds 1 MiB".into());
            }
            body.extend_from_slice(&chunk);
        }
        let body = String::from_utf8_lossy(&body);
        let text = if matches!(mime.as_str(), "text/html" | "application/xhtml+xml") {
            html_text(&body)
        } else {
            body.chars()
                .filter(|ch| !ch.is_control() || matches!(ch, '\n' | '\t'))
                .collect()
        };
        let mut end = text.len().min(MAX_TEXT);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        return Ok(Page {
            url: url.into(),
            read_at: crate::model::now(),
            text: text[..end].trim().to_owned(),
            truncated: end < text.len(),
        });
    }
    Err("Too many redirects".into())
}

#[derive(Default)]
struct Text {
    body: String,
    skip_raw: bool,
    cell: bool,
}

#[derive(Default)]
struct HtmlText(RefCell<Text>);

impl TokenSink for HtmlText {
    type Handle = ();

    fn process_token(&self, token: Token, _: u64) -> TokenSinkResult<()> {
        let mut text = self.0.borrow_mut();
        match token {
            Token::TagToken(tag) => {
                let name = tag.name.as_ref();
                if matches!(name, "script" | "style") {
                    text.skip_raw = tag.kind == TagKind::StartTag;
                    if text.skip_raw {
                        return TokenSinkResult::RawData(if name == "script" {
                            RawKind::ScriptData
                        } else {
                            RawKind::Rawtext
                        });
                    }
                } else if name == "tr" {
                    text.cell = false;
                    text.body.push('\n');
                } else if matches!(name, "td" | "th") && tag.kind == TagKind::StartTag {
                    if text.cell {
                        text.body.push_str(" | ");
                    }
                    text.cell = true;
                } else if matches!(
                    name,
                    "br" | "p" | "div" | "li" | "pre" | "h1" | "h2" | "h3" | "h4"
                ) {
                    text.body.push('\n');
                }
            }
            Token::CharacterTokens(chunk) if !text.skip_raw => {
                for ch in chunk.chars() {
                    if ch.is_whitespace() {
                        if !text.body.ends_with([' ', '\n']) {
                            text.body.push(' ');
                        }
                    } else if !ch.is_control() {
                        text.body.push(ch);
                    }
                }
            }
            _ => {}
        }
        TokenSinkResult::Continue
    }
}

fn html_text(body: &str) -> String {
    let input = BufferQueue::default();
    input.push_back(body.into());
    let parser = Tokenizer::new(HtmlText::default(), Default::default());
    let _ = parser.feed(&input);
    parser.end();
    parser
        .sink
        .0
        .into_inner()
        .body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn advisory_url(provider: &str, cve: &str) -> Result<Url, String> {
    if !crate::advisories::valid_cve(cve) {
        return Err("Incorrect CVE identifier".into());
    }
    let link = match provider {
        "debian" => format!("https://security-tracker.debian.org/tracker/{cve}"),
        "ubuntu" => format!("https://ubuntu.com/security/{cve}"),
        _ => crate::advisories::cve_record_url(cve).ok_or("Incorrect CVE identifier")?,
    };
    parse_url(&link)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_current_https_links_are_authorized() {
        let urls = links_in(
            "Read [tracker](https://example.org/a?q=1) and <https://example.org/wiki/A_(B)>.",
        );
        assert!(requested_url("https://example.org/a?q=1#heading", &urls).is_ok());
        assert!(requested_url("https://example.org/wiki/A_(B)", &urls).is_ok());
        assert!(requested_url("https://example.org/a?q=secret", &urls).is_err());
        for link in [
            "http://example.org",
            "https://user:secret@example.org",
            "https://127.1",
            "https://example.org:8443",
        ] {
            assert!(parse_url(link).is_err(), "{link}");
        }
    }

    #[test]
    fn redirects_are_validated_and_mixed_dns_answers_rejected() {
        let start = parse_url("https://example.org/").unwrap();
        assert!(redirect_url(&start, "//127.0.0.1/admin").is_err());
        assert!(redirect_url(&start, "http://example.org/").is_err());
        let next = redirect_url(&start, "https://internal.example.org/").unwrap();
        assert_eq!(next.domain(), Some("internal.example.org"));
        assert!(public_addresses(vec![
            "8.8.8.8:443".parse().unwrap(),
            "[::ffff:127.0.0.1]:443".parse().unwrap()
        ])
        .is_err());
    }

    #[test]
    fn extracts_advisory_table_and_excludes_script_content() {
        let html = "<script>let example = '<tr><td>malicious';</script><h2>CVE &amp; status</h2><table><tr><th>Release</th><th>Version</th><th>Status</th></tr><tr><td>bookworm</td><td>3.6.0</td><td><b>vulnerable</b></td></tr></table>";
        assert_eq!(
            html_text(html),
            "CVE & status\nRelease | Version | Status\nbookworm | 3.6.0 | vulnerable"
        );
    }
}
