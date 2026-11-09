use super::{target, Scope};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::atomic::Ordering;

pub(super) const READ_TOOLS: &[(&str, &str)] = &[
    ("cat", "Read a bounded page of a text file"),
    ("grep", "Search text for a literal pattern and return matching paths only. A directory is searched recursively"),
    ("ls", "List a directory with file types and sizes"),
    ("du", "Estimate allocated disk space for a directory"),
    ("awk", "Select numbered fields from a page of a text file"),
    ("sed", "Read a range of lines from a text file"),
];

pub(crate) fn is_read(name: &str) -> bool {
    READ_TOOLS.iter().any(|(tool, _)| *tool == name)
}

pub(super) fn tools() -> Vec<Value> {
    let mut tools = Vec::new();
    for &(name, purpose) in READ_TOOLS {
        let mut fields =
            json!({"serverId":{"type":"string"},"path":{"type":"string","maxLength":1024}});
        let mut required = vec!["serverId", "path"];
        if name == "grep" {
            fields["pattern"] = json!({"type":"string","minLength":1,"maxLength":256});
            required.push("pattern");
        }
        if matches!(name, "cat" | "sed" | "awk") {
            fields["startLine"] = json!({"type":"integer","minimum":1,"maximum":100000});
            fields["lineCount"] = json!({"type":"integer","minimum":1,"maximum":200});
        }
        if name == "awk" {
            fields["fields"] = json!({"type":"array","minItems":1,"maxItems":16,"items":{"type":"integer","minimum":1,"maximum":256}});
            fields["separator"] = json!({"type":"string","minLength":1,"maxLength":1});
            required.push("fields");
        }
        tools.push(json!({"name":name,"description":format!("{purpose}. Live SSH read, no approval or shell. Allowed roots: /home, /srv, /opt, /var/www. Skips sensitive paths and links. Check complete and gaps before drawing conclusions."),"inputSchema":{"type":"object","properties":fields,"required":required,"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false}}));
    }
    tools.push(json!({"name":"exec","description":"Request execution of an exact POSIX shell script on one scoped server with the configured SSH user's privileges. Read get_server first. Low risk review and desktop user approval (or an explicit exec grant for this run) are mandatory. Wait for the result, do not poll or retry unknown effects. Prefer cat, grep, ls, du, awk and sed for supported reads.","inputSchema":{"type":"object","additionalProperties":false,"required":["serverId","goal","script"],"properties":{"serverId":{"type":"string","maxLength":128},"goal":{"type":"string","minLength":1,"maxLength":1000},"script":{"type":"string","minLength":1,"maxLength":16384}}},"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":true}}));
    tools
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReadArgs {
    #[serde(skip_serializing)]
    server_id: String,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    line_count: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<Vec<u16>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    separator: Option<String>,
}

impl ReadArgs {
    fn validate(&self, operation: &str) -> Result<(), String> {
        let text = matches!(operation, "cat" | "sed" | "awk");
        let path_allowed = ["/home", "/srv", "/opt", "/var/www"].iter().any(|&root| {
            self.path == root
                || self
                    .path
                    .strip_prefix(root)
                    .is_some_and(|tail| tail.starts_with('/'))
        });
        if !path_allowed
            || self.path.len() > 1024
            || self.path.chars().any(char::is_control)
            || self
                .path
                .split('/')
                .skip(1)
                .any(|p| p.is_empty() || p.starts_with('.'))
            || self.pattern.is_some() != (operation == "grep")
            || self
                .pattern
                .as_ref()
                .is_some_and(|p| p.is_empty() || p.len() > 256 || p.contains('\0'))
            || !text && (self.start_line.is_some() || self.line_count.is_some())
            || self.start_line.is_some_and(|v| !(1..=100000).contains(&v))
            || self.line_count.is_some_and(|v| !(1..=200).contains(&v))
            || self.fields.is_some() != (operation == "awk")
            || self.fields.as_ref().is_some_and(|v| {
                v.is_empty() || v.len() > 16 || v.iter().any(|f| !(1..=256).contains(f))
            })
            || self
                .separator
                .as_ref()
                .is_some_and(|s| operation != "awk" || s.chars().count() != 1)
        {
            return Err("Inadmissible path or reading operation parameters".into());
        }
        Ok(())
    }
}

pub(super) async fn read(scope: &Scope, operation: &str, args: Value) -> Result<Value, String> {
    if !scope.web_enabled() {
        return Err("Remote reading is only available with manual start-up".into());
    }
    let args: ReadArgs =
        serde_json::from_value(args).map_err(|_| "Incorrect reading parameters")?;
    args.validate(operation)?;
    let server = target(scope, &args.server_id)?;
    if scope.remote.fetch_add(1, Ordering::SeqCst) >= 4 {
        return Err("The limit of four remote checks is exhausted".into());
    }
    let _guard = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        scope.app.collectors.manual(&server.id),
    )
    .await
    .map_err(|_| "The server’s queue for reading is not free")??;
    let stamp = crate::ssh_authorization::capture(&server.endpoint).await?;
    let mut request = json!(args);
    request["operation"] = json!(operation);
    let payload = json!({"kind":"remote_read","state":request});
    let bytes = crate::ssh_authorization::guarded(stamp, async {
        target(scope, &server.id)?;
        crate::ssh::deploy(&server.endpoint, &scope.app.collector).await?;
        target(scope, &server.id)?;
        crate::ssh::run_collector(&server.endpoint, &payload, 16384).await
    })
    .await?;
    target(scope, &server.id)?;
    let mut reply: Value = serde_json::from_slice(&bytes)
        .map_err(|_| "Incorrect response of the reading operation")?;
    if reply["operation"] != operation || reply["complete"].as_bool().is_none() {
        return Err("I couldn’t read the path. Make sure it exists, it’s available on SSH, and it’s allowed by the read rules.".into());
    }
    reply["serverId"] = json!(server.id);
    reply["observedAt"] = json!(crate::model::now());
    Ok(reply)
}
