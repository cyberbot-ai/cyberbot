//! Static inventory only. Groups are used to inherit literal SSH settings, then
//! discarded; unrelated variables never reach the database or SSH command line.
use super::{validate_endpoint, Endpoint, Imported};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

type Vars = BTreeMap<String, String>;
const MAX_HOSTS: usize = 5000;
const MAX_GROUPS: usize = 1024;
const MAX_MEMBERSHIPS: usize = 50_000;

#[derive(Default)]
struct Group {
    vars: Vars,
    hosts: BTreeSet<String>,
    children: BTreeSet<String>,
}
#[derive(Default)]
struct Inventory {
    groups: BTreeMap<String, Group>,
    hosts: BTreeMap<String, Vars>,
    entries: usize,
    variable_bytes: usize,
}

fn canonical(key: &str) -> Option<&'static str> {
    Some(match key {
        "ansible_host" | "ansible_ssh_host" => "ansible_host",
        "ansible_user" | "ansible_ssh_user" => "ansible_user",
        "ansible_port" | "ansible_ssh_port" => "ansible_port",
        "ansible_private_key_file" | "ansible_ssh_private_key_file" => {
            "ansible_ssh_private_key_file"
        }
        "ansible_connection" => "ansible_connection",
        "ansible_group_priority" => "ansible_group_priority",
        _ => return None,
    })
}

fn read_vars(value: &Value) -> Result<Vars, String> {
    if value.is_null() {
        return Ok(Vars::new());
    }
    let map = value
        .as_object()
        .ok_or("Inventory variables must be a mapping")?;
    let mut vars = Vars::new();
    for (key, value) in map {
        if matches!(
            key.as_str(),
            "ansible_ssh_common_args" | "ansible_ssh_extra_args" | "ansible_ssh_executable"
        ) {
            return Err(
                "Configure SSH commands in your SSH config. Cyberbot reads only connection parameters from inventory."
                    .into(),
            );
        }
        let Some(name) = canonical(key) else { continue };
        let literal = value
            .as_str()
            .ok_or("SSH parameters must be plain strings or numbers")?;
        if literal.len() > 4096 || literal.contains(['\n', '\r', '\0']) {
            return Err("An SSH parameter is invalid or too long".into());
        }
        if ["{{", "{%", "{#"].iter().any(|s| literal.contains(s)) {
            return Err("Enter literal SSH parameter values in the inventory".into());
        }
        if key == name || !vars.contains_key(name) {
            vars.insert(name.into(), literal.into());
        }
    }
    Ok(vars)
}

impl Inventory {
    fn group(&mut self, name: &str) -> Result<&mut Group, String> {
        if name.is_empty()
            || name.len() > 253
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
        {
            return Err("Invalid inventory group name".into());
        }
        if !self.groups.contains_key(name) && self.groups.len() >= MAX_GROUPS {
            return Err("No more than 1024 groups in inventory".into());
        }
        Ok(self.groups.entry(name.into()).or_default())
    }

    fn child(&mut self, parent: &str, child: &str) -> Result<(), String> {
        self.group(child)?;
        self.group(parent)?.children.insert(child.into());
        self.entries += 1;
        self.check_limits()
    }

    fn check_limits(&self) -> Result<(), String> {
        if self.hosts.len() > MAX_HOSTS
            || self.entries > MAX_MEMBERSHIPS
            || self.variable_bytes > 8 * 1024 * 1024
        {
            return Err(
                "Inventory exceeds the limit: 5,000 servers, 50,000 connections and 8 MiB parameters"
                    .into(),
            );
        }
        Ok(())
    }

    fn host(&mut self, group: &str, pattern: &str, mut vars: Vars) -> Result<(), String> {
        let (pattern, port) = host_port(pattern)?;
        if let Some(port) = port {
            vars.entry("ansible_port".into()).or_insert(port);
        }
        for name in expand_hosts(&pattern)? {
            validate_endpoint(&Endpoint {
                host: name.clone(),
                user: "ops".into(),
                port: 22,
                identity_file: None,
                jump_host: None,
                known_hosts_file: None,
            })?;
            self.entries += 1;
            self.variable_bytes += vars.values().map(String::len).sum::<usize>();
            self.hosts
                .entry(name.clone())
                .or_default()
                .extend(vars.clone());
            self.group(group)?.hosts.insert(name);
            self.check_limits()?;
        }
        Ok(())
    }

    fn yaml_group(&mut self, name: &str, value: &Value) -> Result<(), String> {
        self.group(name)?;
        if value.is_null() {
            return Ok(());
        }
        let map = value
            .as_object()
            .ok_or("An inventory group must be a mapping")?;
        if map
            .keys()
            .any(|k| !matches!(k.as_str(), "vars" | "hosts" | "children"))
        {
            return Err("Use static inventory with hosts, vars, and children".into());
        }
        if let Some(vars) = map.get("vars") {
            self.group(name)?.vars.extend(read_vars(vars)?);
        }
        match map.get("hosts") {
            None | Some(Value::Null) => {}
            Some(Value::Object(hosts)) => {
                for (host, vars) in hosts {
                    self.host(name, host, read_vars(vars)?)?;
                }
            }
            Some(Value::Array(hosts)) => {
                for host in hosts {
                    self.host(
                        name,
                        host.as_str().ok_or("Expected a server name")?,
                        Vars::new(),
                    )?;
                }
            }
            _ => return Err("hosts must contain server names".into()),
        }
        match map.get("children") {
            None | Some(Value::Null) => {}
            Some(Value::Object(children)) => {
                for (child, value) in children {
                    self.child(name, child)?;
                    self.yaml_group(child, value)?;
                }
            }
            Some(Value::Array(children)) => {
                for child in children {
                    self.child(name, child.as_str().ok_or("Expected a group name")?)?;
                }
            }
            _ => return Err("children must contain groups".into()),
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<Imported>, String> {
        self.group("all")?;
        // Every declared host inherits all, including hosts from flat JSON exports.
        self.groups
            .get_mut("all")
            .unwrap()
            .hosts
            .extend(self.hosts.keys().cloned());
        let mut parents: BTreeMap<String, Vec<String>> = self
            .groups
            .keys()
            .map(|g| (g.clone(), Vec::new()))
            .collect();
        for (name, group) in &self.groups {
            for child in &group.children {
                parents.get_mut(child).unwrap().push(name.clone());
            }
        }
        let mut depths = BTreeMap::new();
        for name in self.groups.keys() {
            depth(name, &parents, &mut BTreeSet::new(), &mut depths)?;
        }
        let mut order = Vec::new();
        for (name, group) in &self.groups {
            let priority = group
                .vars
                .get("ansible_group_priority")
                .map(|v| v.parse::<i64>())
                .transpose()
                .map_err(|_| "Incorrect ansible_group_priority")?
                .unwrap_or(1);
            order.push((depths[name], priority, name.clone()));
        }
        order.sort();
        let mut memberships: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut count = 0;
        for (_, _, name) in order.iter().rev() {
            let group = &self.groups[name];
            let mut hosts = group.hosts.clone();
            for child in &group.children {
                hosts.extend(memberships[child].iter().cloned());
            }
            count += hosts.len();
            if count > MAX_MEMBERSHIPS {
                return Err("Too many group and server connections (50,000)".into());
            }
            memberships.insert(name.clone(), hosts);
        }
        let mut merged: BTreeMap<String, Vars> = self
            .hosts
            .keys()
            .map(|h| (h.clone(), Vars::new()))
            .collect();
        for (_, _, group) in order {
            for host in &memberships[&group] {
                merged
                    .get_mut(host)
                    .unwrap()
                    .extend(self.groups[&group].vars.clone());
            }
        }
        self.hosts
            .into_iter()
            .map(|(name, host_vars)| {
                let vars = merged.get_mut(&name).unwrap();
                vars.extend(host_vars);
                if vars
                    .get("ansible_connection")
                    .is_some_and(|v| v != "ssh" && v != "smart")
                {
                    return Err("Cyberbot supports SSH connections only".into());
                }
                let user = vars
                    .get("ansible_user")
                    .map(String::as_str)
                    .unwrap_or("root");
                if user.is_empty() {
                    return Err(
                        "Enter a value for ansible_user or remove it to use root by default".into(),
                    );
                }
                let endpoint = Endpoint {
                    host: vars.get("ansible_host").unwrap_or(&name).clone(),
                    user: user.into(),
                    port: vars
                        .get("ansible_port")
                        .map(|v| v.parse::<u16>())
                        .transpose()
                        .map_err(|_| "Incorrect ansible_port")?
                        .unwrap_or(22),
                    identity_file: vars.get("ansible_ssh_private_key_file").cloned(),
                    jump_host: None,
                    known_hosts_file: None,
                };
                validate_endpoint(&endpoint)?;
                Ok(Imported {
                    identity: name.clone(),
                    name,
                    endpoint,
                })
            })
            .collect()
    }
}

fn depth(
    name: &str,
    parents: &BTreeMap<String, Vec<String>>,
    visiting: &mut BTreeSet<String>,
    memo: &mut BTreeMap<String, usize>,
) -> Result<usize, String> {
    if let Some(d) = memo.get(name) {
        return Ok(*d);
    }
    if !visiting.insert(name.into()) {
        return Err("Inventory groups contain a cycle".into());
    }
    if visiting.len() > 32 {
        return Err("Inventory groups exceed 32 levels of nesting".into());
    }
    let mut result = usize::from(name != "all");
    for parent in &parents[name] {
        result = result.max(depth(parent, parents, visiting, memo)? + 1);
    }
    if result > 32 || (name == "all" && result != 0) {
        return Err("Invalid inventory group hierarchy".into());
    }
    visiting.remove(name);
    memo.insert(name.into(), result);
    Ok(result)
}

fn bracketed_ipv6(input: &str) -> bool {
    input
        .strip_prefix('[')
        .and_then(|rest| rest.split_once(']'))
        .is_some_and(|(host, _)| {
            host.split('%')
                .next()
                .unwrap_or("")
                .parse::<std::net::Ipv6Addr>()
                .is_ok()
        })
}

fn host_port(input: &str) -> Result<(String, Option<String>), String> {
    if input.len() > 253 {
        return Err("The server name is too long".into());
    }
    if bracketed_ipv6(input) {
        let (host, rest) = input[1..].split_once(']').ok_or("Incorrect IPv6 address")?;
        let port = if rest.is_empty() {
            None
        } else {
            Some(rest.strip_prefix(':').ok_or("Incorrect port")?.to_string())
        };
        return Ok((host.into(), port));
    }
    let mut brackets = 0;
    let mut colons = Vec::new();
    for (i, c) in input.char_indices() {
        match c {
            '[' => brackets += 1,
            ']' => brackets -= 1,
            ':' if brackets == 0 => colons.push(i),
            _ => {}
        }
        if brackets < 0 {
            return Err("Incorrect server name".into());
        }
    }
    if brackets != 0 {
        return Err("Incorrect server range".into());
    }
    if colons.len() == 1 {
        let i = colons[0];
        Ok((input[..i].into(), Some(input[i + 1..].into())))
    } else {
        Ok((input.into(), None))
    }
}

fn expand_hosts(input: &str) -> Result<Vec<String>, String> {
    let mut hosts = vec![input.to_string()];
    for _ in 0..8 {
        let mut next = Vec::new();
        let mut expanded = false;
        for host in hosts {
            let Some(start) = host.find('[') else {
                next.push(host);
                continue;
            };
            expanded = true;
            let end = start + host[start..].find(']').ok_or("Incorrect server range")?;
            let parts: Vec<_> = host[start + 1..end].split(':').collect();
            if !(2..=3).contains(&parts.len()) {
                return Err("Expected a range in [start:end:step] format".into());
            }
            let step = if parts.len() == 3 {
                parts[2].parse::<u32>().map_err(|_| "Invalid range step")?
            } else {
                1
            };
            let alpha = parts[0].len() == 1
                && parts[1].len() == 1
                && parts[0].as_bytes()[0].is_ascii_alphabetic()
                && parts[1].as_bytes()[0].is_ascii_alphabetic();
            let (low, high) = if alpha {
                (parts[0].as_bytes()[0] as u32, parts[1].as_bytes()[0] as u32)
            } else {
                (
                    parts[0].parse::<u32>().map_err(|_| "Invalid range start")?,
                    parts[1].parse::<u32>().map_err(|_| "Invalid range end")?,
                )
            };
            if step == 0
                || high < low
                || (high as u64 - low as u64) / u64::from(step) + 1 > MAX_HOSTS as u64
            {
                return Err(
                    "The server range exceeds the limit or has incorrect boundaries".into(),
                );
            }
            let width = if parts[0].starts_with('0') {
                parts[0].len()
            } else {
                0
            };
            for n in (low..=high).step_by(step as usize) {
                let value = if alpha {
                    (n as u8 as char).to_string()
                } else {
                    format!("{n:0width$}")
                };
                next.push(format!("{}{}{}", &host[..start], value, &host[end + 1..]));
                if next.len() > MAX_HOSTS {
                    return Err("A range can contain up to 5,000 servers".into());
                }
            }
        }
        hosts = next;
        if !expanded {
            return Ok(hosts);
        }
    }
    Err("Too many ranges in the server name".into())
}

/// Quote handling only; no substitution, evaluation or shell invocation.
fn words(line: &str) -> Result<Vec<String>, String> {
    let mut result = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escape = false;
    for c in line.chars() {
        if escape {
            word.push(c);
            escape = false;
            continue;
        }
        if c == '\\' && quote != Some('\'') {
            escape = true;
            continue;
        }
        if let Some(q) = quote {
            if c == q {
                quote = None
            } else {
                word.push(c)
            }
        } else if c == '\'' || c == '"' {
            quote = Some(c)
        } else if c == '#' || (c == ';' && word.is_empty()) {
            break;
        } else if c.is_whitespace() {
            if !word.is_empty() {
                result.push(std::mem::take(&mut word));
            }
        } else {
            word.push(c)
        }
    }
    if quote.is_some() || escape {
        return Err("Unterminated quote or escape in INI inventory".into());
    }
    if !word.is_empty() {
        result.push(word);
    }
    Ok(result)
}

fn ini(input: &str) -> Result<Inventory, String> {
    let mut inventory = Inventory::default();
    let mut section = "ungrouped".to_string();
    let mut kind = "hosts";
    for (line_no, line) in input.lines().enumerate() {
        let parse_line = |inventory: &mut Inventory,
                          section: &mut String,
                          kind: &mut &str|
         -> Result<(), String> {
            let line = line.trim();
            if line.is_empty() || line.starts_with(['#', ';']) {
                return Ok(());
            }
            if line.starts_with('[') && !bracketed_ipv6(line) {
                let end = line.find(']').ok_or("INI section not closed")?;
                if !words(&line[end + 1..])?.is_empty() {
                    return Err("Excess data after the INI section".into());
                }
                let (group, suffix) = line[1..end]
                    .split_once(':')
                    .unwrap_or((&line[1..end], "hosts"));
                *kind = match suffix {
                    "hosts" => "hosts",
                    "vars" => "vars",
                    "children" => "children",
                    _ => return Err("Unknown type of INI section".into()),
                };
                *section = group.into();
                inventory.group(group)?;
            } else if *kind == "vars" {
                let (key, value) = line.split_once('=').ok_or("Expected name=value")?;
                let value = if value.trim().starts_with(['\'', '"']) {
                    let tokens = words(value.trim())?;
                    if tokens.len() != 1 {
                        return Err("Invalid INI variable value".into());
                    }
                    tokens[0].clone()
                } else {
                    value.split('#').next().unwrap_or("").trim().to_string()
                };
                let mut map = Map::new();
                map.insert(key.trim().into(), Value::String(value));
                inventory
                    .group(section)?
                    .vars
                    .extend(read_vars(&Value::Object(map))?);
            } else {
                let tokens = words(line)?;
                let Some(first) = tokens.first() else {
                    return Ok(());
                };
                if *kind == "children" {
                    if tokens.len() != 1 {
                        return Err("Expected one child group name".into());
                    }
                    inventory.child(section, first)?;
                } else {
                    let mut map = Map::new();
                    for token in &tokens[1..] {
                        let (key, value) = token
                            .split_once('=')
                            .ok_or("Expected a name=value parameter after the server name")?;
                        map.insert(key.into(), Value::String(value.into()));
                    }
                    inventory.host(section, first, read_vars(&Value::Object(map))?)?;
                }
            }
            Ok(())
        };
        parse_line(&mut inventory, &mut section, &mut kind)
            .map_err(|e| format!("Line {}: {e}", line_no + 1))?;
    }
    Ok(inventory)
}

pub(super) fn parse(input: &str) -> Result<Vec<Imported>, String> {
    let first = input
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with(['#', ';']))
        .unwrap_or("");
    if first.is_empty() {
        return Err("The inventory file does not contain data".into());
    }
    if input.trim_start().starts_with("#!") || first.starts_with("$ANSIBLE_VAULT") {
        return Err("Select static INI, YAML or JSON inventory. Scripts and Ansible Vault are not supported".into());
    }
    let mapping = first.split_once(':').is_some_and(|(key, rest)| {
        !key.trim().contains(char::is_whitespace)
            && (rest.is_empty() || rest.starts_with(char::is_whitespace))
    });
    let structured = first.starts_with(['{', '"', '\''])
        || first.starts_with("---")
        || first.starts_with('%')
        || mapping;
    let inventory = if structured {
        let root = super::data::parse(input)?;
        let groups = root
            .as_object()
            .ok_or("Static inventory with groups and hosts is expected")?;
        if groups.contains_key("plugin") {
            return Err("Inventory plugins are not supported. Select static INI, YAML or JSON with a list of servers".into());
        }
        let mut inventory = Inventory::default();
        for (name, value) in groups.iter().filter(|(name, _)| *name != "_meta") {
            inventory.yaml_group(name, value)?;
        }
        if let Some(meta) = groups.get("_meta") {
            let vars = meta
                .get("hostvars")
                .and_then(Value::as_object)
                .ok_or("_meta.hostvars expected in JSON inventory")?;
            for (host, vars) in vars {
                inventory.host("all", host, read_vars(vars)?)?;
            }
        }
        inventory
    } else {
        ini(input)?
    };
    inventory.finish()
}
