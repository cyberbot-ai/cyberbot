use crate::model::Endpoint;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

mod ansible;
mod data;

const MAX_FILE: usize = 8 * 1024 * 1024;

pub fn read_source(kind: &str, location: &str) -> Result<Vec<Imported>, String> {
    match kind {
        "manual" => parse_manual(location),
        "ansible" => read_ansible(Path::new(location)),
        _ => Err("Unsupported method of adding servers".into()),
    }
}

/// Read only the selected regular file. Never invoke Ansible, a shell, plugins,
/// includes, host_vars/group_vars, or any executable named by its contents.
pub fn read_ansible(path: &Path) -> Result<Vec<Imported>, String> {
    if !path.is_absolute() {
        return Err("Select the absolute path to the inventory file".into());
    }
    // A replaced file must not turn the periodic reader into a blocking FIFO.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "Could not read the inventory file")?;
    let metadata = file
        .metadata()
        .map_err(|_| "Failed to check inventory file")?;
    if !metadata.is_file() || metadata.len() > MAX_FILE as u64 {
        return Err("Inventory must be a normal file of no more than 8 MiB".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Could not read the inventory file")?;
    let input = std::str::from_utf8(&bytes).map_err(|_| "Inventory should be in UTF-8")?;
    parse_ansible(input)
}

pub fn parse_ansible(input: &str) -> Result<Vec<Imported>, String> {
    if input.len() > MAX_FILE {
        return Err("Inventory file more than 8 MiB".into());
    }
    if input.lines().any(|line| line.len() > 64 * 1024) {
        return Err("String inventory more than 64 KiB".into());
    }
    ansible::parse(input.trim_start_matches('\u{feff}'))
}

#[derive(serde::Serialize)]
pub struct SelectedInventory {
    pub name: String,
    pub location: String,
}

pub fn selected_file(path: &Path) -> Result<SelectedInventory, String> {
    if !path.is_absolute() || !path.is_file() {
        return Err("Select an existing inventory file".into());
    }
    let location = path.to_str().ok_or("The file name must be in UTF-8")?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("Failed to identify the file name")?;
    let mut name = String::new();
    for c in filename.trim().chars() {
        if name.len() + c.len_utf8() > 100 {
            break;
        }
        name.push(c);
    }
    if name.is_empty() {
        name = "Ansible inventory".into();
    }
    Ok(SelectedInventory {
        name,
        location: location.into(),
    })
}

pub fn stable_id(source: &str, name: &str) -> String {
    let hash = Sha256::digest(format!("{source}\0{name}").as_bytes());
    format!("{:x}", hash)[..24].to_string()
}
pub fn validate_endpoint(e: &Endpoint) -> Result<(), String> {
    let host_ok = !e.host.is_empty()
        && e.host.len() <= 253
        && !e.host.starts_with('-')
        && e.host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_:%".contains(&b));
    let user_ok = e.user.len() <= 64
        && !e.user.starts_with('-')
        && e.user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if !host_ok || !user_ok || e.port == 0 {
        return Err("Incorrect SSH address, user or port".into());
    }
    if let Some(path) = &e.identity_file {
        if !path.starts_with('/') || path.contains(['\n', '\r', '\0']) {
            return Err("The path to the key must be absolute".into());
        }
    }
    if let Some(path) = &e.known_hosts_file {
        if !path.starts_with('/') || path.contains(['\n', '\r', '\0']) {
            return Err("The known_hosts path should be absolute".into());
        }
    }
    if let Some(jump) = &e.jump_host {
        if jump.is_empty()
            || jump.starts_with('-')
            || !jump
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@._-:[],%".contains(&b))
        {
            return Err("Incorrect ProxyJump".into());
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct Imported {
    // Canonical key stays stable when the displayed address omits the default port.
    pub identity: String,
    pub name: String,
    pub endpoint: Endpoint,
}

pub fn parse_manual(input: &str) -> Result<Vec<Imported>, String> {
    if input.len() > 1024 * 1024 {
        return Err("List more than 1 MB".into());
    }
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for value in input.lines() {
        let value = value.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        let (user, host_port) = match value.split_once('@') {
            Some(("", _)) => return Err("Indicate the user before @".into()),
            Some(parts) => parts,
            None => ("", value),
        };
        let (host, port) = if let Some(bracketed) = host_port.strip_prefix('[') {
            let (host, rest) = bracketed.split_once(']').ok_or("IPv6 bracket not closed")?;
            (
                host,
                if rest.is_empty() {
                    22
                } else {
                    rest.strip_prefix(':')
                        .ok_or("Incorrect port")?
                        .parse::<u16>()
                        .map_err(|_| "Incorrect port")?
                },
            )
        } else if host_port.matches(':').count() == 1 {
            let (host, port) = host_port.split_once(':').unwrap();
            (host, port.parse::<u16>().map_err(|_| "Incorrect port")?)
        } else {
            (host_port, 22)
        };
        let endpoint = Endpoint {
            host: host.into(),
            user: user.into(),
            port,
            identity_file: None,
            jump_host: None,
            known_hosts_file: None,
        };
        validate_endpoint(&endpoint)?;
        let key = format!("{}@{}:{}", user, host, port);
        if seen.insert(key.clone()) {
            result.push(Imported {
                identity: key,
                name: value.into(),
                endpoint,
            });
        }
    }
    if result.is_empty() {
        return Err("The server list is empty".into());
    }
    if result.len() > 5000 {
        return Err("No more than 5,000 servers in a single list".into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected_inventory_uses_the_real_filename_and_absolute_path() {
        let dir = tempfile::tempdir().unwrap();
        for filename in [
            "inventory.yml",
            "hosts",
            "production.ini",
            "servers with spaces.json",
            "--inventory",
        ] {
            let path = dir.path().join(filename);
            std::fs::write(&path, "[web]\nlocalhost ansible_user=ops").unwrap();
            let selected = selected_file(&path).unwrap();
            assert_eq!(selected.name, filename);
            assert_eq!(selected.location, path.to_str().unwrap());
        }
        let filename = format!("{}.yml", "me".repeat(100));
        let path = dir.path().join(filename);
        std::fs::write(&path, "").unwrap();
        let selected = selected_file(&path).unwrap();
        assert!(!selected.name.is_empty() && selected.name.len() <= 100);
        assert_eq!(selected.location, path.to_str().unwrap());
        assert!(selected_file(dir.path()).is_err());
        assert!(selected_file(&dir.path().join("missing.yml")).is_err());
        assert!(selected_file(Path::new("relative.yml")).is_err());
    }
    #[test]
    fn manual_ipv6_dedup_and_ports() {
        let v = parse_manual("# nodes\n root@host \nroot@host:22\nops@[::1]:2222").unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].name, "root@host");
        assert_eq!(v[1].name, "ops@[::1]:2222");
        assert_eq!(v[1].endpoint.port, 2222);
    }
    #[test]
    fn manual_hosts_keep_the_entered_address_without_requiring_a_user() {
        let v = parse_manual("web.example.com\n10.20.1.10\n[::1]:2222\n2001:db8::1\nroot@db:22")
            .unwrap();
        assert_eq!(v.len(), 5);
        for (host, name, port) in [
            (&v[0], "web.example.com", 22),
            (&v[1], "10.20.1.10", 22),
            (&v[2], "[::1]:2222", 2222),
            (&v[3], "2001:db8::1", 22),
        ] {
            assert_eq!(host.name, name);
            assert!(host.endpoint.user.is_empty());
            assert_eq!(host.endpoint.port, port);
        }
        assert_eq!(v[2].endpoint.host, "::1");
        assert_eq!(v[4].name, "root@db:22");
        assert_eq!(v[4].endpoint.user, "root");
    }
    #[test]
    fn reject_injection() {
        for s in [
            "root@-oProxyCommand=x",
            "root@foo;id",
            "a b@host",
            "root@host:0",
            "root@$(id)",
            "@host",
            "-oProxyCommand=x",
            "host;id",
            "host:0",
            "$(id)",
        ] {
            assert!(parse_manual(s).is_err(), "{s}");
        }
    }
    #[test]
    fn inventory_export_is_flattened() {
        let v=parse_ansible(r#"{"_meta":{"hostvars":{"web":{"ansible_user":"ops"}}},"prod":{"children":["webs"]},"webs":{"hosts":["web"]}}"#).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "web");
        assert_eq!(v[0].endpoint.user, "ops");
    }
    #[test]
    fn reject_unsafe_ansible_args() {
        assert!(parse_ansible(r#"{"_meta":{"hostvars":{"web":{"ansible_user":"ops","ansible_ssh_common_args":"-oProxyCommand=bad"}}}}"#).is_err());
    }
}
