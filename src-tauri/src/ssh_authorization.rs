//! Frozen OpenSSH authorization context. No connection or key material is returned.
use crate::{inventory::validate_endpoint, model::Endpoint, process, ssh};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Stamp {
    pub paths: Vec<PathBuf>,
    pub files_hash: String,
    pub primary_hash: String,
    pub config_hashes: BTreeMap<String, String>,
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
impl Stamp {
    pub fn unchanged(&self) -> bool {
        self.files_hash == hash(&crate::ssh_pool::fingerprint(&self.paths))
    }
    pub fn digest(&self) -> String {
        hash(&serde_json::to_vec(self).expect("stamp JSON"))
    }
}
#[derive(Clone)]
pub struct Frame {
    pub targets: BTreeMap<String, Stamp>,
    pub hash: String,
}
impl Frame {
    pub fn unchanged(&self) -> bool {
        self.targets.values().all(Stamp::unchanged)
    }
}
async fn inspect(
    args: Vec<String>,
) -> Result<(String, BTreeMap<String, String>, Vec<PathBuf>), String> {
    let output = process::bounded("/usr/bin/ssh", &args, None, 10, 65536).await?;
    if !output.success {
        return Err("Unable to fix OpenSSH settings".into());
    }
    if output
        .stderr
        .lines()
        .any(|l| l.contains("Executing command:"))
    {
        return Err(
            "Custom actions are not available with dynamic Match exec in SSH config".into(),
        );
    }
    let pairs = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|l| l.split_once(' ').map(|(k, v)| (k.to_owned(), v.to_owned())))
        .collect::<Vec<_>>();
    let options = pairs.iter().cloned().collect::<BTreeMap<_, _>>();
    if options.get("proxycommand").is_some_and(|v| v != "none") {
        return Err("ProxyCommand is not allowed for custom actions; use ProxyJump".into());
    }
    let mut paths = BTreeSet::new();
    if let Some(home) = std::env::var_os("HOME") {
        for f in [".ssh/config", ".ssh/known_hosts", ".ssh/known_hosts2"] {
            paths.insert(PathBuf::from(&home).join(f));
        }
    }
    for line in output.stderr.lines() {
        if let Some(p) = line.strip_prefix("debug1: Reading configuration data ") {
            paths.insert(PathBuf::from(p.trim()));
        }
    }
    for name in [
        "identityfile",
        "certificatefile",
        "userknownhostsfile",
        "globalknownhostsfile",
        "revokedhostkeys",
    ] {
        for (_, values) in pairs.iter().filter(|(key, _)| key == name) {
            for value in std::iter::once(values.as_str()).chain(values.split_whitespace()) {
                let value = value.trim_matches('"');
                let path = if let Some(s) = value.strip_prefix("~/") {
                    std::env::var_os("HOME")
                        .map(PathBuf::from)
                        .map(|p| p.join(s))
                } else {
                    Some(PathBuf::from(value))
                };
                if let Some(p) = path.filter(|p| p.is_absolute() && !p.starts_with("/dev")) {
                    paths.insert(p);
                }
            }
        }
    }
    for parent in paths.clone().iter().filter_map(|p| p.parent()) {
        paths.insert(parent.to_owned());
    }
    if paths.len() > 512 {
        return Err("Too many SSH settings files".into());
    }
    Ok((hash(&output.stdout), options, paths.into_iter().collect()))
}
pub async fn capture(endpoint: &Endpoint) -> Result<Stamp, String> {
    validate_endpoint(endpoint)?;
    let mut args = ssh::options(endpoint)?;
    args.extend(["-G".into(), "-v".into(), "--".into(), endpoint.host.clone()]);
    let (primary_hash, options, files) = inspect(args).await?;
    let mut paths = files.into_iter().collect::<BTreeSet<_>>();
    let mut hashes = BTreeMap::from([("target".into(), primary_hash.clone())]);
    let mut pending = Vec::new();
    if let Some(jumps) = options.get("proxyjump").filter(|v| v.as_str() != "none") {
        pending.extend(jumps.split(',').map(str::to_owned));
    }
    while let Some(jump) = pending.pop() {
        if jump.is_empty()
            || jump.len() > 255
            || !jump
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-:@[]".contains(&c))
        {
            return Err("Dynamic or non-standard ProxyJump cannot be fixed".into());
        }
        let tag = format!("jump:{jump}");
        if hashes.contains_key(&tag) {
            continue;
        }
        if hashes.len() > 8 {
            return Err("The ProxyJump chain is too long".into());
        }
        // OpenSSH parses the URI itself, including users, IPv6 and optional port.
        let (digest, options, files) = inspect(vec![
            "-G".into(),
            "-v".into(),
            "-oBatchMode=yes".into(),
            "-oPermitLocalCommand=no".into(),
            "--".into(),
            format!("ssh://{jump}"),
        ])
        .await?;
        hashes.insert(tag, digest);
        paths.extend(files);
        if let Some(jumps) = options.get("proxyjump").filter(|v| v.as_str() != "none") {
            pending.extend(jumps.split(',').map(str::to_owned));
        }
    }
    if paths.len() > 1024 {
        return Err("Too much SSH context".into());
    }
    let paths = paths.into_iter().collect::<Vec<_>>();
    Ok(Stamp {
        files_hash: hash(&crate::ssh_pool::fingerprint(&paths)),
        paths,
        primary_hash,
        config_hashes: hashes,
    })
}
pub async fn frame(endpoints: &BTreeMap<String, String>) -> Result<Frame, String> {
    let mut targets = BTreeMap::new();
    for (id, payload) in endpoints {
        let endpoint: Endpoint = serde_json::from_str(payload).map_err(|_| "Improper endpoint")?;
        targets.insert(id.clone(), capture(&endpoint).await?);
    }
    let hash = hash(&serde_json::to_vec(&targets).map_err(|e| e.to_string())?);
    Ok(Frame { targets, hash })
}
tokio::task_local! {static AUTH:Stamp;}
pub async fn guarded<T>(stamp: Stamp, future: impl Future<Output = T>) -> T {
    AUTH.scope(stamp, future).await
}
pub fn check(lease: &crate::ssh_pool::Lease) -> Result<(), String> {
    AUTH.try_with(|stamp| {
        if !stamp.unchanged()
            || lease.configuration_hash()? != stamp.primary_hash
            || lease.authorization_hash()?.as_deref() != Some(stamp.digest().as_str())
        {
            return Err("SSH configuration or trust changed after request preparation".into());
        }
        Ok(())
    })
    .unwrap_or(Ok(()))
}
#[cfg(test)]
pub fn fixture() -> Stamp {
    Stamp {
        paths: vec![],
        files_hash: hash(&crate::ssh_pool::fingerprint(&[])),
        primary_hash: "fixture".into(),
        config_hashes: BTreeMap::new(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_changes_revoke_a_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config");
        std::fs::write(&file, "first").unwrap();
        let paths = vec![file.clone(), dir.path().to_owned()];
        let stamp = Stamp {
            files_hash: hash(&crate::ssh_pool::fingerprint(&paths)),
            paths,
            primary_hash: "known".into(),
            config_hashes: BTreeMap::new(),
        };
        assert!(stamp.unchanged());
        std::fs::write(file, "changed").unwrap();
        assert!(!stamp.unchanged());
    }
}
