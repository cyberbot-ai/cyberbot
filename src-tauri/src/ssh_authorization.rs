//! Frozen OpenSSH authorization context. No connection or key material is returned.
use crate::{inventory::validate_endpoint, model::Endpoint, process, ssh};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

pub(crate) const DYNAMIC_MATCH: &str =
    "Custom actions are not available with dynamic Match exec in SSH config";

pub(crate) fn executes_match(stderr: &str) -> bool {
    stderr
        .lines()
        .any(|line| line.contains("Executing command:"))
}

#[derive(Default)]
pub(crate) struct ConfigPaths {
    pub files: BTreeSet<PathBuf>,
    pub include_dirs: BTreeSet<PathBuf>,
}

fn expand_home(path: &str) -> Option<PathBuf> {
    if let Some(suffix) = path.strip_prefix("~/") {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(suffix))
    } else {
        Some(PathBuf::from(path))
    }
}

pub(crate) fn config_paths(output: &process::Output, system_config: bool) -> ConfigPaths {
    let mut paths = ConfigPaths::default();
    if let Some(home) = std::env::var_os("HOME").filter(|_| system_config) {
        for file in [".ssh/config", ".ssh/known_hosts", ".ssh/known_hosts2"] {
            paths.files.insert(PathBuf::from(&home).join(file));
        }
    }
    for line in output.stderr.lines() {
        if let Some(path) = line.strip_prefix("debug1: Reading configuration data ") {
            paths.files.insert(PathBuf::from(path.trim()));
        }
        // With no matches, OpenSSH reports the pattern instead of a file it read.
        if let Some((_, pattern)) = line
            .strip_prefix("debug1: ")
            .and_then(|line| line.strip_suffix(" matched no files"))
            .and_then(|line| line.split_once(": include "))
        {
            let prefix = pattern.split(['*', '?', '[']).next().unwrap_or_default();
            let directory = if prefix.ends_with('/') {
                prefix
            } else {
                prefix.rsplit_once('/').map_or("", |(dir, _)| dir)
            };
            if let Some(path) = expand_home(directory).filter(|path| path.is_absolute()) {
                paths.include_dirs.insert(path);
            }
        }
    }
    for (name, values) in String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_once(' '))
    {
        if [
            "identityfile",
            "certificatefile",
            "userknownhostsfile",
            "globalknownhostsfile",
            "revokedhostkeys",
        ]
        .contains(&name)
        {
            for value in std::iter::once(values).chain(values.split_whitespace()) {
                if let Some(path) = expand_home(value.trim_matches('"'))
                    .filter(|path| path.is_absolute() && !path.starts_with("/dev"))
                {
                    paths.files.insert(path);
                }
            }
        }
    }
    paths
}

pub(crate) fn parents(files: &BTreeSet<PathBuf>) -> BTreeSet<PathBuf> {
    files
        .iter()
        .filter_map(|file| file.parent())
        .map(Path::to_owned)
        .collect()
}

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
fn inspect(
    output: &process::Output,
) -> Result<(String, BTreeMap<String, String>, ConfigPaths), String> {
    if !output.success {
        return Err("Could not capture OpenSSH settings".into());
    }
    if executes_match(&output.stderr) {
        return Err(DYNAMIC_MATCH.into());
    }
    let options = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|l| l.split_once(' ').map(|(k, v)| (k.to_owned(), v.to_owned())))
        .collect::<BTreeMap<_, _>>();
    if options.get("proxycommand").is_some_and(|v| v != "none") {
        return Err("ProxyCommand is not allowed for custom actions; use ProxyJump".into());
    }
    let paths = config_paths(output, true);
    if paths.files.union(&parents(&paths.files)).count() > 512 {
        return Err("Too many SSH settings files".into());
    }
    Ok((hash(&output.stdout), options, paths))
}
pub async fn capture(endpoint: &Endpoint) -> Result<Stamp, String> {
    validate_endpoint(endpoint)?;
    let mut args = ssh::options(endpoint)?;
    args.extend(["-G".into(), "-v".into(), "--".into(), endpoint.host.clone()]);
    let output = process::bounded("/usr/bin/ssh", &args, None, 10, 65536).await?;
    capture_from_output(&output).await.map(|(stamp, _)| stamp)
}

pub(crate) async fn capture_from_output(
    output: &process::Output,
) -> Result<(Stamp, ConfigPaths), String> {
    let (primary_hash, options, mut config_paths) = inspect(output)?;
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
            return Err("Could not capture dynamic or nonstandard ProxyJump settings".into());
        }
        let tag = format!("jump:{jump}");
        if hashes.contains_key(&tag) {
            continue;
        }
        if hashes.len() > 8 {
            return Err("The ProxyJump chain is too long".into());
        }
        // OpenSSH parses the URI itself, including users, IPv6 and optional port.
        let args = [
            "-G".into(),
            "-v".into(),
            "-oBatchMode=yes".into(),
            "-oPermitLocalCommand=no".into(),
            "--".into(),
            format!("ssh://{jump}"),
        ];
        let output = process::bounded("/usr/bin/ssh", &args, None, 10, 65536).await?;
        let (digest, options, paths) = inspect(&output)?;
        hashes.insert(tag, digest);
        config_paths.files.extend(paths.files);
        config_paths.include_dirs.extend(paths.include_dirs);
        if let Some(jumps) = options.get("proxyjump").filter(|v| v.as_str() != "none") {
            pending.extend(jumps.split(',').map(str::to_owned));
        }
    }
    // Keep the same file and parent set for the serialized approval stamp.
    let dirs = parents(&config_paths.files);
    let paths = config_paths.files.union(&dirs).cloned().collect::<Vec<_>>();
    if paths.len() > 1024 {
        return Err("Too much SSH context".into());
    }
    let stamp = Stamp {
        files_hash: hash(&crate::ssh_pool::fingerprint(&paths)),
        paths,
        primary_hash,
        config_hashes: hashes,
    };
    Ok((stamp, config_paths))
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
        std::fs::write(dir.path().join("unrelated"), "temporary").unwrap();
        assert!(!stamp.unchanged(), "approval stamps still pin directories");
        let stamp = Stamp {
            files_hash: hash(&crate::ssh_pool::fingerprint(&stamp.paths)),
            ..stamp
        };
        std::fs::write(file, "changed").unwrap();
        assert!(!stamp.unchanged());
    }
}
