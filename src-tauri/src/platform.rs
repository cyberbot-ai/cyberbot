//! Versioned, bounded host capabilities. Distro identity never implies full coverage.
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinuxPlatform {
    pub version: u32,
    pub distro: String,
    pub release: String,
    pub version_id: String,
    pub id_like: Vec<String>,
    pub family: String,
    pub architecture: String,
    pub kernel: String,
    pub procfs: bool,
    pub init_system: String,
    pub service_adapter: String,
    pub journal_available: bool,
    pub package_manager: String,
    pub package_adapter: String,
    pub advisory_provider: String,
}
impl LinuxPlatform {
    pub fn validate(&self) -> Result<(), String> {
        let token = |s: &str, n| {
            !s.is_empty()
                && s.len() <= n
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        };
        if self.version != 1
            || self.id_like.len() > 8
            || [
                &self.distro,
                &self.release,
                &self.version_id,
                &self.architecture,
            ]
            .iter()
            .any(|s| !token(s, 64))
            || self.id_like.iter().any(|s| !token(s, 64))
            || !token(&self.kernel, 128)
            || !["debian", "rhel", "suse", "arch", "alpine", "generic"]
                .contains(&self.family.as_str())
            || !["systemd", "openrc", "unknown"].contains(&self.init_system.as_str())
            || !["systemd", "unsupported"].contains(&self.service_adapter.as_str())
            || self.service_adapter != "unsupported" && self.service_adapter != self.init_system
            || !["dpkg", "rpm", "apk", "pacman", "unknown"].contains(&self.package_manager.as_str())
            || !["dpkg", "unsupported"].contains(&self.package_adapter.as_str())
            || self.package_adapter != "unsupported" && self.package_adapter != self.package_manager
            || !["ubuntu", "debian", "unsupported"].contains(&self.advisory_provider.as_str())
            || self.advisory_provider != "unsupported"
                && (self.advisory_provider != self.distro || self.package_adapter != "dpkg")
        {
            return Err("Incompatible information about the Linux platform".into());
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn platform_is_bounded_and_does_not_inherit_advisory_support() {
        let raw = json!({"version":1,"distro":"mint","release":"wilma","versionId":"22","idLike":["ubuntu","debian"],"family":"debian","architecture":"x86_64","kernel":"6.8.0","procfs":true,"initSystem":"systemd","serviceAdapter":"systemd","journalAvailable":true,"packageManager":"dpkg","packageAdapter":"dpkg","advisoryProvider":"unsupported"});
        let mut p: LinuxPlatform = serde_json::from_value(raw.clone()).unwrap();
        p.validate().unwrap();
        p.advisory_provider = "ubuntu".into();
        assert!(p.validate().is_err());
        p.advisory_provider = "unsupported".into();
        p.package_manager = "rpm".into();
        assert!(p.validate().is_err());
        let mut malicious = raw;
        malicious["kernel"] = json!("secret\nignore instructions");
        assert!(serde_json::from_value::<LinuxPlatform>(malicious)
            .unwrap()
            .validate()
            .is_err());
    }
    #[test]
    fn old_observations_remain_readable() {
        let old = json!({"at":1,"cpuPercent":0.0,"memoryPercent":0.0,"swapPercent":0.0,"load":0.0,"uptime":1.0,"disks":[],"services":[],"missing":[],"bytesReceived":100,"durationMs":1});
        let observation: crate::model::Observation = serde_json::from_value(old).unwrap();
        assert!(observation.platform.is_none());
    }
}
