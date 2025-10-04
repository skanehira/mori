use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{error::MoriError, policy::NetworkPolicy};

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct ConfigFile {
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub file: FileConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NetworkConfig {
    /// Allowed network destinations (bool for allow-all/deny-all, or Vec<String> for specific destinations)
    #[serde(default)]
    pub allow: AllowConfig,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            allow: AllowConfig::Boolean(false),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AllowConfig {
    Boolean(bool),
    Entries(Vec<String>),
}

impl Default for AllowConfig {
    fn default() -> Self {
        AllowConfig::Boolean(false)
    }
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct FileConfig {
    /// Deny file read/write access to the specified paths
    #[serde(default)]
    pub deny: Vec<PathBuf>,
    /// Deny file read access to the specified paths
    #[serde(default)]
    pub deny_read: Vec<PathBuf>,
    /// Deny file write access to the specified paths
    #[serde(default)]
    pub deny_write: Vec<PathBuf>,
}

impl ConfigFile {
    /// Load configuration file
    pub fn load(path: &Path) -> Result<Self, MoriError> {
        let content = fs::read_to_string(path)?;
        toml::from_str(&content).map_err(|source| MoriError::ConfigParse {
            path: PathBuf::from(path),
            source,
        })
    }

    /// Build network policy from configuration file
    pub fn to_policy(&self) -> Result<NetworkPolicy, MoriError> {
        match &self.network.allow {
            AllowConfig::Boolean(allow_all) => Ok(NetworkPolicy::from_allow_all(*allow_all)),
            AllowConfig::Entries(entries) => NetworkPolicy::from_entries(entries),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn load_and_convert_policy() {
        use crate::policy::AllowPolicy;

        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            "[network]\nallow = [\n \"192.0.2.1\",\n \"example.com\"\n]\n"
        )
        .unwrap();

        let config = ConfigFile::load(tmp.path()).unwrap();
        let policy = config.to_policy().unwrap();
        match policy.policy {
            AllowPolicy::Entries {
                allowed_ipv4,
                allowed_cidr,
                allowed_domains,
            } => {
                assert_eq!(allowed_ipv4.len(), 1);
                assert_eq!(allowed_cidr.len(), 0);
                assert_eq!(allowed_domains.len(), 1);
            }
            _ => panic!("Expected Entries variant"),
        }
    }

    #[test]
    fn load_boolean_allow_true() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "[network]\nallow = true\n").unwrap();

        let config = ConfigFile::load(tmp.path()).unwrap();
        let policy = config.to_policy().unwrap();
        assert!(policy.is_allow_all());
    }

    #[test]
    fn load_boolean_allow_false() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "[network]\nallow = false\n").unwrap();

        let config = ConfigFile::load(tmp.path()).unwrap();
        let policy = config.to_policy().unwrap();
        assert!(!policy.is_allow_all());
    }

    #[test]
    fn load_file_config_deny_paths() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"
[file]
deny = ["/tmp/secret", "/etc/passwd"]
deny_read = ["/home/user/.ssh"]
deny_write = ["/var/log"]
"#
        )
        .unwrap();

        let config = ConfigFile::load(tmp.path()).unwrap();
        assert_eq!(config.file.deny.len(), 2);
        assert_eq!(config.file.deny_read.len(), 1);
        assert_eq!(config.file.deny_write.len(), 1);
    }

    #[test]
    fn load_empty_file_config() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "[network]\nallow = true\n").unwrap();

        let config = ConfigFile::load(tmp.path()).unwrap();
        assert_eq!(config.file.deny.len(), 0);
        assert_eq!(config.file.deny_read.len(), 0);
        assert_eq!(config.file.deny_write.len(), 0);
    }
}
