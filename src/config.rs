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
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct NetworkConfig {
    /// Allowed network destinations (CIDR, IP, domain)
    #[serde(default)]
    pub allow: Vec<String>,
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
        NetworkPolicy::from_entries(&self.network.allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn load_and_convert_policy() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            "[network]\nallow = [\n \"192.0.2.1\",\n \"example.com\"\n]\n"
        )
        .unwrap();

        let config = ConfigFile::load(tmp.path()).unwrap();
        let policy = config.to_policy().unwrap();
        assert_eq!(policy.allowed_ipv4.len(), 1);
        assert_eq!(policy.allowed_domains.len(), 1);
    }
}
