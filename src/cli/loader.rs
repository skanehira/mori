use crate::error::MoriError;
use crate::policy::NetworkPolicy;

use super::args::Args;
use super::config::ConfigFile;

/// Load and merge policies from command line arguments and config file
pub struct PolicyLoader;

impl PolicyLoader {
    /// Load complete policy from CLI arguments
    pub fn load(args: &Args) -> Result<NetworkPolicy, MoriError> {
        let mut policy = NetworkPolicy::from_allow_all(args.allow_network_all);

        // Load configuration file if specified
        if let Some(config_path) = args.config.as_ref() {
            let config = ConfigFile::load(config_path)?;
            let config_policy = config.to_policy()?;
            policy.merge(config_policy);
        }

        // Load policies from CLI arguments (only if not allow-all and on Linux)
        #[cfg(not(target_os = "macos"))]
        if !args.allow_network_all {
            let cli_policy = NetworkPolicy::from_entries(&args.allow_network)?;
            policy.merge(cli_policy);
        }

        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_creates_allow_all_policy() {
        #[cfg(not(target_os = "macos"))]
        let args = Args {
            config: None,
            allow_network: vec![],
            allow_network_all: true,
            command: vec!["echo".to_string(), "test".to_string()],
        };

        #[cfg(target_os = "macos")]
        let args = Args {
            config: None,
            allow_network_all: true,
            command: vec!["echo".to_string(), "test".to_string()],
        };

        let policy = PolicyLoader::load(&args).unwrap();
        assert!(policy.is_allow_all());
    }

    #[test]
    fn load_creates_deny_all_policy() {
        #[cfg(not(target_os = "macos"))]
        let args = Args {
            config: None,
            allow_network: vec![],
            allow_network_all: false,
            command: vec!["echo".to_string(), "test".to_string()],
        };

        #[cfg(target_os = "macos")]
        let args = Args {
            config: None,
            allow_network_all: false,
            command: vec!["echo".to_string(), "test".to_string()],
        };

        let policy = PolicyLoader::load(&args).unwrap();
        assert!(!policy.is_allow_all());
    }
}
