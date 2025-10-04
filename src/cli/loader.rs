use crate::error::MoriError;
use crate::policy::{FilePolicy, NetworkPolicy, Policy};

use super::args::Args;
use super::config::ConfigFile;

/// Load and merge policies from command line arguments and config file
pub struct PolicyLoader;

impl PolicyLoader {
    /// Load complete policy from CLI arguments
    pub fn load(args: &Args) -> Result<Policy, MoriError> {
        let mut network_policy = NetworkPolicy::from_allow_all(args.allow_network_all);

        let mut file_policy = FilePolicy::new();

        // Load configuration file if specified
        if let Some(config_path) = args.config.as_ref() {
            let config = ConfigFile::load(config_path)?;
            let config_network_policy = config.to_policy()?;
            network_policy.merge(config_network_policy);
            // TODO: Load file policy from config file
        }

        // Load policies from CLI arguments
        // Network policy (Linux only - macOS doesn't support --allow-network)
        #[cfg(not(target_os = "macos"))]
        if !args.allow_network_all {
            let cli_network_policy = NetworkPolicy::from_entries(&args.allow_network)?;
            network_policy.merge(cli_network_policy);
        }

        // File policy (deny-list mode) - available on all platforms
        for path in &args.deny_file {
            file_policy.deny_read_write(path);
        }
        for path in &args.deny_file_read {
            file_policy.deny_read(path);
        }
        for path in &args.deny_file_write {
            file_policy.deny_write(path);
        }

        Ok(Policy {
            network: network_policy,
            file: file_policy,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_creates_allow_all_policy() {
        let args = Args {
            config: None,
            #[cfg(not(target_os = "macos"))]
            allow_network: vec![],
            allow_network_all: true,
            deny_file: vec![],
            deny_file_read: vec![],
            deny_file_write: vec![],
            command: vec!["echo".to_string(), "test".to_string()],
        };

        let policy = PolicyLoader::load(&args).unwrap();
        assert!(policy.network.is_allow_all());
    }

    #[test]
    fn load_creates_deny_all_policy() {
        let args = Args {
            config: None,
            #[cfg(not(target_os = "macos"))]
            allow_network: vec![],
            allow_network_all: false,
            deny_file: vec![],
            deny_file_read: vec![],
            deny_file_write: vec![],
            command: vec!["echo".to_string(), "test".to_string()],
        };

        let policy = PolicyLoader::load(&args).unwrap();
        assert!(!policy.network.is_allow_all());
    }
}
