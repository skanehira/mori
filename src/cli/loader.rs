use crate::error::MoriError;
use crate::policy::NetworkPolicy;

use super::args::Args;
use super::config::ConfigFile;

/// Load and merge policies from command line arguments and config file
pub struct PolicyLoader;

impl PolicyLoader {
    /// Load complete policy from CLI arguments
    pub fn load(args: &Args) -> Result<NetworkPolicy, MoriError> {
        let mut policy = NetworkPolicy::new();

        // Load configuration file if specified
        if let Some(config_path) = args.config.as_ref() {
            let config = ConfigFile::load(config_path)?;
            let config_policy = config.to_policy()?;
            policy.merge(config_policy);
        }

        // Load policies from CLI arguments
        let cli_policy = NetworkPolicy::from_entries(&args.allow_network)?;
        policy.merge(cli_policy);

        Ok(policy)
    }
}
