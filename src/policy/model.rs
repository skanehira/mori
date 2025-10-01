// Common model definitions shared across all policy types
use super::file::FilePolicy;
use super::net::NetworkPolicy;
use super::process::ProcessPolicy;

/// Unified policy model that combines all policy types
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Policy {
    pub network: NetworkPolicy,
    pub file: FilePolicy,
    pub process: ProcessPolicy,
}

impl Policy {
    /// Create a new empty policy
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a policy with only network rules
    pub fn with_network(network: NetworkPolicy) -> Self {
        Self {
            network,
            ..Default::default()
        }
    }
}
