use std::net::Ipv4Addr;

use crate::{error::MoriError, net::parse_allow_network};

/// Network access policy variants
#[derive(Debug, Clone, PartialEq)]
pub enum AllowPolicy {
    /// Allow all network connections
    All,
    /// Allow specific entries (IPs and domains)
    Entries {
        allowed_ipv4: Vec<Ipv4Addr>,
        allowed_domains: Vec<String>,
    },
}

/// Unified representation of network access policy
#[derive(Debug, Clone, PartialEq)]
pub struct NetworkPolicy {
    pub policy: AllowPolicy,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            policy: AllowPolicy::Entries {
                allowed_ipv4: Vec::new(),
                allowed_domains: Vec::new(),
            },
        }
    }
}

impl NetworkPolicy {
    /// Create an empty policy
    pub fn new() -> Self {
        Self::default()
    }

    /// Build policy for allow-all or deny-all
    pub fn from_allow_all(allow_all: bool) -> Self {
        if allow_all {
            Self {
                policy: AllowPolicy::All,
            }
        } else {
            Self::default()
        }
    }

    /// Build policy from input entries
    pub fn from_entries(entries: &[String]) -> Result<Self, MoriError> {
        let network_rules = parse_allow_network(entries)?;
        Ok(Self {
            policy: AllowPolicy::Entries {
                allowed_ipv4: network_rules.direct_v4,
                allowed_domains: network_rules.domains,
            },
        })
    }

    /// Check if all network is allowed
    pub fn is_allow_all(&self) -> bool {
        matches!(self.policy, AllowPolicy::All)
    }

    /// Merge another policy
    pub fn merge(&mut self, other: Self) {
        match (&mut self.policy, other.policy) {
            // If either is allow-all, result is allow-all
            (_, AllowPolicy::All) => {
                self.policy = AllowPolicy::All;
            }
            (AllowPolicy::All, _) => {
                // Keep allow-all
            }
            // Both are entries, merge them
            (
                AllowPolicy::Entries {
                    allowed_ipv4: base_ips,
                    allowed_domains: base_domains,
                },
                AllowPolicy::Entries {
                    allowed_ipv4: other_ips,
                    allowed_domains: other_domains,
                },
            ) => {
                for ip in other_ips {
                    if !base_ips.contains(&ip) {
                        base_ips.push(ip);
                    }
                }
                for domain in other_domains {
                    if !base_domains.contains(&domain) {
                        base_domains.push(domain);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_allow_all_true_creates_all_policy() {
        let policy = NetworkPolicy::from_allow_all(true);
        assert!(policy.is_allow_all());
        assert!(matches!(policy.policy, AllowPolicy::All));
    }

    #[test]
    fn from_allow_all_false_creates_empty_entries() {
        let policy = NetworkPolicy::from_allow_all(false);
        assert!(!policy.is_allow_all());
        match policy.policy {
            AllowPolicy::Entries {
                allowed_ipv4,
                allowed_domains,
            } => {
                assert!(allowed_ipv4.is_empty());
                assert!(allowed_domains.is_empty());
            }
            _ => panic!("Expected Entries variant"),
        }
    }

    #[test]
    fn from_entries_creates_entries_policy() {
        let entries = vec!["192.0.2.1".to_string(), "example.com".to_string()];
        let policy = NetworkPolicy::from_entries(&entries).unwrap();
        assert!(!policy.is_allow_all());
        match policy.policy {
            AllowPolicy::Entries {
                allowed_ipv4,
                allowed_domains,
            } => {
                assert_eq!(allowed_ipv4.len(), 1);
                assert_eq!(allowed_domains.len(), 1);
            }
            _ => panic!("Expected Entries variant"),
        }
    }

    #[test]
    fn merge_entries_with_all_becomes_all() {
        let mut base = NetworkPolicy::from_entries(&["192.0.2.1".to_string()]).unwrap();
        let other = NetworkPolicy::from_allow_all(true);
        base.merge(other);
        assert!(base.is_allow_all());
    }

    #[test]
    fn merge_all_with_entries_stays_all() {
        let mut base = NetworkPolicy::from_allow_all(true);
        let other = NetworkPolicy::from_entries(&["192.0.2.1".to_string()]).unwrap();
        base.merge(other);
        assert!(base.is_allow_all());
    }

    #[test]
    fn merge_entries_with_entries_combines() {
        let mut base = NetworkPolicy::from_entries(&["192.0.2.1".to_string()]).unwrap();
        let other = NetworkPolicy::from_entries(&["example.com".to_string()]).unwrap();
        base.merge(other);
        match base.policy {
            AllowPolicy::Entries {
                allowed_ipv4,
                allowed_domains,
            } => {
                assert_eq!(allowed_ipv4.len(), 1);
                assert_eq!(allowed_domains.len(), 1);
            }
            _ => panic!("Expected Entries variant"),
        }
    }

    #[test]
    fn merge_avoids_duplicates() {
        let mut base =
            NetworkPolicy::from_entries(&["192.0.2.1".to_string(), "example.com".to_string()])
                .unwrap();
        let other =
            NetworkPolicy::from_entries(&["192.0.2.1".to_string(), "example.com".to_string()])
                .unwrap();
        base.merge(other);
        match base.policy {
            AllowPolicy::Entries {
                allowed_ipv4,
                allowed_domains,
            } => {
                assert_eq!(allowed_ipv4.len(), 1);
                assert_eq!(allowed_domains.len(), 1);
            }
            _ => panic!("Expected Entries variant"),
        }
    }
}
