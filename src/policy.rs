use std::net::Ipv4Addr;

use crate::{error::MoriError, net::parse_allow_network};

/// Unified representation of network access policy
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NetworkPolicy {
    /// Allowed IPv4 addresses (directly specified)
    pub allowed_ipv4: Vec<Ipv4Addr>,
    /// Allowed domain names
    pub allowed_domains: Vec<String>,
}

impl NetworkPolicy {
    /// Create an empty policy
    pub fn new() -> Self {
        Self::default()
    }

    /// Build policy from input entries
    pub fn from_entries(entries: &[String]) -> Result<Self, MoriError> {
        let network_rules = parse_allow_network(entries)?;
        Ok(Self {
            allowed_ipv4: network_rules.direct_v4,
            allowed_domains: network_rules.domains,
        })
    }

    /// Add IPv4 address (duplicates are automatically eliminated)
    pub fn add_ipv4(&mut self, addr: Ipv4Addr) {
        if !self.allowed_ipv4.contains(&addr) {
            self.allowed_ipv4.push(addr);
        }
    }

    /// Add domain (duplicates are automatically eliminated)
    pub fn add_domain(&mut self, domain: String) {
        if !self.allowed_domains.contains(&domain) {
            self.allowed_domains.push(domain);
        }
    }

    /// Merge another policy
    pub fn merge(&mut self, other: Self) {
        for ip in other.allowed_ipv4 {
            self.add_ipv4(ip);
        }
        for domain in other.allowed_domains {
            self.add_domain(domain);
        }
    }

    /// Check if no allowed targets exist
    pub fn is_empty(&self) -> bool {
        self.allowed_ipv4.is_empty() && self.allowed_domains.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_entries_dedupes() {
        let entries = vec![
            "192.0.2.1".to_string(),
            "example.com".to_string(),
            "192.0.2.1".to_string(),
            "example.com".to_string(),
        ];
        let policy = NetworkPolicy::from_entries(&entries).unwrap();
        assert_eq!(policy.allowed_ipv4.len(), 1);
        assert_eq!(policy.allowed_domains.len(), 1);
    }

    #[test]
    fn merge_combines_unique_values() {
        let mut base = NetworkPolicy {
            allowed_ipv4: vec!["192.0.2.1".parse().unwrap()],
            allowed_domains: vec!["example.com".to_string()],
        };
        let other = NetworkPolicy {
            allowed_ipv4: vec!["198.51.100.1".parse().unwrap()],
            allowed_domains: vec!["test.example".to_string()],
        };
        base.merge(other);
        assert_eq!(base.allowed_ipv4.len(), 2);
        assert_eq!(base.allowed_domains.len(), 2);
    }

    #[test]
    fn merge_avoids_duplicates() {
        let mut base = NetworkPolicy {
            allowed_ipv4: vec!["192.0.2.1".parse().unwrap()],
            allowed_domains: vec!["example.com".to_string()],
        };
        let other = NetworkPolicy {
            allowed_ipv4: vec!["192.0.2.1".parse().unwrap()],
            allowed_domains: vec!["example.com".to_string()],
        };
        base.merge(other);
        assert_eq!(base.allowed_ipv4.len(), 1);
        assert_eq!(base.allowed_domains.len(), 1);
    }
}
