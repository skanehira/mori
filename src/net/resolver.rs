use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
};

use async_trait::async_trait;
use hickory_resolver::{Resolver, config::ResolverConfig, system_conf};

#[cfg(test)]
use mockall::automock;

use super::cache::Entry;
use crate::error::MoriError;

#[derive(Default, Debug, PartialEq)]
pub struct DomainRecords {
    pub domain: String,
    pub records: Vec<Entry>,
}

#[derive(Default, Debug, PartialEq)]
pub struct ResolvedAddresses {
    /// Resolved IPv4 addresses per domain with TTL information
    pub domains: Vec<DomainRecords>,
    /// IPv4 addresses of DNS servers used for resolution
    pub dns_v4: Vec<Ipv4Addr>,
}

/// DNS resolver abstraction for testing
#[cfg_attr(test, automock)]
#[async_trait]
pub trait DnsResolver: Send + Sync + 'static {
    async fn resolve_domains(&self, domains: &[String]) -> Result<ResolvedAddresses, MoriError>;
}

/// Production DNS resolver using the system resolver
pub struct SystemDnsResolver;

#[async_trait]
impl DnsResolver for SystemDnsResolver {
    /// Resolve domain names to IPv4 addresses and collect DNS server IPs
    ///
    /// This function performs DNS resolution for the provided domain names and also
    /// extracts the IPv4 addresses of the DNS servers themselves (which need to be
    /// allowed for DNS queries to work).
    ///
    /// # Arguments
    /// * `domains` - List of domain names to resolve
    ///
    /// # Returns
    /// * `Ok(ResolvedAddresses)` - Contains resolved IPv4 addresses from domains and DNS server IPs
    /// * `Err(MoriError)` - If DNS resolver initialization or lookup fails
    ///
    /// # Examples
    /// ```no_run
    /// use mori::net::{SystemDnsResolver, DnsResolver};
    ///
    /// # async fn example() {
    /// let resolver = SystemDnsResolver;
    /// let domains = vec!["example.com".to_string()];
    /// let resolved = resolver.resolve_domains(&domains).await.unwrap();
    /// # }
    /// ```
    async fn resolve_domains(&self, domains: &[String]) -> Result<ResolvedAddresses, MoriError> {
        // Always read system DNS configuration to get nameserver IPs
        // DNS servers must be allowed even when no domains are specified
        let config = system_conf::read_system_conf()
            .map_err(|source| MoriError::DnsResolverInit { source })?
            .0;
        let nameservers = collect_nameserver_ips(&config);

        if domains.is_empty() {
            return Ok(ResolvedAddresses {
                domains: Vec::new(),
                dns_v4: nameservers,
            });
        }

        let resolver = Resolver::builder_tokio().unwrap().build();
        //let resolver = Resolver::new(config.clone(), opts).map_err(MoriError::Io)?;

        let mut domain_records = Vec::with_capacity(domains.len());

        for domain in domains {
            let response = resolver
                .lookup_ip(domain.as_str())
                .await
                .map_err(|source| MoriError::DnsLookup {
                    domain: domain.clone(),
                    source,
                })?;

            let valid_until = response.valid_until();
            let mut records = Vec::new();

            for ip in response.iter() {
                if let IpAddr::V4(v4) = ip {
                    records.push(Entry {
                        ip: v4,
                        expires_at: valid_until,
                    });
                }
            }

            if !records.is_empty() {
                domain_records.push(DomainRecords {
                    domain: domain.clone(),
                    records,
                });
            }
        }

        Ok(ResolvedAddresses {
            domains: domain_records,
            dns_v4: nameservers,
        })
    }
}

/// Extract IPv4 addresses of DNS nameservers from resolver configuration
///
/// This is necessary because the controlled process needs to be able to
/// connect to DNS servers to perform name resolution.
fn collect_nameserver_ips(config: &ResolverConfig) -> Vec<Ipv4Addr> {
    let mut v4_set: HashSet<Ipv4Addr> = HashSet::new();

    for ns in config.name_servers() {
        if let IpAddr::V4(ip) = ns.socket_addr.ip() {
            v4_set.insert(ip);
        }
    }

    v4_set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn test_resolve_domain_success() {
        let domains = vec!["localhost".to_string()];
        let resolver = SystemDnsResolver;
        let resolved = resolver.resolve_domains(&domains).await.unwrap();
        let record = resolved
            .domains
            .iter()
            .find(|entry| entry.domain == "localhost")
            .expect("localhost record present");
        assert_eq!(record.records.len(), 1);
        let entry = &record.records[0];
        assert_eq!(entry.ip, "127.0.0.1".parse::<Ipv4Addr>().unwrap());
        assert!(entry.expires_at > Instant::now());
    }
}
