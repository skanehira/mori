use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
};

use hickory_resolver::{Resolver, config::ResolverConfig, system_conf};

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
/// ```
/// use mori::net::resolver::resolve_domains;
///
/// let domains = vec!["example.com".to_string()];
/// let resolved = resolve_domains(&domains).unwrap();
/// ```
pub fn resolve_domains(domains: &[String]) -> Result<ResolvedAddresses, MoriError> {
    if domains.is_empty() {
        return Ok(ResolvedAddresses::default());
    }

    let (config, opts) =
        system_conf::read_system_conf().map_err(|source| MoriError::DnsResolverInit { source })?;

    let resolver = Resolver::new(config.clone(), opts).map_err(MoriError::Io)?;

    let nameservers = collect_nameserver_ips(&config);

    let mut domain_records = Vec::with_capacity(domains.len());

    for domain in domains {
        let response =
            resolver
                .lookup_ip(domain.as_str())
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

    #[test]
    fn test_resolve_domain_success() {
        let domains = vec!["localhost".to_string()];
        let resolved = resolve_domains(&domains).unwrap();
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
