use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
};

use hickory_resolver::{Resolver, config::ResolverConfig, system_conf};

use crate::error::MoriError;

#[derive(Default, Debug, PartialEq)]
pub struct ResolvedAddresses {
    /// IPv4 addresses resolved from domain names
    pub domain_v4: Vec<Ipv4Addr>,
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

    let mut v4_set: HashSet<Ipv4Addr> = HashSet::new();

    for domain in domains {
        let response =
            resolver
                .lookup_ip(domain.as_str())
                .map_err(|source| MoriError::DnsLookup {
                    domain: domain.clone(),
                    source,
                })?;

        for ip in response.iter() {
            if let IpAddr::V4(v4) = ip {
                v4_set.insert(v4);
            }
        }
    }

    Ok(ResolvedAddresses {
        domain_v4: v4_set.into_iter().collect(),
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

    #[test]
    fn test_resolve_domain_success() {
        let domains = vec!["localhost".to_string()];
        let resolved = resolve_domains(&domains).unwrap();
        assert_eq!(
            resolved.domain_v4,
            vec!["127.0.0.1".parse::<Ipv4Addr>().unwrap()]
        );
    }
}
