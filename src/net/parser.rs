use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use crate::error::MoriError;

type Port = u16;

#[derive(Debug, Clone)]
enum HostSpec {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Default, Debug, PartialEq)]
pub struct NetworkRules {
    /// IPv4 addresses directly specified in the rules
    pub direct_v4: Vec<Ipv4Addr>,
    /// Domain names specified in the rules
    pub domains: Vec<String>,
}

/// Parse allow network entries into structured network rules
///
/// Takes a list of network entries (IP addresses, domains, with optional ports)
/// and parses them into separated IPv4 addresses and domain names.
///
/// # Arguments
/// * `entries` - List of network entries in formats like "192.168.1.1", "example.com", "example.com:443"
///
/// # Returns
/// * `Ok(NetworkRules)` - Parsed rules with direct IPv4 addresses and domains
/// * `Err(MoriError)` - If parsing fails or IPv6 addresses are provided (not supported)
///
/// # Examples
/// ```
/// use mori::net::parser::parse_allow_network;
///
/// let entries = vec!["192.168.1.1".to_string(), "example.com".to_string()];
/// let rules = parse_allow_network(&entries).unwrap();
/// ```
pub fn parse_allow_network(entries: &[String]) -> Result<NetworkRules, MoriError> {
    let mut v4_set: HashSet<Ipv4Addr> = HashSet::new();
    let mut domain_set: HashSet<String> = HashSet::new();

    for raw in entries {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (host_spec, _port) =
            parse_single_rule(trimmed).map_err(|reason| MoriError::InvalidAllowNetworkEntry {
                entry: raw.clone(),
                reason,
            })?;

        match host_spec {
            HostSpec::Ip(ip) => match ip {
                IpAddr::V4(v4) => {
                    v4_set.insert(v4);
                }
                IpAddr::V6(_) => {
                    return Err(MoriError::InvalidAllowNetworkEntry {
                        entry: raw.clone(),
                        reason: "IPv6 addresses are not supported".to_string(),
                    });
                }
            },
            HostSpec::Domain(domain) => {
                domain_set.insert(domain);
            }
        }
    }

    Ok(NetworkRules {
        direct_v4: v4_set.into_iter().collect(),
        domains: domain_set.into_iter().collect(),
    })
}

/// Parse a single network rule entry
///
/// Parses various formats:
/// - IP addresses: "192.168.1.1", "::1"
/// - IP:port: "192.168.1.1:8080"
/// - Domain: "example.com"
/// - Domain:port: "example.com:443"
fn parse_single_rule(input: &str) -> Result<(HostSpec, Option<Port>), String> {
    if input.is_empty() {
        return Err("empty value".to_string());
    }

    if let Ok(ip) = input.parse::<IpAddr>() {
        return Ok((HostSpec::Ip(ip), None));
    }

    if input.starts_with('[') {
        return Err("IPv6 addresses are not supported".to_string());
    }

    if let Ok(sock) = input.parse::<SocketAddr>() {
        if sock.is_ipv6() {
            return Err("IPv6 addresses are not supported".to_string());
        }
        return Ok((HostSpec::Ip(sock.ip()), Some(sock.port())));
    }

    if let Some((host_part, port_part)) = input.rsplit_once(':')
        && !host_part.is_empty()
        && port_part.chars().all(|c| c.is_ascii_digit())
    {
        let port = port_part
            .parse::<u16>()
            .map_err(|_| "invalid port number".to_string())?;
        if let Ok(ip) = host_part.parse::<IpAddr>() {
            return Ok((HostSpec::Ip(ip), Some(port)));
        } else {
            return Ok((HostSpec::Domain(host_part.to_string()), Some(port)));
        }
    }

    Ok((HostSpec::Domain(input.to_string()), None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // === Positive test cases ===

    #[rstest]
    #[case(vec!["192.168.1.1"], 1, 0, "single IPv4 address")]
    #[case(vec!["192.168.1.1", "10.0.0.1"], 2, 0, "multiple IPv4 addresses")]
    #[case(vec!["192.168.1.1", "192.168.1.1"], 1, 0, "duplicate IPv4 addresses (deduped)")]
    #[case(vec!["0.0.0.0"], 1, 0, "zero IPv4 address")]
    #[case(vec!["255.255.255.255"], 1, 0, "max IPv4 address")]
    fn test_parse_ipv4_addresses(
        #[case] entries: Vec<&str>,
        #[case] expected_v4_count: usize,
        #[case] expected_domain_count: usize,
        #[case] _description: &str,
    ) {
        let entries: Vec<String> = entries.into_iter().map(String::from).collect();
        let rules = parse_allow_network(&entries).unwrap();
        assert_eq!(rules.direct_v4.len(), expected_v4_count);
        assert_eq!(rules.domains.len(), expected_domain_count);
    }

    #[rstest]
    #[case(vec!["example.com"], 0, 1, "single domain")]
    #[case(vec!["example.com", "test.org"], 0, 2, "multiple domains")]
    #[case(vec!["example.com", "example.com"], 0, 1, "duplicate domains (deduped)")]
    #[case(vec!["sub.example.com"], 0, 1, "subdomain")]
    #[case(vec!["my-domain.com"], 0, 1, "domain with hyphen")]
    #[case(vec!["localhost"], 0, 1, "localhost")]
    fn test_parse_domains(
        #[case] entries: Vec<&str>,
        #[case] expected_v4_count: usize,
        #[case] expected_domain_count: usize,
        #[case] _description: &str,
    ) {
        let entries: Vec<String> = entries.into_iter().map(String::from).collect();
        let rules = parse_allow_network(&entries).unwrap();
        assert_eq!(rules.direct_v4.len(), expected_v4_count);
        assert_eq!(rules.domains.len(), expected_domain_count);
    }

    #[rstest]
    #[case(vec!["192.168.1.1", "example.com"], 1, 1, "IPv4 and domain")]
    #[case(vec!["192.168.1.1", "example.com", "10.0.0.1", "test.org"], 2, 2, "multiple mixed")]
    fn test_parse_mixed_entries(
        #[case] entries: Vec<&str>,
        #[case] expected_v4_count: usize,
        #[case] expected_domain_count: usize,
        #[case] _description: &str,
    ) {
        let entries: Vec<String> = entries.into_iter().map(String::from).collect();
        let rules = parse_allow_network(&entries).unwrap();
        assert_eq!(rules.direct_v4.len(), expected_v4_count);
        assert_eq!(rules.domains.len(), expected_domain_count);
    }

    #[rstest]
    #[case(vec!["192.168.1.1:8080"], 1, 0, "IPv4 with port")]
    #[case(vec!["example.com:443"], 0, 1, "domain with port")]
    #[case(vec!["192.168.1.1:80", "example.com:8080"], 1, 1, "mixed with ports")]
    fn test_parse_with_ports(
        #[case] entries: Vec<&str>,
        #[case] expected_v4_count: usize,
        #[case] expected_domain_count: usize,
        #[case] _description: &str,
    ) {
        let entries: Vec<String> = entries.into_iter().map(String::from).collect();
        let rules = parse_allow_network(&entries).unwrap();
        assert_eq!(rules.direct_v4.len(), expected_v4_count);
        assert_eq!(rules.domains.len(), expected_domain_count);
    }

    #[rstest]
    #[case(vec!["192.168.1.1", "", "example.com"], 1, 1, "empty string in middle")]
    #[case(vec!["  ", "\t"], 0, 0, "whitespace only entries")]
    #[case(vec!["  192.168.1.1  ", "  example.com  "], 1, 1, "entries with surrounding whitespace")]
    #[case(vec![], 0, 0, "empty array")]
    fn test_parse_empty_and_whitespace(
        #[case] entries: Vec<&str>,
        #[case] expected_v4_count: usize,
        #[case] expected_domain_count: usize,
        #[case] _description: &str,
    ) {
        let entries: Vec<String> = entries.into_iter().map(String::from).collect();
        let rules = parse_allow_network(&entries).unwrap();
        assert_eq!(rules.direct_v4.len(), expected_v4_count);
        assert_eq!(rules.domains.len(), expected_domain_count);
    }

    // === Negative test cases (IPv6 not supported) ===

    #[rstest]
    #[case("::1", "IPv6 loopback")]
    #[case("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "IPv6 full address")]
    #[case("fe80::1", "IPv6 link-local")]
    #[case("[::1]", "IPv6 with brackets")]
    #[case("[::1]:8080", "IPv6 with port")]
    #[case("2001:db8::1", "IPv6 compressed")]
    fn test_parse_ipv6_errors(#[case] entry: &str, #[case] _description: &str) {
        let entries = vec![entry.to_string()];
        let result = parse_allow_network(&entries);
        assert!(result.is_err());
        if let Err(MoriError::InvalidAllowNetworkEntry { reason, .. }) = result {
            assert!(reason.contains("IPv6"));
        }
    }

    // === Edge cases ===

    #[rstest]
    #[case("999.999.999.999", 0, 1, "invalid IP treated as domain")]
    #[case("192.168.1", 0, 1, "incomplete IP treated as domain")]
    #[case("192.168.1.1.1", 0, 1, "too many octets treated as domain")]
    fn test_parse_invalid_ips_as_domains(
        #[case] entry: &str,
        #[case] expected_v4_count: usize,
        #[case] expected_domain_count: usize,
        #[case] _description: &str,
    ) {
        let entries = vec![entry.to_string()];
        let rules = parse_allow_network(&entries).unwrap();
        assert_eq!(rules.direct_v4.len(), expected_v4_count);
        assert_eq!(rules.domains.len(), expected_domain_count);
    }

    #[rstest]
    #[case("example.com:99999", "port number too large")]
    fn test_parse_invalid_port_errors(#[case] entry: &str, #[case] _description: &str) {
        let entries = vec![entry.to_string()];
        let result = parse_allow_network(&entries);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_verify_actual_values() {
        let entries = vec!["192.168.1.1".to_string(), "example.com".to_string()];
        let rules = parse_allow_network(&entries).unwrap();

        // Verify actual IPv4 value
        assert_eq!(
            rules.direct_v4[0],
            "192.168.1.1".parse::<Ipv4Addr>().unwrap()
        );

        // Verify actual domain value
        assert_eq!(rules.domains[0], "example.com");
    }

    #[test]
    fn test_parse_deduplication_works() {
        let entries = vec![
            "192.168.1.1".to_string(),
            "192.168.1.1".to_string(),
            "example.com".to_string(),
            "example.com".to_string(),
        ];
        let rules = parse_allow_network(&entries).unwrap();

        // Should deduplicate via HashSet
        assert_eq!(rules.direct_v4.len(), 1);
        assert_eq!(rules.domains.len(), 1);
    }
}
