use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use crate::error::MoriError;

type Port = u16;

#[derive(Debug, Clone)]
enum HostSpec {
    Ip(IpAddr),
    Cidr(Ipv4Addr, u8), // (IP, prefix_length)
    Domain(String),
}

#[derive(Default, Debug, PartialEq)]
pub struct NetworkRules {
    /// IPv4 addresses directly specified in the rules
    pub direct_v4: Vec<Ipv4Addr>,
    /// CIDR ranges specified in the rules (IP, prefix_length)
    pub cidr_v4: Vec<(Ipv4Addr, u8)>,
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
    let mut cidr_set: HashSet<(Ipv4Addr, u8)> = HashSet::new();
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
            HostSpec::Cidr(ip, prefix_len) => {
                cidr_set.insert((ip, prefix_len));
            }
            HostSpec::Domain(domain) => {
                domain_set.insert(domain);
            }
        }
    }

    Ok(NetworkRules {
        direct_v4: v4_set.into_iter().collect(),
        cidr_v4: cidr_set.into_iter().collect(),
        domains: domain_set.into_iter().collect(),
    })
}

/// Parse a single network rule entry
///
/// Parses various formats:
/// - IP addresses: "192.168.1.1", "::1"
/// - CIDR: "192.168.1.0/24"
/// - IP:port: "192.168.1.1:8080"
/// - Domain: "example.com"
/// - Domain:port: "example.com:443"
fn parse_single_rule(input: &str) -> Result<(HostSpec, Option<Port>), String> {
    if input.is_empty() {
        return Err("empty value".to_string());
    }

    // Check for CIDR notation
    if let Some((ip_part, prefix_part)) = input.split_once('/') {
        let prefix_len = prefix_part
            .parse::<u8>()
            .map_err(|_| "invalid CIDR prefix length".to_string())?;

        if prefix_len > 32 {
            return Err("CIDR prefix length must be <= 32".to_string());
        }

        let ip = ip_part
            .parse::<IpAddr>()
            .map_err(|_| "invalid IP address in CIDR".to_string())?;

        match ip {
            IpAddr::V4(v4) => return Ok((HostSpec::Cidr(v4, prefix_len), None)),
            IpAddr::V6(_) => return Err("IPv6 CIDR is not supported".to_string()),
        }
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
    #[case::single_ipv4_address(vec!["192.168.1.1"], 1, 0)]
    #[case::multiple_ipv4_addresses(vec!["192.168.1.1", "10.0.0.1"], 2, 0)]
    #[case::duplicate_ipv4_addresses_deduped(vec!["192.168.1.1", "192.168.1.1"], 1, 0)]
    #[case::zero_ipv4_address(vec!["0.0.0.0"], 1, 0)]
    #[case::max_ipv4_address(vec!["255.255.255.255"], 1, 0)]
    fn test_parse_ipv4_addresses(
        #[case] entries: Vec<&str>,
        #[case] expected_v4_count: usize,
        #[case] expected_domain_count: usize,
    ) {
        let entries: Vec<String> = entries.into_iter().map(String::from).collect();
        let rules = parse_allow_network(&entries).unwrap();
        assert_eq!(rules.direct_v4.len(), expected_v4_count);
        assert_eq!(rules.domains.len(), expected_domain_count);
    }

    #[rstest]
    #[case::single_domain(vec!["example.com"], 0, 1)]
    #[case::multiple_domains(vec!["example.com", "test.org"], 0, 2)]
    #[case::duplicate_domains_deduped(vec!["example.com", "example.com"], 0, 1)]
    #[case::subdomain(vec!["sub.example.com"], 0, 1)]
    #[case::domain_with_hyphen(vec!["my-domain.com"], 0, 1)]
    #[case::localhost(vec!["localhost"], 0, 1)]
    fn test_parse_domains(
        #[case] entries: Vec<&str>,
        #[case] expected_v4_count: usize,
        #[case] expected_domain_count: usize,
    ) {
        let entries: Vec<String> = entries.into_iter().map(String::from).collect();
        let rules = parse_allow_network(&entries).unwrap();
        assert_eq!(rules.direct_v4.len(), expected_v4_count);
        assert_eq!(rules.domains.len(), expected_domain_count);
    }

    #[rstest]
    #[case::single_slash_24_cidr(vec!["192.168.1.0/24"], 0, 1, 0)]
    #[case::multiple_cidr_ranges(vec!["10.0.0.0/24", "172.16.0.0/24"], 0, 2, 0)]
    #[case::duplicate_cidr_deduped(vec!["192.168.1.0/24", "192.168.1.0/24"], 0, 1, 0)]
    #[case::slash_32_cidr_single_address(vec!["10.0.0.0/32"], 0, 1, 0)]
    #[case::slash_28_cidr(vec!["172.16.0.0/28"], 0, 1, 0)]
    #[case::slash_25_cidr(vec!["192.168.0.0/25"], 0, 1, 0)]
    #[case::slash_0_cidr_all_addresses(vec!["0.0.0.0/0"], 0, 1, 0)]
    fn test_parse_cidr_ranges(
        #[case] entries: Vec<&str>,
        #[case] expected_v4_count: usize,
        #[case] expected_cidr_count: usize,
        #[case] expected_domain_count: usize,
    ) {
        let entries: Vec<String> = entries.into_iter().map(String::from).collect();
        let rules = parse_allow_network(&entries).unwrap();
        assert_eq!(rules.direct_v4.len(), expected_v4_count);
        assert_eq!(rules.cidr_v4.len(), expected_cidr_count);
        assert_eq!(rules.domains.len(), expected_domain_count);
    }

    #[rstest]
    #[case::ipv4_and_domain(vec!["192.168.1.1", "example.com"], 1, 1)]
    #[case::multiple_mixed(vec!["192.168.1.1", "example.com", "10.0.0.1", "test.org"], 2, 2)]
    fn test_parse_mixed_entries(
        #[case] entries: Vec<&str>,
        #[case] expected_v4_count: usize,
        #[case] expected_domain_count: usize,
    ) {
        let entries: Vec<String> = entries.into_iter().map(String::from).collect();
        let rules = parse_allow_network(&entries).unwrap();
        assert_eq!(rules.direct_v4.len(), expected_v4_count);
        assert_eq!(rules.domains.len(), expected_domain_count);
    }

    #[rstest]
    #[case::ipv4_with_port(vec!["192.168.1.1:8080"], 1, 0)]
    #[case::domain_with_port(vec!["example.com:443"], 0, 1)]
    #[case::mixed_with_ports(vec!["192.168.1.1:80", "example.com:8080"], 1, 1)]
    fn test_parse_with_ports(
        #[case] entries: Vec<&str>,
        #[case] expected_v4_count: usize,
        #[case] expected_domain_count: usize,
    ) {
        let entries: Vec<String> = entries.into_iter().map(String::from).collect();
        let rules = parse_allow_network(&entries).unwrap();
        assert_eq!(rules.direct_v4.len(), expected_v4_count);
        assert_eq!(rules.domains.len(), expected_domain_count);
    }

    #[rstest]
    #[case::empty_string_in_middle(vec!["192.168.1.1", "", "example.com"], 1, 1)]
    #[case::whitespace_only_entries(vec!["  ", "\t"], 0, 0)]
    #[case::entries_with_surrounding_whitespace(vec!["  192.168.1.1  ", "  example.com  "], 1, 1)]
    #[case::empty_array(vec![], 0, 0)]
    fn test_parse_empty_and_whitespace(
        #[case] entries: Vec<&str>,
        #[case] expected_v4_count: usize,
        #[case] expected_domain_count: usize,
    ) {
        let entries: Vec<String> = entries.into_iter().map(String::from).collect();
        let rules = parse_allow_network(&entries).unwrap();
        assert_eq!(rules.direct_v4.len(), expected_v4_count);
        assert_eq!(rules.domains.len(), expected_domain_count);
    }

    // === Negative test cases (IPv6 not supported) ===

    #[rstest]
    #[case::ipv6_loopback("::1")]
    #[case::ipv6_full_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334")]
    #[case::ipv6_link_local("fe80::1")]
    #[case::ipv6_with_brackets("[::1]")]
    #[case::ipv6_with_port("[::1]:8080")]
    #[case::ipv6_compressed("2001:db8::1")]
    #[case::ipv6_cidr("2001:db8::/32")]
    fn test_parse_ipv6_errors(#[case] entry: &str) {
        let entries = vec![entry.to_string()];
        let result = parse_allow_network(&entries);
        assert!(result.is_err());
        if let Err(MoriError::InvalidAllowNetworkEntry { reason, .. }) = result {
            assert!(reason.contains("IPv6"));
        }
    }

    #[rstest]
    #[case::prefix_length_greater_than_32("192.168.1.0/33")]
    #[case::non_numeric_prefix_length("192.168.1.0/abc")]
    #[case::missing_prefix_length("192.168.1.0/")]
    #[case::invalid_ip_in_cidr("192.168.1.999/24")]
    fn test_parse_invalid_cidr_errors(#[case] entry: &str) {
        let entries = vec![entry.to_string()];
        let result = parse_allow_network(&entries);
        assert!(result.is_err());
    }

    // === Edge cases ===

    #[rstest]
    #[case::invalid_ip_treated_as_domain("999.999.999.999", 0, 1)]
    #[case::incomplete_ip_treated_as_domain("192.168.1", 0, 1)]
    #[case::too_many_octets_treated_as_domain("192.168.1.1.1", 0, 1)]
    fn test_parse_invalid_ips_as_domains(
        #[case] entry: &str,
        #[case] expected_v4_count: usize,
        #[case] expected_domain_count: usize,
    ) {
        let entries = vec![entry.to_string()];
        let rules = parse_allow_network(&entries).unwrap();
        assert_eq!(rules.direct_v4.len(), expected_v4_count);
        assert_eq!(rules.domains.len(), expected_domain_count);
    }

    #[rstest]
    #[case::port_number_too_large("example.com:99999")]
    fn test_parse_invalid_port_errors(#[case] entry: &str) {
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
    fn test_parse_verify_cidr_values() {
        let entries = vec!["192.168.1.0/24".to_string()];
        let rules = parse_allow_network(&entries).unwrap();

        // Verify CIDR network address and prefix length
        assert_eq!(rules.cidr_v4.len(), 1);
        assert_eq!(
            rules.cidr_v4[0].0,
            "192.168.1.0".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(rules.cidr_v4[0].1, 24);
    }

    #[test]
    fn test_parse_mixed_ipv4_cidr_domain() {
        let entries = vec![
            "192.168.1.1".to_string(),
            "10.0.0.0/24".to_string(),
            "example.com".to_string(),
        ];
        let rules = parse_allow_network(&entries).unwrap();

        // Verify all types are present
        assert_eq!(rules.direct_v4.len(), 1);
        assert_eq!(rules.cidr_v4.len(), 1);
        assert_eq!(rules.domains.len(), 1);

        // Verify values
        assert_eq!(
            rules.direct_v4[0],
            "192.168.1.1".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            rules.cidr_v4[0],
            ("10.0.0.0".parse::<Ipv4Addr>().unwrap(), 24)
        );
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
