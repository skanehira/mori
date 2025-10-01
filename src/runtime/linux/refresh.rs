use std::{
    collections::HashSet,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use crate::{
    error::MoriError,
    net::{
        cache::DnsCache,
        resolver::{DnsResolver, DomainRecords},
    },
};

use super::{ebpf::EbpfController, sync::ShutdownSignal};

const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

pub(super) fn apply_domain_records<E: EbpfController>(
    dns_cache: &Arc<Mutex<DnsCache>>,
    ebpf: &Arc<Mutex<E>>,
    now: Instant,
    new_domains: Vec<DomainRecords>,
) -> Result<(), MoriError> {
    let diffs = {
        let mut cache = dns_cache.lock().unwrap();
        new_domains
            .into_iter()
            .map(|domain| cache.apply(&domain.domain, now, domain.records))
            .collect::<Vec<_>>()
    };

    let mut ebpf_guard = ebpf.lock().unwrap();
    for diff in diffs {
        for ip in diff.removed {
            ebpf_guard.remove_ipv4(ip)?;
            println!("Resolved domain IPv4 {} removed from allow list", ip);
        }
        for ip in diff.added {
            ebpf_guard.allow_ipv4(ip)?;
            println!("Resolved domain IPv4 {} added to allow list", ip);
        }
    }

    Ok(())
}

pub(super) fn apply_dns_servers<E: EbpfController>(
    ebpf: &Arc<Mutex<E>>,
    allowed_dns_ips: &Arc<Mutex<HashSet<Ipv4Addr>>>,
    ips: Vec<Ipv4Addr>,
) -> Result<(), MoriError> {
    let mut set = allowed_dns_ips.lock().unwrap();
    let mut ebpf_guard = ebpf.lock().unwrap();

    for ip in ips {
        if set.insert(ip) {
            ebpf_guard.allow_ipv4(ip)?;
            println!("Nameserver IPv4 {} added to allow list", ip);
        }
    }

    Ok(())
}

pub(super) fn spawn_refresh_thread<R: DnsResolver, E: EbpfController>(
    domains: Vec<String>,
    dns_cache: Arc<Mutex<DnsCache>>,
    ebpf: Arc<Mutex<E>>,
    allowed_dns_ips: Arc<Mutex<HashSet<Ipv4Addr>>>,
    shutdown_signal: Arc<ShutdownSignal>,
    resolver: Arc<R>,
) -> Option<thread::JoinHandle<Result<(), MoriError>>> {
    if domains.is_empty() {
        return None;
    }

    Some(thread::spawn(move || -> Result<(), MoriError> {
        loop {
            let now = Instant::now();
            let sleep_duration = {
                let cache = dns_cache.lock().unwrap();
                cache
                    .next_refresh_in(now)
                    .unwrap_or(DEFAULT_REFRESH_INTERVAL)
            };

            // Wait for timeout or shutdown signal
            if shutdown_signal.wait_timeout_or_shutdown(sleep_duration) {
                return Ok(());
            }

            match resolver.resolve_domains(&domains) {
                Ok(resolved) => {
                    let now = Instant::now();
                    apply_domain_records(&dns_cache, &ebpf, now, resolved.domains)?;
                    apply_dns_servers(&ebpf, &allowed_dns_ips, resolved.dns_v4)?;
                }
                Err(err) => {
                    eprintln!("Failed to refresh DNS records: {err}");
                }
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{ResolvedAddresses, resolver::MockDnsResolver};

    use super::super::ebpf::MockEbpfController;

    #[test]
    fn test_empty_domains_returns_none() {
        let domains = vec![];
        let dns_cache = Arc::new(Mutex::new(DnsCache::default()));
        let ebpf = Arc::new(Mutex::new(MockEbpfController::new()));
        let allowed_dns_ips = Arc::new(Mutex::new(HashSet::new()));
        let shutdown_signal = ShutdownSignal::new();
        let resolver = Arc::new(MockDnsResolver::new());

        let result = spawn_refresh_thread(
            domains,
            dns_cache,
            ebpf,
            allowed_dns_ips,
            shutdown_signal,
            resolver,
        );

        assert!(result.is_none());
    }

    #[test]
    fn test_notify_causes_early_termination() {
        let domains = vec!["example.com".to_string()];
        let dns_cache = Arc::new(Mutex::new(DnsCache::default()));

        // Pre-populate cache with a very short TTL (1ms) so next_refresh_in returns quickly
        {
            use crate::net::cache::Entry;
            let mut cache = dns_cache.lock().unwrap();
            let now = Instant::now();
            cache.apply(
                "example.com",
                now,
                vec![Entry {
                    ip: "1.2.3.4".parse().unwrap(),
                    expires_at: now + Duration::from_millis(2),
                }],
            );
        }

        let mut mock_ebpf = MockEbpfController::new();
        // eBPF operations should not be called since we terminate early
        mock_ebpf.expect_allow_ipv4().times(0);
        mock_ebpf.expect_remove_ipv4().times(0);
        let ebpf = Arc::new(Mutex::new(mock_ebpf));

        let allowed_dns_ips = Arc::new(Mutex::new(HashSet::new()));
        let shutdown_signal = ShutdownSignal::new();

        let mut mock_resolver = MockDnsResolver::new();
        // DNS resolution should not be called since we shutdown immediately
        mock_resolver.expect_resolve_domains().times(0);
        let resolver = Arc::new(mock_resolver);

        let handle = spawn_refresh_thread(
            domains,
            dns_cache,
            ebpf,
            allowed_dns_ips,
            Arc::clone(&shutdown_signal),
            resolver,
        )
        .unwrap();

        // Wait a tiny bit for thread to start, then immediately signal shutdown
        thread::sleep(Duration::from_micros(100));
        shutdown_signal.shutdown();

        // Thread should terminate successfully
        let result = handle.join().unwrap();
        assert!(result.is_ok());
    }

    #[test]
    fn test_timeout_triggers_dns_resolution() {
        let domains = vec!["example.com".to_string()];
        let dns_cache = Arc::new(Mutex::new(DnsCache::default()));

        // Pre-populate cache with a very short TTL (10ms)
        {
            use crate::net::cache::Entry;
            let mut cache = dns_cache.lock().unwrap();
            let now = Instant::now();
            cache.apply(
                "example.com",
                now,
                vec![Entry {
                    ip: "1.2.3.4".parse().unwrap(),
                    expires_at: now + Duration::from_millis(10),
                }],
            );
        }

        let mut mock_ebpf = MockEbpfController::new();
        // Allow eBPF operations to succeed
        mock_ebpf
            .expect_allow_ipv4()
            .returning(|_| Ok(()))
            .times(..);
        mock_ebpf
            .expect_remove_ipv4()
            .returning(|_| Ok(()))
            .times(..);
        let ebpf = Arc::new(Mutex::new(mock_ebpf));

        let allowed_dns_ips = Arc::new(Mutex::new(HashSet::new()));
        let shutdown_signal = ShutdownSignal::new();

        let mut mock_resolver = MockDnsResolver::new();
        // DNS resolution should be called at least once after timeout
        mock_resolver
            .expect_resolve_domains()
            .times(1..)
            .returning(|_| Ok(ResolvedAddresses::default()));
        let resolver = Arc::new(mock_resolver);

        let handle = spawn_refresh_thread(
            domains,
            dns_cache,
            ebpf,
            allowed_dns_ips,
            Arc::clone(&shutdown_signal),
            resolver,
        )
        .unwrap();

        // Wait long enough for cache entry to expire (10ms) + margin
        thread::sleep(Duration::from_millis(50));

        // Signal shutdown to terminate
        shutdown_signal.shutdown();

        let result = handle.join().unwrap();
        assert!(result.is_ok());
    }

    #[test]
    fn test_dns_resolution_failure_continues_loop() {
        let domains = vec!["example.com".to_string()];
        let dns_cache = Arc::new(Mutex::new(DnsCache::default()));

        // Pre-populate cache with a very short TTL (10ms)
        {
            use crate::net::cache::Entry;
            let mut cache = dns_cache.lock().unwrap();
            let now = Instant::now();
            cache.apply(
                "example.com",
                now,
                vec![Entry {
                    ip: "1.2.3.4".parse().unwrap(),
                    expires_at: now + Duration::from_millis(10),
                }],
            );
        }

        let mock_ebpf = MockEbpfController::new();
        let ebpf = Arc::new(Mutex::new(mock_ebpf));

        let allowed_dns_ips = Arc::new(Mutex::new(HashSet::new()));
        let shutdown_signal = ShutdownSignal::new();

        let mut mock_resolver = MockDnsResolver::new();
        // DNS calls fail, but thread should continue
        mock_resolver
            .expect_resolve_domains()
            .times(1..)
            .returning(|_| Err(MoriError::Io(std::io::Error::other("DNS failure"))));
        let resolver = Arc::new(mock_resolver);

        let handle = spawn_refresh_thread(
            domains,
            dns_cache,
            ebpf,
            allowed_dns_ips,
            Arc::clone(&shutdown_signal),
            resolver,
        )
        .unwrap();

        // Wait to allow at least one DNS resolution attempt (10ms) + margin
        thread::sleep(Duration::from_millis(50));

        // Signal shutdown to terminate
        shutdown_signal.shutdown();

        let result = handle.join().unwrap();
        // Should terminate successfully despite DNS failures
        assert!(result.is_ok());
    }
}
