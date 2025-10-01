use std::{
    collections::HashSet,
    convert::TryInto,
    fs::{self, File, OpenOptions},
    io::Write,
    net::Ipv4Addr,
    os::fd::{AsRawFd, BorrowedFd},
    path::PathBuf,
    process::{self, Command, Stdio},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use aya::{
    Ebpf, include_bytes_aligned,
    maps::HashMap,
    programs::{cgroup_sock_addr::CgroupSockAddr, links::CgroupAttachMode},
};

use crate::{
    error::MoriError,
    net::{
        cache::DnsCache,
        parse_allow_network,
        resolver::{DnsResolver, DomainRecords, SystemDnsResolver},
    },
};

#[cfg(test)]
use mockall::automock;

const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

const EBPF_ELF: &[u8] = include_bytes_aligned!(env!("MORI_BPF_ELF"));
const PROGRAM_NAMES: &[&str] = &["mori_connect4"];

/// Thread shutdown signaling mechanism combining Condvar and AtomicBool
///
/// This struct provides a clean abstraction for coordinating thread shutdown by combining:
/// - `Mutex<()>` and `Condvar` for wait/notify pattern
/// - `AtomicBool` for lock-free shutdown status checking
///
/// # Design rationale
/// Using only Condvar has a timing issue: `notify_all()` only wakes threads currently
/// in `wait()`. If a thread is processing between wait calls, it misses the notification.
/// The AtomicBool flag ensures the thread can check shutdown status at any time,
/// not just during wait.
///
/// # Usage
/// ```no_run
/// use std::time::Duration;
/// # use std::sync::{Arc, Mutex, Condvar, atomic::{AtomicBool, Ordering}};
/// # struct ShutdownSignal { lock: Mutex<()>, condvar: Condvar, shutdown: AtomicBool }
/// # impl ShutdownSignal {
/// #     fn new() -> Arc<Self> { Arc::new(Self { lock: Mutex::new(()), condvar: Condvar::new(), shutdown: AtomicBool::new(false) }) }
/// #     fn wait_timeout_or_shutdown(&self, timeout: Duration) -> bool {
/// #         let guard = self.lock.lock().unwrap();
/// #         let _result = self.condvar.wait_timeout(guard, timeout).unwrap();
/// #         self.shutdown.load(Ordering::Relaxed)
/// #     }
/// #     fn shutdown(&self) { self.shutdown.store(true, Ordering::Relaxed); self.condvar.notify_all(); }
/// # }
///
/// let signal = ShutdownSignal::new();
///
/// // In worker thread:
/// if signal.wait_timeout_or_shutdown(Duration::from_millis(1)) {
///     // shutdown requested
/// }
///
/// // In main thread:
/// signal.shutdown();
/// ```
struct ShutdownSignal {
    lock: Mutex<()>,
    condvar: Condvar,
    shutdown: AtomicBool,
}

impl ShutdownSignal {
    /// Create a new ShutdownSignal
    fn new() -> Arc<Self> {
        Arc::new(Self {
            lock: Mutex::new(()),
            condvar: Condvar::new(),
            shutdown: AtomicBool::new(false),
        })
    }

    /// Wait for timeout or shutdown signal, whichever comes first
    ///
    /// Returns `true` if shutdown was signaled, `false` if timeout occurred
    fn wait_timeout_or_shutdown(&self, timeout: Duration) -> bool {
        let guard = self.lock.lock().unwrap();
        let _result = self.condvar.wait_timeout(guard, timeout).unwrap();

        // Check shutdown flag after waking up
        // This ensures we catch shutdown even if notified during wait
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Signal shutdown to waiting threads
    ///
    /// Sets the shutdown flag and notifies all waiting threads
    fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.condvar.notify_all();
    }
}

/// eBPF controller abstraction for testing
#[cfg_attr(test, automock)]
trait EbpfController: Send + Sync + 'static {
    fn allow_ipv4(&mut self, addr: Ipv4Addr) -> Result<(), MoriError>;
    fn remove_ipv4(&mut self, addr: Ipv4Addr) -> Result<(), MoriError>;
}

/// Cgroup manager that creates and manages a cgroup for process isolation
struct CgroupManager {
    cgroup_path: PathBuf,
    cgroup_file: File,
}

impl CgroupManager {
    /// Create a new cgroup and return a manager for it
    pub fn create() -> Result<Self, MoriError> {
        // Create a unique cgroup directory under /sys/fs/cgroup/
        let cgroup_name = format!("mori-{}", process::id());
        let cgroup_path = PathBuf::from("/sys/fs/cgroup").join(cgroup_name);

        fs::create_dir_all(&cgroup_path)?;
        let cgroup_file = File::open(&cgroup_path)?;

        Ok(Self {
            cgroup_path,
            cgroup_file,
        })
    }

    /// Get a borrowed file descriptor for the cgroup
    pub fn fd(&self) -> BorrowedFd<'_> {
        unsafe { BorrowedFd::borrow_raw(self.cgroup_file.as_raw_fd()) }
    }

    /// Add a process to this cgroup
    pub fn add_process(&self, pid: u32) -> Result<(), MoriError> {
        let procs_path = self.cgroup_path.join("cgroup.procs");
        let mut file = OpenOptions::new().write(true).open(procs_path)?;
        write!(file, "{}", pid)?;
        Ok(())
    }
}

impl Drop for CgroupManager {
    fn drop(&mut self) {
        // Clean up the cgroup directory when dropped
        let _ = fs::remove_dir(&self.cgroup_path);
    }
}

/// Holds the loaded eBPF object. Dropping this struct detaches the programs automatically.
struct NetworkEbpf {
    bpf: Ebpf,
}

impl NetworkEbpf {
    /// Load the mori eBPF program and attach the connect4 hook to the provided cgroup fd.
    pub fn load_and_attach(cgroup_fd: BorrowedFd<'_>) -> Result<Self, MoriError> {
        let mut bpf = Ebpf::load(EBPF_ELF)?;

        for name in PROGRAM_NAMES {
            let program = bpf
                .program_mut(name)
                .ok_or_else(|| MoriError::ProgramNotFound {
                    name: name.to_string(),
                })?;

            let program: &mut CgroupSockAddr =
                program
                    .try_into()
                    .map_err(|source| MoriError::ProgramPrepare {
                        name: name.to_string(),
                        source,
                    })?;

            program.load().map_err(|source| MoriError::ProgramPrepare {
                name: name.to_string(),
                source,
            })?;

            program
                .attach(cgroup_fd, CgroupAttachMode::Single)
                .map_err(|source| MoriError::ProgramAttach {
                    name: name.to_string(),
                    source,
                })?;
        }

        Ok(Self { bpf })
    }

    /// Add an IPv4 address to the allow list
    pub fn allow_ipv4(&mut self, addr: Ipv4Addr) -> Result<(), MoriError> {
        let mut map: HashMap<_, u32, u8> =
            HashMap::try_from(self.bpf.map_mut("ALLOW_V4").unwrap())?;
        let key = addr.to_bits().to_be();
        map.insert(key, 1, 0) // 1 = allowed, flags = 0 (BPF_ANY)
            .map_err(MoriError::Map)?;
        Ok(())
    }

    pub fn remove_ipv4(&mut self, addr: Ipv4Addr) -> Result<(), MoriError> {
        let mut map: HashMap<_, u32, u8> =
            HashMap::try_from(self.bpf.map_mut("ALLOW_V4").unwrap())?;
        let key = addr.to_bits().to_be();
        map.remove(&key).map_err(MoriError::Map)?;
        Ok(())
    }
}

impl EbpfController for NetworkEbpf {
    fn allow_ipv4(&mut self, addr: Ipv4Addr) -> Result<(), MoriError> {
        self.allow_ipv4(addr)
    }

    fn remove_ipv4(&mut self, addr: Ipv4Addr) -> Result<(), MoriError> {
        self.remove_ipv4(addr)
    }
}

/// Execute a command in a controlled cgroup with network restrictions
pub fn execute_with_network_control(
    command: &str,
    args: &[&str],
    allow_network_rules: &[String],
) -> Result<i32, MoriError> {
    let valid_network_rules = parse_allow_network(allow_network_rules)?;
    let domain_names = valid_network_rules.domains.clone();
    let resolver = SystemDnsResolver;
    let resolved = resolver.resolve_domains(&domain_names)?;

    // Create and setup cgroup
    let cgroup = CgroupManager::create()?;

    // Load and attach eBPF programs
    let ebpf = Arc::new(Mutex::new(NetworkEbpf::load_and_attach(cgroup.fd())?));

    let dns_cache = Arc::new(Mutex::new(DnsCache::default()));
    let allowed_dns_ips = Arc::new(Mutex::new(HashSet::new()));
    let now = Instant::now();

    // Add allowed IP addresses to the map
    {
        let mut ebpf_guard = ebpf.lock().unwrap();
        for &ip in &valid_network_rules.direct_v4 {
            ebpf_guard.allow_ipv4(ip)?;
            println!("Added {} to allow list", ip);
        }
    }

    apply_domain_records(&dns_cache, &ebpf, now, resolved.domains)?;
    apply_dns_servers(&ebpf, &allowed_dns_ips, resolved.dns_v4)?;

    // Spawn the command as a child process
    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    // Add the child process to our cgroup
    cgroup.add_process(child.id())?;
    println!("Process {} added to cgroup", child.id());

    if domain_names.is_empty() {
        let status = child.wait()?;
        return Ok(status.code().unwrap_or(-1));
    }

    let shutdown_signal = ShutdownSignal::new();
    let resolver = Arc::new(SystemDnsResolver);
    let refresh_handle = spawn_refresh_thread(
        domain_names.clone(),
        Arc::clone(&dns_cache),
        Arc::clone(&ebpf),
        Arc::clone(&allowed_dns_ips),
        Arc::clone(&shutdown_signal),
        resolver,
    );

    let status = child.wait()?;
    shutdown_signal.shutdown();
    if let Some(handle) = refresh_handle {
        handle
            .join()
            .map_err(|_| std::io::Error::other("refresh thread panicked"))
            .map_err(MoriError::Io)??;
    }

    Ok(status.code().unwrap_or(-1))
}

fn apply_domain_records<E: EbpfController>(
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

fn apply_dns_servers<E: EbpfController>(
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

fn spawn_refresh_thread<R: DnsResolver, E: EbpfController>(
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
    use std::time::Duration;

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
