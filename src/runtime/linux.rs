use std::{
    collections::HashSet,
    convert::TryInto,
    fs::{self, File, OpenOptions},
    io::Write,
    net::Ipv4Addr,
    os::fd::{AsRawFd, BorrowedFd},
    path::PathBuf,
    process::{self, Command, Stdio},
    sync::{Arc, Condvar, Mutex},
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
    net::{cache::DnsCache, parse_allow_network, resolve_domains, resolver::DomainRecords},
};

const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

const EBPF_ELF: &[u8] = include_bytes_aligned!(env!("MORI_BPF_ELF"));
const PROGRAM_NAMES: &[&str] = &["mori_connect4"];

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

/// Execute a command in a controlled cgroup with network restrictions
pub fn execute_with_network_control(
    command: &str,
    args: &[&str],
    allow_network_rules: &[String],
) -> Result<i32, MoriError> {
    let valid_network_rules = parse_allow_network(allow_network_rules)?;
    let domain_names = valid_network_rules.domains.clone();
    let resolved = resolve_domains(&domain_names)?;

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

    let condvar_pair = Arc::new((Mutex::new(()), Condvar::new()));
    let refresh_handle = spawn_refresh_thread(
        domain_names.clone(),
        Arc::clone(&dns_cache),
        Arc::clone(&ebpf),
        Arc::clone(&allowed_dns_ips),
        Arc::clone(&condvar_pair),
    );

    let status = child.wait()?;
    condvar_pair.1.notify_all();
    if let Some(handle) = refresh_handle {
        handle
            .join()
            .map_err(|_| std::io::Error::other("refresh thread panicked"))
            .map_err(MoriError::Io)??;
    }

    Ok(status.code().unwrap_or(-1))
}

fn apply_domain_records(
    dns_cache: &Arc<Mutex<DnsCache>>,
    ebpf: &Arc<Mutex<NetworkEbpf>>,
    now: Instant,
    domains: Vec<DomainRecords>,
) -> Result<(), MoriError> {
    let diffs = {
        let mut cache = dns_cache.lock().unwrap();
        domains
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

fn apply_dns_servers(
    ebpf: &Arc<Mutex<NetworkEbpf>>,
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

fn spawn_refresh_thread(
    domains: Vec<String>,
    dns_cache: Arc<Mutex<DnsCache>>,
    ebpf: Arc<Mutex<NetworkEbpf>>,
    allowed_dns_ips: Arc<Mutex<HashSet<Ipv4Addr>>>,
    condvar_pair: Arc<(Mutex<()>, Condvar)>,
) -> Option<thread::JoinHandle<Result<(), MoriError>>> {
    if domains.is_empty() {
        return None;
    }

    Some(thread::spawn(move || -> Result<(), MoriError> {
        let (lock, condvar) = &*condvar_pair;
        loop {
            let now = Instant::now();
            let sleep_duration = {
                let cache = dns_cache.lock().unwrap();
                cache
                    .next_refresh_in(now)
                    .unwrap_or(DEFAULT_REFRESH_INTERVAL)
                    .max(MIN_REFRESH_INTERVAL)
            };

            let guard = lock.lock().unwrap();
            let result = condvar.wait_timeout(guard, sleep_duration).unwrap();

            if !result.1.timed_out() {
                return Ok(());
            }

            match resolve_domains(&domains) {
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
