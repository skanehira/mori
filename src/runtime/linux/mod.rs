mod cgroup;
mod dns;
mod ebpf;
mod file;
mod sync;

use std::{
    collections::HashSet,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Instant,
};

use aya::Ebpf;

use crate::{
    error::MoriError,
    net::{
        cache::DnsCache,
        resolver::{DnsResolver, SystemDnsResolver},
    },
    policy::{AllowPolicy, Policy},
};

use cgroup::CgroupManager;
use dns::{apply_dns_servers, apply_domain_records, spawn_refresh};
use ebpf::NetworkEbpf;
use sync::ShutdownSignal;

/// Spawn a command and add it to a cgroup before execution
///
/// Uses fork() to get the PID before exec, allowing us to add the process
/// to the cgroup before it starts executing the command.
/// Returns a ChildProcess that can be waited on.
fn spawn_command(
    command: &str,
    args: &[&str],
    cgroup_path: &std::path::Path,
) -> Result<ChildProcess, MoriError> {
    use nix::unistd::{ForkResult, fork};

    // Create a pipe for synchronization using libc
    let mut pipe_fds = [0i32; 2];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        return Err(MoriError::Io(std::io::Error::last_os_error()));
    }
    let read_fd = pipe_fds[0];
    let write_fd = pipe_fds[1];

    // Fork the process
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Parent process: close read end
            unsafe { libc::close(read_fd) };

            // Add child to cgroup
            let pid = child.as_raw() as u32;
            let procs_path = cgroup_path.join("cgroup.procs");
            std::fs::write(&procs_path, pid.to_string())?;
            log::info!("Added process {} to cgroup", pid);

            // Signal child to continue by closing write end
            unsafe { libc::close(write_fd) };

            Ok(ChildProcess { pid: child })
        }
        Ok(ForkResult::Child) => {
            use std::os::unix::process::CommandExt;
            use std::process::Command;

            // Child process: close write end
            unsafe { libc::close(write_fd) };

            // Wait for parent to add us to cgroup (blocks until parent closes write_fd)
            let mut buf = [0u8; 1];
            unsafe { libc::read(read_fd, buf.as_mut_ptr() as *mut libc::c_void, 1) };

            // Close read end
            unsafe { libc::close(read_fd) };

            // Build command
            let mut cmd = Command::new(command);
            cmd.args(args);

            // Drop privileges if running under sudo
            if let (Ok(uid_str), Ok(gid_str)) =
                (std::env::var("SUDO_UID"), std::env::var("SUDO_GID"))
                && let (Ok(uid), Ok(gid)) = (uid_str.parse::<u32>(), gid_str.parse::<u32>())
            {
                cmd.uid(uid).gid(gid);
            }

            // exec the command (this replaces the current process image and never returns)
            let err = cmd.exec();

            // If we reach here, exec failed
            panic!("exec failed: {}", err);
        }
        Err(e) => Err(MoriError::Io(std::io::Error::from(e))),
    }
}

/// Wrapper for a child process that provides wait() functionality
struct ChildProcess {
    pid: nix::unistd::Pid,
}

impl ChildProcess {
    fn id(&self) -> u32 {
        self.pid.as_raw() as u32
    }

    fn wait(&mut self) -> Result<std::process::ExitStatus, MoriError> {
        use nix::sys::wait::{WaitStatus, waitpid};
        use std::os::unix::process::ExitStatusExt;

        match waitpid(self.pid, None) {
            Ok(WaitStatus::Exited(_, code)) => Ok(std::process::ExitStatus::from_raw(code << 8)),
            Ok(WaitStatus::Signaled(_, signal, _)) => {
                Ok(std::process::ExitStatus::from_raw(signal as i32))
            }
            Ok(_) => Ok(std::process::ExitStatus::from_raw(0)),
            Err(e) => Err(MoriError::Io(std::io::Error::from(e))),
        }
    }
}

/// Execute a command in a controlled cgroup with network and file access restrictions
pub async fn execute_with_policy(
    command: &str,
    args: &[&str],
    policy: &Policy,
) -> Result<i32, MoriError> {
    let cgroup = CgroupManager::create()?;

    // If network policy is allow-all and no file deny policy, run without restrictions
    // Still create a cgroup for consistency (no performance impact)
    if matches!(policy.network.policy, AllowPolicy::All) && policy.file.denied_paths.is_empty() {
        let mut child = spawn_command(command, args, &cgroup.path)?;
        let status = child.wait()?;
        return Ok(status.code().unwrap_or(-1));
    }

    // Extract entries from network policy
    let (allowed_ipv4, allowed_cidr, domain_names) = match &policy.network.policy {
        AllowPolicy::Entries {
            allowed_ipv4,
            allowed_cidr,
            allowed_domains,
        } => (
            allowed_ipv4.clone(),
            allowed_cidr.clone(),
            allowed_domains.clone(),
        ),
        AllowPolicy::All => (vec![], vec![], vec![]),
    };

    let resolver = SystemDnsResolver;
    let resolved = resolver.resolve_domains(&domain_names).await?;

    // Load eBPF programs
    let mut bpf = Ebpf::load(ebpf::EBPF_ELF)?;

    // Initialize aya-log for eBPF logging
    if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
        log::warn!("Failed to initialize eBPF logger: {}", e);
    }

    // Attach network control eBPF programs if needed
    let network_ebpf = if !matches!(policy.network.policy, AllowPolicy::All) {
        let ebpf = Arc::new(Mutex::new(NetworkEbpf::load_and_attach(cgroup.fd())?));

        let dns_cache = Arc::new(Mutex::new(DnsCache::default()));
        let allowed_dns_ips = Arc::new(Mutex::new(HashSet::new()));
        let now = Instant::now();

        // Add allowed IP addresses and CIDR ranges to the map
        {
            let mut ebpf_guard = ebpf.lock().unwrap();

            // Always allow localhost (127.0.0.1) by default
            let localhost: Ipv4Addr = "127.0.0.1".parse().unwrap();
            ebpf_guard.allow_ipv4(localhost)?;
            log::info!("Added {} (localhost) to network allow list", localhost);

            for &ip in &allowed_ipv4 {
                ebpf_guard.allow_ipv4(ip)?;
                log::info!("Added {} to network allow list", ip);
            }
            for &(network, prefix_len) in &allowed_cidr {
                ebpf_guard.allow_cidr(network, prefix_len)?;
                log::info!("Added {}/{} to network allow list", network, prefix_len);
            }
        }

        apply_domain_records(&dns_cache, &ebpf, now, resolved.domains.to_vec())?;
        apply_dns_servers(&ebpf, &allowed_dns_ips, resolved.dns_v4.clone())?;

        Some((ebpf, dns_cache, allowed_dns_ips))
    } else {
        None
    };

    // Attach file access control eBPF programs if needed (deny-list mode)
    if !policy.file.denied_paths.is_empty() {
        file::FileEbpf::load_and_attach(&mut bpf, &policy.file, cgroup.fd())?;
    }

    // Spawn the command as a child process with privilege dropping if needed
    // The process is added to the cgroup before exec via pre_exec hook
    let mut child = spawn_command(command, args, &cgroup.path)?;

    log::info!(
        "Spawned child process {} (added to cgroup via pre-exec)",
        child.id()
    );

    // Spawn DNS refresh task if needed
    let refresh_handle = if let Some((ref ebpf, ref dns_cache, ref allowed_dns_ips)) = network_ebpf
    {
        if !domain_names.is_empty() {
            let shutdown_signal = ShutdownSignal::new();
            let resolver = SystemDnsResolver;
            let handle = spawn_refresh(
                domain_names.clone(),
                Arc::clone(dns_cache),
                Arc::clone(ebpf),
                Arc::clone(allowed_dns_ips),
                Arc::clone(&shutdown_signal),
                resolver,
            );
            Some((handle, shutdown_signal))
        } else {
            None
        }
    } else {
        None
    };

    // Wait for child process to finish
    let status = child.wait()?;

    // Shutdown DNS refresh task if running
    if let Some((handle, shutdown_signal)) = refresh_handle {
        shutdown_signal.shutdown();
        if let Some(h) = handle {
            h.await
                .map_err(|_| std::io::Error::other("refresh thread panicked"))
                .map_err(MoriError::Io)??;
        }
    }

    Ok(status.code().unwrap_or(-1))
}
