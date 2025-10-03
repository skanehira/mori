mod cgroup;
mod dns;
mod ebpf;
mod file;
mod sync;

use std::{
    collections::HashSet,
    process::{Command, Stdio},
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

/// Execute a command in a controlled cgroup with network and file access restrictions
pub async fn execute_with_control(
    command: &str,
    args: &[&str],
    policy: &Policy,
) -> Result<i32, MoriError> {
    // If network policy is allow-all and no file deny policy, run without restrictions
    if matches!(policy.network.policy, AllowPolicy::All) && policy.file.denied_paths.is_empty() {
        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;
        let status = child.wait()?;
        return Ok(status.code().unwrap_or(-1));
    }

    // Extract entries from network policy
    let (allowed_ipv4, domain_names) = match &policy.network.policy {
        AllowPolicy::Entries {
            allowed_ipv4,
            allowed_domains,
        } => (allowed_ipv4.clone(), allowed_domains.clone()),
        AllowPolicy::All => (vec![], vec![]),
    };

    let resolver = SystemDnsResolver;
    let resolved = resolver.resolve_domains(&domain_names).await?;

    // Create and setup cgroup
    let cgroup = CgroupManager::create()?;

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

        // Add allowed IP addresses to the map
        {
            let mut ebpf_guard = ebpf.lock().unwrap();
            for &ip in &allowed_ipv4 {
                ebpf_guard.allow_ipv4(ip)?;
                log::info!("Added {} to network allow list", ip);
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

    // Spawn the command as a child process (automatically inherits cgroup)
    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    // Add the child process to our cgroup
    cgroup.add_process(child.id())?;
    println!("Process {} added to cgroup", child.id());

    log::info!(
        "Spawned child process {} (automatically in cgroup)",
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
