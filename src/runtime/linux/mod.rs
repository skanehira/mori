mod cgroup;
mod dns;
mod ebpf;
mod sync;

use std::{
    collections::HashSet,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::Instant,
};

use crate::{
    error::MoriError,
    net::{
        cache::DnsCache,
        resolver::{DnsResolver, SystemDnsResolver},
    },
    policy::NetworkPolicy,
};

use cgroup::CgroupManager;
use dns::{apply_dns_servers, apply_domain_records, spawn_refresh};
use ebpf::NetworkEbpf;
use sync::ShutdownSignal;

/// Execute a command in a controlled cgroup with network restrictions
pub async fn execute_with_network_control(
    command: &str,
    args: &[&str],
    policy: &NetworkPolicy,
) -> Result<i32, MoriError> {
    use crate::policy::AllowPolicy;

    // If policy is allow-all, run without restrictions
    if matches!(policy.policy, AllowPolicy::All) {
        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;
        let status = child.wait()?;
        return Ok(status.code().unwrap_or(-1));
    }

    // Extract entries from policy
    let (allowed_ipv4, domain_names) = match &policy.policy {
        AllowPolicy::Entries {
            allowed_ipv4,
            allowed_domains,
        } => (allowed_ipv4.clone(), allowed_domains.clone()),
        AllowPolicy::All => unreachable!("Already handled above"),
    };

    let resolver = SystemDnsResolver;
    let resolved = resolver.resolve_domains(&domain_names).await?;

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
        for &ip in &allowed_ipv4 {
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
    let resolver = SystemDnsResolver;
    let refresh_handle = spawn_refresh(
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
            .await
            .map_err(|_| std::io::Error::other("refresh thread panicked"))
            .map_err(MoriError::Io)??;
    }

    Ok(status.code().unwrap_or(-1))
}
