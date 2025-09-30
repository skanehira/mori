use std::{
    convert::TryInto,
    fs::{self, File, OpenOptions},
    io::Write,
    net::Ipv4Addr,
    os::fd::{AsRawFd, BorrowedFd},
    path::PathBuf,
    process::{self, Command, Stdio},
};

use aya::{
    Ebpf, include_bytes_aligned,
    maps::HashMap,
    programs::{cgroup_sock_addr::CgroupSockAddr, links::CgroupAttachMode},
};

use crate::{
    error::MoriError,
    net::{parse_allow_network, resolve_domains},
};

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
}

/// Execute a command in a controlled cgroup with network restrictions
pub fn execute_with_network_control(
    command: &str,
    args: &[&str],
    allow_network_rules: &[String],
) -> Result<i32, MoriError> {
    let valid_network_rules = parse_allow_network(allow_network_rules)?;
    let resolved = resolve_domains(&valid_network_rules.domains)?;

    // Create and setup cgroup
    let cgroup = CgroupManager::create()?;

    // Load and attach eBPF programs
    let mut ebpf = NetworkEbpf::load_and_attach(cgroup.fd())?;

    // Add allowed IP addresses to the map
    for &ip in &valid_network_rules.direct_v4 {
        ebpf.allow_ipv4(ip)?;
        println!("Added {} to allow list", ip);
    }

    for &ip in &resolved.domain_v4 {
        ebpf.allow_ipv4(ip)?;
        println!("Resolved domain IPv4 {} added to allow list", ip);
    }

    for &ip in &resolved.dns_v4 {
        ebpf.allow_ipv4(ip)?;
        println!("Nameserver IPv4 {} added to allow list", ip);
    }

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

    // Wait for the child to complete
    let status = child.wait()?;

    Ok(status.code().unwrap_or(-1))
}
