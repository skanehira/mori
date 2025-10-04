use std::{convert::TryInto, net::Ipv4Addr, os::fd::BorrowedFd};

use aya::{
    Ebpf, include_bytes_aligned,
    maps::HashMap,
    programs::{cgroup_sock_addr::CgroupSockAddr, links::CgroupAttachMode},
};

#[cfg(test)]
use mockall::automock;

use crate::error::MoriError;

pub const EBPF_ELF: &[u8] = include_bytes_aligned!(env!("MORI_BPF_ELF"));
const PROGRAM_NAMES: &[&str] = &["mori_connect4"];

/// eBPF controller abstraction for testing
#[cfg_attr(test, automock)]
pub trait EbpfController: Send + Sync + 'static {
    fn allow_ipv4(&mut self, addr: Ipv4Addr) -> Result<(), MoriError>;
    fn remove_ipv4(&mut self, addr: Ipv4Addr) -> Result<(), MoriError>;
}

/// Holds the loaded eBPF object. Dropping this struct detaches the programs automatically.
pub struct NetworkEbpf {
    bpf: Ebpf,
}

impl NetworkEbpf {
    /// Load the mori eBPF program and attach the connect4 hook to the provided cgroup fd.
    pub fn load_and_attach(cgroup_fd: BorrowedFd<'_>) -> Result<Self, MoriError> {
        let mut bpf = Ebpf::load(EBPF_ELF)?;

        // Initialize aya-log for eBPF logging
        if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
            log::warn!("Failed to initialize eBPF logger for NetworkEbpf: {}", e);
        }

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

    /// Add a CIDR range to the allow list
    ///
    /// Note: Only supports CIDR ranges with prefix length >= 24 to avoid map size issues
    pub fn allow_cidr(&mut self, network: Ipv4Addr, prefix_len: u8) -> Result<(), MoriError> {
        if prefix_len < 24 {
            return Err(MoriError::InvalidAllowNetworkEntry {
                entry: format!("{}/{}", network, prefix_len),
                reason: "CIDR prefix length must be >= 24 (max 256 addresses). Use /24 or higher for security.".to_string(),
            });
        }

        let mut map: HashMap<_, u32, u8> =
            HashMap::try_from(self.bpf.map_mut("ALLOW_V4").unwrap())?;

        let network_bits = network.to_bits();
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        let network_addr = network_bits & mask;

        // Calculate the number of addresses in the CIDR range (safe because prefix_len >= 24)
        let num_addresses = 1u32 << (32 - prefix_len);

        // Add each IP in the range individually
        for i in 0..num_addresses {
            let ip_bits = network_addr.wrapping_add(i);
            let key = ip_bits.to_be();
            map.insert(key, 1, 0).map_err(MoriError::Map)?;
        }

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
