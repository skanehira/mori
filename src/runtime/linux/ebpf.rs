use std::{convert::TryInto, net::Ipv4Addr, os::fd::BorrowedFd};

use aya::{
    Ebpf, include_bytes_aligned,
    maps::lpm_trie::{Key, LpmTrie},
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
    fn allow_network(&mut self, addr: Ipv4Addr, prefix_len: u8) -> Result<(), MoriError>;
    fn remove_network(&mut self, addr: Ipv4Addr, prefix_len: u8) -> Result<(), MoriError>;
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

    /// Add a single IPv4 address or CIDR range to the allow list
    ///
    /// # Arguments
    /// - addr: Network address (e.g., 192.168.1.1 or 10.0.0.0)
    /// - prefix_len: Prefix length (32=single IP, 24=/24, 13=/13, etc.)
    ///
    /// # Behavior
    /// - prefix_len=32: Registered as a single IP address
    /// - prefix_len<32: Registered as a CIDR range
    /// - Registered as 1 entry in LPM Trie (no expansion like HashMap)
    pub fn allow_network(&mut self, addr: Ipv4Addr, prefix_len: u8) -> Result<(), MoriError> {
        if prefix_len > 32 {
            return Err(MoriError::InvalidCidrPrefix {
                addr,
                prefix_len,
                max_allowed: 32,
            });
        }

        let mut map: LpmTrie<_, [u8; 4], u8> =
            LpmTrie::try_from(self.bpf.map_mut("ALLOW_V4_LPM").unwrap())?;

        // Normalize network address (apply mask based on prefix_len)
        let network_bits = addr.to_bits();
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        let network_addr = network_bits & mask;

        // Convert to network byte order (big-endian) byte array
        let be_bytes = network_addr.to_be_bytes();
        let key = Key::new(prefix_len as u32, be_bytes);

        // Insert into LPM Trie
        // flags=0 (BPF_ANY) overwrites existing entry if present (same behavior as HashMap)
        map.insert(&key, 1, 0).map_err(MoriError::Map)?;

        Ok(())
    }

    /// Remove an IPv4 address from the allow list
    pub fn remove_network(&mut self, addr: Ipv4Addr, prefix_len: u8) -> Result<(), MoriError> {
        let mut map: LpmTrie<_, [u8; 4], u8> =
            LpmTrie::try_from(self.bpf.map_mut("ALLOW_V4_LPM").unwrap())?;

        let network_bits = addr.to_bits();
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        let network_addr = network_bits & mask;
        let be_bytes = network_addr.to_be_bytes();
        let key = Key::new(prefix_len as u32, be_bytes);

        map.remove(&key).map_err(MoriError::Map)?;
        Ok(())
    }
}

impl EbpfController for NetworkEbpf {
    fn allow_network(&mut self, addr: Ipv4Addr, prefix_len: u8) -> Result<(), MoriError> {
        self.allow_network(addr, prefix_len)
    }

    fn remove_network(&mut self, addr: Ipv4Addr, prefix_len: u8) -> Result<(), MoriError> {
        self.remove_network(addr, prefix_len)
    }
}
