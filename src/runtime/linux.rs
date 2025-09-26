use std::{convert::TryInto, os::fd::BorrowedFd};

use aya::{
    Ebpf, include_bytes_aligned,
    programs::{cgroup_sock_addr::CgroupSockAddr, links::CgroupAttachMode},
};

use crate::error::MoriError;

const EBPF_ELF: &[u8] = include_bytes_aligned!(env!("MORI_BPF_ELF"));
const PROGRAM_NAMES: &[&str] = &["mori_connect4", "mori_connect6"];

/// Holds the loaded eBPF object. Dropping this struct detaches the programs automatically.
#[allow(dead_code)]
pub struct NetworkEbpf {
    bpf: Ebpf,
}

impl NetworkEbpf {
    /// Load the mori eBPF program and attach connect4/connect6 hooks to the provided cgroup fd.
    pub fn load_and_attach(cgroup_fd: BorrowedFd<'_>) -> Result<Self, MoriError> {
        let mut bpf = Ebpf::load(EBPF_ELF)?;

        for name in PROGRAM_NAMES {
            let program = bpf
                .program_mut(name)
                .ok_or_else(|| MoriError::ProgramNotFound {
                    name: (*name).to_string(),
                })?;

            let program: &mut CgroupSockAddr =
                program
                    .try_into()
                    .map_err(|source| MoriError::ProgramPrepare {
                        name: (*name).to_string(),
                        source,
                    })?;

            program.load().map_err(|source| MoriError::ProgramPrepare {
                name: (*name).to_string(),
                source,
            })?;

            program
                .attach(cgroup_fd, CgroupAttachMode::Single)
                .map_err(|source| MoriError::ProgramAttach {
                    name: (*name).to_string(),
                    source,
                })?;
        }

        Ok(Self { bpf })
    }
}
