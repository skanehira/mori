use std::{convert::TryFrom, os::fd::BorrowedFd};

use aya::{
    maps::HashMap,
    programs::lsm::{Lsm, LsmLinkId},
    Btf, Ebpf,
};

use crate::{
    error::MoriError,
    policy::{AccessMode, FilePolicy},
};

const PATH_MAX: usize = 64;
const PROGRAM_NAMES: &[&str] = &["mori_path_open"];

/// File access control using eBPF LSM
pub struct FileEbpf {
    _links: Vec<LsmLinkId>,
}

impl FileEbpf {
    /// Load the file LSM eBPF program and attach it
    pub fn load_and_attach(
        bpf: &mut Ebpf,
        policy: &FilePolicy,
        cgroup_fd: BorrowedFd<'_>,
    ) -> Result<Self, MoriError> {
        let btf = Btf::from_sys_fs()?;

        // Get cgroup ID and register it in TARGET_CGROUP map
        // Note: We use system-wide LSM attach + cgroup ID filtering because:
        // - file_open is a sleepable LSM hook
        // - BPF_LSM_CGROUP attach type only supports non-sleepable hooks
        let cgroup_id = get_cgroup_id(cgroup_fd)?;
        let mut target_cgroup: HashMap<_, u64, u8> =
            HashMap::try_from(bpf.map_mut("TARGET_CGROUP").unwrap())?;
        target_cgroup.insert(cgroup_id, 1, 0)?;
        log::info!("Target cgroup ID: {}", cgroup_id);

        // Populate DENY_PATHS map (deny-list mode)
        let mut deny_paths: HashMap<_, [u8; PATH_MAX], u8> =
            HashMap::try_from(bpf.map_mut("DENY_PATHS").unwrap())?;

        for (path, mode) in &policy.denied_paths {
            let path_str = path.to_string_lossy();
            let path_bytes = path_str.as_bytes();

            if path_bytes.len() >= PATH_MAX {
                log::warn!("Path too long (>= 256 bytes), skipping: {}", path_str);
                continue;
            }

            let mut key = [0u8; PATH_MAX];
            // Copy path bytes including null terminator to match bpf_d_path output
            key[..path_bytes.len()].copy_from_slice(path_bytes);
            // bpf_d_path includes null terminator, so we explicitly set it
            if path_bytes.len() < PATH_MAX {
                key[path_bytes.len()] = 0;
            }

            // Log all 15 bytes of the key for debugging
            let hex_key: String = key
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");

            let mode_value = *mode as u8;
            deny_paths
                .insert(key, mode_value, 0)
                .map_err(MoriError::Map)?;

            log::info!(
                "Denied file access: {} (len={}, mode: {}, key_hex: {})",
                path_str,
                path_bytes.len(),
                match mode {
                    AccessMode::Read => "READ",
                    AccessMode::Write => "WRITE",
                    AccessMode::ReadWrite => "READ|WRITE",
                },
                hex_key
            );
        }

        // Attach LSM programs using standard LSM attach (not cgroup-based)
        let mut links = Vec::new();
        for name in PROGRAM_NAMES {
            let program = bpf
                .program_mut(name)
                .ok_or_else(|| MoriError::ProgramNotFound {
                    name: name.to_string(),
                })?;

            let program: &mut Lsm =
                program
                    .try_into()
                    .map_err(|source| MoriError::ProgramPrepare {
                        name: name.to_string(),
                        source,
                    })?;

            program
                .load("file_open", &btf)
                .map_err(|source| MoriError::ProgramPrepare {
                    name: name.to_string(),
                    source,
                })?;

            let link = program
                .attach()
                .map_err(|source| MoriError::ProgramAttach {
                    name: name.to_string(),
                    source,
                })?;

            links.push(link);
            log::info!("Attached LSM program: {}", name);
        }

        Ok(Self { _links: links })
    }
}

/// Get cgroup ID from cgroup file descriptor using fstat
fn get_cgroup_id(cgroup_fd: BorrowedFd<'_>) -> Result<u64, MoriError> {
    use std::os::unix::fs::MetadataExt;

    // Use fstat to get file metadata directly from fd
    // The inode number of the cgroup directory is the cgroup ID
    let metadata = std::fs::File::from(cgroup_fd.try_clone_to_owned()?).metadata()?;
    let cgroup_id = metadata.ino();

    Ok(cgroup_id)
}
