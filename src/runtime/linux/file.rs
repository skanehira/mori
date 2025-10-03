use std::{
    convert::TryFrom,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
};

use aya::{
    maps::HashMap,
    programs::lsm::{Lsm, LsmLinkId},
    Btf, Ebpf,
};
use aya_obj::generated::{
    bpf_attach_type, bpf_attr, bpf_attr__bindgen_ty_14, bpf_attr__bindgen_ty_14__bindgen_ty_1,
    bpf_attr__bindgen_ty_14__bindgen_ty_2, bpf_cmd,
};
use libc::SYS_bpf;

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

fn attach_lsm_cgroup(
    program: &mut Lsm,
    name: &str,
    cgroup_fd: BorrowedFd<'_>,
) -> Result<OwnedFd, MoriError> {
    let prog_fd = program
        .fd()
        .map_err(|source| MoriError::ProgramAttach {
            name: name.to_string(),
            source,
        })?
        .as_fd();

    let mut attr: bpf_attr = unsafe { std::mem::zeroed() };
    let mut link_create: bpf_attr__bindgen_ty_14 = unsafe { std::mem::zeroed() };

    link_create.__bindgen_anon_1 = bpf_attr__bindgen_ty_14__bindgen_ty_1 {
        prog_fd: prog_fd.as_raw_fd() as u32,
    };
    link_create.__bindgen_anon_2 = bpf_attr__bindgen_ty_14__bindgen_ty_2 {
        target_fd: cgroup_fd.as_raw_fd() as u32,
    };
    link_create.attach_type = bpf_attach_type::BPF_LSM_CGROUP as u32;
    link_create.flags = 0;

    attr.link_create = link_create;

    let ret = unsafe {
        libc::syscall(
            SYS_bpf,
            bpf_cmd::BPF_LINK_CREATE as libc::c_long,
            &mut attr as *mut _,
            std::mem::size_of::<bpf_attr>(),
        )
    };

    if ret < 0 {
        return Err(MoriError::Io(std::io::Error::last_os_error()));
    }

    // SAFETY: on success syscall returns a new FD we must own
    let fd = unsafe { OwnedFd::from_raw_fd(ret as RawFd) };
    Ok(fd)
}
