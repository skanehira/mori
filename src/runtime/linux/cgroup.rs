use std::{
    fs::{self, File},
    os::fd::{AsRawFd, BorrowedFd},
    path::PathBuf,
    process,
};

use crate::error::MoriError;

/// Cgroup manager that creates and manages a cgroup for process isolation
pub struct CgroupManager {
    pub path: PathBuf,
    file: File,
}

impl CgroupManager {
    /// Create a new cgroup and return a manager for it
    pub fn create() -> Result<Self, MoriError> {
        // Create a unique cgroup directory under /sys/fs/cgroup/
        let cgroup_name = format!("mori-{}", process::id());
        let cgroup_path = PathBuf::from("/sys/fs/cgroup").join(cgroup_name);

        fs::create_dir_all(&cgroup_path)?;

        // Change ownership to SUDO_UID/SUDO_GID if running under sudo
        // This allows the child process to write to cgroup.procs after dropping privileges
        if let (Ok(uid_str), Ok(gid_str)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID"))
            && let (Ok(uid), Ok(gid)) = (uid_str.parse::<u32>(), gid_str.parse::<u32>())
        {
            use std::os::unix::fs::chown;
            chown(&cgroup_path, Some(uid), Some(gid))?;
        }

        let cgroup_file = File::open(&cgroup_path)?;

        Ok(Self {
            path: cgroup_path,
            file: cgroup_file,
        })
    }

    /// Get a borrowed file descriptor for the cgroup
    pub fn fd(&self) -> BorrowedFd<'_> {
        unsafe { BorrowedFd::borrow_raw(self.file.as_raw_fd()) }
    }
}

impl Drop for CgroupManager {
    fn drop(&mut self) {
        // Clean up the cgroup directory when dropped
        let _ = fs::remove_dir(&self.path);
    }
}
