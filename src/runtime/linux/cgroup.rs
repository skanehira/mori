use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::fd::{AsRawFd, BorrowedFd},
    path::PathBuf,
    process,
};

use crate::error::MoriError;

/// Cgroup manager that creates and manages a cgroup for process isolation
pub(super) struct CgroupManager {
    cgroup_path: PathBuf,
    cgroup_file: File,
}

impl CgroupManager {
    /// Create a new cgroup and return a manager for it
    pub(super) fn create() -> Result<Self, MoriError> {
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
    pub(super) fn fd(&self) -> BorrowedFd<'_> {
        unsafe { BorrowedFd::borrow_raw(self.cgroup_file.as_raw_fd()) }
    }

    /// Add a process to this cgroup
    pub(super) fn add_process(&self, pid: u32) -> Result<(), MoriError> {
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
