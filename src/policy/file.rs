use std::path::{Path, PathBuf};

/// Access mode for file operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    Read = 1,
    Write = 2,
    ReadWrite = 3,
}

/// File access policy (deny-list mode: all paths allowed except those in the deny list)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FilePolicy {
    /// List of denied file paths with their access modes
    pub denied_paths: Vec<(PathBuf, AccessMode)>,
}

impl FilePolicy {
    /// Create a new empty file policy
    pub fn new() -> Self {
        Self {
            denied_paths: Vec::new(),
        }
    }

    /// Add a path to deny read access
    pub fn deny_read<P: AsRef<Path>>(&mut self, path: P) {
        let path = self.normalize_path(path.as_ref());
        self.denied_paths.push((path, AccessMode::Read));
    }

    /// Add a path to deny write access
    pub fn deny_write<P: AsRef<Path>>(&mut self, path: P) {
        let path = self.normalize_path(path.as_ref());
        self.denied_paths.push((path, AccessMode::Write));
    }

    /// Add a path to deny read and write access
    pub fn deny_read_write<P: AsRef<Path>>(&mut self, path: P) {
        let path = self.normalize_path(path.as_ref());
        self.denied_paths.push((path, AccessMode::ReadWrite));
    }

    /// Normalize a path to absolute form
    fn normalize_path(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("/"))
                .join(path)
        }
    }
}
