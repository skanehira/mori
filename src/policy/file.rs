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

    /// Normalize a path to absolute form, resolving `.` and `..` components
    fn normalize_path(&self, path: &Path) -> PathBuf {
        // Convert to absolute path first
        let absolute = std::path::absolute(path).unwrap_or_else(|_| {
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("/"))
                    .join(path)
            }
        });

        // Manually resolve . and .. components since std::path::absolute doesn't do this
        let mut normalized = PathBuf::new();
        for component in absolute.components() {
            match component {
                std::path::Component::CurDir => {
                    // Skip "." components
                }
                std::path::Component::ParentDir => {
                    // ".." - pop the last component
                    normalized.pop();
                }
                comp => {
                    // Normal component (RootDir, Prefix, Normal)
                    normalized.push(comp);
                }
            }
        }

        normalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::env;

    #[rstest]
    #[case("/tmp/test.txt", "/tmp/test.txt")]
    #[case("/tmp/foo/../bar.txt", "/tmp/bar.txt")]
    #[case("/tmp/./foo/./bar.txt", "/tmp/foo/bar.txt")]
    #[case("/tmp/foo/bar/../baz.txt", "/tmp/foo/baz.txt")]
    fn normalize_path_with_absolute_paths(#[case] input: &str, #[case] expected: &str) {
        let policy = FilePolicy::new();
        let normalized = policy.normalize_path(Path::new(input));
        assert_eq!(normalized, PathBuf::from(expected));
    }

    #[rstest]
    #[case("test.txt", "test.txt")]
    #[case("./test.txt", "test.txt")]
    #[case("foo/bar.txt", "foo/bar.txt")]
    fn normalize_path_with_simple_relative_paths(#[case] input: &str, #[case] rel_expected: &str) {
        let policy = FilePolicy::new();
        let normalized = policy.normalize_path(Path::new(input));
        let expected = env::current_dir().unwrap().join(rel_expected);
        assert_eq!(normalized, expected);
    }

    #[test]
    fn normalize_path_with_parent_directory() {
        let policy = FilePolicy::new();
        let normalized = policy.normalize_path(Path::new("../test.txt"));

        let current = env::current_dir().unwrap();
        let expected = current.parent().unwrap().join("test.txt");
        assert_eq!(normalized, expected);
    }

    #[test]
    fn normalize_path_with_multiple_parent_directories() {
        let policy = FilePolicy::new();
        let normalized = policy.normalize_path(Path::new("../../test.txt"));

        let current = env::current_dir().unwrap();
        let expected = current.parent().unwrap().parent().unwrap().join("test.txt");
        assert_eq!(normalized, expected);
    }

    #[test]
    fn normalize_path_with_mixed_components() {
        let policy = FilePolicy::new();
        let normalized = policy.normalize_path(Path::new("./foo/../bar/./baz.txt"));

        // ./foo/../bar/./baz.txt should become current_dir/bar/baz.txt
        let expected = env::current_dir().unwrap().join("bar").join("baz.txt");
        assert_eq!(normalized, expected);
    }
}
