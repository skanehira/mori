use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Network and file access sandbox for Linux using eBPF"
)]
pub struct Args {
    /// Path to configuration file (TOML)
    #[arg(long = "config", value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Allow outbound connections to the specified host[:port] (FQDN/IP)
    #[cfg(not(target_os = "macos"))]
    #[arg(long = "allow-network", value_delimiter = ',')]
    pub allow_network: Vec<String>,

    /// Allow all outbound network connections
    #[arg(long = "allow-network-all")]
    pub allow_network_all: bool,

    /// Deny file read/write access to the specified paths (all other paths are allowed)
    #[arg(long = "deny-file", value_delimiter = ',')]
    pub deny_file: Vec<PathBuf>,

    /// Deny file read access to the specified paths (all other paths are allowed)
    #[arg(long = "deny-file-read", value_delimiter = ',')]
    pub deny_file_read: Vec<PathBuf>,

    /// Deny file write access to the specified paths (all other paths are allowed)
    #[arg(long = "deny-file-write", value_delimiter = ',')]
    pub deny_file_write: Vec<PathBuf>,

    /// Command to execute
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}
