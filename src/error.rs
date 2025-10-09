use thiserror::Error;

use std::path::PathBuf;

#[cfg(target_os = "linux")]
use aya::{BtfError, EbpfError, maps::MapError, programs::ProgramError};
use hickory_resolver::ResolveError;

#[cfg(target_os = "linux")]
#[derive(Debug, Error)]
pub enum MoriError {
    #[error("failed to load eBPF object: {0}")]
    BpfLoad(#[from] EbpfError),

    #[error("program {name} not found in eBPF object")]
    ProgramNotFound { name: String },

    #[error("failed to prepare program {name}: {source}")]
    ProgramPrepare {
        name: String,
        #[source]
        source: ProgramError,
    },

    #[error("failed to attach program {name}: {source}")]
    ProgramAttach {
        name: String,
        #[source]
        source: ProgramError,
    },

    #[error("failed to initialize DNS resolver: {source}")]
    DnsResolverInit {
        #[source]
        source: ResolveError,
    },

    #[error("failed to resolve domain {domain}: {source}")]
    DnsLookup {
        domain: String,
        #[source]
        source: ResolveError,
    },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("eBPF map error: {0}")]
    Map(#[from] MapError),

    #[error("BTF error: {0}")]
    Btf(#[from] BtfError),

    #[error("invalid --allow-network entry '{entry}': {reason}")]
    InvalidAllowNetworkEntry { entry: String, reason: String },

    #[error("unsupported network protocol '{protocol}' in entry '{entry}'")]
    UnsupportedNetworkProtocol { entry: String, protocol: String },

    #[error("invalid CIDR prefix length {prefix_len} for {addr} (must be 0-{max_allowed})")]
    InvalidCidrPrefix {
        addr: std::net::Ipv4Addr,
        prefix_len: u8,
        max_allowed: u8,
    },

    #[error("failed to perform cgroup operation '{operation}' on {path}: {source}")]
    CgroupOperation {
        operation: String,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to create pipe for process synchronization: {source}")]
    PipeCreation {
        #[source]
        source: std::io::Error,
    },

    #[error("failed to fork process: {source}")]
    ProcessFork {
        #[source]
        source: nix::Error,
    },

    #[error("failed to wait for child process {pid}: {source}")]
    ProcessWait {
        pid: u32,
        #[source]
        source: nix::Error,
    },

    #[error("DNS refresh task panicked")]
    RefreshTaskPanic,

    #[error("failed to read config file {path}: {source}")]
    ConfigRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse config {path}: {source}")]
    ConfigParse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("file path too long (>= {max_len} bytes): {path}")]
    PathTooLong { path: String, max_len: usize },
}

#[cfg(target_os = "macos")]
#[derive(Debug, Error)]
pub enum MoriError {
    #[error("operation not supported on this platform")]
    Unsupported,

    #[error("failed to initialize DNS resolver: {source}")]
    DnsResolverInit {
        #[source]
        source: ResolveError,
    },

    #[error("failed to resolve domain {domain}: {source}")]
    DnsLookup {
        domain: String,
        #[source]
        source: ResolveError,
    },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid --allow-network entry '{entry}': {reason}")]
    InvalidAllowNetworkEntry { entry: String, reason: String },

    #[error("failed to spawn command '{command}': {source}")]
    CommandSpawn {
        command: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to wait for command: {source}")]
    CommandWait {
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read config file {path}: {source}")]
    ConfigRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse config {path}: {source}")]
    ConfigParse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error(
        "entry-based network policy is not supported on macOS. Use 'allow = true' or 'allow = false' instead"
    )]
    EntryBasedPolicyNotSupported,
}
