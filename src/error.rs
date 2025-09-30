use thiserror::Error;

#[cfg(target_os = "linux")]
use aya::{EbpfError, maps::MapError, programs::ProgramError};
use hickory_resolver::error::ResolveError;

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

    #[error("invalid --allow-network entry '{entry}': {reason}")]
    InvalidAllowNetworkEntry { entry: String, reason: String },
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Error)]
pub enum MoriError {
    #[error("operation not supported on this platform")]
    Unsupported,
}
