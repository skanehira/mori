use thiserror::Error;

#[cfg(target_os = "linux")]
use aya::{EbpfError, programs::ProgramError};

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

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Error)]
pub enum MoriError {
    #[error("operation not supported on this platform")]
    Unsupported,
}
