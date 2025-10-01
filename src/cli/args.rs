use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about = "Network sandbox for Linux using eBPF")]
pub struct Args {
    /// Path to configuration file (TOML)
    #[arg(long = "config", value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Allow outbound connections to the specified host[:port] (FQDN/IP)
    #[arg(long = "allow-network", value_delimiter = ',')]
    pub allow_network: Vec<String>,

    /// Command to execute
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}
