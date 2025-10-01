use std::path::PathBuf;

use clap::Parser;
use mori::{config::ConfigFile, policy::NetworkPolicy, runtime::execute_with_network_control};

#[derive(Parser, Debug)]
#[command(author, version, about = "Network sandbox for Linux using eBPF")]
struct Args {
    /// Path to configuration file (TOML)
    #[arg(long = "config", value_name = "PATH")]
    config: Option<PathBuf>,

    /// Allow outbound connections to the specified host[:port] (FQDN/IP)
    #[arg(long = "allow-network", value_delimiter = ',')]
    allow_network: Vec<String>,

    /// Command to execute
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Args::parse();

    let command = &args.command[0];
    let command_args: Vec<&str> = args.command[1..].iter().map(String::as_str).collect();

    let mut policy = NetworkPolicy::new();

    if let Some(config_path) = args.config.as_ref() {
        let config = ConfigFile::load(config_path)?;
        let config_policy = config.to_policy()?;
        policy.merge(config_policy);
    }

    let cli_policy = NetworkPolicy::from_entries(&args.allow_network)?;
    policy.merge(cli_policy);

    let exit_code = execute_with_network_control(command, &command_args, &policy)?;
    std::process::exit(exit_code);
}
