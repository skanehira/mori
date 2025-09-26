use clap::Parser;
use std::net::Ipv4Addr;

#[cfg(target_os = "linux")]
use mori::runtime::linux::execute_with_network_control;

#[derive(Parser, Debug)]
#[command(author, version, about = "Network sandbox for Linux using eBPF")]
struct Args {
    /// Allow connections to this IPv4 address
    #[arg(long)]
    allow_ipv4: Vec<Ipv4Addr>,

    /// Command to execute
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Args::parse();

    if args.command.is_empty() {
        eprintln!("Error: Command is required");
        std::process::exit(1);
    }

    let command = &args.command[0];
    let command_args: Vec<&str> = args.command[1..].iter().map(String::as_str).collect();

    #[cfg(target_os = "linux")]
    {
        let exit_code = execute_with_network_control(command, &command_args, &args.allow_ipv4)?;
        std::process::exit(exit_code);
    }

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("Error: This program only works on Linux");
        std::process::exit(1);
    }
}
