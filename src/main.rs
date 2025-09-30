use clap::Parser;
use mori::runtime::execute_with_network_control;

#[derive(Parser, Debug)]
#[command(author, version, about = "Network sandbox for Linux using eBPF")]
struct Args {
    /// Allow outbound connections to the specified host[:port] (FQDN/IP/CIDR)
    #[arg(long = "allow-network", value_delimiter = ',')]
    allow_network: Vec<String>,

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

    let exit_code = execute_with_network_control(command, &command_args, &args.allow_network)?;
    std::process::exit(exit_code);
}
