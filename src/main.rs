use clap::Parser;
use mori::{
    cli::{Args, PolicyLoader},
    runtime::execute_with_control,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Args::parse();

    let command = &args.command[0];
    let command_args: Vec<&str> = args.command[1..].iter().map(String::as_str).collect();

    let policy = PolicyLoader::load(&args)?;

    let exit_code = execute_with_control(command, &command_args, &policy).await?;
    std::process::exit(exit_code);
}
