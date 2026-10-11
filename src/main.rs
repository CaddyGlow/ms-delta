use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about = "Native Rust PA30, PA31 and MS-PATCH file patches")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect a PA30 or PA31 header without reconstructing its payload.
    Inspect(ms_delta::cli::InspectArgs),
    /// Reconstruct one file without overwriting an existing output.
    Apply(ms_delta::cli::ApplyArgs),
    /// Create a patch without overwriting an existing output.
    Create(ms_delta::cli::CreateArgs),
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Args::parse().command {
        Command::Inspect(args) => ms_delta::cli::inspect(&args)?,
        Command::Apply(args) => ms_delta::cli::apply(&args)?,
        Command::Create(args) => ms_delta::cli::create(&args)?,
    }
    Ok(())
}
