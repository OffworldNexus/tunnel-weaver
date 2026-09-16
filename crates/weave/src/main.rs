//! Tunnel Weaver client CLI.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

pub mod connect;
pub mod poc;

const VERSION_STR: &str = concat!(env!("CARGO_PKG_VERSION"), " (protocol v", "1", ")");

#[derive(Parser, Debug)]
#[command(
    name = "weave",
    version = VERSION_STR,
    about = "Client for Tunnel Weaver reverse proxy and tunnels"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Proof-of-concept tunnel client registering a single transient service.
    Poc(PocArgs),
}

#[derive(Args, Debug)]
struct PocArgs {
    /// Service name to register (e.g. "web").
    service: String,

    /// Relay server address to connect to (<host> or <host>:<port>).
    #[arg(long)]
    server: String,

    /// Custom root CA certificate PEM file for testing against local CAs.
    #[arg(long)]
    insecure_root_ca: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Poc(args) => {
            if let Err(err) =
                poc::run_poc(args.service, args.server, args.insecure_root_ca.as_deref()).await
            {
                eprintln!("Error: {err}");
                std::process::exit(1);
            }
        }
    }
}
