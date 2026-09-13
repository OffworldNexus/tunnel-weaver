use clap::Parser;

/// Tunnel Weaver Client.
#[derive(Parser, Debug)]
#[command(
    name = "weave",
    version,
    about = "Client for Tunnel Weaver reverse proxy and tunnels"
)]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
}
