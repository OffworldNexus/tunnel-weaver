//! Tunnel Weaver client CLI.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

pub mod connect;
pub mod identity;
pub mod log;
pub mod pool;
pub mod proxy;
pub mod rewrite;
pub mod start;
pub mod status;
pub mod target;

fn version_str() -> &'static str {
    Box::leak(
        format!(
            "{} (protocol v{})",
            env!("CARGO_PKG_VERSION"),
            weaver_proto::PROTOCOL_VERSION
        )
        .into_boxed_str(),
    )
}

#[derive(Parser, Debug)]
#[command(
    name = "weave",
    version = version_str(),
    about = "Client for Tunnel Weaver reverse proxy and tunnels"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Expose one or more local services through the relay.
    Start(StartArgs),
}

#[derive(Args, Debug)]
struct StartArgs {
    /// One `<service>=<target>` mapping, repeatable. A target is
    /// `[host:]port`, `http://host[:port]` or `https://host[:port]`; a bare
    /// port means `http://localhost:<port>`.
    #[arg(value_name = "SERVICE=TARGET", required = true)]
    services: Vec<String>,

    /// Relay server address to connect to (<host> or <host>:<port>).
    #[arg(long)]
    server: String,

    /// Extra root CA certificate (PEM) for the relay connection. Distinct
    /// from --insecure-target, which disables verification of a *target*.
    #[arg(long)]
    insecure_root_ca: Option<PathBuf>,

    /// Disable TLS verification for this service's target (repeatable).
    #[arg(long, value_name = "SERVICE")]
    insecure_target: Vec<String>,

    /// Keep the public hostname for this service instead of rewriting Host
    /// to the target host (repeatable).
    #[arg(long, value_name = "SERVICE")]
    preserve_host: Vec<String>,

    /// Disable URL and cookie rewriting for this service (repeatable).
    #[arg(long, value_name = "SERVICE")]
    no_rewrite: Vec<String>,

    /// Keep visitor-supplied Forwarded / X-Forwarded-* headers instead of
    /// replacing them with the canonical ones (repeatable).
    #[arg(long, value_name = "SERVICE")]
    append_forwarded: Vec<String>,

    /// Silence the per-request log.
    #[arg(long)]
    quiet: bool,

    /// Add request and response headers to the per-request log.
    #[arg(long)]
    verbose: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Start(args) => {
            if let Err(err) = run_start(args).await {
                eprintln!("Error: {err}");
                std::process::exit(1);
            }
        }
    }
}

async fn run_start(args: StartArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let specs = target::parse_specs(&args.services)?;
    let known: Vec<&str> = specs.iter().map(|s| s.service.as_str()).collect();
    for (flag, list) in [
        ("--insecure-target", &args.insecure_target),
        ("--preserve-host", &args.preserve_host),
        ("--no-rewrite", &args.no_rewrite),
        ("--append-forwarded", &args.append_forwarded),
    ] {
        for service in list {
            if !known.contains(&service.as_str()) {
                return Err(format!("{flag}: unknown service '{service}'").into());
            }
        }
    }
    let opts = start::StartOptions {
        specs,
        server: args.server,
        insecure_root_ca: args.insecure_root_ca,
        insecure_targets: args.insecure_target,
        preserve_host: args.preserve_host,
        no_rewrite: args.no_rewrite,
        append_forwarded: args.append_forwarded,
        quiet: args.quiet,
        verbose: args.verbose,
    };
    start::run_start(opts).await
}
