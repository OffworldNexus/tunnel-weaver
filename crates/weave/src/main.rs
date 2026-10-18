//! Tunnel Weaver client CLI.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use weave::{host, pair, relays, start, store, target, ui, unpair};

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
    /// Expose one or more local services through a relay.
    Start(StartArgs),
    /// Pair this machine with a relay.
    Pair(PairArgs),
    /// Revoke this machine on a relay and forget it.
    Unpair(UnpairArgs),
    /// List the relays this machine is paired with, or change the default.
    Relays(RelaysArgs),
}

#[derive(Args, Debug)]
struct StartArgs {
    /// One `<service>=<target>` mapping, repeatable. A target is
    /// `[host:]port`, `http://host[:port]` or `https://host[:port]`; a bare
    /// port means `http://localhost:<port>`.
    #[arg(value_name = "SERVICE=TARGET", required = true)]
    services: Vec<String>,

    /// The paired relay to connect to, by admin host. Defaults to the default
    /// relay (see `weave relays`).
    #[arg(long)]
    server: Option<String>,

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

#[derive(Args, Debug)]
struct PairArgs {
    /// The relay's admin host (`host` or `host:port`).
    #[arg(value_name = "ADMIN-HOST")]
    admin_host: String,

    /// Move an existing machine onto this machine's key, by the id it was
    /// paired as (see `weave relays`). By default the CLI decides: a relay that
    /// knows this machine under a lost key gets the same machine back.
    #[arg(long, value_name = "ID")]
    machine: Option<i32>,

    /// Minimum key security: `file`, `keyring`, `sealed` or `hardware`.
    #[arg(long, value_name = "LEVEL", default_value = pair::DEFAULT_FLOOR)]
    min_key_security: String,

    /// Accept a device key below --min-key-security without prompting.
    /// Required when stdin is not a terminal.
    #[arg(long)]
    allow_below_floor: bool,

    /// Extra root CA certificate (PEM) for the relay connection.
    #[arg(long)]
    insecure_root_ca: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct UnpairArgs {
    /// The relay to unpair from. Defaults to the default relay.
    #[arg(value_name = "ADMIN-HOST")]
    admin_host: Option<String>,

    /// Forget the relay without asking it to revoke this machine. Leaves the
    /// machine authorised on the relay until it is revoked there.
    #[arg(long)]
    local_only: bool,
}

#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
struct RelaysArgs {
    #[command(subcommand)]
    command: Option<RelaysCommand>,
}

#[derive(Subcommand, Debug)]
enum RelaysCommand {
    /// List paired relays (the default when no subcommand is given).
    List,
    /// Make a paired relay the default.
    Default {
        /// The relay's admin host.
        #[arg(value_name = "ADMIN-HOST")]
        admin_host: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Start(args) => run_start(args).await,
        Commands::Pair(args) => run_pair(args).await,
        Commands::Unpair(args) => {
            unpair::run_unpair(args.admin_host.as_deref(), args.local_only).await
        }
        Commands::Relays(args) => match args.command {
            None | Some(RelaysCommand::List) => relays::run_list().await,
            Some(RelaysCommand::Default { admin_host }) => {
                relays::run_set_default(&admin_host).await
            }
        },
    };
    if let Err(err) = result {
        ui::report(err.as_ref());
        std::process::exit(1);
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

    // Resolve the relay before touching the network: `--server` if given, else
    // the default one.
    let store = store::Store::open_default().await?;
    let relay = match &args.server {
        Some(requested) => {
            let host = host::normalize_admin_host(requested)?;
            store.relay(&host).await?.ok_or_else(|| {
                ui::hinted(
                    format!("this machine is not paired with {host}"),
                    format!("run `weave pair {host}` first"),
                )
            })?
        }
        None => store.default_relay().await?.ok_or_else(|| {
            ui::hinted(
                "this machine is not paired with any relay",
                "run `weave pair <admin-host>` first",
            )
        })?,
    };

    let opts = start::StartOptions {
        specs,
        server: relay.admin_host,
        signer: start::SignerSpec::Tpmd {
            key_id: relay.key_id,
        },
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

async fn run_pair(args: PairArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    pair::run_pair(pair::PairOptions {
        admin_host: args.admin_host,
        machine: args.machine,
        min_key_security: args.min_key_security,
        allow_below_floor: args.allow_below_floor,
        insecure_root_ca: args.insecure_root_ca,
    })
    .await
}
