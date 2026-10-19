//! Tunnel Weaver client CLI.

mod report;
mod term;
mod tunnel;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Args, CommandFactory, Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use weave::host::normalize_admin_host;
use weave::store::Relay;
use weave::{Client, Error, PairRequest, SecurityLevel, StartOptions, Store, Tpmd};

use crate::report::{TermReporter, report_error};
use crate::term::Stream;

fn version() -> &'static str {
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
    version = version(),
    about = "Client for Tunnel Weaver reverse proxy and tunnels"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Trust only this root CA certificate (PEM) for the relay connection.
    /// Distinct from --insecure-target, which disables verification of a
    /// *target*.
    #[arg(long, global = true, value_name = "PEM")]
    insecure_root_ca: Option<PathBuf>,
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
    #[arg(long, value_parser = admin_host)]
    server: Option<String>,

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
    #[arg(value_name = "ADMIN-HOST", value_parser = admin_host)]
    admin_host: String,

    /// Move an existing machine onto this machine's key, by the id it was
    /// paired as (see `weave relays`). By default the CLI decides: a relay that
    /// knows this machine under a lost key gets the same machine back.
    #[arg(long, value_name = "ID")]
    machine: Option<i32>,

    /// Minimum key security: `file`, `keyring`, `sealed` or `hardware`.
    #[arg(long, value_name = "LEVEL", default_value = "sealed", value_parser = security_level)]
    min_key_security: SecurityLevel,

    /// Accept a device key below --min-key-security without prompting.
    /// Required when stdin is not a terminal.
    #[arg(long)]
    allow_below_floor: bool,
}

#[derive(Args, Debug)]
struct UnpairArgs {
    /// The relay to unpair from. Defaults to the default relay.
    #[arg(value_name = "ADMIN-HOST", value_parser = admin_host)]
    admin_host: Option<String>,
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
        #[arg(value_name = "ADMIN-HOST", value_parser = admin_host)]
        admin_host: String,
    },
}

fn admin_host(raw: &str) -> Result<String, String> {
    normalize_admin_host(raw).map_err(|e| e.to_string())
}

fn security_level(raw: &str) -> Result<SecurityLevel, String> {
    SecurityLevel::parse(raw).ok_or_else(|| {
        format!("unknown key security level '{raw}' (use one of: file, keyring, sealed, hardware)")
    })
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let reporter = Arc::new(match &cli.command {
        Commands::Start(args) => TermReporter::new(args.quiet, args.verbose),
        _ => TermReporter::new(false, false),
    });
    let result = run(cli, Arc::clone(&reporter)).await;
    reporter.finish();
    if let Err(error) = result {
        report_error(&error);
        std::process::exit(1);
    }
}

async fn run(cli: Cli, reporter: Arc<TermReporter>) -> Result<(), Error> {
    // Checked before the store is touched.
    let start = match &cli.command {
        Commands::Start(args) => Some(start_options(args).unwrap_or_else(|message| {
            Cli::command()
                .error(clap::error::ErrorKind::InvalidValue, message)
                .exit()
        })),
        _ => None,
    };
    let client = Client::new(Store::open_default().await?, Box::new(Tpmd), reporter)
        .with_root_ca(cli.insecure_root_ca);
    match cli.command {
        Commands::Start(_) => {
            let shutdown = CancellationToken::new();
            tokio::spawn({
                let shutdown = shutdown.clone();
                async move {
                    if tokio::signal::ctrl_c().await.is_ok() {
                        shutdown.cancel();
                    }
                }
            });
            let opts = start.expect("parsed above");
            client.start(&opts, shutdown).await?;
            term::success(Stream::Err, "Stopped");
        }
        Commands::Pair(args) => {
            let request = PairRequest {
                admin_host: args.admin_host,
                machine: args.machine,
                floor: args.min_key_security,
                allow_below_floor: args.allow_below_floor,
            };
            let paired = cancellable(client.pair(&request)).await?;
            let default = if paired.is_default {
                format!(" {}", term::dim(Stream::Out, "\u{2014} default relay"))
            } else {
                String::new()
            };
            term::success(
                Stream::Out,
                &format!(
                    "Paired as {} {}{default}",
                    term::accent(
                        Stream::Out,
                        &format!("{}/{}", paired.person, paired.machine)
                    ),
                    term::dim(Stream::Out, &format!("(machine {})", paired.machine_id)),
                ),
            );
            term::hint(&if paired.is_default {
                "next: weave start <service>=<port>".to_string()
            } else {
                format!(
                    "next: weave start --server {} <service>=<port>",
                    paired.host
                )
            });
        }
        Commands::Unpair(args) => {
            let unpaired = cancellable(client.unpair(&args.admin_host.unwrap_or_default())).await?;
            let host = term::accent(Stream::Out, &unpaired.host);
            term::success(
                Stream::Out,
                &if unpaired.revoked {
                    format!("Revoked this machine on {host} and unpaired it")
                } else {
                    format!("Unpaired {host}")
                },
            );
            let arrow = term::dim(Stream::Out, term::ARROW);
            if !unpaired.new_default.is_empty() {
                let next = term::accent(Stream::Out, &unpaired.new_default);
                term::step(
                    Stream::Out,
                    &arrow,
                    &format!("{next} is now the default relay"),
                );
            } else if unpaired.remaining == 0 {
                term::step(
                    Stream::Out,
                    &arrow,
                    "This machine is no longer paired with any relay",
                );
            }
        }
        Commands::Relays(args) => match args.command {
            None | Some(RelaysCommand::List) => {
                let relays = client.relays().await?;
                if relays.is_empty() {
                    return Err(Error::NoRelay);
                }
                for line in render_relays(&relays) {
                    println!("{line}");
                }
            }
            Some(RelaysCommand::Default { admin_host }) => {
                let relay = client.set_default(&admin_host).await?;
                term::success(
                    Stream::Out,
                    &format!(
                        "{} is now the default relay",
                        term::accent(Stream::Out, &relay.admin_host)
                    ),
                );
            }
        },
    }
    Ok(())
}

/// Ends `command` on Ctrl-C. Dropping it closes its connection, which is what
/// cancels a pending pairing on the relay.
async fn cancellable<T>(command: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
    tokio::select! {
        result = command => result,
        _ = tokio::signal::ctrl_c() => {
            term::error("cancelled");
            std::process::exit(130);
        }
    }
}

/// The services to start, with their per-service flags applied.
fn start_options(args: &StartArgs) -> Result<StartOptions, String> {
    let mut services = weave::parse_specs(&args.services)?;
    for (flag, names) in [
        ("--insecure-target", &args.insecure_target),
        ("--preserve-host", &args.preserve_host),
        ("--no-rewrite", &args.no_rewrite),
        ("--append-forwarded", &args.append_forwarded),
    ] {
        for name in names {
            let Some(spec) = services.iter_mut().find(|s| &s.service == name) else {
                return Err(format!("{flag}: unknown service '{name}'"));
            };
            match flag {
                "--insecure-target" => spec.insecure = true,
                "--preserve-host" => spec.preserve_host = true,
                "--no-rewrite" => spec.no_rewrite = true,
                _ => spec.append_forwarded = true,
            }
        }
    }
    Ok(StartOptions {
        server: args.server.clone().unwrap_or_default(),
        services,
    })
}

/// One aligned row per relay: marker, host, machine, key, default tag.
fn render_relays(relays: &[Relay]) -> Vec<String> {
    let host_width = relays.iter().map(|r| r.admin_host.len()).max().unwrap_or(0);
    let machine_width = relays
        .iter()
        .map(|r| r.machine_id.to_string().len())
        .max()
        .unwrap_or(0);
    relays
        .iter()
        .map(|r| {
            let host = format!("{:<host_width$}", r.admin_host);
            let (marker, host, tag) = if r.is_default {
                (
                    term::green(Stream::Out, term::STAR),
                    term::accent(Stream::Out, &host),
                    format!("  {}", term::green(Stream::Out, "default")),
                )
            } else {
                (
                    " ".to_string(),
                    term::bold(Stream::Out, &host),
                    String::new(),
                )
            };
            let machine = format!("machine {:<machine_width$}", r.machine_id);
            format!(
                "{marker} {host}  {}  {}{tag}",
                term::dim(Stream::Out, &machine),
                term::dim(Stream::Out, &term::short_fingerprint(&r.key_id)),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_rows_are_aligned_and_mark_the_default() {
        let key = format!("p256:0271af4a{}8329", "0".repeat(54));
        let relay = |id, host: &str, machine_id, is_default| Relay {
            id,
            admin_host: host.into(),
            machine_id,
            key_id: key.clone(),
            is_default,
        };
        assert_eq!(
            render_relays(&[
                relay(2, "weaver1.offworld.nexus", 7, true),
                relay(1, "relay.example:8443", 12, false),
            ]),
            [
                "\u{2605} weaver1.offworld.nexus  machine 7   p256:0271af4a\u{2026}8329  default",
                "  relay.example:8443      machine 12  p256:0271af4a\u{2026}8329",
            ]
        );
    }
}
