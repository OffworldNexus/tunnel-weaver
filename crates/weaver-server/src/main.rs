use clap::{CommandFactory, Parser};

/// Tunnel Weaver Relay Server.
#[derive(Parser, Debug)]
#[command(name = "weaver-server", about = "Relay server for Tunnel Weaver")]
struct Cli {}

fn main() {
    let version: &'static str = Box::leak(
        format!(
            "{} (protocol v{})",
            env!("CARGO_PKG_VERSION"),
            weaver_proto::PROTOCOL_VERSION
        )
        .into_boxed_str(),
    );

    let _matches = Cli::command().version(version).get_matches();
}
