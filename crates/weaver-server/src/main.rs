use std::path::PathBuf;

use clap::{CommandFactory, FromArgMatches, Parser};

/// Tunnel Weaver Relay Server.
#[derive(Parser, Debug, Clone)]
#[command(name = "weaver-server", about = "Relay server for Tunnel Weaver")]
pub struct Cli {
    /// Path to the SQLite state database.
    #[arg(
        long,
        env = "WEAVER_DB",
        default_value = "/var/lib/weaver/weaver.db",
        global = true,
        value_name = "PATH"
    )]
    pub db: PathBuf,
}

fn main() {
    let version: &'static str = Box::leak(
        format!(
            "{} (protocol v{})",
            env!("CARGO_PKG_VERSION"),
            weaver_proto::PROTOCOL_VERSION
        )
        .into_boxed_str(),
    );

    let matches = Cli::command().version(version).get_matches();
    let _cli = Cli::from_arg_matches(&matches).unwrap_or_else(|err| err.exit());
}
