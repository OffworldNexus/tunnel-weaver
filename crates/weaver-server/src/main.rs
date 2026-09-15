use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use weaver_server::server::{self, EX_CONFIG, ServerError};
use weaver_server::{Config, Store};

/// Subcommands supported by `weaver-server`.
#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Runs the long-running Tunnel Weaver relay server daemon.
    Run,

    /// Configures or initializes the SQLite state store with required settings.
    #[command(alias = "init")]
    Configure(Box<ConfigureArgs>),

    /// Displays the supported ACME provider catalog.
    Providers,

    /// Displays runtime server status, listeners, and certificate counts.
    Status {
        /// Outputs the status response as raw JSON.
        #[arg(long)]
        json: bool,
    },

    /// Inspects and manages certificates on the running server.
    Cert {
        #[command(subcommand)]
        command: CertCommands,
    },

    /// Performs an online backup of the SQLite database to the specified path.
    Backup {
        /// Target destination path for SQLite VACUUM INTO backup.
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Outputs the backup response as raw JSON.
        #[arg(long)]
        json: bool,
    },

    /// Initiates a graceful shutdown of the running server daemon.
    Shutdown {
        /// Outputs the shutdown response as raw JSON.
        #[arg(long)]
        json: bool,
    },
}

/// Subcommands for certificate operations.
#[derive(Subcommand, Debug, Clone)]
pub enum CertCommands {
    /// Shows certificate summary table or detailed status for a single hostname.
    Status {
        /// Hostname to inspect (or "root" for base domain). If omitted, displays all certificates.
        #[arg(value_name = "NAME")]
        name: Option<String>,

        /// Maximum number of historical cert events to return in detail view (default: 10).
        #[arg(long)]
        limit: Option<usize>,

        /// Outputs the result as raw JSON.
        #[arg(long)]
        json: bool,
    },

    /// Streams certificate state transitions until Issued or Failed.
    Wait {
        /// Hostname to wait for (defaults to root domain).
        #[arg(value_name = "NAME")]
        name: Option<String>,

        /// Maximum timeout in seconds (default: 300).
        #[arg(long, value_name = "SECS")]
        timeout: Option<u64>,

        /// Outputs streamed transitions as raw JSON lines.
        #[arg(long)]
        json: bool,
    },

    /// Manually triggers renewal for a hostname or all active certificates.
    Renew {
        /// Hostname to renew (defaults to root domain).
        #[arg(value_name = "NAME", conflicts_with = "all")]
        name: Option<String>,

        /// Renew all active hostnames plus the root domain.
        #[arg(long)]
        all: bool,

        /// Bypass rate limits and in-flight concurrency caps.
        #[arg(long)]
        force: bool,

        /// Wait for renewal to complete (streams transitions until Issued or Failed).
        #[arg(long)]
        wait: bool,

        /// Outputs the renewal response as raw JSON.
        #[arg(long)]
        json: bool,
    },
}

/// Parses a socket address or bare port (e.g. "8080" or ":8080" -> "[::]:8080").
pub fn parse_listen_addr(s: &str) -> Result<SocketAddr, String> {
    let trimmed = s.trim();
    let port_str = trimmed.strip_prefix(':').unwrap_or(trimmed);
    if let Ok(port) = port_str.parse::<u16>() {
        return Ok(SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            port,
        ));
    }
    trimmed.parse::<SocketAddr>().map_err(|e| e.to_string())
}

/// Validates that a hostname argument is a valid FQDN or the alias "root".
fn validate_cert_name(name: &Option<String>) {
    if let Some(n) = name
        && n != "root"
        && !n.contains('.')
    {
        eprintln!(
            "Error: Invalid hostname '{n}'. Must be a fully qualified domain name (containing '.') or 'root'."
        );
        std::process::exit(2);
    }
}

/// Arguments for initializing or updating the server configuration.
#[derive(Args, Debug, Clone)]
pub struct ConfigureArgs {
    /// Base domain for routed public tunnels (e.g. "example.com").
    #[arg(long, value_name = "DOMAIN")]
    pub root_domain: String,

    /// Administrator contact email for ACME registration.
    #[arg(long, value_name = "EMAIL")]
    pub admin_email: String,

    /// ACME directory provider (default: letsencrypt-staging).
    #[arg(long, default_value = "letsencrypt-staging", value_name = "PROVIDER")]
    pub acme_provider: String,

    /// HTTP listen socket address or port (e.g. 80, 8080, [::]:80, 0.0.0.0:80).
    #[arg(
        long,
        default_value = "[::]:80",
        value_parser = parse_listen_addr,
        value_name = "ADDR_OR_PORT"
    )]
    pub listen_http: SocketAddr,

    /// HTTPS listen socket address or port (e.g. 443, 8443, [::]:443, 0.0.0.0:443).
    #[arg(
        long,
        default_value = "[::]:443",
        value_parser = parse_listen_addr,
        value_name = "ADDR_OR_PORT"
    )]
    pub listen_https: SocketAddr,

    /// Filesystem path for the UNIX domain control socket.
    #[arg(long, default_value = "/run/weaver/control.sock", value_name = "PATH")]
    pub control_socket: PathBuf,

    /// Custom ACME directory URL (required when acme_provider is "custom").
    #[arg(long, value_name = "URL")]
    pub acme_directory: Option<String>,

    /// External Account Binding Key Identifier.
    #[arg(long, value_name = "KID")]
    pub acme_eab_kid: Option<String>,

    /// External Account Binding HMAC key.
    #[arg(long, value_name = "HMAC")]
    pub acme_eab_hmac: Option<String>,

    /// Optional path to custom Root CA certificate file in PEM format.
    #[arg(long, value_name = "PATH")]
    pub acme_root_ca: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    let version: &'static str = Box::leak(
        format!(
            "{} (protocol v{})",
            env!("CARGO_PKG_VERSION"),
            weaver_proto::PROTOCOL_VERSION
        )
        .into_boxed_str(),
    );

    let matches = Cli::command().version(version).get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|err| err.exit());

    // Configure structured stderr logging
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level));

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .init();

    match cli.command {
        Commands::Run => {
            let Some(db_path) = cli.db else {
                eprintln!(
                    "Error: Database path is required to start the server. Pass --db <PATH> or set WEAVER_DB."
                );
                std::process::exit(2);
            };

            if let Err(err) = server::run_server(db_path, None).await {
                match err {
                    ServerError::MissingConfig(keys) => {
                        eprintln!("Configuration missing required keys: {}", keys.join(", "));
                        std::process::exit(EX_CONFIG);
                    }
                    ServerError::ValidationConfig(issues) => {
                        eprintln!("Configuration validation failed: {}", issues.join("; "));
                        std::process::exit(EX_CONFIG);
                    }
                    ServerError::Bind { addr, source } => {
                        eprintln!("Failed to bind {addr}: {source}");
                        std::process::exit(1);
                    }
                    ServerError::Activation(msg) => {
                        eprintln!("Socket activation failed: {msg}");
                        std::process::exit(1);
                    }
                    ServerError::Store(err) => {
                        eprintln!("Store error: {err}");
                        std::process::exit(1);
                    }
                    ServerError::Tls(err) => {
                        eprintln!("TLS error: {err}");
                        std::process::exit(1);
                    }
                }
            }
        }
        Commands::Configure(args) => {
            let Some(db_path) = cli.db else {
                eprintln!("Error: Database path is required. Pass --db <PATH> or set WEAVER_DB.");
                std::process::exit(2);
            };

            let store = Store::open(&db_path).unwrap_or_else(|err| {
                eprintln!("Failed to open database at {}: {err}", db_path.display());
                std::process::exit(1);
            });

            let root_ca_pem = match args.acme_root_ca {
                Some(path) => match std::fs::read_to_string(&path) {
                    Ok(content) => Some(content),
                    Err(err) => {
                        eprintln!("Failed to read root CA file at {}: {err}", path.display());
                        std::process::exit(1);
                    }
                },
                None => None,
            };

            let config = Config {
                root_domain: args.root_domain,
                admin_email: args.admin_email,
                acme_provider: args.acme_provider,
                listen_http: args.listen_http,
                listen_https: args.listen_https,
                control_socket: args.control_socket,
                acme_directory: args.acme_directory,
                acme_eab_kid: args.acme_eab_kid,
                acme_eab_hmac: args.acme_eab_hmac,
                acme_root_ca_pem: root_ca_pem,
                acme_fallback_providers: Vec::new(),
            };

            if let Err(err) = store.save_config(&config) {
                eprintln!("Failed to write configuration: {err}");
                std::process::exit(1);
            }

            println!("Configuration saved to {}", db_path.display());
        }
        Commands::Providers => {
            weaver_server::cert::providers::print_providers();
        }
        Commands::Status { json } => {
            let socket_path = cli
                .socket
                .unwrap_or_else(|| PathBuf::from("/run/weaver/control.sock"));
            let code = weaver_server::control::client::client_status(&socket_path, json).await;
            std::process::exit(code);
        }
        Commands::Cert { command } => {
            let socket_path = cli
                .socket
                .unwrap_or_else(|| PathBuf::from("/run/weaver/control.sock"));
            match command {
                CertCommands::Status { name, limit, json } => {
                    validate_cert_name(&name);
                    let code = weaver_server::control::client::client_cert_status(
                        &socket_path,
                        name,
                        limit,
                        json,
                    )
                    .await;
                    std::process::exit(code);
                }
                CertCommands::Wait {
                    name,
                    timeout,
                    json,
                } => {
                    validate_cert_name(&name);
                    let code = weaver_server::control::client::client_cert_wait(
                        &socket_path,
                        name,
                        timeout,
                        json,
                    )
                    .await;
                    std::process::exit(code);
                }
                CertCommands::Renew {
                    name,
                    all,
                    force,
                    wait,
                    json,
                } => {
                    validate_cert_name(&name);
                    let code = weaver_server::control::client::client_cert_renew(
                        &socket_path,
                        name,
                        all,
                        force,
                        wait,
                        json,
                    )
                    .await;
                    std::process::exit(code);
                }
            }
        }
        Commands::Backup { path, json } => {
            let socket_path = cli
                .socket
                .unwrap_or_else(|| PathBuf::from("/run/weaver/control.sock"));
            let path_str = path.to_string_lossy().to_string();
            let code =
                weaver_server::control::client::client_backup(&socket_path, path_str, json).await;
            std::process::exit(code);
        }
        Commands::Shutdown { json } => {
            let socket_path = cli
                .socket
                .unwrap_or_else(|| PathBuf::from("/run/weaver/control.sock"));
            let code = weaver_server::control::client::client_shutdown(&socket_path, json).await;
            std::process::exit(code);
        }
    }
}

/// Tunnel Weaver Relay Server.
#[derive(Parser, Debug, Clone)]
#[command(name = "weaver-server", about = "Relay server for Tunnel Weaver")]
pub struct Cli {
    /// Path to the SQLite state database.
    #[arg(
        long,
        env = "WEAVER_DB",
        global = true,
        value_name = "PATH",
        conflicts_with = "socket"
    )]
    pub db: Option<PathBuf>,

    /// Path to the UNIX domain control socket.
    #[arg(
        long,
        env = "WEAVER_SOCKET",
        global = true,
        value_name = "PATH",
        conflicts_with = "db"
    )]
    pub socket: Option<PathBuf>,

    /// Log level for structured stderr logging (e.g. "error", "warn", "info", "debug", "trace").
    #[arg(
        long,
        env = "WEAVER_LOG_LEVEL",
        default_value = "info",
        global = true,
        value_name = "LEVEL"
    )]
    pub log_level: String,

    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}
