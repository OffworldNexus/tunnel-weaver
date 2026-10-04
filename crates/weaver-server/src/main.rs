use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use crossterm::style::Stylize;
use tracing_subscriber::EnvFilter;
use weaver_server::server::{self, EX_CONFIG, ServerError};
use weaver_server::{Config, Store};

/// Subcommands supported by `weaver-server`.
#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Runs the long-running Tunnel Weaver relay server daemon.
    Run,

    /// Orchestrates host preflight, DNS verification, reachability checks, and systemd installation.
    Setup(Box<SetupArgs>),

    /// Runs the same domain/DNS/reachability preflight as setup, standalone.
    ///
    /// Works before install (pass both domains as arguments) and on an
    /// installed host (omitted domains fall back to the stored config). Exits
    /// nonzero if any check fails.
    Doctor(Box<DoctorArgs>),

    /// Uninstalls systemd units and binary.
    Uninstall(Box<UninstallArgs>),

    /// Configures or initializes the SQLite state store with required settings.
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

    /// Shows per-service usage totals over a time window.
    Usage {
        /// Filter to a person's name.
        #[arg(long, value_name = "NAME")]
        person: Option<String>,

        /// Filter to a service name.
        #[arg(long, value_name = "NAME")]
        service: Option<String>,

        /// Window start as a duration before now (e.g. "1d 12h").
        #[arg(long, value_name = "DURATION", conflicts_with = "from")]
        since: Option<String>,

        /// Window start: ISO-8601 timestamp or bare Unix seconds.
        #[arg(long, value_name = "TIME")]
        from: Option<String>,

        /// Window end: ISO-8601 timestamp or bare Unix seconds (default: now).
        #[arg(long, value_name = "TIME")]
        until: Option<String>,

        /// Outputs the usage response as raw JSON.
        #[arg(long)]
        json: bool,
    },
}

/// Subcommands for certificate operations.
#[derive(Subcommand, Debug, Clone)]
pub enum CertCommands {
    /// Shows certificate summary table or detailed status for a single hostname or certificate ID.
    Status {
        /// Hostname or certificate ID to inspect (or "root" for base domain). If omitted, displays all certificates.
        #[arg(value_name = "NAME_OR_CERT_ID")]
        name: Option<String>,

        /// Maximum number of historical cert events to return in detail view (default: 10).
        #[arg(long)]
        limit: Option<usize>,

        /// Disables filtering to only the best certificate per domain in list view.
        #[arg(long)]
        no_only_best: bool,

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

    /// Forces the single wildcard certificate order immediately.
    Order {
        /// Outputs the order response as raw JSON.
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

/// Validates that a hostname argument is a valid FQDN, integer certificate ID, or the alias "root".
fn validate_cert_name(name: &Option<String>) {
    if let Some(n) = name
        && n != "root"
        && !n.contains('.')
        && n.parse::<i32>().is_err()
    {
        eprintln!(
            "Error: Invalid hostname '{n}'. Must be a fully qualified domain name (containing '.'), certificate ID, or 'root'."
        );
        std::process::exit(2);
    }
}

/// Arguments for host setup and systemd installation.
#[derive(Args, Debug, Clone)]
pub struct SetupArgs {
    /// Base domain for routed public tunnels (e.g. "example.com").
    #[arg(long, value_name = "DOMAIN")]
    pub root_domain: Option<String>,

    /// The relay's own stable hostname (e.g. "relay.example.net"), kept outside
    /// the tunnel delegation and issued its own HTTP-01 certificate.
    #[arg(long, value_name = "DOMAIN")]
    pub admin_domain: Option<String>,

    /// Administrator contact email for ACME registration.
    #[arg(long, alias = "admin-email", value_name = "EMAIL")]
    pub email: Option<String>,

    /// ACME directory provider (default: letsencrypt).
    #[arg(long, default_value = "letsencrypt", value_name = "PROVIDER")]
    pub acme_provider: String,

    /// Custom ACME directory URL (implies provider "custom").
    #[arg(long, value_name = "URL")]
    pub acme_directory: Option<String>,

    /// External Account Binding Key Identifier.
    #[arg(long, value_name = "KID")]
    pub acme_eab_kid: Option<String>,

    /// External Account Binding HMAC key.
    #[arg(long, value_name = "HMAC")]
    pub acme_eab_hmac: Option<String>,

    /// Path to file containing External Account Binding HMAC key.
    #[arg(long, value_name = "PATH")]
    pub acme_eab_hmac_file: Option<PathBuf>,

    /// Optional path to custom Root CA certificate file in PEM format.
    #[arg(long, value_name = "PATH")]
    pub acme_root_ca: Option<PathBuf>,

    /// Non-interactive headless execution mode.
    #[arg(long)]
    pub headless: bool,

    /// Skip connect-back reachability verification.
    #[arg(long)]
    pub skip_reachability_check: bool,

    /// The relay's own public IP address(es), repeatable. Overrides automatic
    /// detection; required behind NAT where the bindable address differs.
    #[arg(long = "relay-ip", value_name = "ADDR")]
    pub relay_ips: Vec<std::net::IpAddr>,

    /// Dedicated system user for the service.
    #[arg(long, default_value = "weaver", value_name = "NAME")]
    pub user: String,

    /// Binary installation prefix directory.
    #[arg(long, default_value = "/usr/local/bin", value_name = "PATH")]
    pub prefix: PathBuf,

    /// Internal flag signaling that interactive prompt values are already provided.
    #[arg(long, hide = true)]
    pub no_prompt_values: bool,
}

/// Arguments for the standalone `weaver-server doctor` preflight.
#[derive(Args, Debug, Clone)]
pub struct DoctorArgs {
    /// Tunnel domain (the delegated zone). Falls back to the stored config.
    #[arg(long, value_name = "DOMAIN")]
    pub root_domain: Option<String>,

    /// The relay's own admin hostname. Falls back to the stored config.
    #[arg(long, value_name = "DOMAIN")]
    pub admin_domain: Option<String>,

    /// The relay's own public IP address(es), repeatable. Overrides automatic
    /// detection; use behind NAT where the bindable address differs.
    #[arg(long = "relay-ip", value_name = "ADDR")]
    pub relay_ips: Vec<std::net::IpAddr>,

    /// Skip the 80/443/53 self-reachability probe.
    #[arg(long)]
    pub skip_reachability_check: bool,

    /// Outputs the report as raw JSON.
    #[arg(long)]
    pub json: bool,
}

/// Arguments for removing systemd units and relay installation.
#[derive(Args, Debug, Clone)]
pub struct UninstallArgs {
    /// Binary installation prefix directory.
    #[arg(long, default_value = "/usr/local/bin", value_name = "PATH")]
    pub prefix: PathBuf,

    /// Dedicated system user for the service.
    #[arg(long, default_value = "weaver", value_name = "NAME")]
    pub user: String,

    /// Purge database state directory and remove system user.
    #[arg(long)]
    pub purge: bool,

    /// Non-interactive headless execution mode.
    #[arg(long)]
    pub headless: bool,
}

/// Arguments for initializing or updating the server configuration.
#[derive(Args, Debug, Clone)]
pub struct ConfigureArgs {
    /// Base domain for routed public tunnels (e.g. "example.com").
    #[arg(long, value_name = "DOMAIN")]
    pub root_domain: Option<String>,

    /// The relay's own stable hostname (e.g. "relay.example.net").
    #[arg(long, value_name = "DOMAIN")]
    pub admin_domain: Option<String>,

    /// Administrator contact email for ACME registration.
    #[arg(long, alias = "admin-email", value_name = "EMAIL")]
    pub email: Option<String>,

    /// ACME directory provider (default: letsencrypt).
    #[arg(long, default_value = "letsencrypt", value_name = "PROVIDER")]
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

    /// Path to file containing External Account Binding HMAC key.
    #[arg(long, value_name = "PATH")]
    pub acme_eab_hmac_file: Option<PathBuf>,

    /// Optional path to custom Root CA certificate file in PEM format.
    #[arg(long, value_name = "PATH")]
    pub acme_root_ca: Option<PathBuf>,

    /// Seconds between usage-meter flushes of closed minute buckets.
    #[arg(long, default_value_t = 60, value_name = "SECS")]
    pub usage_flush_interval: u64,

    /// Non-interactive headless execution mode.
    #[arg(long)]
    pub headless: bool,
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

    // Configure structured stderr logging. The daemon gets the operator's
    // requested level; the one-shot CLI commands (setup/doctor/uninstall) run
    // with logging off so their own wizard output is the only thing on screen
    // — migration and driver INFO lines otherwise leak straight through.
    // `RUST_LOG` still overrides everything for debugging.
    let is_daemon = matches!(cli.command, Commands::Run);
    let filter = match EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) if is_daemon => EnvFilter::new(&cli.log_level),
        // An explicit `--log-level`/`WEAVER_LOG_LEVEL` is an operator debugging
        // override even for the quiet CLI commands.
        Err(_) if std::env::var_os("WEAVER_LOG_LEVEL").is_some() => EnvFilter::new(&cli.log_level),
        Err(_) => EnvFilter::new("off"),
    };

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
        Commands::Setup(args) => {
            let db_path = cli
                .db
                .unwrap_or_else(|| PathBuf::from("/var/lib/weaver/weaver.db"));
            handle_setup(*args, db_path).await;
        }
        Commands::Doctor(args) => {
            let db_path = cli
                .db
                .unwrap_or_else(|| PathBuf::from("/var/lib/weaver/weaver.db"));
            let socket_path = cli
                .socket
                .unwrap_or_else(|| PathBuf::from("/run/weaver/control.sock"));
            handle_doctor(*args, db_path, socket_path).await;
        }
        Commands::Uninstall(args) => {
            let db_path = cli
                .db
                .unwrap_or_else(|| PathBuf::from("/var/lib/weaver/weaver.db"));
            handle_uninstall(*args, db_path);
        }
        Commands::Configure(args) => {
            let db_path = cli
                .db
                .unwrap_or_else(|| PathBuf::from("/var/lib/weaver/weaver.db"));

            let mut acme_provider = args.acme_provider;
            let acme_directory = args.acme_directory;
            if acme_directory.is_some() && acme_provider == "letsencrypt" {
                acme_provider = "custom".into();
            }

            let eab_hmac = match (args.acme_eab_hmac, args.acme_eab_hmac_file) {
                (Some(h), _) => Some(h),
                (None, Some(path)) => match std::fs::read_to_string(&path) {
                    Ok(c) => Some(c.trim().to_string()),
                    Err(err) => {
                        eprintln!(
                            "Error: Failed to read EAB HMAC file at {}: {err}",
                            path.display()
                        );
                        std::process::exit(2);
                    }
                },
                (None, None) => None,
            };

            let (root_domain, admin_domain, admin_email) = if args.headless {
                let Some(rd) = args.root_domain else {
                    eprintln!("Error: Missing required option --root-domain in headless mode");
                    std::process::exit(2);
                };
                let Some(ad) = args.admin_domain else {
                    eprintln!("Error: Missing required option --admin-domain in headless mode");
                    std::process::exit(2);
                };
                let Some(email) = args.email else {
                    eprintln!("Error: Missing required option --email in headless mode");
                    std::process::exit(2);
                };
                if !weaver_server::setup::interactive::validate_fqdn(&rd) {
                    eprintln!("Error: Invalid root domain '{rd}'. Must be a valid FQDN.");
                    std::process::exit(2);
                }
                if !weaver_server::setup::interactive::validate_fqdn(&ad) {
                    eprintln!("Error: Invalid admin domain '{ad}'. Must be a valid FQDN.");
                    std::process::exit(2);
                }
                if let Some(issue) = weaver_server::config::domain_split_issue(&ad, &rd) {
                    eprintln!("Error: {issue}");
                    std::process::exit(2);
                }
                if !weaver_server::setup::interactive::validate_email(&email) {
                    eprintln!("Error: Invalid email '{email}'.");
                    std::process::exit(2);
                }
                let prov_info = weaver_server::cert::providers::find_provider(&acme_provider);
                if prov_info.is_some_and(|p| p.eab_required)
                    && (args.acme_eab_kid.is_none() || eab_hmac.is_none())
                {
                    eprintln!(
                        "Error: Provider '{acme_provider}' requires both EAB KID and EAB HMAC in headless mode"
                    );
                    std::process::exit(2);
                }
                (rd, ad, email)
            } else {
                let rd = match args.root_domain {
                    Some(d) => {
                        if !weaver_server::setup::interactive::validate_fqdn(&d) {
                            eprintln!("Error: Invalid root domain '{d}'. Must be a valid FQDN.");
                            std::process::exit(2);
                        }
                        d
                    }
                    None => loop {
                        let input =
                            weaver_server::setup::interactive::prompt_line("Root domain", None)
                                .unwrap_or_default();
                        if weaver_server::setup::interactive::validate_fqdn(&input) {
                            break input;
                        }
                        println!(
                            "Invalid root domain. Please provide a valid FQDN (e.g. example.com)."
                        );
                    },
                };
                let ad = match args.admin_domain {
                    Some(d) => {
                        if !weaver_server::setup::interactive::validate_fqdn(&d) {
                            eprintln!("Error: Invalid admin domain '{d}'. Must be a valid FQDN.");
                            std::process::exit(2);
                        }
                        d
                    }
                    None => loop {
                        let input = weaver_server::setup::interactive::prompt_line(
                            "Admin domain (the relay's own hostname)",
                            None,
                        )
                        .unwrap_or_default();
                        if weaver_server::setup::interactive::validate_fqdn(&input) {
                            break input;
                        }
                        println!(
                            "Invalid admin domain. Please provide a valid FQDN (e.g. relay.example.net)."
                        );
                    },
                };
                if let Some(issue) = weaver_server::config::domain_split_issue(&ad, &rd) {
                    eprintln!("Error: {issue}");
                    std::process::exit(2);
                }
                let email = match args.email {
                    Some(e) => {
                        if !weaver_server::setup::interactive::validate_email(&e) {
                            eprintln!("Error: Invalid email '{e}'.");
                            std::process::exit(2);
                        }
                        e
                    }
                    None => loop {
                        let input =
                            weaver_server::setup::interactive::prompt_line("Admin email", None)
                                .unwrap_or_default();
                        if weaver_server::setup::interactive::validate_email(&input) {
                            break input;
                        }
                        println!("Invalid email. Please provide a valid email address.");
                    },
                };
                (rd, ad, email)
            };

            let store = Store::open(&db_path).await.unwrap_or_else(|err| {
                eprintln!("Failed to open database at {}: {err}", db_path.display());
                std::process::exit(1);
            });

            // Preserve the relay's detected public addresses across a config
            // rewrite; re-running setup is the path that refreshes them.
            let existing_relay_ips = store
                .load_config_json()
                .await
                .ok()
                .flatten()
                .and_then(|json| serde_json::from_str::<Config>(&json).ok())
                .map(|cfg| cfg.relay_ips)
                .unwrap_or_default();

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
                root_domain,
                admin_domain,
                admin_email,
                acme_provider,
                listen_http: args.listen_http,
                listen_https: args.listen_https,
                control_socket: args.control_socket,
                acme_directory,
                acme_eab_kid: args.acme_eab_kid,
                acme_eab_hmac: eab_hmac,
                acme_root_ca_pem: root_ca_pem,
                acme_fallback_providers: Vec::new(),
                usage_flush_interval_secs: args.usage_flush_interval,
                relay_ips: existing_relay_ips,
                // `configure` is the non-systemd (container) flavour: there is no
                // interactive preflight to gate on, and the operator owns DNS.
                // Mark setup complete so the daemon auto-orders the wildcard at
                // startup instead of waiting for a `setup` that never runs.
                setup_complete: true,
            };

            if let Err(err) = store.save_config(&config).await {
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
                CertCommands::Status {
                    name,
                    limit,
                    no_only_best,
                    json,
                } => {
                    validate_cert_name(&name);
                    let code = weaver_server::control::client::client_cert_status(
                        &socket_path,
                        name,
                        limit,
                        no_only_best,
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
                CertCommands::Order { json } => {
                    let code =
                        weaver_server::control::client::client_cert_order(&socket_path, json).await;
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
        Commands::Usage {
            person,
            service,
            since,
            from,
            until,
            json,
        } => {
            let socket_path = cli
                .socket
                .unwrap_or_else(|| PathBuf::from("/run/weaver/control.sock"));
            // Relative windows are resolved here, client-side, so the request
            // only ever carries absolute Unix seconds.
            let (since_secs, until_secs) =
                match resolve_usage_window(since.as_deref(), from.as_deref(), until.as_deref()) {
                    Ok(window) => window,
                    Err(msg) => {
                        eprintln!("Error: {msg}");
                        std::process::exit(2);
                    }
                };
            let code = weaver_server::control::client::client_usage(
                &socket_path,
                person,
                service,
                since_secs,
                until_secs,
                json,
            )
            .await;
            std::process::exit(code);
        }
    }
}

/// Current wall-clock time as absolute Unix seconds.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Parses a `--from`/`--until` value: a bare Unix-seconds integer or an
/// ISO-8601 timestamp.
fn parse_instant(value: &str) -> Result<i64, String> {
    let trimmed = value.trim();
    if let Ok(secs) = trimmed.parse::<i64>() {
        return Ok(secs);
    }
    let ts: jiff::Timestamp = trimmed
        .parse()
        .map_err(|e| format!("invalid timestamp '{value}': {e}"))?;
    Ok(ts.as_second())
}

/// Resolves the `usage` window into absolute Unix seconds.
///
/// `--since` is a duration before now (e.g. `1d 12h`), parsed with `jiff`;
/// `--from`/`--until` are instants. With neither bound the window is the last
/// 24 hours, and a missing `--until` defaults to now.
fn resolve_usage_window(
    since: Option<&str>,
    from: Option<&str>,
    until: Option<&str>,
) -> Result<(i64, i64), String> {
    let now = now_secs();
    let since_secs = match (since, from) {
        (Some(duration), _) => {
            let span: jiff::Span = duration
                .parse()
                .map_err(|e| format!("invalid --since duration '{duration}': {e}"))?;
            // Days and weeks are fixed 24-hour/7-day spans for a wall-clock
            // window; calendar-aware arithmetic is not what the user means.
            let length = span
                .to_duration(jiff::SpanRelativeTo::days_are_24_hours())
                .map_err(|e| format!("invalid --since duration '{duration}': {e}"))?;
            now - length.as_secs()
        }
        (None, Some(from)) => parse_instant(from)?,
        (None, None) => now - 86_400,
    };
    let until_secs = match until {
        Some(value) => parse_instant(value)?,
        None => now,
    };
    if since_secs >= until_secs {
        return Err("window start must be before window end".into());
    }
    Ok((since_secs, until_secs))
}

async fn handle_setup(args: SetupArgs, db_path: PathBuf) {
    let mut acme_provider = args.acme_provider;
    let mut acme_directory = args.acme_directory;
    if acme_directory.is_some() && acme_provider == "letsencrypt" {
        acme_provider = "custom".into();
    }

    let mut eab_kid = args.acme_eab_kid;
    let mut eab_hmac = match (args.acme_eab_hmac, args.acme_eab_hmac_file) {
        (Some(h), _) => Some(h),
        (None, Some(path)) => match std::fs::read_to_string(&path) {
            Ok(c) => Some(c.trim().to_string()),
            Err(err) => {
                eprintln!(
                    "Error: Failed to read EAB HMAC file at {}: {err}",
                    path.display()
                );
                std::process::exit(2);
            }
        },
        (None, None) => None,
    };

    let mut root_ca_path = args.acme_root_ca;

    // 1. Gather configuration
    let (root_domain, admin_domain, admin_email) = if args.no_prompt_values {
        (
            args.root_domain
                .expect("root_domain missing with --no-prompt-values"),
            args.admin_domain
                .expect("admin_domain missing with --no-prompt-values"),
            args.email.expect("email missing with --no-prompt-values"),
        )
    } else if args.headless {
        let Some(rd) = args.root_domain else {
            eprintln!("Error: Missing required option --root-domain in headless mode");
            std::process::exit(2);
        };
        let Some(ad) = args.admin_domain else {
            eprintln!("Error: Missing required option --admin-domain in headless mode");
            std::process::exit(2);
        };
        let Some(email) = args.email else {
            eprintln!("Error: Missing required option --email in headless mode");
            std::process::exit(2);
        };
        if !weaver_server::setup::interactive::validate_fqdn(&rd) {
            eprintln!("Error: Invalid root domain '{rd}'. Must be a valid FQDN.");
            std::process::exit(2);
        }
        if !weaver_server::setup::interactive::validate_fqdn(&ad) {
            eprintln!("Error: Invalid admin domain '{ad}'. Must be a valid FQDN.");
            std::process::exit(2);
        }
        if let Some(issue) = weaver_server::config::domain_split_issue(&ad, &rd) {
            eprintln!("Error: {issue}");
            std::process::exit(2);
        }
        if !weaver_server::setup::interactive::validate_email(&email) {
            eprintln!("Error: Invalid email '{email}'.");
            std::process::exit(2);
        }
        let prov_info = weaver_server::cert::providers::find_provider(&acme_provider);
        if prov_info.is_some_and(|p| p.eab_required) && (eab_kid.is_none() || eab_hmac.is_none()) {
            eprintln!(
                "Error: Provider '{acme_provider}' requires both --acme-eab-kid and --acme-eab-hmac in headless mode"
            );
            std::process::exit(2);
        }
        (rd, ad, email)
    } else {
        weaver_server::setup::interactive::print_domain_step_intro();

        let rd = match args.root_domain {
            Some(d) => {
                if !weaver_server::setup::interactive::validate_fqdn(&d) {
                    eprintln!("Error: Invalid root domain '{d}'. Must be a valid FQDN.");
                    std::process::exit(2);
                }
                d
            }
            None => loop {
                let input = weaver_server::setup::interactive::prompt_line(
                    "Tunnel domain (delegated to this relay)",
                    None,
                )
                .unwrap_or_default();
                if weaver_server::setup::interactive::validate_fqdn(&input) {
                    break input;
                }
                println!(
                    "{} Invalid domain name. Must be a valid FQDN (e.g. example.com).",
                    "✗".red().bold()
                );
            },
        };

        let ad = match args.admin_domain {
            Some(d) => {
                if !weaver_server::setup::interactive::validate_fqdn(&d) {
                    eprintln!("Error: Invalid admin domain '{d}'. Must be a valid FQDN.");
                    std::process::exit(2);
                }
                d
            }
            None => loop {
                let input = weaver_server::setup::interactive::prompt_line(
                    "Admin domain (the relay's own hostname, outside the tunnel zone)",
                    None,
                )
                .unwrap_or_default();
                if weaver_server::setup::interactive::validate_fqdn(&input) {
                    break input;
                }
                println!(
                    "{} Invalid domain name. Must be a valid FQDN (e.g. relay.example.net).",
                    "✗".red().bold()
                );
            },
        };

        // The foot-gun check runs before anything is installed: an admin domain
        // inside the delegated tunnel zone would hand the relay's own DNS to the
        // zone the relay is meant to control.
        if let Some(issue) = weaver_server::config::domain_split_issue(&ad, &rd) {
            eprintln!("Error: {issue}");
            std::process::exit(2);
        }

        let email = match args.email {
            Some(e) => {
                if !weaver_server::setup::interactive::validate_email(&e) {
                    eprintln!("Error: Invalid email '{e}'.");
                    std::process::exit(2);
                }
                e
            }
            None => loop {
                let input = weaver_server::setup::interactive::prompt_line("Admin email", None)
                    .unwrap_or_default();
                if weaver_server::setup::interactive::validate_email(&input) {
                    break input;
                }
                println!("{} Invalid email address.", "✗".red().bold());
            },
        };

        if eab_kid.is_none() && acme_directory.is_none() && acme_provider == "letsencrypt" {
            let (chosen_prov, custom_dir) =
                weaver_server::setup::interactive::prompt_provider_choice().unwrap();
            acme_provider = chosen_prov;
            if let Some(dir) = custom_dir {
                acme_directory = Some(dir);
            }
            let prov_info = weaver_server::cert::providers::find_provider(&acme_provider);
            if prov_info.is_some_and(|p| p.eab_required) {
                let kid = weaver_server::setup::interactive::prompt_line(
                    "EAB Key Identifier (KID)",
                    None,
                )
                .unwrap();
                let hmac =
                    weaver_server::setup::interactive::read_masked_input("EAB HMAC Key").unwrap();
                eab_kid = Some(kid);
                eab_hmac = Some(hmac);
            } else if acme_provider == "custom" {
                let need_eab = weaver_server::setup::interactive::prompt_line(
                    "Does this directory require EAB? [y/N]",
                    Some("n"),
                )
                .unwrap_or_default();
                if need_eab.eq_ignore_ascii_case("y") || need_eab.eq_ignore_ascii_case("yes") {
                    let kid = weaver_server::setup::interactive::prompt_line(
                        "EAB Key Identifier (KID)",
                        None,
                    )
                    .unwrap();
                    let hmac = weaver_server::setup::interactive::read_masked_input("EAB HMAC Key")
                        .unwrap();
                    eab_kid = Some(kid);
                    eab_hmac = Some(hmac);
                }
                let ca_path_str = weaver_server::setup::interactive::prompt_line(
                    "Custom Root CA PEM path (optional, press enter to skip)",
                    None,
                )
                .unwrap_or_default();
                if !ca_path_str.is_empty() {
                    root_ca_path = Some(PathBuf::from(ca_path_str));
                }
            }
        }

        (rd, ad, email)
    };

    let gathered = weaver_server::setup::interactive::GatheredConfig {
        root_domain: root_domain.clone(),
        admin_domain: admin_domain.clone(),
        admin_email: admin_email.clone(),
        acme_provider: acme_provider.clone(),
        acme_directory: acme_directory.clone(),
        acme_eab_kid: eab_kid.clone(),
        acme_eab_hmac: eab_hmac.clone(),
        acme_root_ca_path: root_ca_path.clone(),
        db_path: db_path.clone(),
        user: args.user.clone(),
        prefix: args.prefix.clone(),
        skip_reachability_check: args.skip_reachability_check,
        relay_ips: args.relay_ips.clone(),
    };

    // 2. Display execution plan & confirm (if not already elevated)
    if !args.no_prompt_values {
        let confirmed =
            weaver_server::setup::interactive::display_plan_and_confirm(&gathered, args.headless);
        if !confirmed {
            println!("Setup cancelled by user.");
            std::process::exit(0);
        }

        // 3. Privilege elevation if needed
        weaver_server::setup::privilege::ensure_root_or_elevate(&gathered, args.headless);
    }

    // --- We are now executing with root privileges ---

    // 4. Preflight checks
    if !weaver_server::setup::preflight::is_systemd_present() {
        eprintln!("the server component supports systemd Linux only");
        std::process::exit(1);
    }
    if !weaver_server::setup::preflight::is_supported_arch() {
        eprintln!("unsupported target platform: Linux x86_64 or aarch64 required");
        std::process::exit(1);
    }

    let existing_install = weaver_server::setup::preflight::detect_existing_install(&db_path).await;

    // 5. Preflight: validate the domain split, admin resolution, DNS
    //    delegation, and port reachability BEFORE anything on the host is
    //    modified. This is the same check `weaver-server doctor` exposes, so a
    //    misconfigured or undelegated zone aborts identically in both places.
    //
    //    If our own sockets are already active (an upgrade), stop them first so
    //    the throwaway listeners can bind the public ports.
    let mut stopped_sockets = false;
    if !args.skip_reachability_check {
        let socket_active = std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", "weaver-server.socket"])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);

        if socket_active {
            let _ = std::process::Command::new("systemctl")
                .args(["stop", "weaver-server.service", "weaver-server.socket"])
                .output();
            stopped_sockets = true;
        }
    }

    println!("\n{}", "Preflight Checks".bold().white());
    let report = weaver_server::setup::doctor::run_in_process(
        &root_domain,
        &admin_domain,
        &args.relay_ips,
        args.skip_reachability_check,
    )
    .await;

    println!("{}", report.render());
    // Abort *before* installing anything. `report.ok()` is false when any
    // checklist item failed, and each failure printed its own remediation.
    // If we paused an existing install for the port probe, bring it back so a
    // failed upgrade does not leave the relay down.
    if !report.ok() {
        if stopped_sockets {
            let _ = std::process::Command::new("systemctl")
                .args(["start", "weaver-server.socket", "weaver-server.service"])
                .output();
        }
        eprintln!(
            "\n{} Setup aborted before making any host changes.",
            "✗ Error:".red().bold()
        );
        std::process::exit(1);
    }

    let relay_ips = report.relay_ips.clone();
    let ns_targets = report.ns_targets.clone();
    let delegation_ok = report
        .checks
        .iter()
        .find(|check| check.title == "Delegation")
        .is_some_and(|check| check.ok);
    let port_80 = weaver_server::setup::doctor::port_status(&report, 80);
    let port_443 = weaver_server::setup::doctor::port_status(&report, 443);
    let port_53 = weaver_server::setup::doctor::port_status(&report, 53);

    // A `systemd-resolved` stub already holding a port-53 socket is the most
    // common reason the DNS bind fails; surface it as a first-class abort with
    // operator guidance rather than a generic bind error.
    let resolver_stub_conflict = if matches!(
        port_53,
        weaver_server::setup::planner::PortReachability::Failed(_)
    ) {
        weaver_server::setup::reachability::find_occupying_process(53).and_then(|(pid, comm)| {
            if comm.to_ascii_lowercase().contains("systemd-resolve") {
                Some(format!(
                    "port 53 is held by '{comm}' (PID {pid}); disable the systemd-resolved stub listener \
                     (set DNSStubListener=no in /etc/systemd/resolved.conf, then systemctl restart systemd-resolved) \
                     and re-run setup"
                ))
            } else {
                None
            }
        })
    } else {
        None
    };

    // 6. Build the execution plan from the preflight report. The delegation,
    //    reachability, and domain-split gates have already passed, so the
    //    planner's copy now carries the real values rather than placeholders.
    let probe = weaver_server::setup::planner::SystemProbe {
        systemd_present: true,
        supported_arch: true,
        target_domain: root_domain.clone(),
        admin_domain: admin_domain.clone(),
        existing_install: existing_install.clone(),
        root_ips: relay_ips.clone(),
        probe_ips: relay_ips.clone(),
        ns_targets: ns_targets.clone(),
        delegation_ok,
        resolvers_ok: true,
        port_80: port_80.clone(),
        port_443: port_443.clone(),
        port_53: port_53.clone(),
        resolver_stub_conflict: resolver_stub_conflict.clone(),
        is_headless: args.headless,
        confirmed_domain_change: false,
        skip_reachability_check: args.skip_reachability_check,
        db_path: db_path.display().to_string(),
        user: args.user.clone(),
        prefix: args.prefix.display().to_string(),
        acme_provider: acme_provider.clone(),
        has_eab: eab_kid.is_some(),
    };

    let plan = match weaver_server::setup::planner::plan_setup(&probe) {
        Ok(p) => p,
        Err(abort_err) => {
            eprintln!(
                "{} Setup cannot proceed: {abort_err}",
                "✗ Error:".red().bold()
            );
            std::process::exit(1);
        }
    };

    // 7. Pre-register ACME account against directory before modifying system files or installing
    let root_ca_pem = match &root_ca_path {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("Error reading root CA file: {e}");
                std::process::exit(1);
            }
        },
        None => None,
    };

    let dir_url = acme_directory.clone().unwrap_or_else(|| {
        weaver_server::cert::providers::resolve_directory_url(&acme_provider, None)
            .unwrap_or_else(|| "https://acme-v02.api.letsencrypt.org/directory".into())
    });

    println!(
        "  {} Validating ACME account against directory...",
        "•".blue()
    );
    let registered_account = match weaver_server::cert::register_acme_account(
        &admin_email,
        &acme_provider,
        &dir_url,
        eab_kid.as_deref(),
        eab_hmac.as_deref(),
        root_ca_pem.as_deref(),
    )
    .await
    {
        Ok(acct) => {
            println!(
                "  {} ACME account validated (KID: {})",
                "✓".green(),
                acct.kid
            );
            acct
        }
        Err(err) => {
            eprintln!(
                "{} Failed to validate ACME credentials against {dir_url}: {err}",
                "✗ Error:".red().bold()
            );
            std::process::exit(1);
        }
    };

    // 8. Installation: writes the DNS-enabled socket unit and starts the
    //     responder with `setup_complete = false`, so it serves DNS but does
    //     not auto-order the wildcard yet.
    let install_res = match weaver_server::setup::install::execute_install(
        &plan,
        &gathered,
        Some(&registered_account),
    )
    .await
    {
        Ok(r) => r,
        Err(err) => {
            eprintln!("{} Installation failed: {err}", "✗ Error:".red().bold());
            weaver_server::setup::verify::print_failure_guidance();
            std::process::exit(1);
        }
    };

    if !install_res.changed && plan.is_upgrade {
        println!("\n{}", "already up to date".bold().green());
    }

    // 9. The delegation was confirmed during preflight, so the relay can start
    //    serving the zone immediately. Trigger both orders (tunnel wildcard via
    //    DNS-01, admin via HTTP-01), then verify — which waits for both and
    //    probes both HTTPS endpoints.
    let socket_path = PathBuf::from("/run/weaver/control.sock");

    // The daemon gates its startup auto-order on `setup_complete`, so setup
    // must explicitly kick off the first orders before waiting. Use the quiet
    // client: the wizard prints its own confirmation instead of the raw JSON.
    let order_code = weaver_server::control::client::client_cert_order_quiet(&socket_path).await;
    if order_code != 0 {
        eprintln!(
            "{} Failed to queue the certificate orders (control exit {order_code})",
            "✗ Error:".red().bold()
        );
        std::process::exit(1);
    }
    println!(
        "  {} Queued tunnel and admin certificate orders",
        "✓".green()
    );

    if let Err(err) = weaver_server::setup::verify::verify_setup(
        &plan.root_domain,
        &plan.admin_domain,
        &socket_path,
    )
    .await
    {
        eprintln!(
            "{} Deployment verification failed: {err}",
            "✗ Error:".red().bold()
        );
        std::process::exit(1);
    }

    // 10. Mark setup complete only after delegation, port 53, and both
    //     certificate orders succeeded. Future daemon restarts may then
    //     auto-order.
    match Store::open(&db_path).await {
        Ok(store) => {
            if let Ok(Some(json)) = store.load_config_json().await {
                match serde_json::from_str::<Config>(&json) {
                    Ok(mut cfg) => {
                        cfg.setup_complete = true;
                        if let Err(e) = store.save_config(&cfg).await {
                            eprintln!(
                                "{} Failed to persist setup_complete: {e}",
                                "✗ Error:".red().bold()
                            );
                        }
                    }
                    Err(e) => eprintln!(
                        "{} Failed to parse stored config while marking setup complete: {e}",
                        "✗ Error:".red().bold()
                    ),
                }
            }
            let _ = store.close().await;
        }
        Err(e) => eprintln!(
            "{} Failed to reopen the store to mark setup complete: {e}",
            "✗ Error:".red().bold()
        ),
    }
}

/// Loads the tunnel and admin domains from the stored config when they were
/// not supplied on the command line, so `doctor` works on an installed host
/// with no arguments. Returns `None` when no readable config exists.
async fn load_stored_domains(db_path: &std::path::Path) -> Option<(String, String)> {
    if !db_path.exists() {
        return None;
    }
    let store = Store::open(db_path).await.ok()?;
    let config = store.load_config().await.ok()?;
    let _ = store.close().await;
    Some((config.root_domain, config.admin_domain))
}

/// Runs the standalone `weaver-server doctor` preflight.
///
/// The command runs against whichever context is available. If the relay
/// answers on the control socket it owns 80/443/53 and composes the report
/// itself (normal life); otherwise the command runs the shared preflight
/// in-process with throwaway listeners (pre-install, or the host is down).
/// Domains come from the arguments when given, otherwise from the installed
/// config. Exits nonzero when any check fails.
async fn handle_doctor(args: DoctorArgs, db_path: PathBuf, socket_path: PathBuf) {
    // Normal-life path: prefer the running relay, which self-connects instead
    // of pausing itself for the port probe.
    if weaver_server::control::client::control_socket_available(&socket_path).await {
        let code = weaver_server::control::client::client_doctor(&socket_path, args.json).await;
        std::process::exit(code);
    }

    // Pre-install / host-down path: resolve the domains from the arguments,
    // falling back to the installed config, and bind the ports in-process.
    let (root_domain, admin_domain) = match (args.root_domain, args.admin_domain) {
        (Some(root), Some(admin)) => (root, admin),
        (root, admin) => {
            let stored = load_stored_domains(std::path::Path::new(&db_path)).await;
            let root = root.or_else(|| stored.as_ref().map(|(r, _)| r.clone()));
            let admin = admin.or_else(|| stored.as_ref().map(|(_, a)| a.clone()));
            match (root, admin) {
                (Some(root), Some(admin)) => (root, admin),
                _ => {
                    eprintln!(
                        "Error: --root-domain and --admin-domain are required when no installed \
                         configuration exists at {}",
                        db_path.display()
                    );
                    std::process::exit(2);
                }
            }
        }
    };

    if !weaver_server::setup::interactive::validate_fqdn(&root_domain) {
        eprintln!("Error: Invalid root domain '{root_domain}'. Must be a valid FQDN.");
        std::process::exit(2);
    }
    if !weaver_server::setup::interactive::validate_fqdn(&admin_domain) {
        eprintln!("Error: Invalid admin domain '{admin_domain}'. Must be a valid FQDN.");
        std::process::exit(2);
    }

    let report = weaver_server::setup::doctor::run_in_process(
        &root_domain,
        &admin_domain,
        &args.relay_ips,
        args.skip_reachability_check,
    )
    .await;

    if args.json {
        match serde_json::to_string_pretty(&report.to_json()) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("Error serializing report: {err}");
                std::process::exit(1);
            }
        }
    } else {
        println!("{}", report.render());
    }

    std::process::exit(if report.ok() { 0 } else { 1 });
}

fn handle_uninstall(args: UninstallArgs, db_path: PathBuf) {
    let opts = weaver_server::setup::uninstall::UninstallOptions {
        prefix: args.prefix,
        db_path,
        user: args.user,
        purge: args.purge,
        headless: args.headless,
    };
    if let Err(err) = weaver_server::setup::uninstall::execute_uninstall(&opts) {
        eprintln!("{} Uninstall failed: {err}", "✗ Error:".red().bold());
        std::process::exit(1);
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
