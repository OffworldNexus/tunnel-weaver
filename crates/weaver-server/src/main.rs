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

/// Arguments for host setup and systemd installation.
#[derive(Args, Debug, Clone)]
pub struct SetupArgs {
    /// Base domain for routed public tunnels (e.g. "example.com").
    #[arg(long, value_name = "DOMAIN")]
    pub root_domain: Option<String>,

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
        Commands::Setup(args) => {
            let db_path = cli
                .db
                .unwrap_or_else(|| PathBuf::from("/var/lib/weaver/weaver.db"));
            handle_setup(*args, db_path).await;
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

            let (root_domain, admin_email) = if args.headless {
                let Some(rd) = args.root_domain else {
                    eprintln!("Error: Missing required option --root-domain in headless mode");
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
                (rd, email)
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
                (rd, email)
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
                root_domain,
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
    let (root_domain, admin_email) = if args.no_prompt_values {
        (
            args.root_domain
                .expect("root_domain missing with --no-prompt-values"),
            args.email.expect("email missing with --no-prompt-values"),
        )
    } else if args.headless {
        let Some(rd) = args.root_domain else {
            eprintln!("Error: Missing required option --root-domain in headless mode");
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
        (rd, email)
    } else {
        println!(
            "\n{} {} {}",
            "Weaver Server Setup".bold().cyan(),
            "—".dark_grey(),
            "Host & Relay Deployment".white()
        );
        println!(
            "  {}",
            "Configure your host to run a public Tunnel Weaver relay with automated ACME TLS."
                .dark_grey()
        );
        println!();
        println!("{}", "Step 1: Domain & Contact".bold().white());
        println!(
            "  {}",
            "Enter the public domain pointing to this host, and an admin contact email:"
                .dark_grey()
        );
        println!();

        let rd = match args.root_domain {
            Some(d) => {
                if !weaver_server::setup::interactive::validate_fqdn(&d) {
                    eprintln!("Error: Invalid root domain '{d}'. Must be a valid FQDN.");
                    std::process::exit(2);
                }
                d
            }
            None => loop {
                let input = weaver_server::setup::interactive::prompt_line("Root domain", None)
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

        (rd, email)
    };

    let gathered = weaver_server::setup::interactive::GatheredConfig {
        root_domain: root_domain.clone(),
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

    let existing_install = weaver_server::setup::preflight::detect_existing_install(&db_path);

    // 5. Public DNS verification
    println!(
        "  {} Verifying DNS records for '{}'...",
        "•".blue(),
        root_domain
    );
    let dns_result = match weaver_server::setup::dns::probe_dns(&root_domain).await {
        Ok(res) => res,
        Err(err) => {
            eprintln!("{} DNS verification failed: {err}", "✗ Error:".red().bold());
            std::process::exit(1);
        }
    };

    // 6. Reachability verification
    let (port_80, port_443) = if args.skip_reachability_check {
        println!(
            "  {} Skipping reachability check (--skip-reachability-check)",
            "•".dim()
        );
        (
            weaver_server::setup::planner::PortReachability::Skipped,
            weaver_server::setup::planner::PortReachability::Skipped,
        )
    } else {
        // If our own systemd sockets are active, stop them temporarily so ports 80 and 443 can be probed
        let socket_active = std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", "weaver-server.socket"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if socket_active {
            let _ = std::process::Command::new("systemctl")
                .args(["stop", "weaver-server.service", "weaver-server.socket"])
                .status();
        }

        println!(
            "  {} Verifying port reachability via public IP...",
            "•".blue()
        );
        weaver_server::setup::reachability::verify_reachability(&dns_result.root_ips).await
    };

    // 7. Planning
    let probe = weaver_server::setup::planner::SystemProbe {
        systemd_present: true,
        supported_arch: true,
        target_domain: root_domain.clone(),
        existing_install,
        root_ips: dns_result.root_ips,
        probe_ips: dns_result.probe_ips,
        port_80,
        port_443,
        is_headless: args.headless,
        confirmed_domain_change: false,
        skip_reachability_check: args.skip_reachability_check,
        db_path: db_path.display().to_string(),
        user: args.user,
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

    // 8. Pre-register ACME account against directory before modifying system files or installing
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

    // 9. Installation
    let install_res = match weaver_server::setup::install::execute_install(
        &plan,
        &gathered,
        Some(&registered_account),
    ) {
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

    // 10. Verification & Cert Wait
    let socket_path = PathBuf::from("/run/weaver/control.sock");
    if let Err(err) =
        weaver_server::setup::verify::verify_setup(&plan.root_domain, &socket_path).await
    {
        eprintln!(
            "{} Deployment verification failed: {err}",
            "✗ Error:".red().bold()
        );
        std::process::exit(1);
    }
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
