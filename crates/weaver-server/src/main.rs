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

    /// Displays the supported provider catalogs (ACME/SSL by default).
    Providers {
        /// Which catalog to show; omitted means the ACME/SSL providers.
        #[command(subcommand)]
        command: Option<ProviderCommands>,
    },

    /// Sends a development joke to an address through the configured provider.
    ///
    /// Deliberately temporary and hidden: deleted once real account email
    /// (OFF-194/OFF-191) ships.
    #[command(hide = true, name = "send-a-joke")]
    SendAJoke(Box<SendAJokeArgs>),

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

/// Provider catalogs shown by `weaver-server providers`.
#[derive(Subcommand, Debug, Clone)]
pub enum ProviderCommands {
    /// ACME certificate authority providers (the default).
    Ssl,
    /// Transactional email providers.
    Email,
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
    pub tunnel_domain: Option<String>,

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

    /// Transactional-email settings for headless setup.
    #[command(flatten)]
    pub email_settings: EmailArgs,

    /// Internal: path to a 0600 staging file carrying the gathered email block
    /// across the `sudo` re-exec (credentials never travel in `argv`).
    #[arg(long, hide = true, value_name = "PATH")]
    pub email_config_file: Option<PathBuf>,

    /// Internal flag signaling that interactive prompt values are already provided.
    #[arg(long, hide = true)]
    pub no_prompt_values: bool,
}

/// Arguments for the standalone `weaver-server doctor` preflight.
#[derive(Args, Debug, Clone)]
pub struct DoctorArgs {
    /// Tunnel domain (the delegated zone). Falls back to the stored config.
    #[arg(long, value_name = "DOMAIN")]
    pub tunnel_domain: Option<String>,

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
    pub tunnel_domain: Option<String>,

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

    /// Transactional-email settings.
    #[command(flatten)]
    pub email_settings: EmailArgs,

    /// Non-interactive headless execution mode.
    #[arg(long)]
    pub headless: bool,
}

/// Email settings shared by `configure` (and, in part, `setup`).
///
/// `--email-provider` and `--no-email` conflict; passing any other email flag
/// without `--email-provider` is an error rather than a silent default.
#[derive(Args, Debug, Clone, Default)]
pub struct EmailArgs {
    /// Transactional email provider id (see `providers email`).
    #[arg(long, value_name = "ID", conflicts_with = "no_email")]
    pub email_provider: Option<String>,

    /// Disable email accounts, clearing any configured provider.
    #[arg(long)]
    pub no_email: bool,

    /// Verified sender address.
    #[arg(long, value_name = "ADDRESS")]
    pub email_from: Option<String>,

    /// Sender display name.
    #[arg(long, value_name = "NAME")]
    pub email_from_name: Option<String>,

    /// Provider API key, or the SMTP password.
    #[arg(long, value_name = "KEY", conflicts_with = "email_api_key_file")]
    pub email_api_key: Option<String>,

    /// File containing the provider API key or SMTP password.
    #[arg(long, value_name = "PATH")]
    pub email_api_key_file: Option<PathBuf>,

    /// Mailjet secret key.
    #[arg(long, value_name = "SECRET")]
    pub email_secret: Option<String>,

    /// SMTP or HTTP Basic username.
    #[arg(long, value_name = "USER")]
    pub email_username: Option<String>,

    /// Mailgun sending domain.
    #[arg(long, value_name = "DOMAIN")]
    pub email_domain: Option<String>,

    /// Base-URL override: regional host, EU endpoint, or a CI mock.
    #[arg(long, env = "WEAVER_EMAIL_ENDPOINT", value_name = "URL")]
    pub email_endpoint: Option<String>,

    /// Template id required by template-only providers (Loops).
    #[arg(long, value_name = "ID")]
    pub email_template: Option<String>,

    /// OTP code sent by a prior run, proving the provider.
    #[arg(long, env = "WEAVER_EMAIL_OTP", value_name = "CODE")]
    pub email_otp: Option<String>,
}

impl EmailArgs {
    /// Whether any flag that selects or configures email was supplied.
    pub fn configures_email(&self) -> bool {
        self.email_provider.is_some()
            || self.email_from.is_some()
            || self.email_from_name.is_some()
            || self.email_api_key.is_some()
            || self.email_api_key_file.is_some()
            || self.email_secret.is_some()
            || self.email_username.is_some()
            || self.email_domain.is_some()
            || self.email_endpoint.is_some()
            || self.email_template.is_some()
    }

    /// Builds an [`EmailConfig`] from the flags, reading the key file if given.
    fn to_config(&self) -> Result<weaver_server::config::EmailConfig, String> {
        let provider = self
            .email_provider
            .clone()
            .ok_or("configure requires --email-provider when setting email")?;
        let from = self
            .email_from
            .clone()
            .ok_or("configure requires --email-from when setting email")?;
        let api_key = match &self.email_api_key_file {
            Some(path) => Some(
                std::fs::read_to_string(path)
                    .map_err(|e| format!("failed to read key file {}: {e}", path.display()))?
                    .trim()
                    .to_string(),
            ),
            None => self.email_api_key.clone(),
        };
        Ok(weaver_server::config::EmailConfig {
            provider,
            from,
            from_name: self.email_from_name.clone(),
            api_key,
            secret: self.email_secret.clone(),
            username: self.email_username.clone(),
            domain: self.email_domain.clone(),
            endpoint: self.email_endpoint.clone(),
            template_id: self.email_template.clone(),
        })
    }
}

/// Arguments for the hidden `send-a-joke` dev/e2e verb.
#[derive(Args, Debug, Clone)]
pub struct SendAJokeArgs {
    /// Recipient address.
    #[arg(value_name = "ADDRESS")]
    pub address: String,

    /// Override the provider base URL so CI can point at a mock.
    #[arg(long, env = "WEAVER_EMAIL_ENDPOINT", value_name = "URL")]
    pub email_endpoint: Option<String>,
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

            let gathered = gather_acme_config(
                AcmeConfigInputs {
                    tunnel_domain: args.tunnel_domain,
                    admin_domain: args.admin_domain,
                    email: args.email,
                    acme_provider: args.acme_provider,
                    acme_directory: args.acme_directory,
                    acme_eab_kid: args.acme_eab_kid,
                    acme_eab_hmac: args.acme_eab_hmac,
                    acme_eab_hmac_file: args.acme_eab_hmac_file,
                    acme_root_ca: args.acme_root_ca,
                    headless: args.headless,
                    // `configure` is never re-exec'd for elevation, so there is
                    // no pre-supplied prompt-values path.
                    no_prompt_values: false,
                },
                GatherOptions {
                    print_intro: false,
                    offer_provider_choice: false,
                },
            );
            let GatheredAcme {
                tunnel_domain,
                admin_domain,
                admin_email,
                acme_provider,
                acme_directory,
                acme_eab_kid,
                acme_eab_hmac,
                acme_root_ca,
            } = gathered;

            let store = Store::open(&db_path).await.unwrap_or_else(|err| {
                eprintln!("Failed to open database at {}: {err}", db_path.display());
                std::process::exit(1);
            });

            // Load the previous config once: it supplies the detected public
            // addresses (re-running setup refreshes them) and the existing
            // email block, which flags preserve when they do not set one.
            let existing_config: Option<Config> = store
                .load_config_json()
                .await
                .ok()
                .flatten()
                .and_then(|json| serde_json::from_str::<Config>(&json).ok());
            let existing_relay_ips = existing_config
                .as_ref()
                .map(|cfg| cfg.relay_ips.clone())
                .unwrap_or_default();
            let existing_email = existing_config.as_ref().and_then(|cfg| cfg.email.clone());

            let root_ca_pem = match acme_root_ca {
                Some(path) => match std::fs::read_to_string(&path) {
                    Ok(content) => Some(content),
                    Err(err) => {
                        eprintln!("Failed to read root CA file at {}: {err}", path.display());
                        std::process::exit(1);
                    }
                },
                None => None,
            };

            let email_decision =
                match decide_configure_email(&args.email_settings, existing_email.clone()) {
                    Ok(decision) => decision,
                    Err(msg) => {
                        eprintln!("{} {msg}", "✗ Error:".red().bold());
                        std::process::exit(2);
                    }
                };

            let mut config = Config {
                tunnel_domain,
                admin_domain: admin_domain.clone(),
                admin_email: admin_email.clone(),
                acme_provider,
                listen_http: args.listen_http,
                listen_https: args.listen_https,
                control_socket: args.control_socket,
                acme_directory,
                acme_eab_kid,
                acme_eab_hmac,
                acme_root_ca_pem: root_ca_pem,
                acme_fallback_providers: Vec::new(),
                usage_flush_interval_secs: args.usage_flush_interval,
                relay_ips: existing_relay_ips,
                // `configure` is the non-systemd (container) flavour: there is no
                // interactive preflight to gate on, and the operator owns DNS.
                // Mark setup complete so the daemon auto-orders the wildcard at
                // startup instead of waiting for a `setup` that never runs.
                setup_complete: true,
                email: None,
            };

            match email_decision {
                ConfigureEmail::Preserve(email) => {
                    config.email = email;
                }
                ConfigureEmail::Disable => {
                    config.email = None;
                    let _ = weaver_server::email::otp::PendingOtp::clear(&store).await;
                }
                ConfigureEmail::Verify(code) => {
                    match weaver_server::email::otp::PendingOtp::load(&store).await {
                        Ok(Some(mut pending)) => match pending.verify(&code) {
                            Ok(()) => config.email = Some(pending.pending.clone()),
                            Err(err) => {
                                // Persist the incremented attempt count, then stop.
                                let _ = pending.save(&store).await;
                                eprintln!("{} {err}", "✗ Error:".red().bold());
                                std::process::exit(1);
                            }
                        },
                        Ok(None) => {
                            eprintln!(
                                "{} no pending email OTP; run configure with the email flags first",
                                "✗ Error:".red().bold()
                            );
                            std::process::exit(1);
                        }
                        Err(err) => {
                            eprintln!("{} {err}", "✗ Error:".red().bold());
                            std::process::exit(1);
                        }
                    }
                }
                ConfigureEmail::Begin(cfg) => {
                    // Persist the base config first so the pending challenge can
                    // live in the same JSON singleton.
                    config.email = existing_email;
                    if let Err(err) = store.save_config(&config).await {
                        eprintln!("Failed to write configuration: {err}");
                        std::process::exit(1);
                    }
                    let support_url = format!("https://{admin_domain}");
                    let code =
                        match weaver_server::email::otp::PendingOtp::issue(&store, cfg.clone())
                            .await
                        {
                            Ok(code) => code,
                            Err(err) => {
                                eprintln!("{} {err}", "✗ Error:".red().bold());
                                std::process::exit(1);
                            }
                        };
                    if let Err(err) = send_email_otp(&cfg, &support_url, &admin_email, &code).await
                    {
                        let _ = weaver_server::email::otp::PendingOtp::clear(&store).await;
                        eprintln!("{} {err}", "✗ Error:".red().bold());
                        std::process::exit(1);
                    }
                    println!(
                        "An email OTP was sent to {admin_email}. Re-run configure with --email-otp CODE."
                    );
                    std::process::exit(1);
                }
            }

            if let Err(err) = store.save_config(&config).await {
                eprintln!("Failed to write configuration: {err}");
                std::process::exit(1);
            }

            println!("Configuration saved to {}", db_path.display());
        }
        Commands::Providers { command } => match command {
            None | Some(ProviderCommands::Ssl) => {
                weaver_server::cert::providers::print_providers();
            }
            Some(ProviderCommands::Email) => {
                weaver_server::email::providers::print_providers();
            }
        },
        Commands::SendAJoke(args) => {
            let db_path = cli
                .db
                .unwrap_or_else(|| PathBuf::from("/var/lib/weaver/weaver.db"));
            let code = handle_send_a_joke(*args, db_path).await;
            std::process::exit(code);
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

/// Sends a development joke through the configured provider.
///
/// Returns the process exit code. Errors already carry redacted provider
/// detail; this only adds the surrounding frame.
async fn handle_send_a_joke(args: SendAJokeArgs, db_path: PathBuf) -> i32 {
    use weaver_server::email::{Joke, Mailbox, jokes, mailer_from_config};

    let store = match Store::open(&db_path).await {
        Ok(store) => store,
        Err(err) => {
            eprintln!(
                "{} Failed to open database at {}: {err}",
                "✗ Error:".red().bold(),
                db_path.display()
            );
            return 1;
        }
    };
    let config = match Config::load(&store).await {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{} {err}", "✗ Error:".red().bold());
            return 1;
        }
    };
    let _ = store.close().await;

    // The support link in the shared footer is the relay's own admin host.
    let support_url = format!("https://{}", config.admin_domain);
    let mut email_config = config.email.clone();
    if let (Some(cfg), Some(endpoint)) = (email_config.as_mut(), args.email_endpoint.as_deref()) {
        cfg.endpoint = Some(endpoint.to_string());
    }

    let mailer = match mailer_from_config(email_config.as_ref(), &support_url) {
        Ok(mailer) => mailer,
        Err(err) => {
            eprintln!("{} {err}", "✗ Error:".red().bold());
            return 1;
        }
    };

    let to = match Mailbox::parse(&args.address, None) {
        Ok(to) => to,
        Err(err) => {
            eprintln!("{} {err}", "✗ Error:".red().bold());
            return 2;
        }
    };

    let joke = Joke {
        line: jokes::pick().to_string(),
    };
    let email = match mailer.compose(to, &joke) {
        Ok(email) => email,
        Err(err) => {
            eprintln!("{} {err}", "✗ Error:".red().bold());
            return 1;
        }
    };

    match mailer.send(&email).await {
        Ok(receipt) => {
            println!(
                "sent via {} (id={})",
                mailer.identity().display,
                receipt.message_id.as_deref().unwrap_or("-")
            );
            0
        }
        Err(err) => {
            eprintln!("{} {err}", "✗ Error:".red().bold());
            1
        }
    }
}

/// What a `configure` invocation decided about email.
enum ConfigureEmail {
    /// No email flags: keep whatever was stored.
    Preserve(Option<weaver_server::config::EmailConfig>),
    /// `--no-email`: clear it.
    Disable,
    /// `--email-otp CODE`: verify the pending challenge.
    Verify(String),
    /// First run: the config was built and validated; send an OTP next.
    Begin(weaver_server::config::EmailConfig),
}

/// Decides how `configure` changes the email block, building and validating a
/// new one when the flags ask for it.
fn decide_configure_email(
    settings: &EmailArgs,
    existing: Option<weaver_server::config::EmailConfig>,
) -> Result<ConfigureEmail, String> {
    if settings.no_email {
        return Ok(ConfigureEmail::Disable);
    }
    if let Some(code) = settings.email_otp.clone() {
        return Ok(ConfigureEmail::Verify(code));
    }
    if !settings.configures_email() {
        return Ok(ConfigureEmail::Preserve(existing));
    }
    let cfg = settings.to_config()?;
    let issues = weaver_server::email::providers::validate_email_config(&cfg);
    if !issues.is_empty() {
        return Err(format!(
            "email configuration invalid: {}",
            issues.join("; ")
        ));
    }
    Ok(ConfigureEmail::Begin(cfg))
}

/// Sends the setup/configure OTP through the configured provider.
async fn send_email_otp(
    cfg: &weaver_server::config::EmailConfig,
    support_url: &str,
    admin_email: &str,
    code: &str,
) -> Result<(), weaver_server::email::MailerError> {
    use weaver_server::email::{Mailbox, Otp, mailer_from_config};
    let mailer = mailer_from_config(Some(cfg), support_url)?;
    let to = Mailbox::parse(admin_email, None)?;
    let email = mailer.compose(
        to,
        &Otp {
            code: code.to_string(),
        },
    )?;
    mailer.send(&email).await.map(|_| ())
}

/// Resolves the setup email block for the current phase.
///
/// Interactive setup prompts and returns the config (the OTP is proven later,
/// after the plan). Headless setup uses the flags plus the persisted two-step
/// OTP. The elevated child only reads the staged file.
async fn resolve_setup_email(
    email_settings: &EmailArgs,
    email_config_file: Option<&std::path::Path>,
    no_prompt_values: bool,
    headless: bool,
    db_path: &std::path::Path,
    admin_domain: &str,
    admin_email: &str,
) -> Option<weaver_server::config::EmailConfig> {
    if no_prompt_values {
        return match email_config_file {
            Some(path) => match read_email_config_file(path) {
                Ok(cfg) => cfg,
                Err(err) => {
                    eprintln!(
                        "{} Failed to read staged email config: {err}",
                        "✗ Error:".red().bold()
                    );
                    std::process::exit(1);
                }
            },
            None => None,
        };
    }

    if headless {
        if !email_settings.configures_email() && email_settings.email_otp.is_none() {
            return None;
        }
        let store = Store::open(db_path).await.unwrap_or_else(|err| {
            eprintln!("Failed to open database at {}: {err}", db_path.display());
            std::process::exit(1);
        });

        if let Some(code) = email_settings.email_otp.clone() {
            let mut pending = match weaver_server::email::otp::PendingOtp::load(&store).await {
                Ok(Some(pending)) => pending,
                Ok(None) => {
                    eprintln!(
                        "{} no pending email OTP; run setup with the email flags first",
                        "✗ Error:".red().bold()
                    );
                    std::process::exit(1);
                }
                Err(err) => {
                    eprintln!("{} {err}", "✗ Error:".red().bold());
                    std::process::exit(1);
                }
            };
            return match pending.verify(&code) {
                Ok(()) => Some(pending.pending.clone()),
                Err(err) => {
                    let _ = pending.save(&store).await;
                    eprintln!("{} {err}", "✗ Error:".red().bold());
                    std::process::exit(1);
                }
            };
        }

        let cfg = match email_settings.to_config() {
            Ok(cfg) => cfg,
            Err(msg) => {
                eprintln!("{} {msg}", "✗ Error:".red().bold());
                std::process::exit(2);
            }
        };
        let issues = weaver_server::email::providers::validate_email_config(&cfg);
        if !issues.is_empty() {
            eprintln!(
                "{} email configuration invalid: {}",
                "✗ Error:".red().bold(),
                issues.join("; ")
            );
            std::process::exit(2);
        }
        let support_url = format!("https://{admin_domain}");
        let code = match weaver_server::email::otp::PendingOtp::issue(&store, cfg.clone()).await {
            Ok(code) => code,
            Err(err) => {
                eprintln!("{} {err}", "✗ Error:".red().bold());
                std::process::exit(1);
            }
        };
        if let Err(err) = send_email_otp(&cfg, &support_url, admin_email, &code).await {
            let _ = weaver_server::email::otp::PendingOtp::clear(&store).await;
            eprintln!("{} {err}", "✗ Error:".red().bold());
            std::process::exit(1);
        }
        println!("An email OTP was sent to {admin_email}. Re-run setup with --email-otp CODE.");
        std::process::exit(1);
    }

    match weaver_server::setup::interactive::prompt_email_config() {
        Ok(cfg) => cfg,
        Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
            eprintln!("\n{} Cancelled by user.", "•".blue());
            std::process::exit(130);
        }
        Err(err) => {
            eprintln!(
                "{} Interactive prompt failed: {err}",
                "✗ Error:".red().bold()
            );
            std::process::exit(1);
        }
    }
}

/// Sends and verifies the interactive setup OTP before any host change.
async fn verify_setup_email_otp(
    cfg: &weaver_server::config::EmailConfig,
    admin_domain: &str,
    admin_email: &str,
) {
    use weaver_server::email::otp::{self, OtpChallenge};
    use weaver_server::email::{Mailbox, Otp, mailer_from_config};

    let support_url = format!("https://{admin_domain}");
    let mailer = match mailer_from_config(Some(cfg), &support_url) {
        Ok(mailer) => mailer,
        Err(err) => {
            eprintln!("{} {err}", "✗ Error:".red().bold());
            std::process::exit(1);
        }
    };
    let to = match Mailbox::parse(admin_email, None) {
        Ok(to) => to,
        Err(err) => {
            eprintln!("{} {err}", "✗ Error:".red().bold());
            std::process::exit(1);
        }
    };

    let mut challenge = OtpChallenge::generate();
    let email = match mailer.compose(
        to,
        &Otp {
            code: challenge.code().to_string(),
        },
    ) {
        Ok(email) => email,
        Err(err) => {
            eprintln!("{} {err}", "✗ Error:".red().bold());
            std::process::exit(1);
        }
    };
    if let Err(err) = mailer.send(&email).await {
        eprintln!(
            "{} Failed to send the verification email: {err}",
            "✗ Error:".red().bold()
        );
        std::process::exit(1);
    }
    println!("  {} An email OTP was sent to {admin_email}.", "•".blue());

    loop {
        let input = prompt_required(|| {
            weaver_server::setup::interactive::prompt_line("Enter the email OTP", None)
        });
        match challenge.verify(&input) {
            Ok(()) => {
                println!("  {} Email provider verified.", "✓".green());
                return;
            }
            Err(err) => {
                eprintln!("{} {err}", "✗ Error:".red().bold());
                if matches!(err, otp::OtpError::Expired | otp::OtpError::TooManyAttempts) {
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Writes the gathered email block to a mode-0600 file whose path alone crosses
/// the `sudo` boundary. Returns the path.
fn write_email_config_staging(
    cfg: &weaver_server::config::EmailConfig,
) -> std::io::Result<PathBuf> {
    let path = std::env::temp_dir().join(format!("weaver-email-{}.json", std::process::id()));
    let json = serde_json::to_vec(cfg).map_err(std::io::Error::other)?;

    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(&json)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, &json)?;
    }
    Ok(path)
}

/// Reads and unlinks the staged email block from the elevated child.
fn read_email_config_file(
    path: &std::path::Path,
) -> std::io::Result<Option<weaver_server::config::EmailConfig>> {
    let bytes = std::fs::read(path)?;
    let _ = std::fs::remove_file(path);
    let cfg = serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
    Ok(Some(cfg))
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

/// ACME and domain inputs shared by `setup` and `configure`.
struct AcmeConfigInputs {
    tunnel_domain: Option<String>,
    admin_domain: Option<String>,
    email: Option<String>,
    acme_provider: String,
    acme_directory: Option<String>,
    acme_eab_kid: Option<String>,
    acme_eab_hmac: Option<String>,
    acme_eab_hmac_file: Option<PathBuf>,
    acme_root_ca: Option<PathBuf>,
    headless: bool,
    no_prompt_values: bool,
}

/// Presentation choices that differ between `setup` and `configure`.
#[derive(Clone, Copy)]
struct GatherOptions {
    /// Print the two-domain setup preamble before prompting.
    print_intro: bool,
    /// Offer the interactive ACME provider menu when no provider was chosen.
    offer_provider_choice: bool,
}

/// The gathered, validated ACME/domain configuration.
struct GatheredAcme {
    tunnel_domain: String,
    admin_domain: String,
    admin_email: String,
    acme_provider: String,
    acme_directory: Option<String>,
    acme_eab_kid: Option<String>,
    acme_eab_hmac: Option<String>,
    /// Path to a custom root CA PEM, if one was supplied.
    acme_root_ca: Option<PathBuf>,
}

/// Runs an interactive prompt, exiting the process when the operator aborts.
///
/// `inquire` reports Ctrl-C as an interrupt and Ctrl-D / Esc as a cancel; the
/// `interactive` module surfaces both as [`std::io::ErrorKind::Interrupted`]. An
/// abort is a request to stop and must never be mistaken for an empty answer
/// that gets retried. Any other prompt failure is fatal too — silently falling
/// back to a default would invent an answer the operator never gave.
fn prompt_required<T>(prompt: impl FnOnce() -> std::io::Result<T>) -> T {
    match prompt() {
        Ok(value) => value,
        Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
            eprintln!("\n{} Cancelled by user.", "•".blue());
            std::process::exit(130);
        }
        Err(err) => {
            eprintln!(
                "{} Interactive prompt failed: {err}",
                "✗ Error:".red().bold()
            );
            std::process::exit(1);
        }
    }
}

/// Gathers and validates the domain and ACME settings for `setup` and `configure`.
///
/// Both commands ask for the same fields with the same validation; only the
/// preamble and the optional provider menu differ, which `options` selects.
/// Invalid input exits the process with code 2, matching the commands'
/// existing behaviour.
fn gather_acme_config(mut inputs: AcmeConfigInputs, options: GatherOptions) -> GatheredAcme {
    use weaver_server::setup::interactive;

    // A custom directory implies the `custom` provider.
    if inputs.acme_directory.is_some() && inputs.acme_provider == "letsencrypt" {
        inputs.acme_provider = "custom".into();
    }

    let mut eab_hmac = match (
        inputs.acme_eab_hmac.take(),
        inputs.acme_eab_hmac_file.take(),
    ) {
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

    let mut acme_provider = inputs.acme_provider;
    let mut acme_directory = inputs.acme_directory;
    let mut eab_kid = inputs.acme_eab_kid;
    let mut root_ca = inputs.acme_root_ca;

    let (tunnel_domain, admin_domain, admin_email) = if inputs.no_prompt_values {
        (
            inputs
                .tunnel_domain
                .expect("tunnel_domain missing with --no-prompt-values"),
            inputs
                .admin_domain
                .expect("admin_domain missing with --no-prompt-values"),
            inputs.email.expect("email missing with --no-prompt-values"),
        )
    } else if inputs.headless {
        let Some(rd) = inputs.tunnel_domain else {
            eprintln!("Error: Missing required option --tunnel-domain in headless mode");
            std::process::exit(2);
        };
        let Some(ad) = inputs.admin_domain else {
            eprintln!("Error: Missing required option --admin-domain in headless mode");
            std::process::exit(2);
        };
        let Some(email) = inputs.email else {
            eprintln!("Error: Missing required option --email in headless mode");
            std::process::exit(2);
        };
        if !interactive::validate_fqdn(&rd) {
            eprintln!("Error: Invalid root domain '{rd}'. Must be a valid FQDN.");
            std::process::exit(2);
        }
        if !interactive::validate_fqdn(&ad) {
            eprintln!("Error: Invalid admin domain '{ad}'. Must be a valid FQDN.");
            std::process::exit(2);
        }
        if let Some(issue) = weaver_server::config::domain_split_issue(&ad, &rd) {
            eprintln!("Error: {issue}");
            std::process::exit(2);
        }
        if !interactive::validate_email(&email) {
            eprintln!("Error: Invalid email '{email}'.");
            std::process::exit(2);
        }
        let prov_info = weaver_server::cert::providers::find_provider(&acme_provider);
        if prov_info.is_some_and(|p| p.eab_required) && (eab_kid.is_none() || eab_hmac.is_none()) {
            eprintln!(
                "Error: Provider '{acme_provider}' requires both EAB KID and EAB HMAC \
                 (--acme-eab-kid / --acme-eab-hmac) in headless mode"
            );
            std::process::exit(2);
        }
        (rd, ad, email)
    } else {
        if options.print_intro {
            interactive::print_domain_step_intro();
        }

        let rd = match inputs.tunnel_domain {
            Some(d) => {
                if !interactive::validate_fqdn(&d) {
                    eprintln!("Error: Invalid root domain '{d}'. Must be a valid FQDN.");
                    std::process::exit(2);
                }
                d
            }
            None => loop {
                let input = prompt_required(|| {
                    interactive::prompt_line("Tunnel domain (delegated to this relay)", None)
                });
                if interactive::validate_fqdn(&input) {
                    break input;
                }
                println!(
                    "{} Invalid domain name. Must be a valid FQDN (e.g. example.com).",
                    "✗".red().bold()
                );
            },
        };

        let ad = match inputs.admin_domain {
            Some(d) => {
                if !interactive::validate_fqdn(&d) {
                    eprintln!("Error: Invalid admin domain '{d}'. Must be a valid FQDN.");
                    std::process::exit(2);
                }
                d
            }
            None => loop {
                let input = prompt_required(|| {
                    interactive::prompt_line(
                        "Admin domain (the relay's own hostname, outside the tunnel zone)",
                        None,
                    )
                });
                if interactive::validate_fqdn(&input) {
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

        let email = match inputs.email {
            Some(e) => {
                if !interactive::validate_email(&e) {
                    eprintln!("Error: Invalid email '{e}'.");
                    std::process::exit(2);
                }
                e
            }
            None => loop {
                let input = prompt_required(|| interactive::prompt_line("Admin email", None));
                if interactive::validate_email(&input) {
                    break input;
                }
                println!("{} Invalid email address.", "✗".red().bold());
            },
        };

        if options.offer_provider_choice
            && eab_kid.is_none()
            && acme_directory.is_none()
            && acme_provider == "letsencrypt"
        {
            let (chosen_prov, custom_dir) = prompt_required(interactive::prompt_provider_choice);
            acme_provider = chosen_prov;
            if let Some(dir) = custom_dir {
                acme_directory = Some(dir);
            }
            let prov_info = weaver_server::cert::providers::find_provider(&acme_provider);
            if prov_info.is_some_and(|p| p.eab_required) {
                let kid =
                    prompt_required(|| interactive::prompt_line("EAB Key Identifier (KID)", None));
                let hmac = prompt_required(|| interactive::read_masked_input("EAB HMAC Key"));
                eab_kid = Some(kid);
                eab_hmac = Some(hmac);
            } else if acme_provider == "custom" {
                let need_eab = prompt_required(|| {
                    interactive::prompt_line("Does this directory require EAB? [y/N]", Some("n"))
                });
                if need_eab.eq_ignore_ascii_case("y") || need_eab.eq_ignore_ascii_case("yes") {
                    let kid = prompt_required(|| {
                        interactive::prompt_line("EAB Key Identifier (KID)", None)
                    });
                    let hmac = prompt_required(|| interactive::read_masked_input("EAB HMAC Key"));
                    eab_kid = Some(kid);
                    eab_hmac = Some(hmac);
                }
                let ca_path_str = prompt_required(|| {
                    interactive::prompt_line(
                        "Custom Root CA PEM path (optional, press enter to skip)",
                        None,
                    )
                });
                if !ca_path_str.is_empty() {
                    root_ca = Some(PathBuf::from(ca_path_str));
                }
            }
        }

        (rd, ad, email)
    };

    GatheredAcme {
        tunnel_domain,
        admin_domain,
        admin_email,
        acme_provider,
        acme_directory,
        acme_eab_kid: eab_kid,
        acme_eab_hmac: eab_hmac,
        acme_root_ca: root_ca,
    }
}

async fn handle_setup(args: SetupArgs, db_path: PathBuf) {
    // 1. Gather configuration (shared with `configure`).
    let gathered_acme = gather_acme_config(
        AcmeConfigInputs {
            tunnel_domain: args.tunnel_domain,
            admin_domain: args.admin_domain,
            email: args.email,
            acme_provider: args.acme_provider,
            acme_directory: args.acme_directory,
            acme_eab_kid: args.acme_eab_kid,
            acme_eab_hmac: args.acme_eab_hmac,
            acme_eab_hmac_file: args.acme_eab_hmac_file,
            acme_root_ca: args.acme_root_ca,
            headless: args.headless,
            no_prompt_values: args.no_prompt_values,
        },
        GatherOptions {
            print_intro: true,
            offer_provider_choice: true,
        },
    );
    let GatheredAcme {
        tunnel_domain,
        admin_domain,
        admin_email,
        acme_provider,
        acme_directory,
        acme_eab_kid: eab_kid,
        acme_eab_hmac: eab_hmac,
        acme_root_ca: root_ca_path,
    } = gathered_acme;

    // Gather email settings before the plan so the table can show the provider
    // and sender; the OTP proof runs after confirmation, before elevation.
    let email_config = resolve_setup_email(
        &args.email_settings,
        args.email_config_file.as_deref(),
        args.no_prompt_values,
        args.headless,
        &db_path,
        &admin_domain,
        &admin_email,
    )
    .await;

    let mut gathered = weaver_server::setup::interactive::GatheredConfig {
        tunnel_domain: tunnel_domain.clone(),
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
        email: email_config.clone(),
        email_config_file: None,
    };

    // 2. Display execution plan & confirm (if not already elevated)
    if !args.no_prompt_values {
        match weaver_server::setup::interactive::display_plan_and_confirm(&gathered, args.headless)
        {
            Ok(true) => {}
            Ok(false) => {
                println!("Setup cancelled by user.");
                std::process::exit(0);
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                eprintln!("\n{} Cancelled by user.", "•".blue());
                std::process::exit(130);
            }
            Err(err) => {
                eprintln!(
                    "{} Interactive prompt failed: {err}",
                    "✗ Error:".red().bold()
                );
                std::process::exit(1);
            }
        }

        // 3. Prove the email provider before elevation, then stage credentials.
        //    Interactive setup sends and verifies the OTP now; headless already
        //    proved it via the persisted two-step. Credentials never travel in
        //    `argv`, so a 0600 file carries the block and only its path is
        //    forwarded across `sudo`.
        if !args.headless
            && let Some(cfg) = email_config.as_ref()
        {
            verify_setup_email_otp(cfg, &admin_domain, &admin_email).await;
        }
        if let Some(cfg) = email_config.as_ref()
            && !weaver_server::setup::privilege::is_root()
        {
            match write_email_config_staging(cfg) {
                Ok(path) => gathered.email_config_file = Some(path),
                Err(err) => {
                    eprintln!(
                        "{} Failed to stage email credentials: {err}",
                        "✗ Error:".red().bold()
                    );
                    std::process::exit(1);
                }
            }
        }

        // 4. Privilege elevation if needed
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
        &tunnel_domain,
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
    let port_80 = weaver_server::setup::doctor::port_status(
        &report,
        weaver_server::setup::planner::Port::Http,
    );
    let port_443 = weaver_server::setup::doctor::port_status(
        &report,
        weaver_server::setup::planner::Port::Https,
    );
    let port_53 = weaver_server::setup::doctor::port_status(
        &report,
        weaver_server::setup::planner::Port::Dns,
    );

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
        target_domain: tunnel_domain.clone(),
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
        &plan.tunnel_domain,
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
    Some((config.tunnel_domain, config.admin_domain))
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
    let (tunnel_domain, admin_domain) = match (args.tunnel_domain, args.admin_domain) {
        (Some(root), Some(admin)) => (root, admin),
        (root, admin) => {
            let stored = load_stored_domains(std::path::Path::new(&db_path)).await;
            let root = root.or_else(|| stored.as_ref().map(|(r, _)| r.clone()));
            let admin = admin.or_else(|| stored.as_ref().map(|(_, a)| a.clone()));
            match (root, admin) {
                (Some(root), Some(admin)) => (root, admin),
                _ => {
                    eprintln!(
                        "Error: --tunnel-domain and --admin-domain are required when no installed \
                         configuration exists at {}",
                        db_path.display()
                    );
                    std::process::exit(2);
                }
            }
        }
    };

    if !weaver_server::setup::interactive::validate_fqdn(&tunnel_domain) {
        eprintln!("Error: Invalid root domain '{tunnel_domain}'. Must be a valid FQDN.");
        std::process::exit(2);
    }
    if !weaver_server::setup::interactive::validate_fqdn(&admin_domain) {
        eprintln!("Error: Invalid admin domain '{admin_domain}'. Must be a valid FQDN.");
        std::process::exit(2);
    }

    let report = weaver_server::setup::doctor::run_in_process(
        &tunnel_domain,
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
