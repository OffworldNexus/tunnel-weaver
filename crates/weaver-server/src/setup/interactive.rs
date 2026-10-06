//! Interactive prompting and validation for the `weaver-server setup` command.
//!
//! Collects and validates domain names, admin email, ACME provider configuration,
//! and displays a structured plan before executing installation.

use std::fmt;
use std::path::PathBuf;

use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};
use crossterm::style::Stylize;
use inquire::{Confirm, InquireError, Password, PasswordDisplayMode, Select, Text};

use crate::config::EmailConfig;
use crate::email::providers::{CredentialField, PROVIDERS};

/// Configuration values gathered interactively or via CLI arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatheredConfig {
    pub tunnel_domain: String,
    pub admin_domain: String,
    pub admin_email: String,
    pub acme_provider: String,
    pub acme_directory: Option<String>,
    pub acme_eab_kid: Option<String>,
    pub acme_eab_hmac: Option<String>,
    pub acme_root_ca_path: Option<PathBuf>,
    pub db_path: PathBuf,
    pub user: String,
    pub prefix: PathBuf,
    pub skip_reachability_check: bool,
    /// Operator-supplied public IPs, forwarded across the `sudo` re-exec so a
    /// NAT deployment keeps its explicit `--relay-ip` values.
    pub relay_ips: Vec<std::net::IpAddr>,
    /// Gathered transactional-email settings, or `None` when email is off.
    pub email: Option<EmailConfig>,
    /// A 0600 staging file the elevated child reads the email block from, so
    /// credentials never cross the privilege boundary in `argv`.
    pub email_config_file: Option<PathBuf>,
}

/// Validates whether a domain name is a structurally valid Fully Qualified Domain Name (FQDN).
pub fn validate_fqdn(domain: &str) -> bool {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    for part in parts {
        if part.is_empty() || part.len() > 63 {
            return false;
        }
        if part.starts_with('-') || part.ends_with('-') {
            return false;
        }
        if !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    true
}

/// Validates whether an email string contains standard plausible email syntax.
pub fn validate_email(email: &str) -> bool {
    let email = email.trim();
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let (user, domain) = (parts[0], parts[1]);
    if user.is_empty() || domain.is_empty() || !domain.contains('.') {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    true
}

/// Converts an [`InquireError`] into the `std::io::Error` that this module's
/// API exposes, so callers keep their existing `Result` shape.
///
/// `inquire` reports a non-TTY input device as [`InquireError::NotTTY`], which
/// lets `prompt_line` fail with an `io::Error` on a pipe instead of panicking.
fn inquire_err(err: InquireError) -> std::io::Error {
    match err {
        InquireError::IO(err) => err,
        InquireError::OperationCanceled | InquireError::OperationInterrupted => {
            std::io::Error::new(std::io::ErrorKind::Interrupted, err)
        }
        other => std::io::Error::other(other),
    }
}

/// Prompts the user with an `inquire` [`Text`] prompt and returns the trimmed
/// answer.
///
/// A `default` is pre-filled as the initial value, so pressing Enter accepts it;
/// clearing the field first yields the empty string. Because `Text` handles the
/// arrow keys and line editing, no raw-mode handling is needed here.
pub fn prompt_line(prompt: &str, default: Option<&str>) -> std::io::Result<String> {
    let mut text = Text::new(prompt);
    if let Some(def) = default {
        text = text.with_initial_value(def);
    }
    text.prompt()
        .map(|input| input.trim().to_string())
        .map_err(inquire_err)
}

/// Reads masked input for sensitive values (such as API keys and EAB HMAC keys).
///
/// Uses `inquire`'s [`Password`] prompt. Its default display mode is *hidden*:
/// nothing is drawn while the operator types, so a dropped character, a stray
/// paste, or accidental surrounding quoting is invisible until the provider
/// refuses the credential. We render the input masked instead (one `*` per
/// character) and leave the Ctrl+R reveal toggle enabled, so the value can be
/// checked before submitting. Confirmation stays disabled to preserve the
/// single-entry semantics.
pub fn read_masked_input(prompt: &str) -> std::io::Result<String> {
    Password::new(prompt)
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_display_toggle_enabled()
        .with_help_message("Ctrl+R reveals the value; Enter submits")
        .without_confirmation()
        .prompt()
        .map_err(inquire_err)
}

/// One selectable ACME provider; `Display` supplies the visible label so the
/// `Select` list reads like the old numbered menu without the numbering.
struct ProviderOption {
    id: &'static str,
    label: &'static str,
}

impl fmt::Display for ProviderOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label)
    }
}

/// Displays the interactive ACME provider selection menu with a compact auto-formatted table.
pub fn prompt_provider_choice() -> std::io::Result<(String, Option<String>)> {
    println!("\n{}", "Step 2: Certificate Provider".bold().white());
    println!(
        "  {}",
        "Choose an Automated Certificate Management Environment (ACME) provider:".dark_grey()
    );
    println!();

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("#")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Provider")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("EAB")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Quota")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Notes")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
    ]);

    table.add_row(vec![
        Cell::new("1")
            .add_attribute(Attribute::Bold)
            .fg(Color::Green),
        Cell::new("Let's Encrypt (default)")
            .add_attribute(Attribute::Bold)
            .fg(Color::Green),
        Cell::new("no").fg(Color::DarkGrey),
        Cell::new("50/week"),
        Cell::new("Standard Web PKI; no account needed"),
    ]);

    table.add_row(vec![
        Cell::new("2").add_attribute(Attribute::Bold),
        Cell::new("Google Trust Services").fg(Color::White),
        Cell::new("required")
            .fg(Color::Yellow)
            .add_attribute(Attribute::Bold),
        Cell::new("Very high"),
        Cell::new("Requires GCP project and EAB credentials"),
    ]);

    table.add_row(vec![
        Cell::new("3").add_attribute(Attribute::Bold),
        Cell::new("ZeroSSL").fg(Color::White),
        Cell::new("required")
            .fg(Color::Yellow)
            .add_attribute(Attribute::Bold),
        Cell::new("Unlimited"),
        Cell::new("Requires ZeroSSL account and EAB credentials"),
    ]);

    table.add_row(vec![
        Cell::new("4").add_attribute(Attribute::Bold),
        Cell::new("Buypass").fg(Color::White),
        Cell::new("no").fg(Color::DarkGrey),
        Cell::new("20/week"),
        Cell::new("No account needed; 180-day certificates"),
    ]);

    table.add_row(vec![
        Cell::new("5").add_attribute(Attribute::Bold),
        Cell::new("Custom ACME").fg(Color::DarkCyan),
        Cell::new("optional").fg(Color::DarkGrey),
        Cell::new("Custom"),
        Cell::new("Custom ACME URL (Pebble, step-ca, internal CA)"),
    ]);

    println!("{table}\n");

    let providers = vec![
        ProviderOption {
            id: "letsencrypt",
            label: "Let's Encrypt (default)",
        },
        ProviderOption {
            id: "google",
            label: "Google Trust Services",
        },
        ProviderOption {
            id: "zerossl",
            label: "ZeroSSL",
        },
        ProviderOption {
            id: "buypass",
            label: "Buypass",
        },
        ProviderOption {
            id: "custom",
            label: "Custom ACME",
        },
    ];

    let choice = Select::new("Select an ACME provider:", providers)
        .prompt()
        .map_err(inquire_err)?;

    if choice.id == "custom" {
        let url = prompt_line("ACME directory URL", None)?;
        return Ok(("custom".into(), Some(url)));
    }
    Ok((choice.id.into(), None))
}

/// Current terminal width in columns, falling back to the conventional 80 when
/// stdout is not attached to a terminal.
fn terminal_width() -> usize {
    crossterm::terminal::size()
        .map(|(cols, _)| cols as usize)
        .unwrap_or(80)
}

/// Greedy ASCII word wrap: packs words into lines of at most `width` columns.
///
/// A word longer than `width` is kept intact on its own line rather than split
/// mid-word. Blank input yields no lines.
pub fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// Prints `text` to stdout, wrapped to the current terminal width and prefixed
/// by `indent` on every line.
///
/// Wrapping happens after the indent is subtracted, so continuation lines are
/// hanging-indented under the first and nothing hard-wraps mid-sentence.
pub fn print_wrapped(indent: &str, text: &str) {
    let width = terminal_width()
        .saturating_sub(indent.chars().count())
        .max(1);
    for line in wrap_text(text, width) {
        println!("{indent}{line}");
    }
}

/// Like [`print_wrapped`], but styles a leading `label` and hangs continuation
/// lines under the text that follows it. Used for the domain explanations so
/// the coloured label stays put while the sentence wraps.
fn print_labeled_wrapped(indent: &str, label: &str, rest: &str) {
    let prefix_width = indent.chars().count() + label.chars().count() + 1;
    let width = terminal_width().saturating_sub(prefix_width).max(1);
    let lines = wrap_text(rest, width);
    if lines.is_empty() {
        println!("{indent}{}", label.bold().green());
        return;
    }
    for (index, line) in lines.iter().enumerate() {
        if index == 0 {
            println!("{indent}{} {line}", label.bold().green());
        } else {
            println!("{}{line}", " ".repeat(prefix_width));
        }
    }
}

/// Prints the Step 1 preamble explaining the two domains and the DNS records
/// the operator must create before setup can proceed.
///
/// Setup is mechanical, so there are no choices here; the text exists purely to
/// make the two prompts self-explanatory and to state the expected delegation
/// up front, before any host modification.
pub fn print_domain_step_intro() {
    println!(
        "\n{} {} {}",
        "Weaver Server Setup".bold().cyan(),
        "—".dark_grey(),
        "Host & Relay Deployment".white()
    );
    print_wrapped(
        "  ",
        "Configure your host to run a public Tunnel Weaver relay.",
    );
    println!();
    println!("{}", "Step 1: Two domains".bold().white());
    println!();
    print_wrapped(
        "  ",
        "You need two domains. If they are not set up yet, open the DNS provider for any \
         domain you own — you only go there once, to add the two records below.",
    );
    println!();
    print_labeled_wrapped(
        "  ",
        "Admin domain:",
        "the relay's own address; the admin console runs here.",
    );
    println!(
        "    e.g. for {} → {}",
        "bar.foo".cyan(),
        "admin.bar.foo".cyan()
    );
    println!();
    print_labeled_wrapped(
        "  ",
        "Tunnel domain:",
        "all future tunnels will be subdomains of this one, so pick a dedicated name.",
    );
    println!(
        "    e.g. for {} → {}",
        "bar.foo".cyan(),
        "tunnel.bar.foo".cyan()
    );
    println!();
    print_wrapped("  ", "So now, pick for your own domain:");
    let records = [
        ("admin.<your-domain>", "A/AAAA", "-> this VM's public IP(s)"),
        (
            "tunnel.<your-domain>",
            "NS",
            "-> admin.<your-domain> (yes, the NS points at the domain defined above)",
        ),
    ];
    let name_width = records.iter().map(|(n, _, _)| n.len()).max().unwrap_or(0);
    let kind_width = records.iter().map(|(_, k, _)| k.len()).max().unwrap_or(0);
    // Column where the `-> target` text begins; continuation lines hang there so
    // the two `name kind ->` columns stay aligned even when the NS parenthetical
    // wraps on a narrow terminal.
    let target_col = 4 + name_width + 2 + kind_width + 2;
    let width = terminal_width();
    for (name, kind, target) in records {
        let target_width = width.saturating_sub(target_col).max(1);
        for (index, line) in wrap_text(target, target_width).iter().enumerate() {
            if index == 0 {
                println!(
                    "    {}  {}  {}",
                    format!("{name:<name_width$}").cyan(),
                    format!("{kind:<kind_width$}").yellow(),
                    line.as_str().white()
                );
            } else {
                println!("{}{}", " ".repeat(target_col), line.as_str().white());
            }
        }
    }
    println!();
    print_wrapped(
        "  ",
        "Setup verifies these before changing anything on this host.",
    );
    println!();
}

/// Displays the structured plan and asks for user confirmation.
///
/// Returns `Ok(true)` to proceed and `Ok(false)` when the operator declines. A
/// cancelled or interrupted prompt (Ctrl-C / Ctrl-D / Esc) is surfaced as
/// [`std::io::ErrorKind::Interrupted`] rather than being folded into `false`, so
/// the caller can distinguish "answered no" from "asked to quit".
pub fn display_plan_and_confirm(
    config: &GatheredConfig,
    is_headless: bool,
) -> std::io::Result<bool> {
    println!("\n{}", "Weaver Server Setup Plan".bold().cyan());
    println!();

    println!("{}", "Domain & ACME".bold().white());
    println!(
        "  {:<18} {}",
        "Tunnel Domain:".dark_grey(),
        config.tunnel_domain.as_str().bold().green()
    );
    println!(
        "  {:<18} {}",
        "Admin Domain:".dark_grey(),
        config.admin_domain.as_str().bold().green()
    );
    println!(
        "  {:<18} {}",
        "Admin Email:".dark_grey(),
        config.admin_email.as_str().white()
    );
    println!(
        "  {:<18} {}",
        "Provider:".dark_grey(),
        config.acme_provider.as_str().yellow()
    );
    if let Some(dir) = &config.acme_directory {
        println!(
            "  {:<18} {}",
            "Directory:".dark_grey(),
            dir.as_str().dark_cyan()
        );
    }
    let eab_status = if config.acme_eab_kid.is_some() {
        "configured (registration included)".green()
    } else {
        "none".dark_grey()
    };
    println!("  {:<18} {}", "EAB Account:".dark_grey(), eab_status);
    println!();

    if let Some(email) = &config.email {
        println!("{}", "Email".bold().white());
        println!(
            "  {:<18} {}",
            "Provider:".dark_grey(),
            crate::email::providers::display_name(&email.provider)
        );
        let sender = match email.from_name.as_deref() {
            Some(name) if !name.is_empty() => format!("{name} <{}>", email.from),
            _ => email.from.clone(),
        };
        println!("  {:<18} {}", "Sender:".dark_grey(), sender);
        println!();
    }

    println!("{}", "Host & Services".bold().white());
    println!(
        "  {:<18} {}",
        "Binary Path:".dark_grey(),
        config.prefix.join("weaver-server").display()
    );
    println!(
        "  {:<18} {}",
        "Database:".dark_grey(),
        config.db_path.display()
    );
    println!(
        "  {:<18} {}:{}",
        "System User:".dark_grey(),
        config.user,
        config.user
    );
    println!("  {:<18} [::]:80, [::]:443", "Sockets:".dark_grey());
    println!(
        "  {:<18} weaver-server.socket, weaver-server.service",
        "Systemd Units:".dark_grey()
    );
    println!();

    if is_headless {
        return Ok(true);
    }

    // `Confirm` defaults to "no", so an accidental Enter declines rather than
    // installing.
    Confirm::new("Proceed with installation?")
        .with_default(false)
        .prompt()
        .map_err(inquire_err)
}

/// One selectable email provider for the interactive menu.
struct EmailProviderOption {
    id: &'static str,
    label: String,
}

impl fmt::Display for EmailProviderOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label)
    }
}

/// Assigns a gathered credential to its [`EmailConfig`] slot.
fn set_credential(cfg: &mut EmailConfig, field: CredentialField, value: String) {
    match field {
        CredentialField::ApiKey => cfg.api_key = Some(value),
        CredentialField::Secret => cfg.secret = Some(value),
        CredentialField::Username => cfg.username = Some(value),
        CredentialField::Region => cfg.region = Some(value),
        CredentialField::Domain => cfg.domain = Some(value),
        CredentialField::TemplateId => cfg.template_id = Some(value),
    }
}

/// Asks whether to enable email and, if so, gathers a complete [`EmailConfig`].
///
/// Ambient credentials offered by the environment win by default but the
/// operator may still type a value. The returned block is validated; the OTP
/// proof is performed by the caller after the plan is confirmed.
pub fn prompt_email_config() -> std::io::Result<Option<EmailConfig>> {
    let enable = Confirm::new("Enable email-based accounts?")
        .with_default(false)
        .prompt()
        .map_err(inquire_err)?;
    if !enable {
        return Ok(None);
    }

    // Offer only providers whose transport ships in this release; the full
    // catalog (including the fast-follow AWS/Azure rows) is `providers email`.
    let options: Vec<EmailProviderOption> = PROVIDERS
        .iter()
        .filter(|p| p.kind.is_transported())
        .map(|p| EmailProviderOption {
            id: p.id,
            label: format!("{} ({})", p.id, p.display),
        })
        .collect();
    let chosen = Select::new("Email provider", options)
        .with_starting_cursor(0)
        .prompt()
        .map_err(inquire_err)?;
    let info = crate::email::providers::find_provider(chosen.id).expect("catalog provider");
    println!("  {} {}", "•".blue(), info.guidance);

    let from = loop {
        let input = prompt_line("Verified sender address", None)?;
        if crate::email::is_valid_address(&input) {
            break input;
        }
        println!("{} Invalid email address.", "✗".red().bold());
    };
    let from_name = prompt_line("Sender display name (optional)", Some(""))?;
    let from_name = (!from_name.trim().is_empty()).then(|| from_name.trim().to_string());

    let mut cfg = EmailConfig {
        provider: info.id.to_string(),
        from,
        from_name,
        ..Default::default()
    };

    for field in info.credential_fields {
        // Prefer an ambient value when the conventional env var is present.
        if let Some(env) = field.env
            && let Ok(value) = std::env::var(env)
            && !value.trim().is_empty()
        {
            let use_ambient = Confirm::new(&format!("Use ambient {env} for the {}?", field.label))
                .with_default(true)
                .prompt()
                .map_err(inquire_err)?;
            if use_ambient {
                set_credential(&mut cfg, field.field, value.trim().to_string());
                continue;
            }
        }
        let value = read_masked_input(&format!("{} ({})", field.label, info.id))?;
        set_credential(&mut cfg, field.field, value.trim().to_string());
    }

    if info.needs_domain && cfg.domain.is_none() {
        loop {
            let input = prompt_line("Sending domain", None)?;
            if !input.trim().is_empty() {
                cfg.domain = Some(input.trim().to_string());
                break;
            }
        }
    }
    if info.template_only && cfg.template_id.is_none() {
        loop {
            let input = prompt_line("Transactional template id", None)?;
            if !input.trim().is_empty() {
                cfg.template_id = Some(input.trim().to_string());
                break;
            }
        }
    }
    if info.kind == crate::email::providers::ProviderKind::Smtp && cfg.endpoint.is_none() {
        loop {
            let input = prompt_line("SMTP endpoint (e.g. smtp://host:587)", None)?;
            if !input.trim().is_empty() {
                cfg.endpoint = Some(input.trim().to_string());
                break;
            }
        }
    }

    let issues = crate::email::providers::validate_email_config(&cfg);
    if !issues.is_empty() {
        return Err(std::io::Error::other(issues.join("; ")));
    }
    Ok(Some(cfg))
}

#[cfg(test)]
mod tests {
    use super::wrap_text;

    #[test]
    fn wrap_text_short_input_is_a_single_line() {
        assert_eq!(
            wrap_text("host and relay", 80),
            vec!["host and relay".to_string()]
        );
    }

    #[test]
    fn wrap_text_breaks_when_a_word_would_exceed_the_exact_width() {
        // "ab cd" is exactly five columns; "ef" must start a new line.
        assert_eq!(
            wrap_text("ab cd ef", 5),
            vec!["ab cd".to_string(), "ef".to_string()]
        );
    }

    #[test]
    fn wrap_text_keeps_a_long_word_on_its_own_line() {
        assert_eq!(
            wrap_text("supercalifragilistic", 4),
            vec!["supercalifragilistic".to_string()]
        );
    }

    #[test]
    fn wrap_text_empty_input_yields_no_lines() {
        assert!(wrap_text("", 80).is_empty());
        assert!(wrap_text("   ", 80).is_empty());
    }
}
