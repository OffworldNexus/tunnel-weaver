//! Interactive prompting and validation for the `weaver-server setup` command.
//!
//! Collects and validates domain names, admin email, ACME provider configuration,
//! and displays a structured plan before executing installation.

use std::io::{IsTerminal, Write, stdin, stdout};
use std::path::PathBuf;

use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};
use crossterm::style::Stylize;

/// Configuration values gathered interactively or via CLI arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatheredConfig {
    pub root_domain: String,
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

/// Prompts the user on stdout and reads a line from stdin.
pub fn prompt_line(prompt: &str, default: Option<&str>) -> std::io::Result<String> {
    if let Some(def) = default {
        print!(
            "  {} {prompt} [{}]: ",
            "❯".bold().cyan(),
            def.bold().white()
        );
    } else {
        print!("  {} {prompt}: ", "❯".bold().cyan());
    }
    stdout().flush()?;

    let mut line = String::new();
    stdin().read_line(&mut line)?;
    let trimmed = line.trim();
    if trimmed.is_empty()
        && let Some(def) = default
    {
        return Ok(def.to_string());
    }
    Ok(trimmed.to_string())
}

/// Reads masked input for sensitive values (such as EAB HMAC keys).
pub fn read_masked_input(prompt: &str) -> std::io::Result<String> {
    print!("  {} {prompt}: ", "❯".bold().cyan());
    stdout().flush()?;

    if !stdin().is_terminal() {
        let mut line = String::new();
        stdin().read_line(&mut line)?;
        return Ok(line.trim_end_matches(['\r', '\n']).to_string());
    }

    use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers, read};

    crossterm::terminal::enable_raw_mode()?;
    let mut input = String::new();
    loop {
        if let Ok(Event::Key(KeyEvent {
            code, modifiers, ..
        })) = read()
        {
            match code {
                KeyCode::Enter => break,
                KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                    let _ = crossterm::terminal::disable_raw_mode();
                    println!();
                    std::process::exit(130);
                }
                KeyCode::Char(c) => {
                    input.push(c);
                    print!("*");
                    stdout().flush()?;
                }
                KeyCode::Backspace if !input.is_empty() => {
                    input.pop();
                    print!("\x08 \x08");
                    stdout().flush()?;
                }
                _ => {}
            }
        }
    }
    crossterm::terminal::disable_raw_mode()?;
    println!();
    Ok(input)
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

    loop {
        let choice = prompt_line("Select provider", Some("1"))?;
        match choice.trim() {
            "1" | "letsencrypt" => return Ok(("letsencrypt".into(), None)),
            "2" | "google" => return Ok(("google".into(), None)),
            "3" | "zerossl" => return Ok(("zerossl".into(), None)),
            "4" | "buypass" => return Ok(("buypass".into(), None)),
            "5" | "custom" => {
                let url = prompt_line("ACME directory URL", None)?;
                return Ok(("custom".into(), Some(url)));
            }
            _ => {
                println!(
                    "  {} Invalid selection. Please enter 1, 2, 3, 4, or 5.",
                    "✗".red().bold()
                );
            }
        }
    }
}

/// Displays the structured plan and asks for user confirmation.
pub fn display_plan_and_confirm(config: &GatheredConfig, is_headless: bool) -> bool {
    println!("\n{}", "Weaver Server Setup Plan".bold().cyan());
    println!();

    println!("{}", "Domain & ACME".bold().white());
    println!(
        "  {:<18} {}",
        "Root Domain:".dark_grey(),
        config.root_domain.as_str().bold().green()
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
        return true;
    }

    match prompt_line("Proceed with installation? [y/N]", Some("n")) {
        Ok(ans) => {
            let lower = ans.to_ascii_lowercase();
            lower == "y" || lower == "yes"
        }
        Err(_) => false,
    }
}
