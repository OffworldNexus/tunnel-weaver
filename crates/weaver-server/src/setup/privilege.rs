//! Privilege verification and `sudo` re-execution helpers.
//!
//! Checks for root EUID and transparently re-executes the binary via `sudo`
//! when running unprivileged, forwarding gathered answers through CLI arguments
//! alongside `--no-prompt-values` to prevent duplicate interactive prompts.

use crossterm::style::Stylize;
use std::process::Command;

use super::interactive::GatheredConfig;

/// Returns whether the current process is running with root privileges (EUID 0).
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Ensures the process has root privileges, elevating via `sudo` if necessary.
///
/// In headless mode, verifies that `sudo -n` succeeds without prompting for a password;
/// if password authentication is required, exits immediately with code 2.
pub fn ensure_root_or_elevate(config: &GatheredConfig, is_headless: bool) {
    if is_root() {
        return;
    }

    if is_headless {
        let status = Command::new("sudo").arg("-n").arg("true").status();

        match status {
            Ok(s) if s.success() => {}
            _ => {
                eprintln!(
                    "{} Root privileges required: passwordless sudo (-n) is not permitted for the current user.",
                    "Error:".red().bold()
                );
                std::process::exit(2);
            }
        }
    } else {
        println!(
            "\n{}",
            "Weaver setup requires root privileges to install systemd services and manage the system user. Elevating via sudo...".bold().yellow()
        );
    }

    let current_exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("Failed to determine current executable path: {err}");
            std::process::exit(1);
        }
    };

    let mut cmd = Command::new("sudo");
    if is_headless {
        cmd.arg("-n");
    }
    cmd.arg(current_exe);
    cmd.arg("setup");

    cmd.arg("--root-domain").arg(&config.root_domain);
    cmd.arg("--email").arg(&config.admin_email);
    cmd.arg("--acme-provider").arg(&config.acme_provider);
    cmd.arg("--db").arg(&config.db_path);
    cmd.arg("--user").arg(&config.user);
    cmd.arg("--prefix").arg(&config.prefix);

    if let Some(dir) = &config.acme_directory {
        cmd.arg("--acme-directory").arg(dir);
    }
    if let Some(kid) = &config.acme_eab_kid {
        cmd.arg("--acme-eab-kid").arg(kid);
    }
    if let Some(hmac) = &config.acme_eab_hmac {
        cmd.arg("--acme-eab-hmac").arg(hmac);
    }
    if let Some(ca) = &config.acme_root_ca_path {
        cmd.arg("--acme-root-ca").arg(ca);
    }
    if config.skip_reachability_check {
        cmd.arg("--skip-reachability-check");
    }
    if is_headless {
        cmd.arg("--headless");
    }
    cmd.arg("--no-prompt-values");

    let status = match cmd.status() {
        Ok(s) => s,
        Err(err) => {
            eprintln!("Failed to execute sudo: {err}");
            std::process::exit(1);
        }
    };

    std::process::exit(status.code().unwrap_or(1));
}
