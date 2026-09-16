//! Uninstallation workflow for `weaver-server uninstall`.
//!
//! Handles:
//! - Stopping and disabling systemd service and socket units
//! - Removing systemd unit files and triggering `daemon-reload`
//! - Removing the installed `weaver-server` binary
//! - Preserving state data and user by default
//! - Optionally purging `/var/lib/weaver` and the `weaver` user when `--purge` is passed

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crossterm::style::Stylize;

use crate::setup::interactive::prompt_line;
use crate::setup::privilege::is_root;

/// Arguments configuring the uninstall command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallOptions {
    /// Installation prefix where binary is located.
    pub prefix: PathBuf,
    /// Path to SQLite database / state directory.
    pub db_path: PathBuf,
    /// System service username.
    pub user: String,
    /// Whether to purge database and system user.
    pub purge: bool,
    /// Whether running non-interactively.
    pub headless: bool,
}

/// Executes the uninstallation process.
pub fn execute_uninstall(opts: &UninstallOptions) -> Result<(), String> {
    // 1. Ensure root privileges
    if !is_root() {
        if opts.headless {
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
                "Weaver uninstall requires root privileges to manage systemd and system users. Elevating via sudo...".bold().yellow()
            );
        }

        let current_exe = std::env::current_exe()
            .map_err(|e| format!("cannot determine current executable path: {e}"))?;

        let mut cmd = Command::new("sudo");
        if opts.headless {
            cmd.arg("-n");
        }
        cmd.arg(current_exe);
        cmd.arg("uninstall");
        cmd.arg("--prefix").arg(&opts.prefix);
        cmd.arg("--db").arg(&opts.db_path);
        cmd.arg("--user").arg(&opts.user);
        if opts.purge {
            cmd.arg("--purge");
        }
        if opts.headless {
            cmd.arg("--headless");
        }

        let status = cmd
            .status()
            .map_err(|e| format!("failed to elevate via sudo: {e}"))?;

        std::process::exit(status.code().unwrap_or(1));
    }

    println!("\n{}", "Uninstalling Weaver Server...".bold().cyan());

    // 2. Stop and disable systemd units
    println!("  {} Stopping and disabling systemd units...", "•".blue());
    let _ = Command::new("systemctl")
        .args([
            "disable",
            "--now",
            "weaver-server.service",
            "weaver-server.socket",
        ])
        .status();

    // 3. Remove unit files
    let service_unit = Path::new("/etc/systemd/system/weaver-server.service");
    let socket_unit = Path::new("/etc/systemd/system/weaver-server.socket");

    if service_unit.exists() {
        let _ = fs::remove_file(service_unit);
    }
    if socket_unit.exists() {
        let _ = fs::remove_file(socket_unit);
    }

    let _ = Command::new("systemctl").arg("daemon-reload").status();
    println!("  {} Systemd units removed", "✓".green());

    // 4. Remove installed binary
    let binary_path = opts.prefix.join("weaver-server");
    if binary_path.exists() {
        if let Err(e) = fs::remove_file(&binary_path) {
            eprintln!(
                "  {} Failed to remove binary at {}: {e}",
                "✗".red(),
                binary_path.display()
            );
        } else {
            println!(
                "  {} Binary removed from {}",
                "✓".green(),
                binary_path.display()
            );
        }
    } else {
        println!(
            "  {} Binary not present at {}",
            "•".dim(),
            binary_path.display()
        );
    }

    // 5. Handle state directory and user purge
    let state_dir = opts
        .db_path
        .parent()
        .unwrap_or_else(|| Path::new("/var/lib/weaver"));

    if opts.purge {
        println!("\n{}", "Warning: --purge specified".bold().yellow());
        println!(
            "  This will permanently delete the state directory ({}) and delete user '{}'.",
            state_dir.display(),
            opts.user
        );
        println!("  Ensure any critical certificates or database backups are preserved.");

        let confirmed = if opts.headless {
            true
        } else {
            match prompt_line("Are you sure you want to purge all data? [y/N]", Some("n")) {
                Ok(ans) => {
                    let l = ans.to_ascii_lowercase();
                    l == "y" || l == "yes"
                }
                Err(_) => false,
            }
        };

        if confirmed {
            if state_dir.exists() {
                if let Err(e) = fs::remove_dir_all(state_dir) {
                    eprintln!(
                        "  {} Failed to remove state directory {}: {e}",
                        "✗".red(),
                        state_dir.display()
                    );
                } else {
                    println!(
                        "  {} State directory purged ({})",
                        "✓".green(),
                        state_dir.display()
                    );
                }
            }

            let status = Command::new("userdel").arg(&opts.user).status();
            match status {
                Ok(s) if s.success() => {
                    println!("  {} User '{}' removed", "✓".green(), opts.user);
                }
                _ => {
                    println!(
                        "  {} User '{}' was not removed or does not exist",
                        "•".dim(),
                        opts.user
                    );
                }
            }
            let _ = Command::new("groupdel")
                .arg(&opts.user)
                .stderr(std::process::Stdio::null())
                .status();
        } else {
            println!(
                "  {} Purge cancelled by user. Data preserved at {}",
                "•".blue(),
                state_dir.display()
            );
        }
    } else {
        println!(
            "  {} Data directory preserved at {}",
            "•".dim(),
            state_dir.display()
        );
        println!("  {} System user '{}' preserved", "•".dim(), opts.user);
    }

    println!(
        "\n{}",
        "Weaver Server uninstalled successfully.".bold().green()
    );
    Ok(())
}
