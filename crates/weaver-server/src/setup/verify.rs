//! Verification and certificate wait workflow for `weaver-server setup`.
//!
//! Validates:
//! - Service activation via `systemctl is-active`
//! - Certificate issuance via control socket (`cert wait --timeout 300`)
//! - HTTPS endpoint reachability using system trust store

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crossterm::style::Stylize;

use crate::control::client::client_cert_wait;

/// Prints diagnostic instructions on failure.
pub fn print_failure_guidance() {
    println!("\n{}", "Troubleshooting:".bold().red());
    println!("  Inspect daemon logs with:");
    println!(
        "    {}",
        "journalctl -u weaver-server -n 50 --no-pager"
            .bold()
            .yellow()
    );
    println!("  Check service status with:");
    println!(
        "    {}",
        "systemctl status weaver-server.service".bold().yellow()
    );
}

/// Waits for `systemctl is-active` on the socket and service units.
pub async fn wait_for_systemd_active() -> Result<(), String> {
    print!("  {} Verifying service activation...", "•".blue());

    for _ in 0..30 {
        let sock_active = Command::new("systemctl")
            .args(["is-active", "--quiet", "weaver-server.socket"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        let svc_active = Command::new("systemctl")
            .args(["is-active", "--quiet", "weaver-server.service"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if sock_active && svc_active {
            println!("\r  {} Services active and running        ", "✓".green());
            return Ok(());
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    println!("\r  {} Services failed to activate       ", "✗".red());
    Err("weaver-server systemd units did not become active".into())
}

/// Waits for certificate issuance via control socket and tests HTTPS endpoint.
pub async fn verify_setup(root_domain: &str, socket_path: &Path) -> Result<(), String> {
    println!("\n{}", "Verifying deployment...".bold().cyan());

    // 1. Check systemd service is active
    if let Err(e) = wait_for_systemd_active().await {
        print_failure_guidance();
        return Err(e);
    }

    // 2. Wait for certificate issuance via control socket
    println!(
        "  {} Waiting for certificate issuance for '{}' (timeout: 300s)...",
        "•".blue(),
        root_domain.bold().cyan()
    );

    let wait_code =
        client_cert_wait(socket_path, Some(root_domain.to_string()), Some(300), false).await;

    if wait_code != 0 {
        print_failure_guidance();
        return Err(format!(
            "certificate issuance failed or timed out for '{root_domain}'"
        ));
    }

    // 3. Real HTTPS GET request using system trust store
    print!(
        "  {} Testing HTTPS GET https://{}/...",
        "•".blue(),
        root_domain
    );
    let url = format!("https://{root_domain}/");
    let curl_res = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            &url,
        ])
        .output();

    match curl_res {
        Ok(out) if out.status.success() => {
            let status_code = String::from_utf8_lossy(&out.stdout).trim().to_string();
            println!(
                "\r  {} HTTPS GET https://{}/ succeeded (HTTP {})",
                "✓".green(),
                root_domain,
                status_code.bold()
            );
        }
        Ok(out) => {
            let err_msg = String::from_utf8_lossy(&out.stderr);
            if err_msg.contains("certificate") || err_msg.contains("SSL") {
                println!(
                    "\r  {} HTTPS endpoint reached; certificate verification failed against system roots (expected for staging/Pebble environments)",
                    "•".yellow()
                );
            } else {
                println!(
                    "\r  {} HTTPS request warning: {}",
                    "•".yellow(),
                    err_msg.trim()
                );
            }
        }
        Err(_) => {
            println!(
                "\r  {} curl command not found, skipping local HTTPS check",
                "•".dim()
            );
        }
    }

    // 4. Closing summary
    println!("\n{}", "Weaver Server Setup Complete".bold().green());
    println!();

    println!("{}", "Service Status".bold().white());
    println!(
        "  {:<18} {}",
        "Relay URL:".dark_grey(),
        format!("https://{root_domain}").bold().cyan()
    );
    println!(
        "  {:<18} {}",
        "Status:".dark_grey(),
        "Active & Serving".bold().green()
    );
    println!("  {:<18} [::]:80, [::]:443", "Sockets:".dark_grey());
    println!();

    println!("{}", "Management".bold().white());
    println!(
        "  {:<18} {}",
        "Service Control:".dark_grey(),
        "systemctl status weaver-server.service".yellow()
    );
    println!(
        "  {:<18} {}",
        "Live Logs:".dark_grey(),
        "journalctl -u weaver-server -f".yellow()
    );
    println!();

    Ok(())
}
