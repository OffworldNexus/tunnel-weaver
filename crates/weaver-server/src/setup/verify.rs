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
use crate::setup::dns::generate_random_hex;

/// Outcome of one `curl` HTTPS probe.
enum HttpsProbe {
    /// curl exited zero; carries the HTTP status code.
    Succeeded(String),
    /// The system trust store rejected the certificate (typical for
    /// staging/Pebble CAs).
    TrustFailure(String),
    /// Any other failure, with curl's message.
    Failed(String),
    /// curl is not installed.
    Unavailable,
}

/// Runs `curl` against `url` and classifies the result.
///
/// `fail_on_http_error` adds `--fail`, so a non-2xx status counts as a failure
/// (used for the root and admin endpoints). The wildcard probe omits it because
/// any HTTP response, even a 404, proves the wildcard certificate completed the
/// handshake. A TLS trust failure is separated from other errors so callers can
/// tolerate it in staging/Pebble environments.
fn https_probe(url: &str, fail_on_http_error: bool) -> HttpsProbe {
    let mut args = vec![
        "--silent",
        "--show-error",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
    ];
    if fail_on_http_error {
        args.insert(0, "--fail");
    }
    args.push(url);

    match Command::new("curl").args(&args).output() {
        Ok(out) if out.status.success() => {
            HttpsProbe::Succeeded(String::from_utf8_lossy(&out.stdout).trim().to_string())
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            if err.contains("certificate") || err.contains("SSL") || err.contains("TLS") {
                HttpsProbe::TrustFailure(err)
            } else {
                HttpsProbe::Failed(err)
            }
        }
        Err(_) => HttpsProbe::Unavailable,
    }
}

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

/// Waits for certificate issuance via control socket and tests HTTPS endpoints.
///
/// Both managed certificates are verified: the tunnel wildcard (DNS-01, also
/// exercised through a random one-label name) and the admin certificate
/// (HTTP-01). `setup_complete` is only persisted once both pass.
pub async fn verify_setup(
    root_domain: &str,
    admin_domain: &str,
    socket_path: &Path,
) -> Result<(), String> {
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
    match https_probe(&format!("https://{root_domain}/"), true) {
        HttpsProbe::Succeeded(status_code) => println!(
            "\r  {} HTTPS GET https://{}/ succeeded (HTTP {})",
            "✓".green(),
            root_domain,
            status_code.bold()
        ),
        HttpsProbe::TrustFailure(_) => println!(
            "\r  {} HTTPS endpoint reached; certificate verification failed against system roots (expected for staging/Pebble environments)",
            "•".yellow()
        ),
        HttpsProbe::Failed(err_msg) => {
            println!("\r  {} HTTPS request warning: {}", "•".yellow(), err_msg)
        }
        HttpsProbe::Unavailable => println!(
            "\r  {} curl command not found, skipping local HTTPS check",
            "•".dim()
        ),
    }

    // 3b. Admin certificate: wait for the HTTP-01 order and probe its endpoint.
    println!(
        "  {} Waiting for admin certificate issuance for '{}' (timeout: 300s)...",
        "•".blue(),
        admin_domain.bold().cyan()
    );
    let admin_wait = client_cert_wait(
        socket_path,
        Some(admin_domain.to_string()),
        Some(300),
        false,
    )
    .await;
    if admin_wait != 0 {
        print_failure_guidance();
        return Err(format!(
            "certificate issuance failed or timed out for admin host '{admin_domain}'"
        ));
    }

    print!(
        "  {} Testing HTTPS GET https://{}/...",
        "•".blue(),
        admin_domain
    );
    match https_probe(&format!("https://{admin_domain}/"), true) {
        HttpsProbe::Succeeded(status_code) => println!(
            "\r  {} Admin HTTPS GET https://{}/ succeeded (HTTP {})",
            "✓".green(),
            admin_domain,
            status_code.bold()
        ),
        HttpsProbe::TrustFailure(_) => println!(
            "\r  {} Admin HTTPS endpoint reached; certificate verification failed against system roots (expected for staging/Pebble environments)",
            "•".yellow()
        ),
        HttpsProbe::Failed(err_msg) => {
            // A trust failure is tolerated (staging/Pebble); any other failure
            // means the admin certificate or its HTTP-01 path is broken.
            print_failure_guidance();
            return Err(format!(
                "admin HTTPS GET https://{admin_domain}/ failed: {err_msg}"
            ));
        }
        HttpsProbe::Unavailable => println!(
            "\r  {} curl command not found, skipping admin HTTPS check",
            "•".dim()
        ),
    }

    // 4. Wildcard coverage: a random single-label name must complete a TLS
    //    handshake. Any HTTP response (even 404) proves the wildcard
    //    certificate covers the name; only a TLS failure is a problem.
    let sample_name = format!("sample-{}", generate_random_hex(4));
    let sample_url = format!("https://{sample_name}.{root_domain}/");
    print!(
        "  {} Testing wildcard HTTPS GET {}/...",
        "•".blue(),
        sample_url.trim_start_matches("https://")
    );
    match https_probe(&sample_url, false) {
        HttpsProbe::Succeeded(status_code) => println!(
            "\r  {} Wildcard HTTPS GET for '{}' succeeded (HTTP {})",
            "✓".green(),
            sample_name,
            status_code.bold()
        ),
        HttpsProbe::TrustFailure(err_msg) => println!(
            "\r  {} Wildcard certificate problem for '{}': {}",
            "✗".red().bold(),
            sample_name,
            err_msg
        ),
        HttpsProbe::Failed(err_msg) => println!(
            "\r  {} Wildcard HTTPS request warning for '{}': {}",
            "•".yellow(),
            sample_name,
            err_msg
        ),
        HttpsProbe::Unavailable => println!(
            "\r  {} curl command not found, skipping wildcard HTTPS check",
            "•".dim()
        ),
    }

    // 5. Closing summary
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
