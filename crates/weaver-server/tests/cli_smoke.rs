use std::process::Command;

use tempfile::tempdir;
use weaver_server::Store;

#[test]
fn test_weaver_server_version_exits_zero() {
    let bin_path = env!("CARGO_BIN_EXE_weaver-server");
    let output = Command::new(bin_path)
        .arg("--version")
        .output()
        .expect("failed to execute weaver-server --version");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("weaver-server"));
    assert!(stdout.contains("protocol v1"));
}

#[test]
fn test_weaver_server_help_exits_zero() {
    let bin_path = env!("CARGO_BIN_EXE_weaver-server");
    let output = Command::new(bin_path)
        .arg("--help")
        .output()
        .expect("failed to execute weaver-server --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("--db"));
    assert!(stdout.contains("WEAVER_DB"));
    assert!(stdout.contains("--log-level"));
    assert!(stdout.contains("WEAVER_LOG_LEVEL"));
    assert!(stdout.contains("run"));
    assert!(stdout.contains("configure"));
}

#[test]
fn test_weaver_server_requires_subcommand() {
    let bin_path = env!("CARGO_BIN_EXE_weaver-server");

    // Invoking without subcommand fails with exit status 2
    let output = Command::new(bin_path)
        .arg("--db")
        .arg("/tmp/test-cli.db")
        .output()
        .expect("failed to execute weaver-server without subcommand");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires a subcommand") || stderr.contains("Usage:"));
}

#[test]
fn test_weaver_server_db_flag_and_env_accepted() {
    let bin_path = env!("CARGO_BIN_EXE_weaver-server");

    // Test --db flag with run --help
    let output = Command::new(bin_path)
        .arg("--db")
        .arg("/tmp/test-cli.db")
        .arg("run")
        .arg("--help")
        .output()
        .expect("failed to execute weaver-server run --help with --db");
    assert!(output.status.success());

    // Test WEAVER_DB env with run --help
    let output = Command::new(bin_path)
        .env("WEAVER_DB", "/tmp/test-env.db")
        .arg("run")
        .arg("--help")
        .output()
        .expect("failed to execute weaver-server run --help with WEAVER_DB");
    assert!(output.status.success());

    // Test --log-level flag with run --help
    let output = Command::new(bin_path)
        .arg("--log-level")
        .arg("debug")
        .arg("run")
        .arg("--help")
        .output()
        .expect("failed to execute weaver-server run --help with --log-level");
    assert!(output.status.success());

    // Test WEAVER_LOG_LEVEL env with run --help
    let output = Command::new(bin_path)
        .env("WEAVER_LOG_LEVEL", "debug")
        .arg("run")
        .arg("--help")
        .output()
        .expect("failed to execute weaver-server run --help with WEAVER_LOG_LEVEL");
    assert!(output.status.success());
}

#[test]
fn test_weaver_server_configure_command() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("configured.db");
    let bin_path = env!("CARGO_BIN_EXE_weaver-server");

    let output = Command::new(bin_path)
        .arg("--db")
        .arg(&db_path)
        .arg("configure")
        .arg("--root-domain")
        .arg("test.example.com")
        .arg("--admin-email")
        .arg("admin@example.com")
        .arg("--listen-http")
        .arg("8080")
        .arg("--listen-https")
        .arg("8443")
        .output()
        .expect("failed to execute weaver-server configure");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Configuration saved"));

    // Verify store loads valid config with dual-stack bare ports parsed
    let store = Store::open(&db_path).unwrap();
    let config = store.load_config().unwrap();
    assert_eq!(config.root_domain, "test.example.com");
    assert_eq!(config.admin_email, "admin@example.com");
    assert_eq!(config.acme_provider, "letsencrypt");
    assert_eq!(
        config.listen_http,
        "[::]:8080".parse::<std::net::SocketAddr>().unwrap()
    );
    assert_eq!(
        config.listen_https,
        "[::]:8443".parse::<std::net::SocketAddr>().unwrap()
    );

    // OFF-73: Non-root headless configure — verify headless flag writes config to SQLite database
    // without requiring root privileges or systemd, persisting domain, email, and default provider.
    let headless_output = Command::new(bin_path)
        .arg("--db")
        .arg(&db_path)
        .arg("configure")
        .arg("--headless")
        .arg("--root-domain")
        .arg("headless.example.com")
        .arg("--email")
        .arg("headless@example.com")
        .output()
        .expect("failed to execute weaver-server configure --headless");

    assert!(headless_output.status.success());
    let config2 = store.load_config().unwrap();
    assert_eq!(config2.root_domain, "headless.example.com");
    assert_eq!(config2.admin_email, "headless@example.com");
    assert_eq!(config2.acme_provider, "letsencrypt");
}

// OFF-73: Missing required options in headless mode — invoking setup --headless or
// configure --headless without --root-domain or --email terminates immediately with exit code 2 naming the missing option.
#[test]
fn test_setup_headless_missing_root_domain_exits_2() {
    let bin_path = env!("CARGO_BIN_EXE_weaver-server");

    let output = Command::new(bin_path)
        .arg("setup")
        .arg("--headless")
        .arg("--email")
        .arg("admin@example.com")
        .output()
        .expect("failed to execute setup");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--root-domain"),
        "Expected error message naming --root-domain, got: {stderr}"
    );
}

#[test]
fn test_setup_headless_missing_email_exits_2() {
    let bin_path = env!("CARGO_BIN_EXE_weaver-server");

    let output = Command::new(bin_path)
        .arg("setup")
        .arg("--headless")
        .arg("--root-domain")
        .arg("example.com")
        .output()
        .expect("failed to execute setup");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--email"),
        "Expected error message naming --email, got: {stderr}"
    );
}

#[test]
fn test_configure_headless_missing_root_domain_exits_2() {
    let bin_path = env!("CARGO_BIN_EXE_weaver-server");

    let output = Command::new(bin_path)
        .arg("configure")
        .arg("--headless")
        .arg("--email")
        .arg("admin@example.com")
        .output()
        .expect("failed to execute configure");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--root-domain"),
        "Expected error message naming --root-domain, got: {stderr}"
    );
}

#[test]
fn test_configure_headless_missing_email_exits_2() {
    let bin_path = env!("CARGO_BIN_EXE_weaver-server");

    let output = Command::new(bin_path)
        .arg("configure")
        .arg("--headless")
        .arg("--root-domain")
        .arg("example.com")
        .output()
        .expect("failed to execute configure");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--email"),
        "Expected error message naming --email, got: {stderr}"
    );
}

#[test]
fn test_setup_headless_sudo_password_required_exits_2_no_hang() {
    use std::os::unix::fs::PermissionsExt;

    // Create a fake sudo that always fails with exit 1 (simulating password requirement / failure)
    let fake_bin_dir = tempdir().unwrap();
    let fake_sudo = fake_bin_dir.path().join("sudo");
    std::fs::write(&fake_sudo, b"#!/bin/sh\nexit 1\n").unwrap();
    let mut perms = std::fs::metadata(&fake_sudo).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&fake_sudo, perms).unwrap();

    let current_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{}", fake_bin_dir.path().display(), current_path);

    let bin_path = env!("CARGO_BIN_EXE_weaver-server");

    let output = Command::new(bin_path)
        .env("PATH", &new_path)
        .env("SUDO_ASKPASS", "/bin/false")
        .arg("setup")
        .arg("--headless")
        .arg("--root-domain")
        .arg("example.com")
        .arg("--email")
        .arg("admin@example.com")
        .output()
        .expect("failed to execute setup");

    assert_eq!(
        output.status.code(),
        Some(2),
        "Expected exit code 2 when non-interactive sudo fails"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("sudo") || stderr.contains("Root privileges"),
        "Expected error message mentioning sudo or root privileges, got: {stderr}"
    );

    // OFF-73: Privilege escalation boundary in headless mode — uninstall --headless also terminates
    // immediately with exit code 2 when passwordless sudo fails, avoiding hangs in automated runs.
    let uninstall_output = Command::new(bin_path)
        .env("PATH", &new_path)
        .env("SUDO_ASKPASS", "/bin/false")
        .arg("uninstall")
        .arg("--headless")
        .output()
        .expect("failed to execute uninstall");

    assert_eq!(
        uninstall_output.status.code(),
        Some(2),
        "Expected exit code 2 when non-interactive sudo fails for uninstall"
    );
    let uninstall_stderr = String::from_utf8_lossy(&uninstall_output.stderr);
    assert!(
        uninstall_stderr.contains("sudo") || uninstall_stderr.contains("Root privileges"),
        "Expected error message mentioning sudo or root privileges, got: {uninstall_stderr}"
    );
}

// OFF-73: EAB credential enforcement in headless mode — selecting an ACME provider requiring
// External Account Binding (e.g. Google Trust Services or ZeroSSL) without providing both
// KID and HMAC terminates immediately with exit code 2.
#[test]
fn test_headless_eab_provider_without_credentials_exits_2() {
    let bin_path = env!("CARGO_BIN_EXE_weaver-server");

    // Test configure --headless with google provider but missing EAB credentials
    let output = Command::new(bin_path)
        .arg("configure")
        .arg("--headless")
        .arg("--root-domain")
        .arg("example.com")
        .arg("--email")
        .arg("admin@example.com")
        .arg("--acme-provider")
        .arg("google")
        .output()
        .expect("failed to execute configure");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("EAB KID") && stderr.contains("EAB HMAC"),
        "Expected error message mentioning EAB KID and EAB HMAC, got: {stderr}"
    );

    // Test setup --headless with zerossl provider but missing EAB credentials
    let output = Command::new(bin_path)
        .arg("setup")
        .arg("--headless")
        .arg("--root-domain")
        .arg("example.com")
        .arg("--email")
        .arg("admin@example.com")
        .arg("--acme-provider")
        .arg("zerossl")
        .output()
        .expect("failed to execute setup");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("acme-eab-kid") || stderr.contains("EAB"),
        "Expected error message mentioning EAB credentials, got: {stderr}"
    );
}
