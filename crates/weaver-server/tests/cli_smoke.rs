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
    assert_eq!(config.acme_provider, "letsencrypt-staging");
    assert_eq!(
        config.listen_http,
        "[::]:8080".parse::<std::net::SocketAddr>().unwrap()
    );
    assert_eq!(
        config.listen_https,
        "[::]:8443".parse::<std::net::SocketAddr>().unwrap()
    );
}
