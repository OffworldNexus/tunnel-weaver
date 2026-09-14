use std::process::Command;

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
}

#[test]
fn test_weaver_server_db_flag_and_env_accepted() {
    let bin_path = env!("CARGO_BIN_EXE_weaver-server");

    // Test --db flag
    let output = Command::new(bin_path)
        .arg("--db")
        .arg("/tmp/test-cli.db")
        .output()
        .expect("failed to execute weaver-server with --db");
    assert!(output.status.success());

    // Test WEAVER_DB env
    let output = Command::new(bin_path)
        .env("WEAVER_DB", "/tmp/test-env.db")
        .output()
        .expect("failed to execute weaver-server with WEAVER_DB");
    assert!(output.status.success());
}
