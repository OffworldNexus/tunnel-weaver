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
}
