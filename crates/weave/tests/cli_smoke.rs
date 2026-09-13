use std::process::Command;

#[test]
fn test_weave_version_exits_zero() {
    let bin_path = env!("CARGO_BIN_EXE_weave");
    let output = Command::new(bin_path)
        .arg("--version")
        .output()
        .expect("failed to execute weave --version");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("weave"));
}

#[test]
fn test_weave_help_exits_zero() {
    let bin_path = env!("CARGO_BIN_EXE_weave");
    let output = Command::new(bin_path)
        .arg("--help")
        .output()
        .expect("failed to execute weave --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"));
}
