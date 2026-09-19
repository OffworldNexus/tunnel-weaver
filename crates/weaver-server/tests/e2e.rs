use std::process::Command;

#[test]
#[ignore = "e2e"]
fn test_weaver_server_e2e_version_smoke() {
    let bin_path = env!("CARGO_BIN_EXE_weaver-server");
    let output = Command::new(bin_path)
        .arg("--version")
        .output()
        .expect("failed to spawn weaver-server --version in e2e test");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("weaver-server"));
    assert!(stdout.contains(&format!("protocol v{}", weaver_proto::PROTOCOL_VERSION)));
}
