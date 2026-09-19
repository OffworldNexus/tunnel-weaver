use std::process::Command;
use weave::connect::parse_server_address;

#[test]
fn test_weave_version_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_weave"))
        .arg("--version")
        .output()
        .expect("failed to execute binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("weave"));
    assert!(stdout.contains(&format!("protocol v{}", weaver_proto::PROTOCOL_VERSION)));
}

#[test]
fn test_weave_help_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_weave"))
        .arg("--help")
        .output()
        .expect("failed to execute binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Client for Tunnel Weaver"));
    assert!(stdout.contains("poc"));
}

#[test]
fn test_weave_poc_requires_server_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_weave"))
        .args(["poc", "web"])
        .output()
        .expect("failed to execute binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--server"));
}

#[test]
fn test_parse_server_address_variations() {
    assert_eq!(
        parse_server_address("example.com").unwrap(),
        ("example.com".to_string(), 443)
    );
    assert_eq!(
        parse_server_address("example.com:8443").unwrap(),
        ("example.com".to_string(), 8443)
    );
    assert_eq!(
        parse_server_address("127.0.0.1:38223").unwrap(),
        ("127.0.0.1".to_string(), 38223)
    );
    assert_eq!(
        parse_server_address("[::1]:4433").unwrap(),
        ("::1".to_string(), 4433)
    );
    assert_eq!(
        parse_server_address("[::1]").unwrap(),
        ("::1".to_string(), 443)
    );
    assert!(parse_server_address("").is_err());
    assert!(parse_server_address("example.com:invalid").is_err());
}
