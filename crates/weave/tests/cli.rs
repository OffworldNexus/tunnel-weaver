use std::process::Command;

use weave::connect::parse_server_address;
use weave::parse_specs;

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
    assert!(stdout.contains("start"));
    // The old PoC verb is gone.
    assert!(!stdout.contains("poc"));
}

#[test]
fn test_weave_start_requires_server_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_weave"))
        .args(["start", "web=8080"])
        .output()
        .expect("failed to execute binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--server"));
}

#[test]
fn test_weave_start_help_documents_both_insecure_flags() {
    let output = Command::new(env!("CARGO_BIN_EXE_weave"))
        .args(["start", "--help"])
        .output()
        .expect("failed to execute binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--insecure-root-ca"));
    assert!(stdout.contains("--insecure-target"));
    assert!(stdout.contains("SERVICE=TARGET"));
}

#[test]
fn test_weave_start_rejects_unknown_service_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_weave"))
        .args([
            "start",
            "web=8080",
            "--server",
            "localhost:443",
            "--no-rewrite",
            "api",
        ])
        .output()
        .expect("failed to execute binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown service 'api'"), "stderr: {stderr}");
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

#[test]
fn test_parse_specs_from_cli_shape() {
    let specs = parse_specs(&["web=8080".into(), "api=https://localhost:9000".into()]).unwrap();
    assert_eq!(specs.len(), 2);
    assert_eq!(specs[0].service, "web");
    assert_eq!(specs[0].target.port, 8080);
    assert_eq!(specs[1].service, "api");
    assert_eq!(specs[1].target.port, 9000);
}
