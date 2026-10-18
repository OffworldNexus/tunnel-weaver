//! The test-only development-key path (`dev-signer` builds).
#![cfg(feature = "dev-signer")]

use std::path::Path;
use std::process::{Command, Output};

fn weave(data_dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_weave"))
        .args(args)
        .env("WEAVE_DATA_DIR", data_dir)
        .env_remove("CLICOLOR_FORCE")
        .env_remove("FORCE_HYPERLINK")
        .output()
        .expect("failed to execute binary")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn rows(data_dir: &Path) -> Vec<weave::store::Relay> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        weave::store::Store::open(data_dir.join("weave.db"))
            .await
            .unwrap()
            .relays()
            .await
            .unwrap()
    })
}

#[test]
fn dev_enrol_records_the_dev_key_normalised_default_first_and_idempotently() {
    let dir = tempfile::tempdir().unwrap();

    let out = weave(dir.path(), &["dev-enrol", "A1.Relay.Example.", "7"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("a1.relay.example as machine 7 (default relay)"),
        "{stdout}"
    );

    let first = rows(dir.path());
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].admin_host, "a1.relay.example");
    assert_eq!(first[0].machine_id, 7);
    assert_eq!(first[0].key_id, weave::identity::dev_key_id());
    assert!(first[0].is_default);

    // Idempotent.
    assert!(
        weave(dir.path(), &["dev-enrol", "a1.relay.example", "7"])
            .status
            .success()
    );
    assert_eq!(rows(dir.path()), first);

    // A second relay does not take the default.
    assert!(
        weave(dir.path(), &["dev-enrol", "b.relay.example:8443", "3"])
            .status
            .success()
    );
    let both = rows(dir.path());
    assert_eq!(both.len(), 2);
    assert!(both[0].is_default && both[0].admin_host == "a1.relay.example");
    assert!(!both[1].is_default && both[1].admin_host == "b.relay.example:8443");

    let out = weave(dir.path(), &["dev-enrol", "http://bad", "1"]);
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("not a relay address"));
}

#[test]
fn start_with_dev_signer_skips_the_key_agent() {
    let dir = tempfile::tempdir().unwrap();
    // Port 1 on loopback: nothing listens, so the dial fails fast and no real
    // relay is ever contacted.
    assert!(
        weave(dir.path(), &["dev-enrol", "127.0.0.1:1", "7"])
            .status
            .success()
    );

    let out = weave(
        dir.path(),
        &[
            "start",
            "web=8080",
            "--dev-signer",
            "--server",
            "127.0.0.1:1",
        ],
    );
    assert!(!out.status.success());
    let stderr = text(&out.stderr);
    // With the dev key the key agent is never asked: the first failure is the
    // dial itself.
    assert!(stderr.contains("could not reach 127.0.0.1:1"), "{stderr}");
    assert!(!stderr.contains("tpmd"), "{stderr}");
}

#[test]
fn dev_affordances_stay_out_of_help() {
    let dir = tempfile::tempdir().unwrap();
    assert!(!text(&weave(dir.path(), &["--help"]).stdout).contains("dev-enrol"));
    assert!(!text(&weave(dir.path(), &["start", "--help"]).stdout).contains("--dev-signer"));
}
