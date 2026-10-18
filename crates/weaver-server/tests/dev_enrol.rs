//! `weaver-server dev-enrol`: the development key it enrols is the one `weave`
//! signs with, and the command does what the nightly workflow relies on.

use std::process::Command;

use tempfile::TempDir;
use weaver_mux::auth::Signer as _;
use weaver_server::Store;
use weaver_server::dev_enrol::{DEV_KEY_SEED, dev_key_id};

#[test]
fn the_development_key_is_the_one_weave_signs_with() {
    assert_eq!(DEV_KEY_SEED, weave::identity::DEV_SECRET_KEY);
    assert_eq!(dev_key_id(), weave::Ed25519Signer::dev().key_id());
}

fn dev_enrol(db: &std::path::Path, extra: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_weaver-server"))
        .arg("dev-enrol")
        .arg("--db")
        .arg(db)
        .args(extra)
        .output()
        .expect("run weaver-server")
}

#[tokio::test]
async fn the_command_enrols_the_key_once_and_prints_json() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("weaver.db");

    let first = dev_enrol(&db, &[]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let printed: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(printed["person"], "poc");
    assert_eq!(printed["machine"], "laptop");
    let machine_id = printed["machine_id"].as_i64().unwrap();
    assert_eq!(printed.as_object().unwrap().len(), 3);

    // Running it again changes nothing and says the same thing.
    let again = dev_enrol(&db, &[]);
    assert!(again.status.success());
    assert_eq!(again.stdout, first.stdout);

    // Another machine for the same key is refused, with nothing on stdout.
    let refused = dev_enrol(&db, &["--machine", "desktop"]);
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());

    let store = Store::open(&db).await.unwrap();
    let (person, machine) = store.machine_by_key(&dev_key_id()).await.unwrap().unwrap();
    assert_eq!(
        (
            person.name.as_str(),
            machine.name.as_str(),
            machine.id as i64
        ),
        ("poc", "laptop", machine_id)
    );
}

#[test]
fn names_can_be_chosen() {
    let dir = TempDir::new().unwrap();
    let out = dev_enrol(
        &dir.path().join("weaver.db"),
        &["--person", "nightly", "--machine", "runner"],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let printed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        (printed["person"].as_str(), printed["machine"].as_str()),
        (Some("nightly"), Some("runner"))
    );
}
