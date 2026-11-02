use std::path::Path;
use std::process::{Command, Output};

/// A throwaway data directory.
///
/// `weave start` falls back to the default relay, so a test that ran it with
/// the developer's real data dir would dial a *real* relay. Every test that
/// could read the store gets its own empty one instead.
fn isolated_config() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir for an isolated data dir")
}

/// `weave <args>` against `data_dir`, with the colour/hyperlink forcing
/// variables cleared so the output is what a pipe gets.
fn weave(data_dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_weave"))
        .args(args)
        .env("WEAVE_DATA_DIR", data_dir)
        .env_remove("CLICOLOR_FORCE")
        .env_remove("FORCE_HYPERLINK")
        .env_remove("NO_COLOR")
        .output()
        .expect("failed to execute binary")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Seeds `data_dir` with pairings, in order (the first becomes the default).
fn seed(data_dir: &Path, relays: &[(&str, i32)]) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let store = weave::store::Store::open(data_dir.join("weave.db"))
            .await
            .unwrap();
        for (host, machine) in relays {
            store
                .record_pairing(host, *machine, &format!("p256:02{}", "ab".repeat(32)))
                .await
                .unwrap();
        }
    });
}

fn stored(data_dir: &Path) -> Vec<(String, bool)> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let store = weave::store::Store::open(data_dir.join("weave.db"))
            .await
            .unwrap();
        store
            .relays()
            .await
            .unwrap()
            .into_iter()
            .map(|r| (r.admin_host, r.is_default))
            .collect()
    })
}

#[test]
fn test_weave_start_without_a_paired_relay_tells_you_to_pair() {
    let config = isolated_config();
    let output = Command::new(env!("CARGO_BIN_EXE_weave"))
        .args(["start", "web=8080"])
        .env("WEAVE_DATA_DIR", config.path())
        .output()
        .expect("failed to execute binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("weave pair"), "stderr: {stderr}");
    // It must fail before dialling anything.
    assert!(!stderr.contains("handshake"), "stderr: {stderr}");
}

#[test]
fn test_weave_start_rejects_unknown_service_flag() {
    let config = isolated_config();
    let output = Command::new(env!("CARGO_BIN_EXE_weave"))
        .args([
            "start",
            "web=8080",
            "--server",
            "localhost:443",
            "--no-rewrite",
            "api",
        ])
        .env("WEAVE_DATA_DIR", config.path())
        .output()
        .expect("failed to execute binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown service 'api'"), "stderr: {stderr}");
}

#[test]
fn relays_lists_default_first_and_changes_the_default() {
    let dir = isolated_config();
    seed(dir.path(), &[("a.example", 3), ("b.example:8443", 12)]);

    let out = weave(dir.path(), &["relays"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{stdout}");
    assert!(lines[0].contains("a.example") && lines[0].ends_with("default"));
    assert!(lines[0].contains("machine 3"));
    assert!(lines[0].contains("p256:02ababab\u{2026}abab"), "{stdout}");
    assert!(lines[1].contains("b.example:8443") && !lines[1].contains("default"));

    // The host is normalised before the lookup.
    let out = weave(dir.path(), &["relays", "default", "B.Example.:8443"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("b.example:8443 is now the default relay"));

    let stdout = text(&weave(dir.path(), &["relays", "list"]).stdout);
    assert!(
        stdout.lines().next().unwrap().contains("b.example:8443"),
        "{stdout}"
    );
    assert_eq!(
        stored(dir.path()),
        [
            ("b.example:8443".to_string(), true),
            ("a.example".to_string(), false)
        ]
    );
}

#[test]
fn pair_refuses_bad_input_before_touching_anything() {
    let dir = isolated_config();
    let out = weave(dir.path(), &["pair", "http://relay.example"]);
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("not a relay address"));

    let out = weave(
        dir.path(),
        &["pair", "relay.example", "--min-key-security", "bogus"],
    );
    assert!(!out.status.success());
    let stderr = text(&out.stderr);
    assert!(stderr.contains("unknown key security level"), "{stderr}");
    assert!(
        stderr.contains("file, keyring, sealed, hardware"),
        "{stderr}"
    );
    assert!(!dir.path().join("weave.db").exists());
}

#[test]
fn pair_help_speaks_of_machines() {
    let out = weave(isolated_config().path(), &["pair", "--help"]);
    let stdout = text(&out.stdout);
    assert!(stdout.contains("--machine"));
    assert!(stdout.contains("[default: sealed]"));
}

#[test]
fn piped_output_has_no_escape_codes() {
    let dir = isolated_config();
    seed(dir.path(), &[("a.example", 1), ("b.example", 2)]);
    for args in [
        &["relays"][..],
        &["relays", "default", "b.example"],
        &["relays", "default", "nope.example"],
        &["start", "web=8080", "--server", "nope.example"],
    ] {
        let out = weave(dir.path(), args);
        for (name, bytes) in [("stdout", &out.stdout), ("stderr", &out.stderr)] {
            assert!(
                !bytes.contains(&0x1b),
                "{args:?} {name} has an escape: {:?}",
                text(bytes)
            );
        }
    }
}
