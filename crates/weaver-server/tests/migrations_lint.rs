use std::fs;
use std::path::Path;

use rusqlite::Connection;
use weaver_server::StoreError;
use weaver_server::store::migration::{
    MIGRATIONS, Migration, compute_checksum, run_migrations_with,
};

#[test]
fn test_migrations_lint_contiguous_and_valid_naming() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let migrations_dir = Path::new(manifest_dir).join("migrations");

    let mut entries: Vec<_> = fs::read_dir(&migrations_dir)
        .expect("failed to read migrations directory")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "sql"))
        .collect();

    entries.sort_by_key(|e| e.file_name());
    assert!(
        !entries.is_empty(),
        "migrations directory must contain at least one .sql migration"
    );

    let mut versions = Vec::new();

    for (idx, entry) in entries.iter().enumerate() {
        let file_name = entry.file_name();
        let file_name_str = file_name.to_str().expect("valid UTF-8 filename");

        // Format must be NNNN_name.sql
        let parts: Vec<&str> = file_name_str.splitn(2, '_').collect();
        assert_eq!(
            parts.len(),
            2,
            "Migration filename '{file_name_str}' must follow format 'NNNN_<name>.sql'"
        );

        let version_num: u32 = parts[0]
            .parse()
            .unwrap_or_else(|_| panic!("Invalid numeric prefix in '{file_name_str}'"));

        let expected_version = (idx + 1) as u32;
        assert_eq!(
            version_num, expected_version,
            "Migrations must be contiguously numbered starting at 1. Found {version_num}, expected {expected_version}"
        );
        versions.push(version_num);

        // Read content and check non-empty
        let content = fs::read_to_string(entry.path()).expect("read migration file");
        assert!(
            !content.trim().is_empty(),
            "Migration file '{file_name_str}' must not be empty"
        );
    }
}

#[test]
fn test_migrations_lint_embedded_matches_disk() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let migrations_dir = Path::new(manifest_dir).join("migrations");

    let mut disk_entries: Vec<_> = fs::read_dir(&migrations_dir)
        .expect("read migrations dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "sql"))
        .collect();
    disk_entries.sort_by_key(|e| e.file_name());

    assert_eq!(
        MIGRATIONS.len(),
        disk_entries.len(),
        "Embedded MIGRATIONS length ({}) must match disk migrations count ({})",
        MIGRATIONS.len(),
        disk_entries.len()
    );

    for (idx, disk_entry) in disk_entries.iter().enumerate() {
        let embedded = &MIGRATIONS[idx];
        let file_name = disk_entry.file_name();
        let file_name_str = file_name.to_str().unwrap();
        let stem = file_name_str.strip_suffix(".sql").unwrap();

        assert_eq!(
            embedded.version,
            (idx + 1) as u32,
            "Embedded migration {idx} version mismatch"
        );
        assert_eq!(
            embedded.name, stem,
            "Embedded migration name must match file stem"
        );

        let disk_content = fs::read_to_string(disk_entry.path()).unwrap();
        let disk_checksum = compute_checksum(&disk_content);
        let embedded_checksum = compute_checksum(embedded.sql);

        assert_eq!(
            embedded_checksum, disk_checksum,
            "Embedded migration '{stem}' checksum does not match file on disk"
        );
    }
}

#[test]
fn test_migrations_lint_execution_and_idempotence() {
    let mut conn = Connection::open_in_memory().expect("open in-memory db");

    // 1. Initial run: applies all migrations
    run_migrations_with(&mut conn, MIGRATIONS).expect("first run should succeed");

    let initial_count: i64 = conn
        .query_row("SELECT count(*) FROM schema_migrations", [], |r| r.get(0))
        .expect("count schema_migrations");
    assert_eq!(initial_count, MIGRATIONS.len() as i64);

    // 2. Second run: must be a no-op (idempotent)
    run_migrations_with(&mut conn, MIGRATIONS).expect("second run should be a no-op");

    let second_count: i64 = conn
        .query_row("SELECT count(*) FROM schema_migrations", [], |r| r.get(0))
        .expect("count schema_migrations");
    assert_eq!(
        initial_count, second_count,
        "Re-applying migrations should not insert additional records"
    );
}

#[test]
fn test_migrations_lint_detects_tampered_migration() {
    let mut conn = Connection::open_in_memory().expect("open in-memory db");
    run_migrations_with(&mut conn, MIGRATIONS).expect("initial migration run");

    // Tamper with migration SQL
    let tampered_migrations = vec![Migration {
        version: 1,
        name: "0001_init",
        sql: "CREATE TABLE different_table (id INTEGER);",
    }];

    match run_migrations_with(&mut conn, &tampered_migrations) {
        Err(StoreError::ChecksumMismatch { version, .. }) => {
            assert_eq!(version, 1);
        }
        res => panic!("Expected ChecksumMismatch, got: {res:?}"),
    }
}

#[test]
fn test_migrations_lint_detects_newer_schema() {
    let mut conn = Connection::open_in_memory().expect("open in-memory db");
    run_migrations_with(&mut conn, MIGRATIONS).expect("initial migration run");

    // Suppose DB has migration 2 applied, but binary only knows migration 1
    conn.execute(
        "INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (2, '0002_future', 'fakehash', 99999)",
        [],
    )
    .unwrap();

    match run_migrations_with(&mut conn, MIGRATIONS) {
        Err(StoreError::NewerSchema {
            db_version,
            binary_version,
        }) => {
            assert_eq!(db_version, 2);
            assert_eq!(binary_version, MIGRATIONS.len() as u32);
        }
        res => panic!("Expected NewerSchema, got: {res:?}"),
    }
}
