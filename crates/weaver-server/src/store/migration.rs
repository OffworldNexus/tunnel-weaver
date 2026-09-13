use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;
use sha2::{Digest, Sha256};

use super::error::StoreError;

/// A forward-only SQL database migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    /// 1-based sequential version number.
    pub version: u32,
    /// Human-readable migration name (e.g. "0001_init").
    pub name: &'static str,
    /// Raw SQL statements to execute in a transaction.
    pub sql: &'static str,
}

/// Static registry of migrations embedded into the binary.
pub static MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "0001_init",
    sql: include_str!("../../migrations/0001_init.sql"),
}];

/// Computes the SHA-256 checksum of SQL migration content as a 64-character lowercase hex string.
pub fn compute_checksum(sql: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sql.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex
}

/// Verifies migration sequence and applies any pending migrations in transactions.
pub fn run_migrations(conn: &mut Connection) -> Result<(), StoreError> {
    run_migrations_with(conn, MIGRATIONS)
}

/// Internal migration runner parameterized by migration registry for testing.
pub fn run_migrations_with(
    conn: &mut Connection,
    migrations: &[Migration],
) -> Result<(), StoreError> {
    // 1. Validate contiguous numbering in binary migrations
    for (idx, m) in migrations.iter().enumerate() {
        let expected_version = (idx + 1) as u32;
        if m.version != expected_version {
            return Err(StoreError::InvalidMigrationSequence(format!(
                "Migration '{}' at index {idx} has version {}, expected {expected_version}",
                m.name, m.version
            )));
        }
    }

    // 2. Ensure schema_migrations table exists
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            checksum TEXT NOT NULL,
            applied_at INTEGER NOT NULL
        );",
    )?;

    // 3. Read applied migrations
    let applied_rows: Vec<(u32, String, String)> = {
        let mut stmt = conn.prepare(
            "SELECT version, name, checksum FROM schema_migrations ORDER BY version ASC",
        )?;
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<Result<_, _>>()?
    };

    let binary_version = migrations.last().map_or(0, |m| m.version);
    let max_applied = applied_rows.last().map_or(0, |(v, _, _)| *v);

    // 4. Refuse opening if DB is newer than binary
    if max_applied > binary_version {
        return Err(StoreError::NewerSchema {
            db_version: max_applied,
            binary_version,
        });
    }

    // 5. Verify checksums of already-applied migrations
    for (applied_version, _, recorded_checksum) in &applied_rows {
        let binary_migration = migrations
            .iter()
            .find(|m| m.version == *applied_version)
            .ok_or_else(|| StoreError::NewerSchema {
                db_version: *applied_version,
                binary_version,
            })?;

        let expected_checksum = compute_checksum(binary_migration.sql);
        if *recorded_checksum != expected_checksum {
            return Err(StoreError::ChecksumMismatch {
                version: *applied_version,
                expected: expected_checksum,
                actual: recorded_checksum.clone(),
            });
        }
    }

    // 6. Execute pending migrations in individual transactions
    let pending = migrations
        .iter()
        .filter(|m| m.version > max_applied)
        .collect::<Vec<_>>();

    for migration in pending {
        let checksum = compute_checksum(migration.sql);
        let applied_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let tx = conn.transaction()?;
        tx.execute_batch(migration.sql)?;
        tx.execute(
            "INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![migration.version, migration.name, checksum, applied_at],
        )?;
        tx.commit()?;
    }

    Ok(())
}
