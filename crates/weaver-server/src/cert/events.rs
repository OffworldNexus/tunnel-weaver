use crate::store::{Store, StoreError};

/// Records a certificate lifecycle event into the `cert_events` table.
pub fn record_cert_event(
    store: &Store,
    name: &str,
    at: i64,
    kind: &str,
    detail: Option<&str>,
) -> Result<(), StoreError> {
    store.write(|conn| {
        conn.execute(
            "INSERT INTO cert_events (name, at, kind, detail) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![name, at, kind, detail],
        )?;
        Ok(())
    })
}
