use crate::store::{Store, StoreError};

/// Records a certificate lifecycle event into the `cert_events` table.
pub async fn record_cert_event(
    store: &Store,
    name: &str,
    at: i64,
    kind: &str,
    detail: Option<&str>,
) -> Result<(), StoreError> {
    store.record_cert_event(name, at, kind, detail).await
}
