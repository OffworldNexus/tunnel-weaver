//! ALTCHA API clients and spent proofs.
//!
//! The pure challenge/verification arithmetic lives in `weaver-abuse`; this
//! module is the store side. Clients are created, rotated and revoked by the
//! `altcha clients` CLI; proofs are consumed exactly once by the ALTCHA pass and
//! swept once expired.

use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, Set, TransactionTrait,
};
use weaver_abuse::ConsumeOutcome;

use super::entity::{altcha_client, altcha_proof};
use super::{Store, StoreError};

/// The fields a caller supplies to create an ALTCHA client. The store fills in
/// the id and timestamps.
#[derive(Debug, Clone)]
pub struct NewAltchaClient {
    /// The public key that identifies the client on challenge requests.
    pub public_key: String,
    /// The HMAC secret that signs the client's challenges.
    pub secret: String,
    /// The approved KDF algorithm (e.g. `"PBKDF2/SHA-256"`).
    pub algorithm: String,
    /// The approved PBKDF2 iteration count.
    pub cost: i32,
    /// The approved derived-key length in bytes.
    pub key_length: i32,
    /// The approved hex key prefix.
    pub key_prefix: String,
    /// The challenge lifetime in seconds.
    pub ttl_secs: i64,
    /// The owning service, or `None` for the internal (admin) client.
    pub service_id: Option<i32>,
}

impl Store {
    /// Resolve a live (non-revoked) client by its public key.
    pub async fn altcha_client_live(
        &self,
        public_key: &str,
    ) -> Result<Option<altcha_client::Model>, StoreError> {
        Ok(altcha_client::Entity::find()
            .filter(altcha_client::Column::PublicKey.eq(public_key))
            .filter(altcha_client::Column::RevokedAt.is_null())
            .one(&self.db)
            .await?)
    }

    /// The internal (admin) client, if one exists and is live.
    pub async fn altcha_internal_client(&self) -> Result<Option<altcha_client::Model>, StoreError> {
        Ok(altcha_client::Entity::find()
            .filter(altcha_client::Column::ServiceId.is_null())
            .filter(altcha_client::Column::RevokedAt.is_null())
            .one(&self.db)
            .await?)
    }

    /// Every client, live or revoked, newest first.
    pub async fn altcha_clients_list(&self) -> Result<Vec<altcha_client::Model>, StoreError> {
        Ok(altcha_client::Entity::find().all(&self.db).await?)
    }

    /// Resolve a service id from a materialized flat hostname.
    pub async fn service_id_for_domain(&self, name: &str) -> Result<Option<i32>, StoreError> {
        use super::entity::domain;
        Ok(domain::Entity::find()
            .filter(domain::Column::Name.eq(name))
            .one(&self.db)
            .await?
            .and_then(|d| d.service_id))
    }

    /// Create a client.
    ///
    /// At most one *internal* client (`service_id` null) may exist: the check
    /// and the insert share one transaction so two concurrent creates cannot
    /// both win. A revoked internal client does not block a replacement.
    pub async fn altcha_client_create(
        &self,
        new: NewAltchaClient,
        now_ms: i64,
    ) -> Result<altcha_client::Model, StoreError> {
        let txn = self.db.begin().await?;
        if new.service_id.is_none() {
            let existing = altcha_client::Entity::find()
                .filter(altcha_client::Column::ServiceId.is_null())
                .filter(altcha_client::Column::RevokedAt.is_null())
                .one(&txn)
                .await?;
            if existing.is_some() {
                txn.rollback().await?;
                return Err(StoreError::Conflict(
                    "an internal ALTCHA client already exists".into(),
                ));
            }
        }
        let inserted = altcha_client::Entity::insert(altcha_client::ActiveModel {
            public_key: Set(new.public_key),
            secret: Set(new.secret),
            algorithm: Set(new.algorithm),
            cost: Set(new.cost),
            key_length: Set(new.key_length),
            key_prefix: Set(new.key_prefix),
            ttl_secs: Set(new.ttl_secs),
            service_id: Set(new.service_id),
            created_at: Set(now_ms),
            rotated_at: Set(now_ms),
            revoked_at: Set(None),
            ..Default::default()
        })
        .exec_with_returning(&txn)
        .await?;
        txn.commit().await?;
        Ok(inserted)
    }

    /// Replace a client's secret in place, returning the updated row.
    pub async fn altcha_client_rotate(
        &self,
        public_key: &str,
        new_secret: &str,
        now_ms: i64,
    ) -> Result<Option<altcha_client::Model>, StoreError> {
        let Some(existing) = altcha_client::Entity::find()
            .filter(altcha_client::Column::PublicKey.eq(public_key))
            .one(&self.db)
            .await?
        else {
            return Ok(None);
        };
        let mut active: altcha_client::ActiveModel = existing.into();
        active.secret = Set(new_secret.to_string());
        active.rotated_at = Set(now_ms);
        Ok(Some(active.update(&self.db).await?))
    }

    /// Revoke a client (kept for audit); returns whether a live row was revoked.
    pub async fn altcha_client_revoke(
        &self,
        public_key: &str,
        now_ms: i64,
    ) -> Result<bool, StoreError> {
        let Some(existing) = altcha_client::Entity::find()
            .filter(altcha_client::Column::PublicKey.eq(public_key))
            .filter(altcha_client::Column::RevokedAt.is_null())
            .one(&self.db)
            .await?
        else {
            return Ok(false);
        };
        let mut active: altcha_client::ActiveModel = existing.into();
        active.revoked_at = Set(Some(now_ms));
        active.update(&self.db).await?;
        Ok(true)
    }

    /// Atomically consume a proof, or report it already spent.
    ///
    /// Fails closed (a store error) when the live-proof count at `now_ms` has
    /// reached `cap`, so the table cannot grow without bound. Expired markers
    /// do not count: they no longer guard anything, and how soon the sweep
    /// reclaims them must not decide whether a fresh proof is accepted. `INSERT … ON CONFLICT DO NOTHING`
    /// is the single-use point: the first insert affects one row, a replay zero.
    pub async fn altcha_consume_proof(
        &self,
        public_key: &str,
        nonce: &str,
        expires_at_ms: i64,
        now_ms: i64,
        cap: u64,
    ) -> Result<ConsumeOutcome, StoreError> {
        if cap > 0 && self.altcha_live_proof_count(now_ms).await? >= cap {
            return Err(StoreError::Capacity("altcha_proof"));
        }
        let result = altcha_proof::Entity::insert(altcha_proof::ActiveModel {
            public_key: Set(public_key.to_string()),
            nonce: Set(nonce.to_string()),
            consumed_at_ms: Set(now_ms),
            expires_at_ms: Set(expires_at_ms),
            ..Default::default()
        })
        .on_conflict(
            OnConflict::columns([altcha_proof::Column::PublicKey, altcha_proof::Column::Nonce])
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(&self.db)
        .await?;
        Ok(if result == 1 {
            ConsumeOutcome::Consumed
        } else {
            ConsumeOutcome::AlreadySpent
        })
    }

    /// Count the spent-proof rows still live at `now_ms`.
    pub async fn altcha_live_proof_count(&self, now_ms: i64) -> Result<u64, StoreError> {
        Ok(altcha_proof::Entity::find()
            .filter(altcha_proof::Column::ExpiresAtMs.gte(now_ms))
            .count(&self.db)
            .await?)
    }

    /// Delete spent-proof rows that expired before `cutoff_ms`; returns the
    /// number removed.
    pub async fn altcha_sweep_proofs(&self, cutoff_ms: i64) -> Result<u64, StoreError> {
        let result = altcha_proof::Entity::delete_many()
            .filter(altcha_proof::Column::ExpiresAtMs.lt(cutoff_ms))
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn client(public_key: &str, service_id: Option<i32>) -> NewAltchaClient {
        NewAltchaClient {
            public_key: public_key.to_string(),
            secret: "secret".to_string(),
            algorithm: "PBKDF2/SHA-256".to_string(),
            cost: 10,
            key_length: 32,
            key_prefix: "00".to_string(),
            ttl_secs: 300,
            service_id,
        }
    }

    async fn store() -> Store {
        let dir = tempdir().unwrap().keep();
        Store::open(dir.join("altcha.db")).await.unwrap()
    }

    #[tokio::test]
    async fn create_and_resolve_clients() {
        let store = store().await;
        let internal = store
            .altcha_client_create(client("ak_internal", None), 1_000)
            .await
            .unwrap();
        assert!(internal.service_id.is_none());
        assert!(store.altcha_internal_client().await.unwrap().is_some());
        assert!(
            store
                .altcha_client_live("ak_internal")
                .await
                .unwrap()
                .is_some()
        );

        // A service client needs a real service row for the foreign key.
        use crate::store::entity::service;
        use sea_orm::{ActiveModelTrait, Set};
        let person = store.create_test_person("alice").await.unwrap();
        let machine = store
            .create_machine(person.id, "laptop", &weaver_mux::KeyId::Ed25519([1; 32]))
            .await
            .unwrap();
        let service = service::ActiveModel {
            machine_id: Set(machine.id),
            name: Set("web".into()),
            created_at: Set(1_000),
            ..Default::default()
        }
        .insert(store.db())
        .await
        .unwrap();

        let service_client = store
            .altcha_client_create(client("ak_service", Some(service.id)), 1_000)
            .await
            .unwrap();
        assert_eq!(service_client.service_id, Some(service.id));
    }

    #[tokio::test]
    async fn only_one_internal_client_may_exist() {
        let store = store().await;
        store
            .altcha_client_create(client("ak_first", None), 1_000)
            .await
            .unwrap();
        let second = store
            .altcha_client_create(client("ak_second", None), 1_000)
            .await;
        assert!(matches!(second, Err(StoreError::Conflict(_))));
    }

    #[tokio::test]
    async fn revoke_hides_a_client_but_keeps_the_row() {
        let store = store().await;
        store
            .altcha_client_create(client("ak_internal", None), 1_000)
            .await
            .unwrap();
        assert!(
            store
                .altcha_client_revoke("ak_internal", 2_000)
                .await
                .unwrap()
        );
        assert!(
            store
                .altcha_client_live("ak_internal")
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.altcha_internal_client().await.unwrap().is_none());
        // A revoked internal client does not block a replacement.
        store
            .altcha_client_create(client("ak_replacement", None), 2_000)
            .await
            .unwrap();
        assert_eq!(store.altcha_clients_list().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn rotate_replaces_the_secret() {
        let store = store().await;
        store
            .altcha_client_create(client("ak_internal", None), 1_000)
            .await
            .unwrap();
        let rotated = store
            .altcha_client_rotate("ak_internal", "new-secret", 2_000)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rotated.secret, "new-secret");
        assert_eq!(rotated.rotated_at, 2_000);
    }

    #[tokio::test]
    async fn consume_is_single_use_and_survives_reopen() {
        let dir = tempdir().unwrap().keep();
        let path = dir.join("altcha.db");
        let store = Store::open(&path).await.unwrap();
        assert_eq!(
            store
                .altcha_consume_proof("ak", "nonce-1", 10_000, 1_000, 0)
                .await
                .unwrap(),
            ConsumeOutcome::Consumed
        );
        assert_eq!(
            store
                .altcha_consume_proof("ak", "nonce-1", 10_000, 1_100, 0)
                .await
                .unwrap(),
            ConsumeOutcome::AlreadySpent
        );
        drop(store);

        let reopened = Store::open(&path).await.unwrap();
        assert_eq!(
            reopened
                .altcha_consume_proof("ak", "nonce-1", 10_000, 1_200, 0)
                .await
                .unwrap(),
            ConsumeOutcome::AlreadySpent
        );
    }

    #[tokio::test]
    async fn consume_fails_closed_at_capacity() {
        let store = store().await;
        store
            .altcha_consume_proof("ak", "nonce-1", 10_000, 1_000, 1)
            .await
            .unwrap();
        let capped = store
            .altcha_consume_proof("ak", "nonce-2", 10_000, 1_000, 1)
            .await;
        assert!(matches!(capped, Err(StoreError::Capacity(_))));
    }

    #[tokio::test]
    async fn expired_markers_do_not_count_against_the_cap() {
        let store = store().await;
        store
            .altcha_consume_proof("ak", "nonce-1", 1_000, 0, 1)
            .await
            .unwrap();
        // The first marker expired at 1 000 ms; it is unswept but inert.
        assert_eq!(
            store
                .altcha_consume_proof("ak", "nonce-2", 10_000, 2_000, 1)
                .await
                .unwrap(),
            ConsumeOutcome::Consumed
        );
    }

    #[tokio::test]
    async fn sweep_drops_expired_markers() {
        let store = store().await;
        store
            .altcha_consume_proof("ak", "nonce-1", 1_000, 0, 0)
            .await
            .unwrap();
        assert_eq!(store.altcha_sweep_proofs(2_000).await.unwrap(), 1);
        // The marker is gone, so the same nonce can be consumed again.
        assert_eq!(
            store
                .altcha_consume_proof("ak", "nonce-1", 10_000, 2_100, 0)
                .await
                .unwrap(),
            ConsumeOutcome::Consumed
        );
    }
}
