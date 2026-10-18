//! `weaver-server dev-enrol`: a test-only affordance for the nightly workflow.
//!
//! Pairing a machine takes a browser and a key agent, neither of which a CI
//! runner has. The nightly instead runs `weave` with its built-in development
//! Ed25519 key and enrols that key on the disposable relay directly: this
//! creates (or reuses) an account, its person and a machine holding the
//! development key, so the tunnel hostnames are
//! `<person>-<machine>-<service>.<tunnel domain>` (by default `poc-laptop-…`).
//!
//! It is hidden from `--help` and must never be run against a relay anyone
//! uses: whoever holds the development seed — it is public, in this repository —
//! can then register services as that machine.

use ed25519_dalek::SigningKey;
use serde::Serialize;
use weaver_mux::KeyId;

use crate::store::{Store, StoreError, format_key_id};

/// The development client's Ed25519 seed.
///
/// Must stay byte-for-byte equal to `DEV_SECRET_KEY` in `weave`'s
/// `crates/weave/src/identity.rs` (`tests/dev_enrol.rs` proves it does).
pub const DEV_KEY_SEED: [u8; 32] = *b"weaver-poc-laptop-secret-key-32b";

/// Default person slug.
pub const DEFAULT_PERSON: &str = "poc";
/// Default machine name.
pub const DEFAULT_MACHINE: &str = "laptop";

/// The development key's public half, as `weave`'s dev signer presents it.
pub fn dev_key_id() -> KeyId {
    KeyId::Ed25519(
        SigningKey::from_bytes(&DEV_KEY_SEED)
            .verifying_key()
            .to_bytes(),
    )
}

/// What was enrolled, printed as the command's single line of JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Enrolled {
    /// The machine's id on this relay.
    pub machine_id: i32,
    /// The person slug.
    pub person: String,
    /// The machine name.
    pub machine: String,
}

/// Enrols the development key as `person`'s machine `machine`.
///
/// Idempotent: an existing person is reused (a new one comes with its own
/// login-less account), an existing machine of that name is moved onto the
/// development key, and a key already enrolled there is left as it is. The
/// key already belonging to a *different* machine is a conflict — the relay
/// allows one machine per key — and nothing is changed.
pub async fn enrol(store: &Store, person: &str, machine: &str) -> Result<Enrolled, StoreError> {
    let key = dev_key_id();
    let person_slug = person.to_ascii_lowercase();
    let machine_name = machine.to_ascii_lowercase();

    if let Some((owner, held)) = store.machine_by_key(&key).await? {
        if owner.name == person_slug && held.name == machine_name {
            return Ok(Enrolled {
                machine_id: held.id,
                person: owner.name,
                machine: held.name,
            });
        }
        return Err(StoreError::Conflict(format!(
            "the development key {} is already enrolled as {}-{}",
            format_key_id(&key),
            owner.name,
            held.name
        )));
    }

    let owner = match store.get_person_by_name(&person_slug).await? {
        Some(existing) => existing,
        None => {
            let account = store.create_account_without_login(&person_slug).await?;
            store.create_person(account.id, &person_slug).await?
        }
    };
    let held = match store.get_machine_by_name(owner.id, &machine_name).await? {
        Some(existing) => store.replace_machine_key(existing.id, &key).await?,
        None => store.create_machine(owner.id, &machine_name, &key).await?,
    };
    Ok(Enrolled {
        machine_id: held.id,
        person: owner.name,
        machine: held.name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn enrolling_twice_reuses_everything() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let first = enrol(&store, "poc", "laptop").await.unwrap();
        assert_eq!(
            (first.person.as_str(), first.machine.as_str()),
            ("poc", "laptop")
        );
        assert_eq!(enrol(&store, "POC", "Laptop").await.unwrap(), first);
        let (owner, held) = store.machine_by_key(&dev_key_id()).await.unwrap().unwrap();
        assert_eq!((owner.name.as_str(), held.id), ("poc", first.machine_id));
    }

    #[tokio::test]
    async fn an_existing_machine_moves_onto_the_development_key() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let account = store.create_account_without_login("poc").await.unwrap();
        let poc = store.create_person(account.id, "poc").await.unwrap();
        let laptop = store
            .create_machine(poc.id, "laptop", &KeyId::P256([2; 33]))
            .await
            .unwrap();
        let enrolled = enrol(&store, "poc", "laptop").await.unwrap();
        assert_eq!(enrolled.machine_id, laptop.id);
        assert!(
            store
                .machine_by_key(&KeyId::P256([2; 33]))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn the_key_cannot_become_a_second_machine() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        enrol(&store, "poc", "laptop").await.unwrap();
        assert!(matches!(
            enrol(&store, "poc", "desktop").await,
            Err(StoreError::Conflict(_))
        ));
        assert!(matches!(
            enrol(&store, "bad-slug", "laptop").await,
            Err(StoreError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn invalid_names_are_refused() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        assert!(matches!(
            enrol(&store, "has-dash", "laptop").await,
            Err(StoreError::InvalidName(_))
        ));
    }
}
