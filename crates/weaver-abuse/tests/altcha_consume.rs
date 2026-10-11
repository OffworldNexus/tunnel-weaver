//! Tests for the ALTCHA consumer entry point: verification, context binding,
//! and the atomic single-use consume.
//!
//! These assert the engine *returns a verdict* — it never decides a response.
//! Mapping a refusal to a status is the caller's job.

use std::collections::BTreeMap;

use async_trait::async_trait;
use weaver_abuse::testing::MemoryProofStore;
use weaver_abuse::{
    AltchaClient, AltchaError, Challenge, ConsumeKey, ConsumeOutcome, ConsumeRequest,
    CreateRequest, Payload, ProofError, ProofStore, StoreError, Verified, create_challenge,
    solve_challenge, verify_and_consume,
};

const SECRET: &str = "consume-test-secret";
const KEY: &str = "client-key";
const NOW_MS: i64 = 1_700_000_000_000;

fn client() -> AltchaClient {
    AltchaClient {
        public_key: KEY.to_string(),
        secret: SECRET.to_string(),
        algorithm: "PBKDF2/SHA-256".to_string(),
        cost: 10,
        key_length: 32,
        key_prefix: "00".to_string(),
        ttl_secs: 300,
    }
}

fn payload(ttl_secs: i64) -> Payload {
    let data = BTreeMap::from([
        ("client".to_string(), KEY.into()),
        ("purpose".to_string(), "diagnostic".into()),
        ("flow".to_string(), "flow-1".into()),
    ]);
    let challenge: Challenge = create_challenge(CreateRequest {
        algorithm: "PBKDF2/SHA-256",
        cost: 10,
        key_length: 32,
        key_prefix: "00",
        ttl_secs,
        secret: SECRET,
        data,
        nonce: [3u8; 16],
        salt: [4u8; 16],
        now_ms: NOW_MS,
    });
    let solution = solve_challenge(&challenge);
    Payload {
        challenge,
        solution,
    }
}

async fn consume<S: ProofStore>(
    store: &S,
    payload: &Payload,
    flow: &str,
    now_ms: i64,
) -> Result<Verified, AltchaError> {
    verify_and_consume(
        store,
        ConsumeRequest {
            client: KEY,
            payload,
            purpose: "diagnostic",
            flow,
            now_ms,
        },
    )
    .await
}

#[tokio::test]
async fn a_valid_proof_is_consumed_once() {
    let store = MemoryProofStore::new();
    store.add_client(client());
    let payload = payload(300);

    assert!(consume(&store, &payload, "flow-1", NOW_MS).await.is_ok());
    assert_eq!(store.spent_count(), 1);

    // Replaying the exact same proof is reported as spent.
    assert_eq!(
        consume(&store, &payload, "flow-1", NOW_MS)
            .await
            .unwrap_err(),
        AltchaError::Proof(ProofError::Spent)
    );
}

#[tokio::test]
async fn an_unknown_client_is_refused() {
    let store = MemoryProofStore::new();
    let payload = payload(300);
    assert_eq!(
        consume(&store, &payload, "flow-1", NOW_MS)
            .await
            .unwrap_err(),
        AltchaError::Proof(ProofError::UnknownClient)
    );
}

#[tokio::test]
async fn a_revoked_client_is_refused() {
    let store = MemoryProofStore::new();
    store.add_client(client());
    store.remove_client(KEY);
    let payload = payload(300);
    assert_eq!(
        consume(&store, &payload, "flow-1", NOW_MS)
            .await
            .unwrap_err(),
        AltchaError::Proof(ProofError::UnknownClient)
    );
}

#[tokio::test]
async fn a_wrong_flow_is_refused_and_not_consumed() {
    let store = MemoryProofStore::new();
    store.add_client(client());
    let payload = payload(300);
    assert_eq!(
        consume(&store, &payload, "not-the-flow", NOW_MS)
            .await
            .unwrap_err(),
        AltchaError::Proof(ProofError::WrongContext)
    );
    assert_eq!(store.spent_count(), 0, "a refused proof is not consumed");
}

#[tokio::test]
async fn an_expired_proof_is_refused() {
    let store = MemoryProofStore::new();
    store.add_client(client());
    let payload = payload(60);
    assert_eq!(
        consume(&store, &payload, "flow-1", NOW_MS + 61_000)
            .await
            .unwrap_err(),
        AltchaError::Proof(ProofError::Expired)
    );
}

/// A store whose lookups always fail, to prove the engine reports a store
/// failure rather than authorizing the action.
struct FailingStore;

#[async_trait]
impl ProofStore for FailingStore {
    async fn client(&self, _public_key: &str) -> Result<Option<AltchaClient>, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn consume(
        &self,
        _key: ConsumeKey<'_>,
        _now_ms: i64,
    ) -> Result<ConsumeOutcome, StoreError> {
        Err(StoreError::Unavailable)
    }
}

#[tokio::test]
async fn a_store_failure_is_reported_not_hidden() {
    let payload = payload(300);
    assert_eq!(
        consume(&FailingStore, &payload, "flow-1", NOW_MS)
            .await
            .unwrap_err(),
        AltchaError::Store(StoreError::Unavailable)
    );
}
