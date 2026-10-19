//! The production [`KeyAgent`]: the device key lives in tpmd.
//!
//! tpmd provisions a P-256 key in the `tunnel-weaver` namespace and signs on
//! request; the key never leaves it. Its handshake does get-or-create
//! atomically (`ResumeOrCreate`), so this adapter asks once and reports what
//! tpmd did.
//!
//! A locked store is normal (the user's session is locked), so it is waited
//! for, without limit, both at connect and when a signature comes back
//! `StoreClosed`: the user ends the wait with Ctrl-C.

use std::sync::Arc;
use std::time::Duration;

use tpmd_client::{
    Algorithm, Client, ClientError, ErrorDetail, KeyOutcome, KeyRequest, ProvisionRequest,
    RejectCode, Signature,
};
use tpmd_ipc::Endpoint;
use weaver_mux::auth::Signer;
use weaver_mux::{KeyId, SignError, Signature as MuxSignature};

use crate::key::{KeyAgent, KeyError, OpenedKey, Provision};
use crate::report::Reporter;

/// The tpmd namespace the device key lives in.
const NAMESPACE: &str = "tunnel-weaver";

/// How long one wait for the store lasts before it is issued again.
const STORE_WAIT: Duration = Duration::from_secs(3600);

/// The tpmd key agent, reached on the per-user endpoint, then the system one.
pub struct Tpmd;

#[async_trait::async_trait]
impl KeyAgent for Tpmd {
    async fn open(
        &self,
        remembered: Option<KeyId>,
        provision: Provision,
        reporter: Arc<dyn Reporter>,
    ) -> Result<OpenedKey, KeyError> {
        let provision = ProvisionRequest {
            algorithm: Algorithm::EcdsaP256Sha256,
            min_security: provision.floor,
            allow_below_floor: provision.allow_below_floor,
        };
        let request = match remembered {
            Some(KeyId::P256(bytes)) => KeyRequest::ResumeOrCreate {
                key_id: tpmd_client::KeyId::P256(bytes),
                provision,
            },
            _ => KeyRequest::Create(provision),
        };
        let client = connect(request, reporter.as_ref()).await?;
        let (info, created) = match client.key_outcome() {
            KeyOutcome::Created(info) => (info.clone(), true),
            KeyOutcome::Resumed(info) => (info.clone(), false),
            KeyOutcome::None => return Err(KeyError::Refused("tpmd returned no key".into())),
        };
        Ok(OpenedKey {
            level: info.security_level,
            created,
            signer: Box::new(DeviceKey {
                client,
                key_id: info.key_id,
                reporter,
            }),
        })
    }
}

/// Signs through tpmd with the opened key.
struct DeviceKey {
    client: Client,
    key_id: tpmd_client::KeyId,
    reporter: Arc<dyn Reporter>,
}

#[async_trait::async_trait]
impl Signer for DeviceKey {
    fn key_id(&self) -> KeyId {
        let tpmd_client::KeyId::P256(bytes) = self.key_id;
        KeyId::P256(bytes)
    }

    async fn sign(&mut self, msg: &[u8]) -> Result<MuxSignature, SignError> {
        loop {
            match self.client.sign(self.key_id, msg).await {
                Ok(Signature::P256(bytes)) => return Ok(MuxSignature::P256(bytes)),
                Err(ClientError::StoreClosed { .. }) => {
                    self.reporter.waiting_for_key_store();
                    while let Err(e) = self.client.await_store_open(STORE_WAIT).await {
                        if !matches!(e, ClientError::StoreClosed { .. }) {
                            return Err(SignError(e.to_string()));
                        }
                    }
                }
                Err(e) => return Err(SignError(e.to_string())),
            }
        }
    }
}

/// Connects with `request`, waiting as long as it takes for a locked store.
async fn connect(request: KeyRequest, reporter: &dyn Reporter) -> Result<Client, KeyError> {
    let endpoints =
        Endpoint::client_candidates().map_err(|e| KeyError::Unavailable(e.to_string()))?;
    // Ask without waiting first, so the wait is reported before it starts.
    let mut budget = Duration::ZERO;
    loop {
        match connect_any(&endpoints, &request, budget).await {
            Err(ClientError::StoreClosed { .. }) => {
                if budget.is_zero() {
                    reporter.waiting_for_key_store();
                }
                budget = STORE_WAIT;
            }
            result => return result.map_err(key_error),
        }
    }
}

/// The first endpoint where a daemon answers.
async fn connect_any(
    endpoints: &[Endpoint],
    request: &KeyRequest,
    budget: Duration,
) -> Result<Client, ClientError> {
    let mut last = None;
    for endpoint in endpoints {
        match Client::connect_within(endpoint, NAMESPACE, request.clone(), budget).await {
            Err(e @ ClientError::Unavailable { .. }) => last = Some(e),
            answered => return answered,
        }
    }
    Err(last.unwrap_or_else(|| ClientError::Protocol("no tpmd endpoint to try".into())))
}

fn key_error(e: ClientError) -> KeyError {
    match e {
        ClientError::Unavailable { .. } => KeyError::Unavailable(e.to_string()),
        ClientError::Rejected {
            code: RejectCode::IncompatiblePolicy,
            detail:
                Some(ErrorDetail::Floor {
                    required,
                    available,
                }),
            ..
        } => KeyError::BelowFloor {
            required,
            available,
        },
        other => KeyError::Refused(other.to_string()),
    }
}
