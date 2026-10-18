//! The device key, held by `tpmd`.
//!
//! `weave` never sees a private key. **tpmd**, the local key agent, provisions a
//! P-256 key in the `tunnel-weaver` namespace and signs on request; this module
//! is the thin adapter between tpmd's async client and the mux's
//! [`weaver_mux::auth::Signer`], plus the small amount of policy pairing needs:
//! the assurance floor and the consent to go below it.
//!
//! Two calls matter. [`probe`] asks what the machine can achieve without
//! touching a key (the daemon's capability announce), so `weave pair` can warn
//! *before* provisioning. [`open`] then provisions or resumes the key atomically
//! with `ResumeOrCreate` — a key the agent still holds is never replaced, and a
//! key that is gone (wiped store, cleared TPM) comes back as a new identity the
//! caller must not treat as the old one.

use tpmd_client::{
    Algorithm, Client, ClientError, KeyId, KeyOutcome, KeyRequest, ProvisionRequest, SecurityLevel,
    Signature,
};
use weaver_mux::auth::Signer;
use weaver_mux::{KeyId as MuxKeyId, SignError, Signature as MuxSignature};

/// The tpmd namespace the device key lives in.
pub const NAMESPACE: &str = "tunnel-weaver";

/// What tpmd can achieve on this machine, as it reports it.
#[derive(Debug, Clone)]
pub struct Assurance {
    /// The active backend's name, e.g. `linux-tpm`.
    pub backend: String,
    /// Every level the backend can reach.
    pub levels: Vec<SecurityLevel>,
    /// The level it achieves right now.
    pub achieved: SecurityLevel,
}

/// A failure talking to tpmd or provisioning the key.
#[derive(Debug, thiserror::Error)]
pub enum TpmError {
    /// The daemon could not be reached at all (not installed, not running).
    #[error("the tpmd key agent is not available: {0}")]
    Unavailable(String),
    /// The daemon refused the request (including a floor it cannot meet).
    #[error("tpmd refused the request: {0}")]
    Refused(String),
    /// The backend's dependency is gone (no TPM, no session bus).
    #[error("tpmd cannot serve this machine: {0}")]
    BackendUnavailable(String),
    /// The store is shut and did not open in time.
    #[error("the tpmd store is closed: {0}")]
    StoreClosed(String),
    /// The daemon spoke something unexpected.
    #[error("tpmd protocol error: {0}")]
    Protocol(String),
    /// A stored fingerprint was not a valid key id.
    #[error("the stored device key fingerprint is malformed: {0}")]
    BadStoredKey(String),
}

/// A connected device key: signing goes through tpmd, the key stays inside it.
pub struct DeviceKey {
    client: Client,
    key_id: KeyId,
    created: bool,
    level: SecurityLevel,
}

impl DeviceKey {
    /// Whether the handshake *created* a new key rather than resuming one.
    ///
    /// True on a first pairing, or when a previously remembered key no longer
    /// exists in the agent — a new identity the relay has never authorised.
    pub fn created(&self) -> bool {
        self.created
    }

    /// The fingerprint in the canonical `p256:<hex>` form the relay and the
    /// config file use.
    pub fn fingerprint(&self) -> String {
        key_id_string(self.key_id)
    }

    /// The protection level tpmd achieved for the key.
    pub fn security_level(&self) -> SecurityLevel {
        self.level
    }
}

#[async_trait::async_trait]
impl Signer for DeviceKey {
    fn key_id(&self) -> MuxKeyId {
        let KeyId::P256(bytes) = self.key_id;
        MuxKeyId::P256(bytes)
    }

    async fn sign(&mut self, msg: &[u8]) -> Result<MuxSignature, SignError> {
        match self.client.sign(self.key_id, msg).await {
            Ok(Signature::P256(bytes)) => Ok(MuxSignature::P256(bytes)),
            Err(e) => Err(SignError(e.to_string())),
        }
    }
}

/// Asks tpmd what this machine can achieve, without touching a key.
///
/// The handshake carries `KeyRequest::None`, so nothing is provisioned and no
/// backend choice is committed — this is purely the capability announce.
pub async fn probe() -> Result<Assurance, TpmError> {
    let client = connect(KeyRequest::None).await?;
    let caps = client.welcome().capabilities.clone();
    let _ = client.shutdown().await;
    Ok(Assurance {
        backend: caps.backend,
        levels: caps.levels,
        achieved: caps.default_level,
    })
}

/// Provisions or resumes the device key.
///
/// `remembered` is the fingerprint from a previous pairing: when present the
/// handshake is `ResumeOrCreate`, so a key the agent still holds is reused and
/// only a genuinely missing one is replaced. `floor` is the minimum assurance
/// the caller accepts, and `allow_below_floor` is the explicit consent tpmd
/// requires before it will provision below it.
pub async fn open(
    remembered: Option<KeyId>,
    floor: SecurityLevel,
    allow_below_floor: bool,
) -> Result<DeviceKey, TpmError> {
    let provision = ProvisionRequest {
        algorithm: Algorithm::EcdsaP256Sha256,
        min_security: floor,
        allow_below_floor,
    };
    let request = match remembered {
        Some(key_id) => KeyRequest::ResumeOrCreate { key_id, provision },
        None => KeyRequest::Create(provision),
    };
    let client = connect(request).await?;
    let (key_id, created, level) = match client.key_outcome() {
        KeyOutcome::Created(info) => (info.key_id, true, info.security_level),
        KeyOutcome::Resumed(info) => (info.key_id, false, info.security_level),
        KeyOutcome::None => {
            return Err(TpmError::Protocol(
                "the handshake returned no key outcome".into(),
            ));
        }
    };
    Ok(DeviceKey {
        client,
        key_id,
        created,
        level,
    })
}

/// Opens the machine's one device key, given every fingerprint it may go by.
///
/// All relays share the one key, so the first candidate tpmd still holds is
/// resumed. When it holds none of them, the first candidate goes through
/// `ResumeOrCreate` (and comes back created); with no candidates at all, a key
/// is created.
pub async fn open_any(
    candidates: &[String],
    floor: SecurityLevel,
    allow_below_floor: bool,
) -> Result<DeviceKey, TpmError> {
    let parsed = candidates
        .iter()
        .map(|text| parse_key_id(text))
        .collect::<Result<Vec<_>, _>>()?;
    let mut held = None;
    if parsed.len() > 1 {
        let mut probe = connect(KeyRequest::None).await?;
        for key_id in &parsed {
            if probe.describe(*key_id).await.is_ok() {
                held = Some(*key_id);
                break;
            }
        }
        let _ = probe.shutdown().await;
    }
    open(held.or(parsed.first().copied()), floor, allow_below_floor).await
}

/// Resumes an already-provisioned key for signing, without ever provisioning.
///
/// `weave start` uses this: it must sign with the key the relay authorised, so
/// a vanished key is an error the caller turns into "re-pair", never a silent
/// new identity. That is why the key is *confirmed* with `Describe` before it
/// is requested — `ResumeOrCreate` alone would mint a replacement when the key
/// is missing, and that replacement would be a different identity provisioned
/// at whatever the floor had become.
pub async fn resume(remembered: &str) -> Result<DeviceKey, TpmError> {
    let key_id = parse_key_id(remembered)?;

    let mut probe = connect(KeyRequest::None).await?;
    let present = probe.describe(key_id).await;
    let _ = probe.shutdown().await;
    if let Err(e) = present {
        return Err(TpmError::Refused(format!(
            "the device key {} is not in the key agent ({e})",
            short_fingerprint(remembered)
        )));
    }
    // The key exists, so this can only resume; a sealed floor keeps a race from
    // quietly provisioning below the level pairing chose.
    open(Some(key_id), SecurityLevel::Sealed, false).await
}

/// Connects to the per-user endpoint, then the system one.
///
/// The system endpoint is what a packaged install runs (`/run/tpmd/tpmd.sock`,
/// served as `tss` with TPM access), so this cannot be `connect_user`.
async fn connect(key: KeyRequest) -> Result<Client, TpmError> {
    Client::connect_candidates(NAMESPACE, key)
        .await
        .map_err(map_error)
}

/// Maps tpmd's error taxonomy onto ours, keeping the classes it insists on
/// separating (unreachable vs refused vs gone vs merely shut).
fn map_error(e: ClientError) -> TpmError {
    match &e {
        ClientError::Unavailable { .. } => TpmError::Unavailable(e.to_string()),
        ClientError::Protocol(_) => TpmError::Protocol(e.to_string()),
        ClientError::Rejected { .. } | ClientError::Request { .. } => {
            TpmError::Refused(e.to_string())
        }
        ClientError::StoreClosed { .. } => TpmError::StoreClosed(e.to_string()),
        ClientError::BackendUnavailable { .. } => TpmError::BackendUnavailable(e.to_string()),
    }
}

/// The canonical `p256:<hex>` spelling of a fingerprint.
pub fn key_id_string(key_id: KeyId) -> String {
    format!("p256:{}", key_id.to_hex())
}

/// Parses the canonical `p256:<hex>` spelling back into a fingerprint.
pub fn parse_key_id(text: &str) -> Result<KeyId, TpmError> {
    let hex = text
        .strip_prefix("p256:")
        .ok_or_else(|| TpmError::BadStoredKey(format!("'{text}' has no p256: prefix")))?;
    if hex.len() != 66 {
        return Err(TpmError::BadStoredKey(format!(
            "'{text}' is not 33 bytes of hex"
        )));
    }
    let mut bytes = [0u8; 33];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| TpmError::BadStoredKey(format!("'{text}' is not valid hex")))?;
    }
    Ok(KeyId::P256(bytes))
}

/// A fingerprint shortened for display: `p256:0271af4a…8329`.
pub fn short_fingerprint(text: &str) -> String {
    let (prefix, hex) = text.split_once(':').unwrap_or(("", text));
    if hex.len() <= 14 || !hex.is_ascii() {
        return text.to_string();
    }
    let lead = if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix}:")
    };
    format!("{lead}{}\u{2026}{}", &hex[..8], &hex[hex.len() - 4..])
}

/// Parses a `--min-key-security` value (`file`/`keyring`/`sealed`/`hardware`).
pub fn parse_level(text: &str) -> Option<SecurityLevel> {
    SecurityLevel::parse(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_string_round_trips() {
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        for (i, b) in bytes.iter_mut().enumerate().skip(1) {
            *b = i as u8;
        }
        let id = KeyId::P256(bytes);
        let text = key_id_string(id);
        assert!(text.starts_with("p256:"));
        assert_eq!(text.len(), 5 + 66);
        assert_eq!(parse_key_id(&text).unwrap(), id);
    }

    #[test]
    fn short_fingerprint_keeps_both_ends() {
        let text = format!("p256:0271af4a{}8329", "0".repeat(54));
        assert_eq!(short_fingerprint(&text), "p256:0271af4a\u{2026}8329");
        assert_eq!(short_fingerprint("p256:abcd"), "p256:abcd");
    }

    #[test]
    fn parse_key_id_rejects_junk() {
        assert!(parse_key_id("02abc").is_err());
        assert!(parse_key_id("ed25519:00").is_err());
        assert!(parse_key_id("p256:zz").is_err());
        assert!(parse_key_id(&format!("p256:{}", "0".repeat(66))).is_ok());
    }
}
