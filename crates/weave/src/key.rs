//! The machine's device key, as the rest of the crate sees it.
//!
//! `weave` never holds a private key: a [`KeyAgent`] opens the one device key
//! and hands back a mux [`Signer`]. Production uses tpmd ([`crate::tpm`]);
//! tests inject an in-memory agent.

use std::sync::Arc;

use weaver_mux::KeyId;
use weaver_mux::auth::Signer;

use crate::report::Reporter;

pub use tpmd_client::SecurityLevel;

/// How a key may be created when the agent no longer holds the remembered one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provision {
    /// The minimum protection level.
    pub floor: SecurityLevel,
    /// Consent to create the key below `floor` when the machine cannot reach it.
    pub allow_below_floor: bool,
}

impl Default for Provision {
    fn default() -> Self {
        Self {
            floor: SecurityLevel::Sealed,
            allow_below_floor: false,
        }
    }
}

/// The opened device key.
pub struct OpenedKey {
    /// Signs the mux handshake; its `key_id` is the key's fingerprint.
    pub signer: Box<dyn Signer + Send>,
    /// The protection level the agent achieved for the key.
    pub level: SecurityLevel,
    /// The agent created the key instead of resuming the remembered one.
    pub created: bool,
}

/// Why the device key could not be opened.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// The key agent is not running or not installed.
    #[error("the key agent is not available: {0}")]
    Unavailable(String),
    /// Creating the key needs consent to go below the floor.
    #[error(
        "this machine's strongest key store is '{available}', below the requested '{required}'"
    )]
    BelowFloor {
        /// The requested floor.
        required: SecurityLevel,
        /// The strongest level the machine offers.
        available: SecurityLevel,
    },
    /// Any other refusal from the agent.
    #[error("the key agent refused: {0}")]
    Refused(String),
}

/// Holds the device key and signs with it.
#[async_trait::async_trait]
pub trait KeyAgent: Send + Sync {
    /// Resumes `remembered` if the agent still holds it, else creates a key
    /// under `provision`. Waits (through `reporter`) while the agent's store is
    /// locked.
    async fn open(
        &self,
        remembered: Option<KeyId>,
        provision: Provision,
        reporter: Arc<dyn Reporter>,
    ) -> Result<OpenedKey, KeyError>;
}
