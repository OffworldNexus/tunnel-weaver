//! Schema for pairing a machine to a relay.
//!
//! Two transports share these types:
//!
//! * **The pairing channel** — a WebSocket the CLI opens to the relay's admin
//!   host. The relay speaks first with a proof-of-work [`ServerMessage::Challenge`];
//!   the CLI answers with one [`Begin`] carrying the solved proof, the machine's
//!   public key and its target; the relay answers with a
//!   [`ServerMessage::Handle`], then exactly one outcome once a person acts in
//!   the browser.
//! * **The browser API** — three JSON `POST`s (`lookup`, `accept`, `reject`)
//!   that resolve the pending pairing the handle names.
//!
//! The model behind it: a machine belongs to exactly one person and holds
//! exactly one key, and the key alone identifies the machine. Pairing either
//! creates a machine for a key, or moves an existing machine onto a new key
//! (the old one was lost). There is nothing else to express.
//!
//! Nothing here is postcard: these messages travel as JSON text, because the
//! WebSocket is a plain one on the admin host and the browser API is JSON
//! already. The handle is a capability: it is never part of a URL path or
//! query, only of the link's fragment (CLI side) and a JSON body (browser side).

use serde::{Deserialize, Serialize};
use weaver_abuse::altcha::{Challenge, Payload};
use weaver_mux::KeyId;

/// The WebSocket subprotocol a pairing channel is opened with.
pub const PAIR_SUBPROTOCOL: &str = "weaver-pair-v1";

/// The admin-host path the pairing channel is opened on.
pub const PAIR_CHANNEL_PATH: &str = "/api/account/pair/channel";

/// `POST` — resolve a handle without consuming it.
pub const PAIR_LOOKUP_PATH: &str = "/api/account/pair/lookup";
/// `POST` — approve the pending pairing.
pub const PAIR_ACCEPT_PATH: &str = "/api/account/pair/accept";
/// `POST` — reject the pending pairing.
pub const PAIR_REJECT_PATH: &str = "/api/account/pair/reject";

/// The ALTCHA purpose (and flow) a pairing proof is bound to.
pub const PAIR_POW_PURPOSE: &str = "pair";

/// Which machine the key is for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    /// A new machine; the relay proposes its name from `hostname`.
    New {
        /// The machine's raw hostname, as the OS reports it.
        hostname: String,
    },
    /// An existing machine whose key was lost: the machine — its name and
    /// hostnames — moves onto this key, and the old key stops working.
    Existing {
        /// The machine's id, as reported by [`ServerMessage::Approved`].
        machine_id: i32,
    },
}

/// The CLI's only message on the pairing channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Begin {
    /// The solved [`ServerMessage::Challenge`] this channel was issued.
    pub proof: Payload,
    /// The machine's public key fingerprint (SEC1-compressed P-256).
    pub key_id: KeyId,
    /// Which machine the key is for.
    pub target: Target,
}

/// What the relay sends down the pairing channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// First message on every channel: the proof of work [`Begin`] must carry.
    Challenge {
        /// The signed ALTCHA challenge.
        challenge: Challenge,
    },
    /// The pending pairing is open; the printed link carries this handle.
    Handle {
        /// 32 bytes of randomness, lowercase hex.
        handle: String,
    },
    /// A person approved. Only `machine_id` is for keeping; the names are for
    /// the one line the terminal prints.
    Approved {
        /// The machine's id on this relay.
        machine_id: i32,
        /// The person's slug.
        person: String,
        /// The machine's name.
        machine: String,
    },
    /// The pairing ended without approval. Terminal; the channel closes next.
    Failed {
        /// Why, for the CLI to act on.
        code: FailureCode,
        /// Human-readable detail.
        message: String,
    },
}

/// Why a pairing ended without approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    /// The proof of work was missing, wrong, expired or already used.
    BadProof,
    /// The key is malformed or uses an unsupported algorithm.
    BadKey,
    /// The key already belongs to a machine; there is nothing to pair.
    AlreadyPaired,
    /// The message could not be understood.
    BadRequest,
    /// Too many pairing requests from this source.
    Throttled,
    /// The relay cannot open a pending pairing right now.
    Unavailable,
    /// A person looked at the request and rejected it.
    Rejected,
    /// The request targets a machine that does not belong to the account that
    /// opened the link (or does not exist).
    NotYourMachine,
}

/// Body of [`PAIR_LOOKUP_PATH`], [`PAIR_REJECT_PATH`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleRequest {
    /// The handle from the link's fragment.
    pub handle: String,
}

/// A name shown at the confirmation, and whether the person may still choose it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposed {
    /// The name.
    pub name: String,
    /// `true` when approving creates it — then the name is a proposal the
    /// person may edit. `false` when it already exists and is fixed.
    pub is_new: bool,
}

/// Answer to [`PAIR_LOOKUP_PATH`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LookupResponse {
    /// The pending pairing is live; show the confirmation.
    Waiting {
        /// The key fingerprint to display (`p256:<hex>`).
        fingerprint: String,
        /// The account that will approve, so the person sees whose session it is.
        account: String,
        /// The person the machine belongs to.
        person: Proposed,
        /// The machine.
        machine: Proposed,
    },
    /// The request targets a machine that is not this account's. Only
    /// rejecting is possible.
    NotYourMachine,
    /// No pending pairing with this handle — it died with the CLI's channel,
    /// or the relay restarted.
    Gone,
}

/// Body of [`PAIR_ACCEPT_PATH`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptRequest {
    /// The handle from the link's fragment.
    pub handle: String,
    /// The person slug to create; only when the lookup said `person.is_new`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person_slug: Option<String>,
    /// The machine name to create; only when the lookup said `machine.is_new`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_name: Option<String>,
}

/// Answer to accept/reject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionResponse {
    /// Whether the action was applied.
    pub ok: bool,
    /// On failure, why — safe to show the person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Encode a pairing message as JSON text.
pub fn encode_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    serde_json::to_string(value)
}

/// Decode a pairing message from JSON text.
pub fn decode_json<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, serde_json::Error> {
    serde_json::from_str(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_are_tagged() {
        let new = Target::New {
            hostname: "Rémys-MacBook-Pro.local".into(),
        };
        let text = encode_json(&new).unwrap();
        assert!(text.contains("\"kind\":\"new\""));
        assert_eq!(decode_json::<Target>(&text).unwrap(), new);

        let existing = Target::Existing { machine_id: 42 };
        let text = encode_json(&existing).unwrap();
        assert_eq!(text, "{\"kind\":\"existing\",\"machine_id\":42}");
        assert_eq!(decode_json::<Target>(&text).unwrap(), existing);
    }

    #[test]
    fn server_messages_are_tagged() {
        let approved = ServerMessage::Approved {
            machine_id: 3,
            person: "remy".into(),
            machine: "laptop".into(),
        };
        let text = encode_json(&approved).unwrap();
        assert!(text.contains("\"type\":\"approved\""));
        assert_eq!(decode_json::<ServerMessage>(&text).unwrap(), approved);

        let failed = ServerMessage::Failed {
            code: FailureCode::NotYourMachine,
            message: "no".into(),
        };
        let text = encode_json(&failed).unwrap();
        assert!(text.contains("\"code\":\"not_your_machine\""));
        assert_eq!(decode_json::<ServerMessage>(&text).unwrap(), failed);
    }

    #[test]
    fn accept_omits_fixed_names() {
        let accept = AcceptRequest {
            handle: "ab".into(),
            person_slug: None,
            machine_name: Some("laptop".into()),
        };
        let text = encode_json(&accept).unwrap();
        assert_eq!(text, "{\"handle\":\"ab\",\"machine_name\":\"laptop\"}");
        assert_eq!(decode_json::<AcceptRequest>(&text).unwrap(), accept);
    }

    #[test]
    fn lookup_response_is_tagged() {
        assert_eq!(
            encode_json(&LookupResponse::Gone).unwrap(),
            "{\"state\":\"gone\"}"
        );
        assert_eq!(
            encode_json(&LookupResponse::NotYourMachine).unwrap(),
            "{\"state\":\"not_your_machine\"}"
        );
        let waiting = LookupResponse::Waiting {
            fingerprint: "p256:02abc".into(),
            account: "remy@example.com".into(),
            person: Proposed {
                name: "remy".into(),
                is_new: false,
            },
            machine: Proposed {
                name: "laptop".into(),
                is_new: true,
            },
        };
        let text = encode_json(&waiting).unwrap();
        assert_eq!(decode_json::<LookupResponse>(&text).unwrap(), waiting);
    }
}
