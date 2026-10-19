//! Control stream protocol types for service registration, revocation and
//! lifecycle.

use serde::{Deserialize, Serialize};

/// Categorized refusal reason when a control request is rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefusalCode {
    /// Service is already registered on this machine and cannot be duplicated.
    AlreadyRegistered,
    /// Service name breaks [`is_valid_service_name`].
    InvalidName,
    /// Client identity is unauthorized to register services.
    Unauthorized,
    /// The client's application protocol version is not supported by the
    /// relay. Carries the range the relay accepts.
    UnsupportedVersion {
        /// Lowest version the relay accepts.
        min: u16,
        /// Highest version the relay speaks.
        max: u16,
    },
    /// Any other refusal; the reply's `message` says why.
    Other,
}

/// First message the client sends on its control stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlHead {
    /// Register a named service on the client's machine.
    Register {
        /// Application protocol version the client speaks
        /// ([`crate::PROTOCOL_VERSION`]). Negotiated independently of the
        /// mux version: the relay refuses with
        /// [`RefusalCode::UnsupportedVersion`] if it cannot serve it.
        proto_version: u16,
        /// Name of the service to register (e.g. "web"); see
        /// [`is_valid_service_name`].
        service: String,
    },
    /// Revoke this machine: delete the key this connection authenticated with,
    /// and everything that made it reachable.
    ///
    /// No extra proof is needed or possible — the mux handshake already proved
    /// possession of the device key, which is exactly the authority to revoke
    /// it. This is how `weave unpair` makes unpairing bilateral.
    Revoke {
        /// Application protocol version the client speaks.
        proto_version: u16,
    },
}

impl ControlHead {
    /// Build a `Register` head for this build's protocol version, refusing
    /// an invalid service name. The relay applies the
    /// same check on receipt ([`ControlHead::validate`]) since the wire
    /// cannot enforce it.
    pub fn register(service: impl Into<String>) -> Result<Self, RefusalCode> {
        let service = service.into();
        if !is_valid_service_name(&service) {
            return Err(RefusalCode::InvalidName);
        }
        Ok(Self::Register {
            proto_version: crate::PROTOCOL_VERSION,
            service,
        })
    }

    /// Build a `Revoke` head for this build's protocol version.
    pub fn revoke() -> Self {
        Self::Revoke {
            proto_version: crate::PROTOCOL_VERSION,
        }
    }

    /// Relay-side check of a decoded head: protocol version in range, and —
    /// for [`ControlHead::Register`] — the service name well-formed.
    pub fn validate(&self) -> Result<(), RefusalCode> {
        match self {
            Self::Register {
                proto_version,
                service,
            } => {
                crate::accept_protocol_version(*proto_version)?;
                if !is_valid_service_name(service) {
                    return Err(RefusalCode::InvalidName);
                }
                Ok(())
            }
            Self::Revoke { proto_version } => crate::accept_protocol_version(*proto_version),
        }
    }
}

/// Longest service name: what is left of a 63-byte DNS label once the person
/// and machine (up to 15 bytes each) and their two dashes are in front of it.
pub const SERVICE_NAME_MAX: usize = 31;

/// The one service-name rule, checked by the client before sending and by the
/// relay on receipt: `^[a-z0-9]+(-[a-z0-9]+)*$`, 1 to [`SERVICE_NAME_MAX`]
/// bytes.
///
/// The service is the tail of the flat hostname `<person>-<machine>-<service>`,
/// which is split at its first two dashes; leading, trailing or doubled dashes
/// and uppercase are refused so every name maps to exactly one hostname.
pub fn is_valid_service_name(name: &str) -> bool {
    name.len() <= SERVICE_NAME_MAX
        && name.split('-').all(|run| {
            !run.is_empty()
                && run
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_name_validation() {
        assert!(is_valid_service_name("web"));
        assert!(is_valid_service_name("api-1"));
        assert!(is_valid_service_name("a-b-c-1"));
        assert!(is_valid_service_name("a"));
        assert!(is_valid_service_name(&"a".repeat(31)));
        assert!(!is_valid_service_name(""));
        assert!(!is_valid_service_name("-leading"));
        assert!(!is_valid_service_name("trailing-"));
        assert!(!is_valid_service_name("a--b"));
        assert!(!is_valid_service_name("Web"));
        assert!(!is_valid_service_name("with.dot"));
        assert!(!is_valid_service_name("with_underscore"));
        assert!(!is_valid_service_name(&"a".repeat(32)));
    }

    #[test]
    fn register_validates_both_ends() {
        assert_eq!(
            ControlHead::register("with.dot"),
            Err(RefusalCode::InvalidName)
        );
        let head = ControlHead::register("web").unwrap();
        assert_eq!(head.validate(), Ok(()));
        let stale = ControlHead::Register {
            proto_version: 0,
            service: "web".into(),
        };
        assert!(matches!(
            stale.validate(),
            Err(RefusalCode::UnsupportedVersion { .. })
        ));
    }
}

/// Control stream messages sent by the relay on the same stream.
///
/// `Registered` or `Refused` is always the first reply. While the lease is
/// open the relay may then push any number of [`ControlReply::CertState`]
/// notices as the hostname's certificate moves through its lifecycle, so the
/// client can show a live indicator without polling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlReply {
    /// Service registration succeeded.
    Registered {
        /// Fully-qualified hostname assigned to the registered service.
        hostname: String,
    },
    /// Service registration was refused.
    Refused {
        /// Categorized refusal code.
        code: RefusalCode,
        /// Human-readable explanation.
        message: String,
    },
    /// The certificate for the registered hostname changed state.
    CertState {
        /// Current state.
        state: CertStatus,
    },
    /// The machine was revoked: its key, services and hostnames are gone, and
    /// the relay closes the connection.
    Revoked,
}

/// Certificate lifecycle as seen by the client. Mirrors the relay's cert
/// manager states without exposing timestamps or error internals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertStatus {
    /// Not yet ordered.
    Pending,
    /// ACME order in flight; visitors are held at the TLS layer.
    Ordering,
    /// Valid certificate being served.
    Issued,
    /// Valid certificate being served while a renewal runs.
    Renewing,
    /// Order failed; the relay will retry, visitors are refused.
    Failed,
}

impl CertStatus {
    /// Short lowercase label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ordering => "ordering",
            Self::Issued => "issued",
            Self::Renewing => "renewing",
            Self::Failed => "failed",
        }
    }

    /// Whether visitors can currently reach the service over TLS.
    pub fn is_serving(self) -> bool {
        matches!(self, Self::Issued | Self::Renewing)
    }
}
