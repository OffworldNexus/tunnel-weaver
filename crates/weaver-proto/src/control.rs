//! Control stream protocol types for service registration and lifecycle.

use serde::{Deserialize, Serialize};

/// Categorized refusal reason when a control request is rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefusalCode {
    /// Service is already registered on this machine and cannot be duplicated.
    AlreadyRegistered,
    /// Service name is not a valid DNS label.
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
    /// Other application-defined refusal reason.
    Other(String),
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
        /// Name of the service to register (e.g. "web"). A single DNS
        /// label; see [`ControlHead::register`] and [`is_valid_dns_label`].
        service: String,
    },
}

impl ControlHead {
    /// Build a `Register` head for this build's protocol version, refusing
    /// a service name that is not a valid DNS label. The relay applies the
    /// same check on receipt ([`ControlHead::validate`]) since the wire
    /// cannot enforce it.
    pub fn register(service: impl Into<String>) -> Result<Self, RefusalCode> {
        let service = service.into();
        if !is_valid_dns_label(&service) {
            return Err(RefusalCode::InvalidName);
        }
        Ok(Self::Register {
            proto_version: crate::PROTOCOL_VERSION,
            service,
        })
    }

    /// Relay-side check of a decoded head: protocol version in range and
    /// service name well-formed.
    pub fn validate(&self) -> Result<(), RefusalCode> {
        match self {
            Self::Register {
                proto_version,
                service,
            } => {
                crate::accept_protocol_version(*proto_version)?;
                if !is_valid_dns_label(service) {
                    return Err(RefusalCode::InvalidName);
                }
                Ok(())
            }
        }
    }
}

/// A valid service name is a single DNS label of at most 63 characters
/// (RFC 1035 / RFC 1123): ASCII alphanumerics and hyphens, not starting or
/// ending with a hyphen.
pub fn is_valid_dns_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 {
        return false;
    }
    if label.starts_with('-') || label.ends_with('-') {
        return false;
    }
    label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_label_validation() {
        assert!(is_valid_dns_label("web"));
        assert!(is_valid_dns_label("api-1"));
        assert!(is_valid_dns_label("a"));
        assert!(!is_valid_dns_label(""));
        assert!(!is_valid_dns_label("-leading"));
        assert!(!is_valid_dns_label("trailing-"));
        assert!(!is_valid_dns_label("with.dot"));
        assert!(!is_valid_dns_label("with_underscore"));
        assert!(!is_valid_dns_label(&"a".repeat(64)));
        assert!(is_valid_dns_label(&"a".repeat(63)));
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

/// Control stream response sent by the relay on the same stream.
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
}
