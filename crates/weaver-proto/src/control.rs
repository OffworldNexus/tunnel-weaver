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
        /// Name of the service to register (e.g. "web").
        service: String,
    },
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
