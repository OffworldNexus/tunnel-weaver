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
    /// Other application-defined refusal reason.
    Other(String),
}

/// Control stream head sent by the client when opening stream 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlHead {
    /// Register a named service on the client's machine.
    Register {
        /// Name of the service to register (e.g. "web").
        service: String,
    },
}

/// Control stream response sent by the relay across stream 1.
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
