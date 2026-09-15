use serde::{Deserialize, Serialize};

/// Per-hostname certificate lifecycle state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CertState {
    /// Certificate order has not started or is queued.
    Pending,
    /// ACME order is currently in progress.
    Ordering,
    /// Certificate has been issued and is valid until `not_after`.
    Issued { not_after: i64 },
    /// Certificate order or renewal failed; retry scheduled at `next_retry`.
    Failed { error: String, next_retry: i64 },
    /// Active certificate is being renewed in background; existing cert valid until `not_after`.
    Renewing { not_after: i64 },
}

impl CertState {
    /// Returns true if a valid certificate is currently available for serving.
    pub fn is_issued(&self) -> bool {
        matches!(self, CertState::Issued { .. } | CertState::Renewing { .. })
    }

    /// Returns the certificate expiration timestamp if one is currently held.
    pub fn not_after(&self) -> Option<i64> {
        match self {
            CertState::Issued { not_after } | CertState::Renewing { not_after } => Some(*not_after),
            _ => None,
        }
    }

    /// Short label suitable for logs and systemd status string.
    pub fn label(&self) -> &'static str {
        match self {
            CertState::Pending => "pending",
            CertState::Ordering => "ordering",
            CertState::Issued { .. } => "issued",
            CertState::Failed { .. } => "failed",
            CertState::Renewing { .. } => "renewing",
        }
    }
}
