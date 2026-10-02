use serde::{Deserialize, Serialize};

use crate::cert::CertState;

/// Envelope for client requests sent across the control socket.
///
/// All requests require `v: 1` and one of the seven valid command verbs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlRequest {
    /// Protocol version envelope; must be 1.
    pub v: u32,
    /// Command verb ("status", "cert.status", "cert.wait", "cert.renew", "usage", "backup", "shutdown").
    pub cmd: String,
    /// Target domain or hostname for certificate operations.
    #[serde(default)]
    pub name: Option<String>,
    /// Limit for event history queries.
    #[serde(default)]
    pub limit: Option<usize>,
    /// Timeout in seconds for streaming wait commands.
    #[serde(default)]
    pub timeout_s: Option<u64>,
    /// Flag to indicate an operation applies to all active hostnames + root.
    #[serde(default)]
    pub all: Option<bool>,
    /// Flag to force renewal bypassing rate limits and concurrency caps.
    #[serde(default)]
    pub force: Option<bool>,
    /// Target path for backup operations.
    #[serde(default)]
    pub path: Option<String>,
    /// Flag to disable filtering to only the best certificate per domain.
    #[serde(default)]
    pub no_only_best: Option<bool>,
    /// Usage query: filter to a person's name.
    #[serde(default)]
    pub person: Option<String>,
    /// Usage query: filter to a service name.
    #[serde(default)]
    pub service: Option<String>,
    /// Usage query: lower bound, absolute Unix seconds (inclusive).
    #[serde(default)]
    pub since: Option<i64>,
    /// Usage query: upper bound, absolute Unix seconds (exclusive).
    #[serde(default)]
    pub until: Option<i64>,
}

/// Generic error response returned when a command fails or validation rejects the request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorResponse {
    pub ok: bool,
    pub error: String,
}

impl ErrorResponse {
    /// Creates a new error response envelope.
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: error.into(),
        }
    }
}

/// Bound listener socket information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListenersInfo {
    pub http: String,
    pub https: String,
}

/// Per-name certificate counts partitioned mutually exclusively.
///
/// Inactive hostnames count under `inactive`; active hostnames partition
/// into `issued`, `ordering`, and `failed`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CertCounts {
    pub issued: usize,
    pub ordering: usize,
    pub failed: usize,
    pub inactive: usize,
}

/// Response payload for the `status` command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusResponse {
    pub ok: bool,
    pub version: String,
    pub uptime: u64,
    pub pid: u32,
    pub root_domain: String,
    pub listeners: ListenersInfo,
    pub root_cert: String,
    pub cert_counts: CertCounts,
    pub db_path: String,
    pub db_size: u64,
    pub schema_version: u32,
    #[serde(default)]
    pub control_socket: String,
}

/// Historical certificate lifecycle event record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertEventSummary {
    pub id: i64,
    pub at: i64,
    pub kind: String,
    pub detail: Option<String>,
}

/// Summary representation of a certificate in the summary list view.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertSummary {
    pub name: String,
    pub state: String,
    pub not_after: Option<i64>,
    pub active: bool,
    pub last_event: Option<CertEventSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_id: Option<i32>,
}

/// Response payload for `cert.status` without a hostname.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertListResponse {
    pub ok: bool,
    pub certificates: Vec<CertSummary>,
}

/// Response payload for `cert.status` with a specific hostname or certificate ID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertDetailResponse {
    pub ok: bool,
    pub name: String,
    pub state: CertState,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    pub issuer: Option<String>,
    pub provider: String,
    pub active: bool,
    pub last_active_at: Option<i64>,
    pub cert_events: Vec<CertEventSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_id: Option<i32>,
}

/// Individual streamed event for `cert.wait`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertWaitEvent {
    pub ok: bool,
    pub name: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Response payload for `cert.renew`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RenewResponse {
    pub ok: bool,
    pub renewed: Vec<String>,
    pub status: String,
    pub skipped_inactive: Vec<String>,
}

/// Response payload for `backup`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupResponse {
    pub ok: bool,
    pub path: String,
    pub size: u64,
}

/// Response payload for `shutdown`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShutdownResponse {
    pub ok: bool,
    pub message: String,
}

/// One service's aggregated usage over the queried window.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageService {
    pub service_id: i32,
    pub service: String,
    pub machine: String,
    pub person: String,
    pub bytes_in: i64,
    pub bytes_out: i64,
    /// Tunnel-leg compressed bytes: `client -> relay` and `relay -> client`.
    pub tunnel_in: i64,
    pub tunnel_out: i64,
    /// Milliseconds the service was registered across the window. The store's
    /// inverted `unused_ms` storage never appears on the wire.
    pub open_ms: i64,
    pub requests: i64,
    pub covered_minutes: i64,
}

/// Response payload for `usage`: per-service totals, ordered by service name.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageResponse {
    pub ok: bool,
    pub services: Vec<UsageService>,
}
