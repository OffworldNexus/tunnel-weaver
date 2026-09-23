//! Stream reset codes for mid-body origin failure.
//!
//! `weaver-mux` only knows an opaque `u32` reset code on
//! [`weaver_mux::Connection::reset`]; this module is the application-level
//! taxonomy the `weave` client puts into that field so the relay can map a
//! broken origin exchange to the right visitor-side failure. The numeric
//! values are part of the wire contract and are frozen by ADR 0006.

use serde::{Deserialize, Serialize};

/// Why a visitor stream was reset before its exchange completed.
///
/// Codes are chosen so a non-zero value is easy to trace in a packet
/// capture: they mirror the HTTP status family (5 = server-side origin
/// failure) plus a client-cancellation code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum ResetCode {
    /// The target refused the connection or never answered before the
    /// response head: the relay answers the visitor 502.
    OriginUnreachable = 1,
    /// The origin closed the connection mid-body: the relay truncates an
    /// h1 response or sends `RST_STREAM` on h2.
    OriginClosed = 2,
    /// The visitor or client cancelled (Ctrl-C, visitor disconnect): the
    /// relay drops the exchange without an error response.
    Cancelled = 3,
}

impl ResetCode {
    /// The `u32` carried on the mux reset frame.
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Decode a mux reset code, if it is one this build knows.
    pub const fn from_u32(code: u32) -> Option<Self> {
        match code {
            1 => Some(Self::OriginUnreachable),
            2 => Some(Self::OriginClosed),
            3 => Some(Self::Cancelled),
            _ => None,
        }
    }
}

impl From<ResetCode> for u32 {
    fn from(code: ResetCode) -> Self {
        code.as_u32()
    }
}
