//! Core protocol constants and wire definitions for Tunnel Weaver.
//!
//! This crate defines shared protocol versioning and schema types used across
//! the `weave` client and `weaver-server` relay.

/// The current wire protocol version supported by this build.
pub const PROTOCOL_VERSION: u16 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_is_one() {
        assert_eq!(PROTOCOL_VERSION, 1);
    }
}
