//! Handshake state and version negotiation.
//!
//! The frame handling itself lives in [`crate::connection`] because it
//! needs the whole connection (rng, signer/verifier, timers, event queue);
//! this module only holds the pieces that are pure.

use crate::error::RejectCode;
use crate::wire::{MAX_VERSION, MIN_VERSION};

/// Where the connection is in the CHALLENGE → HELLO → WELCOME exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Client: waiting for the server's CHALLENGE.
    AwaitChallenge,
    /// Server: CHALLENGE queued, waiting for HELLO.
    ChallengeSent,
    /// Client: HELLO queued, waiting for WELCOME or REJECT.
    HelloSent,
    /// Both: authenticated, streams allowed.
    Done,
}

/// Server-side version negotiation: the highest version both sides speak,
/// or the reject code telling the client the range we accept.
pub fn negotiate(client_max: u16) -> Result<u16, RejectCode> {
    if client_max < MIN_VERSION {
        Err(RejectCode::UnsupportedVersion {
            min: MIN_VERSION,
            max: MAX_VERSION,
        })
    } else {
        Ok(client_max.min(MAX_VERSION))
    }
}

/// Client-side check of the version the server picked: it must be one we
/// speak and no higher than what we offered.
pub fn accept_version(offered: u16, chosen: u16) -> bool {
    (MIN_VERSION..=MAX_VERSION).contains(&chosen) && chosen <= offered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation() {
        assert_eq!(negotiate(2), Ok(2));
        assert_eq!(negotiate(3), Ok(2), "future client falls back to ours");
        assert_eq!(
            negotiate(1),
            Err(RejectCode::UnsupportedVersion { min: 2, max: 2 })
        );
        assert!(accept_version(2, 2));
        assert!(!accept_version(2, 3), "server cannot pick above our offer");
        assert!(!accept_version(3, 1));
    }
}
