//! Client-side tables.
//!
//! This is the state a machine keeps about the relays it is paired with: where
//! to dial, which machine it is there, and which key the relay authorised. It
//! holds no names the relay owns — the relay reports those when asked.

pub mod relay;
