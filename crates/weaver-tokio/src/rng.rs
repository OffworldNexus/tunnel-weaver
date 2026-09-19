//! OS-backed randomness for the mux's handshake nonces.

use std::convert::Infallible;

use rand::RngCore as _;
use rand_core::TryRng;

/// `rand_core::TryRng` over the operating system's CSPRNG. Infallible.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemRng;

impl TryRng for SystemRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(rand::rng().next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(rand::rng().next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        rand::rng().fill_bytes(dst);
        Ok(())
    }
}
