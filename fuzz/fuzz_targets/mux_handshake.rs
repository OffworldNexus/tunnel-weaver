#![no_main]

//! Arbitrary bytes as the first frames of a handshake, on both roles.
//!
//! The server side receives the input where a HELLO belongs; the client
//! side receives it where a CHALLENGE (and then WELCOME/REJECT) belongs.
//! Neither may panic.

use libfuzzer_sys::fuzz_target;
use std::time::Instant;
mod async_util;
use async_util::block_on;
use weaver_mux::testing::{Ed25519TestSigner, MapVerifier, SeededRng};
use weaver_mux::{Config, Connection, Signer as _};

/// Feed `data` in 512-byte frames, draining output and events after each.
fn feed(conn: &mut Connection, now: Instant, data: &[u8]) {
    let mut buf = Vec::new();
    while conn.poll_transmit(&mut buf) {}
    for frame in data.chunks(512) {
        let _ = block_on(conn.recv(now, frame));
        while conn.poll_transmit(&mut buf) {}
        while conn.poll_event().is_some() {}
    }
}

fuzz_target!(|data: &[u8]| {
    let now = Instant::now();
    let signer = Ed25519TestSigner::from_seed(1);
    let verifier = MapVerifier::with_key(signer.key_id(), signer.public_key());

    // Server: emit CHALLENGE, then take the input as HELLO(s).
    let mut server = Connection::new(
        Config::server(Box::new(verifier), "fuzz.test", Box::new(SeededRng::new(2))),
        now,
    );
    feed(&mut server, now, data);

    // Client: take the input as CHALLENGE, then as WELCOME/REJECT.
    let mut client = Connection::new(
        Config::client(Box::new(signer), "fuzz.test", Box::new(SeededRng::new(1))),
        now,
    );
    feed(&mut client, now, data);
});
