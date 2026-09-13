#![no_main]

//! Arbitrary bytes as the first frames of a handshake, on both roles.
//!
//! The server side receives the input where a HELLO belongs; the client
//! side receives it where a CHALLENGE (and then WELCOME/REJECT) belongs.
//! Neither may panic.

use libfuzzer_sys::fuzz_target;
use std::time::Instant;
use weaver_mux::testing::{Ed25519TestSigner, MapVerifier, SeededRng};
use weaver_mux::{Config, Connection, Signer as _};

fuzz_target!(|data: &[u8]| {
    let now = Instant::now();
    let signer = Ed25519TestSigner::from_seed(1);
    let verifier = MapVerifier::with_key(signer.key_id(), signer.public_key());
    let mut buf = Vec::new();

    // Server: emit CHALLENGE, then take the input as HELLO(s).
    let mut server = Connection::new(
        Config::server(Box::new(verifier), "fuzz.test", Box::new(SeededRng::new(2))),
        now,
    );
    while server.poll_transmit(now, &mut buf) {}
    let mut rest = data;
    while !rest.is_empty() {
        let take = rest.len().min(512);
        let (frame, tail) = rest.split_at(take);
        rest = tail;
        let _ = server.recv(now, frame);
        while server.poll_transmit(now, &mut buf) {}
        while server.poll_event().is_some() {}
    }

    // Client: take the input as CHALLENGE, then as WELCOME/REJECT.
    let mut client = Connection::new(
        Config::client(Box::new(signer), "fuzz.test", Box::new(SeededRng::new(1))),
        now,
    );
    let mut rest = data;
    while !rest.is_empty() {
        let take = rest.len().min(512);
        let (frame, tail) = rest.split_at(take);
        rest = tail;
        let _ = client.recv(now, frame);
        while client.poll_transmit(now, &mut buf) {}
        while client.poll_event().is_some() {}
    }
});
