#![no_main]

//! Feed arbitrary frames into an authenticated server `Connection`.
//!
//! The input is split into length-prefixed messages (u16 BE) so the fuzzer
//! can explore multi-frame sequences. Every `recv` may fail with a
//! `ProtocolError` — that is the contract — but nothing may panic, and the
//! connection must keep answering API calls afterwards.

use libfuzzer_sys::fuzz_target;
use std::time::{Duration, Instant};
use weaver_mux::testing::{Ed25519TestSigner, MapVerifier, SeededRng};
use weaver_mux::{Compress, Config, Connection, Signer as _, StreamPolicy};

fn authenticated_pair() -> (Connection, Connection, Instant) {
    let signer = Ed25519TestSigner::from_seed(1);
    let verifier = MapVerifier::with_key(signer.key_id(), signer.public_key());
    let now = Instant::now();
    let mut client = Connection::new(
        Config::client(Box::new(signer), "fuzz.test", Box::new(SeededRng::new(1))),
        now,
    );
    let mut server = Connection::new(
        Config::server(Box::new(verifier), "fuzz.test", Box::new(SeededRng::new(2))),
        now,
    );
    let mut buf = Vec::new();
    for _ in 0..4 {
        while server.poll_transmit(now, &mut buf) {
            let _ = client.recv(now, &buf);
        }
        while client.poll_transmit(now, &mut buf) {
            let _ = server.recv(now, &buf);
        }
    }
    assert_eq!(server.version(), Some(1));
    (client, server, now)
}

fuzz_target!(|data: &[u8]| {
    let (mut client, mut server, mut now) = authenticated_pair();
    // A stream the peer legitimately opened, so DATA/FIN/RST on id 1 hit
    // real state rather than the "unknown id" fast path.
    let id = client.open(StreamPolicy::default()).unwrap();
    let _ = client.send(id, b"seed", Compress::Auto);
    let mut buf = Vec::new();
    while client.poll_transmit(now, &mut buf) {
        let _ = server.recv(now, &buf);
    }

    let mut rest = data;
    while rest.len() >= 2 {
        let len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        rest = &rest[2..];
        let take = len.min(rest.len());
        let (frame, tail) = rest.split_at(take);
        rest = tail;
        now += Duration::from_millis(1);
        let _ = server.recv(now, frame);
        server.handle_timeout(now);
        while server.poll_transmit(now, &mut buf) {}
        while server.poll_event().is_some() {}
        while server.recv_msg(id).is_ok() {}
        let _ = server.send(id, b"echo", Compress::Auto);
        if server.is_closed() {
            break;
        }
    }
});
