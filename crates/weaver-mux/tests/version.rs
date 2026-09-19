mod common;

use common::*;
use weaver_mux::testing::Ed25519TestSigner;
use weaver_mux::wire::{self, Challenge, Hello};
use weaver_mux::{Event, Frame, FrameType, RejectCode, Signer as _, auth};

/// Drive a server through CHALLENGE, then hand-craft a HELLO advertising
/// `client_max` and return the server's answer.
fn hello_with_version(client_max: u16) -> (Frame, Pair) {
    let mut p = Pair::default_pair();
    let now = p.clock.now();
    let mut buf = Vec::new();
    assert!(p.server.poll_transmit(now, &mut buf));
    let challenge = Frame::parse(&buf).unwrap();
    let ch: Challenge = wire::decode_payload(FrameType::Challenge, &challenge.payload).unwrap();

    let mut signer = Ed25519TestSigner::from_seed(1);
    let nonce_c = [0x42; 32];
    let msg = auth::transcript(&ch.nonce_s, &nonce_c, SERVER_NAME, None);
    let hello = Hello {
        version: client_max,
        key_id: signer.key_id(),
        nonce_c,
        sig: signer.sign(&msg).unwrap(),
    };
    let frame = Frame {
        stream_id: 0,
        frame_type: FrameType::Hello,
        payload: wire::encode_payload(&hello),
    };
    p.server.recv(now, &frame.encode()).unwrap();
    assert!(p.server.poll_transmit(now, &mut buf));
    (Frame::parse(&buf).unwrap(), p)
}

#[test]
fn matching_version_negotiates_v1() {
    let (reply, mut p) = hello_with_version(1);
    assert_eq!(reply.frame_type, FrameType::Welcome);
    let w: wire::Welcome = wire::decode_payload(FrameType::Welcome, &reply.payload).unwrap();
    assert_eq!(w.version, 1);
    assert_eq!(p.server.version(), Some(1));
    assert!(matches!(
        p.server_event(),
        Some(Event::Authenticated { version: 1, .. })
    ));
}

#[test]
fn future_client_falls_back_to_v1() {
    let (reply, p) = hello_with_version(2);
    assert_eq!(reply.frame_type, FrameType::Welcome);
    let w: wire::Welcome = wire::decode_payload(FrameType::Welcome, &reply.payload).unwrap();
    assert_eq!(w.version, 1);
    assert_eq!(p.server.version(), Some(1));
}

#[test]
fn too_old_client_is_rejected_with_range() {
    let (reply, p) = hello_with_version(0);
    assert_eq!(reply.frame_type, FrameType::Reject);
    let r: wire::Reject = wire::decode_payload(FrameType::Reject, &reply.payload).unwrap();
    assert_eq!(r.code, RejectCode::UnsupportedVersion { min: 1, max: 1 });
    assert!(p.server.is_closed());
    assert_eq!(p.server.version(), None);
}

#[test]
fn negotiated_version_visible_on_both_sides() {
    let mut p = Pair::default_pair();
    p.pump();
    assert_eq!(p.client.version(), Some(1));
    assert_eq!(p.server.version(), Some(1));
    assert!(matches!(
        p.client_event(),
        Some(Event::Authenticated { version: 1, .. })
    ));
}
