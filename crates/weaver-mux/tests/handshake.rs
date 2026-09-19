mod common;

use std::time::Duration;

use common::*;
use weaver_mux::testing::{
    Ed25519TestSigner, FailingSigner, MapVerifier, P256TestSigner, SeededRng,
};
use weaver_mux::{
    Class, CloseCode, Config, Event, Frame, FrameType, ProtocolError, RejectCode, Signer as _,
    StreamError,
};

#[test]
fn happy_path_ed25519() {
    let mut p = Pair::default_pair();
    assert!(p.client.version().is_none());
    p.pump();
    let key = Ed25519TestSigner::from_seed(1).key_id();
    assert_eq!(
        p.client_event(),
        Some(Event::Authenticated {
            key_id: key,
            version: 1
        })
    );
    assert_eq!(
        p.server_event(),
        Some(Event::Authenticated {
            key_id: key,
            version: 1
        })
    );
    assert_eq!(p.client.version(), Some(1));
    assert_eq!(p.server.version(), Some(1));
    let types: Vec<_> = p.log.iter().map(|(s, f)| (*s, f.frame_type)).collect();
    assert_eq!(
        types,
        vec![
            (Side::Server, FrameType::Challenge),
            (Side::Client, FrameType::Hello),
            (Side::Server, FrameType::Welcome),
        ]
    );
}

#[test]
fn happy_path_p256() {
    let signer = P256TestSigner::from_seed(3);
    let verifier = MapVerifier::with_key(signer.key_id(), signer.public_key());
    let key = signer.key_id();
    let client = Config::client(Box::new(signer), SERVER_NAME, Box::new(SeededRng::new(1)));
    let server = Config::server(Box::new(verifier), SERVER_NAME, Box::new(SeededRng::new(2)));
    let mut p = Pair::new(client, server);
    p.pump();
    assert_eq!(
        p.server_event(),
        Some(Event::Authenticated {
            key_id: key,
            version: 1
        })
    );
}

#[test]
fn unknown_key_is_rejected() {
    // Server knows seed 1, client signs with seed 2.
    let mut p = Pair::new(client_config(2), server_config(1));
    p.pump();
    assert_eq!(p.frames_of(Side::Server, FrameType::Reject).len(), 1);
    assert!(matches!(
        p.client_event(),
        Some(Event::Rejected {
            code: RejectCode::UnknownKey,
            ..
        })
    ));
    assert!(matches!(
        p.client_event(),
        Some(Event::Closed { reason }) if reason.code == CloseCode::Rejected
    ));
    assert!(matches!(
        p.server_event(),
        Some(Event::Closed { reason }) if reason.code == CloseCode::Rejected
    ));
    assert!(p.client.is_closed() && p.server.is_closed());
    assert_eq!(p.client.open(Class::Interactive), Err(StreamError::Closed));
}

#[test]
fn wrong_signature_is_rejected() {
    // Server maps seed-1's key id to seed-2's public key: the id is known,
    // but the signature will not verify.
    let good = Ed25519TestSigner::from_seed(1);
    let bad = Ed25519TestSigner::from_seed(2);
    let verifier = MapVerifier::with_key(good.key_id(), bad.public_key());
    let server = Config::server(Box::new(verifier), SERVER_NAME, Box::new(SeededRng::new(9)));
    let mut p = Pair::new(client_config(1), server);
    p.pump();
    assert!(matches!(
        p.client_event(),
        Some(Event::Rejected {
            code: RejectCode::BadSignature,
            ..
        })
    ));
}

#[test]
fn hello_for_another_server_name_is_rejected() {
    let mut client = client_config(1);
    client.server_name = "other.example.test".into();
    let mut p = Pair::new(client, server_config(1));
    p.pump();
    assert!(matches!(
        p.client_event(),
        Some(Event::Rejected {
            code: RejectCode::BadSignature,
            ..
        })
    ));
}

#[test]
fn channel_binding_mismatch_is_rejected() {
    let mut client = client_config(1);
    client.channel_binding = Some([1; 32]);
    let mut server = server_config(1);
    server.channel_binding = Some([2; 32]);
    let mut p = Pair::new(client, server);
    p.pump();
    assert!(matches!(
        p.client_event(),
        Some(Event::Rejected {
            code: RejectCode::BadSignature,
            ..
        })
    ));

    let mut client = client_config(1);
    client.channel_binding = Some([1; 32]);
    let mut server = server_config(1);
    server.channel_binding = Some([1; 32]);
    let mut p = Pair::new(client, server);
    p.pump();
    assert!(matches!(
        p.client_event(),
        Some(Event::Authenticated { .. })
    ));
}

#[test]
fn replayed_hello_is_rejected() {
    // Capture a valid HELLO from one connection...
    let mut p = Pair::default_pair();
    p.pump();
    let hello = p.frames_of(Side::Client, FrameType::Hello)[0].clone();
    // ...and replay it against a fresh server. Its RNG is seeded
    // differently so it draws a different nonce_s, as a real server would.
    let mut server = server_config(1);
    server.rng = Box::new(SeededRng::new(0xDEAD));
    let mut q = Pair::new(client_config(1), server);
    let now = q.clock.now();
    let mut buf = Vec::new();
    assert!(q.server.poll_transmit(now, &mut buf)); // CHALLENGE
    q.server.recv(now, &hello.encode()).unwrap();
    assert!(q.server.poll_transmit(now, &mut buf));
    assert_eq!(Frame::parse(&buf).unwrap().frame_type, FrameType::Reject);
    assert!(q.server.is_closed());
}

#[test]
fn frame_before_welcome_is_a_protocol_error() {
    let mut p = Pair::default_pair();
    let now = p.clock.now();
    let open = Frame {
        stream_id: 1,
        frame_type: FrameType::Open,
        payload: weaver_mux::wire::encode_payload(&Class::Interactive),
    };
    let err = p.server.recv(now, &open.encode()).unwrap_err();
    assert!(matches!(err, ProtocolError::StateViolation(_)));
    let mut buf = Vec::new();
    // Server has CHALLENGE queued but GOAWAY still jumps the line.
    assert!(p.server.poll_transmit(now, &mut buf));
    assert_eq!(Frame::parse(&buf).unwrap().frame_type, FrameType::Goaway);
    assert!(matches!(
        p.server_event(),
        Some(Event::Closed { reason }) if reason.code == CloseCode::ProtocolError
    ));
    // Everything after a close is ignored without panicking.
    assert_eq!(p.server.recv(now, &open.encode()), Ok(()));
}

#[test]
fn handshake_timeout_closes() {
    let mut p = Pair::default_pair();
    let now = p.clock.now();
    assert_eq!(
        p.server.next_timeout(),
        Some(now + Duration::from_secs(10)),
        "default handshake_timeout"
    );
    p.advance(Duration::from_secs(9));
    assert!(!p.server.is_closed());
    p.advance(Duration::from_secs(1));
    assert!(p.server.is_closed());
    assert!(p.client.is_closed(), "client also gives up waiting");
    assert!(matches!(
        p.server_event(),
        Some(Event::Closed { reason }) if reason.code == CloseCode::Timeout
    ));
    assert_eq!(p.server.next_timeout(), None);
}

#[test]
fn signer_failure_closes_locally() {
    let key = Ed25519TestSigner::from_seed(1).key_id();
    let client = Config::client(
        Box::new(FailingSigner(key)),
        SERVER_NAME,
        Box::new(SeededRng::new(5)),
    );
    let mut p = Pair::new(client, server_config(1));
    p.pump();
    assert!(matches!(
        p.client_event(),
        Some(Event::Closed { reason }) if reason.code == CloseCode::Rejected
    ));
    assert!(p.frames_of(Side::Client, FrameType::Hello).is_empty());
    assert!(p.server.is_closed(), "GOAWAY reached the server");
}

#[test]
fn open_before_authenticated_fails() {
    let mut p = Pair::default_pair();
    assert_eq!(
        p.client.open(Class::Interactive),
        Err(StreamError::NotAuthenticated)
    );
}
