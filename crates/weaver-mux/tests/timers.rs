mod common;

use std::time::Duration;

use common::*;
use weaver_mux::{CloseCode, Event, Frame, FrameType, StreamPolicy};

const PING: Duration = Duration::from_secs(15);
const IDLE: Duration = Duration::from_secs(60);

#[test]
fn next_timeout_is_last_activity_plus_ping_interval() {
    let p = Pair::authenticated();
    let now = p.clock.now();
    assert_eq!(p.client.next_timeout(), Some(now + PING));
    assert_eq!(p.server.next_timeout(), Some(now + PING));
}

#[test]
fn ping_emitted_exactly_once_and_pong_measures_rtt() {
    let mut p = Pair::authenticated();
    let t0 = p.clock.now();
    p.advance(PING);
    let mut buf = Vec::new();
    let now = p.clock.now();
    assert!(p.client.poll_transmit(now, &mut buf));
    assert_eq!(Frame::parse(&buf).unwrap().frame_type, FrameType::Ping);
    let ping = buf.clone();
    assert!(!p.client.poll_transmit(now, &mut buf), "exactly one PING");
    buf = ping;
    // With a PING outstanding, the only remaining deadline is idle,
    // measured from the last frame *received* (WELCOME at t0).
    assert_eq!(p.client.next_timeout(), Some(t0 + IDLE));
    // Calling handle_timeout again does not re-ping.
    p.client.handle_timeout(now);
    let mut scratch = Vec::new();
    assert!(!p.client.poll_transmit(now, &mut scratch));

    // Deliver the PING 250ms later, PONG comes back 250ms after that.
    let t1 = p.clock.advance(Duration::from_millis(250));
    // The server has been idle just as long and has its own PING queued;
    // skip that so we isolate the PONG for ours.
    let mut server_ping = Vec::new();
    assert!(p.server.poll_transmit(t1, &mut server_ping));
    assert_eq!(
        Frame::parse(&server_ping).unwrap().frame_type,
        FrameType::Ping
    );
    p.server.recv(t1, &buf).unwrap();
    let mut pong = Vec::new();
    assert!(p.server.poll_transmit(t1, &mut pong));
    assert_eq!(Frame::parse(&pong).unwrap().frame_type, FrameType::Pong);
    let t2 = p.clock.advance(Duration::from_millis(250));
    p.client.recv(t2, &pong).unwrap();
    assert_eq!(p.client.rtt(), Some(Duration::from_millis(500)));
    // Ping cadence re-armed from the last activity.
    assert_eq!(p.client.next_timeout(), Some(t2 + PING));
}

#[test]
fn no_pong_within_idle_timeout_closes_once() {
    let mut p = Pair::authenticated();
    p.advance(PING);
    let mut buf = Vec::new();
    assert!(p.client.poll_transmit(p.clock.now(), &mut buf)); // PING, never delivered
    p.advance(IDLE - PING - Duration::from_millis(1));
    assert!(!p.client.is_closed());
    p.advance(Duration::from_millis(1));
    assert!(p.client.is_closed());
    let events = p.drain_events(Side::Client);
    assert_eq!(
        events,
        vec![Event::Closed {
            reason: weaver_mux::GoAway::new(CloseCode::Timeout)
        }]
    );
    // GOAWAY goes out so the peer learns why.
    assert!(p.client.poll_transmit(p.clock.now(), &mut buf));
    assert_eq!(Frame::parse(&buf).unwrap().frame_type, FrameType::Goaway);
    assert!(!p.client.poll_transmit(p.clock.now(), &mut buf));
}

#[test]
fn late_handle_timeout_closes_only_once() {
    let mut p = Pair::authenticated();
    p.advance(Duration::from_secs(600));
    assert!(p.server.is_closed());
    let closed: Vec<_> = p
        .drain_events(Side::Server)
        .into_iter()
        .filter(|e| matches!(e, Event::Closed { .. }))
        .collect();
    assert_eq!(closed.len(), 1);
    p.advance(Duration::from_secs(600));
    assert!(p.drain_events(Side::Server).is_empty());
    assert_eq!(p.server.next_timeout(), None);
}

#[test]
fn any_received_frame_resets_idle() {
    let mut p = Pair::authenticated();
    p.advance(Duration::from_secs(50));
    // Client opens a stream; the OPEN reaching the server counts as liveness.
    p.client.open(StreamPolicy::default()).unwrap();
    p.pump();
    p.advance(Duration::from_secs(50));
    assert!(!p.server.is_closed(), "idle clock was reset by the OPEN");
}

#[test]
fn never_fin_stream_survives_pings() {
    let mut p = Pair::authenticated();
    let id = p.client.open(StreamPolicy::default()).unwrap();
    p.pump();
    for _ in 0..10 {
        p.advance(PING);
        p.pump();
    }
    assert!(!p.client.is_closed() && !p.server.is_closed());
    send(&mut p.client, id, b"still here");
    p.pump();
    assert_eq!(read_all(&mut p.server, id), b"still here");
    assert!(!p.frames_of(Side::Client, FrameType::Ping).is_empty());
    assert!(!p.frames_of(Side::Server, FrameType::Pong).is_empty());
}

#[test]
fn reverify_polls_and_revokes() {
    let mut server = server_config(1);
    server.reverify_interval = Some(Duration::from_secs(5));
    let mut p = Pair::new(client_config(1), server);
    p.pump();
    let now = p.clock.now();
    assert_eq!(p.server.next_timeout(), Some(now + Duration::from_secs(5)));
    p.advance(Duration::from_secs(5));
    assert!(!p.server.is_closed(), "key still valid");
    p.pump();
    // Revoke: we cannot reach the verifier inside the connection, so build
    // a fresh pair whose verifier is pre-revoked.
    let signer = weaver_mux::testing::Ed25519TestSigner::from_seed(1);
    let mut verifier = weaver_mux::testing::MapVerifier::with_key(
        weaver_mux::Signer::key_id(&signer),
        signer.public_key(),
    );
    verifier.revoke(weaver_mux::Signer::key_id(&signer));
    let mut server = weaver_mux::Config::server(
        Box::new(verifier),
        SERVER_NAME,
        Box::new(weaver_mux::testing::SeededRng::new(7)),
    );
    server.reverify_interval = Some(Duration::from_secs(5));
    let mut q = Pair::new(client_config(1), server);
    q.pump();
    assert!(matches!(
        q.server_event(),
        Some(Event::Authenticated { .. })
    ));
    q.advance(Duration::from_secs(5));
    q.pump();
    assert!(matches!(
        q.server_event(),
        Some(Event::Closed { reason }) if reason.code == CloseCode::KeyRevoked
    ));
    let client_events = q.drain_events(Side::Client);
    assert!(
        client_events
            .iter()
            .any(|e| matches!(e, Event::Closed { reason } if reason.code == CloseCode::KeyRevoked))
    );
}
