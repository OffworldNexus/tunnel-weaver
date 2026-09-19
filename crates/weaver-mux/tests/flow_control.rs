mod common;

use common::*;
use weaver_mux::wire::{self, WindowUpdate};
use weaver_mux::{Compress, Event, Frame, FrameType, StreamError, StreamPolicy};

const WINDOW: u32 = 64 * 1024;

/// Small window so the tests exercise credit exhaustion quickly.
fn small_window_pair() -> Pair {
    let mut server = server_config(1);
    server.initial_window = WINDOW;
    let mut p = Pair::new(client_config(1), server);
    p.pump();
    p.drain_events(Side::Client);
    p.drain_events(Side::Server);
    p
}

/// Incompressible payload, so wire bytes == application bytes + flags.
fn noise(n: usize) -> Vec<u8> {
    (0..n as u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect()
}

/// Send `msg` repeatedly until the credit runs out; returns how many were
/// accepted.
fn fill(p: &mut Pair, id: u32, msg: &[u8]) -> usize {
    let mut n = 0;
    while p.client.send(id, msg, Compress::Never).is_ok() {
        n += 1;
    }
    n
}

#[test]
fn sender_never_exceeds_credit() {
    let mut p = small_window_pair();
    let id = p.client.open(StreamPolicy::default()).unwrap();
    let msg = noise(4000);
    let accepted = fill(&mut p, id, &msg);
    // 16 messages of 4001 wire bytes fit in 64 KiB; the 17th does not.
    assert_eq!(accepted, 16);
    assert_eq!(
        p.client.send(id, &msg, Compress::Never),
        Err(StreamError::WouldBlock)
    );
    // Client alone (no WINDOW_UPDATEs come back): count wire bytes.
    let now = p.clock.now();
    let mut buf = Vec::new();
    let mut wire_total = 0u32;
    while p.client.poll_transmit(now, &mut buf) {
        let f = Frame::parse(&buf).unwrap();
        if f.frame_type == FrameType::Data {
            wire_total += f.payload.len() as u32;
            assert!(wire_total <= WINDOW, "credit exceeded");
        }
    }
    assert!(wire_total <= WINDOW);
}

#[test]
fn window_update_cadence_and_writable() {
    let mut p = small_window_pair();
    let id = p.client.open(StreamPolicy::default()).unwrap();
    let msg = noise(4000);
    let first = fill(&mut p, id, &msg);
    p.pump();
    p.drain_events(Side::Client);
    // Server has the bytes but has not consumed them: no update yet.
    assert!(
        p.frames_of(Side::Server, FrameType::WindowUpdate)
            .is_empty()
    );
    // Consume just under half the window: still nothing.
    let under_half = (WINDOW as usize / 2) / 4001 - 1;
    for _ in 0..under_half {
        p.server.recv_msg(id).unwrap();
    }
    p.pump();
    assert!(
        p.frames_of(Side::Server, FrameType::WindowUpdate)
            .is_empty(),
        "no update before half the window is consumed"
    );
    // Consume the rest: together the updates return exactly the wire
    // bytes consumed.
    let rest = recv_all(&mut p.server, id).len();
    assert_eq!(under_half + rest, first);
    p.pump();
    let updates = p.frames_of(Side::Server, FrameType::WindowUpdate);
    assert!(!updates.is_empty());
    let credits: Vec<u32> = updates
        .iter()
        .map(|f| {
            wire::decode_payload::<WindowUpdate>(FrameType::WindowUpdate, &f.payload)
                .unwrap()
                .credit
        })
        .collect();
    assert!(credits.iter().all(|&c| c >= WINDOW / 2), "{credits:?}");
    let consumed_wire = first as u32 * 4001;
    assert!(
        credits.iter().sum::<u32>() <= consumed_wire,
        "credit never exceeds wire bytes consumed"
    );
    // Client was blocked and now learns it may send again.
    assert_eq!(p.drain_events(Side::Client), vec![Event::Writable(id)]);
    p.client.send(id, &msg, Compress::Never).unwrap();
}

#[test]
fn stalled_reader_does_not_block_other_streams() {
    let mut p = small_window_pair();
    let stalled = p.client.open(StreamPolicy::default()).unwrap();
    let live = p.client.open(StreamPolicy::default()).unwrap();
    fill(&mut p, stalled, &noise(4000));
    p.pump();
    // Stalled stream is out of credit; nobody reads it on the server.
    assert_eq!(
        p.client.send(stalled, &noise(4000), Compress::Never),
        Err(StreamError::WouldBlock)
    );
    // The live stream keeps flowing round after round.
    for round in 0..5 {
        let msg = format!("round {round}");
        send(&mut p.client, live, msg.as_bytes());
        p.pump();
        assert_eq!(read_all(&mut p.server, live), msg.as_bytes());
    }
    assert!(!p.client.is_closed() && !p.server.is_closed());
}

#[test]
fn peer_overrunning_credit_is_a_protocol_error() {
    let mut p = small_window_pair();
    let id = p.client.open(StreamPolicy::default()).unwrap();
    p.pump();
    p.drain_events(Side::Server);
    // Hand-craft DATA frames beyond the window straight into the server.
    let now = p.clock.now();
    let mut payload = vec![0u8];
    payload.extend_from_slice(&noise(16 * 1024 - 1));
    let frame = Frame {
        stream_id: id,
        frame_type: FrameType::Data,
        payload,
    }
    .encode();
    for _ in 0..4 {
        p.server.recv(now, &frame).unwrap();
    }
    assert!(
        p.server.recv(now, &frame).is_err(),
        "fifth frame overruns the 64 KiB window"
    );
    assert!(p.server.is_closed());
}

#[test]
fn send_on_unknown_stream_fails() {
    let mut p = small_window_pair();
    assert_eq!(
        p.client.send(99, b"x", Compress::Auto),
        Err(StreamError::UnknownStream)
    );
}
