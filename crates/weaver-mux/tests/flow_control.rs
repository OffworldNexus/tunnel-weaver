mod common;

use common::*;
use weaver_mux::wire::{self, WindowUpdate};
use weaver_mux::{Event, Frame, FrameType, Head, StreamError};

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

/// Incompressible payload, so wire bytes == application bytes + flag.
fn noise(n: usize) -> Vec<u8> {
    (0..n as u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect()
}

#[test]
fn sender_never_exceeds_credit() {
    let mut p = small_window_pair();
    let id = p.client.open(Head::default()).unwrap();
    let data = noise(WINDOW as usize * 3);
    let accepted = p.client.write(id, &data).unwrap();
    // Each frame carries a flag byte, so slightly less than WINDOW fits.
    assert!(accepted < WINDOW as usize && accepted > WINDOW as usize - 64);
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
    // Further writes get zero until credit returns.
    assert_eq!(p.client.write(id, &data).unwrap(), 0);
}

#[test]
fn window_update_cadence_and_writable() {
    let mut p = small_window_pair();
    let id = p.client.open(Head::default()).unwrap();
    let data = noise(WINDOW as usize);
    let first = p.client.write(id, &data).unwrap();
    p.pump();
    p.drain_events(Side::Client);
    // Server has the bytes but has not read them: no update yet.
    assert!(
        p.frames_of(Side::Server, FrameType::WindowUpdate)
            .is_empty()
    );
    // Read just under half the window: still nothing.
    let mut buf = vec![0u8; WINDOW as usize / 2 - 2048];
    let mut got = 0;
    while got < buf.len() {
        let n = p.server.read(id, &mut buf[got..]).unwrap();
        got += n;
    }
    p.pump();
    assert!(
        p.frames_of(Side::Server, FrameType::WindowUpdate)
            .is_empty(),
        "no update before half the window is consumed"
    );
    // Read the rest (a full window in total): every update announces at
    // least half a window, and together they return exactly the wire
    // bytes consumed.
    let rest = read_all(&mut p.server, id);
    p.pump();
    let updates = p.frames_of(Side::Server, FrameType::WindowUpdate);
    assert_eq!(
        updates.len(),
        2,
        "64 KiB consumed = two half-window crossings"
    );
    let credits: Vec<u32> = updates
        .iter()
        .map(|f| {
            wire::decode_payload::<WindowUpdate>(FrameType::WindowUpdate, &f.payload)
                .unwrap()
                .credit
        })
        .collect();
    assert!(credits.iter().all(|&c| c >= WINDOW / 2), "{credits:?}");
    let consumed_wire =
        (got + rest.len()) as u32 + p.frames_of(Side::Client, FrameType::Data).len() as u32;
    assert_eq!(
        credits.iter().sum::<u32>(),
        consumed_wire,
        "credit == wire bytes consumed"
    );
    // Client was blocked and now learns it may write again.
    assert_eq!(p.drain_events(Side::Client), vec![Event::Writable(id)]);
    let second = p.client.write(id, &data[first..]).unwrap();
    assert!(second > 0);
}

#[test]
fn stalled_reader_does_not_block_other_streams() {
    let mut p = small_window_pair();
    let stalled = p.client.open(Head::default()).unwrap();
    let live = p.client.open(Head::default()).unwrap();
    let data = noise(WINDOW as usize * 2);
    p.client.write(stalled, &data).unwrap();
    p.pump();
    // Stalled stream is out of credit; nobody reads it on the server.
    assert_eq!(p.client.write(stalled, &data).unwrap(), 0);
    // The live stream keeps flowing round after round.
    for round in 0..5 {
        let msg = format!("round {round}");
        assert_eq!(p.client.write(live, msg.as_bytes()).unwrap(), msg.len());
        p.pump();
        assert_eq!(read_all(&mut p.server, live), msg.as_bytes());
    }
    assert!(!p.client.is_closed() && !p.server.is_closed());
}

#[test]
fn peer_overrunning_credit_is_a_protocol_error() {
    let mut p = small_window_pair();
    let id = p.client.open(Head::default()).unwrap();
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
fn write_on_unknown_stream_fails() {
    let mut p = small_window_pair();
    assert_eq!(p.client.write(99, b"x"), Err(StreamError::UnknownStream));
}
