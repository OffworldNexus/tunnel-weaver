mod common;

use common::*;
use weaver_mux::{Event, FrameType, Head, Hints, StreamError};

fn head(opaque: &[u8]) -> Head {
    Head {
        hints: Hints::default(),
        opaque: opaque.to_vec(),
    }
}

#[test]
fn round_trip_client_to_server() {
    let mut p = Pair::authenticated();
    let id = p.client.open(head(b"GET /")).unwrap();
    assert_eq!(id, 1, "client ids are odd, starting at 1");
    assert_eq!(p.client.write(id, b"hello").unwrap(), 5);
    p.client.finish(id).unwrap();
    p.pump();

    let events = p.drain_events(Side::Server);
    assert_eq!(
        events,
        vec![
            Event::StreamOpened {
                id,
                head: head(b"GET /")
            },
            Event::Readable(id),
            Event::Finished(id),
        ]
    );
    let mut buf = [0u8; 16];
    assert_eq!(p.server.read(id, &mut buf).unwrap(), 5);
    assert_eq!(&buf[..5], b"hello");
    assert_eq!(p.server.read(id, &mut buf).unwrap(), 0, "EOF after FIN");
}

#[test]
fn round_trip_server_to_client_and_both_directions() {
    let mut p = Pair::authenticated();
    let id = p.server.open(head(b"push")).unwrap();
    assert_eq!(id, 2, "server ids are even, starting at 2");
    p.server.write(id, b"from server").unwrap();
    p.pump();
    assert!(matches!(
        p.client_event(),
        Some(Event::StreamOpened { id: 2, .. })
    ));
    assert_eq!(read_all(&mut p.client, id), b"from server");
    // Client answers on the same stream.
    p.client.write(id, b"from client").unwrap();
    p.client.finish(id).unwrap();
    p.pump();
    assert_eq!(read_all(&mut p.server, id), b"from client");
    let mut buf = [0u8; 1];
    assert_eq!(p.server.read(id, &mut buf).unwrap(), 0);
    // Server side still open for writing.
    p.server.write(id, b"more").unwrap();
    p.server.finish(id).unwrap();
    p.pump();
    assert_eq!(read_all(&mut p.client, id), b"more");
    // `read_all` stopped on the `Ok(0)` EOF. Both directions are done and
    // EOF was consumed: the stream is gone on both sides.
    assert_eq!(p.client.write(id, b"x"), Err(StreamError::UnknownStream));
    assert_eq!(p.server.write(id, b"x"), Err(StreamError::UnknownStream));
}

#[test]
fn half_close_semantics() {
    let mut p = Pair::authenticated();
    let id = p.client.open(head(b"")).unwrap();
    p.client.finish(id).unwrap();
    p.pump();
    // Client cannot write after FIN...
    assert_eq!(p.client.write(id, b"x"), Err(StreamError::SendClosed));
    assert_eq!(p.client.finish(id), Err(StreamError::SendClosed));
    // ...but the server still can.
    let mut buf = [0u8; 8];
    assert_eq!(p.server.read(id, &mut buf).unwrap(), 0);
    assert_eq!(p.server.write(id, b"late").unwrap(), 4);
    p.pump();
    assert_eq!(read_all(&mut p.client, id), b"late");
    assert_eq!(
        p.client.read(id, &mut buf),
        Err(StreamError::WouldBlock),
        "server has not FINed yet"
    );
}

#[test]
fn reset_mid_stream() {
    let mut p = Pair::authenticated();
    let id = p.client.open(head(b"")).unwrap();
    p.client.write(id, b"partial").unwrap();
    p.pump();
    p.drain_events(Side::Server);
    p.client.reset(id, 77).unwrap();
    p.pump();
    assert_eq!(
        p.drain_events(Side::Server),
        vec![Event::Reset { id, code: 77 }]
    );
    assert_eq!(
        p.server.read(id, &mut [0; 8]),
        Err(StreamError::UnknownStream)
    );
    assert_eq!(p.client.write(id, b"x"), Err(StreamError::UnknownStream));
    // A late frame from the server for that id is tolerated, not fatal.
    assert!(!p.client.is_closed());
}

#[test]
fn ids_have_parity_and_are_never_reused() {
    let mut p = Pair::authenticated();
    let mut client_ids = Vec::new();
    let mut server_ids = Vec::new();
    for _ in 0..5 {
        let c = p.client.open(head(b"")).unwrap();
        let s = p.server.open(head(b"")).unwrap();
        p.client.finish(c).unwrap();
        p.server.finish(s).unwrap();
        p.pump();
        // Peer closes its side too so the streams fully drain.
        p.server.finish(c).unwrap();
        p.client.finish(s).unwrap();
        p.pump();
        let _ = p.server.read(c, &mut [0; 1]);
        let _ = p.client.read(c, &mut [0; 1]);
        let _ = p.client.read(s, &mut [0; 1]);
        let _ = p.server.read(s, &mut [0; 1]);
        client_ids.push(c);
        server_ids.push(s);
    }
    assert_eq!(client_ids, vec![1, 3, 5, 7, 9]);
    assert_eq!(server_ids, vec![2, 4, 6, 8, 10]);
}

#[test]
fn peer_open_with_wrong_parity_is_a_protocol_error() {
    let mut p = Pair::authenticated();
    let now = p.clock.now();
    let bogus = weaver_mux::Frame {
        stream_id: 2, // even: server parity, sent by the client
        frame_type: FrameType::Open,
        payload: weaver_mux::wire::encode_payload(&Head::default()),
    };
    assert!(p.server.recv(now, &bogus.encode()).is_err());
    assert!(p.server.is_closed());
}

#[test]
fn write_before_open_leaves_wire_emits_open_first() {
    let mut p = Pair::authenticated();
    let id = p.client.open(head(b"h")).unwrap();
    p.client.write(id, b"body").unwrap();
    p.pump();
    let client_frames: Vec<_> = p
        .log
        .iter()
        .filter(|(s, f)| *s == Side::Client && f.stream_id != 0)
        .map(|(_, f)| f.frame_type)
        .collect();
    assert_eq!(client_frames, vec![FrameType::Open, FrameType::Data]);
    assert_eq!(read_all(&mut p.server, id), b"body");
}

#[test]
fn large_writes_are_split_into_max_frame_chunks() {
    let mut p = Pair::authenticated();
    let id = p.client.open(head(b"")).unwrap();
    // Random-ish bytes so compression stays off and the frame count is exact.
    let data: Vec<u8> = (0..100_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    assert_eq!(p.client.write(id, &data).unwrap(), data.len());
    p.pump();
    let frames = p.frames_of(Side::Client, FrameType::Data);
    let max_frame = p.client.params().unwrap().max_frame as usize;
    assert!(frames.iter().all(|f| f.payload.len() <= max_frame));
    assert_eq!(frames.len(), data.len().div_ceil(max_frame - 1));
    assert_eq!(read_all(&mut p.server, id), data);
}
