mod common;

use common::*;
use weaver_mux::wire::DATA_FLAG_MORE;
use weaver_mux::{Class, Compress, Event, Frame, FrameType, StreamError};

fn policy() -> Class {
    Class::Interactive
}

#[tokio::test]
async fn round_trip_client_to_server() {
    let mut p = Pair::authenticated().await;
    let id = p.client.open(policy()).unwrap();
    assert_eq!(id, 1, "client ids are odd, starting at 1");
    send(&mut p.client, id, b"GET /");
    send(&mut p.client, id, b"hello");
    p.client.finish(id).unwrap();
    p.pump().await;

    let events = p.drain_events(Side::Server);
    assert_eq!(
        events,
        vec![
            Event::StreamOpened {
                id,
                class: policy()
            },
            Event::Readable(id),
        ],
        "Finished waits until the inbox is drained"
    );
    assert_eq!(p.server.pending_messages(id), Some(2));
    assert_eq!(p.server.recv_msg(id).unwrap(), b"GET /");
    assert_eq!(p.server.recv_msg(id).unwrap(), b"hello");
    assert_eq!(p.drain_events(Side::Server), vec![Event::Finished(id)]);
    assert_eq!(p.server.recv_msg(id), Err(StreamError::WouldBlock));
}

#[tokio::test]
async fn finished_is_immediate_when_nothing_was_sent() {
    let mut p = Pair::authenticated().await;
    let id = p.client.open(policy()).unwrap();
    p.client.finish(id).unwrap();
    p.pump().await;
    let events = p.drain_events(Side::Server);
    assert_eq!(
        events,
        vec![
            Event::StreamOpened {
                id,
                class: policy()
            },
            Event::Finished(id),
        ]
    );
}

#[tokio::test]
async fn round_trip_server_to_client_and_both_directions() {
    let mut p = Pair::authenticated().await;
    let id = p.server.open(policy()).unwrap();
    assert_eq!(id, 2, "server ids are even, starting at 2");
    send(&mut p.server, id, b"from server");
    p.pump().await;
    assert!(matches!(
        p.client_event(),
        Some(Event::StreamOpened { id: 2, .. })
    ));
    assert_eq!(read_all(&mut p.client, id), b"from server");
    // Client answers on the same stream.
    send(&mut p.client, id, b"from client");
    p.client.finish(id).unwrap();
    p.pump().await;
    assert_eq!(read_all(&mut p.server, id), b"from client");
    // Server side still open for writing.
    send(&mut p.server, id, b"more");
    p.server.finish(id).unwrap();
    p.pump().await;
    assert_eq!(read_all(&mut p.client, id), b"more");
    // Both directions are done and both inboxes drained: the stream is
    // gone on both sides.
    assert_eq!(
        p.client.send(id, b"x", Compress::Auto),
        Err(StreamError::UnknownStream)
    );
    assert_eq!(
        p.server.send(id, b"x", Compress::Auto),
        Err(StreamError::UnknownStream)
    );
}

#[tokio::test]
async fn half_close_semantics() {
    let mut p = Pair::authenticated().await;
    let id = p.client.open(policy()).unwrap();
    p.client.finish(id).unwrap();
    p.pump().await;
    // Client cannot send after FIN...
    assert_eq!(
        p.client.send(id, b"x", Compress::Auto),
        Err(StreamError::SendClosed)
    );
    assert_eq!(p.client.finish(id), Err(StreamError::SendClosed));
    // ...but the server still can.
    assert_eq!(p.server.recv_msg(id), Err(StreamError::WouldBlock));
    send(&mut p.server, id, b"late");
    p.pump().await;
    assert_eq!(read_all(&mut p.client, id), b"late");
    assert_eq!(
        p.client.recv_msg(id),
        Err(StreamError::WouldBlock),
        "server has not FINed yet"
    );
}

#[tokio::test]
async fn reset_mid_stream() {
    let mut p = Pair::authenticated().await;
    let id = p.client.open(policy()).unwrap();
    send(&mut p.client, id, b"partial");
    p.pump().await;
    p.drain_events(Side::Server);
    p.client.reset(id, 77).unwrap();
    p.pump().await;
    assert_eq!(
        p.drain_events(Side::Server),
        vec![Event::Reset { id, code: 77 }]
    );
    assert_eq!(p.server.recv_msg(id), Err(StreamError::UnknownStream));
    assert_eq!(
        p.client.send(id, b"x", Compress::Auto),
        Err(StreamError::UnknownStream)
    );
    // A late frame from the server for that id is tolerated, not fatal.
    assert!(!p.client.is_closed());
}

#[tokio::test]
async fn ids_have_parity_and_are_never_reused() {
    let mut p = Pair::authenticated().await;
    let mut client_ids = Vec::new();
    let mut server_ids = Vec::new();
    for _ in 0..5 {
        let c = p.client.open(policy()).unwrap();
        let s = p.server.open(policy()).unwrap();
        p.client.finish(c).unwrap();
        p.server.finish(s).unwrap();
        p.pump().await;
        // Peer closes its side too so the streams fully drain.
        p.server.finish(c).unwrap();
        p.client.finish(s).unwrap();
        p.pump().await;
        client_ids.push(c);
        server_ids.push(s);
    }
    assert_eq!(client_ids, vec![1, 3, 5, 7, 9]);
    assert_eq!(server_ids, vec![2, 4, 6, 8, 10]);
}

#[tokio::test]
async fn peer_open_with_wrong_parity_is_a_protocol_error() {
    let mut p = Pair::authenticated().await;
    let now = p.clock.now();
    let bogus = Frame {
        stream_id: 2, // even: server parity, sent by the client
        frame_type: FrameType::Open,
        payload: weaver_mux::wire::encode_payload(&Class::Interactive),
    };
    assert!(p.server.recv(now, &encode(&bogus)).await.is_err());
    assert!(p.server.is_closed());
}

#[tokio::test]
async fn control_class_is_rejected_on_both_ends() {
    let mut p = Pair::authenticated().await;
    assert_eq!(
        p.client.open(Class::Control),
        Err(StreamError::InvalidClass)
    );
    let now = p.clock.now();
    let bogus = Frame {
        stream_id: 1,
        frame_type: FrameType::Open,
        payload: weaver_mux::wire::encode_payload(&Class::Control),
    };
    assert!(p.server.recv(now, &encode(&bogus)).await.is_err());
    assert!(p.server.is_closed());
}

#[tokio::test]
async fn send_before_open_leaves_wire_emits_open_first() {
    let mut p = Pair::authenticated().await;
    let id = p.client.open(policy()).unwrap();
    send(&mut p.client, id, b"body");
    p.pump().await;
    let client_frames: Vec<_> = p
        .log
        .iter()
        .filter(|(s, f)| *s == Side::Client && f.stream_id != 0)
        .map(|(_, f)| f.frame_type)
        .collect();
    assert_eq!(client_frames, vec![FrameType::Open, FrameType::Data]);
    assert_eq!(read_all(&mut p.server, id), b"body");
}

#[tokio::test]
async fn large_messages_are_fragmented_and_reassembled() {
    let mut p = Pair::authenticated().await;
    let id = p.client.open(policy()).unwrap();
    // Random-ish bytes so compression stays off and the frame count is exact.
    let data: Vec<u8> = (0..100_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    send(&mut p.client, id, &data);
    send(&mut p.client, id, b"tail");
    p.pump().await;
    let frames = p.frames_of(Side::Client, FrameType::Data);
    let max_frame = p.client.params().unwrap().max_frame as usize;
    assert!(frames.iter().all(|f| f.payload.len() <= max_frame));
    let n_big = data.len().div_ceil(max_frame - 1);
    assert_eq!(frames.len(), n_big + 1);
    // Every fragment but the last of the big message carries MORE.
    for (i, f) in frames.iter().enumerate() {
        let more = f.payload[0] & DATA_FLAG_MORE != 0;
        assert_eq!(more, i + 1 < n_big, "fragment {i}");
    }
    assert_eq!(recv_all(&mut p.server, id), vec![data, b"tail".to_vec()]);
}

#[tokio::test]
async fn empty_message_round_trips() {
    let mut p = Pair::authenticated().await;
    let id = p.client.open(policy()).unwrap();
    send(&mut p.client, id, b"");
    send(&mut p.client, id, b"after");
    p.pump().await;
    assert_eq!(recv_all(&mut p.server, id), vec![vec![], b"after".to_vec()]);
}

#[tokio::test]
async fn message_over_max_message_is_refused_locally() {
    let mut p = Pair::authenticated().await;
    let id = p.client.open(policy()).unwrap();
    let max = p.client.params().unwrap().max_message;
    let big = vec![0u8; max as usize + 1];
    assert_eq!(
        p.client.send(id, &big, Compress::Never),
        Err(StreamError::TooLarge {
            len: max as usize + 1,
            max
        })
    );
}

#[tokio::test]
async fn oversized_reassembly_from_peer_is_a_protocol_error() {
    let mut server = server_config(1);
    server_params(&mut server, |p| p.max_message = 16 * 1024);
    let mut p = Pair::new(client_config(1), server);
    p.pump().await;
    let id = p.client.open(policy()).unwrap();
    p.pump().await;
    let now = p.clock.now();
    // Hand-craft MORE fragments past the 16 KiB cap.
    let mut payload = vec![DATA_FLAG_MORE];
    payload.extend_from_slice(&[0u8; 8000]);
    let f = encode(&Frame {
        stream_id: id,
        frame_type: FrameType::Data,
        payload,
    });
    p.server.recv(now, &f).await.unwrap();
    p.server.recv(now, &f).await.unwrap();
    assert!(
        p.server.recv(now, &f).await.is_err(),
        "third fragment overruns"
    );
    assert!(p.server.is_closed());
}

#[tokio::test]
async fn fin_inside_a_message_is_a_protocol_error() {
    let mut p = Pair::authenticated().await;
    let id = p.client.open(policy()).unwrap();
    p.pump().await;
    let now = p.clock.now();
    let frag = encode(&Frame {
        stream_id: id,
        frame_type: FrameType::Data,
        payload: vec![DATA_FLAG_MORE, 1, 2, 3],
    });
    p.server.recv(now, &frag).await.unwrap();
    let fin = encode(&Frame {
        stream_id: id,
        frame_type: FrameType::Fin,
        payload: vec![],
    });
    assert!(p.server.recv(now, &fin).await.is_err());
}

#[tokio::test]
async fn unknown_data_flag_is_a_protocol_error() {
    let mut p = Pair::authenticated().await;
    let id = p.client.open(policy()).unwrap();
    p.pump().await;
    let now = p.clock.now();
    let f = encode(&Frame {
        stream_id: id,
        frame_type: FrameType::Data,
        payload: vec![0x80, 1],
    });
    assert!(p.server.recv(now, &f).await.is_err());
}
