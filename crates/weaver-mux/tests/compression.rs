mod common;

use common::*;
use weaver_mux::wire::DATA_FLAG_COMPRESSED;
use weaver_mux::{Class, Compression, Frame, FrameType, Head, Hints};

fn json(n: usize) -> Vec<u8> {
    let mut v = Vec::new();
    while v.len() < n {
        v.extend_from_slice(br#"{"id":123,"name":"weaver","tags":["a","b"],"ok":true},"#);
    }
    v.truncate(n);
    v
}

fn noise(n: usize) -> Vec<u8> {
    (0..n as u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect()
}

fn hints(ct: &str) -> Hints {
    Hints {
        content_type: Some(ct.into()),
        ..Hints::default()
    }
}

/// Open a stream with `hints`, write `data`, pump, and return the client's
/// DATA frames plus what the server read.
fn send(p: &mut Pair, hints: Hints, data: &[u8]) -> (Vec<Frame>, Vec<u8>) {
    let id = p
        .client
        .open(Head {
            hints,
            opaque: vec![],
        })
        .unwrap();
    assert_eq!(p.client.write(id, data).unwrap(), data.len());
    let before = p.log.len();
    p.pump();
    let frames = p.log[before..]
        .iter()
        .filter(|(s, f)| *s == Side::Client && f.frame_type == FrameType::Data && f.stream_id == id)
        .map(|(_, f)| f.clone())
        .collect();
    (frames, read_all(&mut p.server, id))
}

fn is_compressed(f: &Frame) -> bool {
    f.payload[0] & DATA_FLAG_COMPRESSED != 0
}

#[test]
fn json_body_is_compressed_and_round_trips() {
    let mut p = Pair::authenticated();
    let data = json(50_000);
    let (frames, got) = send(&mut p, hints("application/json"), &data);
    assert!(
        frames.iter().all(is_compressed),
        "every frame carries the flag"
    );
    let wire: usize = frames.iter().map(|f| f.payload.len()).sum();
    assert!(wire < data.len() / 4, "wire {wire} vs {}", data.len());
    assert_eq!(got, data);
}

#[test]
fn heads_are_never_compressed() {
    let mut p = Pair::authenticated();
    let head = Head {
        hints: hints("application/json"),
        opaque: json(8192),
    };
    p.client.open(head.clone()).unwrap();
    p.pump();
    let open = p.frames_of(Side::Client, FrameType::Open);
    assert_eq!(open.len(), 1);
    // OPEN payload is the postcard head verbatim: opaque bytes appear in it.
    assert!(open[0].payload.len() >= head.opaque.len());
    assert!(open[0].payload.windows(64).any(|w| w == &head.opaque[..64]));
}

#[test]
fn realtime_streams_are_not_compressed() {
    let mut p = Pair::authenticated();
    let (frames, got) = send(
        &mut p,
        Hints {
            content_type: Some("application/json".into()),
            upgrade: true,
            ..Hints::default()
        },
        &json(8192),
    );
    assert!(frames.iter().all(|f| !is_compressed(f)));
    assert_eq!(got, json(8192));

    let (frames, _) = send(&mut p, hints("text/event-stream"), &json(8192));
    assert!(frames.iter().all(|f| !is_compressed(f)));
}

#[test]
fn content_type_skip_list() {
    let mut p = Pair::authenticated();
    for ct in [
        "image/png",
        "video/mp4",
        "audio/ogg",
        "font/woff2",
        "application/zip",
        "application/pdf; version=1.7",
        "application/octet-stream",
    ] {
        let (frames, _) = send(&mut p, hints(ct), &json(8192));
        assert!(frames.iter().all(|f| !is_compressed(f)), "{ct} should skip");
    }
    for ct in ["image/svg+xml", "text/html", "application/json"] {
        let (frames, _) = send(&mut p, hints(ct), &json(8192));
        assert!(frames.iter().all(is_compressed), "{ct} should compress");
    }
    let (frames, _) = send(
        &mut p,
        Hints {
            content_type: Some("text/html".into()),
            content_encoding: Some("gzip".into()),
            ..Hints::default()
        },
        &json(8192),
    );
    assert!(frames.iter().all(|f| !is_compressed(f)), "already encoded");
}

#[test]
fn one_kib_floor_and_decide_once() {
    let mut p = Pair::authenticated();
    // A small first write turns compression off for the whole stream, even
    // when a big compressible write follows.
    let id = p
        .client
        .open(Head {
            hints: hints("text/plain"),
            opaque: vec![],
        })
        .unwrap();
    p.client.write(id, &json(1023)).unwrap();
    p.client.write(id, &json(20_000)).unwrap();
    p.pump();
    let frames = p.frames_of(Side::Client, FrameType::Data);
    assert!(frames.iter().all(|f| !is_compressed(f)));
    // Exactly 1 KiB is enough.
    let (frames, _) = send(&mut p, hints("text/plain"), &json(1024));
    assert!(frames.iter().all(is_compressed));
}

#[test]
fn entropy_probe_rejects_random_bytes() {
    let mut p = Pair::authenticated();
    let (frames, got) = send(&mut p, Hints::default(), &noise(8192));
    assert!(frames.iter().all(|f| !is_compressed(f)));
    assert_eq!(got, noise(8192));
}

#[test]
fn windows_count_compressed_bytes() {
    let mut server = server_config(1);
    server.initial_window = 64 * 1024;
    let mut p = Pair::new(client_config(1), server);
    p.pump();
    let id = p
        .client
        .open(Head {
            hints: hints("application/json"),
            opaque: vec![],
        })
        .unwrap();
    // Far more than the window in application bytes fits because credit
    // is spent on the compressed size.
    let data = json(1 << 20);
    let accepted = p.client.write(id, &data).unwrap();
    assert!(accepted > 64 * 1024, "accepted {accepted} > window");
    p.pump();
    let wire: usize = p
        .frames_of(Side::Client, FrameType::Data)
        .iter()
        .map(|f| f.payload.len())
        .sum();
    assert!(wire <= 64 * 1024, "wire bytes {wire} within window");
    assert_eq!(read_all(&mut p.server, id), data[..accepted]);
}

#[test]
fn server_can_refuse_compression() {
    let mut server = server_config(1);
    server.compression = Compression::Off;
    let mut p = Pair::new(client_config(1), server);
    p.pump();
    assert_eq!(p.client.params().unwrap().compression, Compression::Off);
    let (frames, got) = send(&mut p, hints("application/json"), &json(8192));
    assert!(frames.iter().all(|f| !is_compressed(f)));
    assert_eq!(got, json(8192));
}

#[test]
fn pinned_realtime_after_open_is_honoured_on_first_write() {
    let mut p = Pair::authenticated();
    let id = p
        .client
        .open(Head {
            hints: hints("application/json"),
            opaque: vec![],
        })
        .unwrap();
    p.client.set_class(id, Class::Realtime).unwrap();
    p.client.write(id, &json(8192)).unwrap();
    p.pump();
    assert!(
        p.frames_of(Side::Client, FrameType::Data)
            .iter()
            .all(|f| !is_compressed(f))
    );
}

#[test]
fn hostile_compressed_frame_is_a_protocol_error() {
    let mut p = Pair::authenticated();
    let id = p.client.open(Head::default()).unwrap();
    p.pump();
    let now = p.clock.now();
    let mut payload = vec![DATA_FLAG_COMPRESSED];
    payload.extend_from_slice(b"definitely not zstd");
    let f = Frame {
        stream_id: id,
        frame_type: FrameType::Data,
        payload,
    };
    assert!(p.server.recv(now, &f.encode()).is_err());
    assert!(p.server.is_closed());
}
