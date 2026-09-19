mod common;

use common::*;
use weaver_mux::wire::DATA_FLAG_COMPRESSED;
use weaver_mux::{Class, Compress, Frame, FrameType};

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

/// Open a stream in `class`, send `data` with `stance`, pump, and return
/// the client's DATA frames plus what the server received.
fn send_one(p: &mut Pair, class: Class, stance: Compress, data: &[u8]) -> (Vec<Frame>, Vec<u8>) {
    let id = p.client.open(class).unwrap();
    p.client.send(id, data, stance).unwrap();
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
fn auto_compresses_json_and_round_trips() {
    let mut p = Pair::authenticated();
    let data = json(50_000);
    let (frames, got) = send_one(&mut p, Class::Interactive, Compress::Auto, &data);
    // Every fragment above the 1 KiB floor carries the flag; the 851-byte
    // tail fragment legitimately goes raw.
    let (last, body) = frames.split_last().unwrap();
    assert!(
        body.iter().all(is_compressed),
        "every full fragment is compressed"
    );
    assert!(!is_compressed(last), "tail under the floor is raw");
    let wire: usize = frames.iter().map(|f| f.payload.len()).sum();
    assert!(wire < data.len() / 4, "wire {wire} vs {}", data.len());
    assert_eq!(got, data);
}

#[test]
fn never_is_final() {
    let mut p = Pair::authenticated();
    let (frames, got) = send_one(&mut p, Class::Bulk, Compress::Never, &json(50_000));
    assert!(frames.iter().all(|f| !is_compressed(f)));
    assert_eq!(got, json(50_000));
}

#[test]
fn stance_is_per_message_not_per_stream() {
    // The BREACH shape: an uncompressed head followed by a compressed body
    // on the same stream, then another uncompressed message.
    let mut p = Pair::authenticated();
    let id = p.client.open(Class::Interactive).unwrap();
    p.client.send(id, &json(4096), Compress::Never).unwrap();
    p.client.send(id, &json(4096), Compress::Auto).unwrap();
    p.client.send(id, &json(4096), Compress::Never).unwrap();
    p.pump();
    let flags: Vec<bool> = p
        .frames_of(Side::Client, FrameType::Data)
        .iter()
        .map(|f| is_compressed(f))
        .collect();
    assert_eq!(flags, vec![false, true, false]);
    assert_eq!(recv_all(&mut p.server, id).len(), 3);
}

#[test]
fn realtime_streams_are_never_compressed() {
    let mut p = Pair::authenticated();
    let (frames, got) = send_one(&mut p, Class::Realtime, Compress::Auto, &json(8192));
    assert!(frames.iter().all(|f| !is_compressed(f)));
    assert_eq!(got, json(8192));
}

#[test]
fn one_kib_floor_per_fragment() {
    let mut p = Pair::authenticated();
    let (frames, _) = send_one(&mut p, Class::Interactive, Compress::Auto, &json(1023));
    assert!(frames.iter().all(|f| !is_compressed(f)), "under floor");
    let (frames, _) = send_one(&mut p, Class::Interactive, Compress::Auto, &json(1024));
    assert!(frames.iter().all(is_compressed), "exactly 1 KiB is enough");
    // A small message does not poison later big ones on the same stream.
    let id = p.client.open(Class::Interactive).unwrap();
    p.client.send(id, &json(100), Compress::Auto).unwrap();
    p.client.send(id, &json(20_000), Compress::Auto).unwrap();
    let before = p.log.len();
    p.pump();
    let frames: Vec<_> = p.log[before..]
        .iter()
        .filter(|(s, f)| *s == Side::Client && f.frame_type == FrameType::Data)
        .map(|(_, f)| f.clone())
        .collect();
    assert!(!is_compressed(&frames[0]));
    assert!(frames[1..].iter().all(is_compressed));
}

#[test]
fn entropy_probe_rejects_random_bytes() {
    let mut p = Pair::authenticated();
    let (frames, got) = send_one(&mut p, Class::Interactive, Compress::Auto, &noise(8192));
    assert!(frames.iter().all(|f| !is_compressed(f)));
    assert_eq!(got, noise(8192));
}

#[test]
fn windows_count_compressed_bytes() {
    let mut server = server_config(1);
    server_params(&mut server, |p| p.initial_window = 64 * 1024);
    let mut p = Pair::new(client_config(1), server);
    p.pump();
    let id = p.client.open(Class::Interactive).unwrap();
    // Credit is reserved on the raw size but spent on the wire size, so
    // after sending, far more credit is free than raw bytes would allow.
    let data = json(60_000);
    p.client.send(id, &data, Compress::Auto).unwrap();
    // A second 60 KB message would not fit raw in 64 KiB, but the first
    // one only cost its compressed size — check by draining and looking at
    // total wire bytes.
    p.pump();
    let wire: usize = p
        .frames_of(Side::Client, FrameType::Data)
        .iter()
        .map(|f| f.payload.len())
        .sum();
    assert!(wire < 8 * 1024, "wire bytes {wire} far under window");
    assert_eq!(read_all(&mut p.server, id), data);
    // Credit consumed == wire bytes, so another full message fits.
    p.client.send(id, &data, Compress::Auto).unwrap();
}

#[test]
fn server_can_refuse_compression() {
    let mut server = server_config(1);
    server_params(&mut server, |p| p.compression_allowed = false);
    let mut p = Pair::new(client_config(1), server);
    p.pump();
    assert!(!p.client.params().unwrap().compression_allowed);
    let (frames, got) = send_one(&mut p, Class::Interactive, Compress::Auto, &json(8192));
    assert!(frames.iter().all(|f| !is_compressed(f)));
    assert_eq!(got, json(8192));
}

#[test]
fn policy_change_to_realtime_stops_compression() {
    let mut p = Pair::authenticated();
    let id = p.client.open(Class::Interactive).unwrap();
    p.client.set_class(id, Class::Realtime).unwrap();
    p.client.send(id, &json(8192), Compress::Auto).unwrap();
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
    let id = p.client.open(Class::Interactive).unwrap();
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
