//! Per-stream byte reporting through the injected [`StreamBytesSink`].
//!
//! The mux keeps no byte accounting: on every DATA payload it sends or
//! receives it reports the payload length (flags byte + body, post-compression
//! on send, pre-decompression on receive) to the sink. The 5-byte frame header
//! and every non-DATA frame are excluded, and an application head message
//! carried as the first DATA message is counted.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use common::*;
use proptest::prelude::*;
use weaver_mux::{Class, FrameType, StreamBytesSink, StreamId};

fn policy() -> Class {
    Class::Interactive
}

/// A sink that accumulates reported `(bytes_in, bytes_out)` per stream.
#[derive(Default)]
struct RecordingSink {
    totals: Mutex<HashMap<StreamId, (u64, u64)>>,
}

impl RecordingSink {
    fn totals(&self, id: StreamId) -> (u64, u64) {
        self.totals
            .lock()
            .unwrap()
            .get(&id)
            .copied()
            .unwrap_or((0, 0))
    }
}

impl StreamBytesSink for RecordingSink {
    fn bytes(&self, id: StreamId, bytes_in: u64, bytes_out: u64) {
        let mut totals = self.totals.lock().unwrap();
        let entry = totals.entry(id).or_default();
        entry.0 += bytes_in;
        entry.1 += bytes_out;
    }
}

/// Sum of DATA payload lengths actually put on the wire by `side`.
fn data_payload_bytes(p: &Pair, side: Side) -> u64 {
    p.frames_of(side, FrameType::Data)
        .iter()
        .map(|f| f.payload.len() as u64)
        .sum()
}

/// Installs sinks on both ends, returning them for assertions.
fn install_sinks(p: &mut Pair) -> (Arc<RecordingSink>, Arc<RecordingSink>) {
    let client = Arc::new(RecordingSink::default());
    let server = Arc::new(RecordingSink::default());
    p.client.set_bytes_sink(client.clone());
    p.server.set_bytes_sink(server.clone());
    (client, server)
}

#[tokio::test]
async fn sink_reports_the_sum_of_data_payloads() {
    let mut p = Pair::authenticated().await;
    let (client_sink, server_sink) = install_sinks(&mut p);
    let id = p.client.open(policy()).unwrap();
    send(&mut p.client, id, b"first message");
    send(&mut p.client, id, b"second, a little longer");
    p.pump().await;

    let wire = data_payload_bytes(&p, Side::Client);
    assert!(wire > 0);
    assert_eq!(
        client_sink.totals(id).1,
        wire,
        "sender reports queued DATA payloads"
    );
    assert_eq!(
        server_sink.totals(id).0,
        wire,
        "receiver reports received DATA payloads"
    );
    // Control frames (OPEN, WINDOW_UPDATE, FIN) never reach the sink.
    assert!(
        p.frames_of(Side::Client, FrameType::Open).len() == 1,
        "OPEN crossed the wire but was not reported"
    );
}

#[tokio::test]
async fn empty_message_reports_its_flag_byte() {
    let mut p = Pair::authenticated().await;
    let (client_sink, server_sink) = install_sinks(&mut p);
    let id = p.client.open(policy()).unwrap();
    send(&mut p.client, id, b"");
    p.pump().await;
    // One DATA payload of just the flags byte.
    assert_eq!(client_sink.totals(id).1, 1);
    assert_eq!(server_sink.totals(id).0, 1);
}

#[tokio::test]
async fn reporting_happens_at_flow_time_not_at_stream_end() {
    let mut p = Pair::authenticated().await;
    let (client_sink, server_sink) = install_sinks(&mut p);
    let id = p.client.open(policy()).unwrap();
    send(&mut p.client, id, b"payload"); // 7 + 1 flag byte
    p.pump().await;
    // Reported while the stream is still open...
    assert_eq!(client_sink.totals(id).1, 8);
    assert_eq!(server_sink.totals(id).0, 8);

    // ...and the totals are unaffected by the stream going away.
    p.client.finish(id).unwrap();
    p.pump().await;
    let _ = read_all(&mut p.server, id);
    p.server.finish(id).unwrap();
    p.pump().await;
    assert_eq!(client_sink.totals(id).1, 8);
    assert_eq!(server_sink.totals(id).0, 8);
}

#[tokio::test]
async fn a_connection_without_a_sink_still_works() {
    // No sink installed: reporting is a no-op and traffic flows normally.
    let mut p = Pair::authenticated().await;
    let id = p.client.open(policy()).unwrap();
    send(&mut p.client, id, b"no sink");
    p.pump().await;
    assert_eq!(read_all(&mut p.server, id), b"no sink");
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 16,
        ..ProptestConfig::default()
    })]

    /// Reported bytes equal the sum of DATA payloads over a randomized send
    /// script, on both ends.
    #[test]
    fn reported_bytes_match_data_payload_sum(
        msgs in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 0..3000),
            1..8,
        ),
    ) {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let mut server = server_config(1);
                // A generous window keeps the script from blocking on credit.
                server_params(&mut server, |p| p.initial_window = 4 * 1024 * 1024);
                let mut p = Pair::new(client_config(1), server);
                p.pump().await;
                p.drain_events(Side::Client);
                p.drain_events(Side::Server);
                let (client_sink, server_sink) = install_sinks(&mut p);

                let id = p.client.open(policy()).unwrap();
                for msg in &msgs {
                    send(&mut p.client, id, msg);
                }
                p.pump().await;

                let wire = data_payload_bytes(&p, Side::Client);
                prop_assert_eq!(client_sink.totals(id).1, wire);
                prop_assert_eq!(server_sink.totals(id).0, wire);
                Ok(())
            })
            .unwrap();
    }
}
