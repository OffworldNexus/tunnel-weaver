//! Scheduler behaviour on a simulated fixed-rate pipe.
//!
//! The pipe moves at most `RATE` wire bytes per tick from client to
//! server; frames are indivisible, so a tick may carry several small
//! frames or wait for one large one. Time is fake and only advances by
//! ticks, so every measurement is deterministic.

mod common;

use std::collections::HashMap;
use std::time::Duration;

use common::*;
use proptest::prelude::*;
use weaver_mux::{Class, CloseCode, CloseReason, Compress, Event, Frame, FrameType, StreamId};

/// Wire bytes per tick.
const RATE: u32 = 64 * 1024;
const TICK: Duration = Duration::from_millis(10);
const MAX_FRAME: u32 = 16 * 1024;
/// Roughly one frame's worth of pipe time, in ticks (RATE / MAX_FRAME = 4
/// frames per tick, so "one frame time" is a quarter tick; we round up).
const FRAME_TIME_TICKS: u64 = 1;

fn noise(n: usize, salt: u32) -> Vec<u8> {
    (0..n as u32)
        .map(|i| (i.wrapping_add(salt).wrapping_mul(2654435761) >> 13) as u8)
        .collect()
}

struct Sim {
    p: Pair,
    /// Bytes delivered per stream.
    delivered: HashMap<StreamId, u64>,
    /// Tick at which each DATA frame of each stream was delivered.
    frame_ticks: HashMap<StreamId, Vec<u64>>,
    /// Client frames in wire order (type, stream id, tick).
    trace: Vec<(FrameType, StreamId, u64)>,
    tick: u64,
    /// Streams the client keeps saturated with this payload.
    feed: Vec<(StreamId, Vec<u8>)>,
}

impl Sim {
    fn new() -> Self {
        Self::with_threshold(None)
    }

    /// `bulk_threshold` for the client; `None` pins every class.
    fn with_threshold(bulk_threshold: Option<u64>) -> Self {
        let mut server = server_config(1);
        server_params(&mut server, |p| {
            p.max_frame = MAX_FRAME;
            // Generous window so credit never throttles the scheduler.
            p.initial_window = 4 * 1024 * 1024;
        });
        let mut client = client_config(1);
        client.bulk_threshold = bulk_threshold;
        let mut p = Pair::new(client, server);
        p.pump();
        p.drain_events(Side::Client);
        p.drain_events(Side::Server);
        Self {
            p,
            delivered: HashMap::new(),
            frame_ticks: HashMap::new(),
            trace: Vec::new(),
            tick: 0,
            feed: Vec::new(),
        }
    }

    fn open(&mut self, class: Class) -> StreamId {
        self.p.client.open(class).unwrap()
    }

    /// Keep this stream's outbox full for the rest of the simulation.
    fn saturate(&mut self, id: StreamId) {
        self.feed.push((id, noise(MAX_FRAME as usize * 4, id)));
    }

    fn top_up(&mut self) {
        for (id, data) in &self.feed {
            // Fill until the crate refuses (credit/outbox bound); ignore
            // errors for streams that were reset or finished.
            for _ in 0..8 {
                match self.p.client.send(*id, data, Compress::Never) {
                    Ok(()) => continue,
                    Err(_) => break,
                }
            }
        }
    }

    /// One tick of the pipe: up to RATE bytes client → server, then let the
    /// server drain everything it wants to send back (WINDOW_UPDATEs) and
    /// read every stream so the sender never runs out of credit.
    fn tick(&mut self) {
        self.top_up();
        let now = self.p.clock.now();
        let mut budget = RATE as i64;
        let mut buf = Vec::new();
        while budget > 0 && self.p.client.poll_transmit(now, &mut buf) {
            let f = Frame::parse(&buf).unwrap();
            budget -= f.wire_len() as i64;
            let _ = self.p.server.recv(now, &buf);
            self.trace.push((f.frame_type, f.stream_id, self.tick));
            if f.frame_type == FrameType::Data {
                *self.delivered.entry(f.stream_id).or_default() += f.payload.len() as u64;
                self.frame_ticks
                    .entry(f.stream_id)
                    .or_default()
                    .push(self.tick);
            }
        }
        // Server side: read everything, return credit.
        let ids: Vec<StreamId> = self.delivered.keys().copied().collect();
        for id in ids {
            let _ = read_all(&mut self.p.server, id);
        }
        while self.p.step(Side::Server).is_some() {}
        self.p.drain_events(Side::Server);
        self.p.drain_events(Side::Client);
        self.tick += 1;
        let t = self.p.clock.advance(TICK);
        self.p.client.handle_timeout(t);
        self.p.server.handle_timeout(t);
    }

    fn run(&mut self, ticks: u64) {
        for _ in 0..ticks {
            self.tick();
        }
    }

    fn delivered(&self, id: StreamId) -> u64 {
        self.delivered.get(&id).copied().unwrap_or(0)
    }

    fn total(&self) -> u64 {
        self.delivered.values().sum()
    }
}

#[test]
fn lone_bulk_stream_gets_full_rate() {
    let mut s = Sim::new();
    let bulk = s.open(Class::Bulk);
    assert_eq!(s.p.client.class_of(bulk), Some(Class::Bulk));
    s.saturate(bulk);
    s.run(50);
    // Every tick moved (almost) a full RATE of bulk payload: 4 frames of
    // 16 KiB minus headers/flags.
    let per_tick = s.delivered(bulk) as f64 / 50.0;
    assert!(
        per_tick > RATE as f64 * 0.98,
        "bulk got {per_tick} B/tick of {RATE}"
    );
}

#[test]
fn class_shares_converge_to_weights() {
    let mut s = Sim::new();
    let rt = s.open(Class::Realtime);
    let small = s.open(Class::Interactive);
    let bulk = s.open(Class::Bulk);
    for id in [rt, small, bulk] {
        s.saturate(id);
    }
    s.run(400);
    let total = s.total() as f64;
    let expect = |w: f64| total * w / (300.0 + 300.0 + 40.0);
    for (id, w) in [(rt, 300.0), (small, 300.0), (bulk, 40.0)] {
        let got = s.delivered(id) as f64;
        let err = (got - expect(w)).abs() / expect(w);
        assert!(err < 0.05, "stream {id} w={w}: {got} vs {}", expect(w));
    }
}

#[test]
fn equal_shares_within_a_class() {
    let mut s = Sim::new();
    let ids: Vec<_> = (0..4).map(|_| s.open(Class::Interactive)).collect();
    for &id in &ids {
        s.saturate(id);
    }
    s.run(200);
    let mean = s.total() as f64 / 4.0;
    for &id in &ids {
        let got = s.delivered(id) as f64;
        assert!(
            (got - mean).abs() / mean < 0.05,
            "stream {id}: {got} vs {mean}"
        );
    }
}

#[test]
fn bulk_keeps_flowing_under_interactive_load() {
    let mut s = Sim::new();
    let bulk = s.open(Class::Bulk);
    s.saturate(bulk);
    let smalls: Vec<_> = (0..8)
        .map(|_| {
            let id = s.open(Class::Interactive);
            s.p.client.set_class(id, Class::Interactive).unwrap();
            s.saturate(id);
            id
        })
        .collect();
    s.run(300);
    let ticks = &s.frame_ticks[&bulk];
    assert!(
        ticks.len() > 10,
        "bulk must keep flowing: {} frames",
        ticks.len()
    );
    // QFQ bound: a backlogged flow waits at most (W/w_k + 2) frame times.
    // W = 300 (small) + 40 (bulk) + 1000 (control, mostly idle); the control
    // weight is counted because QFQ's V advances over the registered sum.
    let w_total = 1000.0 + 300.0 + 300.0 + 40.0;
    let bound_frames = w_total / 40.0 + 2.0;
    let frames_per_tick = RATE as f64 / (MAX_FRAME as f64 + 5.0);
    let bound_ticks = (bound_frames / frames_per_tick).ceil() as u64;
    let max_gap = ticks.windows(2).map(|w| w[1] - w[0]).max().unwrap();
    assert!(
        max_gap <= bound_ticks,
        "bulk gap {max_gap} ticks > bound {bound_ticks}"
    );
    for id in smalls {
        assert!(s.delivered(id) > 0);
    }
}

#[test]
fn new_small_stream_is_served_promptly() {
    let mut s = Sim::new();
    let bulk = s.open(Class::Bulk);
    s.saturate(bulk);
    s.run(200); // bulk has been hogging the pipe for a while
    let small = s.open(Class::Interactive);
    s.p.client
        .send(small, &noise(MAX_FRAME as usize - 1, 9), Compress::Never)
        .unwrap();
    let start = s.tick;
    s.run(FRAME_TIME_TICKS + 1);
    let first = s.frame_ticks[&small][0];
    assert!(
        first - start <= FRAME_TIME_TICKS,
        "small waited {} ticks",
        first - start
    );
    assert!(s.delivered(small) >= MAX_FRAME as u64 - 1);
}

#[test]
fn interactive_demotes_to_bulk_at_threshold() {
    let threshold = 256 * 1024usize;
    let mut s = Sim::with_threshold(Some(threshold as u64));
    let id = s.open(Class::Interactive);
    assert_eq!(s.p.client.class_of(id), Some(Class::Interactive));
    s.p.client
        .send(id, &noise(threshold, 1), Compress::Never)
        .unwrap();
    assert_eq!(
        s.p.client.class_of(id),
        Some(Class::Interactive),
        "exactly at threshold stays"
    );
    s.p.client.send(id, b"x", Compress::Never).unwrap();
    assert_eq!(s.p.client.class_of(id), Some(Class::Bulk));
    // Other classes are never demoted.
    let rt = s.open(Class::Realtime);
    s.p.client
        .send(rt, &noise(threshold + 10, 2), Compress::Never)
        .unwrap();
    assert_eq!(s.p.client.class_of(rt), Some(Class::Realtime));
    // Control is not a valid target.
    assert!(s.p.client.set_class(rt, Class::Control).is_err());
    // Without a threshold nothing is demoted.
    let mut s = Sim::with_threshold(None);
    let id = s.open(Class::Interactive);
    s.p.client
        .send(id, &noise(threshold + 10, 3), Compress::Never)
        .unwrap();
    assert_eq!(s.p.client.class_of(id), Some(Class::Interactive));
}

#[test]
fn reclassification_takes_effect_on_next_selection() {
    let mut s = Sim::new();
    let a = s.open(Class::Interactive);
    let b = s.open(Class::Interactive);
    s.saturate(a);
    s.saturate(b);
    s.run(50);
    let (a0, b0) = (s.delivered(a), s.delivered(b));
    // Demote b: from now on a should get ~300/340 of the pipe.
    s.p.client.set_class(b, Class::Bulk).unwrap();
    s.run(200);
    let (da, db) = ((s.delivered(a) - a0) as f64, (s.delivered(b) - b0) as f64);
    let share_a = da / (da + db);
    assert!((share_a - 300.0 / 340.0).abs() < 0.05, "a share {share_a}");
}

#[test]
fn control_frames_are_not_starved_by_data() {
    let mut s = Sim::new();
    let bulk = s.open(Class::Bulk);
    s.saturate(bulk);
    s.run(20);
    // Queue a PING behind a full outbox by advancing past ping_interval.
    let t = s.p.clock.advance(Duration::from_secs(15));
    s.p.client.handle_timeout(t);
    let before = s.trace.len();
    s.tick();
    let ping_pos = s.trace[before..]
        .iter()
        .position(|(t, _, _)| *t == FrameType::Ping)
        .expect("PING emitted within the tick");
    // Control has weight 1000 vs bulk 40 and a tiny frame: QFQ makes it
    // eligible immediately, so it goes out first.
    assert_eq!(
        ping_pos,
        0,
        "PING should be the next frame: {:?}",
        &s.trace[before..before + 3]
    );

    // Same for RST of another stream while bulk is saturated.
    let victim = s.open(Class::Interactive);
    s.tick();
    s.p.client.reset(victim, 1).unwrap();
    let before = s.trace.len();
    s.tick();
    let rst_pos = s.trace[before..]
        .iter()
        .position(|(t, id, _)| *t == FrameType::Rst && *id == victim)
        .unwrap();
    assert_eq!(rst_pos, 0);
}

#[test]
fn goaway_is_the_very_next_frame() {
    let mut s = Sim::new();
    let bulk = s.open(Class::Bulk);
    s.saturate(bulk);
    s.run(20);
    s.p.client.close(CloseReason::new(CloseCode::Shutdown));
    let now = s.p.clock.now();
    let mut buf = Vec::new();
    assert!(s.p.client.poll_transmit(now, &mut buf));
    assert_eq!(Frame::parse(&buf).unwrap().frame_type, FrameType::Goaway);
    assert!(s.p.client.poll_transmit(now, &mut buf));
    let f = Frame::parse(&buf).unwrap();
    assert_eq!((f.frame_type, f.stream_id), (FrameType::Rst, bulk));
    assert!(
        !s.p.client.poll_transmit(now, &mut buf),
        "no DATA after close"
    );
    assert!(matches!(
        s.p.drain_events(Side::Client).last(),
        Some(Event::Closed { reason }) if reason.code == CloseCode::Shutdown
    ));
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 8,
        ..ProptestConfig::default()
    })]

    /// Random weights, one saturated stream per class: shares track the
    /// configured weights within 5%.
    #[test]
    fn shares_track_arbitrary_weights(
        w_rt in 50u32..=1000,
        w_small in 50u32..=1000,
        w_bulk in 20u32..=1000,
    ) {
        let mut server = server_config(1);
        server_params(&mut server, |p| {
            p.max_frame = MAX_FRAME;
            p.initial_window = 4 * 1024 * 1024;
        });
        let mut client = client_config(1);
        client.weights.realtime = w_rt;
        client.weights.interactive = w_small;
        client.weights.bulk = w_bulk;
        client.bulk_threshold = None;
        let mut p = Pair::new(client, server);
        p.pump();
        p.drain_events(Side::Client);
        p.drain_events(Side::Server);
        let mut s = Sim {
            p,
            delivered: HashMap::new(),
            frame_ticks: HashMap::new(),
            trace: Vec::new(),
            tick: 0,
            feed: Vec::new(),
        };
        let rt = s.open(Class::Realtime);
        let small = s.open(Class::Interactive);
        let bulk = s.open(Class::Bulk);
        for id in [rt, small, bulk] {
            s.saturate(id);
        }
        s.run(300);
        let total = s.total() as f64;
        let wsum = f64::from(w_rt + w_small + w_bulk);
        for (id, w) in [(rt, w_rt), (small, w_small), (bulk, w_bulk)] {
            let expected = total * f64::from(w) / wsum;
            let got = s.delivered(id) as f64;
            // Allow 5% plus a few frames: QFQ bounds the lag of a flow to a
            // constant number of packets, which for a tiny share is a large
            // fraction of a short run.
            prop_assert!(
                (got - expected).abs() <= 0.05 * expected + 3.0 * f64::from(MAX_FRAME),
                "stream {id} w={w}: got {got} expected {expected}"
            );
        }
    }
}
