use std::time::{Duration, Instant};
use weaver_mux::testing::FakeClock;
use weaver_mux::wire::Head;
use weaver_mux::{Config, Connection, Event, Hints, SignError};
use weaver_proto::poc::{POC_KEY_ID, POC_PUBLIC_KEY, POC_SECRET_KEY};

struct InProcessPocSigner {
    key: ed25519_dalek::SigningKey,
}

impl weaver_mux::auth::Signer for InProcessPocSigner {
    fn key_id(&self) -> weaver_mux::KeyId {
        POC_KEY_ID
    }
    fn sign(&mut self, msg: &[u8]) -> Result<weaver_mux::wire::Signature, SignError> {
        use ed25519_dalek::Signer;
        let sig: ed25519_dalek::Signature = self.key.sign(msg);
        Ok(weaver_mux::wire::Signature::Ed25519(sig.to_bytes()))
    }
}

struct InProcessPocVerifier;

impl weaver_mux::auth::Verifier for InProcessPocVerifier {
    fn public_key(&mut self, key_id: &weaver_mux::KeyId) -> Option<weaver_mux::auth::PublicKey> {
        if key_id == &POC_KEY_ID {
            Some(weaver_mux::auth::PublicKey::Ed25519(POC_PUBLIC_KEY))
        } else {
            None
        }
    }
}

/// A simulated throttled duplex pipe between client and server.
struct ThrottledPipe {
    client: Connection,
    server: Connection,
    clock: FakeClock,
    bytes_per_tick: usize,
    c_to_s: Vec<Vec<u8>>,
    s_to_c: Vec<Vec<u8>>,
}

impl ThrottledPipe {
    fn new(bytes_per_tick: usize) -> Self {
        let clock = FakeClock::at(Instant::now());
        let now = clock.now();

        let signer = Box::new(InProcessPocSigner {
            key: ed25519_dalek::SigningKey::from_bytes(&POC_SECRET_KEY),
        });
        let client_cfg = Config::client(
            signer,
            "weaver.test".to_string(),
            Box::new(weaver_mux::testing::SeededRng::new(42)),
        );
        let client = Connection::new(client_cfg, now);

        let verifier = Box::new(InProcessPocVerifier);
        let mut server_cfg = Config::server(
            verifier,
            "weaver.test".to_string(),
            Box::new(weaver_mux::testing::SeededRng::new(43)),
        );
        server_cfg.initial_window = 4 * 1024 * 1024;
        let server = Connection::new(server_cfg, now);

        let mut pipe = Self {
            client,
            server,
            clock,
            bytes_per_tick,
            c_to_s: Vec::new(),
            s_to_c: Vec::new(),
        };

        pipe.step_until_authenticated();
        pipe
    }

    fn step_until_authenticated(&mut self) {
        let mut c_auth = false;
        let mut s_auth = false;
        for _ in 0..100 {
            self.tick();
            while let Some(ev) = self.client.poll_event() {
                if matches!(ev, Event::Authenticated { .. }) {
                    c_auth = true;
                }
            }
            while let Some(ev) = self.server.poll_event() {
                if matches!(ev, Event::Authenticated { .. }) {
                    s_auth = true;
                }
            }
            if c_auth && s_auth {
                break;
            }
        }
        assert!(c_auth && s_auth, "Both client and server must authenticate");
    }

    fn tick(&mut self) {
        let now = self.clock.advance(Duration::from_millis(10));
        let mut buf = Vec::with_capacity(64 * 1024);

        while self.client.poll_transmit(now, &mut buf) {
            self.c_to_s.push(std::mem::take(&mut buf));
        }

        while self.server.poll_transmit(now, &mut buf) {
            self.s_to_c.push(std::mem::take(&mut buf));
        }

        let mut budget_c = self.bytes_per_tick;
        while !self.c_to_s.is_empty() && budget_c > 0 {
            let frame = self.c_to_s.remove(0);
            budget_c = budget_c.saturating_sub(frame.len());
            let _ = self.server.recv(now, &frame);
        }

        let mut budget_s = self.bytes_per_tick;
        while !self.s_to_c.is_empty() && budget_s > 0 {
            let frame = self.s_to_c.remove(0);
            budget_s = budget_s.saturating_sub(frame.len());
            let _ = self.client.recv(now, &frame);
        }

        self.client.handle_timeout(now);
        self.server.handle_timeout(now);
    }
}

#[test]
fn test_concurrent_small_requests_during_50mb_bulk_transfer() {
    let bytes_per_tick = 64 * 1024;
    let mut pipe = ThrottledPipe::new(bytes_per_tick);

    // 1. Measure unloaded baseline latency for 20 small requests
    let mut baseline_latencies = Vec::new();
    for _ in 0..20 {
        let start_tick = pipe.clock.now();
        let stream = pipe
            .client
            .open(Head {
                hints: Hints::default(),
                opaque: vec![],
            })
            .unwrap();

        let _ = pipe.client.write(stream, b"GET /hello HTTP/1.1\r\n\r\n");
        let _ = pipe.client.finish(stream);

        let mut finished = false;
        for _ in 0..100 {
            pipe.tick();
            while let Some(ev) = pipe.server.poll_event() {
                if let Event::StreamOpened { id, .. } = ev {
                    let _ = pipe.server.write(id, b"HTTP/1.1 200 OK\r\n\r\n");
                    let _ = pipe.server.finish(id);
                }
            }
            while let Some(ev) = pipe.client.poll_event() {
                if let Event::Finished(id) = ev
                    && id == stream
                {
                    finished = true;
                    break;
                }
            }
            if finished {
                break;
            }
        }
        assert!(finished);
        let elapsed = pipe.clock.now().duration_since(start_tick).as_millis();
        baseline_latencies.push(elapsed);
    }

    baseline_latencies.sort();
    let p99_baseline = baseline_latencies[(baseline_latencies.len() as f64 * 0.95) as usize];

    // 2. Start an active 50 MB bulk transfer
    let bulk_size = 50 * 1024 * 1024;
    let bulk_stream = pipe
        .client
        .open(Head {
            hints: Hints {
                content_length: Some(bulk_size as u64),
                ..Hints::default()
            },
            opaque: vec![],
        })
        .unwrap();

    let chunk = vec![0xaa; 32 * 1024];
    let _ = pipe.client.write(bulk_stream, &chunk);

    // 3. Inject 20 small requests during active bulk transfer
    let mut loaded_latencies = Vec::new();
    for _ in 0..20 {
        let _ = pipe.client.write(bulk_stream, &chunk);

        let start_tick = pipe.clock.now();
        let small_stream = pipe
            .client
            .open(Head {
                hints: Hints::default(),
                opaque: vec![],
            })
            .unwrap();

        let _ = pipe
            .client
            .write(small_stream, b"GET /small HTTP/1.1\r\n\r\n");
        let _ = pipe.client.finish(small_stream);

        let mut finished = false;
        for _ in 0..100 {
            let _ = pipe.client.write(bulk_stream, &chunk);
            pipe.tick();

            while let Some(ev) = pipe.server.poll_event() {
                if let Event::StreamOpened { id, .. } = ev
                    && id != bulk_stream
                {
                    let _ = pipe.server.write(id, b"HTTP/1.1 200 OK\r\n\r\n");
                    let _ = pipe.server.finish(id);
                }
            }
            while let Some(ev) = pipe.client.poll_event() {
                if let Event::Finished(id) = ev
                    && id == small_stream
                {
                    finished = true;
                    break;
                }
            }
            if finished {
                break;
            }
        }
        assert!(finished, "Small request should finish under bulk load");
        let elapsed = pipe.clock.now().duration_since(start_tick).as_millis();
        loaded_latencies.push(elapsed);
    }

    loaded_latencies.sort();
    let p99_loaded = loaded_latencies[(loaded_latencies.len() as f64 * 0.95) as usize];

    assert!(
        p99_loaded as f64 <= 2.0 * p99_baseline as f64,
        "p99 loaded latency ({p99_loaded}ms) should be <= 2x baseline ({p99_baseline}ms)"
    );
}
