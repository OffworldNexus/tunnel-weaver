use std::time::{Duration, Instant};
use weaver_mux::testing::{Ed25519TestSigner, FakeClock, MapVerifier};
use weaver_mux::{Class, Compress, Config, Connection, Event, Signer as _};

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
    async fn new(bytes_per_tick: usize) -> Self {
        let clock = FakeClock::at(Instant::now());
        let now = clock.now();

        let signer = Ed25519TestSigner::from_seed(7);
        let verifier = Box::new(MapVerifier::with_key(signer.key_id(), signer.public_key()));
        let client_cfg = Config::client(
            Box::new(signer),
            "weaver.test".to_string(),
            Box::new(weaver_mux::testing::SeededRng::new(42)),
        );
        let client = Connection::new(client_cfg, now);

        let mut server_cfg = Config::server(
            verifier,
            "weaver.test".to_string(),
            Box::new(weaver_mux::testing::SeededRng::new(43)),
        );
        server_cfg.server_params_mut().unwrap().initial_window = 4 * 1024 * 1024;
        let server = Connection::new(server_cfg, now);

        let mut pipe = Self {
            client,
            server,
            clock,
            bytes_per_tick,
            c_to_s: Vec::new(),
            s_to_c: Vec::new(),
        };

        pipe.step_until_authenticated().await;
        pipe
    }

    async fn step_until_authenticated(&mut self) {
        let mut c_auth = false;
        let mut s_auth = false;
        for _ in 0..100 {
            self.tick().await;
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

    async fn tick(&mut self) {
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
            let _ = self.server.recv(now, &frame).await;
        }

        let mut budget_s = self.bytes_per_tick;
        while !self.s_to_c.is_empty() && budget_s > 0 {
            let frame = self.s_to_c.remove(0);
            budget_s = budget_s.saturating_sub(frame.len());
            let _ = self.client.recv(now, &frame).await;
        }

        self.client.handle_timeout(now).await;
        self.server.handle_timeout(now).await;
    }
}

#[tokio::test]
async fn test_concurrent_small_requests_during_50mb_bulk_transfer() {
    let bytes_per_tick = 64 * 1024;
    let mut pipe = ThrottledPipe::new(bytes_per_tick).await;

    // 1. Measure unloaded baseline latency for 20 small requests
    let mut baseline_latencies = Vec::new();
    for _ in 0..20 {
        let start_tick = pipe.clock.now();
        let stream = pipe.client.open(Class::Interactive).unwrap();

        let _ = pipe
            .client
            .send(stream, b"GET /hello HTTP/1.1\r\n\r\n", Compress::Never);
        let _ = pipe.client.finish(stream);

        let mut finished = false;
        for _ in 0..100 {
            pipe.tick().await;
            while let Some(ev) = pipe.server.poll_event() {
                if let Event::StreamOpened { id, .. } = ev {
                    let _ = pipe
                        .server
                        .send(id, b"HTTP/1.1 200 OK\r\n\r\n", Compress::Never);
                    let _ = pipe.server.finish(id);
                }
            }
            while let Some(ev) = pipe.client.poll_event() {
                match ev {
                    // Finished fires only once the inbox is drained.
                    Event::Readable(id) => while pipe.client.recv_msg(id).is_ok() {},
                    Event::Finished(id) if id == stream => {
                        finished = true;
                        break;
                    }
                    _ => {}
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
    let bulk_stream = pipe.client.open(Class::Bulk).unwrap();

    let chunk = vec![0xaa; 32 * 1024];
    let _ = pipe.client.send(bulk_stream, &chunk, Compress::Never);

    // 3. Inject 20 small requests during active bulk transfer
    let mut loaded_latencies = Vec::new();
    for _ in 0..20 {
        let _ = pipe.client.send(bulk_stream, &chunk, Compress::Never);

        let start_tick = pipe.clock.now();
        let small_stream = pipe.client.open(Class::Interactive).unwrap();

        let _ = pipe.client.send(
            small_stream,
            b"GET /small HTTP/1.1\r\n\r\n",
            Compress::Never,
        );
        let _ = pipe.client.finish(small_stream);

        let mut finished = false;
        for _ in 0..100 {
            let _ = pipe.client.send(bulk_stream, &chunk, Compress::Never);
            pipe.tick().await;

            while let Some(ev) = pipe.server.poll_event() {
                if let Event::StreamOpened { id, .. } = ev
                    && id != bulk_stream
                {
                    let _ = pipe
                        .server
                        .send(id, b"HTTP/1.1 200 OK\r\n\r\n", Compress::Never);
                    let _ = pipe.server.finish(id);
                }
            }
            while let Some(ev) = pipe.client.poll_event() {
                match ev {
                    Event::Readable(id) => while pipe.client.recv_msg(id).is_ok() {},
                    Event::Finished(id) if id == small_stream => {
                        finished = true;
                        break;
                    }
                    _ => {}
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
