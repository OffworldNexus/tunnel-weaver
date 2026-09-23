//! Driver liveness under sustained load.
//!
//! Regression for a real outage: during a long bulk transfer the sending
//! side's `flush` loop never returned to `select!`, so it neither answered
//! the peer's PINGs nor sent its own, and the peer dropped the connection
//! with `CloseCode::Timeout` after `idle_timeout`. The driver must keep the
//! keepalive exchange alive no matter how much data the scheduler has
//! queued.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::{Sink, Stream};
use tokio::sync::mpsc;
use weaver_mux::testing::{Ed25519TestSigner, MapVerifier, SeededRng};
use weaver_mux::{Class, CloseCode, Compress, Config, Connection, Event, Signer as _, StreamId};
use weaver_tokio::{Driver, StreamHandler};

const SERVER_NAME: &str = "mux.example.test";

/// One direction of an in-memory duplex: frames go into `tx`, come out of
/// `rx`. Bounded so a saturating sender actually experiences backpressure,
/// and *rate-limited* so that, like a real WAN socket, each send can sit
/// pending for a while — that is the condition under which a flush loop
/// that never yields to input starves the keepalive.
struct Pipe {
    tx: mpsc::Sender<Bytes>,
    rx: mpsc::Receiver<Bytes>,
    pending: Option<Bytes>,
    /// Minimum spacing between frames leaving this side.
    pace: Duration,
    next_slot: Option<Pin<Box<tokio::time::Sleep>>>,
}

fn duplex(capacity: usize, pace: Duration) -> (Pipe, Pipe) {
    let (a_tx, a_rx) = mpsc::channel(capacity);
    let (b_tx, b_rx) = mpsc::channel(capacity);
    (
        Pipe {
            tx: a_tx,
            rx: b_rx,
            pending: None,
            pace,
            next_slot: None,
        },
        Pipe {
            tx: b_tx,
            rx: a_rx,
            pending: None,
            pace,
            next_slot: None,
        },
    )
}

#[derive(Debug)]
struct PipeClosed;
impl std::fmt::Display for PipeClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("pipe closed")
    }
}
impl std::error::Error for PipeClosed {}

impl Stream for Pipe {
    type Item = Result<Option<Bytes>, PipeClosed>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx).map(|o| o.map(|b| Ok(Some(b))))
    }
}

impl Sink<Bytes> for Pipe {
    type Error = PipeClosed;
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), PipeClosed>> {
        let this = &mut *self;
        if let Some(b) = this.pending.take() {
            // Pace: the frame leaves only once its slot timer has fired.
            if this.next_slot.is_none() {
                this.next_slot = Some(Box::pin(tokio::time::sleep(this.pace)));
            }
            if this
                .next_slot
                .as_mut()
                .unwrap()
                .as_mut()
                .poll(cx)
                .is_pending()
            {
                this.pending = Some(b);
                return Poll::Pending;
            }
            match this.tx.try_reserve() {
                Ok(permit) => {
                    permit.send(b);
                    this.next_slot = None;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Poll::Ready(Err(PipeClosed));
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    this.pending = Some(b);
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
        }
        Poll::Ready(Ok(()))
    }
    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), PipeClosed> {
        let this = &mut *self;
        assert!(this.pending.is_none(), "start_send without poll_ready");
        this.pending = Some(item);
        Ok(())
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), PipeClosed>> {
        self.poll_ready(cx)
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), PipeClosed>> {
        self.poll_flush(cx)
    }
}

/// Client: once authenticated, opens one bulk stream and keeps it saturated
/// (re-filling on every `Writable`) until told to stop.
struct Flood {
    stream: Option<StreamId>,
    sent: u64,
    stop_after: u64,
    payload: Vec<u8>,
}

impl StreamHandler for Flood {
    fn on_event(&mut self, conn: &mut Connection, event: Event) {
        match event {
            Event::Authenticated { .. } => {
                let id = conn.open(Class::Bulk).unwrap();
                self.stream = Some(id);
                self.fill(conn);
            }
            Event::Writable { .. } => self.fill(conn),
            _ => {}
        }
    }
}

impl Flood {
    fn fill(&mut self, conn: &mut Connection) {
        let Some(id) = self.stream else { return };
        while self.sent < self.stop_after {
            match conn.send(id, &self.payload, Compress::Never) {
                Ok(()) => self.sent += self.payload.len() as u64,
                Err(_) => return,
            }
        }
        if self.sent >= self.stop_after {
            let _ = conn.finish(id);
            self.stream = None;
        }
    }
}

/// Server: drains whatever arrives and records how it was closed.
#[derive(Default)]
struct Sink_ {
    received: u64,
    closed: Option<CloseCode>,
}

impl StreamHandler for Sink_ {
    fn on_event(&mut self, conn: &mut Connection, event: Event) {
        match event {
            Event::Readable(id) => {
                while let Ok(msg) = conn.recv_msg(id) {
                    self.received += msg.len() as u64;
                }
            }
            Event::Closed { reason } => self.closed = Some(reason.code),
            _ => {}
        }
    }
}

fn configs() -> (Config, Config) {
    let signer = Ed25519TestSigner::from_seed(7);
    let verifier = MapVerifier::with_key(signer.key_id(), signer.public_key());
    let mut client = Config::client(Box::new(signer), SERVER_NAME, Box::new(SeededRng::new(1)));
    let mut server = Config::server(Box::new(verifier), SERVER_NAME, Box::new(SeededRng::new(2)));
    // Tight keepalive so the test runs in seconds: PING every 200 ms, drop
    // the peer after 800 ms of silence. The flood lasts well over 800 ms.
    for cfg in [&mut client, &mut server] {
        cfg.ping_interval = Duration::from_millis(200);
        cfg.idle_timeout = Duration::from_millis(800);
    }
    (client, server)
}

#[tokio::test]
async fn keepalives_survive_a_saturating_bulk_send() {
    let (client_cfg, server_cfg) = configs();
    // Small pipe so the sender is permanently backlogged.
    // 2 ms per frame ≈ 8 MB/s of 16 KiB frames: a fast link, but each send
    // still parks, which is what exposes a flush loop that never yields.
    let (client_pipe, server_pipe) = duplex(1, Duration::from_millis(50));

    let payload = vec![0xA5u8; 16 * 1024];
    let flood = Flood {
        stream: None,
        sent: 0,
        // ~3 s of transfer at the pipe's pace: several idle_timeouts.
        stop_after: 8 * 1024 * 1024,
        payload,
    };
    let client = Driver::new(
        Connection::new(client_cfg, Instant::now()),
        client_pipe,
        flood,
    );
    let server = Driver::new(
        Connection::new(server_cfg, Instant::now()),
        server_pipe,
        Sink_::default(),
    );
    let client_handle = client.handle();

    let server_task = tokio::spawn(server.run());
    let client_task = tokio::spawn(client.run());

    // Let the flood run through several keepalive periods, then shut the
    // client down cleanly.
    tokio::time::sleep(Duration::from_secs(3)).await;
    client_handle.close(weaver_mux::CloseReason::new(CloseCode::Shutdown));

    let (flood, client_res) = tokio::time::timeout(Duration::from_secs(10), client_task)
        .await
        .expect("client driver hung")
        .unwrap();
    let (sink, server_res) = tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .expect("server driver hung")
        .unwrap();

    eprintln!(
        "flood sent={} server received={} server_closed={:?} server_res={:?} client_res={:?}",
        flood.sent, sink.received, sink.closed, server_res, client_res
    );
    assert!(
        flood.sent > 256 * 1024,
        "flood barely ran: {} bytes",
        flood.sent
    );
    assert!(sink.received > 0);
    // The whole point: nobody timed out. The server is the side that would
    // drop us (`idle_timeout`); its recorded close reason is the verdict.
    assert_ne!(
        sink.closed,
        Some(CloseCode::Timeout),
        "server dropped the client for idleness while it was flooding: {server_res:?}"
    );
    assert_eq!(sink.closed, Some(CloseCode::Shutdown), "{server_res:?}");
}

/// The mirror image of the flood test: the *receiving* side of a saturating
/// transfer must keep pinging and pong'ing too. Here the server floods the
/// client (a big download through the tunnel), the client only ever
/// receives, and neither side may drop the other for idleness.
#[tokio::test]
async fn keepalives_survive_a_saturating_bulk_receive() {
    let (client_cfg, server_cfg) = configs();
    let (client_pipe, server_pipe) = duplex(1, Duration::from_millis(50));

    // Server floods once the client opens a stream toward it; simplest is a
    // server-side handler that opens the stream itself after auth.
    let flood = Flood {
        stream: None,
        sent: 0,
        stop_after: 8 * 1024 * 1024,
        payload: vec![0x5Au8; 16 * 1024],
    };
    let server = Driver::new(
        Connection::new(server_cfg, Instant::now()),
        server_pipe,
        flood,
    );
    let client = Driver::new(
        Connection::new(client_cfg, Instant::now()),
        client_pipe,
        Sink_::default(),
    );
    let client_handle = client.handle();
    let server_task = tokio::spawn(server.run());
    let client_task = tokio::spawn(client.run());

    tokio::time::sleep(Duration::from_secs(3)).await;
    client_handle.close(weaver_mux::CloseReason::new(CloseCode::Shutdown));

    let (sink, client_res) = tokio::time::timeout(Duration::from_secs(10), client_task)
        .await
        .expect("client driver hung")
        .unwrap();
    let (flood, server_res) = tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .expect("server driver hung")
        .unwrap();
    eprintln!(
        "server sent={} client received={} client_closed={:?} client_res={:?} server_res={:?}",
        flood.sent, sink.received, sink.closed, client_res, server_res
    );
    assert!(sink.received > 256 * 1024, "receiver barely ran");
    assert_ne!(
        sink.closed,
        Some(CloseCode::Timeout),
        "receiver timed out mid-download"
    );
    assert!(
        !matches!(&server_res, Ok(r) if r.code == CloseCode::Timeout),
        "sender saw Timeout: {server_res:?}"
    );
    assert_eq!(sink.closed, Some(CloseCode::Shutdown));
}
