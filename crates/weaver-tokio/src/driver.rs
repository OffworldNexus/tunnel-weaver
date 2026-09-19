//! The event loop that pumps a [`Connection`] over a [`Transport`].

use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, trace};
use weaver_mux::{CloseCode, CloseReason, Connection, Event, ProtocolError};

use crate::ws::Transport;

/// Application logic plugged into a [`Driver`].
///
/// Called from inside the event loop with exclusive access to the
/// connection, so every method is synchronous and must not block: do
/// async work in a spawned task and come back through a [`Handle`], whose
/// commands receive both the connection and the handler.
pub trait StreamHandler: Send + 'static {
    /// One mux event. Typical reactions: `Authenticated` → open streams;
    /// `StreamOpened` → remember the stream; `Readable(id)` → loop
    /// `conn.recv_msg(id)` until `WouldBlock`; `Writable { id, .. }` →
    /// retry the message that got `WouldBlock`.
    fn on_event(&mut self, conn: &mut Connection, event: Event);
}

type Command<H> = Box<dyn FnOnce(&mut Connection, &mut H) + Send>;

/// Cloneable handle other tasks use to act on the connection and the
/// handler from inside the driver's loop.
pub struct Handle<H> {
    tx: mpsc::Sender<Command<H>>,
}

impl<H> Clone for Handle<H> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

impl<H: StreamHandler> Handle<H> {
    /// Run `f` on the connection and handler at the next loop iteration.
    /// Silently dropped if the driver has already finished.
    pub fn spawn_on(&self, f: impl FnOnce(&mut Connection, &mut H) + Send + 'static) {
        let _ = self.tx.try_send(Box::new(f));
    }

    /// Run `f` and await its result. `None` if the driver finished first.
    pub async fn call<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection, &mut H) -> R + Send + 'static,
    ) -> Option<R> {
        let (tx, rx) = oneshot::channel();
        let cmd: Command<H> = Box::new(move |conn, h| {
            let _ = tx.send(f(conn, h));
        });
        if self.tx.send(cmd).await.is_err() {
            return None;
        }
        rx.await.ok()
    }

    /// Tear the connection down with the given reason.
    pub fn close(&self, reason: CloseReason) {
        self.spawn_on(move |conn, _| conn.close(reason));
    }
}

/// Why [`Driver::run`] returned before the mux closed cleanly.
#[derive(Debug, Error)]
pub enum DriverError {
    /// The transport ended (peer hung up) before a GOAWAY.
    #[error("transport closed by peer")]
    TransportClosed,
    /// The transport failed.
    #[error("transport error: {0}")]
    Transport(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The peer violated the mux protocol; the mux queued its GOAWAY,
    /// which the driver flushed before returning.
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
}

/// Pumps one [`Connection`] over one [`Transport`] with one handler.
pub struct Driver<T, H> {
    conn: Connection,
    transport: T,
    handler: H,
    cmd_rx: mpsc::Receiver<Command<H>>,
    handle: Handle<H>,
    buf: Vec<u8>,
    /// Reason from the `Event::Closed` we forwarded, if any.
    last_close: Option<CloseReason>,
}

/// How long to sleep when the mux has no deadline armed.
const IDLE_WAKE: Duration = Duration::from_secs(60);

impl<T: Transport, H: StreamHandler> Driver<T, H> {
    /// Wrap a connection, a transport and the application handler.
    pub fn new(conn: Connection, transport: T, handler: H) -> Self {
        let (tx, cmd_rx) = mpsc::channel(256);
        Self {
            conn,
            transport,
            handler,
            cmd_rx,
            handle: Handle { tx },
            buf: Vec::with_capacity(64 * 1024),
            last_close: None,
        }
    }

    /// Handle for other tasks.
    pub fn handle(&self) -> Handle<H> {
        self.handle.clone()
    }

    /// Run until the connection closes. Returns the close reason on a
    /// clean mux-level close (either side's GOAWAY) or the transport /
    /// protocol failure that ended things first. In every case the
    /// handler has seen `Event::Closed` and any outgoing GOAWAY has been
    /// flushed. The handler is returned alongside so callers can inspect
    /// its final state.
    pub async fn run(mut self) -> (H, Result<CloseReason, DriverError>) {
        let result = self.run_inner().await;
        (self.handler, result)
    }

    async fn run_inner(&mut self) -> Result<CloseReason, DriverError> {
        let mut outcome: Option<Result<CloseReason, DriverError>> = None;
        loop {
            // Bytes out: one frame per poll, flushed before the next, so
            // the scheduler decides as late as possible.
            if let Err(e) = self.flush().await {
                self.finish(CloseReason::new(CloseCode::Shutdown));
                return Err(e);
            }
            if let Some(r) = outcome.take() {
                return r;
            }
            if self.conn.is_closed() {
                self.dispatch_events();
                return Ok(self.close_reason());
            }

            let now = Instant::now();
            let sleep_for = self
                .conn
                .next_timeout()
                .map_or(IDLE_WAKE, |t| t.saturating_duration_since(now));

            tokio::select! {
                _ = tokio::time::sleep(sleep_for) => {
                    self.conn.handle_timeout(Instant::now());
                }
                msg = self.transport.next() => match msg {
                    Some(Ok(Some(bytes))) => {
                        if let Err(e) = self.conn.recv(Instant::now(), &bytes) {
                            debug!(error = %e, "mux protocol error");
                            outcome = Some(Err(DriverError::Protocol(e)));
                        }
                    }
                    Some(Ok(None)) => {}
                    Some(Err(e)) => {
                        debug!(error = %e, "transport error");
                        self.finish(CloseReason::new(CloseCode::Shutdown));
                        return Err(DriverError::Transport(Box::new(e)));
                    }
                    None => {
                        trace!("transport closed");
                        self.finish(CloseReason::new(CloseCode::Shutdown));
                        return Err(DriverError::TransportClosed);
                    }
                },
                cmd = self.cmd_rx.recv() => {
                    if let Some(cmd) = cmd {
                        cmd(&mut self.conn, &mut self.handler);
                    }
                }
            }

            self.dispatch_events();
            if outcome.is_none() && self.conn.is_closed() {
                outcome = Some(Ok(self.close_reason()));
            }
        }
    }

    fn dispatch_events(&mut self) {
        while let Some(ev) = self.conn.poll_event() {
            if let Event::Closed { reason } = &ev {
                self.last_close = Some(reason.clone());
            }
            self.handler.on_event(&mut self.conn, ev);
        }
    }

    async fn flush(&mut self) -> Result<(), DriverError> {
        let now = Instant::now();
        while self.conn.poll_transmit(now, &mut self.buf) {
            let frame = Bytes::from(std::mem::take(&mut self.buf));
            self.transport
                .send(frame)
                .await
                .map_err(|e| DriverError::Transport(Box::new(e)))?;
        }
        Ok(())
    }

    /// The transport is gone: close the mux locally so the handler sees a
    /// terminal `Closed` and every stream gets its `Reset`.
    fn finish(&mut self, reason: CloseReason) {
        if !self.conn.is_closed() {
            self.conn.close(reason);
        }
        self.dispatch_events();
    }

    fn close_reason(&mut self) -> CloseReason {
        self.last_close
            .take()
            .unwrap_or(CloseReason::new(CloseCode::Shutdown))
    }
}
