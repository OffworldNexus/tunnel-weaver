//! Socket-level byte counting for the visitor edge.
//!
//! The browser leg must be measured where the bytes actually cross the
//! visitor socket, not reconstructed from body frames: that includes request
//! and response heads, HTTP/2 framing, and anything else hyper reads or
//! writes. [`CountingIo`] wraps the (decrypted) visitor stream and tallies
//! every byte read from the browser and written to it; [`ConnBytes`] holds
//! the shared counters and attributes the connection to the service it ends
//! up serving.
//!
//! Counting sits above TLS (the stream hyper sees), so it measures the HTTP
//! bytes the browser sent/received rather than TLS record framing.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Shared byte counters for one visitor connection.
///
/// `read` is `browser -> relay`, `written` is `relay -> browser`. The
/// `reported_*` pair tracks how much has already been handed to metering so a
/// long-lived connection can be sampled without double counting.
#[derive(Debug, Default)]
pub struct ConnBytes {
    read: AtomicU64,
    written: AtomicU64,
    reported_read: AtomicU64,
    reported_written: AtomicU64,
    /// `service.id` once a tunnel route has been resolved; `0` is unsigned.
    service_id: AtomicI32,
}

impl ConnBytes {
    /// Creates a zeroed counter set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attributes this connection to `service_id`. First writer wins: SNI must
    /// equal the request `Host`, so a visitor connection serves a single
    /// service in practice.
    pub fn set_service(&self, service_id: i32) {
        let _ =
            self.service_id
                .compare_exchange(0, service_id, Ordering::Relaxed, Ordering::Relaxed);
    }

    /// The service this connection is attributed to, or `0` if none.
    pub fn service_id(&self) -> i32 {
        self.service_id.load(Ordering::Relaxed)
    }

    /// Returns `(browser -> relay, relay -> browser)` bytes since the previous
    /// call, advancing the reported baseline.
    pub fn take_delta(&self) -> (u64, u64) {
        let read = self.read.load(Ordering::Relaxed);
        let written = self.written.load(Ordering::Relaxed);
        let prev_read = self.reported_read.swap(read, Ordering::Relaxed);
        let prev_written = self.reported_written.swap(written, Ordering::Relaxed);
        (
            read.saturating_sub(prev_read),
            written.saturating_sub(prev_written),
        )
    }
}

/// An [`AsyncRead`]/[`AsyncWrite`] wrapper that tallies bytes into a
/// [`ConnBytes`].
#[derive(Debug)]
pub struct CountingIo<S> {
    inner: S,
    bytes: std::sync::Arc<ConnBytes>,
}

impl<S> CountingIo<S> {
    /// Wraps `inner`, counting into `bytes`.
    pub fn new(inner: S, bytes: std::sync::Arc<ConnBytes>) -> Self {
        Self { inner, bytes }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let n = buf.filled().len() - before;
            self.bytes.read.fetch_add(n as u64, Ordering::Relaxed);
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            self.bytes.written.fetch_add(*n as u64, Ordering::Relaxed);
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn counts_bytes_both_directions_and_reports_deltas() {
        let bytes = Arc::new(ConnBytes::new());
        assert_eq!(bytes.service_id(), 0);

        let (mut client, server) = tokio::io::duplex(64);
        let mut counted = CountingIo::new(server, Arc::clone(&bytes));

        client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        counted.read_exact(&mut buf).await.unwrap();
        counted.write_all(b"world!").await.unwrap();

        let (read, written) = bytes.take_delta();
        assert_eq!(read, 5);
        assert_eq!(written, 6);
        // A second call sees only the new bytes.
        let (read, written) = bytes.take_delta();
        assert_eq!((read, written), (0, 0));
    }

    #[tokio::test]
    async fn first_service_wins() {
        let bytes = ConnBytes::new();
        bytes.set_service(7);
        bytes.set_service(9);
        assert_eq!(bytes.service_id(), 7);
    }
}
