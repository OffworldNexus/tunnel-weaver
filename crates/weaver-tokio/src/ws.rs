//! WebSocket transport: one binary WebSocket message per mux frame.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

/// A message-delimited transport the [`crate::Driver`] can pump.
///
/// Implemented for [`WebSocketStream`] via [`WsTransport`]; any
/// `Sink<Bytes> + Stream<Item = Result<Option<Bytes>, E>>` works, where a
/// `None` item is transport-level chatter (ping/pong) that carries no mux
/// frame.
pub trait Transport:
    Sink<Bytes, Error = Self::Err> + Stream<Item = Result<Option<Bytes>, Self::Err>> + Unpin
{
    /// Transport error type.
    type Err: std::error::Error + Send + Sync + 'static;
}

impl<T> Transport for T
where
    T: Sink<Bytes> + Stream<Item = Result<Option<Bytes>, <T as Sink<Bytes>>::Error>> + Unpin,
    <T as Sink<Bytes>>::Error: std::error::Error + Send + Sync + 'static,
{
    type Err = <T as Sink<Bytes>>::Error;
}

/// WebSocket adapter: binary messages carry mux frames; WebSocket
/// ping/pong/close are answered or reported here so the mux never sees
/// them. The stream yields `Ok(None)` for such control traffic and ends
/// (`None`) on close.
pub struct WsTransport<S> {
    inner: WebSocketStream<S>,
    /// A WebSocket pong we owe the peer; sent before the next frame.
    pending_pong: Option<Bytes>,
}

impl<S> WsTransport<S> {
    /// Wrap an established WebSocket.
    pub fn new(inner: WebSocketStream<S>) -> Self {
        Self {
            inner,
            pending_pong: None,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Stream for WsTransport<S> {
    type Item = Result<Option<Bytes>, WsError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(Some(Ok(Message::Binary(b)))) => Poll::Ready(Some(Ok(Some(b)))),
            Poll::Ready(Some(Ok(Message::Close(_)))) => Poll::Ready(None),
            Poll::Ready(Some(Ok(Message::Ping(p)))) => {
                self.pending_pong = Some(p);
                Poll::Ready(Some(Ok(None)))
            }
            Poll::Ready(Some(Ok(_))) => Poll::Ready(Some(Ok(None))),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Sink<Bytes> for WsTransport<S> {
    type Error = WsError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), WsError>> {
        // Settle an owed pong first; it is a tiny frame and keeps the peer
        // from timing us out under bulk load.
        if self.pending_pong.is_some() {
            match Pin::new(&mut self.inner).poll_ready(cx) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
            let p = self.pending_pong.take().expect("checked above");
            Pin::new(&mut self.inner).start_send(Message::Pong(p))?;
        }
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), WsError> {
        Pin::new(&mut self.inner).start_send(Message::Binary(item))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), WsError>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), WsError>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}
