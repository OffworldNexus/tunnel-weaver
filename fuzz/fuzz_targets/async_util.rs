//! Minimal executor for fuzz targets.
//!
//! libFuzzer drives a plain synchronous closure, but the mux handshake now
//! awaits its `Verifier`. With the in-memory `MapVerifier` every future
//! completes on the first poll, so a no-op waker plus a single `poll` is
//! enough — and it keeps the fuzz build free of a runtime dependency.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

pub fn block_on<F: Future>(fut: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut fut = pin!(fut);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(val) => val,
        Poll::Pending => panic!("future unexpectedly returned Poll::Pending"),
    }
}
