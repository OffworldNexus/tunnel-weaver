//! Tokio adapter for [`weaver_mux`].
//!
//! `weaver-mux` is sans-IO; this crate is the one place that pumps a
//! [`weaver_mux::Connection`] over a real transport. It owns the rules the mux asks
//! adapters to follow (one frame per `poll_transmit`, flushed before the
//! next; `TCP_NOTSENT_LOWAT` on the socket), the system RNG, and the
//! WebSocket-level ping/pong, so that neither binary has to.
//!
//! Application behaviour is supplied through a [`StreamHandler`]; it is
//! given `&mut weaver_mux::Connection` and reacts to [`weaver_mux::Event`]s. Other tasks talk to
//! the driver through a [`Handle`], which runs closures on the connection
//! from inside the event loop.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod driver;
mod rng;
mod socket;
mod ws;

pub use driver::{Driver, DriverError, Handle, StreamHandler};
pub use rng::SystemRng;
pub use socket::{set_tcp_nodelay, set_tcp_notsent_lowat};
pub use ws::{Transport, WsTransport};
