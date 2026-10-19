//! Why a client command failed.

use weaver_mux::RejectCode;
use weaver_proto::pair::FailureCode;

use crate::host::HostError;
use crate::key::KeyError;
use crate::store::StoreError;

/// Boxed error from the network and TLS layers.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A failed client command.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No relay was named and none is the default.
    #[error("this machine is not paired with any relay")]
    NoRelay,
    /// The named relay is not paired.
    #[error("this machine is not paired with {0}")]
    NotPaired(String),
    /// The relay already authorises the current device key.
    #[error("this machine is already paired with {host} (machine {machine_id})")]
    AlreadyPaired {
        /// The relay.
        host: String,
        /// The machine it is paired as.
        machine_id: i32,
    },
    /// The device key the relay authorised no longer exists.
    #[error("your device key is gone")]
    KeyGone {
        /// The relay to pair with again.
        host: String,
    },
    /// The device key could not be opened.
    #[error(transparent)]
    Key(#[from] KeyError),
    /// The relay could not be reached.
    #[error("could not reach {host}: {source}")]
    Unreachable {
        /// The relay.
        host: String,
        /// What failed.
        source: BoxError,
    },
    /// The relay refused the tunnel handshake.
    #[error("{host} refused the connection: {message} ({code:?})")]
    Rejected {
        /// The relay.
        host: String,
        /// Why.
        code: RejectCode,
        /// The relay's detail.
        message: String,
    },
    /// The relay closed the tunnel because this machine was revoked.
    #[error("{host} revoked this machine")]
    Revoked {
        /// The relay.
        host: String,
    },
    /// The tunnel ended without being asked to.
    #[error("disconnected from {host}: {reason}")]
    Disconnected {
        /// The relay.
        host: String,
        /// What happened.
        reason: String,
    },
    /// Some services could not be registered.
    #[error("{} of {total} service(s) failed to register: {}", failures.len(), failures.join("; "))]
    Registration {
        /// How many services were asked for.
        total: usize,
        /// `service: reason`, one per failure.
        failures: Vec<String>,
    },
    /// The relay ended the pairing.
    #[error("{}", pairing_failure(host, *code, message))]
    Pairing {
        /// The relay.
        host: String,
        /// Why.
        code: FailureCode,
        /// The relay's detail.
        message: String,
    },
    /// The proof of work the relay asked for cannot be solved.
    #[error("cannot solve the relay's proof of work: {0}")]
    ProofOfWork(#[from] weaver_abuse::SolveError),
    /// The relay said something out of turn.
    #[error("unexpected reply from the relay: {0}")]
    Protocol(String),
    /// The client's own state.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A malformed relay address.
    #[error(transparent)]
    Host(#[from] HostError),
}

fn pairing_failure(host: &str, code: FailureCode, message: &str) -> String {
    let what = match code {
        FailureCode::Rejected => "the pairing was rejected in the browser".to_string(),
        FailureCode::AlreadyPaired => format!("{host} already knows this device key"),
        FailureCode::NotYourMachine => {
            "that machine does not belong to the account that opened the link".to_string()
        }
        FailureCode::Throttled => format!("{host} is receiving too many pairing requests"),
        FailureCode::Unavailable => format!("{host} cannot pair machines right now"),
        FailureCode::BadProof => "the relay did not accept the proof of work".to_string(),
        FailureCode::BadKey => "the relay does not accept this device key".to_string(),
        FailureCode::BadRequest => "the relay did not understand the pairing request".to_string(),
    };
    if message.is_empty() {
        what
    } else {
        format!("{what}: {message}")
    }
}
