//! `weave unpair`: revoke this machine on a relay, then forget the relay.
//!
//! The tunnel handshake is signed by the very key being revoked, so holding
//! the key is the authority to withdraw it. The relay is forgotten locally only
//! once it confirms with `Revoked`, or when it does not accept the key at all
//! (the pairing was not in effect anyway). Any other failure keeps the pairing.

use weaver_mux::{CloseCode, CloseReason, Connection, Event, RejectCode, StreamId};
use weaver_proto::control::{ControlHead, ControlReply};
use weaver_tokio::StreamHandler;

use crate::client::{Client, PairedKey, open_control};
use crate::error::Error;
use crate::host::AdminHost;

/// A relay this machine is no longer paired with.
#[derive(Debug, Clone)]
pub struct Unpaired {
    /// The relay.
    pub host: String,
    /// The relay revoked the machine. `false` when it did not accept the key,
    /// so there was nothing to revoke.
    pub revoked: bool,
    /// The relay that became the default in its place; empty when none did.
    pub new_default: String,
    /// How many relays remain paired.
    pub remaining: usize,
}

impl Client {
    /// Revokes this machine on `admin_host` (the default relay when empty)
    /// and forgets it.
    pub async fn unpair(&self, admin_host: &str) -> Result<Unpaired, Error> {
        let relay = self.paired_relay(admin_host).await?;
        let host = relay.admin_host.clone();

        let revoked = match self.open_paired_key(&relay).await? {
            PairedKey::Valid(signer) => {
                self.reporter.revoking(&host);
                let handler = Revoke {
                    host: host.clone(),
                    stream: None,
                    outcome: None,
                };
                let driver = self.mux(&AdminHost::parse(&host)?, signer, handler).await?;
                let (handler, closed) = driver.run().await;
                match handler.outcome {
                    Some(Outcome::Revoked) => true,
                    Some(Outcome::UnknownKey(message)) => {
                        self.reporter.pairing_not_effective(&host, &message);
                        false
                    }
                    Some(Outcome::Failed(error)) => return Err(error),
                    None => {
                        let reason = match closed {
                            Ok(reason) => {
                                format!("the relay closed the connection ({:?})", reason.code)
                            }
                            Err(e) => e.to_string(),
                        };
                        return Err(Error::Disconnected {
                            host,
                            reason: format!("{reason} before confirming the revoke"),
                        });
                    }
                }
            }
            PairedKey::Lost => {
                self.reporter.pairing_not_effective(
                    &host,
                    "this machine no longer has the key paired there",
                );
                false
            }
        };

        let new_default = self.store.forget(&host).await?;
        Ok(Unpaired {
            host,
            revoked,
            new_default: new_default
                .map(|relay| relay.admin_host)
                .unwrap_or_default(),
            remaining: self.store.relays().await?.len(),
        })
    }
}

enum Outcome {
    Revoked,
    /// The relay does not know the key.
    UnknownKey(String),
    Failed(Error),
}

/// Opens one control stream, sends `Revoke`, and records the answer.
struct Revoke {
    host: String,
    stream: Option<StreamId>,
    outcome: Option<Outcome>,
}

impl Revoke {
    fn settle(&mut self, conn: &mut Connection, outcome: Outcome) {
        self.outcome = Some(outcome);
        conn.close(CloseReason::with_message(CloseCode::Shutdown, "unpaired"));
    }
}

impl StreamHandler for Revoke {
    fn on_event(&mut self, conn: &mut Connection, event: Event) {
        match event {
            Event::Authenticated { .. } => match open_control(conn, &ControlHead::revoke()) {
                Ok(id) => self.stream = Some(id),
                Err(e) => self.settle(conn, Outcome::Failed(Error::Protocol(e))),
            },
            Event::Rejected {
                code: RejectCode::UnknownKey,
                message,
            } => self.outcome = Some(Outcome::UnknownKey(message)),
            Event::Rejected { code, message } => {
                self.outcome = Some(Outcome::Failed(Error::Rejected {
                    host: self.host.clone(),
                    code,
                    message,
                }));
            }
            Event::Readable(id) if Some(id) == self.stream => {
                if let Ok(msg) = conn.recv_msg(id) {
                    let outcome = match weaver_proto::decode::<ControlReply>(&msg) {
                        Ok(ControlReply::Revoked) => Outcome::Revoked,
                        Ok(ControlReply::Refused { message, .. }) => Outcome::Failed(
                            Error::Protocol(format!("the relay refused: {message}")),
                        ),
                        Ok(other) => Outcome::Failed(Error::Protocol(format!("{other:?}"))),
                        Err(e) => Outcome::Failed(Error::Protocol(e.to_string())),
                    };
                    self.settle(conn, outcome);
                }
            }
            _ => {}
        }
    }
}
