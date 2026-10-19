//! `weave pair`: enrol this machine with a relay.
//!
//! The command opens a pairing channel to the relay's admin host, solves the
//! proof of work the relay opens with, sends the device key's public half and
//! which machine it is for, and waits while someone approves the link the relay
//! hands back. The pending pairing lives exactly as long as the channel.

use std::time::Instant;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use weaver_abuse::{Payload, SolveLimits};
use weaver_proto::pair::{self, Begin, ServerMessage, Target};

use crate::client::{Client, RelaySocket};
use crate::error::Error;
use crate::host::AdminHost;
use crate::key::{KeyError, Provision, SecurityLevel};

/// The proof of work the CLI agrees to do: at most this PBKDF2 cost per
/// attempt…
const MAX_POW_COST: u32 = 200_000;

/// …and this many iterations in total, about a minute or two on a slow
/// machine.
const MAX_POW_WORK: u64 = 400_000_000;

/// What to pair.
#[derive(Debug, Clone)]
pub struct PairRequest {
    /// The relay's admin host.
    pub admin_host: String,
    /// Move this existing machine onto the device key instead of letting the
    /// client decide.
    pub machine: Option<i32>,
    /// The minimum protection level for a new device key.
    pub floor: SecurityLevel,
    /// Consent to create the key below `floor` without being asked.
    pub allow_below_floor: bool,
}

/// An approved pairing.
#[derive(Debug, Clone)]
pub struct Paired {
    /// The relay.
    pub host: String,
    /// The machine's id there.
    pub machine_id: i32,
    /// The owner's name.
    pub person: String,
    /// The machine's name.
    pub machine: String,
    /// The relay is now the default one.
    pub is_default: bool,
}

/// The link a person opens to approve a pairing.
///
/// The handle is a capability, so it rides in the URL fragment, which never
/// reaches the server, a log line or a `Referer`.
pub fn pairing_url(admin_host: &str, handle: &str) -> String {
    format!("https://{admin_host}/pair#handle={handle}")
}

impl Client {
    /// Pairs this machine with a relay, returning once the pairing is approved.
    pub async fn pair(&self, request: &PairRequest) -> Result<Paired, Error> {
        let host = AdminHost::parse(&request.admin_host)?;
        let host_name = host.to_string();

        let key = self.open_pairing_key(request).await?;
        self.reporter
            .device_key(&key.fingerprint, key.level, key.replaced);

        let known = self.store.relay(&host_name).await?;
        let target = choose_target(
            request.machine,
            known.as_ref().map(|r| (r.machine_id, r.key_id.as_str())),
            &key.fingerprint,
        )
        .map_err(|machine_id| Error::AlreadyPaired {
            host: host_name.clone(),
            machine_id,
        })?;
        if let Target::Existing { machine_id } = target {
            self.reporter.moving_machine(machine_id);
        }

        self.reporter.connecting(&host_name);
        let mut ws = self
            .dial(&host, pair::PAIR_CHANNEL_PATH, pair::PAIR_SUBPROTOCOL)
            .await?;
        self.reporter.connected(&host_name);

        let challenge = match next_message(&mut ws, &host_name).await? {
            ServerMessage::Challenge { challenge } => challenge,
            other => return Err(unexpected(other, &host_name)),
        };
        self.reporter.solving_proof_of_work();
        let started = Instant::now();
        let solution = {
            let challenge = challenge.clone();
            tokio::task::spawn_blocking(move || {
                weaver_abuse::try_solve_challenge(
                    &challenge,
                    &SolveLimits {
                        max_cost: MAX_POW_COST,
                        max_work: MAX_POW_WORK,
                    },
                )
            })
            .await
            .expect("the proof-of-work task does not panic")?
        };
        self.reporter.proof_of_work_solved(started.elapsed());

        let begin = Begin {
            proof: Payload {
                challenge,
                solution,
            },
            key_id: key.signer.key_id(),
            target,
        };
        let begin = serde_json::to_string(&begin).map_err(|e| Error::Protocol(e.to_string()))?;
        ws.send(Message::Text(begin.into()))
            .await
            .map_err(|e| closed(&host_name, e))?;

        let handle = match next_message(&mut ws, &host_name).await? {
            ServerMessage::Handle { handle } => handle,
            other => return Err(unexpected(other, &host_name)),
        };
        self.reporter
            .awaiting_approval(&pairing_url(&host_name, &handle));

        let (machine_id, person, machine) = match next_message(&mut ws, &host_name).await? {
            ServerMessage::Approved {
                machine_id,
                person,
                machine,
            } => (machine_id, person, machine),
            other => return Err(unexpected(other, &host_name)),
        };
        let saved = self
            .store
            .record_pairing(&host_name, machine_id, &key.fingerprint)
            .await?;
        Ok(Paired {
            host: host_name,
            machine_id,
            person,
            machine,
            is_default: saved.is_default,
        })
    }

    /// Opens the device key, asking before creating it below the floor.
    async fn open_pairing_key(
        &self,
        request: &PairRequest,
    ) -> Result<crate::client::DeviceKey, Error> {
        let provision = Provision {
            floor: request.floor,
            allow_below_floor: request.allow_below_floor,
        };
        match self.open_key(provision).await {
            Err(Error::Key(KeyError::BelowFloor {
                required,
                available,
            })) if !request.allow_below_floor
                && self.reporter.allow_below_floor(required, available) =>
            {
                self.open_key(Provision {
                    allow_below_floor: true,
                    ..provision
                })
                .await
            }
            result => result,
        }
    }
}

/// Decides which machine a pairing is for, or the machine id it is already
/// paired as.
///
/// An explicit `machine` wins. A known relay that recorded another key gets
/// its machine back on this one; one that recorded this key has nothing to
/// pair. An unknown relay gets a new machine.
fn choose_target(
    machine: Option<i32>,
    known: Option<(i32, &str)>,
    fingerprint: &str,
) -> Result<Target, i32> {
    match (machine, known) {
        (Some(machine_id), _) => Ok(Target::Existing { machine_id }),
        (None, Some((machine_id, key_id))) if key_id != fingerprint => {
            Ok(Target::Existing { machine_id })
        }
        (None, Some((machine_id, _))) => Err(machine_id),
        (None, None) => Ok(Target::New {
            hostname: hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "machine".to_string()),
        }),
    }
}

/// The next pairing message.
async fn next_message(ws: &mut RelaySocket, host: &str) -> Result<ServerMessage, Error> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Text(text))) => {
                return serde_json::from_str(&text).map_err(|e| Error::Protocol(e.to_string()));
            }
            Some(Ok(Message::Close(_))) | None => return Err(closed(host, "the channel closed")),
            Some(Ok(_)) => continue,
            Some(Err(e)) => return Err(closed(host, e)),
        }
    }
}

fn closed(host: &str, why: impl std::fmt::Display) -> Error {
    Error::Disconnected {
        host: host.to_string(),
        reason: format!("the pairing channel broke: {why}"),
    }
}

/// A `Failed` ends the pairing; anything else is out of turn.
fn unexpected(message: ServerMessage, host: &str) -> Error {
    match message {
        ServerMessage::Failed { code, message } => Error::Pairing {
            host: host.to_string(),
            code,
            message,
        },
        other => Error::Protocol(format!("{other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_url_puts_the_handle_in_the_fragment() {
        assert_eq!(
            pairing_url("relay.example.com", "abc123"),
            "https://relay.example.com/pair#handle=abc123"
        );
    }

    #[test]
    fn target_selection() {
        assert!(matches!(
            choose_target(None, None, "p256:aa"),
            Ok(Target::New { .. })
        ));
        // Known relay, key replaced: the machine moves.
        assert_eq!(
            choose_target(None, Some((7, "p256:old")), "p256:new"),
            Ok(Target::Existing { machine_id: 7 })
        );
        // Known relay, same key: nothing to do.
        assert_eq!(choose_target(None, Some((7, "p256:aa")), "p256:aa"), Err(7));
        // An explicit machine wins.
        assert_eq!(
            choose_target(Some(3), Some((7, "p256:aa")), "p256:aa"),
            Ok(Target::Existing { machine_id: 3 })
        );
    }
}
