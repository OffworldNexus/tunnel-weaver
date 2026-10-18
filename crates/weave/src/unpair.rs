//! `weave unpair` — revoke this machine on a relay and forget it locally.
//!
//! Unpairing is bilateral. The connection to the relay is authenticated by the
//! very device key being revoked (the mux handshake), so possessing the key *is*
//! the authority to withdraw it: the relay deletes the machine, its key and its
//! hostnames. Only once the relay confirms does this command touch local state —
//! so a failure leaves the pairing intact rather than silently half-removing it.
//!
//! `--local-only` is the escape hatch for a relay that no longer exists: it
//! forgets the relay without asking it, and says so.

use std::time::Instant;

use weaver_mux::{CloseCode, CloseReason, Config, Connection, Event, StreamId};
use weaver_proto::control::{ControlHead, ControlReply};
use weaver_proto::policy;
use weaver_proto::{Head, encode};
use weaver_tokio::{Driver, StreamHandler, SystemRng, WsTransport};

use crate::connect::dial_relay;
use crate::host::normalize_admin_host;
use crate::store::Store;
use crate::ui::{self, Spinner, Stream, hinted};

/// Boxed error the CLI prints and exits on.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The relay's tunnel-edge WebSocket endpoint, on its admin host.
pub const CONNECT_PATH: &str = "/_weaver/connect";

/// Revokes this machine on `admin_host` (the default relay when `None`) and
/// forgets it locally; with `local_only`, only forgets it.
pub async fn run_unpair(admin_host: Option<&str>, local_only: bool) -> Result<(), BoxError> {
    let store = Store::open_default().await?;

    let relay = match admin_host {
        Some(raw) => {
            let host = normalize_admin_host(raw)?;
            match store.relay(&host).await? {
                Some(relay) => relay,
                None => return unpair_unknown(&store, &host, local_only).await,
            }
        }
        None => store.default_relay().await?.ok_or_else(|| {
            hinted(
                "this machine is not paired with any relay",
                "nothing to unpair",
            )
        })?,
    };
    let host = relay.admin_host.clone();

    if local_only {
        ui::warn(&format!(
            "Forgetting {host} without asking it: the machine stays authorised there \
             until it is revoked in the relay's web UI."
        ));
    } else {
        revoke_on_relay(&host, &relay.key_id).await?;
    }

    let forgotten = store.forget(&host).await?;
    if local_only {
        ui::success(&format!(
            "Unpaired {} locally",
            ui::accent(Stream::Out, &host)
        ));
    } else {
        ui::success(&format!(
            "Revoked this machine on {} and unpaired it",
            ui::accent(Stream::Out, &host)
        ));
    }
    match forgotten.and_then(|f| f.new_default) {
        Some(next) => ui::step(
            Stream::Out,
            &ui::dim(Stream::Out, ui::ARROW),
            &format!(
                "{} is now the default relay",
                ui::accent(Stream::Out, &next.admin_host)
            ),
        ),
        None if store.relays().await?.is_empty() => ui::step(
            Stream::Out,
            &ui::dim(Stream::Out, ui::ARROW),
            "This machine is no longer paired with any relay",
        ),
        None => {}
    }
    Ok(())
}

/// No local record of `host`. The device key is still the authority, so the
/// relay can still be asked directly — otherwise a lost store would leave the
/// machine authorised there for good.
async fn unpair_unknown(store: &Store, host: &str, local_only: bool) -> Result<(), BoxError> {
    if local_only {
        return Err(hinted(
            format!("this machine is not paired with {host} locally"),
            "run `weave relays` to see the relays it is paired with",
        ));
    }
    let key_id = store.key_ids().await?.into_iter().next().ok_or_else(|| {
        hinted(
            format!("nothing to revoke: this machine has no device key paired with {host}"),
            "run `weave relays` to see the relays it is paired with",
        )
    })?;
    revoke_on_relay(host, &key_id).await?;
    ui::success(&format!(
        "Revoked this machine on {} {}",
        ui::accent(Stream::Out, host),
        ui::dim(Stream::Out, "(there was no local record of it)")
    ));
    Ok(())
}

/// Asks the relay to revoke the machine holding `key_id`.
async fn revoke_on_relay(admin_host: &str, key_id: &str) -> Result<(), BoxError> {
    // Sign the handshake with the key being revoked: possession is the proof.
    let spinner = Spinner::new("Contacting the key agent\u{2026}");
    let signer = crate::tpm::resume(key_id).await.map_err(|e| {
        hinted(
            e.to_string(),
            format!("the relay cannot be asked without the key; use `weave unpair {admin_host} --local-only` to just forget it"),
        )
    })?;
    if signer.created() {
        return Err(hinted(
            "the device key is not in the key agent, so the relay cannot be asked to revoke it",
            format!("use `weave unpair {admin_host} --local-only` to just forget it"),
        ));
    }
    spinner.set_message(format!("Revoking this machine on {admin_host}\u{2026}"));
    let result = revoke_with_signer(admin_host, None, Box::new(signer)).await;
    spinner.clear();
    result
}

/// Revokes, over the mux, the machine that `signer`'s key belongs to.
///
/// Split out so tests can drive it with an in-memory signer instead of a key
/// agent: the authority is the handshake, so any signer the relay accepts works.
pub async fn revoke_with_signer(
    edge: &str,
    insecure_root_ca: Option<&std::path::Path>,
    signer: Box<dyn weaver_mux::auth::Signer + Send>,
) -> Result<(), BoxError> {
    let (ws_stream, host) = dial_relay(
        edge,
        CONNECT_PATH,
        crate::start::WS_SUBPROTOCOL,
        insecure_root_ca,
    )
    .await
    .map_err(|e| crate::pair::connect_error(edge, e))?;

    let cfg = Config::client(signer, host.clone(), Box::new(SystemRng));
    let conn = Connection::new(cfg, Instant::now());
    let (handler, closed) =
        Driver::new(conn, WsTransport::new(ws_stream), RevokeHandler::default())
            .run()
            .await;
    if let Some(outcome) = handler.outcome {
        return match outcome {
            Ok(()) => Ok(()),
            Err(message) => Err(message.into()),
        };
    }
    // No explicit reply reached us. Revoking the key makes the relay close this
    // connection as revoked — which *is* the confirmation, arriving as the
    // close rather than as a message.
    if let Ok(reason) = &closed
        && reason.code == CloseCode::KeyRevoked
    {
        return Ok(());
    }
    Err(format!("the relay did not confirm the revoke (closed: {closed:?})").into())
}

/// Opens one control stream, sends `Revoke`, and records the answer.
#[derive(Default)]
struct RevokeHandler {
    stream: Option<StreamId>,
    outcome: Option<Result<(), String>>,
}

impl StreamHandler for RevokeHandler {
    fn on_event(&mut self, conn: &mut Connection, event: Event) {
        match event {
            Event::Authenticated { .. } => {
                let Ok(bytes) = encode(&Head::Control(ControlHead::revoke())) else {
                    self.outcome = Some(Err("could not encode the revoke request".into()));
                    return;
                };
                match conn.open(policy::CONTROL_CLASS) {
                    Ok(id) => match conn.send(id, &bytes, policy::CONTROL_COMPRESS) {
                        Ok(()) => self.stream = Some(id),
                        Err(e) => {
                            self.outcome = Some(Err(format!("could not send the revoke: {e}")));
                        }
                    },
                    Err(e) => {
                        self.outcome = Some(Err(format!("could not open a control stream: {e}")));
                    }
                }
            }
            Event::Rejected { code, message } => {
                self.outcome = Some(Err(format!(
                    "the relay refused the connection: {message} ({code:?})"
                )));
            }
            Event::Readable(id) if Some(id) == self.stream => {
                while let Ok(msg) = conn.recv_msg(id) {
                    match weaver_proto::decode::<ControlReply>(&msg) {
                        Ok(ControlReply::Revoked) => {
                            self.outcome = Some(Ok(()));
                            conn.close(CloseReason::with_message(CloseCode::Shutdown, "unpaired"));
                        }
                        Ok(ControlReply::Refused { message, .. }) => {
                            self.outcome = Some(Err(message));
                            conn.close(CloseReason::with_message(CloseCode::Shutdown, "unpaired"));
                        }
                        Ok(_) => {}
                        Err(e) => {
                            self.outcome = Some(Err(format!("unexpected reply: {e}")));
                            conn.close(CloseReason::with_message(CloseCode::Shutdown, "unpaired"));
                        }
                    }
                }
            }
            // A `Reset` here is the local teardown of our own stream after we
            // close on success, so it must not overwrite an outcome.
            _ => {}
        }
    }
}
