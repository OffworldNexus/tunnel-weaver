//! The pairing plane: a machine asks for its key to be enrolled, a person
//! approves it in the browser.
//!
//! Three pieces live here:
//!
//! * [`Pairings`] — the in-memory registry of *pending* pairings. It is
//!   deliberately not a table: a pending pairing exists exactly as long as the
//!   CLI's channel is open, so there is nothing to expire, sweep or leak. A
//!   relay restart simply means the request is no longer waiting.
//! * [`serve_channel`] — the WebSocket side, spawned by the raw edge. It issues
//!   a proof of work, checks the CLI's `Begin`, registers the pending pairing,
//!   hands the CLI its handle, and relays the browser's outcome.
//! * The name rules lookup and accept share — proposing a person slug and a
//!   machine name.
//!
//! The channel is unauthenticated, so it never answers anything about existing
//! machines beyond "this key is already paired" (which only the key's holder can
//! ask about usefully). Whether a targeted machine exists and is the
//! approver's is decided in the browser, behind a session.
//!
//! The handle is a capability: 32 random bytes, single use, carried only in the
//! link's fragment and in JSON bodies — never a path or a query, so it cannot
//! reach an access log or a `Referer`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use weaver_abuse::{AltchaError, Pipeline, RequestContext, Surface, ViewId};
use weaver_mux::KeyId;
use weaver_proto::pair::{
    self, Begin, FailureCode, PAIR_CHANNEL_PATH, PAIR_POW_PURPOSE, ServerMessage, Target,
};

use crate::abuse::Refusal;
use crate::account::AccountRuntime;
use crate::store::Store;
use crate::store::entity::{account, person};
use crate::store::names;

/// How long the CLI has, after the challenge, to send its `Begin`. Covers
/// solving the proof of work on a slow machine.
pub const BEGIN_TIMEOUT: Duration = Duration::from_secs(60);

/// Largest message the channel accepts. A `Begin` is a few hundred bytes.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;

/// The WebSocket limits the pairing channel runs with.
pub fn channel_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_MESSAGE_BYTES))
}

/// What the browser sees of a pending pairing.
#[derive(Debug, Clone)]
pub struct PendingView {
    /// The machine's public key.
    pub key_id: KeyId,
    /// Which machine the key is for.
    pub target: Target,
}

/// A pending pairing consumed by accept/reject.
pub struct Taken {
    /// The machine's public key.
    pub key_id: KeyId,
    /// Which machine the key is for.
    pub target: Target,
    sender: oneshot::Sender<ServerMessage>,
}

impl Taken {
    /// Tells the CLI how the pairing ended. A CLI that stopped waiting is not
    /// an error: the outcome stands either way.
    pub fn finish(self, outcome: ServerMessage) {
        let _ = self.sender.send(outcome);
    }

    /// Ends the pairing with a failure.
    pub fn fail(self, code: FailureCode, message: &str) {
        self.finish(ServerMessage::Failed {
            code,
            message: message.to_string(),
        });
    }
}

struct Pending {
    view: PendingView,
    sender: oneshot::Sender<ServerMessage>,
}

#[derive(Default)]
struct Inner {
    by_handle: HashMap<String, Pending>,
    /// At most one pending pairing per key: a second `weave pair` supersedes
    /// the first, so a stolen handle cannot be raced against a fresh one.
    handle_by_key: HashMap<KeyId, String>,
}

impl Inner {
    fn remove(&mut self, handle: &str) -> Option<Pending> {
        let pending = self.by_handle.remove(handle)?;
        let key = pending.view.key_id;
        if self.handle_by_key.get(&key).map(String::as_str) == Some(handle) {
            self.handle_by_key.remove(&key);
        }
        Some(pending)
    }
}

/// The registry of pending pairings, shared by the edge and the account API.
#[derive(Clone, Default)]
pub struct Pairings {
    inner: Arc<Mutex<Inner>>,
}

impl Pairings {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a pending pairing, superseding any earlier one for the same
    /// key. Returns the handle and the channel the outcome arrives on.
    pub fn register(
        &self,
        key_id: KeyId,
        target: Target,
    ) -> (String, oneshot::Receiver<ServerMessage>) {
        let handle = crate::account::session::random_hex(32);
        let (sender, receiver) = oneshot::channel();
        let mut inner = self.inner.lock().expect("pairings mutex poisoned");
        if let Some(previous) = inner.handle_by_key.insert(key_id, handle.clone()) {
            inner.by_handle.remove(&previous);
        }
        inner.by_handle.insert(
            handle.clone(),
            Pending {
                view: PendingView { key_id, target },
                sender,
            },
        );
        (handle, receiver)
    }

    /// Forgets a pending pairing (the channel closed).
    pub fn unregister(&self, handle: &str) {
        self.inner
            .lock()
            .expect("pairings mutex poisoned")
            .remove(handle);
    }

    /// What the browser needs, or `None` if the handle is gone.
    pub fn view(&self, handle: &str) -> Option<PendingView> {
        let inner = self.inner.lock().expect("pairings mutex poisoned");
        inner.by_handle.get(handle).map(|p| p.view.clone())
    }

    /// Consumes the pending pairing, so a handle is single use.
    pub fn take(&self, handle: &str) -> Option<Taken> {
        let pending = self
            .inner
            .lock()
            .expect("pairings mutex poisoned")
            .remove(handle)?;
        Some(Taken {
            key_id: pending.view.key_id,
            target: pending.view.target,
            sender: pending.sender,
        })
    }

    /// How many pairings are waiting (tests, diagnostics).
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("pairings mutex poisoned")
            .by_handle
            .len()
    }

    /// Whether nothing is waiting.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Where a channel came from, for the pairing budget.
pub struct Peer {
    /// The relay's safety pipeline.
    pub guard: Arc<Pipeline>,
    /// The socket peer.
    pub addr: SocketAddr,
}

impl Peer {
    /// Charges the pairing budget for one pending pairing.
    async fn admit(&self) -> Result<(), FailureCode> {
        let mut ctx = RequestContext {
            surface: Surface::https(weaver_abuse::Host::Admin),
            method: http::Method::GET,
            path: PAIR_CHANNEL_PATH,
            raw_path: PAIR_CHANNEL_PATH,
            body_len: None,
            fingerprint: weaver_abuse::fingerprint(crate::abuse::effective_peer(self.addr), None),
            view: ViewId::ACCOUNT_PAIR,
            now_ms: crate::abuse::unix_ms(),
            findings: Vec::new(),
            cost: 0,
        };
        match Refusal::from_decision(self.guard.evaluate(&mut ctx).await) {
            None => Ok(()),
            Some(Refusal::Throttled { .. }) => Err(FailureCode::Throttled),
            Some(Refusal::Unavailable) => Err(FailureCode::Unavailable),
            Some(Refusal::Blocked { .. }) => Err(FailureCode::BadRequest),
        }
    }
}

/// Serves one pairing channel: challenge, `Begin`, handle, outcome.
pub async fn serve_channel<S>(mut ws: WebSocketStream<S>, account: Arc<AccountRuntime>, peer: Peer)
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let outcome = run_channel(&mut ws, &account, &peer).await;
    if let Some(outcome) = outcome {
        let _ = send(&mut ws, &outcome).await;
    }
    let _ = ws.close(None).await;
}

/// Everything up to the final message, which the caller sends. `None` means
/// the CLI went away and there is nobody to tell.
async fn run_channel<S>(
    ws: &mut WebSocketStream<S>,
    account: &AccountRuntime,
    peer: &Peer,
) -> Option<ServerMessage>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let Some(challenge) = account
        .altcha
        .challenge_for_internal_client(PAIR_POW_PURPOSE, PAIR_POW_PURPOSE)
        .await
    else {
        return Some(failed(
            FailureCode::Unavailable,
            "the relay cannot issue a proof of work right now; try again later",
        ));
    };
    let issued_signature = challenge.signature.clone();
    send(ws, &ServerMessage::Challenge { challenge })
        .await
        .ok()?;

    let begin = match tokio::time::timeout(BEGIN_TIMEOUT, read_begin(ws)).await {
        Err(_) => {
            return Some(failed(
                FailureCode::BadRequest,
                "timed out waiting for the pairing request",
            ));
        }
        Ok(Read::Gone) => return None,
        Ok(Read::Malformed) => {
            return Some(failed(
                FailureCode::BadRequest,
                "the pairing request could not be understood",
            ));
        }
        Ok(Read::Begin(begin)) => *begin,
    };

    // The proof comes first: nothing below — not even whether the key is known
    // — is answered to a caller that has not paid for it.
    if let Err(code) = verify_proof(account, &begin, issued_signature.as_deref()).await {
        let message = match code {
            FailureCode::Unavailable => "the relay cannot check the proof of work right now",
            _ => "the proof of work is missing, wrong, expired or already used",
        };
        return Some(failed(code, message));
    }
    if !key_is_valid(&begin.key_id) {
        return Some(failed(
            FailureCode::BadKey,
            "the device key is malformed or uses an unsupported algorithm",
        ));
    }
    if let Err(code) = peer.admit().await {
        let message = match code {
            FailureCode::Throttled => "too many pairing requests; try again later",
            _ => "the relay cannot open a pairing right now",
        };
        return Some(failed(code, message));
    }
    match account.store.machine_by_key(&begin.key_id).await {
        Ok(None) => {}
        Ok(Some((person, machine))) => {
            return Some(failed(
                FailureCode::AlreadyPaired,
                &format!(
                    "this device key is already paired as {}-{}",
                    person.name, machine.name
                ),
            ));
        }
        Err(e) => {
            tracing::warn!(error = %e, "pairing: key lookup failed");
            return Some(failed(
                FailureCode::Unavailable,
                "the relay cannot open a pairing right now",
            ));
        }
    }

    let (handle, mut outcome) = account.pairings.register(begin.key_id, begin.target);
    if send(
        ws,
        &ServerMessage::Handle {
            handle: handle.clone(),
        },
    )
    .await
    .is_err()
    {
        account.pairings.unregister(&handle);
        return None;
    }

    // Wait for the browser, or for the channel to die — whichever comes first.
    // Anything the CLI sends after `Begin` is ignored.
    let result = loop {
        tokio::select! {
            result = &mut outcome => break result.ok(),
            message = ws.next() => match message {
                Some(Ok(Message::Text(_) | Message::Binary(_) | Message::Ping(_) | Message::Pong(_))) => continue,
                _ => break None,
            },
        }
    };
    account.pairings.unregister(&handle);
    result
}

enum Read {
    Begin(Box<Begin>),
    Malformed,
    Gone,
}

/// Reads the CLI's one `Begin`.
async fn read_begin<S>(ws: &mut WebSocketStream<S>) -> Read
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    while let Some(message) = ws.next().await {
        return match message {
            Ok(Message::Text(text)) if text.len() <= MAX_MESSAGE_BYTES => {
                match pair::decode_json::<Begin>(&text) {
                    Ok(begin) => Read::Begin(Box::new(begin)),
                    Err(_) => Read::Malformed,
                }
            }
            Ok(Message::Ping(_) | Message::Pong(_)) => continue,
            Ok(Message::Close(_)) => Read::Gone,
            Ok(_) => Read::Malformed,
            Err(tokio_tungstenite::tungstenite::Error::Capacity(_)) => Read::Malformed,
            Err(_) => Read::Gone,
        };
    }
    Read::Gone
}

/// Checks that `begin` carries a solved, unspent proof of *this channel's*
/// challenge, consuming it.
async fn verify_proof(
    account: &AccountRuntime,
    begin: &Begin,
    issued_signature: Option<&str>,
) -> Result<(), FailureCode> {
    let payload = &begin.proof;
    if issued_signature.is_none() || payload.challenge.signature.as_deref() != issued_signature {
        return Err(FailureCode::BadProof);
    }
    let client = payload
        .challenge
        .parameters
        .data
        .as_ref()
        .and_then(|data| data.get("client"))
        .and_then(Value::as_str)
        .ok_or(FailureCode::BadProof)?;
    match account
        .altcha
        .verify_payload(client, payload, PAIR_POW_PURPOSE, PAIR_POW_PURPOSE)
        .await
    {
        Ok(_) => Ok(()),
        Err(AltchaError::Proof(_)) => Err(FailureCode::BadProof),
        Err(AltchaError::Store(_)) => Err(FailureCode::Unavailable),
    }
}

/// Whether `key_id` is a well-formed public key of a supported algorithm.
pub fn key_is_valid(key_id: &KeyId) -> bool {
    match key_id {
        KeyId::P256(bytes) => p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes).is_ok(),
        KeyId::Ed25519(bytes) => ed25519_dalek::VerifyingKey::from_bytes(bytes).is_ok(),
    }
}

fn failed(code: FailureCode, message: &str) -> ServerMessage {
    ServerMessage::Failed {
        code,
        message: message.to_string(),
    }
}

/// Sends one server message as JSON text.
async fn send<S>(ws: &mut WebSocketStream<S>, message: &ServerMessage) -> Result<(), ()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let text = pair::encode_json(message).map_err(|_| ())?;
    ws.send(Message::Text(text.into())).await.map_err(|_| ())
}

/// The fingerprint shown for a key (`p256:<hex>`): byte-for-byte the
/// `machine.key_id` the relay stores.
pub fn fingerprint(key_id: &KeyId) -> String {
    crate::store::format_key_id(key_id)
}

/// The person slug to propose for an account that has no person yet: a
/// zone-unique slug derived from the account name.
pub async fn propose_person_slug(
    store: &Store,
    account: &account::Model,
) -> Result<String, String> {
    let taken = store.list_person_names().await.map_err(|e| e.to_string())?;
    let base = names::slugify_person(&account.name);
    Ok(names::uniquify(&base, |candidate| {
        taken.iter().any(|t| t == candidate)
    }))
}

/// The machine name to propose (or to settle on) for `requested`: slugified,
/// then uniquified against the person's machines — a collision becomes a digit
/// suffix (`laptop`, `laptop2`) rather than a refusal.
pub async fn unique_machine_name(
    store: &Store,
    person: Option<&person::Model>,
    requested: &str,
) -> Result<String, String> {
    let base = names::slugify_machine(requested);
    let Some(person) = person else {
        return Ok(base);
    };
    let taken = store
        .list_machine_names(person.id)
        .await
        .map_err(|e| e.to_string())?;
    Ok(names::uniquify(&base, |candidate| {
        taken.iter().any(|t| t == candidate)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> KeyId {
        KeyId::P256([byte; 33])
    }

    fn new_machine() -> Target {
        Target::New {
            hostname: "laptop".into(),
        }
    }

    #[test]
    fn handle_is_single_use() {
        let pairings = Pairings::new();
        let (handle, _rx) = pairings.register(key(1), new_machine());
        assert!(pairings.view(&handle).is_some());
        assert!(pairings.take(&handle).is_some());
        assert!(pairings.take(&handle).is_none());
        assert!(pairings.view(&handle).is_none());
        assert!(pairings.is_empty());
    }

    #[test]
    fn a_second_pairing_supersedes_the_first_for_the_same_key() {
        let pairings = Pairings::new();
        let (first, _r1) = pairings.register(key(2), new_machine());
        let (second, _r2) = pairings.register(key(2), Target::Existing { machine_id: 4 });
        assert!(pairings.view(&first).is_none());
        assert_eq!(
            pairings.view(&second).unwrap().target,
            Target::Existing { machine_id: 4 }
        );
        assert_eq!(pairings.len(), 1);
    }

    #[test]
    fn unregister_frees_the_key_again() {
        let pairings = Pairings::new();
        let (handle, _rx) = pairings.register(key(3), new_machine());
        pairings.unregister(&handle);
        assert!(pairings.is_empty());
        let (again, _r) = pairings.register(key(3), new_machine());
        assert!(pairings.view(&again).is_some());
    }

    #[test]
    fn taken_pairings_report_their_outcome() {
        let pairings = Pairings::new();
        let (handle, mut rx) = pairings.register(key(4), new_machine());
        pairings
            .take(&handle)
            .unwrap()
            .fail(FailureCode::Rejected, "no");
        assert_eq!(
            rx.try_recv().unwrap(),
            ServerMessage::Failed {
                code: FailureCode::Rejected,
                message: "no".into()
            }
        );
    }

    #[test]
    fn fingerprints_match_the_store_spelling() {
        let mut bytes = [0u8; 33];
        bytes[0] = 2;
        bytes[32] = 0xab;
        let text = fingerprint(&KeyId::P256(bytes));
        assert!(text.starts_with("p256:02"));
        assert!(text.ends_with("ab"));
        assert_eq!(text.len(), 5 + 66);
    }

    #[test]
    fn only_real_public_keys_are_valid() {
        assert!(!key_is_valid(&KeyId::P256([0x07; 33])));
        let signer = weaver_mux::testing::P256TestSigner::from_seed(1);
        assert!(key_is_valid(&weaver_mux::auth::Signer::key_id(&signer)));
    }
}
