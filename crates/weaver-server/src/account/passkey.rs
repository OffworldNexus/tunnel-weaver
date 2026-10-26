//! Passkeys: the registration and assertion ceremonies, and the challenges
//! they run on (WVR-163).
//!
//! A passkey is a whole way in: one gesture, no password and no emailed code.
//! The assertion the authenticator produces carries *user verification* (Face
//! ID, Touch ID, Windows Hello, a key's PIN), so it proves both possession and
//! the presence of the person — the same two things a password typed moments
//! ago and an emailed code prove between them. That is why it lands a session
//! at `Certain` at once and lets it fall to `Strong` when the confirmation
//! window ends (see [`crate::account::auth`]).
//!
//! Three ceremonies run here, all of them the same two-step shape — `begin`
//! issues a challenge and registers it; `finish` verifies the browser's answer:
//!
//! * **register** — an authenticated account adds a credential. The gate
//!   demands `Certain` for it: a credential outlives every password, so
//!   planting one must take a proof of presence, not merely of a session.
//! * **assert** — a sign-in for a *named* address, or a step-up for a session
//!   that already has one. Same ceremony, two callers.
//! * **discover** — a sign-in where nobody was named: the browser offers the
//!   passkeys it holds for us (the sign-in field's autofill) and the account is
//!   resolved from the credential that came back. We never trust the browser's
//!   idea of who that is: the credential id is looked up in the store, and the
//!   user handle it returned is only cross-checked against the stored one.
//!
//! The relying party is the account plane's own admin domain, and the origin is
//! the console's own origin: there is no third-party identity service and no
//! client secret anywhere in this. Attestation is deliberately neither
//! requested nor verified (the `attestation` feature is off), because platform
//! passkeys — the ones people actually have — cannot attest, and an allow-list
//! of authenticator models would exclude most of them for no gain here.
//!
//! The challenge state lives in memory, like [`crate::account::pairing`]: it is
//! a nonce for an interaction that lasts seconds, it must not survive a relay
//! restart, and it is single use.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use serde::Serialize;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, CredentialID, DiscoverableAuthentication,
    DiscoverableKey, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse,
};

use crate::account::AccountRuntime;
use crate::store::account::NewPasskey;
use crate::store::entity::passkey_credential;

/// How long a started ceremony stays finishable.
///
/// Long enough for a person to find their security key or satisfy a biometric
/// prompt, short enough that a challenge left behind in a stale tab cannot be
/// completed much later.
pub const CEREMONY_TTL_SECS: i64 = 300;

/// Why a ceremony could not be completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyError {
    /// No such ceremony, or it is past its lifetime: the challenge was not
    /// issued by this process, was already answered, or is too old. Unknown and
    /// expired are one answer on purpose, so a probe cannot tell them apart.
    UnknownCeremony,
    /// The ceremony could not be run or its answer did not verify: no usable
    /// credential, a wrong signature, a wrong origin or relying party, an
    /// unknown credential, or a handle that is not this credential's.
    Refused,
    /// The ceremony verified but the store could not be read or written.
    Unavailable,
}

impl PasskeyError {
    /// The message shown to the person (English; no locale yet).
    pub const fn message(self) -> &'static str {
        match self {
            PasskeyError::UnknownCeremony => "That passkey request has expired. Start again.",
            PasskeyError::Refused => "That passkey was not accepted. Try again.",
            PasskeyError::Unavailable => "That did not work. Try again in a moment.",
        }
    }
}

/// A started ceremony: the single-use handle that identifies it, and what the
/// browser has to be given to run it.
pub struct Started<T> {
    /// Single-use, and the only thing that ties `finish` to `begin`.
    pub handle: String,
    /// The ceremony's options, straight from `webauthn-rs`, for the browser.
    pub options: T,
}

/// One passkey as the console lists it.
///
/// The credential itself never leaves the relay: what the console gets is enough
/// to recognise a passkey and remove it, and nothing that could be replayed.
#[derive(Debug, Clone, Serialize)]
pub struct PasskeyView {
    /// The row id, which is what removal is by.
    pub id: i32,
    /// What the person called it; empty when they did not name it, in which
    /// case the console labels it from `transports` and `created_at`.
    pub name: String,
    /// The transports the authenticator announced, as the wire spells them
    /// (`internal`, `usb`, …). Empty when it announced none.
    pub transports: Vec<String>,
    pub created_at: i64,
    /// Absent until the passkey has actually been used to sign in.
    pub last_used_at: Option<i64>,
}

/// An assertion that verified.
pub struct Asserted {
    /// The account the credential belongs to, read from the store — never taken
    /// from the request.
    pub account_id: i32,
    /// Whether the authenticator verified the person as it signed. The
    /// possession half is proven either way; only this half is what makes the
    /// session `Certain`.
    pub user_verified: bool,
}

// ----- challenge registry --------------------------------------------------

/// Single-use, expiring handles for state that must not outlive its interaction.
///
/// `T` is whatever a ceremony has to remember between its two halves. It is
/// kept apart from the ceremonies themselves so the part with the security
/// property — a handle works exactly once, and only for a few minutes — can be
/// tested without an authenticator.
struct Handles<T> {
    inner: Arc<Mutex<HashMap<String, Entry<T>>>>,
}

struct Entry<T> {
    value: T,
    expires_at: i64,
}

/// The clone is the shared registry, not a copy of it; `T` need not be
/// `Clone`, which the ceremony payloads are not.
impl<T> Clone for Handles<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T> Default for Handles<T> {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<T> Handles<T> {
    /// Stores `value` under a fresh handle.
    fn start(&self, value: T, now: i64) -> String {
        let handle = crate::random_hex(32);
        let mut inner = self.inner.lock().expect("ceremonies mutex poisoned");
        // Drop what has already expired: this registry is only ever read through
        // `take`, so a ceremony nobody finished would otherwise sit in memory
        // for the life of the process.
        inner.retain(|_, entry| entry.expires_at > now);
        inner.insert(
            handle.clone(),
            Entry {
                value,
                expires_at: now + CEREMONY_TTL_SECS,
            },
        );
        handle
    }

    /// Takes the value behind `handle`, consuming it.
    ///
    /// An unknown handle, an expired one and a spent one are one answer: the
    /// caller learns only that there is nothing to finish.
    fn take(&self, handle: &str, now: i64) -> Option<T> {
        let entry = self
            .inner
            .lock()
            .expect("ceremonies mutex poisoned")
            .remove(handle)?;
        (entry.expires_at > now).then_some(entry.value)
    }

    /// How many handles are held, expired ones included (tests).
    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().expect("ceremonies mutex poisoned").len()
    }
}

/// A ceremony that has been started and not yet finished.
enum Pending {
    /// Adding a credential to `account_id`.
    Register {
        account_id: i32,
        registration: PasskeyRegistration,
    },
    /// An assertion for an account we already know: the address was given, or
    /// the session is being stepped up.
    Assert {
        account_id: i32,
        authentication: PasskeyAuthentication,
    },
    /// An assertion for an account nobody named: the browser picks.
    Discover {
        authentication: DiscoverableAuthentication,
    },
}

/// The in-memory registry of started ceremonies.
#[derive(Clone, Default)]
pub struct Ceremonies {
    handles: Handles<Pending>,
}

impl Ceremonies {
    /// Registers a started ceremony and returns its handle.
    fn start(&self, pending: Pending, now: i64) -> String {
        self.handles.start(pending, now)
    }

    /// Takes a started ceremony, consuming it.
    fn take(&self, handle: &str, now: i64) -> Option<Pending> {
        self.handles.take(handle, now)
    }

    /// Whether nothing is waiting (tests).
    pub fn is_empty(&self) -> bool {
        self.handles
            .inner
            .lock()
            .expect("ceremonies mutex poisoned")
            .is_empty()
    }
}

// ----- begin ---------------------------------------------------------------

/// Starts a registration for `account_id`.
///
/// The credential is asked to be *discoverable*: that is what lets the browser
/// offer it in the sign-in field without an address, and a passkey nobody is
/// offered is a passkey people forget they have. The library asks for
/// `discouraged` by default, and browsers treat `preferred` as `required` in any
/// case, so the practical difference is that an authenticator with nowhere to
/// store a discoverable credential cannot register one here — that account keeps
/// its password and emailed code, which stay the recovery route regardless.
pub async fn begin_register(
    rt: &AccountRuntime,
    account_id: i32,
    name: &str,
    email: &str,
    now: i64,
) -> Result<Started<serde_json::Value>, PasskeyError> {
    // Credentials already on the account are excluded, so one authenticator
    // cannot be enrolled twice under two names.
    let exclude: Vec<CredentialID> = rt
        .store
        .passkeys_for_account(account_id)
        .await
        .map_err(|_| PasskeyError::Unavailable)?
        .iter()
        .filter_map(|row| stored_credential(row).map(|passkey| passkey.cred_id().clone()))
        .collect();

    let (options, registration) = rt
        .webauthn
        .start_passkey_registration(
            user_handle(account_id),
            email,
            name,
            (!exclude.is_empty()).then_some(exclude),
        )
        .map_err(|error| {
            tracing::warn!(%error, "passkey registration could not be started");
            PasskeyError::Unavailable
        })?;

    let handle = rt.ceremonies.start(
        Pending::Register {
            account_id,
            registration,
        },
        now,
    );
    Ok(Started {
        handle,
        options: with_discoverable_credential(options),
    })
}

/// Starts an assertion for a known account: a sign-in by address, or a step-up.
pub async fn begin_assert(
    rt: &AccountRuntime,
    account_id: i32,
    now: i64,
) -> Result<Started<RequestChallengeResponse>, PasskeyError> {
    let credentials: Vec<Passkey> = rt
        .store
        .passkeys_for_account(account_id)
        .await
        .map_err(|_| PasskeyError::Unavailable)?
        .iter()
        .filter_map(stored_credential)
        .collect();
    if credentials.is_empty() {
        // Nothing to assert with. The caller decides what to say about it: on an
        // anonymous sign-in it must not be told apart from an unknown address.
        return Err(PasskeyError::Refused);
    }
    let (options, authentication) = rt
        .webauthn
        .start_passkey_authentication(&credentials)
        .map_err(|error| {
            tracing::warn!(%error, "passkey assertion could not be started");
            PasskeyError::Unavailable
        })?;
    let handle = rt.ceremonies.start(
        Pending::Assert {
            account_id,
            authentication,
        },
        now,
    );
    Ok(Started { handle, options })
}

/// Starts a discoverable assertion: nobody is named, the browser offers what it
/// holds for us.
pub fn begin_discover(
    rt: &AccountRuntime,
    now: i64,
) -> Result<Started<RequestChallengeResponse>, PasskeyError> {
    // `webauthn-rs` hands back options with `mediation: conditional`, which is
    // exactly the point: the passkey is offered inline in the sign-in field's
    // autofill ("conditional UI"), not as a separate modal.
    let (options, authentication) =
        rt.webauthn
            .start_discoverable_authentication()
            .map_err(|error| {
                tracing::warn!(%error, "discoverable passkey assertion could not be started");
                PasskeyError::Unavailable
            })?;
    let handle = rt
        .ceremonies
        .start(Pending::Discover { authentication }, now);
    Ok(Started { handle, options })
}

// ----- finish --------------------------------------------------------------

/// Finishes a registration and stores the credential.
///
/// Returns the stored row, whose `account_id` the caller must check against the
/// session it served: the ceremony carries the account it was started for, and
/// that is the account the credential is filed under.
pub async fn finish_register(
    rt: &AccountRuntime,
    handle: &str,
    credential: &RegisterPublicKeyCredential,
    name: &str,
    now: i64,
) -> Result<passkey_credential::Model, PasskeyError> {
    let Some(Pending::Register {
        account_id,
        registration,
    }) = rt.ceremonies.take(handle, now)
    else {
        return Err(PasskeyError::UnknownCeremony);
    };
    let passkey = rt
        .webauthn
        .finish_passkey_registration(credential, &registration)
        .map_err(|error| {
            tracing::warn!(account_id, %error, "passkey registration refused");
            PasskeyError::Refused
        })?;

    // A credential id belongs to one account, everywhere, for good: if this one
    // is already enrolled, the answer is a refusal rather than a second home for
    // it. The table's unique index is what actually enforces that; this only
    // makes the ordinary case say the right thing.
    let credential_id = credential_id_string(passkey.cred_id().as_ref());
    if rt
        .store
        .passkey_by_credential_id(&credential_id)
        .await
        .map_err(|_| PasskeyError::Unavailable)?
        .is_some()
    {
        tracing::warn!(
            account_id,
            "passkey registration refused: credential already enrolled"
        );
        return Err(PasskeyError::Refused);
    }

    let serialised = serde_json::to_string(&passkey).map_err(|error| {
        tracing::error!(account_id, %error, "passkey could not be serialised");
        PasskeyError::Unavailable
    })?;
    let row = rt
        .store
        .passkey_create(NewPasskey {
            account_id,
            credential_id,
            credential: serialised,
            user_unique_id: user_handle(account_id).to_string(),
            transports: transports_string(credential),
            name: name.trim().to_string(),
            created_at: now,
        })
        .await
        .map_err(|error| {
            tracing::error!(account_id, %error, "passkey could not be stored");
            PasskeyError::Unavailable
        })?;
    tracing::info!(account_id, passkey_id = row.id, "Passkey registered");
    Ok(row)
}

/// Finishes an anonymous sign-in: the handle decides which ceremony it was.
///
/// A sign-in may have started either the named or the discoverable ceremony and
/// has no business knowing which — the handle is the only thing that says. The
/// account always comes from the store, never from the request, which is what
/// makes it safe to finish a discoverable ceremony here at all.
pub async fn finish_signin(
    rt: &AccountRuntime,
    handle: &str,
    credential: &PublicKeyCredential,
    now: i64,
) -> Result<Asserted, PasskeyError> {
    match rt.ceremonies.take(handle, now) {
        Some(Pending::Assert {
            account_id,
            authentication,
        }) => assert_with(rt, account_id, &authentication, credential, now).await,
        Some(Pending::Discover { authentication }) => {
            discover_with(rt, &authentication, credential, now).await
        }
        // A registration is finished through its own route, and a spent or
        // unknown handle is nothing to finish.
        _ => Err(PasskeyError::UnknownCeremony),
    }
}

/// Finishes a step-up: an assertion for the session's own account.
///
/// Both shapes are accepted, because what an assertion is *asked* for is the
/// browser's business: a password manager answers a usernameless request (the
/// credential picks the account) while our own options may name it. The caller
/// checks that the account it returns is the session's, which is what keeps a
/// discovery started elsewhere from lifting this session.
pub async fn finish_step_up(
    rt: &AccountRuntime,
    handle: &str,
    credential: &PublicKeyCredential,
    now: i64,
) -> Result<Asserted, PasskeyError> {
    match rt.ceremonies.take(handle, now) {
        Some(Pending::Assert {
            account_id,
            authentication,
        }) => assert_with(rt, account_id, &authentication, credential, now).await,
        Some(Pending::Discover { authentication }) => {
            discover_with(rt, &authentication, credential, now).await
        }
        _ => Err(PasskeyError::UnknownCeremony),
    }
}

/// Finishes an assertion whose account the ceremony named.
async fn assert_with(
    rt: &AccountRuntime,
    account_id: i32,
    authentication: &PasskeyAuthentication,
    credential: &PublicKeyCredential,
    now: i64,
) -> Result<Asserted, PasskeyError> {
    let result = rt
        .webauthn
        .finish_passkey_authentication(credential, authentication)
        .map_err(|error| {
            tracing::warn!(account_id, %error, "passkey assertion refused");
            PasskeyError::Refused
        })?;
    // The credential that signed must be one the store filed under this account:
    // the ceremony named the account, and the credential has to agree.
    let Some(row) = rt
        .store
        .passkey_by_credential_id(&credential_id_string(credential.get_credential_id()))
        .await
        .map_err(|_| PasskeyError::Unavailable)?
        .filter(|row| row.account_id == account_id)
    else {
        tracing::warn!(
            account_id,
            "passkey assertion named a credential that is not this account's"
        );
        return Err(PasskeyError::Refused);
    };
    record_use(rt, &row, &result, now).await?;
    Ok(Asserted {
        account_id,
        user_verified: result.user_verified(),
    })
}

/// Finishes a discoverable assertion: resolves the account from the credential
/// the browser produced.
///
/// The account is the credential's owner as the *store* knows it. The user
/// handle the authenticator returned is only cross-checked against the stored
/// one: it is a second, independent statement of which account this credential
/// belongs to, and the two must agree.
async fn discover_with(
    rt: &AccountRuntime,
    authentication: &DiscoverableAuthentication,
    credential: &PublicKeyCredential,
    now: i64,
) -> Result<Asserted, PasskeyError> {
    let (claimed_handle, cred_id) = rt
        .webauthn
        .identify_discoverable_authentication(credential)
        .map_err(|error| {
            tracing::warn!(%error, "discoverable passkey assertion could not be identified");
            PasskeyError::Refused
        })?;
    let Some(row) = rt
        .store
        .passkey_by_credential_id(&credential_id_string(cred_id))
        .await
        .map_err(|_| PasskeyError::Unavailable)?
    else {
        tracing::warn!("discoverable passkey assertion named an unknown credential");
        return Err(PasskeyError::Refused);
    };
    if row.user_unique_id != claimed_handle.to_string() {
        tracing::warn!(
            account_id = row.account_id,
            "discoverable passkey assertion carried another account's user handle"
        );
        return Err(PasskeyError::Refused);
    }
    let Some(passkey) = stored_credential(&row) else {
        tracing::error!(
            account_id = row.account_id,
            passkey_id = row.id,
            "a stored passkey could not be read back"
        );
        return Err(PasskeyError::Unavailable);
    };
    let result = rt
        .webauthn
        .finish_discoverable_authentication(
            credential,
            authentication.clone(),
            &[DiscoverableKey::from(&passkey)],
        )
        .map_err(|error| {
            tracing::warn!(account_id = row.account_id, %error, "discoverable assertion refused");
            PasskeyError::Refused
        })?;
    record_use(rt, &row, &result, now).await?;
    Ok(Asserted {
        account_id: row.account_id,
        user_verified: result.user_verified(),
    })
}

// ----- views and internals -------------------------------------------------

/// One stored row as the console lists it.
pub fn view(row: &passkey_credential::Model) -> PasskeyView {
    PasskeyView {
        id: row.id,
        name: row.name.clone(),
        transports: row
            .transports
            .split(',')
            .filter(|transport| !transport.is_empty())
            .map(str::to_string)
            .collect(),
        created_at: row.created_at,
        last_used_at: row.last_used_at,
    }
}

/// The WebAuthn user handle of an account.
///
/// Derived, never random: it is stored inside the credential and comes back on
/// every discoverable assertion, so it has to be the same value every time. It
/// is deliberately not the account id — the handle is what the browser's
/// passkey picker shows and what lives on the authenticator, so it should say
/// nothing an observer could act on.
fn user_handle(account_id: i32) -> Uuid {
    Uuid::new_v5(
        &Uuid::NAMESPACE_OID,
        format!("tunnel-weaver:account:{account_id}").as_bytes(),
    )
}

/// The wire spelling of a credential id: base64url without padding, exactly
/// what `PublicKeyCredential.rawId` carries.
fn credential_id_string(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The credential a stored row holds, or `None` when the row cannot be read
/// back — a row that is not a credential is never a valid one.
fn stored_credential(row: &passkey_credential::Model) -> Option<Passkey> {
    serde_json::from_str(&row.credential).ok()
}

/// Records that a credential has just been used: when, and the refreshed
/// properties the authenticator reported.
///
/// The counter inside the credential is what the next assertion's clone
/// detection compares against, so the stored copy is re-serialised whenever
/// `webauthn-rs` says the credential changed.
async fn record_use(
    rt: &AccountRuntime,
    row: &passkey_credential::Model,
    result: &AuthenticationResult,
    now: i64,
) -> Result<(), PasskeyError> {
    let mut passkey = stored_credential(row).ok_or(PasskeyError::Unavailable)?;
    let refreshed = match passkey.update_credential(result) {
        Some(true) => Some(serde_json::to_string(&passkey).map_err(|error| {
            tracing::error!(passkey_id = row.id, %error, "passkey could not be re-serialised");
            PasskeyError::Unavailable
        })?),
        _ => None,
    };
    rt.store
        .passkey_record_use(row.id, refreshed.as_deref(), now)
        .await
        .map_err(|_| PasskeyError::Unavailable)
}

/// The registration options, with the credential asked to be discoverable.
///
/// `webauthn-rs` asks for `discouraged` on a passkey registration, and that one
/// value is the whole difference between a passkey the browser can offer without
/// an address and one it cannot: it is decided here, at registration, and
/// nothing at sign-in can recover it. So it is raised to `required`.
///
/// `required` rather than `preferred` deliberately: authenticators and password
/// managers read `preferred` as "only if it is no trouble" and many of them
/// simply do not bother, which silently costs the passkey its place in the
/// sign-in field's autofill. The price is that an authenticator with nowhere to
/// store a discoverable credential cannot register one at all — and such a
/// person keeps their password and emailed codes, which stay the way in.
///
/// It is a *client hint* on the options the browser is handed — the ceremony
/// state is untouched — and it is set through the options' own JSON because the
/// crate does not re-export the type that names the field. A test pins the
/// resulting shape, so a rename there fails loudly rather than quietly taking
/// the autofill experience away.
fn with_discoverable_credential(options: CreationChallengeResponse) -> serde_json::Value {
    let mut options = serde_json::to_value(options).unwrap_or(serde_json::Value::Null);
    if let Some(selection) = options
        .pointer_mut("/publicKey/authenticatorSelection")
        .and_then(serde_json::Value::as_object_mut)
    {
        selection.insert(
            "residentKey".to_string(),
            serde_json::Value::String("required".to_string()),
        );
        // The legacy twin of the same field: `preferred`/`required` is the modern
        // spelling, but a client that only knows the old one must not read this
        // as "a resident key is optional".
        selection.insert(
            "requireResidentKey".to_string(),
            serde_json::Value::Bool(true),
        );
    }
    options
}

/// The transports the registration announced, comma-joined for storage.
///
/// They are a UI hint the browser reports on the response (a key on a port
/// versus this very device), never a security property, and the wire spelling
/// comes from the type's own `Serialize` rather than a second mapping kept in
/// step by hand.
fn transports_string(credential: &RegisterPublicKeyCredential) -> String {
    let announced = credential
        .response
        .transports
        .as_ref()
        .and_then(|transports| serde_json::to_value(transports).ok())
        .unwrap_or(serde_json::Value::Null);
    announced
        .as_array()
        .map(|transports| {
            transports
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handle_is_derived_and_stable() {
        let first = user_handle(7);
        assert_eq!(first, user_handle(7));
        assert_ne!(first, user_handle(8));
        // A UUID, not the account id: this value travels to the authenticator.
        assert_eq!(first.to_string().len(), 36);
    }

    #[test]
    fn credential_ids_use_the_wire_spelling() {
        assert_eq!(credential_id_string(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn a_handle_works_once() {
        let handles = Handles::default();
        let handle = handles.start("ceremony", 1_000);
        assert_eq!(handles.take(&handle, 1_000), Some("ceremony"));
        assert_eq!(handles.take(&handle, 1_000), None);
        assert_eq!(handles.len(), 0);
    }

    #[test]
    fn a_handle_expires() {
        let handles = Handles::default();
        let handle = handles.start("ceremony", 1_000);
        assert_eq!(handles.take(&handle, 1_000 + CEREMONY_TTL_SECS), None);
    }

    #[test]
    fn starting_sweeps_what_has_expired() {
        let handles = Handles::default();
        handles.start("stale", 1_000);
        handles.start("fresh", 1_000 + CEREMONY_TTL_SECS + 1);
        assert_eq!(handles.len(), 1);
    }
}
