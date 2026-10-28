//! Authenticator apps: the shared secret behind one, the codes it produces, and
//! the sealed form the store keeps (WVR-166).
//!
//! The protocol is RFC 6238 TOTP over RFC 4226 HOTP with HMAC-SHA-1 — the lowest
//! common denominator every authenticator app implements, and the only one this
//! relay will speak, because an app cannot be asked to upgrade. Everything here
//! is a plain function of `(secret, time)`: no state, so an app, this relay and a
//! test all compute the same code without agreeing on anything but the clock.
//!
//! Two properties are security-critical and neither is obvious from a signature:
//!
//! * **The acceptance window.** A code is accepted for the step it belongs to
//!   and for the step either side, which is 90 seconds of tolerance in total.
//!   That covers a phone whose clock has drifted; what keeps the extra width from
//!   being a second chance for an attacker is the *replay guard* — the step a
//!   code actually belongs to is recorded in the store, so an observed code is
//!   refused however long it stays inside the window.
//! * **The sealed secret.** What the store keeps is `nonce ‖ ciphertext` under
//!   AES-256-GCM, with the account id as associated data. The account id belongs
//!   in there: it is what makes a sealed secret copied into another account's row
//!   fail to open, rather than quietly become that account's second factor.

use hmac::{Hmac, KeyInit, Mac};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use sha1::Sha1;
use subtle::ConstantTimeEq;

use crate::config::TotpKey;
use crate::store::Store;
use crate::store::account::NewTotpCredential;
use crate::store::entity::totp_credential;

/// How long one code is valid for. RFC 6238's default, and what every app
/// assumes from a `period` it does not read.
pub const STEP_SECS: i64 = 30;

/// How many digits a code has, as the URI promises the app.
pub const DIGITS: u32 = 6;

/// How many steps either side of now are accepted.
///
/// One, deliberately, and not more: every extra step widens the window in which
/// an observed code is still usable, and the replay guard only refuses codes that
/// were actually *used*, not ones still in flight.
const DRIFT_STEPS: i64 = 1;

/// The name the authenticator app shows beside the account (the `issuer`, and
/// the first half of the label).
pub const ISSUER: &str = "Tunnel Weaver";

/// The secret's length: 160 bits, the size RFC 4226 recommends for HMAC-SHA-1
/// and the one every app is comfortable with.
const SECRET_BYTES: usize = 20;

/// Why a secret could not be sealed or opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// The configured key is empty or is not a 32-byte hex key.
    Key,
    /// The stored value is malformed, or it was sealed under a different key or
    /// for a different account.
    Tampered,
}

impl SealError {
    /// The line to log. These are operator problems, never something to show a
    /// person: an enrolment cannot say more than "start again".
    pub const fn message(self) -> &'static str {
        match self {
            SealError::Key => {
                "account.totp_key is not a 32-byte hex key; authenticator-app secrets cannot be read"
            }
            SealError::Tampered => {
                "a stored authenticator-app secret could not be opened (wrong key, or the row changed)"
            }
        }
    }
}

/// A fresh random secret.
pub fn generate_secret() -> Vec<u8> {
    let mut secret = vec![0u8; SECRET_BYTES];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut secret);
    secret
}

/// The time step a moment belongs to.
pub fn step_at(now: i64) -> i64 {
    now.div_euclid(STEP_SECS)
}

/// The code a secret produces for a step, as [`DIGITS`] decimal characters.
///
/// This is the whole of RFC 4226: HMAC over the big-endian step, then dynamic
/// truncation from the low nibble of the last byte. It is public because the
/// tests assert the RFC's own vectors against it.
pub fn code_for_step(secret: &[u8], step: i64) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts a key of any length");
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let truncated = u32::from_be_bytes([
        digest[offset],
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]) & 0x7fff_ffff;
    format!(
        "{:0width$}",
        truncated % 10u32.pow(DIGITS),
        width = DIGITS as usize
    )
}

/// Matches a submitted code against the accepted window, returning the step the
/// code belongs to.
///
/// The *step*, not merely "yes": that is what the caller records to burn the
/// code, so the window can never be re-entered with a code that was already
/// accepted. The current step is tried first, so a code that somehow matched two
/// steps would be recorded as the most recent one.
///
/// The comparison is constant-time. A code is a secret shared with the app, and
/// how many of its digits matched must not be observable.
pub fn match_code(secret: &[u8], candidate: &str, now: i64) -> Option<i64> {
    let candidate = candidate.trim();
    if candidate.len() != DIGITS as usize {
        return None;
    }
    let current = step_at(now);
    [0, -DRIFT_STEPS, DRIFT_STEPS]
        .into_iter()
        .find_map(|offset| {
            let step = current + offset;
            let expected = code_for_step(secret, step);
            bool::from(expected.as_bytes().ct_eq(candidate.as_bytes())).then_some(step)
        })
}

/// The secret as an authenticator app wants it spelled: RFC 4648 base32,
/// uppercase, unpadded.
///
/// Unpadded because that is what a QR code carries and what the apps accept when
/// a secret is typed by hand; the padding would be three characters of ceremony
/// the person would have to copy correctly.
pub fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    for chunk in bytes.chunks(5) {
        let mut block = [0u8; 5];
        block[..chunk.len()].copy_from_slice(chunk);
        let bits = u64::from_be_bytes([0, 0, 0, block[0], block[1], block[2], block[3], block[4]]);
        for index in 0..8 {
            out.push(ALPHABET[((bits >> (35 - index * 5)) & 0x1f) as usize] as char);
        }
    }
    out.truncate((bytes.len() * 8).div_ceil(5));
    out
}

/// The `otpauth://` URI an authenticator app is set up from.
///
/// `label` is what the app shows beside the issuer — the account's address — and
/// the secret travels as base32, which is the only spelling the format defines.
pub fn otpauth_uri(label: &str, secret: &[u8]) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        percent_encode(ISSUER),
        percent_encode(label),
        base32_encode(secret),
        percent_encode(ISSUER),
    )
}

/// Percent-encodes everything outside the unreserved set (plus `@`, which is
/// legal in a path segment and is the one character of an address a person would
/// notice being escaped).
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'@') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Seals a secret for storage under the account's TOTP key.
///
/// The returned value is the nonce followed by the ciphertext, hex-encoded: one
/// opaque string the store can hold without ever knowing what it is.
pub fn seal(key: &TotpKey, account_id: i32, secret: &[u8]) -> Result<String, SealError> {
    let sealing = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, &key.bytes().ok_or(SealError::Key)?)
            .map_err(|_| SealError::Key)?,
    );
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| SealError::Key)?;
    let mut in_out = secret.to_vec();
    sealing
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(account_id.to_be_bytes().as_slice()),
            &mut in_out,
        )
        .map_err(|_| SealError::Key)?;
    let mut sealed = nonce.to_vec();
    sealed.extend_from_slice(&in_out);
    Ok(hex::encode(sealed))
}

/// Opens a sealed secret, binding it back to the account it was sealed for.
///
/// A failure here is not "wrong code": it means the stored secret cannot be read
/// at all (a changed `account.totp_key`, or a row that was tampered with). The
/// caller logs it and falls back to the emailed code rather than failing the
/// sign-in.
pub fn open(key: &TotpKey, account_id: i32, sealed: &str) -> Result<Vec<u8>, SealError> {
    let opening = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, &key.bytes().ok_or(SealError::Key)?)
            .map_err(|_| SealError::Key)?,
    );
    let raw = hex::decode(sealed).map_err(|_| SealError::Tampered)?;
    let (nonce, ciphertext) = raw.split_at_checked(NONCE_LEN).ok_or(SealError::Tampered)?;
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| SealError::Tampered)?;
    let mut in_out = ciphertext.to_vec();
    let plain = opening
        .open_in_place(
            nonce,
            Aad::from(account_id.to_be_bytes().as_slice()),
            &mut in_out,
        )
        .map_err(|_| SealError::Tampered)?;
    Ok(plain.to_vec())
}

// ----- the account's side: enrolling, confirming, entering a code -----------

/// How many wrong codes one session may submit before this step is closed.
///
/// Six digits behind a stolen password are a real guessing surface, and with a
/// one-step drift window three codes are valid at any instant. The allowance is
/// counted from the session's own failures (its `totp_failed` rows), so it can
/// only ever stop the session that spent them: a guesser exhausts their own and
/// never the owner's, and the emailed code remains a way through for both.
pub const MAX_WRONG_CODES: u64 = 5;

/// Why enrolling, confirming or entering a code was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatorError {
    /// No such app on this account: a guessed, stale, or another account's id.
    Unknown,
    /// The enrolment was already confirmed — possibly by a request that raced
    /// this one.
    Confirmed,
    /// The digits matched no step in the window.
    Wrong,
    /// The code belonged to a step that was already accepted: a replay, or the
    /// same code submitted twice.
    Used,
    /// The session has spent its wrong-code allowance.
    TooManyAttempts,
    /// Nothing can be sealed: `account.totp_key` is missing or unusable.
    NoKey,
    /// The store could not be read or written.
    Unavailable,
}

impl AuthenticatorError {
    /// The message shown to the person (English; no locale yet).
    pub const fn message(self) -> &'static str {
        match self {
            AuthenticatorError::Unknown => "That authenticator app is not on this account.",
            AuthenticatorError::Confirmed => "That authenticator app is already confirmed.",
            AuthenticatorError::Wrong => "That code is not right. Check it and try again.",
            AuthenticatorError::Used => "That code has already been used. Wait for the next one.",
            AuthenticatorError::TooManyAttempts => "Too many tries. Use your emailed code instead.",
            AuthenticatorError::NoKey => "Authenticator apps are temporarily unavailable.",
            AuthenticatorError::Unavailable => "That did not work. Try again in a moment.",
        }
    }
}

/// A freshly begun enrolment.
///
/// `secret` is the base32 spelling an app is set up with — the only form the
/// secret ever leaves the relay in — and it is returned exactly once, on this
/// response. Afterwards it exists only sealed.
pub struct Begun {
    pub id: i32,
    pub secret: String,
    pub uri: String,
}

/// One authenticated app as the console lists it.
///
/// Only *confirmed* apps reach here — the console never shows an enrolment that
/// was begun and never proved, and the sweep deletes the ones nobody finished —
/// so there is no "pending" state to describe. Nothing of the secret is here
/// either: enough to recognise an app, see when it was added and last used, and
/// remove it.
#[derive(Debug, Clone, Serialize)]
pub struct AuthenticatorView {
    /// The row id, which is what removing is by.
    pub id: i32,
    /// What the person called it; empty when they did not name it, in which case
    /// the console labels it from when it was added.
    pub name: String,
    pub created_at: i64,
    /// Absent until a code from this app has been accepted.
    pub last_used_at: Option<i64>,
}

/// Lists an app as the console shows it.
pub fn view(row: &totp_credential::Model) -> AuthenticatorView {
    AuthenticatorView {
        id: row.id,
        name: row.name.clone(),
        created_at: row.created_at,
        last_used_at: row.last_used_at,
    }
}

/// Starts an enrolment: a fresh secret, sealed and stored unconfirmed.
///
/// `address` is the account's own address and `name` is what the person called
/// the app. The name is the label the authenticator app displays — falling back
/// to the address when there is none — because that is the whole point of naming
/// one: two apps enrolled on one account are told apart in the authenticator
/// itself, not only in the console.
///
/// The row is written before the response is built, so the secret a person has
/// already scanned is one the relay can confirm. An enrolment abandoned here
/// leaves an unconfirmed row: not a factor, never listed, and dropped by the
/// account sweep.
pub async fn begin(
    store: &Store,
    key: &TotpKey,
    account_id: i32,
    address: &str,
    name: &str,
    now: i64,
) -> Result<Begun, AuthenticatorError> {
    let name = name.trim();
    let secret = generate_secret();
    let sealed = seal(key, account_id, &secret).map_err(|error| {
        tracing::error!(
            account_id,
            reason = error.message(),
            "an authenticator secret could not be sealed"
        );
        AuthenticatorError::NoKey
    })?;
    let row = store
        .totp_credential_create(NewTotpCredential {
            account_id,
            name: name.to_string(),
            secret: sealed,
            created_at: now,
        })
        .await
        .map_err(|_| AuthenticatorError::Unavailable)?;
    let label = if name.is_empty() { address } else { name };
    Ok(Begun {
        id: row.id,
        secret: base32_encode(&secret),
        uri: otpauth_uri(label, &secret),
    })
}

/// Confirms a pending enrolment with a code the app produced.
///
/// The step that proved the app is recorded as used in the same write that
/// confirms it: a code that has enrolled an app has been accepted, and must not
/// be accepted again at sign-in.
pub async fn confirm(
    store: &Store,
    key: &TotpKey,
    account_id: i32,
    id: i32,
    candidate: &str,
    now: i64,
) -> Result<totp_credential::Model, AuthenticatorError> {
    let Some(row) = store
        .totp_credential(id, account_id)
        .await
        .map_err(|_| AuthenticatorError::Unavailable)?
    else {
        return Err(AuthenticatorError::Unknown);
    };
    if row.confirmed_at.is_some() {
        return Err(AuthenticatorError::Confirmed);
    }
    let secret = open(key, account_id, &row.secret).map_err(|error| {
        tracing::warn!(
            account_id,
            app_id = id,
            reason = error.message(),
            "a pending authenticator secret could not be opened"
        );
        AuthenticatorError::NoKey
    })?;
    let Some(step) = match_code(&secret, candidate, now) else {
        return Err(AuthenticatorError::Wrong);
    };
    if !store
        .totp_confirm(id, account_id, now, step)
        .await
        .map_err(|_| AuthenticatorError::Unavailable)?
    {
        // Confirmed by a request that raced this one.
        return Err(AuthenticatorError::Confirmed);
    }
    store
        .totp_credential(id, account_id)
        .await
        .map_err(|_| AuthenticatorError::Unavailable)?
        .ok_or(AuthenticatorError::Unknown)
}

/// Verifies a code at sign-in against every confirmed app of the account,
/// consuming the step it belongs to.
///
/// `wrong_codes` is how many this session has already submitted; the caller
/// reads it from the session's own failures, so the allowance cannot reach
/// another session. A secret that cannot be opened is logged and skipped rather
/// than failing the sign-in: a rotated `account.totp_key` must cost the account
/// its app, not its way in — the emailed code still works.
pub async fn verify(
    store: &Store,
    key: &TotpKey,
    account_id: i32,
    candidate: &str,
    wrong_codes: u64,
    now: i64,
) -> Result<(), AuthenticatorError> {
    if wrong_codes >= MAX_WRONG_CODES {
        return Err(AuthenticatorError::TooManyAttempts);
    }
    // Every call gets an answer, so no candidate code is distinguished by how
    // many apps were tried before it.
    let rows = store
        .totp_confirmed_for_account(account_id)
        .await
        .map_err(|_| AuthenticatorError::Unavailable)?;
    for row in rows {
        let Ok(secret) = open(key, account_id, &row.secret) else {
            tracing::warn!(
                account_id,
                app_id = row.id,
                "an enrolled authenticator secret could not be opened; it is skipped"
            );
            continue;
        };
        let Some(step) = match_code(&secret, candidate, now) else {
            continue;
        };
        return match store.totp_record_use(row.id, step, now).await {
            Ok(true) => Ok(()),
            // That step was already accepted: a replay, or a double submit.
            Ok(false) => Err(AuthenticatorError::Used),
            Err(_) => Err(AuthenticatorError::Unavailable),
        };
    }
    Err(AuthenticatorError::Wrong)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RFC 6238 test secret: the ASCII digits `12345678901234567890`.
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc6238_sha1_vectors() {
        // The RFC's own table (T0 = 0, X = 30), whose codes are eight digits;
        // this relay issues six, which is the same truncation reduced, so the
        // vectors are asserted on their last six digits.
        for (unix, expected) in [
            (59_i64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(
                code_for_step(RFC_SECRET, step_at(unix)),
                expected[expected.len() - DIGITS as usize..],
                "RFC 6238 vector at T={unix}"
            );
        }
    }

    #[test]
    fn base32_matches_the_well_known_spelling() {
        // The same secret, as every authenticator app expects to read it.
        assert_eq!(
            base32_encode(RFC_SECRET),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
        // Lengths that are not a multiple of five must come out unpadded rather
        // than padded with `=`.
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b""), "");
        assert!(!base32_encode(b"f").contains('='));
    }

    #[test]
    fn a_code_is_accepted_inside_the_window_and_not_beyond_it() {
        let now = 1_234_567_890;
        for offset in [-1_i64, 0, 1] {
            let step = step_at(now) + offset;
            let code = code_for_step(RFC_SECRET, step);
            assert_eq!(
                match_code(RFC_SECRET, &code, now),
                Some(step),
                "a code from {offset} steps away is inside the window"
            );
        }
        for offset in [-2_i64, 2, 10] {
            let code = code_for_step(RFC_SECRET, step_at(now) + offset);
            assert_eq!(
                match_code(RFC_SECRET, &code, now),
                None,
                "a code from {offset} steps away is outside the window"
            );
        }
    }

    #[test]
    fn the_matched_step_is_the_codes_own_step() {
        // The replay guard depends on this: a code observed at one step is
        // recorded against *that* step, so submitting it a step later still
        // matches the old step and is refused rather than looking fresh.
        let step = step_at(1_234_567_890);
        let code = code_for_step(RFC_SECRET, step - 1);
        assert_eq!(match_code(RFC_SECRET, &code, 1_234_567_890), Some(step - 1));
        // Whitespace around a typed code is tolerated; anything else is not.
        assert_eq!(
            match_code(RFC_SECRET, &format!(" {code} "), 1_234_567_890),
            Some(step - 1)
        );
        assert_eq!(match_code(RFC_SECRET, "12345", 1_234_567_890), None);
        assert_eq!(match_code(RFC_SECRET, "1234567", 1_234_567_890), None);
        assert_eq!(match_code(RFC_SECRET, "abcdef", 1_234_567_890), None);
    }

    #[test]
    fn the_uri_carries_everything_an_app_needs() {
        let uri = otpauth_uri("person@weaver.test", RFC_SECRET);
        assert!(uri.starts_with("otpauth://totp/Tunnel%20Weaver:person@weaver.test?"));
        assert!(uri.contains("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
        assert!(uri.contains("issuer=Tunnel%20Weaver"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    #[test]
    fn a_sealed_secret_opens_for_its_own_account_only() {
        let key = TotpKey::generate();
        let secret = generate_secret();
        let sealed = seal(&key, 7, &secret).expect("sealing works with a generated key");
        assert_eq!(open(&key, 7, &sealed).expect("it opens"), secret);
        // Another account's row must not open it: the id is authenticated.
        assert_eq!(open(&key, 8, &sealed), Err(SealError::Tampered));
        // Neither must another key, nor a value that was edited.
        let other = TotpKey::generate();
        assert_eq!(open(&other, 7, &sealed), Err(SealError::Tampered));
        let mut edited = sealed.clone();
        edited.pop();
        edited.push(if sealed.ends_with('0') { '1' } else { '0' });
        assert_eq!(open(&key, 7, &edited), Err(SealError::Tampered));
        assert_eq!(open(&key, 7, "not hex"), Err(SealError::Tampered));
        assert_eq!(open(&key, 7, "abcd"), Err(SealError::Tampered));
    }

    #[test]
    fn an_empty_or_malformed_key_is_refused_rather_than_defaulted() {
        let empty = TotpKey::default();
        assert_eq!(seal(&empty, 1, b"secret"), Err(SealError::Key));
        assert_eq!(open(&empty, 1, "00"), Err(SealError::Key));
        let short: TotpKey = serde_json::from_str("\"00ff\"").expect("a hex string deserialises");
        assert_eq!(seal(&short, 1, b"secret"), Err(SealError::Key));
    }

    #[test]
    fn sealed_secrets_are_not_the_plaintext() {
        let key = TotpKey::generate();
        let secret = generate_secret();
        let sealed = seal(&key, 1, &secret).expect("sealing works");
        assert!(!sealed.contains(&hex::encode(&secret)));
        assert_ne!(sealed, hex::encode(&secret));
        // Two sealings of the same secret differ: the nonce is random.
        assert_ne!(seal(&key, 1, &secret).expect("sealing works"), sealed);
    }

    #[test]
    fn every_seal_error_has_a_line_to_log() {
        for error in [SealError::Key, SealError::Tampered] {
            assert!(!error.message().is_empty());
        }
    }
}
