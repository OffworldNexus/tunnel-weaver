//! Browser sessions and CSRF cookies (WVR-36).
//!
//! A session is an opaque random token carried in a `__Host-` Secure, HttpOnly,
//! `SameSite=Lax` cookie. The server stores only its SHA-256 digest, so a stolen
//! database cannot be replayed as a live session and a leaked cookie cannot be
//! recovered from storage. Logout *invalidates* the row rather than deleting it,
//! so a replayed cookie finds a dead session rather than no session at all.
//! Login always mints a fresh token, which is the session-rotation guarantee.
//!
//! CSRF uses a second, script-readable `__Host-` cookie plus a matching
//! `X-CSRF-Token` header (double submit) and an Origin / `Sec-Fetch-Site` check
//! on the server. Logout is POST-only; no state change is reachable through GET.

use http::HeaderMap;
use http::header::COOKIE;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::store::entity::account;
use crate::store::{Store, StoreError};

/// Session cookie name. The `__Host-` prefix forces `Secure; Path=/` and forbids
/// a `Domain`, so the cookie is scoped to exactly the admin host.
pub const SESSION_COOKIE: &str = "__Host-weaver_session";
/// CSRF double-submit cookie name (must be readable by the SPA's script).
pub const CSRF_COOKIE: &str = "__Host-weaver_csrf";
/// Header the SPA echoes the CSRF cookie in on state-changing requests.
pub const CSRF_HEADER: &str = "x-csrf-token";

/// Generates a fresh 256-bit opaque token as lowercase hex.
pub fn new_token() -> String {
    random_hex(32)
}

/// The stored form of a bearer secret: SHA-256, lowercase hex.
pub fn token_hash(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Cryptographically random lowercase-hex string of `bytes * 2` characters.
pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut buf);
    let mut out = String::with_capacity(bytes * 2);
    for byte in buf {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Returns the value of cookie `name` from a request's `Cookie` header.
pub fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        if let Some((key, value)) = part.trim().split_once('=')
            && key == name
        {
            return Some(value.to_string());
        }
    }
    None
}

/// Formats a `Set-Cookie` value for a `__Host-` cookie.
///
/// `Path=/` and (when `secure`) `Secure` are mandatory for the `__Host-` prefix;
/// no `Domain` is emitted.
pub fn set_cookie(
    name: &str,
    value: &str,
    max_age: Option<i64>,
    http_only: bool,
    secure: bool,
) -> String {
    use std::fmt::Write;
    let mut out = format!("{name}={value}; Path=/; SameSite=Lax");
    if let Some(age) = max_age {
        let _ = write!(out, "; Max-Age={age}");
    }
    if http_only {
        out.push_str("; HttpOnly");
    }
    if secure {
        out.push_str("; Secure");
    }
    out
}

/// Owns the session lifetime policy and the cookie formatting around the store.
#[derive(Clone)]
pub struct Sessions {
    store: Store,
    ttl_secs: i64,
    secure: bool,
}

impl Sessions {
    /// `secure` should be true everywhere except local plain-HTTP development,
    /// where a `Secure` cookie would be dropped by the browser.
    pub fn new(store: Store, ttl_secs: i64, secure: bool) -> Self {
        Self {
            store,
            ttl_secs,
            secure,
        }
    }

    /// Mints a fresh session for `account_id`, returning the raw cookie token.
    /// Because the raw token is random, this is also the login-rotation step.
    pub async fn create(&self, account_id: i32, now: i64) -> Result<String, StoreError> {
        let raw = new_token();
        self.store
            .session_create(account_id, &token_hash(&raw), now, now + self.ttl_secs)
            .await?;
        Ok(raw)
    }

    /// Resolves a raw cookie token to its account when the session is live.
    pub async fn account(&self, raw: &str, now: i64) -> Result<Option<account::Model>, StoreError> {
        let Some(session) = self.store.session_live(&token_hash(raw), now).await? else {
            return Ok(None);
        };
        self.store.account_by_id(session.account_id).await
    }

    /// Invalidates the current session (logout). Returns whether a live row was
    /// retired.
    pub async fn invalidate(&self, raw: &str, now: i64) -> Result<bool, StoreError> {
        self.store.session_invalidate(&token_hash(raw), now).await
    }

    /// The `Set-Cookie` value that starts a browser session.
    pub fn session_cookie(&self, raw: &str) -> String {
        set_cookie(SESSION_COOKIE, raw, Some(self.ttl_secs), true, self.secure)
    }

    /// The `Set-Cookie` value that clears the session cookie.
    pub fn clear_session_cookie(&self) -> String {
        set_cookie(SESSION_COOKIE, "", Some(0), true, self.secure)
    }

    /// The `Set-Cookie` value for a fresh CSRF double-submit cookie.
    pub fn csrf_cookie(&self, token: &str) -> String {
        set_cookie(CSRF_COOKIE, token, Some(self.ttl_secs), false, self.secure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_hash_is_stable_and_lowercase() {
        assert_eq!(
            token_hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(new_token().len(), 64);
        assert_eq!(new_token().len(), 64); // different each call
    }

    #[test]
    fn cookie_header_is_parsed_by_name() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            "a=1; __Host-weaver_session=xyz; b=2".parse().unwrap(),
        );
        assert_eq!(cookie(&headers, SESSION_COOKIE).as_deref(), Some("xyz"));
        assert_eq!(cookie(&headers, "missing"), None);
    }

    #[test]
    fn host_cookies_carry_the_required_attributes() {
        let value = set_cookie("__Host-x", "v", Some(60), true, true);
        assert!(value.contains("Path=/"));
        assert!(value.contains("Secure"));
        assert!(value.contains("HttpOnly"));
        assert!(value.contains("SameSite=Lax"));
        assert!(!value.contains("Domain"));
    }
}
