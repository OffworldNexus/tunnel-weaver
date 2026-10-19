//! Password policy: Argon2id hashing and breach screening.
//!
//! Raw passwords are never persisted; the store keeps only the PHC-encoded
//! Argon2id string, which embeds the algorithm, version, work parameters and
//! salt, so the encoded form is self-describing and Django-compatible. A new
//! password must clear the minimum length and the Have I Been Pwned
//! k-anonymity range check.
//!
//! The breach check is deliberately **fail-closed**: if the range service
//! cannot be reached, the password is refused rather than accepted unchecked.
//! The range query never sends the password or its full hash — only the first
//! five hex characters of the SHA-1 digest leave the process.

use std::sync::Arc;
use std::time::Duration;

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};
use async_trait::async_trait;
use bytes::Bytes;
use http::{Method, Request, header};
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

/// Default minimum password length, used when configuration omits one.
pub const MIN_PASSWORD_LENGTH: usize = 12;

/// How long a single Have I Been Pwned range request may take.
const BREACH_TIMEOUT: Duration = Duration::from_secs(5);

type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Failures raised while validating or hashing a password.
#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    /// The password failed the minimum-length check.
    #[error("password must be at least {min} characters")]
    TooShort { min: usize },
    /// The password appears in a known breach corpus.
    #[error("password appears in a known breach corpus")]
    Breached,
    /// The breach service could not be consulted (fail-closed).
    #[error("breach check unavailable: {0}")]
    BreachUnavailable(String),
    /// Argon2 rejected the parameters or the input.
    #[error("password hashing failed: {0}")]
    Hash(String),
}

/// A source of "has this password appeared in a breach" answers.
///
/// Abstracted so tests (and offline deployments) can supply a deterministic
/// answer without reaching the network.
#[async_trait]
pub trait BreachCheck: Send + Sync {
    /// Returns `Ok(true)` when the password is known to have been breached.
    /// An `Err` is treated as "cannot verify" and must fail closed.
    async fn is_breached(&self, password: &str) -> Result<bool, String>;
}

/// A [`BreachCheck`] backed by the Have I Been Pwned k-anonymity range API.
pub struct HibpBreachCheck {
    client: HttpClient,
    base_url: String,
}

impl HibpBreachCheck {
    /// Builds the checker over the platform TLS roots.
    pub fn new(base_url: impl Into<String>) -> Result<Self, String> {
        Ok(Self {
            client: build_client()?,
            base_url: base_url.into(),
        })
    }
}

#[async_trait]
impl BreachCheck for HibpBreachCheck {
    async fn is_breached(&self, password: &str) -> Result<bool, String> {
        let digest = sha1_hex_upper(password.as_bytes());
        let (prefix, suffix) = digest.split_at(5);
        let url = format!("{}/{}", self.base_url.trim_end_matches('/'), prefix);
        let request = Request::builder()
            .method(Method::GET)
            .uri(url)
            .header(header::USER_AGENT, "tunnel-weaver-account")
            .body(Full::new(Bytes::new()))
            .map_err(|e| e.to_string())?;
        let response = tokio::time::timeout(BREACH_TIMEOUT, self.client.request(request))
            .await
            .map_err(|_| "HIBP request timed out".to_string())?
            .map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!("HIBP returned {}", response.status()));
        }
        let bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| e.to_string())?
            .to_bytes();
        let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
        Ok(text.lines().any(|line| match line.split_once(':') {
            Some((candidate, count)) => {
                candidate.trim().eq_ignore_ascii_case(suffix)
                    && count.trim().parse::<u64>().map(|c| c > 0).unwrap_or(false)
            }
            None => false,
        }))
    }
}

/// Password hashing and validation bound to a fixed work factor.
pub struct Passwords {
    min_length: usize,
    argon2: Argon2<'static>,
    breach: Arc<dyn BreachCheck>,
}

impl Passwords {
    /// Builds a policy with the given minimum length, Argon2 work parameters
    /// (`m_cost` in KiB, `t_cost` iterations, `p_cost` lanes) and breach source.
    pub fn new(
        min_length: usize,
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        breach: Arc<dyn BreachCheck>,
    ) -> Result<Self, PasswordError> {
        let params = Params::new(m_cost, t_cost, p_cost, Some(32))
            .map_err(|e| PasswordError::Hash(e.to_string()))?;
        Ok(Self {
            min_length: min_length.max(1),
            argon2: Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
            breach,
        })
    }

    /// The configured minimum length.
    pub fn min_length(&self) -> usize {
        self.min_length
    }

    /// Hashes a password into its PHC-encoded Argon2id representation.
    ///
    /// The salt is generated fresh by the hasher for every call.
    pub fn hash(&self, password: &str) -> Result<String, PasswordError> {
        self.argon2
            .hash_password(password.as_bytes())
            .map(|hash| hash.to_string())
            .map_err(|e| PasswordError::Hash(e.to_string()))
    }

    /// Verifies a password against a stored PHC hash. Malformed hashes and
    /// mismatches both return `false`.
    pub fn verify(&self, password: &str, encoded: &str) -> bool {
        match PasswordHash::new(encoded) {
            Ok(parsed) => self
                .argon2
                .verify_password(password.as_bytes(), &parsed)
                .is_ok(),
            Err(_) => false,
        }
    }

    /// Validates a candidate new password: length first, then the fail-closed
    /// breach check.
    pub async fn validate(&self, password: &str) -> Result<(), PasswordError> {
        if password.chars().count() < self.min_length {
            return Err(PasswordError::TooShort {
                min: self.min_length,
            });
        }
        match self.breach.is_breached(password).await {
            Ok(true) => Err(PasswordError::Breached),
            Ok(false) => Ok(()),
            Err(e) => Err(PasswordError::BreachUnavailable(e)),
        }
    }
}

/// Uppercase hex SHA-1 of `bytes`, the input the k-anonymity range expects.
fn sha1_hex_upper(bytes: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    use std::fmt::Write;
    let digest = Sha1::digest(bytes);
    let mut out = String::with_capacity(40);
    for byte in digest {
        let _ = write!(out, "{byte:02X}");
    }
    out
}

/// Builds the shared HTTPS client. Platform roots are used; plain HTTP is
/// allowed so a test endpoint can point at a local server.
fn build_client() -> Result<HttpClient, String> {
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .try_with_platform_verifier()
        .map_err(|e| format!("failed to load system TLS roots: {e}"))?
        .https_or_http()
        .enable_http1()
        .build();
    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(bool);

    #[async_trait]
    impl BreachCheck for Fixed {
        async fn is_breached(&self, _password: &str) -> Result<bool, String> {
            Ok(self.0)
        }
    }

    struct Unavailable;

    #[async_trait]
    impl BreachCheck for Unavailable {
        async fn is_breached(&self, _password: &str) -> Result<bool, String> {
            Err("offline".into())
        }
    }

    /// Small work factor so the unit test is fast.
    fn policy(breach: Arc<dyn BreachCheck>) -> Passwords {
        Passwords::new(MIN_PASSWORD_LENGTH, 8, 1, 1, breach).unwrap()
    }

    #[test]
    fn hash_and_verify_roundtrip() {
        let p = policy(Arc::new(Fixed(false)));
        let encoded = p.hash("correct horse battery").unwrap();
        assert!(encoded.starts_with("$argon2id$v=19$"));
        assert!(p.verify("correct horse battery", &encoded));
        assert!(!p.verify("wrong password here", &encoded));
        assert!(!p.verify("correct horse battery", "not-a-hash"));
    }

    #[tokio::test]
    async fn short_passwords_are_refused() {
        let p = policy(Arc::new(Fixed(false)));
        let err = p.validate("short").await.unwrap_err();
        assert!(matches!(err, PasswordError::TooShort { min: 12 }));
    }

    #[tokio::test]
    async fn breached_passwords_are_refused() {
        let p = policy(Arc::new(Fixed(true)));
        let err = p.validate("sufficiently long").await.unwrap_err();
        assert!(matches!(err, PasswordError::Breached));
    }

    #[tokio::test]
    async fn breach_check_failure_fails_closed() {
        let p = policy(Arc::new(Unavailable));
        let err = p.validate("sufficiently long").await.unwrap_err();
        assert!(matches!(err, PasswordError::BreachUnavailable(_)));
    }

    #[test]
    fn sha1_matches_the_known_hibp_vector() {
        // The canonical k-anonymity example: "password" → 5BAA6...; prefix 5BAA6.
        assert_eq!(
            sha1_hex_upper(b"password"),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        );
    }
}
