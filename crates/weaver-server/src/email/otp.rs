//! Numeric one-time codes that prove an email provider during setup/configure.
//!
//! Interactive setup keeps the challenge in memory (it verifies immediately).
//! The headless `configure` flow is two-step across processes, so it persists a
//! hashed code with its TTL and attempt count — and the pending
//! [`EmailConfig`] it is proving — under the config singleton.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::{ConfigError, EmailConfig};
use crate::store::{Store, StoreError};

/// Number of digits in a code.
pub const OTP_DIGITS: usize = 6;
/// How long a code stays valid, in seconds (a few minutes).
pub const OTP_TTL_SECS: i64 = 300;
/// How many wrong entries are tolerated before a new code is required.
pub const OTP_MAX_ATTEMPTS: u32 = 5;

/// The config-singleton key holding the pending headless challenge.
const OTP_CONFIG_KEY: &str = "email_otp";

/// Verification failures, all of which block setup.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum OtpError {
    /// The submitted digits did not match.
    #[error("the code is incorrect")]
    Wrong,
    /// The code outlived its TTL.
    #[error("the code has expired; request a new one")]
    Expired,
    /// The attempt cap was reached; a fresh code is required.
    #[error("too many attempts; request a new code")]
    TooManyAttempts,
}

/// Generates a zero-padded numeric code from the process CSPRNG.
fn generate_code() -> String {
    let mut rng = rand::rng();
    (0..OTP_DIGITS)
        .map(|_| {
            let digit: u8 = rng.random_range(0..10);
            char::from(b'0' + digit)
        })
        .collect()
}

/// Hashes a code so the persisted challenge never stores it in the clear.
fn hash_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

/// Current Unix time in seconds.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Subject line shared by all OTP messages (English; setup has no locale).
pub const OTP_SUBJECT: &str = "Your Tunnel Weaver email verification code";

/// The plain-text OTP body, including the code, expiry, and support host.
pub fn otp_body(code: &str, support_url: &str) -> String {
    format!(
        "Your Tunnel Weaver verification code\r\n\
         \r\n\
         {code}\r\n\
         \r\n\
         Enter this code to prove your email provider. It expires in {minutes} minutes.\r\n\
         If you did not request this, you can ignore this message.\r\n\
         \r\n\
         {support_url}\r\n",
        minutes = OTP_TTL_SECS / 60,
    )
}

/// An in-memory challenge, used by interactive setup.
#[derive(Debug)]
pub struct OtpChallenge {
    code: String,
    issued_at: Instant,
    ttl: Duration,
    attempts: u32,
    max_attempts: u32,
}

impl OtpChallenge {
    /// A fresh challenge with the default policy.
    pub fn generate() -> Self {
        OtpChallenge {
            code: generate_code(),
            issued_at: Instant::now(),
            ttl: Duration::from_secs(OTP_TTL_SECS as u64),
            attempts: 0,
            max_attempts: OTP_MAX_ATTEMPTS,
        }
    }

    /// The generated code, for the outbound message.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Verifies against the wall clock.
    pub fn verify(&mut self, candidate: &str) -> Result<(), OtpError> {
        self.verify_at(candidate, Instant::now())
    }

    /// Verifies at a supplied instant so expiry is testable.
    pub fn verify_at(&mut self, candidate: &str, now: Instant) -> Result<(), OtpError> {
        if now.duration_since(self.issued_at) > self.ttl {
            return Err(OtpError::Expired);
        }
        if self.attempts >= self.max_attempts {
            return Err(OtpError::TooManyAttempts);
        }
        if candidate.trim() == self.code {
            return Ok(());
        }
        self.attempts += 1;
        if self.attempts >= self.max_attempts {
            Err(OtpError::TooManyAttempts)
        } else {
            Err(OtpError::Wrong)
        }
    }
}

/// A persisted headless challenge plus the configuration it proves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingOtp {
    /// Hash of the issued code.
    pub code_hash: String,
    /// Unix seconds at which the code expires.
    pub expires_at: i64,
    /// Wrong entries so far.
    pub attempts: u32,
    /// Attempt cap.
    pub max_attempts: u32,
    /// The email configuration written once the code is accepted.
    pub pending: EmailConfig,
}

impl PendingOtp {
    /// Issues a code, persists the challenge, and returns the plaintext code.
    pub async fn issue(store: &Store, pending: EmailConfig) -> Result<String, StoreError> {
        let code = generate_code();
        let record = PendingOtp {
            code_hash: hash_code(&code),
            expires_at: now_unix() + OTP_TTL_SECS,
            attempts: 0,
            max_attempts: OTP_MAX_ATTEMPTS,
            pending,
        };
        record.save(store).await?;
        Ok(code)
    }

    /// Loads the pending challenge, if any.
    pub async fn load(store: &Store) -> Result<Option<Self>, StoreError> {
        let Some(json) = store.load_config_json().await? else {
            return Ok(None);
        };
        let value: serde_json::Value = serde_json::from_str(&json)
            .map_err(|e| StoreError::Config(ConfigError::DeserializationFailed(e.to_string())))?;
        let Some(raw) = value.get(OTP_CONFIG_KEY) else {
            return Ok(None);
        };
        if raw.is_null() {
            return Ok(None);
        }
        let record = serde_json::from_value(raw.clone())
            .map_err(|e| StoreError::Config(ConfigError::DeserializationFailed(e.to_string())))?;
        Ok(Some(record))
    }

    /// Persists the challenge under the config singleton.
    pub async fn save(&self, store: &Store) -> Result<(), StoreError> {
        let json = serde_json::to_string(self)
            .map_err(|e| StoreError::Config(ConfigError::DeserializationFailed(e.to_string())))?;
        store.set_config(OTP_CONFIG_KEY, &json).await
    }

    /// Removes any pending challenge.
    pub async fn clear(store: &Store) -> Result<(), StoreError> {
        store.set_config(OTP_CONFIG_KEY, "null").await
    }

    /// Verifies against the wall clock and counts a miss.
    pub fn verify(&mut self, candidate: &str) -> Result<(), OtpError> {
        self.verify_at(candidate, now_unix())
    }

    /// Verifies at a supplied Unix time so expiry is testable.
    pub fn verify_at(&mut self, candidate: &str, now: i64) -> Result<(), OtpError> {
        if now > self.expires_at {
            return Err(OtpError::Expired);
        }
        if self.attempts >= self.max_attempts {
            return Err(OtpError::TooManyAttempts);
        }
        if hash_code(candidate.trim()) == self.code_hash {
            return Ok(());
        }
        self.attempts += 1;
        if self.attempts >= self.max_attempts {
            Err(OtpError::TooManyAttempts)
        } else {
            Err(OtpError::Wrong)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flush() -> PendingOtp {
        PendingOtp {
            code_hash: hash_code("123456"),
            expires_at: now_unix() + OTP_TTL_SECS,
            attempts: 0,
            max_attempts: OTP_MAX_ATTEMPTS,
            pending: EmailConfig::default(),
        }
    }

    #[test]
    fn generated_codes_are_six_digits() {
        for _ in 0..50 {
            let code = generate_code();
            assert_eq!(code.len(), OTP_DIGITS);
            assert!(code.chars().all(|c| c.is_ascii_digit()), "{code}");
        }
    }

    #[test]
    fn in_memory_accepts_correct_rejects_wrong() {
        let mut challenge = OtpChallenge::generate();
        let now = Instant::now();
        assert_eq!(challenge.verify_at("not-a-code", now), Err(OtpError::Wrong));
        // Correct code succeeds.
        let code = challenge.code().to_string();
        assert_eq!(challenge.verify_at(&code, now), Ok(()));
    }

    #[test]
    fn in_memory_expires() {
        let mut challenge = OtpChallenge::generate();
        let later = Instant::now() + Duration::from_secs(OTP_TTL_SECS as u64 + 1);
        assert_eq!(challenge.verify_at("123456", later), Err(OtpError::Expired));
    }

    #[test]
    fn in_memory_attempt_cap() {
        let mut challenge = OtpChallenge::generate();
        let now = Instant::now();
        for i in 0..OTP_MAX_ATTEMPTS {
            let err = challenge.verify_at("wrong-code", now).unwrap_err();
            if i + 1 == OTP_MAX_ATTEMPTS {
                assert_eq!(err, OtpError::TooManyAttempts);
            } else {
                assert_eq!(err, OtpError::Wrong);
            }
        }
        // Even the right code is refused once the cap is hit.
        let code = challenge.code().to_string();
        assert_eq!(
            challenge.verify_at(&code, now),
            Err(OtpError::TooManyAttempts)
        );
    }

    #[test]
    fn pending_verifies_hash_and_expiry() {
        let mut pending = flush();
        assert_eq!(pending.verify_at("123456", now_unix()), Ok(()));
        assert_eq!(
            pending.verify_at("999999", now_unix()),
            Err(OtpError::Wrong)
        );
        assert_eq!(
            pending.verify_at("123456", now_unix() + OTP_TTL_SECS + 1),
            Err(OtpError::Expired)
        );
    }

    #[test]
    fn otp_body_carries_code_and_expiry() {
        let body = otp_body("424242", "https://relay.example.org");
        assert!(body.contains("424242"));
        assert!(body.contains("5 minutes"));
        assert!(body.contains("https://relay.example.org"));
    }
}
