//! Secrets sealed at rest: AES-256-GCM under a configured key.
//!
//! The sealed form is `nonce ‖ ciphertext`, hex-encoded — one opaque string the
//! store can hold without knowing what it is. Every caller binds the value to
//! the record it belongs to through the associated data (an account id, a
//! provider name), so a sealed value copied into another record's slot fails to
//! open instead of quietly becoming that record's credential.

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

/// Why a value could not be sealed or opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// The configured key is empty or is not a 32-byte hex key.
    Key,
    /// The stored value is malformed, or it was sealed under a different key or
    /// for a different record.
    Tampered,
}

impl SealError {
    /// The line to log. These are operator problems, never something to show a
    /// person.
    pub const fn message(self) -> &'static str {
        match self {
            SealError::Key => {
                "the sealing key is not a 32-byte hex key; sealed secrets cannot be read"
            }
            SealError::Tampered => {
                "a sealed secret could not be opened (wrong key, or the stored value changed)"
            }
        }
    }
}

/// A sealing key, as the config file holds it.
///
/// A newtype rather than a bare `String` because the config derives `Debug` and
/// is printed at startup: a plain string field would put the key in the logs.
/// The value is 32 bytes of hex so the config file stays editable text, and an
/// empty value means "not generated yet" — the daemon fills it at boot rather
/// than refusing to serve.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SealKey(String);

impl SealKey {
    /// Whether no key has been generated yet.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// A fresh random key, hex-encoded.
    pub fn generate() -> Self {
        Self(crate::random_hex(32))
    }

    /// Whether the key is usable: 64 hex characters.
    pub fn is_valid(&self) -> bool {
        self.bytes().is_some()
    }

    /// The key as the config file spells it. For writing the file back only:
    /// never log it, and never put it in a response.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Seals `plain`, bound to `aad`.
    pub fn seal(&self, aad: &[u8], plain: &[u8]) -> Result<String, SealError> {
        let key = self.aead()?;
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| SealError::Key)?;
        let mut in_out = plain.to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| SealError::Key)?;
        let mut sealed = nonce.to_vec();
        sealed.extend_from_slice(&in_out);
        Ok(hex::encode(sealed))
    }

    /// Opens a value sealed for `aad`.
    pub fn open(&self, aad: &[u8], sealed: &str) -> Result<Vec<u8>, SealError> {
        let key = self.aead()?;
        let raw = hex::decode(sealed).map_err(|_| SealError::Tampered)?;
        let (nonce, ciphertext) = raw.split_at_checked(NONCE_LEN).ok_or(SealError::Tampered)?;
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| SealError::Tampered)?;
        let mut in_out = ciphertext.to_vec();
        let plain = key
            .open_in_place(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| SealError::Tampered)?;
        Ok(plain.to_vec())
    }

    /// Opens a value sealed for `aad` that is known to be text.
    pub fn open_text(&self, aad: &[u8], sealed: &str) -> Result<String, SealError> {
        String::from_utf8(self.open(aad, sealed)?).map_err(|_| SealError::Tampered)
    }

    fn bytes(&self) -> Option<[u8; 32]> {
        hex::decode(&self.0).ok()?.try_into().ok()
    }

    fn aead(&self) -> Result<LessSafeKey, SealError> {
        let bytes = self.bytes().ok_or(SealError::Key)?;
        let key = UnboundKey::new(&AES_256_GCM, &bytes).map_err(|_| SealError::Key)?;
        Ok(LessSafeKey::new(key))
    }
}

/// Redacts the key, so a derived `Debug` cannot print it.
impl std::fmt::Debug for SealKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.is_empty() {
            "SealKey(<empty>)"
        } else {
            "SealKey(<redacted>)"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_value_opens_for_its_own_binding_only() {
        let key = SealKey::generate();
        let sealed = key.seal(b"a", b"secret").expect("sealing works");
        assert_eq!(key.open(b"a", &sealed).expect("it opens"), b"secret");
        assert_eq!(key.open(b"b", &sealed), Err(SealError::Tampered));
        assert_eq!(
            SealKey::generate().open(b"a", &sealed),
            Err(SealError::Tampered)
        );
        assert_eq!(key.open(b"a", "not hex"), Err(SealError::Tampered));
        assert_eq!(key.open(b"a", "abcd"), Err(SealError::Tampered));
    }
}
