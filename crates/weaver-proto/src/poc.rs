//! Hard-coded identity constants and hostname derivation for Milestone 1 PoC.

use weaver_mux::KeyId;

/// Fixed 32-byte Ed25519 secret seed for the PoC client.
pub const POC_SECRET_KEY: [u8; 32] = *b"weaver-poc-laptop-secret-key-32b";

/// Deterministically derived public key bytes corresponding to `POC_SECRET_KEY`.
pub const POC_PUBLIC_KEY: [u8; 32] = [
    0x9b, 0x01, 0x7a, 0xbe, 0x25, 0x0e, 0x5b, 0x63, 0xf6, 0x81, 0x7a, 0x84, 0xec, 0x9c, 0x7b, 0x75,
    0x98, 0xb1, 0x1f, 0xc8, 0x00, 0x56, 0xec, 0xe2, 0x9e, 0x06, 0xb8, 0xaa, 0x4b, 0x51, 0x79, 0x06,
];

/// Fixed KeyId identifying the PoC client.
pub const POC_KEY_ID: KeyId = KeyId::Ed25519(POC_PUBLIC_KEY);

/// Maps a KeyId to its hard-coded person and machine identifiers if recognized.
pub fn poc_identity(key_id: &KeyId) -> Option<(&'static str, &'static str)> {
    if key_id == &POC_KEY_ID {
        Some(("poc", "laptop"))
    } else {
        None
    }
}

/// Derives the fully-qualified tunnel hostname: `<service>.<machine>.<person>.<root>`.
pub fn derive_hostname(service: &str, machine: &str, person: &str, root: &str) -> String {
    format!("{}.{machine}.{person}.{root}", service.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_poc_public_key() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&POC_SECRET_KEY);
        let derived_pub = signing_key.verifying_key().to_bytes();
        assert_eq!(derived_pub, POC_PUBLIC_KEY);
    }

    #[test]
    fn test_derive_hostname() {
        let h = derive_hostname("web", "laptop", "poc", "example.com");
        assert_eq!(h, "web.laptop.poc.example.com");
    }
}
