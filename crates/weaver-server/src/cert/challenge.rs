use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use rcgen::{CertificateParams, CustomExtension, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};

/// In-memory registry for active ACME HTTP-01 and TLS-ALPN-01 challenges.
#[derive(Default)]
pub struct ChallengeRegistry {
    http_01: RwLock<HashMap<String, String>>,
    tls_alpn_01: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}

impl ChallengeRegistry {
    /// Creates a new empty challenge registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an active HTTP-01 challenge token and its corresponding key authorization.
    pub fn register_http_01(&self, token: String, key_authorization: String) {
        self.http_01
            .write()
            .unwrap()
            .insert(token, key_authorization);
    }

    /// Looks up key authorization for an HTTP-01 challenge token.
    pub fn get_http_01(&self, token: &str) -> Option<String> {
        self.http_01.read().unwrap().get(token).cloned()
    }

    /// Unregisters an HTTP-01 challenge token after completion or cleanup.
    pub fn remove_http_01(&self, token: &str) {
        self.http_01.write().unwrap().remove(token);
    }

    /// Registers an active TLS-ALPN-01 certified key for a hostname.
    pub fn register_tls_alpn_01(&self, host: String, cert: Arc<CertifiedKey>) {
        self.tls_alpn_01
            .write()
            .unwrap()
            .insert(host.to_ascii_lowercase(), cert);
    }

    /// Looks up a TLS-ALPN-01 certified key for a hostname.
    pub fn get_tls_alpn_01(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        self.tls_alpn_01
            .read()
            .unwrap()
            .get(&host.to_ascii_lowercase())
            .cloned()
    }

    /// Unregisters a TLS-ALPN-01 challenge after completion or cleanup.
    pub fn remove_tls_alpn_01(&self, host: &str) {
        self.tls_alpn_01
            .write()
            .unwrap()
            .remove(&host.to_ascii_lowercase());
    }
}

/// Generates an ephemeral self-signed `CertifiedKey` for a TLS-ALPN-01 challenge.
///
/// Complies with RFC 8737 section 3:
/// - SAN includes the exact domain name being validated
/// - Contains critical extension `id-pe-acmeIdentifier` (1.3.6.1.5.5.7.1.31)
/// - Extension value is an ASN.1 DER OCTET STRING (32 bytes) of the SHA-256 digest of key authorization.
pub fn create_tls_alpn_01_certified_key(
    host: &str,
    key_authorization: &str,
) -> Result<Arc<CertifiedKey>, Box<dyn std::error::Error + Send + Sync>> {
    let mut params = CertificateParams::new(vec![host.to_string()])?;

    // Compute SHA-256 of key authorization
    let digest = Sha256::digest(key_authorization.as_bytes());

    // DER OCTET STRING of 32 bytes: Tag 0x04, Length 0x20, followed by digest
    let mut ext_der = Vec::with_capacity(34);
    ext_der.push(0x04);
    ext_der.push(0x20);
    ext_der.extend_from_slice(&digest);

    // OID id-pe-acmeIdentifier = 1.3.6.1.5.5.7.1.31
    let acme_oid = &[1, 3, 6, 1, 5, 5, 7, 1, 31];
    let mut ext = CustomExtension::from_oid_content(acme_oid, ext_der);
    ext.set_criticality(true);
    params.custom_extensions.push(ext);

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let cert = params.self_signed(&key_pair)?;

    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();

    let cert_chain = vec![CertificateDer::from(cert_der)];
    let signing_key =
        rustls::crypto::ring::sign::any_ecdsa_type(&PrivateKeyDer::try_from(key_der)?)?;

    Ok(Arc::new(CertifiedKey::new(cert_chain, signing_key)))
}
