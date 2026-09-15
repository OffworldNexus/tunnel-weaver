//! In-memory self-signed TLS certificate generation and dynamic rustls configuration.
//!
//! Generates temporary self-signed X.509 certificates for the configured root domain
//! and SAN wildcards to bootstrap HTTPS serving prior to ACME issuance, and builds
//! `rustls::ServerConfig` with dynamic certificate resolution and ALPN support.

use std::sync::Arc;

use rcgen::generate_simple_self_signed;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use thiserror::Error;

/// Errors that can occur during TLS configuration and certificate generation.
#[derive(Debug, Error)]
pub enum TlsError {
    /// Failed to generate self-signed certificate using rcgen.
    #[error("Certificate generation failed: {0}")]
    Rcgen(#[from] rcgen::Error),

    /// Rustls configuration error.
    #[error("Rustls error: {0}")]
    Rustls(#[from] rustls::Error),
}

/// Generates an in-memory self-signed fallback certificate for the root domain and `*.root_domain`.
pub fn generate_placeholder_certified_key(
    root_domain: &str,
) -> Result<Arc<CertifiedKey>, TlsError> {
    let sans = vec![root_domain.to_string(), format!("*.{root_domain}")];
    let certified_key = generate_simple_self_signed(sans)?;

    let cert_der = certified_key.cert.der().to_vec();
    let key_der = certified_key.signing_key.serialize_der();

    let cert_chain = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::try_from(key_der)
        .map_err(|e| rustls::Error::General(format!("Invalid private key: {e}")))?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)?;
    Ok(Arc::new(CertifiedKey::new(cert_chain, signing_key)))
}

/// Builds a `rustls::ServerConfig` using the provided dynamic certificate resolver
/// and configured with ALPN `acme-tls/1`, `h2`, and `http/1.1`.
pub fn create_server_config(
    resolver: Arc<dyn ResolvesServerCert>,
) -> Result<Arc<ServerConfig>, TlsError> {
    let provider = rustls::crypto::ring::default_provider();
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    config.alpn_protocols = vec![b"acme-tls/1".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

/// Generates an in-memory self-signed certificate and builds a static `rustls::ServerConfig`
/// configured with ALPN `h2` and `http/1.1` (for test compatibility).
pub fn create_self_signed_server_config(root_domain: &str) -> Result<Arc<ServerConfig>, TlsError> {
    let sans = vec![root_domain.to_string(), format!("*.{root_domain}")];
    let certified_key = generate_simple_self_signed(sans)?;

    let cert_der = certified_key.cert.der().to_vec();
    let key_der = certified_key.signing_key.serialize_der();

    let cert_chain = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::try_from(key_der)
        .map_err(|e| rustls::Error::General(format!("Invalid private key: {e}")))?;

    let provider = rustls::crypto::ring::default_provider();
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

    config.alpn_protocols = vec![b"acme-tls/1".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_self_signed_server_config() {
        let config = create_self_signed_server_config("example.com")
            .expect("Failed to create TLS server config");
        assert_eq!(
            config.alpn_protocols,
            vec![b"acme-tls/1".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }
}
