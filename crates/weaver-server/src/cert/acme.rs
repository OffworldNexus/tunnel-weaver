//! ACME protocol engine for automated certificate issuance and renewal.
//!
//! Orchestrates RFC 8555 certificate orders using `instant-acme`, supporting:
//! - ECDSA P-256 account and certificate keys
//! - External Account Binding (EAB) for commercial CAs
//! - Custom Root CA PEM for private/staging environments (Pebble)
//! - Challenge solving via HTTP-01 and TLS-ALPN-01
//! - Provider fallback on rate limiting (429) or upstream 5xx errors

use std::sync::Arc;

use base64::Engine;
use instant_acme::{
    Account, AccountBuilder, AccountCredentials, ChallengeType, ExternalAccountKey, Identifier,
    NewAccount, NewOrder, RetryPolicy,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use tracing::{debug, info, warn};

use crate::cert::challenge::{ChallengeRegistry, create_tls_alpn_01_certified_key};
use crate::cert::clock::{Clock, format_unix_timestamp};
use crate::cert::events::record_cert_event;
use crate::cert::providers::{find_provider, resolve_directory_url};
use crate::config::Config;
use crate::store::Store;

/// Errors returned by the ACME issuance workflow.
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    /// Upstream CA rejected request due to rate limits.
    #[error("ACME rate limited: {detail} (retry after {retry_after_secs:?}s)")]
    RateLimited {
        detail: String,
        retry_after_secs: Option<u64>,
    },

    /// Upstream CA server error (HTTP 5xx).
    #[error("ACME server error ({status:?}): {detail}")]
    ServerError { status: Option<u16>, detail: String },

    /// All primary and fallback directories failed.
    #[error("All ACME providers failed. Last error: {0}")]
    AllProvidersFailed(String),

    /// Other failure during ordering, cryptographic operations, or validation.
    #[error("ACME failure: {0}")]
    Other(String),
}

impl AcmeError {
    /// Returns true if this error indicates rate limiting.
    pub fn is_rate_limited(&self) -> bool {
        matches!(self, AcmeError::RateLimited { .. })
    }

    /// Returns true if this error indicates an upstream server failure.
    pub fn is_server_error(&self) -> bool {
        matches!(self, AcmeError::ServerError { .. })
    }
}

/// An issued certificate chain and its matching private key.
#[derive(Debug, Clone)]
pub struct IssuedCertificate {
    pub name: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub not_before: i64,
    pub not_after: i64,
    pub directory: String,
}

/// ACME protocol client engine.
pub struct AcmeEngine {
    config: Arc<Config>,
    store: Arc<Store>,
    clock: Arc<dyn Clock>,
    challenge_registry: Arc<ChallengeRegistry>,
}

impl AcmeEngine {
    /// Creates a new ACME engine instance.
    pub fn new(
        config: Arc<Config>,
        store: Arc<Store>,
        clock: Arc<dyn Clock>,
        challenge_registry: Arc<ChallengeRegistry>,
    ) -> Self {
        Self {
            config,
            store,
            clock,
            challenge_registry,
        }
    }

    /// Issues or renews a certificate for `hostname`, trying primary and fallback providers.
    pub async fn issue_certificate(
        &self,
        hostname: &str,
        http_enabled: bool,
    ) -> Result<IssuedCertificate, AcmeError> {
        let directories = self.resolve_directory_list();
        if directories.is_empty() {
            return Err(AcmeError::Other("No ACME directories available".into()));
        }

        let mut last_err = String::from("No providers attempted");

        for (idx, (provider_id, dir_url)) in directories.iter().enumerate() {
            debug!(
                hostname,
                provider_id,
                dir_url,
                attempt = idx + 1,
                total = directories.len(),
                "Attempting ACME issuance"
            );

            match self
                .issue_against_directory(hostname, provider_id, dir_url, http_enabled)
                .await
            {
                Ok(cert) => {
                    info!(
                        hostname,
                        provider = provider_id,
                        dir_url,
                        valid_from = %format_unix_timestamp(cert.not_before),
                        valid_until = %format_unix_timestamp(cert.not_after),
                        "ACME certificate issued successfully"
                    );
                    return Ok(cert);
                }
                Err(err) => {
                    warn!(
                        hostname,
                        provider_id,
                        dir_url,
                        error = %err,
                        "ACME issuance failed against provider"
                    );
                    last_err = err.to_string();

                    // Fallback on rate limits or 5xx server errors
                    if (err.is_rate_limited() || err.is_server_error())
                        && idx + 1 < directories.len()
                    {
                        info!(
                            next_provider = directories[idx + 1].0,
                            "Failing over to fallback ACME provider"
                        );
                        continue;
                    }

                    // Otherwise stop and return error
                    return Err(err);
                }
            }
        }

        Err(AcmeError::AllProvidersFailed(last_err))
    }

    /// Resolves the list of ACME directories to try: primary provider first, then fallbacks.
    fn resolve_directory_list(&self) -> Vec<(String, String)> {
        let mut list = Vec::new();

        if let Some(primary_url) = resolve_directory_url(
            &self.config.acme_provider,
            self.config.acme_directory.as_deref(),
        ) {
            list.push((self.config.acme_provider.clone(), primary_url));
        }

        for fallback in &self.config.acme_fallback_providers {
            if let Some(url) = resolve_directory_url(fallback, None)
                && !list.iter().any(|(_, u)| u == &url)
            {
                list.push((fallback.clone(), url));
            }
        }

        list
    }

    /// Executes the full ACME order lifecycle against a single directory endpoint.
    async fn issue_against_directory(
        &self,
        hostname: &str,
        provider_id: &str,
        directory_url: &str,
        http_enabled: bool,
    ) -> Result<IssuedCertificate, AcmeError> {
        let account = self
            .get_or_create_account(provider_id, directory_url)
            .await?;

        // 1. Generate certificate keypair (ECDSA P-256)
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| AcmeError::Other(format!("Failed to generate P-256 keypair: {e}")))?;
        let key_pem = key_pair.serialize_pem();

        // 2. Generate CSR for hostname
        let mut params = CertificateParams::new(vec![hostname.to_string()])
            .map_err(|e| AcmeError::Other(format!("Failed to create CertificateParams: {e}")))?;
        params.distinguished_name = DistinguishedName::new();
        let csr = params
            .serialize_request(&key_pair)
            .map_err(|e| AcmeError::Other(format!("Failed to generate CSR: {e}")))?;

        // 3. Create new order
        let identifier = Identifier::Dns(hostname.to_string());
        let identifiers = [identifier];
        let new_order = NewOrder::new(&identifiers);
        let mut order = account
            .new_order(&new_order)
            .await
            .map_err(Self::map_instant_acme_error)?;

        // 4. Solve authorizations
        let mut registered_http_tokens = Vec::new();
        let mut registered_tls_hosts = Vec::new();

        let mut authzs = order.authorizations();
        while let Some(authz_res) = authzs.next().await {
            let mut authz = authz_res.map_err(Self::map_instant_acme_error)?;

            let has_http = authz
                .challenges
                .iter()
                .any(|c| c.r#type == ChallengeType::Http01);
            let has_alpn = authz
                .challenges
                .iter()
                .any(|c| c.r#type == ChallengeType::TlsAlpn01);

            let target_type = if http_enabled && has_http {
                Some(ChallengeType::Http01)
            } else if has_alpn {
                Some(ChallengeType::TlsAlpn01)
            } else if has_http {
                Some(ChallengeType::Http01)
            } else {
                None
            };

            let Some(target) = target_type else {
                return Err(AcmeError::Other(format!(
                    "No supported challenge type found in authorization for {hostname}"
                )));
            };

            let mut chal = authz.challenge(target).unwrap();

            let key_auth = chal.key_authorization();
            let key_auth_str = key_auth.as_str().to_string();

            if chal.r#type == ChallengeType::Http01 {
                let token = chal.token.clone();
                self.challenge_registry
                    .register_http_01(token.clone(), key_auth_str);
                registered_http_tokens.push(token);
            } else if chal.r#type == ChallengeType::TlsAlpn01 {
                let certified_key = create_tls_alpn_01_certified_key(hostname, &key_auth_str)
                    .map_err(|e| {
                        AcmeError::Other(format!("Failed to create TLS-ALPN-01 cert: {e}"))
                    })?;
                self.challenge_registry
                    .register_tls_alpn_01(hostname.to_string(), certified_key);
                registered_tls_hosts.push(hostname.to_string());
            }

            // Signal readiness to ACME server
            chal.set_ready()
                .await
                .map_err(Self::map_instant_acme_error)?;
        }

        // 5. Poll order readiness
        let ready_res = order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(Self::map_instant_acme_error);

        // Clean up registered challenge responders
        for token in registered_http_tokens {
            self.challenge_registry.remove_http_01(&token);
        }
        for host in registered_tls_hosts {
            self.challenge_registry.remove_tls_alpn_01(&host);
        }

        ready_res?;

        // 6. Finalize CSR and retrieve certificate
        order
            .finalize_csr(csr.der())
            .await
            .map_err(Self::map_instant_acme_error)?;

        let cert_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(Self::map_instant_acme_error)?;

        // 7. Parse validity from first certificate in PEM chain
        let first_der = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .next()
            .ok_or_else(|| AcmeError::Other("Empty certificate chain returned".into()))?
            .map_err(|e| AcmeError::Other(format!("Invalid certificate DER: {e}")))?;

        let (not_before, not_after) = parse_cert_validity(&first_der)
            .map_err(|e| AcmeError::Other(format!("Failed to parse validity: {e}")))?;

        let now = self.clock.now_unix();

        // 8. Persist into SQLite certificates table
        self.store
            .write(|conn| {
                conn.execute(
                    "INSERT INTO certificates (name, cert_pem, key_pem, not_before, not_after, issuer, directory, obtained_at, last_active_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                     ON CONFLICT(name) DO UPDATE SET
                        cert_pem = excluded.cert_pem,
                        key_pem = excluded.key_pem,
                        not_before = excluded.not_before,
                        not_after = excluded.not_after,
                        issuer = excluded.issuer,
                        directory = excluded.directory,
                        obtained_at = excluded.obtained_at,
                        last_active_at = excluded.last_active_at",
                    rusqlite::params![
                        hostname,
                        cert_pem,
                        key_pem,
                        not_before,
                        not_after,
                        Option::<String>::None,
                        directory_url,
                        now,
                        now,
                    ],
                )?;
                Ok(())
            })
            .map_err(|e| AcmeError::Other(format!("Failed to save certificate: {e}")))?;

        // Record event
        let _ = record_cert_event(
            &self.store,
            hostname,
            now,
            "issued",
            Some(&format!("directory: {directory_url}")),
        );

        Ok(IssuedCertificate {
            name: hostname.to_string(),
            cert_pem,
            key_pem,
            not_before,
            not_after,
            directory: directory_url.to_string(),
        })
    }

    /// Fetches existing ACME account credentials from SQLite or creates a new account.
    async fn get_or_create_account(
        &self,
        provider_id: &str,
        directory_url: &str,
    ) -> Result<Account, AcmeError> {
        let dir_key = directory_url.to_string();

        // 1. Check if account already exists in DB
        let cached = self
            .store
            .read(|conn| {
                let mut stmt =
                    conn.prepare("SELECT key_pem, kid FROM acme_account WHERE directory = ?1")?;
                let res = stmt
                    .query_row(rusqlite::params![dir_key], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
                    })
                    .rusqlite_optional()?;
                Ok(res)
            })
            .map_err(|e| AcmeError::Other(format!("Database read failed: {e}")))?;

        let builder = self.create_account_builder()?;

        if let Some((creds_json, _)) = cached
            && let Ok(creds) = serde_json::from_str::<AccountCredentials>(&creds_json)
        {
            match builder.from_credentials(creds).await {
                Ok(account) => return Ok(account),
                Err(e) => {
                    warn!(directory = directory_url, error = %e, "Failed to restore ACME account from credentials, recreating");
                }
            }
        }

        // 2. Create new account with ECDSA P-256 key
        let builder = self.create_account_builder()?;
        let contact = format!("mailto:{}", self.config.admin_email);
        let new_account = NewAccount {
            contact: &[&contact],
            terms_of_service_agreed: true,
            only_return_existing: false,
        };

        // Prepare External Account Binding (EAB) if configured or required
        let eab = self.prepare_eab(provider_id)?;

        let (account, credentials) = builder
            .create(&new_account, directory_url.to_string(), eab.as_ref())
            .await
            .map_err(Self::map_instant_acme_error)?;

        let creds_json = serde_json::to_string(&credentials)
            .map_err(|e| AcmeError::Other(format!("Failed to serialize credentials: {e}")))?;
        let kid = account.id().to_string();
        let now = self.clock.now_unix();

        // Persist into SQLite acme_account
        self.store
            .write(|conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO acme_account (directory, email, key_pem, kid, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        directory_url,
                        self.config.admin_email,
                        creds_json,
                        kid,
                        now,
                    ],
                )?;
                Ok(())
            })
            .map_err(|e| AcmeError::Other(format!("Failed to save account: {e}")))?;

        Ok(account)
    }

    /// Creates an `AccountBuilder` configured with custom Root CA PEM if present.
    fn create_account_builder(&self) -> Result<AccountBuilder, AcmeError> {
        if let Some(ca_pem) = &self.config.acme_root_ca_pem {
            let mut temp = tempfile::NamedTempFile::new()
                .map_err(|e| AcmeError::Other(format!("Failed to create tempfile: {e}")))?;
            use std::io::Write;
            temp.write_all(ca_pem.as_bytes())
                .map_err(|e| AcmeError::Other(format!("Failed to write Root CA PEM: {e}")))?;

            Account::builder_with_root(temp.path())
                .map_err(|e| AcmeError::Other(format!("Failed to configure Root CA: {e}")))
        } else {
            Account::builder()
                .map_err(|e| AcmeError::Other(format!("Failed to create AccountBuilder: {e}")))
        }
    }

    /// Prepares External Account Binding if keys are provided or required.
    fn prepare_eab(&self, provider_id: &str) -> Result<Option<ExternalAccountKey>, AcmeError> {
        let kid = self.config.acme_eab_kid.as_deref();
        let hmac = self.config.acme_eab_hmac.as_deref();

        let (Some(kid_str), Some(hmac_str)) = (kid, hmac) else {
            let provider_info = find_provider(provider_id);
            if provider_info.is_some_and(|p| p.eab_required) {
                return Err(AcmeError::Other(format!(
                    "Provider '{provider_id}' mandates EAB, but acme_eab_kid/acme_eab_hmac are unset"
                )));
            }
            return Ok(None);
        };

        // Decode base64 / base64url HMAC key
        let hmac_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(hmac_str)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(hmac_str))
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(hmac_str))
            .map_err(|e| AcmeError::Other(format!("Invalid base64 in acme_eab_hmac: {e}")))?;

        Ok(Some(ExternalAccountKey::new(
            kid_str.to_string(),
            &hmac_bytes,
        )))
    }

    /// Converts an `instant_acme::Error` into an `AcmeError`, classifying rate limits and server errors.
    fn map_instant_acme_error(err: instant_acme::Error) -> AcmeError {
        match err {
            instant_acme::Error::Api(problem) => {
                let status = problem.status;
                let detail = problem.detail.unwrap_or_else(|| "ACME error".into());
                let is_rate_limited = status == Some(429)
                    || problem
                        .r#type
                        .as_deref()
                        .is_some_and(|t| t.contains("rateLimited") || t.contains("rate-limit"));

                if is_rate_limited {
                    AcmeError::RateLimited {
                        detail,
                        retry_after_secs: None,
                    }
                } else if status.is_some_and(|s| s >= 500) {
                    AcmeError::ServerError { status, detail }
                } else {
                    AcmeError::Other(format!("API error ({status:?}): {detail}"))
                }
            }
            other => AcmeError::Other(other.to_string()),
        }
    }
}

/// Helper to parse optional SQLite results without extra imports.
trait RusqliteOptional<T> {
    fn rusqlite_optional(self) -> Result<Option<T>, rusqlite::Error>;
}

impl<T> RusqliteOptional<T> for Result<T, rusqlite::Error> {
    fn rusqlite_optional(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(val) => Ok(Some(val)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

/// Minimal DER ASN.1 parser to extract `not_before` and `not_after` Unix timestamps from an X.509 certificate.
fn parse_time(bytes: &[u8], tag: u8) -> Result<i64, String> {
    let s = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
    let (year, rest) = if tag == 0x17 {
        if s.len() < 13 {
            return Err("UTCTime too short".into());
        }
        let yy: i64 = s[0..2]
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;
        let full_year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        (full_year, &s[2..])
    } else if tag == 0x18 {
        if s.len() < 15 {
            return Err("GeneralizedTime too short".into());
        }
        let yyyy: i64 = s[0..4]
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;
        (yyyy, &s[4..])
    } else {
        return Err(format!("Unexpected time tag 0x{tag:02x}"));
    };

    let month: i64 = rest[0..2]
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    let day: i64 = rest[2..4]
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    let hour: i64 = rest[4..6]
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    let min: i64 = rest[6..8]
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    let sec: i64 = rest[8..10]
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;

    let days = days_from_civil(year, month, day);
    Ok(days * 86400 + hour * 3600 + min * 60 + sec)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let mut y = year;
    let m = month;
    let d = day;
    if m <= 2 {
        y -= 1;
    }
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn read_tlv(bytes: &[u8]) -> Result<(u8, &[u8], &[u8]), String> {
    if bytes.is_empty() {
        return Err("Unexpected EOF in ASN.1".into());
    }
    let tag = bytes[0];
    let mut pos = 1;
    if pos >= bytes.len() {
        return Err("Unexpected EOF reading length".into());
    }
    let len_byte = bytes[pos];
    pos += 1;
    let len = if len_byte < 0x80 {
        len_byte as usize
    } else {
        let num_octets = (len_byte & 0x7f) as usize;
        if num_octets > 4 || pos + num_octets > bytes.len() {
            return Err("Invalid ASN.1 length encoding".into());
        }
        let mut l = 0usize;
        for i in 0..num_octets {
            l = (l << 8) | (bytes[pos + i] as usize);
        }
        pos += num_octets;
        l
    };
    if pos + len > bytes.len() {
        return Err("ASN.1 length exceeds buffer".into());
    }
    let val = &bytes[pos..pos + len];
    let rest = &bytes[pos + len..];
    Ok((tag, val, rest))
}

pub fn parse_cert_validity(cert_der: &[u8]) -> Result<(i64, i64), String> {
    let (tag, cert_content, _) = read_tlv(cert_der)?;
    if tag != 0x30 {
        return Err("Certificate is not a SEQUENCE".into());
    }

    let (tag, mut tbs_content, _) = read_tlv(cert_content)?;
    if tag != 0x30 {
        return Err("TBSCertificate is not a SEQUENCE".into());
    }

    let (tag, _, rest) = read_tlv(tbs_content)?;
    if tag == 0xa0 {
        tbs_content = rest;
    }
    let (tag, _, rest) = read_tlv(tbs_content)?;
    if tag != 0x02 {
        return Err("Expected serialNumber INTEGER".into());
    }
    tbs_content = rest;
    let (tag, _, rest) = read_tlv(tbs_content)?;
    if tag != 0x30 {
        return Err("Expected signature AlgorithmIdentifier".into());
    }
    tbs_content = rest;
    let (tag, _, rest) = read_tlv(tbs_content)?;
    if tag != 0x30 {
        return Err("Expected issuer Name".into());
    }
    tbs_content = rest;
    let (tag, validity_content, _) = read_tlv(tbs_content)?;
    if tag != 0x30 {
        return Err("Expected validity SEQUENCE".into());
    }

    let (tag1, nb_val, rest) = read_tlv(validity_content)?;
    let (tag2, na_val, _) = read_tlv(rest)?;

    let not_before = parse_time(nb_val, tag1)?;
    let not_after = parse_time(na_val, tag2)?;

    Ok((not_before, not_after))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::generate_simple_self_signed;

    #[test]
    fn test_parse_validity() {
        let cert = generate_simple_self_signed(vec!["example.com".to_string()]).unwrap();
        let der = cert.cert.der();
        let (nb, na) = parse_cert_validity(der).unwrap();
        assert!(na > nb);
        assert!(na - nb > 86400 * 300);
    }
}
