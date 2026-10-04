//! ACME protocol engine for automated certificate issuance and renewal.
//!
//! Orchestrates RFC 8555 certificate orders using `instant-acme`, supporting:
//! - ECDSA P-256 account and certificate keys
//! - External Account Binding (EAB) for commercial CAs
//! - Custom Root CA PEM for private/staging environments (Pebble)
//! - Challenge solving via a `ChallengeSolver` registry (DNS-01, HTTP-01)
//! - Provider fallback on rate limiting (429) or upstream 5xx errors

use std::sync::Arc;

use base64::Engine;
use instant_acme::{
    Account, AccountBuilder, AccountCredentials, ChallengeType, ExternalAccountKey, Identifier,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use tracing::{debug, info, warn};

use crate::cert::clock::{Clock, format_unix_timestamp};
use crate::cert::events::record_cert_event;
use crate::cert::providers::{find_provider, is_wildcard_capable, resolve_directory_url};
use crate::cert::solver::{SolverRegistry, validation_label};
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
    /// DCV mechanisms the engine can drive. The engine itself never knows what
    /// DNS or HTTP mean; it only maps an offered `ChallengeType` onto a solver.
    registry: SolverRegistry,
}

impl AcmeEngine {
    /// Creates a new ACME engine instance.
    pub fn new(config: Arc<Config>, store: Arc<Store>, clock: Arc<dyn Clock>) -> Self {
        let registry = SolverRegistry::with_defaults(Arc::clone(&store));
        Self {
            config,
            store,
            clock,
            registry,
        }
    }

    /// Issues or renews the single wildcard certificate for `root`.
    ///
    /// One DNS-01 order carries both SANs, `<root>` and `*.<root>`. The two
    /// authorizations share the challenge name `_acme-challenge.<root>`, so
    /// both TXT values are published before either authorization is marked
    /// ready; the authoritative responder answers that name with a multi-value
    /// RRset.
    pub async fn issue_wildcard(&self, root: &str) -> Result<IssuedCertificate, AcmeError> {
        let root = root.to_ascii_lowercase();
        if !is_wildcard_capable(&self.config.acme_provider) {
            return Err(AcmeError::Other(format!(
                "provider '{}' cannot issue wildcard certificates",
                self.config.acme_provider
            )));
        }

        let directories = self.resolve_directory_list();
        if directories.is_empty() {
            return Err(AcmeError::Other(
                "No wildcard-capable ACME directories available".into(),
            ));
        }

        // One DNS-01 order carries both SANs. The apex and wildcard
        // authorizations derive the same `_acme-challenge.<root>` owner name, so
        // both TXT digests are published before either is marked ready.
        let names = vec![root.clone(), format!("*.{root}")];
        self.issue_with_fallback(&root, &names, ChallengeType::Dns01, &directories)
            .await
    }

    /// Issues or renews the single-name admin certificate for `admin_domain`
    /// using HTTP-01.
    ///
    /// The admin domain is deliberately *outside* the tunnel delegation, so no
    /// DNS-01 TXT can be published for it and no CAA is served by our responder.
    /// HTTP-01 only needs port 80, which the edge already owns; the solver
    /// stores token rows for the port-80 responder to serve.
    pub async fn issue_admin(&self, admin_domain: &str) -> Result<IssuedCertificate, AcmeError> {
        let admin = admin_domain.to_ascii_lowercase();
        let directories = self.resolve_admin_directory_list();
        if directories.is_empty() {
            return Err(AcmeError::Other(
                "No ACME directories available for the admin certificate".into(),
            ));
        }

        let names = vec![admin.clone()];
        self.issue_with_fallback(&admin, &names, ChallengeType::Http01, &directories)
            .await
    }

    /// Tries each resolved directory in order, falling over to the next on a
    /// rate limit or an upstream 5xx.
    async fn issue_with_fallback(
        &self,
        cert_name: &str,
        names: &[String],
        challenge_type: ChallengeType,
        directories: &[(String, String)],
    ) -> Result<IssuedCertificate, AcmeError> {
        let mut last_err = String::from("No providers attempted");

        for (idx, (provider_id, dir_url)) in directories.iter().enumerate() {
            debug!(
                cert_name,
                provider_id,
                dir_url,
                mechanism = validation_label(&challenge_type),
                attempt = idx + 1,
                total = directories.len(),
                "Attempting ACME issuance"
            );

            match self
                .issue_order_against_directory(
                    cert_name,
                    names,
                    challenge_type.clone(),
                    provider_id,
                    dir_url,
                )
                .await
            {
                Ok(cert) => {
                    info!(
                        cert_name,
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
                        cert_name,
                        provider_id,
                        dir_url,
                        error = %err,
                        "ACME issuance failed against provider"
                    );
                    last_err = err.to_string();

                    // Fallback on rate limits or 5xx server errors.
                    if (err.is_rate_limited() || err.is_server_error())
                        && idx + 1 < directories.len()
                    {
                        info!(
                            next_provider = directories[idx + 1].0,
                            "Failing over to fallback ACME provider"
                        );
                        continue;
                    }

                    return Err(err);
                }
            }
        }

        Err(AcmeError::AllProvidersFailed(last_err))
    }

    /// Executes the full order lifecycle against a single directory endpoint.
    ///
    /// This method is mechanism-agnostic: it provisions through whichever
    /// solver the registry maps `challenge_type` to and never names DNS or HTTP.
    async fn issue_order_against_directory(
        &self,
        cert_name: &str,
        names: &[String],
        challenge_type: ChallengeType,
        provider_id: &str,
        directory_url: &str,
    ) -> Result<IssuedCertificate, AcmeError> {
        let account = self
            .get_or_create_account(provider_id, directory_url)
            .await?;
        let solver = self.registry.get(&challenge_type).ok_or_else(|| {
            AcmeError::Other(format!(
                "no challenge solver registered for '{}'",
                validation_label(&challenge_type)
            ))
        })?;

        // 1. Generate certificate keypair (ECDSA P-256)
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| AcmeError::Other(format!("Failed to generate P-256 keypair: {e}")))?;
        let key_pem = key_pair.serialize_pem();

        // 2. Generate the CSR for every SAN (one name for admin, apex+wildcard
        //    for the tunnel).
        let mut params = CertificateParams::new(names.to_vec())
            .map_err(|e| AcmeError::Other(format!("Failed to create CertificateParams: {e}")))?;
        params.distinguished_name = DistinguishedName::new();
        let csr = params
            .serialize_request(&key_pair)
            .map_err(|e| AcmeError::Other(format!("Failed to generate CSR: {e}")))?;

        // 3. Create the order.
        let identifiers: Vec<Identifier> = names
            .iter()
            .map(|name| Identifier::Dns(name.clone()))
            .collect();
        let new_order = NewOrder::new(&identifiers);
        let mut order = account
            .new_order(&new_order)
            .await
            .map_err(Self::map_instant_acme_error)?;

        // 4. Provision every authorization before marking any ready. The guards
        //    withdraw each response when this scope ends, whatever the outcome.
        let mut guards = Vec::new();
        let mut authzs = order.authorizations();
        while let Some(authz_res) = authzs.next().await {
            let mut authz = authz_res.map_err(Self::map_instant_acme_error)?;

            let mut chal = authz.challenge(challenge_type.clone()).ok_or_else(|| {
                AcmeError::Other(format!(
                    "no '{}' challenge offered for an authorization of {cert_name}",
                    validation_label(&challenge_type)
                ))
            })?;

            let identifier = chal.identifier().to_string();
            let key_auth = chal.key_authorization().as_str().to_string();
            let token = chal.token.clone();
            let guard = solver
                .provision(&identifier, &token, &key_auth)
                .await
                .map_err(|e| AcmeError::Other(format!("Failed to provision challenge: {e}")))?;
            guards.push(guard);

            chal.set_ready()
                .await
                .map_err(Self::map_instant_acme_error)?;
        }

        // 5. Poll order readiness. `poll_ready` returns the status even on
        //    failure, so an `Invalid` order must be turned into an error with
        //    the per-authorization reason rather than allowed to reach
        //    `finalize_csr`.
        let ready_res = order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(Self::map_instant_acme_error);

        let status = match ready_res {
            Ok(status) => Some(status),
            Err(err) => {
                drop(guards);
                return Err(err);
            }
        };

        if status == Some(OrderStatus::Invalid) {
            let mut details = Vec::new();
            let mut authzs = order.authorizations();
            while let Some(authz_res) = authzs.next().await {
                let Ok(mut authz) = authz_res else {
                    continue;
                };
                if let Ok(state) = authz.refresh().await {
                    for challenge in &state.challenges {
                        if let Some(error) = &challenge.error {
                            details.push(format!(
                                "{:?}: {} ({})",
                                challenge.r#type,
                                error.detail.clone().unwrap_or_default(),
                                error.r#type.clone().unwrap_or_default()
                            ));
                        }
                    }
                }
            }

            drop(guards);

            let detail = if details.is_empty() {
                "no authorization error detail returned".to_string()
            } else {
                details.join("; ")
            };
            return Err(AcmeError::Other(format!(
                "'{}' validation failed for {cert_name}: {detail}",
                validation_label(&challenge_type)
            )));
        }

        // 6. Withdraw the challenge responses before finalizing.
        drop(guards);

        order
            .finalize_csr(csr.der())
            .await
            .map_err(Self::map_instant_acme_error)?;

        let cert_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(Self::map_instant_acme_error)?;

        // 7. Parse validity from the first certificate in the PEM chain.
        let first_der = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .next()
            .ok_or_else(|| AcmeError::Other("Empty certificate chain returned".into()))?
            .map_err(|e| AcmeError::Other(format!("Invalid certificate DER: {e}")))?;

        let (not_before, not_after) = parse_cert_validity(&first_der)
            .map_err(|e| AcmeError::Other(format!("Failed to parse validity: {e}")))?;

        let now = self.clock.now_unix();

        // 8. Persist into the certificates table, keyed by the certificate name.
        //    Whether any SAN is a wildcard is recorded on the row so the control
        //    surface can label the tunnel cert vs the admin cert without
        //    re-deriving it from the name.
        let wildcard = names.iter().any(|name| name.starts_with("*."));
        self.store
            .save_certificate(
                cert_name,
                crate::store::NewCertificate {
                    cert_pem: cert_pem.clone(),
                    key_pem: key_pem.clone(),
                    not_before,
                    not_after,
                    issuer: None,
                    directory: directory_url.to_string(),
                    obtained_at: now,
                    validation: validation_label(&challenge_type).to_string(),
                    wildcard,
                },
            )
            .await
            .map_err(|e| AcmeError::Other(format!("Failed to save certificate: {e}")))?;

        let _ = record_cert_event(
            &self.store,
            cert_name,
            now,
            "issued",
            Some(&format!("directory: {directory_url}")),
        )
        .await;

        Ok(IssuedCertificate {
            name: cert_name.to_string(),
            cert_pem,
            key_pem,
            not_before,
            not_after,
            directory: directory_url.to_string(),
        })
    }

    /// Resolves the list of ACME directories to try: primary provider first,
    /// then fallbacks, restricted to wildcard-capable providers.
    fn resolve_directory_list(&self) -> Vec<(String, String)> {
        self.resolve_directory_list_filtered(true)
    }

    /// Resolves the directories for an HTTP-01, single-name admin order.
    ///
    /// Wildcard capability is irrelevant here (the admin certificate is one
    /// exact name), so every configured provider — including e.g. Buypass — is
    /// eligible.
    fn resolve_admin_directory_list(&self) -> Vec<(String, String)> {
        self.resolve_directory_list_filtered(false)
    }

    /// Builds the ordered provider/directory list, optionally requiring
    /// wildcard capability.
    fn resolve_directory_list_filtered(&self, require_wildcard: bool) -> Vec<(String, String)> {
        let eligible = |id: &str| !require_wildcard || is_wildcard_capable(id);
        let mut list = Vec::new();

        if eligible(&self.config.acme_provider)
            && let Some(primary_url) = resolve_directory_url(
                &self.config.acme_provider,
                self.config.acme_directory.as_deref(),
            )
        {
            list.push((self.config.acme_provider.clone(), primary_url));
        }

        for fallback in &self.config.acme_fallback_providers {
            if !eligible(fallback) {
                warn!(
                    provider = %fallback,
                    "Skipping ACME fallback provider: wildcard-incapable"
                );
                continue;
            }
            if let Some(url) = resolve_directory_url(fallback, None)
                && !list.iter().any(|(_, u)| u == &url)
            {
                list.push((fallback.clone(), url));
            }
        }

        list
    }

    /// Fetches existing ACME account credentials from SQLite or creates a new account.
    async fn get_or_create_account(
        &self,
        provider_id: &str,
        directory_url: &str,
    ) -> Result<Account, AcmeError> {
        // 1. Check if account already exists in DB
        let cached = self
            .store
            .get_acme_account(directory_url)
            .await
            .map_err(|e| AcmeError::Other(format!("Database read failed: {e}")))?;

        let builder = create_account_builder_from_pem(self.config.acme_root_ca_pem.as_deref())?;

        if let Some(account) = cached
            && let Ok(creds) = serde_json::from_str::<AccountCredentials>(&account.credentials_json)
        {
            match builder.from_credentials(creds).await {
                Ok(account) => return Ok(account),
                Err(e) => {
                    warn!(directory = directory_url, error = %e, "Failed to restore ACME account from credentials, recreating");
                }
            }
        }

        // 2. Create new account with ECDSA P-256 key
        let builder = create_account_builder_from_pem(self.config.acme_root_ca_pem.as_deref())?;
        let contact = format!("mailto:{}", self.config.admin_email);
        let new_account = NewAccount {
            contact: &[&contact],
            terms_of_service_agreed: true,
            only_return_existing: false,
        };

        // Prepare External Account Binding (EAB) if configured or required
        let eab = parse_eab(
            provider_id,
            self.config.acme_eab_kid.as_deref(),
            self.config.acme_eab_hmac.as_deref(),
        )?;

        let (account, credentials): (Account, AccountCredentials) = builder
            .create(&new_account, directory_url.to_string(), eab.as_ref())
            .await
            .map_err(Self::map_instant_acme_error)?;

        let creds_json = serde_json::to_string(&credentials)
            .map_err(|e| AcmeError::Other(format!("Failed to serialize credentials: {e}")))?;
        let kid = account.id().to_string();
        let now = self.clock.now_unix();

        // Persist into acme_account
        self.store
            .upsert_acme_account(
                directory_url,
                &self.config.admin_email,
                &creds_json,
                Some(&kid),
                now,
            )
            .await
            .map_err(|e| AcmeError::Other(format!("Failed to save account: {e}")))?;

        Ok(account)
    }

    /// Converts an `instant_acme::Error` into an `AcmeError`, classifying rate limits and server errors.
    pub fn map_instant_acme_error(err: instant_acme::Error) -> AcmeError {
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

/// Result of registering a new ACME account against the directory.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegisteredAcmeAccount {
    /// Serialized credentials JSON suitable for persisting in the database.
    pub creds_json: String,
    /// Account Key Identifier (KID) assigned by the ACME server.
    pub kid: String,
}

/// Prepares External Account Binding if keys are provided or required.
pub fn parse_eab(
    provider_id: &str,
    eab_kid: Option<&str>,
    eab_hmac: Option<&str>,
) -> Result<Option<ExternalAccountKey>, AcmeError> {
    let (Some(kid_str), Some(hmac_str)) = (eab_kid, eab_hmac) else {
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

/// Creates an `AccountBuilder` configured with custom Root CA PEM if present.
pub fn create_account_builder_from_pem(
    root_ca_pem: Option<&str>,
) -> Result<AccountBuilder, AcmeError> {
    if let Some(ca_pem) = root_ca_pem {
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

/// Registers a new ACME account directly against the directory without requiring database persistence.
pub async fn register_acme_account(
    admin_email: &str,
    provider_id: &str,
    directory_url: &str,
    eab_kid: Option<&str>,
    eab_hmac: Option<&str>,
    root_ca_pem: Option<&str>,
) -> Result<RegisteredAcmeAccount, AcmeError> {
    let builder = create_account_builder_from_pem(root_ca_pem)?;
    let contact = format!("mailto:{admin_email}");
    let new_account = NewAccount {
        contact: &[&contact],
        terms_of_service_agreed: true,
        only_return_existing: false,
    };

    let eab = parse_eab(provider_id, eab_kid, eab_hmac)?;

    let (account, credentials): (Account, AccountCredentials) = builder
        .create(&new_account, directory_url.to_string(), eab.as_ref())
        .await
        .map_err(AcmeEngine::map_instant_acme_error)?;

    let creds_json = serde_json::to_string(&credentials)
        .map_err(|e| AcmeError::Other(format!("Failed to serialize credentials: {e}")))?;
    let kid = account.id().to_string();

    Ok(RegisteredAcmeAccount { creds_json, kid })
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
