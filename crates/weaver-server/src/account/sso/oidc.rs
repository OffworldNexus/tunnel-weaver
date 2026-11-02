//! The Microsoft identity platform client: discovery, the authorization request,
//! the code exchange, the refresh, and ID-token verification (WVR-169).
//!
//! One [`EntraClient`] per configured app registration. It owns everything those
//! calls share — the outbound client, the authority, the client credentials and
//! the cached discovery document and signing keys — so callers only pass what
//! differs per request. Microsoft-specific facts the rest of the relay must not
//! have to know are pinned here: the login host, the personal-account tenant id,
//! and the fact that `iss` is `https://{host}/{tid}/v2.0` rather than a single
//! fixed string when the authority is `common` or `organizations`.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use http::{Method, Request, header};
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use ring::digest::{SHA256, digest};
use serde::Deserialize;
use tokio::sync::{OnceCell, RwLock};

/// How long any single outbound provider request may take.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The Microsoft identity platform's fixed host.
const LOGIN_HOST: &str = "login.microsoftonline.com";

/// The tenant id Microsoft uses for personal Microsoft accounts.
const MSA_TENANT: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";

/// The scopes every grant asks for: the ID token, and a refresh token.
const SCOPE: &str = "openid profile email offline_access";

type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// The endpoints the authority advertises.
#[derive(Debug, Deserialize)]
struct Endpoints {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

/// The ID-token claims this relay reads. A missing `iss` fails deserialisation.
#[derive(Debug, Clone, Deserialize)]
pub struct IdToken {
    iss: String,
    #[serde(default)]
    nonce: String,
    #[serde(default)]
    pub tid: String,
    #[serde(default)]
    pub oid: String,
    /// The authentication methods the provider used; `mfa` means a second
    /// factor was performed.
    #[serde(default)]
    amr: Vec<String>,
    #[serde(default)]
    email: String,
    /// `true` or the string `"true"`; anything else means "not verified".
    #[serde(default)]
    email_verified: Option<serde_json::Value>,
    #[serde(default)]
    pub auth_time: Option<i64>,
    #[serde(default)]
    preferred_username: String,
    #[serde(default)]
    name: String,
}

impl IdToken {
    /// The address to create or sign in the account with, and whether the
    /// provider vouched for it.
    ///
    /// `email` is the real address. Entra often omits it, and then
    /// `preferred_username` is the same address in practice — taken as an
    /// **unverified** candidate, since our own emailed code is what proves the
    /// mailbox. Only a vouched `email` counts as verified.
    pub fn address(&self) -> Option<(&str, bool)> {
        let email = self.email.trim();
        if !email.is_empty() {
            return Some((email, truthy(&self.email_verified)));
        }
        let username = self.preferred_username.trim();
        username.contains('@').then_some((username, false))
    }

    /// The display name for a new account.
    pub fn display_name(&self) -> &str {
        [&self.name, &self.preferred_username, &self.email]
            .into_iter()
            .map(|value| value.trim())
            .find(|value| !value.is_empty())
            .unwrap_or_default()
    }

    /// Whether the provider asserted a second factor.
    pub fn asserted_mfa(&self) -> bool {
        self.amr.iter().any(|m| m == "mfa" || m == "ngcmfa")
    }
}

/// A provider's token-endpoint answer.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
}

/// Why a token-endpoint call failed.
#[derive(Debug)]
pub enum TokenError {
    /// The provider refused the grant outright — a spent, expired or revoked
    /// code or refresh token, or a policy that now demands interaction. Fail
    /// closed on this; it never means "try the same grant again".
    Rejected,
    /// Anything else: a transport failure or a malformed answer.
    Unavailable(String),
}

/// Why an ID token was refused.
#[derive(Debug)]
pub enum VerifyError {
    /// The keys could not be fetched; nothing is known about the token.
    Unavailable(String),
    /// The token is invalid; the reason goes to the trail.
    Invalid(&'static str),
}

/// The client of one app registration.
pub struct EntraClient {
    http: HttpClient,
    authority: String,
    client_id: String,
    client_secret: String,
    endpoints: OnceCell<Endpoints>,
    jwks: RwLock<Option<Arc<JwkSet>>>,
}

impl EntraClient {
    /// A client for `authority` (a tenant, or `common`/`organizations`/
    /// `consumers`) with the registration's credentials.
    pub fn new(authority: &str, client_id: &str, client_secret: &str) -> Result<Self, String> {
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .try_with_platform_verifier()
            .map_err(|e| format!("failed to load system TLS roots: {e}"))?
            .https_only()
            .enable_http1()
            .build();
        Ok(Self {
            http: Client::builder(TokioExecutor::new()).build(connector),
            authority: authority.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            endpoints: OnceCell::new(),
            jwks: RwLock::new(None),
        })
    }

    /// The authorization-request URL.
    ///
    /// `prompt` is `select_account` for a sign-in and `login` for a step-up.
    /// `max_age` makes the provider report `auth_time`; it also caps the ID
    /// token's lifetime at `auth_time + max_age`, so it is only asked for where
    /// the time of authentication matters (a step-up).
    pub async fn authorize_url(
        &self,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        code_verifier: &str,
        prompt: &str,
        max_age: Option<i64>,
    ) -> Result<String, String> {
        let endpoints = self.endpoints().await?;
        let mut url = format!(
            "{}?client_id={}&response_type=code&response_mode=query&redirect_uri={}\
             &scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256&prompt={}",
            endpoints.authorization_endpoint,
            percent_encode(&self.client_id),
            percent_encode(redirect_uri),
            percent_encode(SCOPE),
            percent_encode(state),
            percent_encode(nonce),
            pkce_challenge(code_verifier),
            percent_encode(prompt),
        );
        if let Some(max_age) = max_age {
            url.push_str(&format!("&max_age={max_age}"));
        }
        Ok(url)
    }

    /// Exchanges an authorization code for tokens.
    pub async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<TokenResponse, TokenError> {
        self.token(&format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&code_verifier={}",
            percent_encode(code),
            percent_encode(redirect_uri),
            percent_encode(code_verifier),
        ))
        .await
    }

    /// Exchanges a refresh token for a fresh pair.
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenResponse, TokenError> {
        self.token(&format!(
            "grant_type=refresh_token&refresh_token={}",
            percent_encode(refresh_token),
        ))
        .await
    }

    /// Verifies an ID token: signature, `exp` and `aud`, then the claims that
    /// bind it to this flow (`nonce`) and this authority (`tid`, `iss`).
    ///
    /// A key that is not published is retried once against a freshly fetched
    /// set: that is exactly how a key rotation looks.
    pub async fn verify(&self, token: &str, nonce: &str) -> Result<IdToken, VerifyError> {
        let claims = match self.decode(token, false).await? {
            Err(Invalid::UnknownKey) => self.decode(token, true).await?,
            decoded => decoded,
        }
        .map_err(|error| VerifyError::Invalid(error.reason()))?;

        if claims.nonce != nonce {
            return Err(VerifyError::Invalid("nonce mismatch"));
        }
        if !tenant_allowed(&self.authority, &claims.tid) {
            return Err(VerifyError::Invalid("tenant not allowed"));
        }
        // `iss` is pinned to the host and to the token's own tenant, so a token
        // for another tenant cannot pass by carrying a matching `tid`.
        let expected = format!("https://{LOGIN_HOST}/{}/v2.0", claims.tid);
        if !claims.iss.eq_ignore_ascii_case(&expected) {
            return Err(VerifyError::Invalid("issuer mismatch"));
        }
        if claims.oid.is_empty() {
            return Err(VerifyError::Invalid("token has no subject"));
        }
        Ok(claims)
    }

    /// Decodes against the cached keys, or freshly fetched ones.
    async fn decode(
        &self,
        token: &str,
        refresh: bool,
    ) -> Result<Result<IdToken, Invalid>, VerifyError> {
        let jwks = self.jwks(refresh).await.map_err(VerifyError::Unavailable)?;
        Ok(decode_with(&jwks, &self.client_id, token))
    }

    async fn endpoints(&self) -> Result<&Endpoints, String> {
        self.endpoints
            .get_or_try_init(|| async {
                let url = format!(
                    "https://{LOGIN_HOST}/{}/v2.0/.well-known/openid-configuration",
                    self.authority
                );
                let body = self.get_text(&url).await?;
                serde_json::from_str(&body).map_err(|e| format!("bad discovery document: {e}"))
            })
            .await
    }

    async fn jwks(&self, refresh: bool) -> Result<Arc<JwkSet>, String> {
        if !refresh && let Some(found) = self.jwks.read().await.as_ref() {
            return Ok(found.clone());
        }
        let uri = &self.endpoints().await?.jwks_uri;
        let body = self.get_text(uri).await?;
        let fetched: Arc<JwkSet> =
            Arc::new(serde_json::from_str(&body).map_err(|e| format!("bad JWKS: {e}"))?);
        *self.jwks.write().await = Some(fetched.clone());
        Ok(fetched)
    }

    /// POSTs a grant (plus the client credentials) and classifies a refusal.
    async fn token(&self, grant: &str) -> Result<TokenResponse, TokenError> {
        let endpoints = self.endpoints().await.map_err(TokenError::Unavailable)?;
        let form = format!(
            "{grant}&client_id={}&client_secret={}&scope={}",
            percent_encode(&self.client_id),
            percent_encode(&self.client_secret),
            percent_encode(SCOPE),
        );
        let request = Request::builder()
            .method(Method::POST)
            .uri(&endpoints.token_endpoint)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Full::new(Bytes::from(form)))
            .map_err(|e| TokenError::Unavailable(e.to_string()))?;
        let (status, bytes) = self.send(request).await.map_err(TokenError::Unavailable)?;
        if status.is_success() {
            return serde_json::from_slice(&bytes)
                .map_err(|e| TokenError::Unavailable(format!("bad token answer: {e}")));
        }

        // A refusal carries `{"error": "..."}`. `invalid_grant` and
        // `interaction_required` mean the grant itself is dead — a revoked
        // token, a changed password, a policy that now demands interaction.
        let error = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|value| value.get("error")?.as_str().map(str::to_string))
            .unwrap_or_default();
        if matches!(error.as_str(), "invalid_grant" | "interaction_required") {
            return Err(TokenError::Rejected);
        }
        Err(TokenError::Unavailable(format!(
            "provider returned {status} ({error})"
        )))
    }

    async fn get_text(&self, url: &str) -> Result<String, String> {
        let request = Request::builder()
            .method(Method::GET)
            .uri(url)
            .body(Full::new(Bytes::new()))
            .map_err(|e| e.to_string())?;
        let (status, bytes) = self.send(request).await?;
        if !status.is_success() {
            return Err(format!("provider returned {status}"));
        }
        String::from_utf8(bytes.to_vec()).map_err(|e| e.to_string())
    }

    async fn send(
        &self,
        mut request: Request<Full<Bytes>>,
    ) -> Result<(http::StatusCode, Bytes), String> {
        request.headers_mut().insert(
            header::USER_AGENT,
            header::HeaderValue::from_static("tunnel-weaver-account"),
        );
        let response = tokio::time::timeout(TIMEOUT, self.http.request(request))
            .await
            .map_err(|_| "provider request timed out".to_string())?
            .map_err(|e| e.to_string())?;
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| e.to_string())?
            .to_bytes();
        Ok((status, bytes))
    }
}

/// Why a token failed to decode.
enum Invalid {
    /// Its `kid` is not in the key set: a forgery, or a rotation.
    UnknownKey,
    Rejected(&'static str),
}

impl Invalid {
    fn reason(&self) -> &'static str {
        match self {
            Invalid::UnknownKey => "token key is not published",
            Invalid::Rejected(reason) => reason,
        }
    }
}

/// Checks a token's signature, `exp` and `aud` against a key set.
fn decode_with(jwks: &JwkSet, client_id: &str, token: &str) -> Result<IdToken, Invalid> {
    let header = decode_header(token).map_err(|_| Invalid::Rejected("bad token header"))?;
    if header.alg != Algorithm::RS256 {
        return Err(Invalid::Rejected("unexpected token algorithm"));
    }
    let kid = header.kid.ok_or(Invalid::Rejected("token has no key id"))?;
    let jwk = jwks.find(&kid).ok_or(Invalid::UnknownKey)?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| Invalid::Rejected("unusable token key"))?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[client_id]);
    decode::<IdToken>(token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|_| Invalid::Rejected("token signature or lifetime rejected"))
}

/// The `tid` matrix for the configured authority.
fn tenant_allowed(authority: &str, tid: &str) -> bool {
    let is_guid = tid.len() == 36 && tid.chars().filter(|c| *c == '-').count() == 4;
    if !is_guid {
        return false;
    }
    match authority.to_ascii_lowercase().as_str() {
        // Any work or school tenant, but not a personal account.
        "organizations" => !tid.eq_ignore_ascii_case(MSA_TENANT),
        // Work, school, and personal.
        "common" => true,
        // Personal only.
        "consumers" => tid.eq_ignore_ascii_case(MSA_TENANT),
        // A specific tenant.
        tenant => tid.eq_ignore_ascii_case(tenant),
    }
}

/// The PKCE challenge for a verifier: base64url(SHA-256(verifier)), unpadded.
fn pkce_challenge(verifier: &str) -> String {
    let hash = digest(&SHA256, verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.as_ref())
}

/// Percent-encodes a query component, keeping the unreserved set readable.
pub fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The names of the claims a JWT carries, without their values.
///
/// Diagnostics only: when a claim the relay needs is missing, which claims *did*
/// arrive is what tells one cause from another. Values are never read.
pub fn claim_names(token: &str) -> Vec<String> {
    token
        .split('.')
        .nth(1)
        .and_then(|payload| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .ok()
        })
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|value| value.as_object().map(|map| map.keys().cloned().collect()))
        .unwrap_or_default()
}

/// Reads a claim that is `true` in either the boolean or the string spelling.
fn truthy(value: &Option<serde_json::Value>) -> bool {
    match value {
        Some(serde_json::Value::Bool(value)) => *value,
        Some(serde_json::Value::String(value)) => value == "true",
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT: &str = "32fb7b25-9b31-4552-a225-7cb8da0afb61";

    fn token(json: serde_json::Value) -> IdToken {
        serde_json::from_value(json).expect("claims deserialise")
    }

    #[test]
    fn the_tenant_matrix_follows_the_authority() {
        assert!(tenant_allowed("common", TENANT));
        assert!(tenant_allowed("common", MSA_TENANT));
        assert!(tenant_allowed("organizations", TENANT));
        assert!(!tenant_allowed("organizations", MSA_TENANT));
        assert!(tenant_allowed("consumers", MSA_TENANT));
        assert!(!tenant_allowed("consumers", TENANT));
        assert!(tenant_allowed(TENANT, TENANT));
        assert!(!tenant_allowed(TENANT, MSA_TENANT));
        assert!(!tenant_allowed("common", "not-a-guid"));
    }

    #[test]
    fn only_a_vouched_email_claim_is_a_verified_address() {
        let vouched = token(serde_json::json!({
            "iss": "x", "email": "a@b.c", "email_verified": "true",
        }));
        assert_eq!(vouched.address(), Some(("a@b.c", true)));
        let unvouched = token(serde_json::json!({ "iss": "x", "email": "a@b.c" }));
        assert_eq!(unvouched.address(), Some(("a@b.c", false)));
        let username = token(serde_json::json!({
            "iss": "x", "preferred_username": "a@b.c", "email_verified": true,
        }));
        assert_eq!(username.address(), Some(("a@b.c", false)));
        let none = token(serde_json::json!({ "iss": "x", "preferred_username": "alice" }));
        assert_eq!(none.address(), None);
    }

    #[test]
    fn mfa_is_read_from_amr() {
        assert!(token(serde_json::json!({ "iss": "x", "amr": ["pwd", "mfa"] })).asserted_mfa());
        assert!(token(serde_json::json!({ "iss": "x", "amr": ["ngcmfa"] })).asserted_mfa());
        assert!(!token(serde_json::json!({ "iss": "x", "amr": ["pwd"] })).asserted_mfa());
        assert!(!token(serde_json::json!({ "iss": "x" })).asserted_mfa());
    }

    #[test]
    fn the_pkce_challenge_matches_rfc_7636() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
