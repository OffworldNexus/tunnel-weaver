//! The protocol building blocks every direct OIDC provider is assembled from
//! (WVR-175).
//!
//! These are deliberately provider-neutral: an [`HttpClient`] that owns the
//! outbound connection, a [`Jwks`] that caches a signing-key set, and an
//! [`OidcClient`] that speaks discovery, the authorization request, the code
//! exchange, the refresh, and ID-token verification. A provider file supplies
//! only *facts* — its discovery URL, how its issuer is spelled, the extra
//! authorize parameters it needs, and how its claims map onto an [`Assertion`] —
//! and never a second implementation of the flow.
//!
//! Nothing here knows a provider's name. `IssuerRule::TenantTemplate` exists for
//! providers whose `iss` embeds a tenant claim; `Fixed` covers the rest.

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
use serde_json::{Map, Value};
use tokio::sync::{OnceCell, RwLock};

/// How long any single outbound provider request may take.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The one outbound HTTP client of a provider.
///
/// Built once per provider so every call shares the connection pool and the
/// platform's TLS roots. `https_only` keeps a provider-supplied discovery URL
/// from downgrading the grant to cleartext.
pub struct HttpClient {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
}

impl HttpClient {
    /// Builds the client over the system trust store.
    pub fn new() -> Result<Self, String> {
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .try_with_platform_verifier()
            .map_err(|e| format!("failed to load system TLS roots: {e}"))?
            .https_only()
            .enable_http1()
            .build();
        Ok(Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
        })
    }

    /// GETs a URL and returns its body as text.
    pub async fn get_text(&self, url: &str) -> Result<String, String> {
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

    /// POSTs a form body and returns the status with the raw answer, so the
    /// caller can classify a refusal from the provider's error document.
    async fn post_form(&self, url: &str, form: &str) -> Result<(http::StatusCode, Bytes), String> {
        let request = Request::builder()
            .method(Method::POST)
            .uri(url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Full::new(Bytes::from(form.to_string())))
            .map_err(|e| e.to_string())?;
        self.send(request).await
    }

    async fn send(
        &self,
        mut request: Request<Full<Bytes>>,
    ) -> Result<(http::StatusCode, Bytes), String> {
        request.headers_mut().insert(
            header::USER_AGENT,
            header::HeaderValue::from_static("tunnel-weaver-account"),
        );
        let response = tokio::time::timeout(TIMEOUT, self.client.request(request))
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

/// A provider's signing-key set, cached until a `kid` it does not hold is seen.
///
/// A key that is not published is retried once against a freshly fetched set:
/// that is exactly how a key rotation looks. The cache is per provider, so a
/// rotation at one provider never refetches another's keys.
pub struct Jwks {
    http: Arc<HttpClient>,
    cache: RwLock<Option<Arc<JwkSet>>>,
}

impl Jwks {
    /// An empty cache over `http`.
    pub fn new(http: Arc<HttpClient>) -> Self {
        Self {
            http,
            cache: RwLock::new(None),
        }
    }

    /// The key set at `uri`, from the cache unless `refresh` asks for a fetch.
    async fn get(&self, uri: &str, refresh: bool) -> Result<Arc<JwkSet>, String> {
        if !refresh && let Some(found) = self.cache.read().await.as_ref() {
            return Ok(found.clone());
        }
        let body = self.http.get_text(uri).await?;
        let fetched: Arc<JwkSet> =
            Arc::new(serde_json::from_str(&body).map_err(|e| format!("bad JWKS: {e}"))?);
        *self.cache.write().await = Some(fetched.clone());
        Ok(fetched)
    }
}

/// How a provider spells `iss`.
#[derive(Debug, Clone)]
pub enum IssuerRule {
    /// One exact URL, whatever the claims say.
    Fixed(String),
    /// `prefix + <tenant claim> + suffix` — how a multi-tenant issuer embeds the
    /// tenant the token was minted for.
    TenantTemplate { prefix: String, suffix: String },
}

impl IssuerRule {
    /// Whether `claims` names an issuer this provider may have minted.
    fn accepts(&self, claims: &Map<String, Value>) -> bool {
        let Some(issuer) = claims.get("iss").and_then(Value::as_str) else {
            return false;
        };
        match self {
            IssuerRule::Fixed(expected) => issuer.eq_ignore_ascii_case(expected),
            IssuerRule::TenantTemplate { prefix, suffix } => {
                let Some(tenant) = claims.get("tid").and_then(Value::as_str) else {
                    return false;
                };
                issuer.eq_ignore_ascii_case(&format!("{prefix}{tenant}{suffix}"))
            }
        }
    }
}

/// Provider facts, as opposed to protocol behaviour.
pub struct OidcSettings {
    /// The OpenID Connect discovery document.
    pub discovery_url: String,
    /// The OAuth client id; also the ID token's expected audience.
    pub client_id: String,
    /// The plaintext client secret (already unsealed).
    pub client_secret: String,
    /// The scopes every grant asks for.
    pub scopes: String,
    /// How the provider spells `iss`.
    pub issuer: IssuerRule,
    /// Extra fixed query parameters for the authorization request (Google's
    /// `access_type` and `claims`, for instance).
    pub authorize_params: Vec<(String, String)>,
}

/// The endpoints the discovery document advertises.
#[derive(Debug, Deserialize)]
struct Endpoints {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
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

/// An ID token whose signature, lifetime, audience, nonce and issuer have all
/// been checked, with its claims left for the provider to map.
pub struct VerifiedClaims {
    claims: Map<String, Value>,
    /// The verified token itself, for diagnostics that name (never print) its
    /// claims.
    pub token: String,
}

impl VerifiedClaims {
    /// A string claim, empty when absent or of another type.
    pub fn string(&self, name: &str) -> &str {
        self.claims.get(name).and_then(Value::as_str).unwrap_or("")
    }

    /// A claim that is `true` in either the boolean or the string spelling.
    pub fn truthy(&self, name: &str) -> bool {
        match self.claims.get(name) {
            Some(Value::Bool(value)) => *value,
            Some(Value::String(value)) => value == "true",
            _ => false,
        }
    }

    /// A claim holding a list of strings.
    pub fn strings(&self, name: &str) -> Vec<&str> {
        self.claims
            .get(name)
            .and_then(Value::as_array)
            .map(|values| values.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default()
    }

    /// An integer claim.
    pub fn integer(&self, name: &str) -> Option<i64> {
        self.claims.get(name).and_then(Value::as_i64)
    }

    /// The names of the claims that arrived, without their values.
    ///
    /// Diagnostics only: when a claim the relay needs is missing, which claims
    /// *did* arrive is what tells one cause from another.
    pub fn claim_names(&self) -> Vec<String> {
        self.claims.keys().cloned().collect()
    }

    /// A verified-claims value built straight from a claim map.
    ///
    /// Test-only: it skips the verification this type exists to prove, so it
    /// must never be reachable from production code.
    #[cfg(test)]
    pub(crate) fn from_test_claims(claims: Map<String, Value>) -> Self {
        Self {
            claims,
            token: String::new(),
        }
    }
}

/// The OIDC client of one configured app registration.
pub struct OidcClient {
    http: Arc<HttpClient>,
    jwks: Jwks,
    settings: OidcSettings,
    endpoints: OnceCell<Endpoints>,
}

impl OidcClient {
    /// A client over the provider's facts.
    pub fn new(settings: OidcSettings) -> Result<Self, String> {
        let http = Arc::new(HttpClient::new()?);
        Ok(Self {
            jwks: Jwks::new(Arc::clone(&http)),
            http,
            settings,
            endpoints: OnceCell::new(),
        })
    }

    /// The authorization-request URL.
    ///
    /// `prompt` is the provider's own spelling (`select_account` for a sign-in,
    /// `login` for a step-up). `max_age` makes the provider report `auth_time`;
    /// it also caps the ID token's lifetime at `auth_time + max_age`, so it is
    /// only asked for where the time of authentication matters (a step-up).
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
            percent_encode(&self.settings.client_id),
            percent_encode(redirect_uri),
            percent_encode(&self.settings.scopes),
            percent_encode(state),
            percent_encode(nonce),
            pkce_challenge(code_verifier),
            percent_encode(prompt),
        );
        for (name, value) in &self.settings.authorize_params {
            url.push('&');
            url.push_str(&percent_encode(name));
            url.push('=');
            url.push_str(&percent_encode(value));
        }
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
    /// bind it to this flow (`nonce`) and this provider (`iss`).
    ///
    /// A key that is not published is retried once against a freshly fetched
    /// set, so a rotation is not a failed sign-in.
    pub async fn verify(&self, token: &str, nonce: &str) -> Result<VerifiedClaims, VerifyError> {
        let claims = match self.decode(token, false).await? {
            Err(Invalid::UnknownKey) => self.decode(token, true).await?,
            decoded => decoded,
        }
        .map_err(|error| VerifyError::Invalid(error.reason()))?;

        let found_nonce = claims.get("nonce").and_then(Value::as_str).unwrap_or("");
        if found_nonce != nonce {
            return Err(VerifyError::Invalid("nonce mismatch"));
        }
        // `azp` names the party the token was issued to. It is optional (and
        // only present when a provider has several audiences), but when it is
        // there it must be us.
        if let Some(azp) = claims.get("azp").and_then(Value::as_str)
            && azp != self.settings.client_id
        {
            return Err(VerifyError::Invalid("authorized party mismatch"));
        }
        if !self.settings.issuer.accepts(&claims) {
            return Err(VerifyError::Invalid("issuer mismatch"));
        }
        Ok(VerifiedClaims {
            claims,
            token: token.to_string(),
        })
    }

    /// Decodes against the cached keys, or freshly fetched ones.
    async fn decode(
        &self,
        token: &str,
        refresh: bool,
    ) -> Result<Result<Map<String, Value>, Invalid>, VerifyError> {
        let jwks = self
            .jwks
            .get(
                &self
                    .endpoints()
                    .await
                    .map_err(VerifyError::Unavailable)?
                    .jwks_uri,
                refresh,
            )
            .await
            .map_err(VerifyError::Unavailable)?;
        Ok(decode_with(&jwks, &self.settings.client_id, token))
    }

    async fn endpoints(&self) -> Result<&Endpoints, String> {
        self.endpoints
            .get_or_try_init(|| async {
                let body = self.http.get_text(&self.settings.discovery_url).await?;
                serde_json::from_str(&body).map_err(|e| format!("bad discovery document: {e}"))
            })
            .await
    }

    /// POSTs a grant (plus the client credentials) and classifies a refusal.
    async fn token(&self, grant: &str) -> Result<TokenResponse, TokenError> {
        let endpoints = self.endpoints().await.map_err(TokenError::Unavailable)?;
        let form = format!(
            "{grant}&client_id={}&client_secret={}&scope={}",
            percent_encode(&self.settings.client_id),
            percent_encode(&self.settings.client_secret),
            percent_encode(&self.settings.scopes),
        );
        let (status, bytes) = self
            .http
            .post_form(&endpoints.token_endpoint, &form)
            .await
            .map_err(TokenError::Unavailable)?;
        if status.is_success() {
            return serde_json::from_slice(&bytes)
                .map_err(|e| TokenError::Unavailable(format!("bad token answer: {e}")));
        }

        // A refusal carries `{"error": "..."}`. `invalid_grant` and
        // `interaction_required` mean the grant itself is dead — a revoked
        // token, a changed password, a policy that now demands interaction.
        let error = serde_json::from_slice::<Value>(&bytes)
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

/// Checks a token's signature, `exp` and `aud` against a key set, returning the
/// raw claims for the provider to map.
fn decode_with(jwks: &JwkSet, client_id: &str, token: &str) -> Result<Map<String, Value>, Invalid> {
    let header = decode_header(token).map_err(|_| Invalid::Rejected("bad token header"))?;
    // Every provider in use signs with RS256; ES256 is accepted because it is
    // the other registered JWS algorithm a compliant issuer may use today.
    if !matches!(header.alg, Algorithm::RS256 | Algorithm::ES256) {
        return Err(Invalid::Rejected("unexpected token algorithm"));
    }
    let kid = header.kid.ok_or(Invalid::Rejected("token has no key id"))?;
    let jwk = jwks.find(&kid).ok_or(Invalid::UnknownKey)?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| Invalid::Rejected("unusable token key"))?;
    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[client_id]);
    decode::<Map<String, Value>>(token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|_| Invalid::Rejected("token signature or lifetime rejected"))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(json: Value) -> Map<String, Value> {
        json.as_object().cloned().expect("an object")
    }

    #[test]
    fn a_fixed_issuer_is_exact() {
        let rule = IssuerRule::Fixed("https://accounts.google.com".into());
        assert!(rule.accepts(&claims(serde_json::json!({
            "iss": "https://accounts.google.com",
        }))));
        assert!(!rule.accepts(&claims(serde_json::json!({
            "iss": "https://accounts.evil.example",
        }))));
        assert!(!rule.accepts(&claims(serde_json::json!({}))));
    }

    #[test]
    fn a_tenant_template_uses_the_tid_claim() {
        let rule = IssuerRule::TenantTemplate {
            prefix: "https://login.example/".into(),
            suffix: "/v2.0".into(),
        };
        assert!(rule.accepts(&claims(serde_json::json!({
            "iss": "https://login.example/tenant-a/v2.0",
            "tid": "tenant-a",
        }))));
        // A token whose `iss` names one tenant while `tid` names another cannot
        // pass by carrying a matching `tid`.
        assert!(!rule.accepts(&claims(serde_json::json!({
            "iss": "https://login.example/tenant-a/v2.0",
            "tid": "tenant-b",
        }))));
        assert!(!rule.accepts(&claims(serde_json::json!({
            "iss": "https://login.example/tenant-a/v2.0",
        }))));
    }

    #[test]
    fn the_pkce_challenge_matches_rfc_7636() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
