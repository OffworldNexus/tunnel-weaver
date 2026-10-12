//! Server-side ALTCHA proof-of-work: the API, its clients, and the diagnostic.
//!
//! The ALTCHA API is a standalone service on the tunnel root: a challenge
//! endpoint the browser reaches cross-origin, and a verification endpoint the
//! relay (and, later, real account flows) reaches as a client. All the protocol
//! arithmetic lives in `weaver-abuse`; this module owns the HTTP wiring — the
//! JSON shapes, CORS, the client registry lookups, and the admin diagnostic
//! page that exercises the whole thing end to end.
//!
//! The diagnostic is deliberately *not* in-process: the browser fetches the
//! challenge from the apex, the widget solves it, and the admin handler posts
//! the payload back to the apex `/altcha/verify` over HTTP before rendering the
//! result. The demo is just another client of the API.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};

use weaver_abuse::{
    AltchaClient, AltchaError, ConsumeKey, ConsumeOutcome, ConsumeRequest, CreateRequest, Payload,
    ProofError, ProofStore, StoreError as EngineStoreError, Verified, create_challenge,
    verify_and_consume,
};
use weaver_assets::{
    AbuseCheckPage, altcha_asset, apply_common_security_headers, apply_demo_security_headers,
    render_abuse_check, render_abuse_check_result,
};

use crate::config::{AltchaConfig, Config};
use crate::store::Store;
use crate::store::altcha::NewAltchaClient;
use crate::store::entity::altcha_client as altcha_client_entity;
use crate::tunnel::proxy::{BoxBody, empty_body, full_body};

/// Timeout for the diagnostic's server-side call back to the API.
const API_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest accepted verification body, in bytes.
const MAX_BODY_BYTES: usize = 16 * 1024;

/// Largest accepted base64 `altcha` payload, in bytes.
const MAX_PAYLOAD_CHARS: usize = 8 * 1024;

/// The signed purpose the diagnostic binds its proofs to.
pub const DIAGNOSTIC_PURPOSE: &str = "diagnostic";

/// An HTTPS-capable client (`https_or_http` keeps a local test endpoint reachable).
type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// The server-side ALTCHA runtime: the API, its pipeline, and the diagnostic's
/// outbound client. Built once at startup and shared through the edge config.
pub struct AltchaRuntime {
    store: Store,
    /// The public base URL of the ALTCHA API (the tunnel root, no trailing slash).
    api_base_url: String,
    /// The origin allowed to call the API cross-origin (the admin host).
    admin_origin: String,
    /// The proof store the verification consumes through.
    proof: DbProofStore,
    /// Approved defaults for a client the runtime provisions itself.
    default_cost: u32,
    default_key_prefix: String,
    default_ttl_secs: i64,
    /// The client used for the diagnostic's server-side verification call.
    http: HttpClient,
}

impl std::fmt::Debug for AltchaRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AltchaRuntime")
            .field("api_base_url", &self.api_base_url)
            .field("admin_origin", &self.admin_origin)
            .finish_non_exhaustive()
    }
}

impl AltchaRuntime {
    /// Build the ALTCHA runtime.
    ///
    /// The API is always served, so this never returns `None`; the optional
    /// `abuse.altcha` block only tunes it.
    pub fn from_config(config: &Config, store: Store) -> Result<Arc<Self>, String> {
        let altcha = config
            .abuse
            .as_ref()
            .and_then(|abuse| abuse.altcha.clone())
            .unwrap_or_else(AltchaConfig::builtin);

        let proof = DbProofStore::new(store.clone(), altcha.proof_cap);
        Ok(Arc::new(Self {
            store,
            api_base_url: altcha
                .api_base_url
                .clone()
                .filter(|url| !url.is_empty())
                .unwrap_or_else(|| format!("https://{}", config.tunnel_domain)),
            admin_origin: format!("https://{}", config.admin_domain),
            proof,
            default_cost: altcha.default_cost,
            default_key_prefix: altcha.default_key_prefix.clone(),
            default_ttl_secs: altcha.default_ttl_secs as i64,
            http: build_client()?,
        }))
    }

    /// Verify and consume an ALTCHA payload for a consumer, returning the
    /// engine's result.
    ///
    /// This is the account plane's entry point into the WVR-136 engine: it
    /// resolves the client named inside the payload and consumes the proof
    /// exactly once. Whether a refusal should block the caller's action is the
    /// caller's decision, not the engine's.
    pub async fn verify_payload(
        &self,
        client: &str,
        payload: &Payload,
        purpose: &str,
        flow: &str,
    ) -> Result<Verified, AltchaError> {
        verify_and_consume(
            &self.proof,
            ConsumeRequest {
                client,
                payload,
                purpose,
                flow,
                now_ms: crate::abuse::unix_ms(),
            },
        )
        .await
    }

    /// Issue a challenge for the relay's own internal client, bound to
    /// `purpose`/`flow`.
    ///
    /// The account SPA is one of the relay's own consumers, so it never needs to
    /// know a client key: this resolves the auto-provisioned internal client
    /// itself. Returns `None` when no internal client exists yet.
    pub async fn challenge_for_internal_client(
        &self,
        purpose: &str,
        flow: &str,
    ) -> Option<weaver_abuse::Challenge> {
        let model = self.store.altcha_internal_client().await.ok().flatten()?;
        Some(self.challenge(&model_to_client(model), purpose, flow))
    }

    /// Build a challenge for `client`, bound to `purpose`/`flow`.
    fn challenge(
        &self,
        client: &AltchaClient,
        purpose: &str,
        flow: &str,
    ) -> weaver_abuse::Challenge {
        let mut data: BTreeMap<String, Value> = BTreeMap::new();
        data.insert("client".into(), Value::String(client.public_key.clone()));
        data.insert("purpose".into(), Value::String(purpose.to_string()));
        data.insert("flow".into(), Value::String(flow.to_string()));
        let mut nonce = [0u8; 16];
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut nonce);
        rand::rng().fill_bytes(&mut salt);
        create_challenge(CreateRequest {
            algorithm: &client.algorithm,
            cost: client.cost,
            key_length: client.key_length,
            key_prefix: &client.key_prefix,
            ttl_secs: client.ttl_secs,
            secret: &client.secret,
            data,
            nonce,
            salt,
            now_ms: crate::abuse::unix_ms(),
        })
    }

    /// Ensure the internal (admin) client exists so the diagnostic is
    /// self-contained.
    ///
    /// The diagnostic is a client of its own API; rather than requiring an
    /// operator to run `altcha clients create` first, the relay provisions the
    /// internal client on startup. The generated secret stays in the store and
    /// is never displayed. A concurrent creator loses benignly to the unique
    /// internal-client check.
    pub async fn ensure_demo_client(&self) -> Result<(), crate::store::StoreError> {
        if self.store.altcha_internal_client().await?.is_some() {
            return Ok(());
        }
        let new = NewAltchaClient {
            public_key: format!("ak_{}", random_hex(16)),
            secret: random_hex(32),
            algorithm: weaver_abuse::altcha::SUPPORTED_ALGORITHM.to_string(),
            cost: self.default_cost as i32,
            key_length: 32,
            key_prefix: self.default_key_prefix.clone(),
            ttl_secs: self.default_ttl_secs,
            service_id: None,
        };
        match self
            .store
            .altcha_client_create(new, crate::abuse::unix_ms())
            .await
        {
            Ok(_) | Err(crate::store::StoreError::Conflict(_)) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// POST a verification request to the API and return its JSON body.
    async fn call_verify_api(
        &self,
        altcha: &str,
        purpose: &str,
        flow: &str,
    ) -> Result<Value, String> {
        let url = format!("{}/altcha/verify", self.api_base_url.trim_end_matches('/'));
        let body = json!({ "altcha": altcha, "purpose": purpose, "flow": flow });
        let request = Request::builder()
            .method(Method::POST)
            .uri(url)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, &self.admin_origin)
            .body(Full::new(Bytes::from(body.to_string())))
            .map_err(|e| e.to_string())?;
        let response = tokio::time::timeout(API_TIMEOUT, self.http.request(request))
            .await
            .map_err(|_| "ALTCHA API timed out".to_string())?
            .map_err(|e| e.to_string())?;
        let bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| e.to_string())?
            .to_bytes();
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())
    }
}

/// A [`ProofStore`] over the typed SQLite store.
struct DbProofStore {
    store: Store,
    cap: u64,
}

impl DbProofStore {
    fn new(store: Store, cap: u64) -> Self {
        Self { store, cap }
    }
}

#[async_trait]
impl ProofStore for DbProofStore {
    async fn client(&self, public_key: &str) -> Result<Option<AltchaClient>, EngineStoreError> {
        self.store
            .altcha_client_live(public_key)
            .await
            .map(|model| model.map(model_to_client))
            .map_err(engine_error)
    }

    async fn consume(
        &self,
        key: ConsumeKey<'_>,
        now_ms: i64,
    ) -> Result<ConsumeOutcome, EngineStoreError> {
        self.store
            .altcha_consume_proof(
                key.public_key,
                key.nonce,
                key.expires_at_ms,
                now_ms,
                self.cap,
            )
            .await
            .map_err(engine_error)
    }
}

/// Map a store failure onto the engine's two-way error, so a bounded table
/// surfaces distinctly from an unavailable one.
fn engine_error(error: crate::store::StoreError) -> EngineStoreError {
    match error {
        crate::store::StoreError::Capacity(_) => EngineStoreError::Capacity,
        _ => EngineStoreError::Unavailable,
    }
}

/// Convert a persisted client row into the engine's client view.
fn model_to_client(model: altcha_client_entity::Model) -> AltchaClient {
    AltchaClient {
        public_key: model.public_key,
        secret: model.secret,
        algorithm: model.algorithm,
        cost: model.cost.max(1) as u32,
        key_length: model.key_length.max(1) as usize,
        key_prefix: model.key_prefix,
        ttl_secs: model.ttl_secs,
    }
}

/// Build the shared HTTPS client. Platform roots are used; plain HTTP is allowed
/// so a test endpoint can point at a local server.
fn build_client() -> Result<HttpClient, String> {
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .try_with_platform_verifier()
        .map_err(|e| format!("failed to load system TLS roots: {e}"))?
        .https_or_http()
        .enable_http1()
        .build();
    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

/// The body of a verification request.
#[derive(Deserialize)]
struct VerifyBody {
    /// The Base64-encoded `{ challenge, solution }` payload from the widget.
    altcha: String,
    /// The purpose the action expects (must match the signed challenge).
    #[serde(default)]
    purpose: String,
    /// The flow the action expects (must match the signed challenge).
    #[serde(default)]
    flow: String,
}

/// Serve `GET /altcha/challenge?key=&purpose=&flow=`.
pub async fn api_challenge(
    runtime: &AltchaRuntime,
    query: Option<&str>,
    include_hsts: bool,
) -> Response<BoxBody> {
    let params = parse_query(query);
    let (Some(key), Some(purpose), Some(flow)) =
        (params.get("key"), params.get("purpose"), params.get("flow"))
    else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "missing key, purpose or flow",
            runtime,
            include_hsts,
        );
    };
    if purpose.is_empty() || flow.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "empty purpose or flow",
            runtime,
            include_hsts,
        );
    }
    let model = match runtime.store.altcha_client_live(key).await {
        Ok(Some(model)) => model,
        Ok(None) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "unknown client",
                runtime,
                include_hsts,
            );
        }
        Err(_) => {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "store unavailable",
                runtime,
                include_hsts,
            );
        }
    };
    let challenge = runtime.challenge(&model_to_client(model), purpose, flow);
    json_response(
        StatusCode::OK,
        &serde_json::to_value(&challenge).unwrap_or(Value::Null),
        runtime,
        include_hsts,
    )
}

/// Serve `POST /altcha/verify` with a `{ altcha, purpose, flow }` body.
pub async fn api_verify(
    runtime: &AltchaRuntime,
    body: Bytes,
    include_hsts: bool,
) -> Response<BoxBody> {
    if body.len() > MAX_BODY_BYTES {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request too large",
            runtime,
            include_hsts,
        );
    }
    let Ok(request) = serde_json::from_slice::<VerifyBody>(&body) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "malformed request",
            runtime,
            include_hsts,
        );
    };
    if request.altcha.len() > MAX_PAYLOAD_CHARS {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload too large",
            runtime,
            include_hsts,
        );
    }
    let Some(payload) = decode_payload(&request.altcha) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "malformed payload",
            runtime,
            include_hsts,
        );
    };
    let Some(client_key) = payload
        .challenge
        .parameters
        .data
        .as_ref()
        .and_then(|data| data.get("client"))
        .and_then(Value::as_str)
    else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "payload has no client",
            runtime,
            include_hsts,
        );
    };

    let now_ms = crate::abuse::unix_ms();
    let result = verify_and_consume(
        &runtime.proof,
        ConsumeRequest {
            client: client_key,
            payload: &payload,
            purpose: &request.purpose,
            flow: &request.flow,
            now_ms,
        },
    )
    .await;
    let (status, value) = verify_result_response(result, &payload);
    json_response(status, &value, runtime, include_hsts)
}

/// Answer a CORS preflight for the API routes.
pub fn api_preflight(runtime: &AltchaRuntime, include_hsts: bool) -> Response<BoxBody> {
    let mut resp = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(empty_body())
        .unwrap();
    apply_cors(&mut resp, runtime);
    let headers = resp.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        header::HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        header::HeaderValue::from_static("content-type"),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        header::HeaderValue::from_static("600"),
    );
    apply_common_security_headers(&mut resp, include_hsts);
    resp
}

/// Serve the diagnostic page on the admin host.
///
/// `?mode=auto` renders the widget hidden (an automatic proof on submit); the
/// default shows the standard checkbox.
pub async fn demo_page(
    runtime: &AltchaRuntime,
    query: Option<&str>,
    include_hsts: bool,
) -> Response<BoxBody> {
    let Some(model) = runtime.store.altcha_internal_client().await.ok().flatten() else {
        return html_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "No internal ALTCHA client is configured. Run `weaver-server altcha clients create`.",
            runtime,
            include_hsts,
        );
    };
    let mode = match parse_query(query).get("mode").map(String::as_str) {
        Some("auto") => "auto",
        _ => "standard",
    };
    let display = if mode == "auto" { "bar" } else { "standard" };
    let client = model_to_client(model);
    let flow = random_hex(16);
    let challenge_url = format!(
        "{}/altcha/challenge?key={}&purpose={}&flow={}",
        runtime.api_base_url.trim_end_matches('/'),
        client.public_key,
        DIAGNOSTIC_PURPOSE,
        flow,
    );
    let page = render_abuse_check(AbuseCheckPage {
        challenge_url: &challenge_url,
        flow: &flow,
        display,
        mode,
        failure_payload: &failure_payload(&client.public_key, &flow),
    });
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .body(full_body(page))
        .unwrap();
    apply_demo_security_headers(&mut resp, &runtime.api_base_url, include_hsts);
    resp
}

/// Serve a vendored ALTCHA asset under
/// `/abuse/check/assets/altcha/<version>/<file>`.
///
/// The path carries the content version, so a mismatched (stale) version 404s
/// and the browser fetches the current one; a match is served `immutable`, in
/// the gzip/zstd variant the client accepts (both are pre-built at compile time).
pub fn demo_asset(
    path: &str,
    accept_encoding: Option<&str>,
    include_hsts: bool,
) -> Response<BoxBody> {
    let rest = path
        .strip_prefix("/abuse/check/assets/altcha/")
        .unwrap_or("");
    let file = match rest.split_once('/') {
        Some((version, file)) if version == weaver_assets::altcha_asset_version() => file,
        _ => "",
    };
    let Some(asset) = altcha_asset(file) else {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(full_body("404 Not Found\n"))
            .unwrap();
    };
    let coding = weaver_assets::negotiate_encoding(accept_encoding, &asset);
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, asset.content_type)
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .header(header::VARY, "accept-encoding");
    if let Some(token) = coding.token() {
        builder = builder.header(header::CONTENT_ENCODING, token);
    }
    let mut resp = builder
        .body(full_body(Bytes::from_static(asset.encoded(coding))))
        .unwrap();
    apply_common_security_headers(&mut resp, include_hsts);
    resp
}

/// Serve `POST /abuse/check/verify`: forward the widget payload to the API.
pub async fn demo_verify(
    runtime: &AltchaRuntime,
    body: Bytes,
    include_hsts: bool,
) -> Response<BoxBody> {
    if body.len() > MAX_BODY_BYTES {
        return html_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Submission too large.",
            runtime,
            include_hsts,
        );
    }
    let form = parse_query(Some(std::str::from_utf8(&body).unwrap_or("")));
    let Some(altcha) = form.get("altcha") else {
        return html_response(
            StatusCode::BAD_REQUEST,
            "No proof was submitted.",
            runtime,
            include_hsts,
        );
    };
    let flow = form.get("flow").cloned().unwrap_or_default();

    let result = runtime
        .call_verify_api(altcha, DIAGNOSTIC_PURPOSE, &flow)
        .await;
    let (verified, summary) = match result {
        Ok(value) => {
            let verified = value
                .pointer("/verification/verified")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let summary = if verified {
                "The submitted proof was verified and consumed exactly once.".to_string()
            } else {
                let reason = value
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("invalid proof");
                format!("The proof was rejected: {reason}.")
            };
            (verified, summary)
        }
        Err(error) => (false, format!("Could not reach the ALTCHA API: {error}.")),
    };
    let page = render_abuse_check_result(verified, &summary);
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .body(full_body(page))
        .unwrap();
    apply_demo_security_headers(&mut resp, &runtime.api_base_url, include_hsts);
    resp
}

/// A well-formed but unsigned payload for the diagnostic's "failed check".
///
/// The relay resolves the client, then refuses the missing signature — without
/// consuming anything — so the failure path is demonstrable end to end.
fn failure_payload(client: &str, flow: &str) -> String {
    let payload = json!({
        "challenge": {
            "parameters": {
                "algorithm": "PBKDF2/SHA-256",
                "cost": 1,
                "data": { "client": client, "purpose": DIAGNOSTIC_PURPOSE, "flow": flow },
                "keyLength": 32,
                "keyPrefix": "00",
                "nonce": "00",
                "salt": "00"
            }
        },
        "solution": { "counter": 0, "derivedKey": "00" }
    });
    base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_vec(&payload).unwrap_or_default())
}

/// Map the engine's verification result to the ALTCHA result body.
///
/// This is the API's own contract, not a relay-level refusal: a `Store` failure
/// is reported distinctly so the caller never treats it as a pass.
fn verify_result_response(
    result: Result<Verified, AltchaError>,
    payload: &Payload,
) -> (StatusCode, Value) {
    match result {
        Ok(_) => (
            StatusCode::OK,
            json!({
                "error": Value::Null,
                "payload": payload,
                "verification": {
                    "verified": true,
                    "expired": false,
                    "invalidSignature": false,
                    "invalidSolution": false,
                    "time": 0.0,
                },
            }),
        ),
        Err(AltchaError::Proof(reason)) => {
            let mut expired = false;
            let mut invalid_signature = false;
            let mut invalid_solution = false;
            let error = match reason {
                ProofError::Expired => {
                    expired = true;
                    "expired"
                }
                ProofError::MissingSignature
                | ProofError::BadSignature
                | ProofError::UnknownClient
                | ProofError::UnsupportedAlgorithm => {
                    invalid_signature = true;
                    "invalid signature"
                }
                ProofError::WrongContext => "wrong context",
                ProofError::BadSolution => {
                    invalid_solution = true;
                    "invalid solution"
                }
                ProofError::Spent => "already spent",
            };
            (
                StatusCode::FORBIDDEN,
                json!({
                    "error": error,
                    "payload": payload,
                    "verification": {
                        "verified": false,
                        "expired": expired,
                        "invalidSignature": invalid_signature,
                        "invalidSolution": invalid_solution,
                        "time": 0.0,
                    },
                }),
            )
        }
        Err(AltchaError::Store(_)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "error": "unavailable" }),
        ),
    }
}

/// Decode the widget's Base64 payload into a [`Payload`].
///
/// Tolerant of the Base64 alphabets/padding the widget may emit; the size cap is
/// enforced by the caller before this runs.
pub fn decode_payload(encoded: &str) -> Option<Payload> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let bytes = STANDARD
        .decode(encoded)
        .or_else(|_| STANDARD_NO_PAD.decode(encoded))
        .or_else(|_| URL_SAFE.decode(encoded))
        .or_else(|_| URL_SAFE_NO_PAD.decode(encoded))
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Parse an `application/x-www-form-urlencoded` body (or a query string).
fn parse_query(raw: Option<&str>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(raw) = raw else {
        return out;
    };
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        out.insert(percent_decode(key), percent_decode(value));
    }
    out
}

/// Percent-decode form text, mapping `+` to space.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = hex_val(bytes[i + 1]);
                let lo = hex_val(bytes[i + 2]);
                match (hi, lo) {
                    (Some(hi), Some(lo)) => {
                        out.push(hi << 4 | lo);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// A random lowercase-hex string of `n` bytes.
fn random_hex(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The CORS headers an API response carries.
fn apply_cors(resp: &mut Response<BoxBody>, runtime: &AltchaRuntime) {
    let headers = resp.headers_mut();
    if let Ok(origin) = header::HeaderValue::from_str(&runtime.admin_origin) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }
    headers.insert(header::VARY, header::HeaderValue::from_static("origin"));
}

/// A JSON response with CORS and common security headers.
fn json_response(
    status: StatusCode,
    value: &Value,
    runtime: &AltchaRuntime,
    include_hsts: bool,
) -> Response<BoxBody> {
    let body = serde_json::to_vec(value).unwrap_or_default();
    let mut resp = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .body(full_body(body))
        .unwrap();
    apply_cors(&mut resp, runtime);
    apply_common_security_headers(&mut resp, include_hsts);
    resp
}

/// A JSON error response.
fn api_error(
    status: StatusCode,
    message: &str,
    runtime: &AltchaRuntime,
    include_hsts: bool,
) -> Response<BoxBody> {
    json_response(status, &json!({ "error": message }), runtime, include_hsts)
}

/// A minimal HTML response (diagnostic errors) with the demo CSP.
fn html_response(
    status: StatusCode,
    message: &str,
    runtime: &AltchaRuntime,
    include_hsts: bool,
) -> Response<BoxBody> {
    let page = render_abuse_check_result(false, message);
    let mut resp = Response::builder()
        .status(status)
        .body(full_body(page))
        .unwrap();
    apply_demo_security_headers(&mut resp, &runtime.api_base_url, include_hsts);
    resp
}
