//! the ALTCHA API on the tunnel apex and the admin diagnostic page.
//!
//! These drive the real HTTPS edge and the real SQLite store: a client is
//! registered, the browser fetches a signed challenge, the widget's solve is
//! reproduced with the engine's test solver, and the payload is verified and
//! consumed exactly once.

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine as _;
use http_body_util::BodyExt;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use weaver_abuse::altcha::{Challenge, Payload, solve_challenge};
use weaver_server::altcha::AltchaRuntime;
use weaver_server::cert::managed::ManagedCerts;
use weaver_server::config::{AbuseConfig, AltchaConfig, BudgetConfig};
use weaver_server::edge::https::{HttpsEdgeConfig, run_https_server_full};
use weaver_server::edge::tls::create_self_signed_server_config;
use weaver_server::store::altcha::NewAltchaClient;
use weaver_server::{Config, Store, abuse};

const SECRET: &str = "test-altcha-secret";
const CLIENT_KEY: &str = "ak_test_client";

fn generous() -> BudgetConfig {
    BudgetConfig {
        burst: 1_000,
        refill_units: 1_000,
        refill_per_secs: 1,
    }
}

fn sample_config() -> Config {
    Config {
        tunnel_domain: "weaver.test".into(),
        admin_domain: "relay-admin.test".into(),
        admin_email: "admin@weaver.test".into(),
        acme_provider: "letsencrypt-staging".into(),
        listen_http: SocketAddr::from(([127, 0, 0, 1], 0)),
        listen_https: SocketAddr::from(([127, 0, 0, 1], 0)),
        control_socket: std::env::temp_dir().join("weaver-altcha-test.sock"),
        acme_directory: None,
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: None,
        acme_fallback_providers: Vec::new(),
        usage_flush_interval_secs: 60,
        relay_ips: Vec::new(),
        setup_complete: false,
        email: None,
        abuse: Some(AbuseConfig {
            enabled: true,
            peer_host: generous(),
            peer_network: generous(),
            retry_after_cap_secs: 60,
            bucket_ttl_secs: 3600,
            altcha: Some(AltchaConfig {
                challenge: generous(),
                verify: generous(),
                default_cost: 10,
                default_key_prefix: "00".into(),
                default_ttl_secs: 300,
                proof_cap: 1_000,
                sweep_interval_secs: 60,
                api_base_url: None,
            }),
        }),
        account: Default::default(),
    }
}

async fn test_store() -> Store {
    let dir = tempfile::tempdir().unwrap().keep();
    let store = Store::open(dir.join("altcha.db")).await.unwrap();
    store
        .altcha_client_create(
            NewAltchaClient {
                public_key: CLIENT_KEY.into(),
                secret: SECRET.into(),
                algorithm: "PBKDF2/SHA-256".into(),
                cost: 10,
                key_length: 32,
                key_prefix: "00".into(),
                ttl_secs: 300,
                service_id: None,
            },
            weaver_server::wall_clock::unix_ms(),
        )
        .await
        .unwrap();
    store
}

#[derive(Debug)]
struct TestInsecureCertVerifier;

impl ServerCertVerifier for TestInsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

fn client_config() -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TestInsecureCertVerifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

async fn https_request(addr: SocketAddr, sni: &str, raw: &str) -> String {
    let connector = TlsConnector::from(client_config());
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from(sni).unwrap().to_owned();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();
    tls.write_all(raw.as_bytes()).await.unwrap();
    let mut resp = String::new();
    tls.read_to_string(&mut resp).await.unwrap();
    resp
}

fn body(resp: &str) -> &str {
    resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
}

/// Start the HTTPS edge with the given config, returning its address.
async fn start_edge(config: Config) -> (SocketAddr, Store, CancellationToken) {
    let store = test_store().await;
    start_edge_with_store(config, store).await
}

/// Start the HTTPS edge over an existing store.
async fn start_edge_with_store(
    config: Config,
    store: Store,
) -> (SocketAddr, Store, CancellationToken) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let guard = abuse::build(&config, store.clone());
    let altcha = AltchaRuntime::from_config(&config, store.clone()).unwrap();
    let server_tls = create_self_signed_server_config("weaver.test").unwrap();
    let token = shutdown.clone();
    tokio::spawn(run_https_server_full(
        listener,
        server_tls,
        HttpsEdgeConfig {
            managed: Arc::new(ManagedCerts::from_config(&config)),
            cert_resolver: None,
            cert_manager: None,
            tunnel_registry: None,
            guard,
            altcha: Some(altcha),
            account: None,
        },
        token,
    ));
    (addr, store, shutdown)
}

/// A minimal plain-HTTP host for the ALTCHA API, standing in for the public apex
/// so the diagnostic's server-side call can be exercised without TLS.
async fn start_mock_api(runtime: Arc<AltchaRuntime>) -> (SocketAddr, CancellationToken) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let token = shutdown.clone();
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                _ = token.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            let Ok((stream, _peer)) = accepted else {
                break;
            };
            let runtime = runtime.clone();
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let service =
                    hyper::service::service_fn(move |req: http::Request<hyper::body::Incoming>| {
                        let runtime = runtime.clone();
                        async move {
                            let path = req.uri().path().to_string();
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            let response = if path == "/altcha/verify" {
                                weaver_server::altcha::api_verify(&runtime, body, false).await
                            } else {
                                http::Response::builder()
                                    .status(http::StatusCode::NOT_FOUND)
                                    .body(weaver_server::tunnel::proxy::full_body("404\n"))
                                    .unwrap()
                            };
                            Ok::<_, std::convert::Infallible>(response)
                        }
                    });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });
    (addr, shutdown)
}

/// Form-encode a value (including the `+`/`/`/`=` in a Base64 payload).
fn form_encode(input: &str) -> String {
    input
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            b' ' => "+".to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Fetch a challenge from the API and solve it as the widget would.
async fn fetch_and_solve(addr: SocketAddr, flow: &str) -> Challenge {
    let resp = https_request(
        addr,
        "weaver.test",
        &format!(
            "GET /altcha/challenge?key={CLIENT_KEY}&purpose=diagnostic&flow={flow} HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200"), "challenge: {resp:?}");
    let challenge: Challenge = serde_json::from_str(body(&resp)).expect("valid challenge JSON");
    // Prove the engine really solves it (not a fixed answer).
    let _ = solve_challenge(&challenge);
    challenge
}

fn submit_body(flow: &str, challenge: &Challenge) -> String {
    let payload = Payload {
        challenge: challenge.clone(),
        solution: solve_challenge(challenge),
    };
    let altcha =
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&payload).unwrap());
    serde_json::json!({ "altcha": altcha, "purpose": "diagnostic", "flow": flow }).to_string()
}

async fn post_verify(addr: SocketAddr, flow: &str, challenge: &Challenge) -> String {
    let req_body = submit_body(flow, challenge);
    let request = format!(
        "POST /altcha/verify HTTP/1.1\r\nHost: weaver.test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        req_body.len(),
        req_body
    );
    https_request(addr, "weaver.test", &request).await
}

#[tokio::test]
async fn challenge_verifies_once_and_then_is_spent() {
    let (addr, _store, shutdown) = start_edge(sample_config()).await;
    let challenge = fetch_and_solve(addr, "flow-1").await;

    let resp = post_verify(addr, "flow-1", &challenge).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "verify: {resp:?}");
    assert!(
        body(&resp).contains("\"verified\":true"),
        "verify: {resp:?}"
    );

    // Re-submitting the exact same proof is refused as spent.
    let replay = post_verify(addr, "flow-1", &challenge).await;
    assert!(replay.starts_with("HTTP/1.1 403"), "replay: {replay:?}");
    assert!(
        body(&replay).contains("already spent"),
        "replay: {replay:?}"
    );

    shutdown.cancel();
}

#[tokio::test]
async fn a_wrong_flow_is_refused() {
    let (addr, _store, shutdown) = start_edge(sample_config()).await;
    let challenge = fetch_and_solve(addr, "flow-1").await;
    let resp = post_verify(addr, "not-the-flow", &challenge).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp:?}");
    assert!(body(&resp).contains("wrong context"), "{resp:?}");
    shutdown.cancel();
}

#[tokio::test]
async fn the_challenge_response_allows_the_admin_origin() {
    let (addr, _store, shutdown) = start_edge(sample_config()).await;
    let resp = https_request(
        addr,
        "weaver.test",
        &format!(
            "GET /altcha/challenge?key={CLIENT_KEY}&purpose=diagnostic&flow=x HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(
        resp.to_lowercase()
            .contains("access-control-allow-origin: https://relay-admin.test"),
        "{resp:?}"
    );
    assert!(resp.to_lowercase().contains("vary: origin"), "{resp:?}");
    shutdown.cancel();
}

#[tokio::test]
async fn an_unknown_client_is_refused() {
    let (addr, _store, shutdown) = start_edge(sample_config()).await;
    let resp = https_request(
        addr,
        "weaver.test",
        "GET /altcha/challenge?key=nope&purpose=diagnostic&flow=x HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 404"), "{resp:?}");
    shutdown.cancel();
}

#[tokio::test]
async fn a_malformed_verify_body_is_refused() {
    let (addr, _store, shutdown) = start_edge(sample_config()).await;
    let req_body = "{\"altcha\":\"%%%not-base64%%%\",\"purpose\":\"diagnostic\",\"flow\":\"x\"}";
    let request = format!(
        "POST /altcha/verify HTTP/1.1\r\nHost: weaver.test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        req_body.len(),
        req_body
    );
    let resp = https_request(addr, "weaver.test", &request).await;
    assert!(resp.starts_with("HTTP/1.1 400"), "{resp:?}");
    shutdown.cancel();
}

#[tokio::test]
async fn the_demo_provisions_its_own_client() {
    let dir = tempfile::tempdir().unwrap().keep();
    let store = Store::open(dir.join("demo.db")).await.unwrap();
    let runtime = AltchaRuntime::from_config(&sample_config(), store.clone()).unwrap();

    assert!(store.altcha_internal_client().await.unwrap().is_none());
    runtime.ensure_demo_client().await.unwrap();
    assert!(store.altcha_internal_client().await.unwrap().is_some());

    // Idempotent: a second call does not add another client.
    runtime.ensure_demo_client().await.unwrap();
    assert_eq!(store.altcha_clients_list().await.unwrap().len(), 1);
}

#[tokio::test]
async fn the_diagnostic_page_is_served_with_the_widget() {
    let (addr, _store, shutdown) = start_edge(sample_config()).await;
    let resp = https_request(
        addr,
        "relay-admin.test",
        "GET /abuse/check HTTP/1.1\r\nHost: relay-admin.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp:?}");
    assert!(body(&resp).contains("<altcha-widget"), "{resp:?}");
    assert!(
        body(&resp).contains("/altcha/challenge?key=ak_test_client"),
        "{resp:?}"
    );
    // The demo CSP allows the widget but keeps everything else locked down.
    assert!(
        resp.to_lowercase().contains("content-security-policy:"),
        "{resp:?}"
    );

    // The widget assets are referenced with a content version, and served.
    let version = weaver_assets::altcha_asset_version();
    assert!(
        body(&resp).contains(&format!("/abuse/check/assets/altcha/{version}/altcha.js")),
        "{resp:?}"
    );
    let js = https_request(
        addr,
        "relay-admin.test",
        &format!(
            "GET /abuse/check/assets/altcha/{version}/altcha.js HTTP/1.1\r\nHost: relay-admin.test\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(js.starts_with("HTTP/1.1 200"), "{js:?}");
    assert!(
        js.to_lowercase().contains("content-type: text/javascript"),
        "{js:?}"
    );
    assert!(js.to_lowercase().contains("cache-control"), "{js:?}");

    // A stale version 404s, so a cached page never serves mismatched assets.
    let stale = https_request(
        addr,
        "relay-admin.test",
        "GET /abuse/check/assets/altcha/0000000000000000/altcha.js HTTP/1.1\r\nHost: relay-admin.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(stale.starts_with("HTTP/1.1 404"), "{stale:?}");

    let missing = https_request(
        addr,
        "relay-admin.test",
        "GET /abuse/check/assets/altcha/nope.js HTTP/1.1\r\nHost: relay-admin.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(missing.starts_with("HTTP/1.1 404"), "{missing:?}");
    shutdown.cancel();
}

#[tokio::test]
async fn the_diagnostic_offers_an_automatic_mode() {
    let (addr, _store, shutdown) = start_edge(sample_config()).await;
    let standard = https_request(
        addr,
        "relay-admin.test",
        "GET /abuse/check HTTP/1.1\r\nHost: relay-admin.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        body(&standard).contains("display=\"standard\""),
        "{standard:?}"
    );
    // The attribution is hidden in every mode.
    assert!(body(&standard).contains("hideFooter"), "{standard:?}");

    let auto = https_request(
        addr,
        "relay-admin.test",
        "GET /abuse/check?mode=auto HTTP/1.1\r\nHost: relay-admin.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(auto.starts_with("HTTP/1.1 200"), "{auto:?}");
    assert!(body(&auto).contains("display=\"bar\""), "{auto:?}");
    shutdown.cancel();
}

#[tokio::test]
async fn the_diagnostic_verifies_through_the_api_server_side() {
    // One store, shared by a stand-in API host and the edge.
    let store = test_store().await;

    // A plain-HTTP host for the ALTCHA API, so the diagnostic's server-side call
    // has somewhere to go without TLS.
    let mock_runtime = AltchaRuntime::from_config(&sample_config(), store.clone()).unwrap();
    let (api_addr, api_shutdown) = start_mock_api(mock_runtime).await;

    // The edge's runtime points its server-side call at the stand-in API.
    let mut config = sample_config();
    config
        .abuse
        .as_mut()
        .unwrap()
        .altcha
        .as_mut()
        .unwrap()
        .api_base_url = Some(format!("http://{api_addr}"));
    let (edge_addr, _store, edge_shutdown) = start_edge_with_store(config, store.clone()).await;

    // Fetch a challenge from the apex and solve it as the widget would.
    let flow = "demo-flow";
    let challenge = fetch_and_solve(edge_addr, flow).await;
    let payload = Payload {
        challenge: challenge.clone(),
        solution: solve_challenge(&challenge),
    };
    let altcha =
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&payload).unwrap());

    let form = format!("altcha={}&flow={}", form_encode(&altcha), form_encode(flow));
    let request = format!(
        "POST /abuse/check/verify HTTP/1.1\r\nHost: relay-admin.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        form.len(),
        form
    );
    let resp = https_request(edge_addr, "relay-admin.test", &request).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "demo: {resp:?}");
    assert!(body(&resp).contains("Proof accepted"), "demo: {resp:?}");

    // Replaying the same proof is rejected as spent, by the API.
    let resp = https_request(edge_addr, "relay-admin.test", &request).await;
    assert!(body(&resp).contains("Proof rejected"), "replay: {resp:?}");

    edge_shutdown.cancel();
    api_shutdown.cancel();
}
