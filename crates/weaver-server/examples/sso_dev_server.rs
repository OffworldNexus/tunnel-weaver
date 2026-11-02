//! A runnable, dev-only harness for exercising the Microsoft Entra ID sign-in
//! (WVR-169) against the **real** provider in a headed browser.
//!
//! Unlike `e2e_server`, this speaks **plain HTTP** on a fixed loopback port so
//! the OIDC redirect URI matches the one registered verbatim in the Entra app
//! registration. TLS would change the origin (`https://…`) and the redirect URI
//! is compared byte-for-byte by Entra — a mismatch is `AADSTS50011`, not a
//! useful error — so the harness deliberately gives up TLS rather than the
//! operator having to re-register a second redirect URI just to test.
//!
//! It boots the *real* account stack (the real `Store`, the real ALTCHA
//! runtime, the real account router mounted in a raw-hyper edge). By default the
//! mailer is swapped for one that prints each email to stdout, so the emailed
//! sign-in code can be read straight from the terminal when the SSO session lands
//! at `Basic`; set `WEAVER_RESEND_API_KEY` to deliver for real through Resend
//! instead.
//!
//! The Microsoft preset comes from the environment, and is **optional**:
//!
//! ```text
//! WEAVER_SSO_MICROSOFT_AUTHORITY=common \
//! WEAVER_SSO_MICROSOFT_CLIENT_ID=<app-id> \
//! WEAVER_SSO_MICROSOFT_CLIENT_SECRET=<client-secret> \
//! cargo run -p weaver-server --example sso_dev_server
//! ```
//!
//! With none of those set the server still runs, just with no provider
//! configured — the sign-in page then shows no Microsoft button.
//!
//! Email delivery is likewise **optional**:
//!
//! ```text
//! WEAVER_RESEND_API_KEY=<re_...> \
//! WEAVER_RESEND_FROM=contact@offworld.nexus \
//! cargo run -p weaver-server --example sso_dev_server
//! ```
//!
//! With `WEAVER_RESEND_API_KEY` set and non-empty the harness builds the
//! daemon's own Resend mailer and delivers for real; `WEAVER_RESEND_FROM`
//! defaults to `contact@offworld.nexus`. With it unset or empty every message is
//! captured to stdout instead, so the harness still works offline.
//!
//! No ACME, no TLS, no control socket, no DNS: this is a local dev harness, not
//! a deployment.

use std::convert::Infallible;
use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use http::Response;
use http_body_util::BodyExt as _;
use hyper::Request;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use weaver_assets::{apply_common_security_headers, apply_spa_security_headers};
use weaver_server::Store;
use weaver_server::account::AccountRuntime;
use weaver_server::account::auth::ClientAddr;
use weaver_server::account::sso::Microsoft;
use weaver_server::altcha::AltchaRuntime;
use weaver_server::config::{AccountConfig, Config, EmailConfig, MicrosoftPreset};
use weaver_server::email::{
    Email, Mailbox, Mailer, MailerError, MailerIdentity, SendReceipt, mailer_from_config,
};
use weaver_server::seal::SealKey;
use weaver_server::tunnel::proxy::{BoxBody, full_body};

mod support;

/// The single host (and port) the harness serves. The Entra app registers the
/// redirect URI built from this verbatim, so it is a constant rather than a
/// random port: the operator does not have to re-register per run.
const ADMIN_HOST: &str = "localhost:43871";
/// Loopback address the listener binds. `localhost` resolves here.
const LISTEN: &str = "127.0.0.1:43871";

/// A mailer that prints each message to **stdout** instead of sending it.
///
/// The SSO flow lands at `Basic` and issues an emailed code when the account has
/// no authenticator app, so the operator needs the code; printing it to the
/// terminal is the whole capture mechanism (there is no test runner here to poll
/// an HTTP buffer the way `e2e_server` does).
struct StdoutMailer {
    identity: MailerIdentity,
}

#[async_trait]
impl Mailer for StdoutMailer {
    fn identity(&self) -> &MailerIdentity {
        &self.identity
    }

    async fn send(&self, email: &Email) -> Result<SendReceipt, MailerError> {
        let to = email
            .to
            .iter()
            .map(|mailbox| mailbox.address.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        // A fenced block so the code is easy to find amid tracing noise.
        println!(
            "\n----- dev mail (captured, not sent) -----\nTo: {to}\nSubject: {}\n\n{}\n-----------------------------------------\n",
            email.subject, email.text
        );
        std::io::stdout().flush().expect("flush stdout");
        Ok(SendReceipt { message_id: None })
    }
}

/// The Resend API key from the environment, when one is set and non-empty.
///
/// The key is read here and only here — never hardcoded, printed, or written to
/// a file — and handed straight to the product's mailer factory.
fn resend_api_key_from_env() -> Option<String> {
    std::env::var("WEAVER_RESEND_API_KEY")
        .ok()
        .filter(|key| !key.is_empty())
}

/// Builds the real Resend mailer through the daemon's own factory.
///
/// `mailer_from_config` is what `server::run` uses, so the harness gets the same
/// provider catalog, auth scheme, request shape, and error redaction as a
/// deployment. The sender address comes from `WEAVER_RESEND_FROM` (default
/// `contact@offworld.nexus`) under the `Tunnel Weaver` display name; the support
/// link is a decorative HTTPS placeholder, since the harness serves cleartext.
fn resend_mailer(api_key: String) -> Arc<dyn Mailer> {
    let from = std::env::var("WEAVER_RESEND_FROM")
        .ok()
        .filter(|address| !address.is_empty())
        .unwrap_or_else(|| "contact@offworld.nexus".to_string());
    let email = EmailConfig {
        provider: "resend".to_string(),
        from,
        from_name: Some("Tunnel Weaver".to_string()),
        api_key: Some(api_key),
        ..EmailConfig::default()
    };
    mailer_from_config(Some(&email), "https://localhost").expect("build the Resend mailer")
}

/// The Microsoft preset from the environment, sealed exactly as the CLI
/// (`weaver-server sso microsoft set`) stores it. All three variables are
/// required: a partial set is reported and ignored rather than half-configured.
fn microsoft_from_env(sso_key: &SealKey) -> Option<MicrosoftPreset> {
    let read = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    match (
        read("WEAVER_SSO_MICROSOFT_AUTHORITY"),
        read("WEAVER_SSO_MICROSOFT_CLIENT_ID"),
        read("WEAVER_SSO_MICROSOFT_CLIENT_SECRET"),
    ) {
        (Some(authority), Some(client_id), Some(secret)) => Some(MicrosoftPreset {
            authority,
            client_id,
            client_secret: Microsoft::seal_client_secret(sso_key, &secret)
                .expect("seal the Microsoft client secret"),
            enabled: true,
        }),
        (None, None, None) => None,
        _ => {
            eprintln!(
                "Ignoring the Microsoft preset: set all of WEAVER_SSO_MICROSOFT_AUTHORITY, \
                 WEAVER_SSO_MICROSOFT_CLIENT_ID and WEAVER_SSO_MICROSOFT_CLIENT_SECRET, or none."
            );
            None
        }
    }
}

/// The config the harness runs with. It is never persisted: the sealing key
/// is this process's, so a stored secret could not open under the next run's.
fn sample_config() -> Config {
    let mut account = AccountConfig {
        // Keep `Secure`: the session cookie is `__Host-weaver_session`, and a
        // `__Host-` cookie **must** carry `Secure` or the browser rejects it
        // outright — which silently strands every sign-in on the sign-in page.
        // Browsers treat `http://localhost` as a trustworthy origin, so a
        // `Secure` cookie is accepted there even over plain HTTP.
        cookie_secure: true,
        ..support::account_config(format!("http://{ADMIN_HOST}"))
    };
    account.microsoft = microsoft_from_env(&account.sso_key);
    // The harness injects its own mailer (captured or Resend).
    support::config(account, "sso-dev-server.sock", None)
}

/// Bridges a hyper request into the account router and maps the response back,
/// applying the account surface's security headers.
///
/// This is `edge::https::serve_account` for cleartext: the daemon has no
/// plain-HTTP account mount (its HTTP edge only redirects to TLS), so the small
/// bridge is repeated here rather than changing product code for a dev tool.
async fn serve_account(
    account: &Arc<AccountRuntime>,
    remote_addr: SocketAddr,
    req: Request<hyper::body::Incoming>,
) -> Response<BoxBody> {
    use tower::ServiceExt as _;

    let router = weaver_server::account::router::router(account.clone(), None);
    let (parts, body) = req.into_parts();
    let mut request = Request::from_parts(parts, axum::body::Body::new(body));
    // The raw edge is the only layer that knows the socket address; the account
    // plane records it on its authentication trail (WVR-167).
    request.extensions_mut().insert(ClientAddr(remote_addr));
    let response = match router.oneshot(request).await {
        Ok(response) => response,
        Err(never) => match never {},
    };
    let (parts, body) = response.into_parts();
    // The SSE stream never ends, so it is bridged frame by frame; everything
    // else is buffered so the boxed body stays `Send + Sync`.
    let is_stream = parts
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/event-stream"));
    if is_stream {
        let (tx, rx) = tokio::sync::mpsc::channel::<weaver_server::tunnel::proxy::BodyFrameItem>(8);
        tokio::spawn(async move {
            let mut body = body;
            while let Some(frame) = body.frame().await {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(e) => {
                        let _ = tx.send(Err(Box::new(e))).await;
                        break;
                    }
                };
                if tx.send(Ok(frame)).await.is_err() {
                    break;
                }
            }
        });
        let mut response = Response::from_parts(
            parts,
            weaver_server::tunnel::proxy::TunnelResponseBody::boxed(rx),
        );
        apply_common_security_headers(&mut response, false);
        return response;
    }
    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return internal_error_response(),
    };
    let mut response = Response::from_parts(parts, full_body(bytes));
    let is_html = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/html"));
    if is_html {
        apply_spa_security_headers(&mut response, false);
    } else {
        apply_common_security_headers(&mut response, false);
    }
    response
}

/// The canned `500` for a response body that failed to buffer.
fn internal_error_response() -> Response<BoxBody> {
    let mut response = Response::builder()
        .status(http::StatusCode::INTERNAL_SERVER_ERROR)
        .body(full_body("500 Internal Server Error\n"))
        .expect("static response");
    apply_common_security_headers(&mut response, false);
    response
}

/// Serves the account router over plain HTTP until the shutdown token fires.
async fn run_plain_http(
    listener: TcpListener,
    account: Arc<AccountRuntime>,
    shutdown: CancellationToken,
) {
    let builder = Builder::new(TokioExecutor::new());
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accept_res = listener.accept() => {
                let (stream, remote_addr) = match accept_res {
                    Ok(pair) => pair,
                    Err(err) => {
                        tracing::debug!(error = %err, "accept error");
                        continue;
                    }
                };
                let account = Arc::clone(&account);
                let builder = builder.clone();
                let conn_token = shutdown.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |req| {
                        let account = Arc::clone(&account);
                        async move {
                            Ok::<_, Infallible>(serve_account(&account, remote_addr, req).await)
                        }
                    });
                    let conn = builder.serve_connection_with_upgrades(io, service);
                    tokio::pin!(conn);
                    tokio::select! {
                        res = conn.as_mut() => {
                            if let Err(err) = res {
                                tracing::debug!(error = %err, "connection error");
                            }
                        }
                        _ = conn_token.cancelled() => {
                            conn.as_mut().graceful_shutdown();
                            let _ = conn.as_mut().await;
                        }
                    }
                });
            }
        }
    }
}

#[tokio::main]
async fn main() {
    // Stdout carries the operator-facing lines (banner + captured mail), so
    // tracing goes to stderr to keep both readable.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .try_init();

    // A temporary SQLite store, dropped with the process.
    let dir = tempfile::tempdir().expect("temp dir");
    let store = Store::open(dir.path().join("sso-dev.db"))
        .await
        .expect("open store");

    let config = sample_config();
    let provider = config
        .account
        .microsoft
        .as_ref()
        .is_some_and(|preset| preset.enabled);

    let altcha = AltchaRuntime::from_config(&config, store.clone()).expect("altcha runtime");
    altcha.ensure_demo_client().await.expect("demo client");

    // Real delivery when a Resend key is present; otherwise the captured mailer
    // that prints to stdout, so the harness still works offline. Either way the
    // mailer identity insists on an absolute HTTPS support link; the link is
    // only a decorative footer here, so a placeholder satisfies it without the
    // harness needing the TLS origin it deliberately does not serve.
    let resend = resend_api_key_from_env();
    let real_delivery = resend.is_some();
    let mailer: Arc<dyn Mailer> = match resend {
        Some(api_key) => resend_mailer(api_key),
        None => Arc::new(StdoutMailer {
            identity: MailerIdentity::new(
                "stdout",
                "Dev capture",
                Mailbox::new("no-reply@localhost"),
                "https://localhost",
                Vec::new(),
            )
            .expect("mailer identity"),
        }),
    };

    let account = AccountRuntime::with_breach(
        &config.account,
        &config.admin_domain,
        store,
        altcha,
        Some(mailer),
        weaver_server::live::LiveHub::new(),
        Arc::new(support::NoBreach),
    )
    .expect("account runtime");

    let listener = TcpListener::bind(LISTEN).await.expect("bind http");
    let shutdown = CancellationToken::new();
    tokio::spawn(run_plain_http(
        listener,
        Arc::clone(&account),
        shutdown.clone(),
    ));

    println!("SSO dev server:     http://{ADMIN_HOST}/app");
    println!("OIDC redirect URI:  http://{ADMIN_HOST}/api/account/sso/microsoft/callback");
    if provider {
        println!("Microsoft provider: configured from the environment");
    } else {
        println!(
            "Microsoft provider: not configured (set WEAVER_SSO_MICROSOFT_AUTHORITY, \
             WEAVER_SSO_MICROSOFT_CLIENT_ID and WEAVER_SSO_MICROSOFT_CLIENT_SECRET to enable it)"
        );
    }
    if real_delivery {
        println!("Email: resend (real delivery)");
    } else {
        println!("Email: captured to stdout");
        println!("(the emailed sign-in code will be printed below when it is issued)");
    }
    std::io::stdout().flush().expect("flush stdout");

    support::wait_for_shutdown().await;
    shutdown.cancel();
}
