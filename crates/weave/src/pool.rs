//! Per-target origin connection pool for `weave start`.
//!
//! Every visitor request becomes one outbound HTTP request to the service's
//! target. Opening a fresh TCP+TLS connection per request would make the
//! tunnel useless for anything chatty, so this module keeps a small idle
//! pool per target and reuses keep-alive connections.
//!
//! It talks to origins with hyper's low-level client connection API rather
//! than the pooled high-level client, because the proxy must preserve
//! trailers, interim responses and upgrade semantics that the high-level
//! client normalizes away. HTTP/1.1 is used for `http://` targets (never
//! h2c); `https://` targets negotiate h1 or h2 by ALPN.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use hyper::client::conn::http1;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;

use crate::proxy::{Body, BoxError};
use crate::target::{Target, TargetScheme};

/// How long to wait for the TCP/TLS connection to a target before giving
/// up with a 502. There is deliberately no timeout on the origin's response
/// itself (see ADR 0006).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum idle connections kept per target.
const MAX_IDLE_PER_TARGET: usize = 8;

/// The framing-negotiated connection to one origin.
pub enum OriginConn {
    /// An HTTP/1.1 connection (http targets, or https with h1 ALPN).
    Http1(http1::SendRequest<Body>),
    /// An HTTP/2 connection (https targets that negotiated h2).
    Http2(http2::SendRequest<Body>),
}

impl OriginConn {
    /// Whether the underlying connection task is still running. A pooled
    /// connection the origin has since closed reports `false`.
    fn is_alive(&self) -> bool {
        match self {
            Self::Http1(send) => !send.is_closed(),
            Self::Http2(send) => !send.is_closed(),
        }
    }
}

/// Identity of a pool bucket: the target plus whether its TLS is verified.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    scheme: TargetScheme,
    host: String,
    port: u16,
    insecure: bool,
}

impl PoolKey {
    fn new(target: &Target, insecure: bool) -> Self {
        Self {
            scheme: target.scheme,
            host: target.host.clone(),
            port: target.port,
            insecure,
        }
    }
}

/// A small keep-alive pool of origin connections, keyed by target.
#[derive(Clone)]
pub struct Pool {
    idle: Arc<Mutex<HashMap<PoolKey, Vec<OriginConn>>>>,
}

impl Default for Pool {
    fn default() -> Self {
        Self::new()
    }
}

impl Pool {
    /// An empty pool.
    pub fn new() -> Self {
        Self {
            idle: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Take a usable connection to `target`, opening one if the pool is
    /// empty. `insecure` disables certificate verification for this target.
    pub async fn acquire(&self, target: &Target, insecure: bool) -> Result<OriginConn, BoxError> {
        let key = PoolKey::new(target, insecure);
        // An idle keep-alive connection may have been closed by the origin
        // since it was pooled (`Connection: close`, idle timeout). Skip any
        // that hyper reports as gone rather than 502-ing the request.
        loop {
            let idle = self.idle.lock().await.get_mut(&key).and_then(Vec::pop);
            match idle {
                Some(conn) if conn.is_alive() => return Ok(conn),
                Some(_) => continue,
                None => break,
            }
        }
        self.connect(target, insecure).await
    }

    /// Return a connection to the pool. The caller must only release a
    /// connection that completed its exchange cleanly (keep-alive intact).
    pub async fn release(&self, target: &Target, insecure: bool, conn: OriginConn) {
        let key = PoolKey::new(target, insecure);
        let mut idle = self.idle.lock().await;
        let bucket = idle.entry(key).or_default();
        if bucket.len() < MAX_IDLE_PER_TARGET {
            bucket.push(conn);
        }
    }

    async fn connect(&self, target: &Target, insecure: bool) -> Result<OriginConn, BoxError> {
        let tcp = tokio::time::timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect((target.host.as_str(), target.port)),
        )
        .await
        .map_err(|_| format!("connection to {} timed out", target.origin()))??;
        weaver_tokio::set_tcp_nodelay(&tcp);
        weaver_tokio::set_tcp_notsent_lowat(&tcp);

        match target.scheme {
            TargetScheme::Http => {
                // Plaintext is always HTTP/1.1; h2c is never used.
                let (send, conn) = http1::handshake(TokioIo::new(tcp)).await?;
                spawn_http1(conn);
                Ok(OriginConn::Http1(send))
            }
            TargetScheme::Https => {
                let tls = tls_connect(target, tcp, insecure).await?;
                let negotiated_h2 = tls.get_ref().1.alpn_protocol().is_some_and(|p| p == b"h2");
                if negotiated_h2 {
                    let (send, conn) =
                        http2::handshake(TokioExecutor::new(), TokioIo::new(tls)).await?;
                    spawn_http2(conn);
                    Ok(OriginConn::Http2(send))
                } else {
                    let (send, conn) = http1::handshake(TokioIo::new(tls)).await?;
                    spawn_http1(conn);
                    Ok(OriginConn::Http1(send))
                }
            }
        }
    }
}

fn spawn_http1<T>(conn: http1::Connection<T, Body>)
where
    T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
}

fn spawn_http2<T>(conn: http2::Connection<T, Body, TokioExecutor>)
where
    T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let _ = conn.await;
    });
}

async fn tls_connect(
    target: &Target,
    tcp: TcpStream,
    insecure: bool,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, BoxError> {
    let mut config = if insecure {
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AllowAllVerifier))
            .with_no_client_auth()
    } else {
        use rustls_platform_verifier::BuilderVerifierExt;
        ClientConfig::builder()
            .with_platform_verifier()?
            .with_no_client_auth()
    };
    // Offer h2 first; fall back to http/1.1. Never offer h2c.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(target.host.clone())?;
    Ok(connector.connect(server_name, tcp).await?)
}

/// Certificate verifier used for `--insecure-target`: accepts anything.
/// Only ever installed for targets the user explicitly opted out of
/// verification for.
#[derive(Debug)]
struct AllowAllVerifier;

impl ServerCertVerifier for AllowAllVerifier {
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
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
