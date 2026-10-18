//! TCP and TLS connection helpers for the weave client.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use tokio_rustls::TlsConnector;

pub use weaver_tokio::{set_tcp_nodelay, set_tcp_notsent_lowat};

/// Parses a server string in the format `<host>` or `<host>:<port>`, defaulting to port 443.
pub fn parse_server_address(raw: &str) -> Result<(String, u16), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Server address cannot be empty".to_string());
    }
    if trimmed.starts_with('[')
        && let Some(close) = trimmed.find(']')
    {
        let host = &trimmed[1..close];
        let rest = &trimmed[close + 1..];
        if let Some(port_str) = rest.strip_prefix(':') {
            let port: u16 = port_str
                .parse()
                .map_err(|e| format!("Invalid port in server address: {e}"))?;
            return Ok((host.to_string(), port));
        } else {
            return Ok((host.to_string(), 443));
        }
    }
    if let Some((host, port_str)) = trimmed.split_once(':') {
        let port: u16 = port_str
            .parse()
            .map_err(|e| format!("Invalid port in server address: {e}"))?;
        Ok((host.to_string(), port))
    } else {
        Ok((trimmed.to_string(), 443))
    }
}

/// Establishes a TLS connection to `<host>:<port>` using either custom CA PEM or OS trust store.
pub async fn connect_tls(
    host: &str,
    port: u16,
    insecure_root_ca: Option<&Path>,
) -> Result<
    tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    let tcp = tokio::net::TcpStream::connect((host, port)).await?;
    set_tcp_nodelay(&tcp);
    set_tcp_notsent_lowat(&tcp);

    let client_config = if let Some(ca_path) = insecure_root_ca {
        let pem_bytes = tokio::fs::read(ca_path).await?;
        let mut root_store = rustls::RootCertStore::empty();
        for cert in rustls::pki_types::CertificateDer::pem_slice_iter(&pem_bytes) {
            root_store.add(cert?)?;
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else {
        use rustls_platform_verifier::BuilderVerifierExt;
        rustls::ClientConfig::builder()
            .with_platform_verifier()?
            .with_no_client_auth()
    };

    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())?;
    let tls_stream = connector.connect(server_name, tcp).await?;
    Ok(tls_stream)
}

/// A WebSocket over TLS to a relay.
pub type RelaySocket =
    tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

/// Opens a WebSocket to `path` on a relay's admin host with `subprotocol`.
///
/// `admin_host` is normalised first, and the normalised host — what the relay
/// compares against — is returned alongside the socket, for use as the mux
/// server name. The same value is the SNI name and the `Host` header.
pub async fn dial_relay(
    admin_host: &str,
    path: &str,
    subprotocol: &str,
    insecure_root_ca: Option<&Path>,
) -> Result<(RelaySocket, String), Box<dyn std::error::Error + Send + Sync>> {
    let normalized = crate::host::normalize_admin_host(admin_host)?;
    let (host, port) = parse_server_address(&normalized)?;
    let tls_stream = connect_tls(&host, port, insecure_root_ca).await?;
    let authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    let req = http::Request::builder()
        .method("GET")
        .uri(format!("wss://{authority}:{port}{path}"))
        .header(http::header::HOST, &host)
        .header(http::header::CONNECTION, "Upgrade")
        .header(http::header::UPGRADE, "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tokio_tungstenite::tungstenite::handshake::client::generate_key(),
        )
        .header("Sec-WebSocket-Protocol", subprotocol)
        .body(())?;
    let (ws, _resp) = tokio_tungstenite::client_async_with_config(req, tls_stream, None).await?;
    Ok((ws, host))
}
