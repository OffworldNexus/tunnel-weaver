//! TCP and TLS connection helpers for the weave client.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use tokio_rustls::TlsConnector;

/// Sets the TCP_NOTSENT_LOWAT socket option to ~32 KiB on Linux and Apple systems.
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "android"
))]
pub fn set_tcp_notsent_lowat(stream: &tokio::net::TcpStream) {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let val: libc::c_uint = 32768;
    unsafe {
        #[cfg(target_os = "linux")]
        let _ = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NOTSENT_LOWAT,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        );
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        let _ = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            0x201,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        );
    }
}

/// No-op on platforms without TCP_NOTSENT_LOWAT.
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "android"
)))]
pub fn set_tcp_notsent_lowat(_stream: &tokio::net::TcpStream) {}

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
