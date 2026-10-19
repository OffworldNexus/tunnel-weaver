//! The [`Client`]: everything a command needs, in one place.
//!
//! The CLI builds one with its store, key agent and reporter; tests build one
//! with an in-memory agent. Each command is a method (`pair`, `start`,
//! `unpair`, `relays`, `set_default`), and they share one way to reach a
//! relay: TLS to the admin host, a WebSocket on it, and for tunnels the mux
//! handshake signed by the device key.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use rustls::pki_types::pem::PemObject;
use weaver_mux::auth::Signer;
use weaver_mux::{Config, Connection, StreamId};
use weaver_proto::{ControlHead, Head, encode, policy};
use weaver_tokio::{Driver, StreamHandler, SystemRng, WsTransport};

use crate::error::{BoxError, Error};
use crate::host::AdminHost;
use crate::key::{KeyAgent, KeyError, OpenedKey, Provision, SecurityLevel};
use crate::report::Reporter;
use crate::store::{Relay, Store};

/// The relay's tunnel endpoint, on its admin host.
const CONNECT_PATH: &str = "/_weaver/connect";

/// The WebSocket subprotocol of the tunnel endpoint.
const MUX_SUBPROTOCOL: &str = "weaver-mux-v1";

type Tls = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

/// A WebSocket over TLS to a relay.
pub(crate) type RelaySocket = tokio_tungstenite::WebSocketStream<Tls>;

/// A mux connection to a relay, driven by `H`.
pub(crate) type MuxDriver<H> = Driver<WsTransport<Tls>, H>;

/// The `weave` client.
pub struct Client {
    pub(crate) store: Store,
    agent: Box<dyn KeyAgent>,
    pub(crate) reporter: Arc<dyn Reporter>,
    root_ca: Option<PathBuf>,
}

/// The device key, opened and remembered.
pub(crate) struct DeviceKey {
    pub signer: Box<dyn Signer + Send>,
    pub fingerprint: String,
    pub level: SecurityLevel,
    /// The agent created this key, though another was remembered.
    pub replaced: bool,
}

/// The device key, checked against what a relay authorised.
pub(crate) enum PairedKey {
    /// The key the relay authorised.
    Valid(Box<dyn Signer + Send>),
    /// The relay authorised a key this machine no longer has.
    Lost,
}

impl Client {
    /// A client over `store`, signing through `agent`, reporting to `reporter`.
    pub fn new(store: Store, agent: Box<dyn KeyAgent>, reporter: Arc<dyn Reporter>) -> Self {
        Self {
            store,
            agent,
            reporter,
            root_ca: None,
        }
    }

    /// Trusts only the PEM root certificates in `path` for relay connections,
    /// instead of the platform's (a relay with a private CA).
    pub fn with_root_ca(mut self, path: Option<PathBuf>) -> Self {
        self.root_ca = path;
        self
    }

    /// Every paired relay, the default first.
    pub async fn relays(&self) -> Result<Vec<Relay>, Error> {
        Ok(self.store.relays().await?)
    }

    /// Makes `admin_host` the default relay.
    pub async fn set_default(&self, admin_host: &str) -> Result<Relay, Error> {
        let host = AdminHost::parse(admin_host)?.to_string();
        self.store
            .set_default(&host)
            .await?
            .ok_or(Error::NotPaired(host))
    }

    /// The relay at `admin_host`, or the default one when it is empty.
    pub(crate) async fn paired_relay(&self, admin_host: &str) -> Result<Relay, Error> {
        if admin_host.is_empty() {
            return self.store.default_relay().await?.ok_or(Error::NoRelay);
        }
        let host = AdminHost::parse(admin_host)?.to_string();
        self.store.relay(&host).await?.ok_or(Error::NotPaired(host))
    }

    /// Opens the device key, resuming the remembered one, and remembers what
    /// the agent returned.
    pub(crate) async fn open_key(&self, provision: Provision) -> Result<DeviceKey, Error> {
        self.reporter.opening_key();
        let remembered = self.store.device_key().await?;
        let OpenedKey {
            signer,
            level,
            created,
        } = self
            .agent
            .open(
                remembered.parse().ok(),
                provision,
                Arc::clone(&self.reporter),
            )
            .await?;
        let fingerprint = signer.key_id().to_string();
        if remembered != fingerprint {
            self.store.set_device_key(&fingerprint).await?;
        }
        Ok(DeviceKey {
            signer,
            fingerprint,
            level,
            replaced: created && !remembered.is_empty(),
        })
    }

    /// Opens the device key for a command against `relay`. Any key but the one
    /// the relay authorised (a new one, or none at the floor) means the
    /// pairing is lost.
    pub(crate) async fn open_paired_key(&self, relay: &Relay) -> Result<PairedKey, Error> {
        match self.open_key(Provision::default()).await {
            Ok(key) if key.fingerprint == relay.key_id => Ok(PairedKey::Valid(key.signer)),
            Ok(_) | Err(Error::Key(KeyError::BelowFloor { .. })) => Ok(PairedKey::Lost),
            Err(e) => Err(e),
        }
    }

    /// A WebSocket to `path` on `host`, speaking `subprotocol`.
    pub(crate) async fn dial(
        &self,
        host: &AdminHost,
        path: &str,
        subprotocol: &str,
    ) -> Result<RelaySocket, Error> {
        self.dial_inner(host, path, subprotocol)
            .await
            .map_err(|source| Error::Unreachable {
                host: host.to_string(),
                source,
            })
    }

    async fn dial_inner(
        &self,
        host: &AdminHost,
        path: &str,
        subprotocol: &str,
    ) -> Result<RelaySocket, BoxError> {
        let config = match &self.root_ca {
            Some(path) => {
                let mut roots = rustls::RootCertStore::empty();
                for cert in rustls::pki_types::CertificateDer::pem_file_iter(path)? {
                    roots.add(cert?)?;
                }
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth()
            }
            None => {
                use rustls_platform_verifier::BuilderVerifierExt;
                rustls::ClientConfig::builder()
                    .with_platform_verifier()?
                    .with_no_client_auth()
            }
        };
        let tcp = tokio::net::TcpStream::connect((host.host.as_str(), host.port)).await?;
        weaver_tokio::set_tcp_nodelay(&tcp);
        weaver_tokio::set_tcp_notsent_lowat(&tcp);
        let server_name = rustls::pki_types::ServerName::try_from(host.host.clone())?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(server_name, tcp)
            .await?;

        let request = http::Request::builder()
            .uri(format!("wss://{}:{}{path}", host.host, host.port))
            .header(http::header::HOST, &host.host)
            .header(http::header::CONNECTION, "Upgrade")
            .header(http::header::UPGRADE, "websocket")
            .header(http::header::SEC_WEBSOCKET_VERSION, "13")
            .header(
                http::header::SEC_WEBSOCKET_KEY,
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .header(http::header::SEC_WEBSOCKET_PROTOCOL, subprotocol)
            .body(())?;
        let (ws, _) = tokio_tungstenite::client_async(request, tls).await?;
        Ok(ws)
    }

    /// A mux connection to `host`'s tunnel endpoint, authenticated by `signer`
    /// and driven by `handler`, ready to run.
    pub(crate) async fn mux<H: StreamHandler>(
        &self,
        host: &AdminHost,
        signer: Box<dyn Signer + Send>,
        handler: H,
    ) -> Result<MuxDriver<H>, Error> {
        let ws = self.dial(host, CONNECT_PATH, MUX_SUBPROTOCOL).await?;
        // The host name is the server name the relay's transcript binds.
        let config = Config::client(signer, host.host.clone(), Box::new(SystemRng));
        let conn = Connection::new(config, Instant::now());
        Ok(Driver::new(conn, WsTransport::new(ws), handler))
    }
}

/// Opens a control stream and sends `head` on it.
pub(crate) fn open_control(conn: &mut Connection, head: &ControlHead) -> Result<StreamId, String> {
    let bytes = encode(&Head::Control(head.clone())).map_err(|e| e.to_string())?;
    let id = conn
        .open(policy::CONTROL_CLASS)
        .map_err(|e| format!("could not open a control stream: {e}"))?;
    conn.send(id, &bytes, policy::CONTROL_COMPRESS)
        .map_err(|e| format!("could not send on a control stream: {e}"))?;
    Ok(id)
}
