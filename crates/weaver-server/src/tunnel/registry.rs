//! In-memory tunnel service registry mapping hostnames to active connections.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use tokio::sync::{mpsc, oneshot};
use tracing::info;
use weaver_mux::KeyId;
use weaver_proto::control::RefusalCode;
use weaver_proto::is_valid_dns_label;
use weaver_proto::poc::{derive_hostname, poc_identity};

use crate::cert::CertManager;
use crate::tunnel::proxy::ProxyRequest;

/// Route information for a registered tunnel service.
#[derive(Clone)]
pub struct TunnelRoute {
    /// Fully-qualified hostname (e.g. "web.laptop.poc.example.com").
    pub hostname: String,
    /// Registered service name (e.g. "web").
    pub service: String,
    /// Authenticated public key ID of the tunnel client.
    pub key_id: KeyId,
    /// Channel for forwarding visitor proxy requests to this tunnel connection.
    pub proxy_tx: mpsc::Sender<ProxyRequest>,
}

struct ActiveConnection {
    connection_id: u64,
    superseded_tx: Option<oneshot::Sender<()>>,
    services: HashSet<String>,
}

/// Registry managing active tunnel connections and registered services.
pub struct TunnelRegistry {
    root_domain: String,
    cert_manager: Arc<CertManager>,
    routes: RwLock<HashMap<String, TunnelRoute>>,
    connections: Mutex<HashMap<KeyId, ActiveConnection>>,
    next_conn_id: AtomicU64,
}

impl TunnelRegistry {
    /// Creates a new in-memory registry tied to the given root domain and certificate manager.
    pub fn new(root_domain: String, cert_manager: Arc<CertManager>) -> Self {
        Self {
            root_domain,
            cert_manager,
            routes: RwLock::new(HashMap::new()),
            connections: Mutex::new(HashMap::new()),
            next_conn_id: AtomicU64::new(1),
        }
    }

    /// Registers a newly authenticated tunnel connection.
    ///
    /// If an existing connection with the same `KeyId` is currently active, it is
    /// marked as superseded and its registered services are evicted immediately.
    pub fn register_connection(&self, key_id: KeyId, superseded_tx: oneshot::Sender<()>) -> u64 {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let mut conns = self.connections.lock().unwrap();

        if let Some(old_conn) = conns.insert(
            key_id,
            ActiveConnection {
                connection_id: conn_id,
                superseded_tx: Some(superseded_tx),
                services: HashSet::new(),
            },
        ) {
            info!(?key_id, "Tunnel connection superseded by newer connection");
            if let Some(tx) = old_conn.superseded_tx {
                let _ = tx.send(());
            }
            let mut routes = self.routes.write().unwrap();
            for hostname in old_conn.services {
                routes.remove(&hostname);
                self.cert_manager.set_active(&hostname, false);
                info!(%hostname, "Evicted service from superseded connection");
            }
        }

        conn_id
    }

    /// Unregisters a connection if it matches the current `connection_id`, evicting its services.
    pub fn unregister_connection(&self, key_id: KeyId, connection_id: u64) {
        let mut conns = self.connections.lock().unwrap();
        if let Some(entry) = conns.get(&key_id)
            && entry.connection_id == connection_id
        {
            let old_conn = conns.remove(&key_id).unwrap();
            let mut routes = self.routes.write().unwrap();
            for hostname in old_conn.services {
                routes.remove(&hostname);
                self.cert_manager.set_active(&hostname, false);
                info!(%hostname, "Unregistered service on connection close");
            }
        }
    }

    /// Registers a service on an active connection.
    ///
    /// Validates the service name, verifies the caller identity, checks for duplicates,
    /// activates the certificate in `CertManager`, and updates routing tables.
    pub async fn register_service(
        &self,
        key_id: KeyId,
        connection_id: u64,
        service: &str,
        proxy_tx: mpsc::Sender<ProxyRequest>,
    ) -> Result<String, RefusalCode> {
        if !is_valid_dns_label(service) {
            return Err(RefusalCode::InvalidName);
        }

        let Some((person, machine)) = poc_identity(&key_id) else {
            return Err(RefusalCode::Unauthorized);
        };

        let hostname = derive_hostname(service, machine, person, &self.root_domain);
        let host_lower = hostname.to_ascii_lowercase();

        {
            let routes = self.routes.read().unwrap();
            if routes.contains_key(&host_lower) {
                return Err(RefusalCode::AlreadyRegistered);
            }
        }

        {
            let mut routes = self.routes.write().unwrap();
            if routes.contains_key(&host_lower) {
                return Err(RefusalCode::AlreadyRegistered);
            }
            routes.insert(
                host_lower.clone(),
                TunnelRoute {
                    hostname: host_lower.clone(),
                    service: service.to_string(),
                    key_id,
                    proxy_tx,
                },
            );
        }

        {
            let mut conns = self.connections.lock().unwrap();
            if let Some(conn) = conns.get_mut(&key_id)
                && conn.connection_id == connection_id
            {
                conn.services.insert(host_lower.clone());
            }
        }

        // Trigger certificate issuance and mark active in renewal manager
        let _ = self.cert_manager.ensure(&host_lower).await;
        self.cert_manager.set_active(&host_lower, true);
        info!(hostname = %host_lower, "Tunnel service registered");

        Ok(host_lower)
    }

    /// Unregisters an individual service hostname.
    pub fn unregister_service(&self, key_id: KeyId, hostname: &str) {
        let lower = hostname.to_ascii_lowercase();
        let mut routes = self.routes.write().unwrap();
        if let Some(route) = routes.get(&lower)
            && route.key_id == key_id
        {
            routes.remove(&lower);
            self.cert_manager.set_active(&lower, false);
            info!(hostname = %lower, "Tunnel service unregistered");

            let mut conns = self.connections.lock().unwrap();
            if let Some(conn) = conns.get_mut(&key_id) {
                conn.services.remove(&lower);
            }
        }
    }

    /// Looks up an active tunnel route by hostname.
    pub fn lookup(&self, hostname: &str) -> Option<TunnelRoute> {
        let lower = hostname.to_ascii_lowercase();
        let routes = self.routes.read().unwrap();
        routes.get(&lower).cloned()
    }
}
