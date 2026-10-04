//! In-memory tunnel service registry mapping hostnames to active connections.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use tokio::sync::{mpsc, oneshot};
use tracing::info;
use weaver_mux::KeyId;
use weaver_proto::control::RefusalCode;

use crate::cert::CertManager;
use crate::metering::MeteringManager;
use crate::store::Store;
use crate::tunnel::identity::{IdentityResolver, derive_hostname};
use crate::tunnel::proxy::ProxyRequest;

/// Current Unix time, for `last_active_at` stamps.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Route information for a registered tunnel service.
#[derive(Clone)]
pub struct TunnelRoute {
    /// Fully-qualified hostname (e.g. "web.laptop.poc.example.com").
    pub hostname: String,
    /// Registered service name (e.g. "web").
    pub service: String,
    /// Persisted `service.id` this route meters usage under.
    pub service_id: i32,
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
    tunnel_domain: String,
    cert_manager: Arc<CertManager>,
    identities: Arc<dyn IdentityResolver>,
    store: Store,
    metering: Arc<MeteringManager>,
    routes: RwLock<HashMap<String, TunnelRoute>>,
    connections: Mutex<HashMap<KeyId, ActiveConnection>>,
    /// Hostnames with a live route (and the admin host once visited). Owned by
    /// the registry, which is the component that knows what is live; mirrored
    /// to `domains.last_active_at` for persistence.
    active_hosts: RwLock<HashSet<String>>,
    next_conn_id: AtomicU64,
}

impl TunnelRegistry {
    /// Creates a new in-memory registry tied to the given root domain and certificate manager.
    pub fn new(
        tunnel_domain: String,
        cert_manager: Arc<CertManager>,
        identities: Arc<dyn IdentityResolver>,
        store: Store,
        metering: Arc<MeteringManager>,
    ) -> Self {
        Self {
            tunnel_domain,
            cert_manager,
            identities,
            store,
            metering,
            routes: RwLock::new(HashMap::new()),
            connections: Mutex::new(HashMap::new()),
            active_hosts: RwLock::new(HashSet::new()),
            next_conn_id: AtomicU64::new(1),
        }
    }

    /// Access to the underlying state store.
    pub fn store(&self) -> Store {
        self.store.clone()
    }

    /// Marks a hostname active or inactive, mirroring to `domains.last_active_at`.
    ///
    /// The tunnel registry owns domain activity — it is the component that knows
    /// which hostnames are live. The certificate manager and the control surface
    /// only read the flag back.
    pub fn set_active(&self, name: &str, active: bool) {
        let lower = name.to_ascii_lowercase();
        if active {
            self.active_hosts.write().unwrap().insert(lower.clone());
        } else {
            self.active_hosts.write().unwrap().remove(&lower);
        }
        let store = self.store.clone();
        let active_at = active.then(now_unix);
        tokio::spawn(async move {
            if let Err(err) = store.set_domain_active(&lower, active_at).await {
                tracing::warn!(hostname = %lower, error = %err, "Failed to persist domain active flag");
            }
        });
    }

    /// Whether `name` currently has a live route.
    pub fn is_active(&self, name: &str) -> bool {
        self.active_hosts
            .read()
            .unwrap()
            .contains(&name.to_ascii_lowercase())
    }

    /// The metering manager routes and the relay report traffic to.
    pub fn metering(&self) -> Arc<MeteringManager> {
        Arc::clone(&self.metering)
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
                if let Some(route) = routes.remove(&hostname) {
                    self.metering.unregister_service(route.service_id);
                }
                self.set_active(&hostname, false);
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
                if let Some(route) = routes.remove(&hostname) {
                    self.metering.unregister_service(route.service_id);
                }
                self.set_active(&hostname, false);
                info!(%hostname, "Unregistered service on connection close");
            }
        }
    }

    /// Registers a service on an active connection.
    ///
    /// Verifies the caller identity, checks for duplicates (the service name
    /// was validated by `ControlHead::validate` on receipt),
    /// activates the certificate in `CertManager`, and updates routing tables.
    /// The certificate manager this registry activates hostnames on.
    pub fn cert_manager(&self) -> Arc<CertManager> {
        Arc::clone(&self.cert_manager)
    }

    pub async fn register_service(
        &self,
        key_id: KeyId,
        connection_id: u64,
        service: &str,
        proxy_tx: mpsc::Sender<ProxyRequest>,
    ) -> Result<String, RefusalCode> {
        let Some(identity) = self.identities.identity(&key_id).await else {
            return Err(RefusalCode::Unauthorized);
        };

        let host_lower = derive_hostname(service, &identity, &self.tunnel_domain);

        // Refuse duplicates before touching the database: a rejected
        // registration must not leave `service`/`domain` rows behind.
        {
            let routes = self.routes.read().unwrap();
            if routes.contains_key(&host_lower) {
                return Err(RefusalCode::AlreadyRegistered);
            }
        }

        // Persist the declared service under the authenticated machine and
        // link the hostname to it. The person and machine must already exist:
        // this call never enrols an identity. The returned id is what the
        // meter attributes traffic and open time to.
        let persisted = self
            .store
            .register_declared_service(&key_id, &host_lower, service)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, hostname = %host_lower, "Failed to persist declared service");
                RefusalCode::Other("failed to persist declared service".into())
            })?;

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
                    service_id: persisted.id,
                    key_id,
                    proxy_tx,
                },
            );
        }
        self.metering.register_service(persisted.id);

        // The route exists, so the hostname is active for the whole (bounded)
        // certificate wait. The post-order recompute below corrects it if the
        // tunnel leaves while the order is in flight.
        self.set_active(&host_lower, true);

        {
            let mut conns = self.connections.lock().unwrap();
            if let Some(conn) = conns.get_mut(&key_id)
                && conn.connection_id == connection_id
            {
                conn.services.insert(host_lower.clone());
            }
        }

        // Trigger certificate issuance. The wildcard covers every hostname, so
        // `ensure` resolves to the apex and waits (bounded) for it to be valid.
        // The covering certificate is resolved at run time by the certificate
        // registry; the domain is not linked to a certificate row.
        let _ = self.cert_manager.ensure(&host_lower).await;
        let still_routed = {
            // Held across `set_active` so an unregister cannot slip in
            // between the check and the flag (it takes the same lock
            // first, in the same order).
            let routes = self.routes.read().unwrap();
            let routed = routes
                .get(&host_lower)
                .is_some_and(|route| route.key_id == key_id);
            self.set_active(&host_lower, routed);
            routed
        };
        if still_routed {
            info!(hostname = %host_lower, "Tunnel service registered");
        } else {
            info!(hostname = %host_lower, "Tunnel service left during certificate issuance");
        }

        Ok(host_lower)
    }

    /// Unregisters an individual service hostname.
    pub fn unregister_service(&self, key_id: KeyId, hostname: &str) {
        let lower = hostname.to_ascii_lowercase();
        let mut routes = self.routes.write().unwrap();
        if let Some(route) = routes.get(&lower)
            && route.key_id == key_id
        {
            let service_id = route.service_id;
            routes.remove(&lower);
            self.metering.unregister_service(service_id);
            self.set_active(&lower, false);
            info!(hostname = %lower, "Tunnel service unregistered");

            let mut conns = self.connections.lock().unwrap();
            if let Some(conn) = conns.get_mut(&key_id) {
                conn.services.remove(&lower);
            }
        }
    }

    /// Looks up an active tunnel route by hostname.
    /// The identity resolver, shared with the mux `Verifier`.
    pub fn identities(&self) -> Arc<dyn IdentityResolver> {
        Arc::clone(&self.identities)
    }

    /// Resolves an incoming `Host` to its live tunnel.
    ///
    /// The materialized `domains` table is the source of truth for
    /// `hostname -> service_id` (the "one join" of OFF-190); the in-memory map
    /// only supplies the process-local `proxy_tx` channel, which cannot be a DB
    /// row. A domain with no live route, or a route whose `service_id` does not
    /// match the database, resolves to `None`.
    pub async fn resolve(&self, hostname: &str) -> Option<TunnelRoute> {
        let lower = hostname.to_ascii_lowercase();
        let domain = self.store.get_domain(&lower).await.ok().flatten()?;
        let service_id = domain.service_id?;
        let routes = self.routes.read().unwrap();
        routes
            .get(&lower)
            .filter(|route| route.service_id == service_id)
            .cloned()
    }
}
