//! In-memory tunnel service registry mapping hostnames to active connections.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use tokio::sync::{mpsc, oneshot};
use tracing::info;
use weaver_mux::{CloseCode, KeyId};
use weaver_proto::control::RefusalCode;

use crate::cert::CertManager;
use crate::live::{Change, Entity, LiveHub, Viewer};
use crate::metering::MeteringManager;
use crate::store::Store;
use crate::tunnel::identity::{Identity, StoreIdentityResolver};
use crate::tunnel::proxy::ProxyRequest;

/// Route information for a registered tunnel service.
#[derive(Clone)]
pub struct TunnelRoute {
    /// Fully-qualified hostname (e.g. "poc-laptop-web.example.com").
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
    /// How the relay asks this connection to end itself. The driver task on the
    /// other end sends a GOAWAY with whatever [`CloseCode`] it receives here,
    /// so a supersede, a web-side disconnect and a web-side revoke each close
    /// the live tunnel without the client having to ask. `None` once taken.
    close_tx: Option<oneshot::Sender<CloseCode>>,
    services: HashSet<String>,
}

/// Registry managing active tunnel connections and registered services.
pub struct TunnelRegistry {
    tunnel_domain: String,
    cert_manager: Arc<CertManager>,
    identities: Arc<StoreIdentityResolver>,
    store: Store,
    metering: Arc<MeteringManager>,
    /// The console's change bus. Every presence or route transition here is a
    /// change to the owning person's view, so each announces the person; a relay
    /// whose console is closed has no subscriber and pays nothing.
    live: LiveHub,
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
        identities: Arc<StoreIdentityResolver>,
        store: Store,
        metering: Arc<MeteringManager>,
        live: LiveHub,
    ) -> Self {
        Self {
            tunnel_domain,
            cert_manager,
            identities,
            store,
            metering,
            live,
            routes: RwLock::new(HashMap::new()),
            connections: Mutex::new(HashMap::new()),
            active_hosts: RwLock::new(HashSet::new()),
            next_conn_id: AtomicU64::new(1),
        }
    }

    /// Tells the person behind `key_id` that their machine's live state may have
    /// changed.
    ///
    /// Best-effort and detached: a transition never waits on a console, and a
    /// key with no resolvable machine (a revoke that already deleted the row)
    /// simply has nobody to tell. The change names the machine by id, so only a
    /// view that showed it (or every machine, for a set change) re-reads.
    fn announce_machine(&self, key_id: KeyId) {
        let identities = Arc::clone(&self.identities);
        let live = self.live.clone();
        tokio::spawn(async move {
            if let Some(identity) = identities.identity(&key_id).await {
                live.publish(
                    Change::visible_to(Viewer::Person(identity.person_id))
                        .entity(Entity::Machine)
                        .id(identity.machine_id),
                );
            }
        });
    }

    /// Announces that a service's state changed on `identity`'s machine: the
    /// machine itself (its service set and its own row) and the tunnel, each by
    /// id.
    fn announce_service(&self, identity: &Identity, service_id: i32) {
        let viewer = Viewer::Person(identity.person_id);
        self.live.publish(
            Change::visible_to(viewer)
                .entity(Entity::Machine)
                .id(identity.machine_id),
        );
        self.live.publish(
            Change::visible_to(viewer)
                .entity(Entity::Tunnel)
                .id(service_id),
        );
    }

    /// The same, when only the key is at hand: resolves the identity off the
    /// hot path.
    fn announce_service_by_key(&self, key_id: KeyId, service_id: i32) {
        let identities = Arc::clone(&self.identities);
        let live = self.live.clone();
        tokio::spawn(async move {
            if let Some(identity) = identities.identity(&key_id).await {
                let viewer = Viewer::Person(identity.person_id);
                live.publish(
                    Change::visible_to(viewer)
                        .entity(Entity::Machine)
                        .id(identity.machine_id),
                );
                live.publish(
                    Change::visible_to(viewer)
                        .entity(Entity::Tunnel)
                        .id(service_id),
                );
            }
        });
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
        let active_at = active.then(crate::wall_clock::unix_secs);
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
    ///
    /// `close_tx` is how the relay later ends this connection — a supersede, a
    /// web-side disconnect or a web-side revoke. The driver task on the other
    /// end sends it a [`CloseCode`] and closes the tunnel with it, so an
    /// operator can drop a live tunnel without the client asking.
    pub fn register_connection(&self, key_id: KeyId, close_tx: oneshot::Sender<CloseCode>) -> u64 {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let mut conns = self.connections.lock().unwrap();

        if let Some(old_conn) = conns.insert(
            key_id,
            ActiveConnection {
                connection_id: conn_id,
                close_tx: Some(close_tx),
                services: HashSet::new(),
            },
        ) {
            info!(?key_id, "Tunnel connection superseded by newer connection");
            if let Some(tx) = old_conn.close_tx {
                let _ = tx.send(CloseCode::Superseded);
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

        drop(conns);
        self.announce_machine(key_id);
        conn_id
    }

    /// Whether `key_id` currently holds a live tunnel connection.
    ///
    /// The account plane's only source of "online"; the state is never
    /// persisted, so it can never disagree with the connections that exist.
    pub fn is_connected(&self, key_id: &KeyId) -> bool {
        self.connections.lock().unwrap().contains_key(key_id)
    }

    /// Asks the live connection holding `key_id` to close with `code`.
    ///
    /// The web-side counterpart of the client-driven revoke:
    /// [`CloseCode::Rejected`](weaver_mux::CloseCode::Rejected) drops a tunnel
    /// on a web-side **disconnect** (the key stays; the client exits and the
    /// machine must be restarted with `weave start`), and
    /// [`CloseCode::KeyRevoked`](weaver_mux::CloseCode::KeyRevoked) on a
    /// **revoke**. The close itself runs in the connection's driver loop, whose
    /// `Closed` event evicts the connection's routes. Returns `true` iff a live
    /// connection was signalled; an unknown or already-closing key is a no-op.
    pub fn close_connection(&self, key_id: &KeyId, code: CloseCode) -> bool {
        let mut conns = self.connections.lock().unwrap();
        match conns.get_mut(key_id).and_then(|conn| conn.close_tx.take()) {
            Some(tx) => tx.send(code).is_ok(),
            None => false,
        }
    }

    /// Re-derives the live route hostnames of `key_id` after its machine was
    /// renamed, mirroring the change to `active_hosts` and the connection's
    /// service set.
    ///
    /// The caller renames the machine and its `domains` rows in the store
    /// first; this then re-resolves the identity (which reports the new machine
    /// name) and remaps every route the connection owns to the hostname that
    /// name derives. The old hostnames stop routing at once, so they stop
    /// serving without waiting for a reconnect. Returns the number of routes
    /// remapped (`0` when the machine is offline — the `domains` rows already
    /// carry the new names for whenever it reconnects).
    pub async fn rename_machine(&self, key_id: &KeyId) -> usize {
        let Some(identity) = self.identities.identity(key_id).await else {
            return 0;
        };
        // Remap under the routes lock, then release it before touching the
        // connections lock: `register_connection` takes them in the opposite
        // order, so the two must never be held at once.
        let (remapped, live) = {
            let mut routes = self.routes.write().unwrap();
            let old_hosts: Vec<String> = routes
                .iter()
                .filter(|(_, route)| route.key_id == *key_id)
                .map(|(host, _)| host.clone())
                .collect();
            let mut remapped = 0;
            for old in old_hosts {
                let Some(mut route) = routes.remove(&old) else {
                    continue;
                };
                let new = identity.hostname(&route.service, &self.tunnel_domain);
                if new != old {
                    let was_active = self.is_active(&old);
                    self.set_active(&old, false);
                    self.set_active(&new, was_active);
                }
                route.hostname = new.clone();
                info!(%old, %new, "Remapped tunnel route after rename");
                routes.insert(new, route);
                remapped += 1;
            }
            let live: HashSet<String> = routes
                .iter()
                .filter(|(_, route)| route.key_id == *key_id)
                .map(|(host, _)| host.clone())
                .collect();
            (remapped, live)
        };
        if let Some(conn) = self.connections.lock().unwrap().get_mut(key_id) {
            conn.services = live;
        }
        // The caller (the account plane's rename handler) announces the change.
        remapped
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
        self.announce_machine(key_id);
    }

    /// The certificate manager this registry activates hostnames on.
    pub fn cert_manager(&self) -> Arc<CertManager> {
        Arc::clone(&self.cert_manager)
    }

    /// Registers a service on an active connection.
    ///
    /// Verifies the caller identity, checks for duplicates, persists the
    /// service, updates the routing tables and waits (bounded) for the
    /// certificate.
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

        let host_lower = identity.hostname(service, &self.tunnel_domain);

        // Refuse duplicates before touching the database: a rejected
        // registration must not leave `service`/`domain` rows behind.
        {
            let routes = self.routes.read().unwrap();
            if routes.contains_key(&host_lower) {
                return Err(RefusalCode::AlreadyRegistered);
            }
        }

        // Persist the declared service under the authenticated machine and
        // link the hostname to it. The returned id is what the meter
        // attributes traffic and open time to.
        let persisted = self
            .store
            .register_declared_service(identity.machine_id, &host_lower, service)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, hostname = %host_lower, "Failed to persist declared service");
                RefusalCode::Other
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
        self.announce_service(&identity, persisted.id);

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
            self.announce_service_by_key(key_id, service_id);
        }
    }

    /// The identity resolver, shared with the mux `Verifier`.
    pub fn identities(&self) -> Arc<StoreIdentityResolver> {
        Arc::clone(&self.identities)
    }

    /// Resolves an incoming `Host` to its live tunnel.
    ///
    /// The materialized `domains` table is the source of truth for
    /// `hostname -> service_id`; the in-memory map
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
