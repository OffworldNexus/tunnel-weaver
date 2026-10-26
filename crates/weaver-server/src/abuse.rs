//! Server-side safety-middleware wiring for the relay web surface.
//!
//! Builds the [`weaver_abuse::Pipeline`] the edges run — the scanner firewall
//! pass always, plus the budget pass when the operator has armed `abuse` — and
//! maps a [`weaver_abuse::Decision`] onto the response the edge sends.
//!
//! The relay *is* the reverse proxy: the client address is always the socket
//! peer, and forwarding headers are deliberately never read, so spoofing one
//! cannot create a new identity.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use http::{Request, StatusCode};
use weaver_abuse::{
    Budget, BudgetPass, BudgetStore, Charge, Decision, Gate, Key, KeyKind, Pass, Pipeline, Policy,
    PolicyId, PolicySet, Quota, Rate, RequestContext, RouteTable, ScannerPass, StoreError,
    StoreErrorPolicy, Surface, ViewId, fingerprint,
};

use crate::config::{AltchaConfig, BudgetConfig, Config};
use crate::store::Store;

/// The SQLite-backed budget store: typed `Store` methods, one transaction per
/// charge (so a multi-key policy is atomic).
pub struct DbStore {
    store: Store,
}

impl DbStore {
    /// Wrap a [`Store`] as the budget backend.
    ///
    /// Public so benchmarks and tests can drive the store directly; the daemon
    /// builds it via [`build`].
    pub fn new(store: Store) -> Self {
        Self { store }
    }
}

#[async_trait]
impl BudgetStore for DbStore {
    async fn check(
        &self,
        scope: PolicyId,
        key: Key,
        quota: &Quota,
        cost: u32,
        now_ms: i64,
        retry_cap_ms: i64,
    ) -> Result<Charge, StoreError> {
        let charges = self
            .store
            .abuse_check_all(scope, &[(key, *quota)], cost, now_ms, retry_cap_ms)
            .await
            .map_err(|_| StoreError::Unavailable)?;
        charges.into_iter().next().ok_or(StoreError::Unavailable)
    }

    async fn check_all(
        &self,
        scope: PolicyId,
        budgets: &[(Key, Quota)],
        cost: u32,
        now_ms: i64,
        retry_cap_ms: i64,
    ) -> Result<Vec<Charge>, StoreError> {
        self.store
            .abuse_check_all(scope, budgets, cost, now_ms, retry_cap_ms)
            .await
            .map_err(|_| StoreError::Unavailable)
    }
}

/// Build the relay safety pipeline.
///
/// The scanner firewall pass is always present (the WAF is not optional). The
/// budget pass is always present too: the ALTCHA API is always served and always
/// budgeted, while the relay-web budget is opt-in via `abuse.enabled`.
pub fn build(config: &Config, store: Store) -> Arc<Pipeline> {
    let mut passes: Vec<Box<dyn Pass>> = vec![Box::new(ScannerPass::default())];

    let mut policies: Vec<Policy> = Vec::new();
    let mut routes: Vec<(ViewId, PolicyId)> = Vec::new();

    // The relay's own web surface budget is opt-in.
    if let Some(abuse) = config.abuse.as_ref().filter(|abuse| abuse.enabled) {
        policies.push(Policy {
            id: PolicyId::RELAY_WEB,
            budgets: vec![
                Budget {
                    key: KeyKind::PeerHost,
                    quota: quota(&abuse.peer_host),
                },
                Budget {
                    key: KeyKind::PeerNetwork,
                    quota: quota(&abuse.peer_network),
                },
            ],
            // The relay's own web surface favours availability: a broken store
            // is served and logged, never a silent bypass.
            on_store_error: StoreErrorPolicy::Degraded,
        });
        routes.push((ViewId::RELAY_WEB, PolicyId::RELAY_WEB));
    }

    // the ALTCHA API is the relay's own service and is always served, so
    // its budgets are always applied — one per endpoint, both fail-closed, so
    // exhausting challenge issuance cannot spend the verification budget or fall
    // through to unbudgeted work.
    let altcha = config
        .abuse
        .as_ref()
        .and_then(|abuse| abuse.altcha.clone())
        .unwrap_or_else(AltchaConfig::builtin);
    for (policy, view, budget) in [
        (
            PolicyId::ALTCHA_CHALLENGE,
            ViewId::ALTCHA_CHALLENGE,
            &altcha.challenge,
        ),
        (
            PolicyId::ALTCHA_VERIFY,
            ViewId::ALTCHA_VERIFY,
            &altcha.verify,
        ),
    ] {
        policies.push(Policy {
            id: policy,
            budgets: vec![
                Budget {
                    key: KeyKind::PeerHost,
                    quota: quota(budget),
                },
                Budget {
                    key: KeyKind::PeerNetwork,
                    quota: quota(budget),
                },
            ],
            on_store_error: StoreErrorPolicy::FailClosed,
        });
        routes.push((view, policy));
    }

    // the account plane is always served, so its budgets are always
    // applied — one per action, all fail-closed. The per-registration resend
    // cooldown is enforced in the handler; these budgets bound whole networks.
    for (policy, view, budget) in [
        (
            PolicyId::ACCOUNT_SIGNUP,
            ViewId::ACCOUNT_SIGNUP,
            &config.account.signup,
        ),
        (
            PolicyId::ACCOUNT_LOGIN,
            ViewId::ACCOUNT_LOGIN,
            &config.account.login,
        ),
        (
            PolicyId::ACCOUNT_RESEND,
            ViewId::ACCOUNT_RESEND,
            &config.account.resend,
        ),
        (
            PolicyId::ACCOUNT_PAIR,
            ViewId::ACCOUNT_PAIR,
            &config.account.pair,
        ),
    ] {
        policies.push(Policy {
            id: policy,
            budgets: vec![
                Budget {
                    key: KeyKind::PeerHost,
                    quota: quota(budget),
                },
                Budget {
                    key: KeyKind::PeerNetwork,
                    quota: quota(budget),
                },
            ],
            on_store_error: StoreErrorPolicy::FailClosed,
        });
        routes.push((view, policy));
    }

    // the passkey ceremonies are always served too, but they get a budget of
    // their own: a passkey assertion is cryptographic, so there is nothing to
    // guess and the allowance only has to bound unauthenticated work (one
    // sign-in is a handful of requests, and it never shares a bucket with the
    // password login, whose 30-per-10-minutes allowance a page load could
    // spend). It also favours availability where the credentials above fail
    // closed: a budget store that cannot answer serves the ceremony and logs
    // loudly, because what it would have protected is a resource, not a secret.
    policies.push(Policy {
        id: PolicyId::ACCOUNT_PASSKEY,
        budgets: vec![
            Budget {
                key: KeyKind::PeerHost,
                quota: quota(&config.account.passkey),
            },
            Budget {
                key: KeyKind::PeerNetwork,
                quota: quota(&config.account.passkey),
            },
        ],
        on_store_error: StoreErrorPolicy::Degraded,
    });
    routes.push((ViewId::ACCOUNT_PASSKEY, PolicyId::ACCOUNT_PASSKEY));

    let retry_cap_secs = config
        .abuse
        .as_ref()
        .map(|abuse| abuse.retry_after_cap_secs)
        .unwrap_or(600);
    let gate = Gate::new(
        DbStore::new(store),
        PolicySet::new(policies),
        secs_to_ms(retry_cap_secs),
    );
    passes.push(Box::new(BudgetPass::new(gate, RouteTable::new(routes))));

    Arc::new(Pipeline::new(passes))
}

/// Build a [`RequestContext`] for a request on `surface`.
pub fn context<'a, B>(
    surface: Surface,
    req: &'a Request<B>,
    remote_addr: SocketAddr,
    view: ViewId,
    now_ms: i64,
) -> RequestContext<'a> {
    RequestContext {
        surface,
        method: req.method().clone(),
        path: req.uri().path(),
        raw_path: req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or_else(|| req.uri().path()),
        fingerprint: fingerprint(effective_peer(remote_addr)),
        view,
        now_ms,
    }
}

fn quota(cfg: &BudgetConfig) -> Quota {
    Quota {
        burst: cfg.burst,
        refill: Rate {
            units: cfg.refill_units,
            per_ms: secs_to_ms(cfg.refill_per_secs),
        },
    }
}

fn secs_to_ms(secs: u64) -> i64 {
    (secs as i64).saturating_mul(1000).max(1)
}

/// The authoritative client address: always the socket peer.
///
/// Kept as a named function (rather than an inline `.ip()`) to make the
/// invariant obvious: no `Forwarded`/`X-Forwarded-For` parsing exists, so a
/// client cannot influence its identity by spoofing a header.
pub fn effective_peer(remote_addr: SocketAddr) -> IpAddr {
    remote_addr.ip()
}

/// The refusal the edge must surface for a [`Decision`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A firewall rule fired: `403`, `x-weaver-blocked: <verdict>`.
    Blocked {
        /// The firewall verdict token.
        verdict: &'static str,
    },
    /// The budget is exhausted: `429`, `Retry-After`, `x-weaver-throttled`.
    Throttled {
        /// The policy that refused.
        policy: &'static str,
        /// Whole seconds to wait.
        retry_after_secs: u64,
    },
    /// The store failed and the policy fails closed: `503`.
    Unavailable,
}

impl Refusal {
    /// Turn a decision into a refusal, or `None` when the request proceeds.
    pub fn from_decision(decision: Decision) -> Option<Self> {
        Some(match decision {
            Decision::Allow | Decision::Degraded { .. } => return None,
            Decision::Block { verdict } => Self::Blocked {
                verdict: verdict.as_str(),
            },
            Decision::Throttle {
                policy,
                retry_after_ms,
            } => Self::Throttled {
                policy: policy.as_str(),
                retry_after_secs: ms_to_secs_ceil(retry_after_ms),
            },
            Decision::Unavailable { .. } => Self::Unavailable,
        })
    }

    /// The HTTP status code.
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Blocked { .. } => StatusCode::FORBIDDEN,
            Self::Throttled { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// The branded HTML body.
    pub fn body(&self) -> String {
        match self {
            Self::Blocked { verdict } => weaver_assets::render_forbidden(verdict),
            Self::Throttled {
                retry_after_secs, ..
            } => weaver_assets::render_throttled(*retry_after_secs),
            Self::Unavailable => weaver_assets::render_unavailable(),
        }
    }

    /// Apply the reason and `Retry-After` headers.
    pub fn apply<B>(&self, response: &mut http::Response<B>) {
        let headers = response.headers_mut();
        match self {
            Self::Blocked { verdict } => {
                headers.insert("x-weaver-blocked", http::HeaderValue::from_static(verdict));
            }
            Self::Throttled {
                policy,
                retry_after_secs,
            } => {
                headers.insert("x-weaver-throttled", http::HeaderValue::from_static(policy));
                if let Ok(value) = http::HeaderValue::from_str(&retry_after_secs.to_string()) {
                    headers.insert(http::header::RETRY_AFTER, value);
                }
            }
            Self::Unavailable => {}
        }
    }
}

fn ms_to_secs_ceil(ms: i64) -> u64 {
    (ms.max(1) as u64).div_ceil(1000)
}
