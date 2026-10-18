//! Policies: the budgets a request is charged against, the views that select
//! them, and how store failures count.

use crate::context::RequestContext;
use crate::gcra::Quota;
use crate::key::KeyKind;

/// A stable identifier for a policy.
///
/// It doubles as the store's scope (so two policies never share a bucket) and as
/// the reason code surfaced in logs and the `x-weaver-throttled` response
/// header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PolicyId(&'static str);

impl PolicyId {
    /// The relay's own web surface (`admin`, tunnel apex, cleartext edge).
    pub const RELAY_WEB: PolicyId = PolicyId("relay-web");

    /// The ALTCHA API's challenge-issuance endpoint.
    pub const ALTCHA_CHALLENGE: PolicyId = PolicyId("altcha-challenge");

    /// The ALTCHA API's solution-verification endpoint.
    pub const ALTCHA_VERIFY: PolicyId = PolicyId("altcha-verify");

    /// Starting an email signup (admin host account plane).
    pub const ACCOUNT_SIGNUP: PolicyId = PolicyId("account-signup");

    /// A credential login attempt (admin host account plane).
    pub const ACCOUNT_LOGIN: PolicyId = PolicyId("account-login");

    /// Resending a verification link (admin host account plane).
    pub const ACCOUNT_RESEND: PolicyId = PolicyId("account-resend");

    /// The pairing channel and its browser API (admin host, WVR-13).
    pub const ACCOUNT_PAIR: PolicyId = PolicyId("account-pair");

    /// Build a policy id from a static string.
    pub const fn new(id: &'static str) -> Self {
        Self(id)
    }

    /// The stable string form.
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// A protected thing a request targets.
///
/// Views decouple "what is being protected" from "which budget applies": a
/// future signup handler names its own view, and the route table maps it to a
/// policy and a cost without the engine hard-coding it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ViewId(&'static str);

impl ViewId {
    /// The relay's own web surface (admin host, tunnel apex, cleartext edge).
    pub const RELAY_WEB: ViewId = ViewId("relay-web");
    /// Proxied tunnelled traffic, which has no budget by default.
    pub const TUNNEL: ViewId = ViewId("tunnel");
    /// A challenge request to the ALTCHA API (tunnel apex).
    pub const ALTCHA_CHALLENGE: ViewId = ViewId("altcha-challenge");
    /// A verification request to the ALTCHA API (tunnel apex).
    pub const ALTCHA_VERIFY: ViewId = ViewId("altcha-verify");
    /// Starting an email signup (admin host account plane).
    pub const ACCOUNT_SIGNUP: ViewId = ViewId("account-signup");
    /// A credential login attempt (admin host account plane).
    pub const ACCOUNT_LOGIN: ViewId = ViewId("account-login");
    /// Resending a verification link (admin host account plane).
    pub const ACCOUNT_RESEND: ViewId = ViewId("account-resend");
    /// The pairing channel and its browser API (admin host, WVR-13).
    pub const ACCOUNT_PAIR: ViewId = ViewId("account-pair");

    /// Build a view id from a static string.
    pub const fn new(id: &'static str) -> Self {
        Self(id)
    }

    /// The stable string form.
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// One budget a policy charges: a key dimension and its quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// Which fingerprint key to charge.
    pub key: KeyKind,
    /// The bucket capacity and refill for that key.
    pub quota: Quota,
}

/// What to do when the budget store cannot answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreErrorPolicy {
    /// Refuse the request (fail closed); the caller surfaces `503`.
    FailClosed,
    /// Serve the request and log loudly; never a silent bypass.
    Degraded,
}

/// A named set of budgets plus its store-failure stance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Stable identifier.
    pub id: PolicyId,
    /// Budgets charged for every request under this policy.
    pub budgets: Vec<Budget>,
    /// How to treat a store failure.
    pub on_store_error: StoreErrorPolicy,
}

/// The configured policies, looked up by [`PolicyId`].
#[derive(Debug, Clone, Default)]
pub struct PolicySet {
    policies: Vec<Policy>,
}

impl PolicySet {
    /// Wrap a list of policies.
    pub fn new(policies: Vec<Policy>) -> Self {
        Self { policies }
    }

    /// Find a policy by id.
    pub fn get(&self, id: PolicyId) -> Option<&Policy> {
        self.policies.iter().find(|policy| policy.id == id)
    }

    /// Iterate the configured policies.
    pub fn iter(&self) -> impl Iterator<Item = &Policy> {
        self.policies.iter()
    }
}

/// How much a request costs a view's budget.
///
/// The cost must be decidable *before* the protected work runs, so it can only
/// use pre-handler facts (declared body size, method). IO-derived signals are
/// resolved by the caller and passed in, never computed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CostRule {
    /// A fixed number of units.
    Static(u32),
    /// A base plus a per-KiB surcharge on the declared body.
    Weighted {
        /// Fixed units charged to any request.
        base: u32,
        /// Additional units per KiB of declared body.
        per_kib: u32,
    },
}

impl CostRule {
    /// The units this request costs.
    pub fn units(&self, ctx: &RequestContext<'_>) -> u32 {
        match *self {
            Self::Static(units) => units,
            Self::Weighted { base, per_kib } => {
                let kib = ctx.body_len.unwrap_or(0).div_ceil(1024) as u32;
                base.saturating_add(per_kib.saturating_mul(kib))
            }
        }
    }
}

/// Which policy and cost apply to a view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// The budget policy to charge.
    pub policy: PolicyId,
    /// The cost rule for the view.
    pub cost: CostRule,
}

/// The view→route mapping consulted by [`crate::passes::BudgetPass`].
#[derive(Debug, Clone, Default)]
pub struct RouteTable {
    routes: Vec<(ViewId, Route)>,
}

impl RouteTable {
    /// Wrap a list of `(view, route)` pairs.
    pub fn new(routes: Vec<(ViewId, Route)>) -> Self {
        Self { routes }
    }

    /// The route for a view, if it is budgeted.
    pub fn get(&self, view: ViewId) -> Option<&Route> {
        self.routes
            .iter()
            .find(|(candidate, _)| *candidate == view)
            .map(|(_, route)| route)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_rule_static_and_weighted() {
        let base = |body_len| {
            let ctx = RequestContext {
                surface: crate::surface::Surface::cleartext(),
                method: http::Method::GET,
                path: "/",
                raw_path: "/",
                body_len,
                fingerprint: crate::fingerprint("10.0.0.1".parse().unwrap(), None),
                view: ViewId::RELAY_WEB,
                now_ms: 0,
                findings: Vec::new(),
                cost: 0,
            };
            (
                ctx,
                CostRule::Weighted {
                    base: 1,
                    per_kib: 2,
                },
            )
        };
        let weighted = CostRule::Weighted {
            base: 1,
            per_kib: 2,
        };
        let (ctx, _) = base(None);
        assert_eq!(weighted.units(&ctx), 1);
        let (ctx, _) = base(Some(1024));
        assert_eq!(weighted.units(&ctx), 3);
        let (ctx, _) = base(Some(1025));
        assert_eq!(weighted.units(&ctx), 5);
        let (ctx, _) = base(Some(0));
        assert_eq!(CostRule::Static(4).units(&ctx), 4);
    }

    #[test]
    fn policy_and_route_lookup() {
        let set = PolicySet::new(vec![Policy {
            id: PolicyId::RELAY_WEB,
            budgets: Vec::new(),
            on_store_error: StoreErrorPolicy::Degraded,
        }]);
        assert!(set.get(PolicyId::RELAY_WEB).is_some());
        assert!(set.get(PolicyId::new("other")).is_none());

        let routes = RouteTable::new(vec![(
            ViewId::RELAY_WEB,
            Route {
                policy: PolicyId::RELAY_WEB,
                cost: CostRule::Static(1),
            },
        )]);
        assert!(routes.get(ViewId::RELAY_WEB).is_some());
        assert!(routes.get(ViewId::TUNNEL).is_none());
    }
}
