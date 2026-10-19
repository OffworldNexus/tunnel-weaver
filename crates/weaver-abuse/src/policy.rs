//! Policies: the budgets a request is charged against, the views that select
//! them, and how store failures count.

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

    /// The pairing channel and its browser API (admin host).
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
/// each handler names its own view, and the route table maps it to a
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
    /// The pairing channel and its browser API (admin host).
    pub const ACCOUNT_PAIR: ViewId = ViewId("account-pair");

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
}

/// The view→policy mapping consulted by [`crate::passes::BudgetPass`].
#[derive(Debug, Clone, Default)]
pub struct RouteTable {
    routes: Vec<(ViewId, PolicyId)>,
}

impl RouteTable {
    /// Wrap a list of `(view, policy)` pairs.
    pub fn new(routes: Vec<(ViewId, PolicyId)>) -> Self {
        Self { routes }
    }

    /// The policy for a view, if it is budgeted.
    pub fn get(&self, view: ViewId) -> Option<PolicyId> {
        self.routes
            .iter()
            .find(|(candidate, _)| *candidate == view)
            .map(|&(_, policy)| policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_and_route_lookup() {
        let set = PolicySet::new(vec![Policy {
            id: PolicyId::RELAY_WEB,
            budgets: Vec::new(),
            on_store_error: StoreErrorPolicy::Degraded,
        }]);
        assert!(set.get(PolicyId::RELAY_WEB).is_some());
        assert!(set.get(PolicyId::new("other")).is_none());

        let routes = RouteTable::new(vec![(ViewId::RELAY_WEB, PolicyId::RELAY_WEB)]);
        assert!(routes.get(ViewId::RELAY_WEB).is_some());
        assert!(routes.get(ViewId::TUNNEL).is_none());
    }
}
