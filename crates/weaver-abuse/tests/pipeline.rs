//! The safety pipeline: passes collaborating over one context, short-circuiting
//! on the first verdict.

use http::Method;
use weaver_abuse::testing::MemoryStore;
use weaver_abuse::{
    Budget, BudgetPass, CostRule, Decision, Gate, Host, KeyKind, Pipeline, Policy, PolicyId,
    PolicySet, Quota, Rate, RequestContext, Route, RouteTable, ScanVerdict, ScannerPass,
    StoreErrorPolicy, Surface, ViewId, fingerprint,
};

const POLICY: PolicyId = PolicyId::new("relay-web");

fn host_budget(burst: u32) -> Quota {
    Quota {
        burst,
        refill: Rate {
            units: 1,
            per_ms: 3_600_000,
        },
    }
}

/// A pipeline: scanner pass then a relay-web budget of `burst` requests.
fn pipeline(burst: u32) -> Pipeline {
    let gate = Gate::new(
        MemoryStore::new(64, 0),
        PolicySet::new(vec![Policy {
            id: POLICY,
            budgets: vec![Budget {
                key: KeyKind::PeerHost,
                quota: host_budget(burst),
            }],
            on_store_error: StoreErrorPolicy::Degraded,
        }]),
        60_000,
    );
    let routes = RouteTable::new(vec![(
        ViewId::RELAY_WEB,
        Route {
            policy: POLICY,
            cost: CostRule::Static(1),
        },
    )]);
    Pipeline::new(vec![
        Box::new(ScannerPass::default()),
        Box::new(BudgetPass::new(gate, routes)),
    ])
}

fn context<'a>(
    surface: Surface,
    view: ViewId,
    method: Method,
    path: &'a str,
) -> RequestContext<'a> {
    RequestContext {
        surface,
        method,
        path,
        raw_path: path,
        body_len: None,
        fingerprint: fingerprint("203.0.113.7".parse().unwrap(), None),
        view,
        now_ms: 1_000_000,
        findings: Vec::new(),
        cost: 0,
    }
}

fn apex() -> Surface {
    Surface::https(Host::TunnelRoot)
}

#[tokio::test]
async fn scanner_pass_blocks_before_the_budget_runs() {
    let pipeline = pipeline(1);
    let mut ctx = context(apex(), ViewId::RELAY_WEB, Method::GET, "/.env");
    let decision = pipeline.evaluate(&mut ctx).await;
    assert_eq!(
        decision,
        Decision::Block {
            verdict: ScanVerdict::Dotfile,
            rule: "dotfile"
        }
    );
    // The finding is recorded even though the pipeline stopped.
    assert_eq!(ctx.findings.len(), 1);

    // The scanner's block did not consume the budget: a clean request still
    // gets the (single) unit.
    let mut clean = context(apex(), ViewId::RELAY_WEB, Method::GET, "/");
    assert_eq!(pipeline.evaluate(&mut clean).await, Decision::Allow);
}

#[tokio::test]
async fn budget_pass_throttles_after_the_burst() {
    let pipeline = pipeline(1);
    let mut first = context(apex(), ViewId::RELAY_WEB, Method::GET, "/");
    assert_eq!(pipeline.evaluate(&mut first).await, Decision::Allow);

    let mut second = context(apex(), ViewId::RELAY_WEB, Method::GET, "/");
    assert!(matches!(
        pipeline.evaluate(&mut second).await,
        Decision::Throttle { policy, .. } if policy == POLICY
    ));
}

#[tokio::test]
async fn exempt_routes_skip_every_pass() {
    let pipeline = pipeline(1);
    // `/healthz` is a control-plane route: never blocked, never charged.
    for _ in 0..10 {
        let mut ctx = context(apex(), ViewId::RELAY_WEB, Method::GET, "/healthz");
        assert_eq!(pipeline.evaluate(&mut ctx).await, Decision::Allow);
        assert!(ctx.findings.is_empty());
    }
}

#[tokio::test]
async fn tunnelled_traffic_is_scanned_but_not_budgeted() {
    let pipeline = pipeline(1);
    let tunneled = Surface::https(Host::Tunneled);

    // The scanner still protects tunnelled hostnames.
    let mut probe = context(tunneled, ViewId::TUNNEL, Method::GET, "/.git/HEAD");
    assert!(matches!(
        pipeline.evaluate(&mut probe).await,
        Decision::Block { .. }
    ));

    // But tunnelled traffic has no route, so it is never throttled.
    for _ in 0..10 {
        let mut ctx = context(tunneled, ViewId::TUNNEL, Method::GET, "/app");
        assert_eq!(pipeline.evaluate(&mut ctx).await, Decision::Allow);
    }
}
