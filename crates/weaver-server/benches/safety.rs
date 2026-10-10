//! Per-request cost of the safety middleware.
//!
//! Times [`Pipeline::evaluate`] over the real pass chain with the in-crate
//! in-memory store, so the numbers isolate **engine** cost:
//!
//! * `scanner+budget (admit)` — scanner pass (no match) then budget admission;
//! * `scanner+budget (probe)` — scanner pass matches a probe (budget not reached);
//! * `scanner only (admit)`   — the scanner pass alone, no budget;
//! * `scanner, tunnelled`     — scanner on tunnelled traffic (no route/charge).
//!
//! Each iteration also builds the [`RequestContext`] (including the fingerprint
//! hash), so the figure is a true per-request cost. It does **not** include the
//! production SQLite transaction a charged request performs — see the note
//! printed at the end.
//!
//! Run with:
//!
//! ```text
//! cargo bench -p weaver-server --bench safety
//! ```

use std::future::Future;
use std::hint::black_box;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use http::Method;
use weaver_abuse::testing::MemoryStore;
use weaver_abuse::{
    Budget, BudgetPass, CostRule, Gate, Host, KeyKind, Pipeline, Policy, PolicyId, PolicySet,
    Quota, Rate, RequestContext, Route, RouteTable, ScannerPass, StoreErrorPolicy, Surface, ViewId,
    fingerprint,
};

/// Iterations per measured round.
const ITERS: usize = 5_000;
/// Measured rounds; the fastest is reported (least noisy).
const ROUNDS: usize = 200;

/// The relay's real pass chain: scanner, then a relay-web budget. The budget is
/// effectively unlimited so we measure admission, not throttling.
fn relay_pipeline() -> Pipeline {
    let gate = Gate::new(
        MemoryStore::new(1024, 0),
        PolicySet::new(vec![Policy {
            id: PolicyId::RELAY_WEB,
            budgets: vec![Budget {
                key: KeyKind::PeerHost,
                quota: Quota {
                    burst: u32::MAX,
                    refill: Rate {
                        units: 1,
                        per_ms: 1,
                    },
                },
            }],
            on_store_error: StoreErrorPolicy::Degraded,
        }]),
        60_000,
    );
    let routes = RouteTable::new(vec![(
        ViewId::RELAY_WEB,
        Route {
            policy: PolicyId::RELAY_WEB,
            cost: CostRule::Static(1),
        },
    )]);
    Pipeline::new(vec![
        Box::new(ScannerPass::default()),
        Box::new(BudgetPass::new(gate, routes)),
    ])
}

fn context<'a>(surface: Surface, view: ViewId, path: &'a str, peer: IpAddr) -> RequestContext<'a> {
    RequestContext {
        surface,
        method: Method::GET,
        path,
        raw_path: path,
        body_len: None,
        fingerprint: fingerprint(peer, None),
        view,
        now_ms: 1_000_000,
        findings: Vec::new(),
        cost: 0,
    }
}

/// Runs `body` `ITERS` times per round for `ROUNDS` rounds; returns the best
/// average per-op time.
async fn measure<F, Fut>(mut body: F) -> Duration
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    let mut best = Duration::MAX;
    for _ in 0..ROUNDS {
        let start = Instant::now();
        for _ in 0..ITERS {
            body().await;
        }
        best = best.min(start.elapsed());
    }
    best / ITERS as u32
}

async fn run() {
    let full = relay_pipeline();
    let scanner_only = Pipeline::scanner_only();
    let apex = Surface::https(Host::TunnelRoot);
    let tunneled = Surface::https(Host::Tunneled);
    let peer: IpAddr = "203.0.113.7".parse().unwrap();

    let admit = measure(|| {
        let full = &full;
        async move {
            let mut ctx = context(apex, ViewId::RELAY_WEB, "/", peer);
            black_box(full.evaluate(&mut ctx).await);
        }
    })
    .await;

    let probe = measure(|| {
        let full = &full;
        async move {
            let mut ctx = context(apex, ViewId::RELAY_WEB, "/.env", peer);
            black_box(full.evaluate(&mut ctx).await);
        }
    })
    .await;

    let scan = measure(|| {
        let scanner_only = &scanner_only;
        async move {
            let mut ctx = context(apex, ViewId::RELAY_WEB, "/", peer);
            black_box(scanner_only.evaluate(&mut ctx).await);
        }
    })
    .await;

    let tunnel = measure(|| {
        let full = &full;
        async move {
            let mut ctx = context(tunneled, ViewId::TUNNEL, "/app", peer);
            black_box(full.evaluate(&mut ctx).await);
        }
    })
    .await;

    let ns = |d: Duration| d.as_nanos() as f64 / 1.0;
    println!("safety middleware — ns/request, best of {ROUNDS} rounds of {ITERS}");
    println!("  scanner + budget (admit)   : {:>7.0} ns", ns(admit));
    println!(
        "  scanner + budget (probe)   : {:>7.0} ns  (blocked; budget not reached)",
        ns(probe)
    );
    println!("  scanner only     (admit)   : {:>7.0} ns", ns(scan));
    println!(
        "  scanner, tunnelled         : {:>7.0} ns  (scanned, never charged)",
        ns(tunnel)
    );
    println!();
    println!(
        "note: a charged relay-web request also writes one SQLite transaction in\n\
         production; that write is not part of these engine numbers."
    );
}

fn main() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio runtime");
    runtime.block_on(run());
}
