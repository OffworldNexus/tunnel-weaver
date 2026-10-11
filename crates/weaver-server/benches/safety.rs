//! Per-request cost of the safety middleware, engine and store.
//!
//! Times the real pass chain end to end. Two backends are measured so the
//! store's contribution is visible:
//!
//! * **memory** — the reference in-memory store isolates pure **engine** cost;
//! * **sqlite** — the shipped `DbStore`, i.e. the production path, where every
//!   charged request performs one transaction.
//!
//! Each iteration also builds the [`RequestContext`] (including the fingerprint
//! hash), so the figures are true per-request costs.
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
use tempfile::TempDir;
use weaver_abuse::testing::MemoryStore;
use weaver_abuse::{
    Budget, BudgetPass, BudgetStore, CostRule, Gate, Host, Key, KeyKind, Pipeline, Policy,
    PolicyId, PolicySet, Quota, Rate, RequestContext, Route, RouteTable, ScannerPass,
    StoreErrorPolicy, Surface, ViewId, fingerprint,
};
use weaver_server::Store;
use weaver_server::abuse::DbStore;

/// Iterations/rounds for the in-memory (sub-microsecond) scenarios.
const MEM_ITERS: usize = 5_000;
const MEM_ROUNDS: usize = 200;
/// Iterations/rounds for the SQLite (microsecond) scenarios.
const DB_ITERS: usize = 1_000;
const DB_ROUNDS: usize = 50;

/// Effectively unlimited so we measure admission, not throttling.
fn unlimited_quota() -> Quota {
    Quota {
        burst: u32::MAX,
        refill: Rate {
            units: 1,
            per_ms: 1,
        },
    }
}

fn relay_policies() -> PolicySet {
    PolicySet::new(vec![Policy {
        id: PolicyId::RELAY_WEB,
        budgets: vec![Budget {
            key: KeyKind::PeerHost,
            quota: unlimited_quota(),
        }],
        on_store_error: StoreErrorPolicy::Degraded,
    }])
}

fn relay_routes() -> RouteTable {
    RouteTable::new(vec![(
        ViewId::RELAY_WEB,
        Route {
            policy: PolicyId::RELAY_WEB,
            cost: CostRule::Static(1),
        },
    )])
}

fn memory_pipeline() -> Pipeline {
    let gate = Gate::new(MemoryStore::new(1024, 0), relay_policies(), 60_000);
    Pipeline::new(vec![
        Box::new(ScannerPass::default()),
        Box::new(BudgetPass::new(gate, relay_routes())),
    ])
}

/// A SQLite-backed pipeline over a fresh temp database.
async fn sqlite_pipeline() -> (Pipeline, DbStore, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let store = Store::open(dir.path().join("bench.db"))
        .await
        .expect("open store");
    let gate = Gate::new(DbStore::new(store.clone()), relay_policies(), 60_000);
    let pipeline = Pipeline::new(vec![
        Box::new(ScannerPass::default()),
        Box::new(BudgetPass::new(gate, relay_routes())),
    ]);
    (pipeline, DbStore::new(store), dir)
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

/// Runs `body` `iters` times per round for `rounds` rounds; returns the best
/// average per-op time.
async fn measure<F, Fut>(iters: usize, rounds: usize, mut body: F) -> Duration
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    let mut best = Duration::MAX;
    for _ in 0..rounds {
        let start = Instant::now();
        for _ in 0..iters {
            body().await;
        }
        best = best.min(start.elapsed());
    }
    best / iters as u32
}

fn fmt(d: Duration) -> String {
    let ns = d.as_nanos();
    if ns < 10_000 {
        format!("{ns:>6} ns")
    } else {
        format!("{:>6.2} µs", ns as f64 / 1000.0)
    }
}

async fn run() {
    let memory = memory_pipeline();
    let scanner_only = Pipeline::scanner_only();
    let (sqlite, dbstore, _dir) = sqlite_pipeline().await;
    let apex = Surface::https(Host::TunnelRoot);
    let tunneled = Surface::https(Host::Tunneled);
    let peer: IpAddr = "203.0.113.7".parse().unwrap();

    let mem_admit = measure(MEM_ITERS, MEM_ROUNDS, || {
        let memory = &memory;
        async move {
            let mut ctx = context(apex, ViewId::RELAY_WEB, "/", peer);
            black_box(memory.evaluate(&mut ctx).await);
        }
    })
    .await;

    let mem_probe = measure(MEM_ITERS, MEM_ROUNDS, || {
        let memory = &memory;
        async move {
            let mut ctx = context(apex, ViewId::RELAY_WEB, "/.env", peer);
            black_box(memory.evaluate(&mut ctx).await);
        }
    })
    .await;

    let scan_only = measure(MEM_ITERS, MEM_ROUNDS, || {
        let scanner_only = &scanner_only;
        async move {
            let mut ctx = context(apex, ViewId::RELAY_WEB, "/", peer);
            black_box(scanner_only.evaluate(&mut ctx).await);
        }
    })
    .await;

    let scan_tunnel = measure(MEM_ITERS, MEM_ROUNDS, || {
        let memory = &memory;
        async move {
            let mut ctx = context(tunneled, ViewId::TUNNEL, "/app", peer);
            black_box(memory.evaluate(&mut ctx).await);
        }
    })
    .await;

    // The SQLite transaction alone (no pipeline, no context).
    let db_check = measure(DB_ITERS, DB_ROUNDS, || {
        let dbstore = &dbstore;
        async move {
            let budgets = [(
                Key {
                    kind: KeyKind::PeerHost,
                    id: 1,
                },
                unlimited_quota(),
            )];
            let charges = dbstore
                .check_all(PolicyId::RELAY_WEB, &budgets, 1, 1_000_000, 60_000)
                .await
                .expect("check_all");
            black_box(charges);
        }
    })
    .await;

    // Full per-request cost on the production path: engine + SQLite.
    let sqlite_admit = measure(DB_ITERS, DB_ROUNDS, || {
        let sqlite = &sqlite;
        async move {
            let mut ctx = context(apex, ViewId::RELAY_WEB, "/", peer);
            black_box(sqlite.evaluate(&mut ctx).await);
        }
    })
    .await;

    let delta = sqlite_admit.saturating_sub(mem_admit);

    println!("safety middleware — per request (best round)");
    println!("  engine only (memory store):");
    println!("    scanner + budget, admit  : {}", fmt(mem_admit));
    println!("    scanner + budget, probe  : {}", fmt(mem_probe));
    println!("    scanner only, admit      : {}", fmt(scan_only));
    println!("    tunnelled (uncharged)    : {}", fmt(scan_tunnel));
    println!("  production path (sqlite store):");
    println!("    DbStore::check_all       : {}", fmt(db_check));
    println!("    scanner + budget, admit  : {}", fmt(sqlite_admit));
    println!();
    println!(
        "  the store adds about {} over the engine per charged request",
        fmt(delta)
    );
}

fn main() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(run());
}
