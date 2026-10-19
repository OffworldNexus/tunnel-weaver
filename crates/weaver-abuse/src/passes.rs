//! The built-in pipeline passes.
//!
//! [`ScannerPass`] runs the scanner firewall and blocks on a probe.
//! [`BudgetPass`] charges the requesting view's GCRA budget.

use async_trait::async_trait;

use crate::context::RequestContext;
use crate::gate::{Gate, GateError};
use crate::pass::{Decision, Pass, PassOutcome};
use crate::policy::{RouteTable, StoreErrorPolicy};
use crate::scanner;
use crate::store::BudgetStore;
use crate::surface::is_exempt;

/// Runs the scanner firewall ([`crate::scanner`]) and blocks on a probe.
///
/// Control-plane routes ([`is_exempt`]) skip it entirely, so health, ACME and
/// the mux handshake stay reachable no matter what the catalogue grows to.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct ScannerPass;

#[async_trait]
impl Pass for ScannerPass {
    fn name(&self) -> &'static str {
        "scanner"
    }

    async fn run(&self, ctx: &RequestContext<'_>) -> PassOutcome {
        if is_exempt(ctx.surface, &ctx.method, ctx.path) {
            return PassOutcome::Continue;
        }
        match scanner::inspect(&ctx.method, ctx.raw_path) {
            Some(verdict) => PassOutcome::Stop(Decision::Block { verdict }),
            None => PassOutcome::Continue,
        }
    }
}

/// Charges the requesting view's budget one unit for the request's fingerprint.
///
/// A view with no route is not budgeted (for example, tunnelled traffic, whose
/// policy is deliberately separate). Control-plane routes are never charged.
pub struct BudgetPass<S> {
    gate: Gate<S>,
    routes: RouteTable,
}

impl<S: BudgetStore> BudgetPass<S> {
    /// Build from the budget engine and the view→route table.
    pub fn new(gate: Gate<S>, routes: RouteTable) -> Self {
        Self { gate, routes }
    }
}

#[async_trait]
impl<S: BudgetStore> Pass for BudgetPass<S> {
    fn name(&self) -> &'static str {
        "budget"
    }

    async fn run(&self, ctx: &RequestContext<'_>) -> PassOutcome {
        if is_exempt(ctx.surface, &ctx.method, ctx.path) {
            return PassOutcome::Continue;
        }
        let Some(policy) = self.routes.get(ctx.view) else {
            return PassOutcome::Continue;
        };
        match self
            .gate
            .admit(policy, &ctx.fingerprint, 1, ctx.now_ms)
            .await
        {
            Ok(()) => PassOutcome::Continue,
            Err(GateError::Throttled {
                policy,
                retry_after_ms,
            }) => PassOutcome::Stop(Decision::Throttle {
                policy,
                retry_after_ms,
            }),
            Err(GateError::Store { policy, decision }) => PassOutcome::Stop(match decision {
                StoreErrorPolicy::FailClosed => Decision::Unavailable { policy },
                StoreErrorPolicy::Degraded => Decision::Degraded { policy },
            }),
        }
    }
}
