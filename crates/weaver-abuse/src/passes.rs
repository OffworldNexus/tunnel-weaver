//! The built-in pipeline passes.
//!
//! [`ScannerPass`] runs the rule set and stops on the first blocking finding.
//! [`BudgetPass`] charges the requesting view's GCRA budget. They collaborate
//! through the shared [`RequestContext`]: the WAF pass records findings, and a
//! later pass (a future `CostPass`, or PoW) can read them.

use async_trait::async_trait;

use crate::context::RequestContext;
use crate::gate::{Gate, GateError};
use crate::pass::{Decision, Pass, PassOutcome};
use crate::policy::{RouteTable, StoreErrorPolicy};
use crate::rule::{Rule, Severity};
use crate::store::BudgetStore;
use crate::surface::is_exempt;

/// Runs the rule set and stops on the first blocking finding.
///
/// Control-plane routes ([`is_exempt`]) skip the rules entirely, so health,
/// ACME and the mux handshake stay reachable no matter what the catalogue
/// grows to.
pub struct ScannerPass {
    rules: Vec<Box<dyn Rule>>,
}

impl ScannerPass {
    /// Build from an explicit rule set.
    pub fn new(rules: Vec<Box<dyn Rule>>) -> Self {
        Self { rules }
    }
}

impl Default for ScannerPass {
    /// The default pass: the scanner firewall rule only.
    fn default() -> Self {
        Self::new(vec![Box::new(crate::rule::ScannerRule)])
    }
}

#[async_trait]
impl Pass for ScannerPass {
    fn name(&self) -> &'static str {
        "scanner"
    }

    async fn run(&self, ctx: &mut RequestContext<'_>) -> PassOutcome {
        if is_exempt(ctx.surface, &ctx.method, ctx.path) {
            return PassOutcome::Continue;
        }
        for rule in &self.rules {
            if let Some(finding) = rule.inspect(ctx) {
                let blocking = finding.severity == Severity::Block;
                let verdict = finding
                    .verdict
                    .unwrap_or(crate::scanner::ScanVerdict::Malformed);
                let rule_name = finding.rule;
                ctx.findings.push(finding);
                if blocking {
                    return PassOutcome::Stop(Decision::Block {
                        verdict,
                        rule: rule_name,
                    });
                }
            }
        }
        PassOutcome::Continue
    }
}

/// Charges the requesting view's budget for the request's fingerprint.
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

    async fn run(&self, ctx: &mut RequestContext<'_>) -> PassOutcome {
        if is_exempt(ctx.surface, &ctx.method, ctx.path) {
            return PassOutcome::Continue;
        }
        let Some(route) = self.routes.get(ctx.view) else {
            return PassOutcome::Continue;
        };
        let cost = route.cost.units(ctx);
        ctx.cost = cost;
        match self
            .gate
            .admit(route.policy, &ctx.fingerprint, cost, ctx.now_ms)
            .await
        {
            Ok(_) => PassOutcome::Continue,
            Err(GateError::Throttled {
                policy,
                retry_after_ms,
                ..
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
