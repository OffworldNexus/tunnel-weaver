//! Rules: reusable predicates over the request context that produce findings.
//!
//! A rule is a pure observer. It never mutates anything and never decides the
//! pipeline's fate on its own; it reports a [`Finding`], and the pass that ran
//! it (see [`crate::passes::ScannerPass`]) decides whether that stops the pipeline.

use crate::context::RequestContext;
use crate::scanner::{self, ScanVerdict};

/// How seriously a finding is treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Observed and recorded; the pipeline continues.
    Notice,
    /// The request must be refused.
    Block,
}

/// One rule's observation about a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finding {
    /// Stable rule name, carried into logs and decisions.
    pub rule: &'static str,
    /// How to treat the finding.
    pub severity: Severity,
    /// The firewall verdict, when the rule is a firewall rule.
    pub verdict: Option<ScanVerdict>,
}

/// A reusable predicate over the request context.
pub trait Rule: Send + Sync {
    /// Stable name.
    fn name(&self) -> &'static str;
    /// Observe the request; `Some` means the rule matched.
    fn inspect(&self, ctx: &RequestContext<'_>) -> Option<Finding>;
}

/// The default scanner firewall rule: the narrow probe catalogue in
/// [`crate::scanner`]. Every finding it produces blocks.
pub struct ScannerRule;

impl Rule for ScannerRule {
    fn name(&self) -> &'static str {
        "scanner"
    }

    fn inspect(&self, ctx: &RequestContext<'_>) -> Option<Finding> {
        scanner::inspect(&ctx.method, ctx.raw_path).map(|verdict| Finding {
            rule: verdict.as_str(),
            severity: Severity::Block,
            verdict: Some(verdict),
        })
    }
}
