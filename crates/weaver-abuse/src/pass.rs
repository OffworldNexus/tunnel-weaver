//! Passes: the ordered stages of the safety pipeline.
//!
//! A pass sees the whole [`RequestContext`] and either continues or stops the
//! pipeline with a [`Decision`].
//!
//! The built-in passes are in [`crate::passes`].

use async_trait::async_trait;

use crate::context::RequestContext;
use crate::policy::PolicyId;
use crate::scanner::ScanVerdict;

/// The pipeline's answer for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Forward the request.
    Allow,
    /// Refuse it: `403`.
    Block {
        /// The firewall verdict that fired.
        verdict: ScanVerdict,
    },
    /// Too many requests: `429` plus `Retry-After`.
    Throttle {
        /// The policy that refused.
        policy: PolicyId,
        /// Milliseconds to wait, already bounded by the configured cap.
        retry_after_ms: i64,
    },
    /// The store failed and the policy fails closed: `503`.
    Unavailable {
        /// The policy whose charge failed.
        policy: PolicyId,
    },
    /// The store failed but the policy serves anyway; the caller logs loudly.
    Degraded {
        /// The policy whose charge failed.
        policy: PolicyId,
    },
}

/// What a pass does to the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassOutcome {
    /// The request is still viable; run the next pass.
    Continue,
    /// Stop the pipeline with this decision.
    Stop(Decision),
}

/// One ordered stage of the safety pipeline.
#[async_trait]
pub trait Pass: Send + Sync {
    /// Stable name, for logs and observability.
    fn name(&self) -> &'static str;
    /// Inspect the context, or stop the pipeline.
    async fn run(&self, ctx: &RequestContext<'_>) -> PassOutcome;
}

/// The ordered passes that protect the relay, run in order until one stops.
pub struct Pipeline {
    passes: Vec<Box<dyn Pass>>,
}

impl Pipeline {
    /// Build a pipeline from ordered passes.
    pub fn new(passes: Vec<Box<dyn Pass>>) -> Self {
        Self { passes }
    }

    /// A pipeline with only the scanner firewall pass (no budget). Useful where
    /// no store is available, and as the base every real pipeline extends.
    pub fn scanner_only() -> Self {
        Self::new(vec![Box::new(crate::passes::ScannerPass)])
    }

    /// Run the passes in order; the first non-[`PassOutcome::Continue`] wins.
    pub async fn evaluate(&self, ctx: &RequestContext<'_>) -> Decision {
        for pass in &self.passes {
            if let PassOutcome::Stop(decision) = pass.run(ctx).await {
                return decision;
            }
        }
        Decision::Allow
    }

    /// The pass names, in order, for logging.
    pub fn pass_names(&self) -> Vec<&'static str> {
        self.passes.iter().map(|pass| pass.name()).collect()
    }
}
