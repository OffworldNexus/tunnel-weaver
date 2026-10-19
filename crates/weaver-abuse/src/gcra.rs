//! GCRA limiter arithmetic.
//!
//! The Generic Cell Rate Algorithm is a token bucket written as a single
//! theoretical-arrival time (`tat`). It has two parameters derived from a
//! [`Quota`]: the *emission interval* `T` (time between successive units) and
//! the *tolerance* `τ` (how far ahead of now the bucket may run — that is the
//! burst). Charging `cost` units conforms iff the bucket has not run more than
//! `τ` ahead; conforming advances `tat` by `cost·T`, a refusal leaves `tat`
//! untouched and reports exactly how long to wait.
//!
//! State is one `i64`, so it persists in a single column and never drifts from
//! wall-clock resets: the caller always passes an absolute `now_ms`.

/// Steady-state refill: `units` units per `per_ms` milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    /// Units replenished every `per_ms`.
    pub units: u32,
    /// The refill window, in milliseconds.
    pub per_ms: i64,
}

/// A bucket's capacity and refill rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    /// Maximum units available at once (the burst).
    pub burst: u32,
    /// Steady-state refill.
    pub refill: Rate,
}

/// The rate-limit decision for one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The request is within budget.
    Admitted,
    /// The request exceeds budget.
    Throttled,
}

/// The result of charging one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Charge {
    /// Whether the request was admitted.
    pub outcome: Outcome,
    /// Milliseconds to wait before retrying; 0 when admitted.
    pub retry_after_ms: i64,
}

/// The per-key limiter state: a single theoretical-arrival time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Gcra {
    tat_ms: Option<i64>,
}

impl Gcra {
    /// A fresh, full bucket. Its first observation is at the caller's `now_ms`.
    pub fn new() -> Self {
        Self { tat_ms: None }
    }

    /// Rebuild from a persisted theoretical-arrival time.
    pub fn from_tat_ms(tat_ms: i64) -> Self {
        Self {
            tat_ms: Some(tat_ms),
        }
    }

    /// The persisted theoretical-arrival time, if the bucket has been used.
    pub fn tat_ms(&self) -> Option<i64> {
        self.tat_ms
    }

    /// Charge `cost` units at `now_ms`, mutating the bucket.
    ///
    /// `retry_cap_ms` bounds the returned delay so `Retry-After` stays small
    /// and actionable even for a large weighted cost.
    pub fn check(&mut self, quota: &Quota, cost: u32, now_ms: i64, retry_cap_ms: i64) -> Charge {
        let tolerance = tolerance_ms(quota);
        let tat = self.tat_ms.unwrap_or(now_ms).max(now_ms);
        let allow_at = tat.saturating_sub(tolerance);
        if now_ms >= allow_at {
            let new_tat = tat.saturating_add(cost_ms(quota, cost));
            self.tat_ms = Some(new_tat);
            Charge {
                outcome: Outcome::Admitted,
                retry_after_ms: 0,
            }
        } else {
            Charge {
                outcome: Outcome::Throttled,
                retry_after_ms: (allow_at - now_ms).clamp(1, retry_cap_ms.max(1)),
            }
        }
    }
}

/// The emission interval `T` in milliseconds (time to accrue one unit).
fn emission_ms(quota: &Quota) -> i64 {
    (quota.refill.per_ms / i64::from(quota.refill.units.max(1))).max(1)
}

/// The tolerance `τ = (burst - 1)·T`.
fn tolerance_ms(quota: &Quota) -> i64 {
    i64::from(quota.burst.saturating_sub(1)).saturating_mul(emission_ms(quota))
}

/// How much time `cost` units occupy, `cost·T`.
fn cost_ms(quota: &Quota, cost: u32) -> i64 {
    i64::from(cost).saturating_mul(emission_ms(quota))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quota(burst: u32, units: u32, per_ms: i64) -> Quota {
        Quota {
            burst,
            refill: Rate { units, per_ms },
        }
    }

    #[test]
    fn burst_admits_then_throttles_then_recovers() {
        // T = 1000ms, τ = 2000ms.
        let q = quota(3, 1, 1_000);
        let mut gcra = Gcra::new();
        for _ in 0..3 {
            assert_eq!(gcra.check(&q, 1, 0, 60_000).outcome, Outcome::Admitted);
        }
        let denied = gcra.check(&q, 1, 0, 60_000);
        assert_eq!(denied.outcome, Outcome::Throttled);
        assert_eq!(denied.retry_after_ms, 1_000);
        // Waiting exactly the reported delay admits again.
        assert_eq!(gcra.check(&q, 1, 1_000, 60_000).outcome, Outcome::Admitted);
    }

    #[test]
    fn retry_is_clamped_to_the_cap() {
        // burst 1 -> τ = 0, so a single admitted unit queues a full minute.
        let q = quota(1, 1, 60_000);
        let mut gcra = Gcra::new();
        gcra.check(&q, 1, 0, 60_000);
        let denied = gcra.check(&q, 1, 0, 5_000);
        assert_eq!(denied.outcome, Outcome::Throttled);
        assert_eq!(denied.retry_after_ms, 5_000, "clamped to the cap");
    }

    #[test]
    fn refill_is_linear_in_time() {
        let q = quota(1, 1, 1_000); // one unit per second
        let mut gcra = Gcra::new();
        assert_eq!(gcra.check(&q, 1, 0, 60_000).outcome, Outcome::Admitted);
        assert_eq!(gcra.check(&q, 1, 500, 60_000).outcome, Outcome::Throttled);
        assert_eq!(gcra.check(&q, 1, 1_000, 60_000).outcome, Outcome::Admitted);
    }
}
