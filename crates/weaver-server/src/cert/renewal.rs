//! Certificate renewal and backoff policy.
//!
//! Evaluates renewal eligibility according to the one-third remaining lifetime rule,
//! and computes exponential retry backoff (1h to 24h cap) for failed issuances.

use std::time::Duration;

/// Returns true if a certificate should be renewed.
///
/// A certificate is eligible for renewal when less than one-third of its total
/// validity lifetime remains (or if it has already expired).
pub fn should_renew(not_before: i64, not_after: i64, now: i64) -> bool {
    let total_lifetime = not_after.saturating_sub(not_before);
    let remaining = not_after.saturating_sub(now);
    remaining <= total_lifetime / 3
}

/// Computes exponential backoff for issuance or renewal failure.
///
/// Starts at 1 hour (3600s), doubles per consecutive failure, and caps at 24 hours (86400s).
/// If the CA returned a `retry_after` delay larger than the computed backoff, honors it.
pub fn compute_backoff(consecutive_failures: u32, retry_after: Option<u64>) -> Duration {
    let exponent = consecutive_failures.saturating_sub(1).min(6);
    let base_secs: u64 = 3600; // 1 hour
    let backoff_secs = (base_secs * (1 << exponent)).min(86400); // 24 hour cap

    let final_secs = match retry_after {
        Some(ra) => backoff_secs.max(ra),
        None => backoff_secs,
    };

    Duration::from_secs(final_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_renew_at_one_third() {
        let nb = 1_000_000;
        let na = 1_090_000; // 90,000s lifetime (~90 days / scaled)
        // 1/3 lifetime = 30,000s.
        // Threshold timestamp = 1,060,000 (when 30,000s remain)

        assert!(!should_renew(nb, na, 1_050_000)); // 40,000s left -> false
        assert!(should_renew(nb, na, 1_060_000)); // 30,000s left -> true
        assert!(should_renew(nb, na, 1_070_000)); // 20,000s left -> true
        assert!(should_renew(nb, na, 1_100_000)); // expired -> true
    }

    #[test]
    fn test_compute_backoff_exponential() {
        assert_eq!(compute_backoff(1, None), Duration::from_secs(3600)); // 1h
        assert_eq!(compute_backoff(2, None), Duration::from_secs(7200)); // 2h
        assert_eq!(compute_backoff(3, None), Duration::from_secs(14400)); // 4h
        assert_eq!(compute_backoff(4, None), Duration::from_secs(28800)); // 8h
        assert_eq!(compute_backoff(5, None), Duration::from_secs(57600)); // 16h
        assert_eq!(compute_backoff(6, None), Duration::from_secs(86400)); // 24h cap
        assert_eq!(compute_backoff(10, None), Duration::from_secs(86400)); // 24h cap

        // retry-after override
        assert_eq!(compute_backoff(1, Some(10000)), Duration::from_secs(10000));
    }
}
