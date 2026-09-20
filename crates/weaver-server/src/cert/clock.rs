#[cfg(any(test, feature = "test-util"))]
use std::sync::Arc;
#[cfg(any(test, feature = "test-util"))]
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Clock abstraction allowing deterministic time injection in tests.
pub trait Clock: Send + Sync + 'static {
    /// Returns the current Unix timestamp in seconds.
    fn now_unix(&self) -> i64;
}

/// Standard system wall-clock time provider.
#[derive(Debug, Default, Clone)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs() as i64
    }
}

/// Injected mock clock for tests and deterministic simulation.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Clone)]
pub struct MockClock {
    now: Arc<AtomicI64>,
}

#[cfg(any(test, feature = "test-util"))]
impl MockClock {
    /// Creates a mock clock initialized to the specified timestamp.
    pub fn new(initial: i64) -> Self {
        Self {
            now: Arc::new(AtomicI64::new(initial)),
        }
    }

    /// Sets the current timestamp to an exact value.
    pub fn set(&self, ts: i64) {
        self.now.store(ts, Ordering::SeqCst);
    }

    /// Advances the clock forward by the given duration in seconds.
    pub fn advance(&self, secs: i64) {
        self.now.fetch_add(secs, Ordering::SeqCst);
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Clock for MockClock {
    fn now_unix(&self) -> i64 {
        self.now.load(Ordering::SeqCst)
    }
}

/// Formats a Unix timestamp as a human-readable UTC date-time string ("YYYY-MM-DD HH:MM:SS UTC").
pub fn format_unix_timestamp(ts: i64) -> String {
    let days = ts / 86400;
    let rem_secs = ts.rem_euclid(86400);
    let h = rem_secs / 3600;
    let min = (rem_secs % 3600) / 60;
    let s = rem_secs % 60;

    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }

    format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02}:{s:02} UTC")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_unix_timestamp() {
        assert_eq!(format_unix_timestamp(0), "1970-01-01 00:00:00 UTC");
        // 2026-09-15 18:05:02 UTC
        // days between 1970-01-01 and 2026-09-15 = 20711
        // 20711 * 86400 + 18*3600 + 5*60 + 2 = 1789495502
        let ts = 20711 * 86400 + 18 * 3600 + 5 * 60 + 2;
        assert_eq!(format_unix_timestamp(ts), "2026-09-15 18:05:02 UTC");
    }
}
