//! The wall clock, read in the two units the relay stores.

use std::time::{SystemTime, UNIX_EPOCH};

fn since_epoch() -> std::time::Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

/// Unix seconds.
pub fn unix_secs() -> i64 {
    since_epoch().as_secs() as i64
}

/// Unix milliseconds.
pub fn unix_ms() -> i64 {
    since_epoch().as_millis() as i64
}
