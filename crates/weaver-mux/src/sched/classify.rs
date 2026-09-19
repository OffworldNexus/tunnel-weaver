//! Automatic stream demotion.
//!
//! The only rule the mux applies on its own: an `Interactive` stream whose
//! policy carries `demote_after` becomes `Bulk` once that many bytes have
//! been sent. Everything else about a stream's class is decided by the
//! caller, at `open` or via `set_policy`.

use super::Class;

/// Class after `written_total` cumulative bytes.
pub fn after_write(current: Class, written_total: u64, demote_after: Option<u64>) -> Class {
    match (current, demote_after) {
        (Class::Interactive, Some(t)) if written_total > t => Class::Bulk,
        (other, _) => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 256 * 1024;

    #[test]
    fn demotion_only_from_interactive_with_threshold() {
        assert_eq!(
            after_write(Class::Interactive, T, Some(T)),
            Class::Interactive
        );
        assert_eq!(after_write(Class::Interactive, T + 1, Some(T)), Class::Bulk);
        assert_eq!(
            after_write(Class::Interactive, T * 10, None),
            Class::Interactive
        );
        assert_eq!(
            after_write(Class::Realtime, T * 10, Some(T)),
            Class::Realtime
        );
        assert_eq!(after_write(Class::Bulk, 0, Some(T)), Class::Bulk);
    }
}
