//! Automatic stream classification.
//!
//! Rules are evaluated at open and after every write; a stream the
//! application pinned with `set_class` is never touched again.

use super::Class;
use crate::wire::Hints;

/// Class assigned at `open`, from the head's hints alone.
pub fn at_birth(hints: &Hints, bulk_threshold: u64) -> Class {
    if hints.upgrade || is_event_stream(hints) {
        return Class::Realtime;
    }
    if hints.content_length.is_some_and(|len| len > bulk_threshold) {
        return Class::Bulk;
    }
    Class::Small
}

/// Class after `written_total` cumulative bytes: `small` demotes to `bulk`
/// past the threshold; `realtime` and already-`bulk` streams stay put.
pub fn after_write(current: Class, written_total: u64, bulk_threshold: u64) -> Class {
    match current {
        Class::Small if written_total > bulk_threshold => Class::Bulk,
        other => other,
    }
}

fn is_event_stream(hints: &Hints) -> bool {
    hints
        .content_type
        .as_deref()
        .is_some_and(|ct| super::mime_essence(ct) == "text/event-stream")
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 256 * 1024;

    fn hints(ct: Option<&str>, len: Option<u64>, upgrade: bool) -> Hints {
        Hints {
            content_type: ct.map(str::to_owned),
            content_length: len,
            upgrade,
            content_encoding: None,
        }
    }

    #[test]
    fn birth_rules() {
        assert_eq!(at_birth(&hints(None, None, false), T), Class::Small);
        assert_eq!(at_birth(&hints(None, None, true), T), Class::Realtime);
        assert_eq!(
            at_birth(
                &hints(Some("text/event-stream; charset=utf-8"), None, false),
                T
            ),
            Class::Realtime
        );
        assert_eq!(at_birth(&hints(None, Some(T), false), T), Class::Small);
        assert_eq!(at_birth(&hints(None, Some(T + 1), false), T), Class::Bulk);
        // Realtime wins over a large content-length.
        assert_eq!(
            at_birth(&hints(None, Some(T + 1), true), T),
            Class::Realtime
        );
    }

    #[test]
    fn demotion_only_from_small() {
        assert_eq!(after_write(Class::Small, T, T), Class::Small);
        assert_eq!(after_write(Class::Small, T + 1, T), Class::Bulk);
        assert_eq!(after_write(Class::Realtime, T * 10, T), Class::Realtime);
        assert_eq!(after_write(Class::Bulk, 0, T), Class::Bulk);
    }
}
