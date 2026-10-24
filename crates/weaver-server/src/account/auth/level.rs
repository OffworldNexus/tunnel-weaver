//! The ordered authentication strength of a session.
//!
//! Spaced by ten so an intermediate level can be inserted later without
//! renumbering, exactly as the reference does. WVR-167 uses `Basic` and
//! `Strong`; `None` is "no session" and is never stored; `Certain` is declared
//! but unused, so WVR-165's step-up (re-typing the password before a sensitive
//! action) is a value rather than a renumbering.

/// How strongly a request has been authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthLevel {
    /// No session at all.
    None,
    /// A session exists and one factor (the password) is proven.
    Basic,
    /// The second factor (the emailed code) is alive.
    Strong,
    /// `Strong` plus a password re-typed moments ago. Nothing requires it yet.
    Certain,
}

impl AuthLevel {
    /// The wire name, used in `GET /api/account/me` and the gate's `403`.
    ///
    /// `Certain` reports as `strong`: the wire only has to distinguish "the
    /// second factor is still pending" from "it is done", so the extra rank
    /// stays server-side until a client needs it (the numeric ordering is what
    /// the gate compares).
    pub const fn as_str(self) -> &'static str {
        match self {
            AuthLevel::None => "none",
            AuthLevel::Basic => "basic",
            AuthLevel::Strong | AuthLevel::Certain => "strong",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_are_ordered() {
        assert!(AuthLevel::None < AuthLevel::Basic);
        assert!(AuthLevel::Basic < AuthLevel::Strong);
        assert!(AuthLevel::Strong < AuthLevel::Certain);
    }

    #[test]
    fn wire_names_are_stable() {
        assert_eq!(AuthLevel::Basic.as_str(), "basic");
        assert_eq!(AuthLevel::Strong.as_str(), "strong");
        // `Certain` is not a client-visible level yet.
        assert_eq!(AuthLevel::Certain.as_str(), "strong");
    }
}
