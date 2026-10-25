//! The ordered authentication strength of a session.
//!
//! `None` is "no session" and is never stored. `Basic` is the password alone,
//! `Strong` adds the second factor, `Certain` is `Strong` plus a password typed
//! moments ago — what a sensitive action will ask for (WVR-165). Each is a
//! level of its own, on the wire too: a client planning an action needs to
//! know which one it holds and which one the action needs.

/// How strongly a request has been authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthLevel {
    /// No session at all.
    None,
    /// A session exists and one factor (the password) is proven.
    Basic,
    /// The second factor (the emailed code) is alive.
    Strong,
    /// `Strong` plus a password re-typed moments ago.
    Certain,
}

impl AuthLevel {
    /// Every level, weakest first.
    pub const ALL: [AuthLevel; 4] = [
        AuthLevel::None,
        AuthLevel::Basic,
        AuthLevel::Strong,
        AuthLevel::Certain,
    ];

    /// The wire name, used in the `GET /api/account/me` stream and the gate's
    /// refusal headers.
    pub const fn as_str(self) -> &'static str {
        match self {
            AuthLevel::None => "none",
            AuthLevel::Basic => "basic",
            AuthLevel::Strong => "strong",
            AuthLevel::Certain => "certain",
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
    fn wire_names_are_stable_and_distinct() {
        let names: Vec<&str> = AuthLevel::ALL.iter().map(|level| level.as_str()).collect();
        assert_eq!(names, ["none", "basic", "strong", "certain"]);
    }
}
