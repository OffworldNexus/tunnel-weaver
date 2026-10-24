//! The real-time change bus behind the console's SSE streams (WVR-25).
//!
//! A console stream is one [`View`](crate::account::views::View) re-rendered
//! whenever something it showed has changed. Three things describe a change:
//!
//! * a **viewer scope** — whose consoles may see it (one person, one account's
//!   sessions, everyone, or an organisation later);
//! * an **entity scope** — what kind of thing changed (a machine, a tunnel, the
//!   metered statistics, or a session's authentication);
//! * and, optionally, **which ids** of that entity changed.
//!
//! A view declares the opposite: the [`Interest`]s its last render is sensitive
//! to (`this machine id`, or `every machine`). A change invalidates a view when
//! the viewer matches and the entity matches, with the id sets intersecting — or
//! when the change carries no ids at all, which means *every* view of the entity
//! (an addition or a removal changes the set, so nobody's snapshot survives).
//!
//! The payload is deliberately absent. A stream re-reads its whole resource, so
//! a change only has to say *whether* a view is stale, never *what* it now
//! holds. That keeps the bus cheap and keeps each view the single source of
//! truth for the shape it sends.

use std::collections::BTreeSet;

use tokio::sync::broadcast;

/// How many changes may be queued for a subscriber that has fallen behind. A
/// lagged subscriber is told so and re-reads everything, so the buffer only
/// needs to absorb a burst: `Lagged` is a correctness-safe outcome, not loss.
const CAPACITY: usize = 256;

/// Whose console may see a change.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Viewer {
    /// Every signed-in console, whatever the person.
    Anyone,
    /// One person's consoles only.
    Person(i32),
    /// One account's sessions — wider than a person, because an account that
    /// has not paired yet has no person but still has sessions to watch.
    Account(i32),
}

impl Viewer {
    /// Whether a change announced to `self` reaches a console scoped to
    /// `subscriber`. `Anyone` is global; anything else must match exactly.
    fn reaches(self, subscriber: Viewer) -> bool {
        self == Viewer::Anyone || self == subscriber
    }
}

/// What a change is about.
///
/// [`Entity::Statistics`] is a *meta* entity: it carries no ids, because the
/// metered rollup is one figure per person rather than a set of rows.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Entity {
    /// A machine's identity or presence: added, revoked, renamed, online/offline.
    Machine,
    /// A service tunnel's live state.
    Tunnel,
    /// The metered traffic rollup. Meta — carries no ids.
    Statistics,
    /// A browser session's authentication: its level rose, or it ended. The
    /// ids are session ids; none means every session of the account (a
    /// password change or a deletion retires them all). WVR-167.
    Session,
}

/// The ids a change touches, or that a view cares about.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Ids {
    /// Every id of the entity. An addition or a removal changes the set, so it
    /// reaches every view of the entity, whatever ids it happens to show.
    All,
    /// A specific set.
    Only(BTreeSet<i32>),
}

impl Ids {
    /// Whether a change carrying `self` must reach an interest holding `other`.
    /// An entity-wide side reaches everything; two id sets must intersect.
    fn touches(&self, other: &Ids) -> bool {
        match (self, other) {
            (Ids::All, _) | (_, Ids::All) => true,
            (Ids::Only(change), Ids::Only(interest)) => !change.is_disjoint(interest),
        }
    }
}

/// A published change: who can see it, and what it is about.
#[derive(Clone, Debug)]
pub struct Change {
    viewer: Viewer,
    /// `None` invalidates every view in the viewer's scope.
    entity: Option<Entity>,
    /// `Ids::All` means every id of `entity`; ignored when `entity` is `None`.
    ids: Ids,
}

impl Change {
    /// A change visible to `viewer` about nothing in particular: every view in
    /// that scope is invalidated.
    pub fn visible_to(viewer: Viewer) -> Self {
        Self {
            viewer,
            entity: None,
            ids: Ids::All,
        }
    }

    /// Narrows the change to `entity`. With no ids it invalidates every view of
    /// that entity.
    pub fn entity(mut self, entity: Entity) -> Self {
        self.entity = Some(entity);
        self.ids = Ids::All;
        self
    }

    /// Narrows the change to one id of the entity.
    pub fn id(mut self, id: i32) -> Self {
        self.select(id);
        self
    }

    /// Narrows the change to several ids of the entity.
    pub fn ids(mut self, ids: impl IntoIterator<Item = i32>) -> Self {
        for id in ids {
            self.select(id);
        }
        self
    }

    fn select(&mut self, id: i32) {
        match &mut self.ids {
            Ids::All => {
                self.ids = Ids::Only(BTreeSet::from([id]));
            }
            Ids::Only(set) => {
                set.insert(id);
            }
        }
    }

    /// Whether this change makes a view scoped to `viewer` with these interests
    /// stale.
    pub fn invalidates(&self, viewer: Viewer, interests: &[Interest]) -> bool {
        if !self.viewer.reaches(viewer) {
            return false;
        }
        let Some(entity) = self.entity else {
            return true;
        };
        interests
            .iter()
            .any(|interest| interest.entity == entity && self.ids.touches(&interest.ids))
    }
}

/// What a view listens to: an entity, and which of its ids the view's last
/// render mentioned.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Interest {
    /// The entity the view cares about.
    pub entity: Entity,
    /// Which ids of it the view showed.
    pub ids: Ids,
}

impl Interest {
    /// Any change to `entity`, whatever the id.
    pub fn all(entity: Entity) -> Self {
        Self {
            entity,
            ids: Ids::All,
        }
    }

    /// Only changes touching one of `ids` — or an entity-wide change (an
    /// addition or a removal).
    pub fn these(entity: Entity, ids: impl IntoIterator<Item = i32>) -> Self {
        Self {
            entity,
            ids: Ids::Only(ids.into_iter().collect()),
        }
    }
}

/// The per-viewer change fan-out shared by the tunnel registry, the account
/// plane and the metering flush.
#[derive(Clone)]
pub struct LiveHub {
    tx: broadcast::Sender<Change>,
}

impl LiveHub {
    /// Creates an empty hub. A hub with no subscriber is the normal state on a
    /// relay whose console is closed: publishes are dropped and nothing runs.
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(CAPACITY);
        Self { tx }
    }

    /// Announces that a change happened.
    ///
    /// Always safe to call: with no live subscriber the change is discarded,
    /// and a slow subscriber that has overflowed the buffer is woken with
    /// `Lagged` and re-reads everything anyway.
    pub fn publish(&self, change: Change) {
        let _ = self.tx.send(change);
    }

    /// Subscribes a stream to every change; a stream filters for the viewer
    /// scope and interests of its own view.
    pub fn subscribe(&self) -> broadcast::Receiver<Change> {
        self.tx.subscribe()
    }
}

impl Default for LiveHub {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn person() -> Viewer {
        Viewer::Person(7)
    }

    #[test]
    fn a_change_only_reaches_its_viewer() {
        let change = Change::visible_to(person()).entity(Entity::Machine);
        assert!(change.invalidates(person(), &[Interest::all(Entity::Machine)]));
        assert!(!change.invalidates(Viewer::Person(8), &[Interest::all(Entity::Machine)]));
        // A global change reaches every viewer.
        let global = Change::visible_to(Viewer::Anyone).entity(Entity::Machine);
        assert!(global.invalidates(Viewer::Person(8), &[Interest::all(Entity::Machine)]));
    }

    #[test]
    fn a_scopeless_change_invalidates_everything_in_scope() {
        let change = Change::visible_to(person());
        assert!(change.invalidates(person(), &[Interest::all(Entity::Machine)]));
        assert!(change.invalidates(person(), &[]));
    }

    #[test]
    fn an_id_change_only_reaches_views_showing_that_id() {
        let renamed = Change::visible_to(person()).entity(Entity::Machine).id(3);
        // A view showing machine 3 re-reads; one showing 9 does not.
        assert!(renamed.invalidates(person(), &[Interest::these(Entity::Machine, [3, 5])]));
        assert!(!renamed.invalidates(person(), &[Interest::these(Entity::Machine, [9])]));
        // A view showing every machine re-reads.
        assert!(renamed.invalidates(person(), &[Interest::all(Entity::Machine)]));
    }

    #[test]
    fn an_entity_wide_change_reaches_every_view_of_the_entity() {
        // An addition has no ids: everyone showing that entity re-reads.
        let added = Change::visible_to(person()).entity(Entity::Machine);
        assert!(added.invalidates(person(), &[Interest::these(Entity::Machine, [9])]));
        // But not a view of a different entity.
        assert!(!added.invalidates(person(), &[Interest::all(Entity::Tunnel)]));
    }

    #[test]
    fn a_session_change_reaches_that_session_or_all_of_the_account() {
        let account = Viewer::Account(4);
        let watching = [Interest::these(Entity::Session, [11])];
        let verified = Change::visible_to(account).entity(Entity::Session).id(11);
        assert!(verified.invalidates(account, &watching));
        let elsewhere = Change::visible_to(account).entity(Entity::Session).id(12);
        assert!(!elsewhere.invalidates(account, &watching));
        // A password change retires every session of the account.
        let everywhere = Change::visible_to(account).entity(Entity::Session);
        assert!(everywhere.invalidates(account, &watching));
        // An account scope is not a person scope, even with the same number.
        assert!(!everywhere.invalidates(Viewer::Person(4), &watching));
    }

    #[test]
    fn a_meta_change_reaches_every_view_that_listens_for_it() {
        let stats = Change::visible_to(person()).entity(Entity::Statistics);
        assert!(stats.invalidates(person(), &[Interest::all(Entity::Statistics)]));
        assert!(!stats.invalidates(person(), &[Interest::all(Entity::Machine)]));
    }
}
