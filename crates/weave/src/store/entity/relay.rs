//! `relay` table: one row per relay this machine is paired with.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "relay")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// The relay's normalised admin host (`host` or `host:port`) — the one
    /// address the client dials, for pairing and for tunnels alike.
    #[sea_orm(unique)]
    pub admin_host: String,
    /// This machine's id on that relay, kept to re-attach the machine to a
    /// new key when the old one is lost.
    pub machine_id: i32,
    /// The device-key fingerprint (`p256:<hex>`) authorised there.
    pub key_id: String,
    /// Whether this is the relay used when none is named. At most one row is.
    pub is_default: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
