//! `certificates` table: issued TLS certificates.
//!
//! One row per certificate, keyed by its own `name`. In the wildcard model
//! there is exactly one row — the `[<root>, *.<root>]` certificate held under
//! the zone apex — but the table itself does not hard-code that cardinality so
//! a future per-name path could return without a schema change. `domains`
//! references rows here.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "certificates")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub name: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub not_before: i64,
    pub not_after: i64,
    pub issuer: Option<String>,
    pub directory: String,
    pub obtained_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::domain::Entity")]
    Domains,
}

impl Related<super::domain::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Domains.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
