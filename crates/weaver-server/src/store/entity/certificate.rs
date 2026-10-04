//! `certificates` table: issued TLS certificates.
//!
//! One row per certificate, keyed by its own `name`. In the OFF-198 model there
//! are two long-lived rows — the `[<root>, *.<root>]` tunnel wildcard held
//! under the zone apex, and the single-name admin certificate held under the
//! admin domain — but the table itself does not hard-code that cardinality so
//! a future per-name path could return without a schema change. `domains`
//! references rows here.
//!
//! `validation` records the ACME mechanism (`dns-01` vs `http-01`) so renewal
//! can be dispatched per row without re-deriving it from the name.

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
    /// ACME validation mechanism that produced this row: `dns-01` for the
    /// tunnel wildcard, `http-01` for the relay's admin certificate.
    pub validation: String,
    /// Whether the certificate carries a wildcard SAN (`*.<root>`). Persisted
    /// so `cert status` can label a row without re-deriving it from the name.
    pub wildcard: bool,
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
