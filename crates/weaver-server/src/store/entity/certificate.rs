//! `certificates` table: issued TLS certificates keyed by lowercase hostname.
//!
//! `last_active_at` is `NULL` for hostnames no tunnel currently serves; the
//! renewal loop skips those so unused certificates are allowed to lapse.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "certificates")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub name: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub not_before: i64,
    pub not_after: i64,
    pub issuer: Option<String>,
    pub directory: String,
    pub obtained_at: i64,
    pub last_active_at: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
