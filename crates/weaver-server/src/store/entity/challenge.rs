//! `challenge` table: persistent, multi-value ACME DNS-01 challenge records.
//!
//! The apex and wildcard authorisations for one order share the challenge name
//! `_acme-challenge.<root>`, so a name maps to a *set* of TXT values, not a
//! single slot. Rows are only meaningful while an order is in flight; the
//! ACME engine deletes its own rows when the order settles.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "challenge")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub name: String,
    pub value: String,
    pub created_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
