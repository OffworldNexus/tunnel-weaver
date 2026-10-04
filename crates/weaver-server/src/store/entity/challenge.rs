//! `challenge` table: persistent ACME challenge records.
//!
//! The apex and wildcard authorisations for one order share the challenge name
//! `_acme-challenge.<root>`, so a name maps to a *set* of TXT values, not a
//! single slot. Rows are only meaningful while an order is in flight; the
//! ACME engine deletes its own rows when the order settles.
//!
//! `kind` separates DNS-01 TXT rows (`dns-01`, `name =
//! _acme-challenge.<root>`, `value = <digest>`) from HTTP-01 token rows
//! (`http-01`, `name = <token>`, `value = <key authorization>`) so the two
//! responders only ever read their own rows.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "challenge")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub name: String,
    pub value: String,
    pub created_at: i64,
    /// `dns-01` (TXT digest) or `http-01` (key authorization).
    pub kind: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
