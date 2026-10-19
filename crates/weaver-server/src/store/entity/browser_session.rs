//! `browser_session` table: server-side browser sessions.
//!
//! The opaque cookie secret is stored only as a digest; `invalidated_at` retires
//! a session without deleting the row, so a replayed cookie finds a dead row
//! rather than no row.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "browser_session")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub account_id: i32,
    #[sea_orm(unique)]
    pub token_hash: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub invalidated_at: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::account::Entity",
        from = "Column::AccountId",
        to = "super::account::Column::Id",
        on_delete = "Cascade"
    )]
    Account,
}

impl Related<super::account::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Account.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
