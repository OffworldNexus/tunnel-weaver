//! `person` table: the tunnel-namespace owner behind an account.
//!
//! An account has exactly one person, and a person belongs to exactly one
//! account: `account_id` is unique and cascades, so deleting an account takes
//! its person — and with it every machine, service and hostname — along.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "person")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// The person slug: the first segment of every hostname.
    #[sea_orm(unique)]
    pub name: String,
    pub created_at: i64,
    /// The account this person belongs to.
    #[sea_orm(unique)]
    pub account_id: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::machine::Entity")]
    Machines,
    #[sea_orm(
        belongs_to = "super::account::Entity",
        from = "Column::AccountId",
        to = "super::account::Column::Id",
        on_delete = "Cascade"
    )]
    Account,
}

impl Related<super::machine::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Machines.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
