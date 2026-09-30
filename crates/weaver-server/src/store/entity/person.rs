//! `person` table: identity namespace owners (users/accounts).

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "person")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub name: String,
    pub created_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::machine::Entity")]
    Machines,
}

impl Related<super::machine::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Machines.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
