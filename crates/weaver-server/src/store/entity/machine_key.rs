//! `machine_key` table: authorized public keys for machines.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "machine_key")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub machine_id: i32,
    #[sea_orm(unique)]
    pub key_id: String,
    pub created_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::machine::Entity",
        from = "Column::MachineId",
        to = "super::machine::Column::Id",
        on_delete = "Cascade"
    )]
    Machine,
}

impl Related<super::machine::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Machine.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
