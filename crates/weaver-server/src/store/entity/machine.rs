//! `machine` table: client machines belonging to a person.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "machine")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub person_id: i32,
    pub name: String,
    pub created_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::person::Entity",
        from = "Column::PersonId",
        to = "super::person::Column::Id",
        on_delete = "Cascade"
    )]
    Person,
    #[sea_orm(has_many = "super::machine_key::Entity")]
    MachineKeys,
    #[sea_orm(has_many = "super::service::Entity")]
    Services,
}

impl Related<super::person::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Person.def()
    }
}

impl Related<super::machine_key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::MachineKeys.def()
    }
}

impl Related<super::service::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Services.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
