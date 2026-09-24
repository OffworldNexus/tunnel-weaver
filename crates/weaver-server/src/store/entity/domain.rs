//! `domains` table: registered hostnames/domains and their activity tracking.
//!
//! `last_active_at` is `NULL` for hostnames no tunnel currently serves; the
//! renewal loop skips those so unused certificates are allowed to lapse.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "domains")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub name: String,
    pub last_active_at: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::certificate::Entity")]
    Certificates,
}

impl Related<super::certificate::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Certificates.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
