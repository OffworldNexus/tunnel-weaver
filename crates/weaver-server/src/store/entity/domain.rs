//! `domains` table: materialized flat service hostnames.
//!
//! Each row's `name` is the full `<person>-<machine>-<service>.<root>` label
//! derived from entity names, so an incoming `Host` resolves to its service in
//! one join. The certificate covering a name is resolved at run time by the
//! certificate registry (`cert::ManagedCerts`), not stored as a foreign key: a
//! domain does not own its certificate, it is merely covered by one.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "domains")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub name: String,
    pub last_active_at: Option<i64>,
    pub service_id: Option<i32>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::service::Entity",
        from = "Column::ServiceId",
        to = "super::service::Column::Id",
        on_delete = "SetNull"
    )]
    Service,
}

impl Related<super::service::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Service.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
