//! `domains` table: materialized flat service hostnames.
//!
//! Each row's `name` is the full `<person>-<machine>-<service>.<root>` label
//! derived from entity names, so an incoming `Host` resolves to its service in
//! one join. `certificate_id` points at the certificate covering the name; in
//! the wildcard model every domain shares the single apex certificate, so the
//! column is the routing half of "one cert covers all tunnels".

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
    pub certificate_id: Option<i32>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::certificate::Entity",
        from = "Column::CertificateId",
        to = "super::certificate::Column::Id",
        on_update = "Cascade",
        on_delete = "SetNull"
    )]
    Certificate,
    #[sea_orm(
        belongs_to = "super::service::Entity",
        from = "Column::ServiceId",
        to = "super::service::Column::Id",
        on_delete = "SetNull"
    )]
    Service,
}

impl Related<super::certificate::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Certificate.def()
    }
}

impl Related<super::service::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Service.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
