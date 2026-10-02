//! `usage` table: per-service, per-minute metering buckets.
//!
//! The primary key is `(service_id, minute)`, where `minute` is the minute
//! number since the Unix epoch (`unix_seconds / 60`). `unused_ms` is stored
//! inverted (`60_000 - open_ms`) so the common "service was up the whole
//! minute" case is the zero value; readers turn it back into `open_ms` in
//! exactly one place (`Store::query_usage`).

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "usage")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub service_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub minute: i64,
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub requests: i64,
    pub unused_ms: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::service::Entity",
        from = "Column::ServiceId",
        to = "super::service::Column::Id",
        on_delete = "Cascade"
    )]
    Service,
}

impl Related<super::service::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Service.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
