//! `altcha_client` table: registered ALTCHA API clients.
//!
//! A client is either a tunnelled *service* (`service_id` set) or the relay's
//! *internal* client (`service_id` null) that serves the admin domain. The
//! `secret` signs that client's challenges; `algorithm`/`cost`/`key_length`/
//! `key_prefix` are the server-approved work parameters; `ttl_secs` bounds a
//! challenge's life. `revoked_at` retires a client without deleting its row.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "altcha_client")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub public_key: String,
    pub secret: String,
    pub algorithm: String,
    pub cost: i32,
    pub key_length: i32,
    pub key_prefix: String,
    pub ttl_secs: i64,
    pub service_id: Option<i32>,
    pub created_at: i64,
    pub rotated_at: i64,
    pub revoked_at: Option<i64>,
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
