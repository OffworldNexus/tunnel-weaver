//! `acme_account` table: one registered ACME account per directory URL.
//!
//! `credentials_json` holds the serialized `instant_acme::AccountCredentials`
//! (private key + account URL), which is what is needed to resume the account.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "acme_account")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub directory: String,
    pub email: String,
    pub credentials_json: String,
    pub kid: Option<String>,
    pub created_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
