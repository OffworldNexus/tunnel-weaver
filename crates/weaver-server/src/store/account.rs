//! Email account lifecycle persistence.
//!
//! This module is the only place the account tables are queried. It exposes
//! typed operations and keeps every write inside a transaction so the
//! invariants the spec depends on — one account per address, a single-use
//! verification token, and an atomic activation that links the account to its
//! initial email-verification and password history — hold under concurrency
//! rather than only in the UI.
//!
//! Timestamps are Unix seconds supplied by the caller (the HTTP layer owns the
//! clock), matching the rest of the store's testability posture.

use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, EntityTrait, QueryFilter, QueryOrder, QuerySelect,
    Set, TransactionTrait,
};

use std::collections::{HashMap, HashSet};

use super::entity::{
    account, browser_session, domain, email_identity, email_verification, machine, machine_key_log,
    password_credential, password_reset_token, pending_registration, person, service, usage_daily,
    usage_live, verification_token,
};
use super::{Store, StoreError};

/// Caller-supplied fields for a new in-flight signup.
#[derive(Debug, Clone)]
pub struct NewPendingRegistration {
    /// Random, server-owned opaque flow id (never derived from the email).
    pub flow_id: String,
    /// The display name exactly as entered (Unicode preserved).
    pub name: String,
    /// The address exactly as entered, for display.
    pub email: String,
    /// The trimmed, lowercased address used for uniqueness and lookup.
    pub lookup_key: String,
    pub created_at: i64,
    /// When the emailed link stops working.
    pub expires_at: i64,
}

/// Caller-supplied fields for a newly minted verification token.
#[derive(Debug, Clone)]
pub struct NewVerificationToken {
    pub email_lookup_key: String,
    /// SHA-256 digest (hex) of the raw token; the raw value is never stored.
    pub token_digest: String,
    pub purpose: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Everything the atomic activation needs. The token and pending registration
/// are consumed in the same transaction as the account creation.
#[derive(Debug, Clone)]
pub struct ActivationRequest<'a> {
    pub pending_registration_id: i32,
    /// The token to consume now (the short-lived registration-completion token).
    pub consume_token_id: i32,
    /// The already-consumed email-verification token that proved ownership,
    /// referenced by the verification-history row.
    pub proof_token_id: i32,
    pub name: &'a str,
    pub email: &'a str,
    pub lookup_key: &'a str,
    /// Argon2id PHC-encoded hash for the initial credential.
    pub encoded_hash: &'a str,
    pub now: i64,
}

/// The result of activating a verified signup.
#[derive(Debug, Clone)]
pub enum ActivationOutcome {
    /// The address was new; an account, identity, credential and verification
    /// history row were created.
    Activated(account::Model),
    /// The address already belonged to an account. Ownership is confirmed, but
    /// no credential was written and the existing account is returned so the
    /// caller can offer login without disclosing anything earlier.
    ExistingAccount(account::Model),
}

/// Caller-supplied fields for a newly minted password-reset token.
#[derive(Debug, Clone)]
pub struct NewPasswordResetToken {
    /// SHA-256 digest (hex) of the raw token; the raw value is never stored.
    pub token_digest: String,
    pub issued_at: i64,
    /// When the emailed link stops working.
    pub expires_at: i64,
}

/// Everything the atomic password reset needs. The token is consumed in the
/// same transaction that retires the old credential and kills every session.
#[derive(Debug, Clone)]
pub struct ResetRequest<'a> {
    /// The reset token to consume now.
    pub token_id: i32,
    /// Argon2id PHC-encoded hash for the replacement credential.
    pub encoded_hash: &'a str,
    pub now: i64,
}

impl Store {
    // ----- pending registrations -----

    /// Creates a new in-flight signup.
    pub async fn pending_registration_create(
        &self,
        new: NewPendingRegistration,
    ) -> Result<pending_registration::Model, StoreError> {
        Ok(pending_registration::ActiveModel {
            flow_id: Set(new.flow_id),
            name: Set(new.name),
            email: Set(new.email),
            lookup_key: Set(new.lookup_key),
            created_at: Set(new.created_at),
            expires_at: Set(new.expires_at),
            ..Default::default()
        }
        .insert(&self.db)
        .await?)
    }

    /// Resolves a pending registration by its opaque flow id.
    pub async fn pending_registration_by_flow(
        &self,
        flow_id: &str,
    ) -> Result<Option<pending_registration::Model>, StoreError> {
        Ok(pending_registration::Entity::find()
            .filter(pending_registration::Column::FlowId.eq(flow_id))
            .one(&self.db)
            .await?)
    }

    /// Resolves a pending registration by its stable id.
    pub async fn pending_registration_by_id(
        &self,
        id: i32,
    ) -> Result<Option<pending_registration::Model>, StoreError> {
        Ok(pending_registration::Entity::find_by_id(id)
            .one(&self.db)
            .await?)
    }

    /// Marks a pending registration complete without creating an account (the
    /// existing-address path).
    pub async fn pending_registration_complete(
        &self,
        pending_registration_id: i32,
        now: i64,
    ) -> Result<(), StoreError> {
        mark_pending_complete(&self.db, pending_registration_id, now).await
    }

    // ----- verification tokens -----

    /// Issues a fresh token for a pending registration, revoking that flow's
    /// outstanding unconsumed tokens first so only the latest link works.
    pub async fn verification_token_issue(
        &self,
        pending_registration_id: i32,
        new: NewVerificationToken,
    ) -> Result<verification_token::Model, StoreError> {
        let txn = self.db.begin().await?;
        verification_token::Entity::update_many()
            .col_expr(
                verification_token::Column::RevokedAt,
                Expr::value(Some(new.issued_at)),
            )
            .filter(verification_token::Column::PendingRegistrationId.eq(pending_registration_id))
            .filter(verification_token::Column::ConsumedAt.is_null())
            .filter(verification_token::Column::RevokedAt.is_null())
            .exec(&txn)
            .await?;
        let token = verification_token::ActiveModel {
            pending_registration_id: Set(pending_registration_id),
            email_lookup_key: Set(new.email_lookup_key),
            token_digest: Set(new.token_digest),
            purpose: Set(new.purpose),
            issued_at: Set(new.issued_at),
            expires_at: Set(new.expires_at),
            ..Default::default()
        }
        .insert(&txn)
        .await?;
        txn.commit().await?;
        Ok(token)
    }

    /// Resolves a token by its stored digest.
    pub async fn verification_token_by_digest(
        &self,
        token_digest: &str,
    ) -> Result<Option<verification_token::Model>, StoreError> {
        Ok(verification_token::Entity::find()
            .filter(verification_token::Column::TokenDigest.eq(token_digest))
            .one(&self.db)
            .await?)
    }

    /// The most recently issued token for a pending registration, used to
    /// enforce the resend cooldown.
    pub async fn verification_token_latest_for_flow(
        &self,
        pending_registration_id: i32,
    ) -> Result<Option<verification_token::Model>, StoreError> {
        Ok(verification_token::Entity::find()
            .filter(verification_token::Column::PendingRegistrationId.eq(pending_registration_id))
            .order_by_desc(verification_token::Column::IssuedAt)
            .order_by_desc(verification_token::Column::Id)
            .one(&self.db)
            .await?)
    }

    /// Consumes a token at most once. Returns `false` when it was already
    /// consumed, revoked, or expired.
    pub async fn verification_token_consume(
        &self,
        token_id: i32,
        now: i64,
    ) -> Result<bool, StoreError> {
        let result = verification_token::Entity::update_many()
            .col_expr(
                verification_token::Column::ConsumedAt,
                Expr::value(Some(now)),
            )
            .filter(verification_token::Column::Id.eq(token_id))
            .filter(verification_token::Column::ConsumedAt.is_null())
            .filter(verification_token::Column::RevokedAt.is_null())
            .filter(verification_token::Column::ExpiresAt.gt(now))
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected == 1)
    }

    /// Records the consumed email-verification token that proved ownership of a
    /// registration's address, so the completion step can link the history to it.
    pub async fn pending_registration_set_proved_by(
        &self,
        pending_registration_id: i32,
        token_id: i32,
    ) -> Result<(), StoreError> {
        pending_registration::Entity::update_many()
            .col_expr(
                pending_registration::Column::ProvedByTokenId,
                Expr::value(Some(token_id)),
            )
            .filter(pending_registration::Column::Id.eq(pending_registration_id))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    // ----- password-reset tokens -----

    /// Issues a fresh reset token for an account, revoking that account's
    /// outstanding unconsumed tokens first so only the latest link works.
    pub async fn password_reset_token_issue(
        &self,
        account_id: i32,
        new: NewPasswordResetToken,
    ) -> Result<password_reset_token::Model, StoreError> {
        let txn = self.db.begin().await?;
        password_reset_token::Entity::update_many()
            .col_expr(
                password_reset_token::Column::RevokedAt,
                Expr::value(Some(new.issued_at)),
            )
            .filter(password_reset_token::Column::AccountId.eq(account_id))
            .filter(password_reset_token::Column::ConsumedAt.is_null())
            .filter(password_reset_token::Column::RevokedAt.is_null())
            .exec(&txn)
            .await?;
        let token = password_reset_token::ActiveModel {
            account_id: Set(account_id),
            token_digest: Set(new.token_digest),
            issued_at: Set(new.issued_at),
            expires_at: Set(new.expires_at),
            ..Default::default()
        }
        .insert(&txn)
        .await?;
        txn.commit().await?;
        Ok(token)
    }

    /// Resolves a reset token by its stored digest.
    pub async fn password_reset_token_by_digest(
        &self,
        token_digest: &str,
    ) -> Result<Option<password_reset_token::Model>, StoreError> {
        Ok(password_reset_token::Entity::find()
            .filter(password_reset_token::Column::TokenDigest.eq(token_digest))
            .one(&self.db)
            .await?)
    }

    /// The most recently issued reset token for an account, used to enforce the
    /// resend cooldown.
    pub async fn password_reset_token_latest_for_account(
        &self,
        account_id: i32,
    ) -> Result<Option<password_reset_token::Model>, StoreError> {
        Ok(password_reset_token::Entity::find()
            .filter(password_reset_token::Column::AccountId.eq(account_id))
            .order_by_desc(password_reset_token::Column::IssuedAt)
            .order_by_desc(password_reset_token::Column::Id)
            .one(&self.db)
            .await?)
    }

    /// Consumes a reset token at most once. Returns `false` when it was already
    /// consumed, revoked, or expired.
    pub async fn password_reset_token_consume(
        &self,
        token_id: i32,
        now: i64,
    ) -> Result<bool, StoreError> {
        let result = password_reset_token::Entity::update_many()
            .col_expr(
                password_reset_token::Column::ConsumedAt,
                Expr::value(Some(now)),
            )
            .filter(password_reset_token::Column::Id.eq(token_id))
            .filter(password_reset_token::Column::ConsumedAt.is_null())
            .filter(password_reset_token::Column::RevokedAt.is_null())
            .filter(password_reset_token::Column::ExpiresAt.gt(now))
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected == 1)
    }

    // ----- email identities -----

    /// Resolves an address to its account association by lookup key, if any.
    pub async fn email_identity_find(
        &self,
        lookup_key: &str,
    ) -> Result<Option<email_identity::Model>, StoreError> {
        Ok(email_identity::Entity::find()
            .filter(email_identity::Column::LookupKey.eq(lookup_key))
            .one(&self.db)
            .await?)
    }

    /// The email identity associated with an account. The schema permits one
    /// verified address per account in this slice.
    pub async fn email_identity_for_account(
        &self,
        account_id: i32,
    ) -> Result<Option<email_identity::Model>, StoreError> {
        Ok(email_identity::Entity::find()
            .filter(email_identity::Column::AccountId.eq(account_id))
            .one(&self.db)
            .await?)
    }

    // ----- accounts -----

    /// Fetches an account by its stable id.
    pub async fn account_by_id(&self, id: i32) -> Result<Option<account::Model>, StoreError> {
        Ok(account::Entity::find_by_id(id).one(&self.db).await?)
    }

    /// Records a successful sign-in for `account_id` at `now` (Unix seconds).
    ///
    /// This is the inactivity clock: both the password login and the warning
    /// link's sign-in call it, so any way in resets the clock. The historical
    /// `inactivity_warning_at` is deliberately left in place — it is the record
    /// that a warning went out, and the sweep compares it against the (now more
    /// recent) sign-in to know the cycle restarted.
    pub async fn account_record_login(&self, account_id: i32, now: i64) -> Result<(), StoreError> {
        account::Entity::update_many()
            .col_expr(account::Column::LastLoginAt, Expr::value(Some(now)))
            .filter(account::Column::Id.eq(account_id))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    /// Records that the inactivity warning was emailed to `account_id` at `now`.
    ///
    /// Written only after a successful send, so a failed or absent mailer leaves
    /// the column unset and the next tick may try again.
    pub async fn account_mark_inactivity_warning(
        &self,
        account_id: i32,
        now: i64,
    ) -> Result<(), StoreError> {
        account::Entity::update_many()
            .col_expr(account::Column::InactivityWarningAt, Expr::value(Some(now)))
            .filter(account::Column::Id.eq(account_id))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    /// Hard-deletes an account and everything it owns, atomically.
    ///
    /// This is the "delete my account" path and it is deliberately terminal:
    /// nothing is anonymized, nothing is kept for accounting, and there is no
    /// soft-delete state or recovery window. One transaction removes, in order:
    ///
    /// * the person's materialized hostname rows, by name prefix — the account
    ///   cascade only `SET NULL`s `domains.service_id`, which would leave every
    ///   name behind and keep it reserved;
    /// * the person's `machine_key_log` rows — the one path that overrides the
    ///   "the log outlives the machine and person" rule, because no row may
    ///   still name the person;
    /// * the account itself, cascading person → machine → service →
    ///   `usage_live`/`usage_daily` and the account-scoped rows (browser
    ///   sessions, password credentials, email identity, verification history,
    ///   reset tokens);
    /// * the pre-account `pending_registration` rows that still hold this
    ///   person's address (and, through the foreign key, their
    ///   `verification_token`s) — rows no account cascade reaches.
    ///
    /// The pending-row purge **must** follow the account delete: `email_verification`
    /// references `verification_token` with `RESTRICT`, and only the account
    /// cascade removes those referencing rows first.
    ///
    /// Idempotent: an account that is already gone is the goal state, so a
    /// repeat call commits and returns `Ok(())`.
    pub async fn delete_account(&self, account_id: i32) -> Result<(), StoreError> {
        let txn = self.db.begin().await?;
        let Some(account) = account::Entity::find_by_id(account_id).one(&txn).await? else {
            txn.commit().await?;
            return Ok(());
        };

        // Read the person and the verified address before the cascade removes
        // them; both drive the explicit purges below.
        let person = person::Entity::find()
            .filter(person::Column::AccountId.eq(account_id))
            .one(&txn)
            .await?;
        let identity = email_identity::Entity::find()
            .filter(email_identity::Column::AccountId.eq(account_id))
            .one(&txn)
            .await?;

        if let Some(person) = &person {
            // Person names are `[a-z0-9]{1,15}` with no dash and no `LIKE`
            // metacharacter, so a `name-%` prefix match is exact.
            domain::Entity::delete_many()
                .filter(domain::Column::Name.like(format!("{}-%", person.name)))
                .exec(&txn)
                .await?;
            machine_key_log::Entity::delete_many()
                .filter(machine_key_log::Column::PersonId.eq(person.id))
                .exec(&txn)
                .await?;
        }

        account::Entity::delete_by_id(account_id).exec(&txn).await?;

        // Pre-account rows: match on the verified address when there is one,
        // otherwise on the display name. Name matching is case-folded in Rust
        // because SQLite's `LOWER` is ASCII-only and the name preserves Unicode.
        if let Some(identity) = identity {
            pending_registration::Entity::delete_many()
                .filter(pending_registration::Column::LookupKey.eq(identity.lookup_key))
                .exec(&txn)
                .await?;
        } else {
            let wanted = account.name.trim().to_lowercase();
            let matching: Vec<i32> = pending_registration::Entity::find()
                .all(&txn)
                .await?
                .into_iter()
                .filter(|pending| pending.name.trim().to_lowercase() == wanted)
                .map(|pending| pending.id)
                .collect();
            if !matching.is_empty() {
                pending_registration::Entity::delete_many()
                    .filter(pending_registration::Column::Id.is_in(matching))
                    .exec(&txn)
                    .await?;
            }
        }

        txn.commit().await?;
        Ok(())
    }

    /// Atomically activates a verified signup.
    ///
    /// In one transaction: consume the token (single-use; a replayed or expired
    /// token is refused), then either create the account, identity, credential
    /// and verification history, or — if the address is already associated with
    /// an account — discard the freshly created placeholder account and return
    /// the existing one. The unique `email_identity.lookup_key` plus the
    /// conditional consume make this safe under concurrent activations: at most
    /// one account can ever own an address.
    pub async fn account_activate(
        &self,
        req: ActivationRequest<'_>,
    ) -> Result<ActivationOutcome, StoreError> {
        let txn = self.db.begin().await?;

        // Single-use, unexpired consume. `rows_affected == 0` means a replay, a
        // revoked link, or an expired link — all refused.
        let consumed = verification_token::Entity::update_many()
            .col_expr(
                verification_token::Column::ConsumedAt,
                Expr::value(Some(req.now)),
            )
            .filter(verification_token::Column::Id.eq(req.consume_token_id))
            .filter(verification_token::Column::ConsumedAt.is_null())
            .filter(verification_token::Column::RevokedAt.is_null())
            .filter(verification_token::Column::ExpiresAt.gt(req.now))
            .exec(&txn)
            .await?;
        if consumed.rows_affected == 0 {
            txn.rollback().await?;
            return Err(StoreError::Conflict(
                "verification token is already spent or expired".into(),
            ));
        }

        let created = account::ActiveModel {
            name: Set(req.name.to_string()),
            state: Set("active".to_string()),
            created_at: Set(req.now),
            activated_at: Set(req.now),
            ..Default::default()
        }
        .insert(&txn)
        .await?;

        // Claim the address with the database-level uniqueness guarantee. A
        // conflict here means another activation already owns it.
        let claimed = email_identity::Entity::insert(email_identity::ActiveModel {
            account_id: Set(created.id),
            email: Set(req.email.to_string()),
            lookup_key: Set(req.lookup_key.to_string()),
            created_at: Set(req.now),
            verified_at: Set(Some(req.now)),
            ..Default::default()
        })
        .on_conflict(
            OnConflict::column(email_identity::Column::LookupKey)
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(&txn)
        .await?;

        if claimed == 0 {
            // The address already belongs to an account: drop the placeholder
            // account we just made and hand back the real one. No credential is
            // written and no session is created.
            account::Entity::delete_by_id(created.id).exec(&txn).await?;
            let identity = email_identity::Entity::find()
                .filter(email_identity::Column::LookupKey.eq(req.lookup_key))
                .one(&txn)
                .await?
                .ok_or_else(|| {
                    StoreError::Conflict("address associated with a missing identity".into())
                })?;
            let existing = account::Entity::find_by_id(identity.account_id)
                .one(&txn)
                .await?
                .ok_or_else(|| {
                    StoreError::Conflict("identity references a missing account".into())
                })?;
            mark_pending_complete(&txn, req.pending_registration_id, req.now).await?;
            txn.commit().await?;
            return Ok(ActivationOutcome::ExistingAccount(existing));
        }

        // New address: initial password credential and ownership history.
        password_credential::Entity::insert(password_credential::ActiveModel {
            account_id: Set(created.id),
            encoded_hash: Set(req.encoded_hash.to_string()),
            created_at: Set(req.now),
            retired_at: Set(None),
            ..Default::default()
        })
        .exec_without_returning(&txn)
        .await?;

        let identity = email_identity::Entity::find()
            .filter(email_identity::Column::LookupKey.eq(req.lookup_key))
            .one(&txn)
            .await?
            .ok_or_else(|| StoreError::Conflict("identity missing after claim".into()))?;

        email_verification::Entity::insert(email_verification::ActiveModel {
            account_id: Set(created.id),
            email_identity_id: Set(identity.id),
            token_id: Set(req.proof_token_id),
            verified_at: Set(req.now),
            ..Default::default()
        })
        .exec_without_returning(&txn)
        .await?;

        mark_pending_complete(&txn, req.pending_registration_id, req.now).await?;
        txn.commit().await?;
        Ok(ActivationOutcome::Activated(created))
    }

    // ----- password credentials -----

    /// Atomically applies a password reset.
    ///
    /// In one transaction: consume the reset token (single-use; a replayed,
    /// revoked or expired token is refused), retire the account's current
    /// credential, write the replacement, and invalidate **every** live session
    /// so a reset signs the user out everywhere. The conditional consume keeps
    /// this safe under concurrency: at most one caller can spend a given token.
    pub async fn account_reset_password(
        &self,
        req: ResetRequest<'_>,
    ) -> Result<account::Model, StoreError> {
        let txn = self.db.begin().await?;

        let consumed = password_reset_token::Entity::update_many()
            .col_expr(
                password_reset_token::Column::ConsumedAt,
                Expr::value(Some(req.now)),
            )
            .filter(password_reset_token::Column::Id.eq(req.token_id))
            .filter(password_reset_token::Column::ConsumedAt.is_null())
            .filter(password_reset_token::Column::RevokedAt.is_null())
            .filter(password_reset_token::Column::ExpiresAt.gt(req.now))
            .exec(&txn)
            .await?;
        if consumed.rows_affected == 0 {
            txn.rollback().await?;
            return Err(StoreError::Conflict(
                "reset token is already spent, revoked, or expired".into(),
            ));
        }

        let token = password_reset_token::Entity::find_by_id(req.token_id)
            .one(&txn)
            .await?
            .ok_or_else(|| StoreError::Conflict("reset token vanished after consume".into()))?;
        let account_id = token.account_id;

        let account = match rotate_credential(&txn, account_id, req.encoded_hash, req.now).await {
            Ok(account) => account,
            Err(err) => {
                txn.rollback().await?;
                return Err(err);
            }
        };

        txn.commit().await?;
        Ok(account)
    }

    /// Atomically applies an authenticated password change.
    ///
    /// The caller has already proved the account's current password, so this is
    /// the reset body without the token consume: retire the live credential,
    /// write the replacement, and end **every** session — including the one that
    /// made the request, so the user signs in again with the new password. Both
    /// paths share `rotate_credential`, so a change and a reset cannot drift in
    /// what they guarantee.
    pub async fn account_change_password(
        &self,
        account_id: i32,
        encoded_hash: &str,
        now: i64,
    ) -> Result<account::Model, StoreError> {
        let txn = self.db.begin().await?;

        let account = match rotate_credential(&txn, account_id, encoded_hash, now).await {
            Ok(account) => account,
            Err(err) => {
                txn.rollback().await?;
                return Err(err);
            }
        };

        txn.commit().await?;
        Ok(account)
    }

    /// The current (non-retired) password credential for an account.
    pub async fn password_current_for(
        &self,
        account_id: i32,
    ) -> Result<Option<password_credential::Model>, StoreError> {
        Ok(password_credential::Entity::find()
            .filter(password_credential::Column::AccountId.eq(account_id))
            .filter(password_credential::Column::RetiredAt.is_null())
            .one(&self.db)
            .await?)
    }

    // ----- browser sessions -----

    /// Records a new server-side session for an account.
    pub async fn session_create(
        &self,
        account_id: i32,
        token_hash: &str,
        created_at: i64,
        expires_at: i64,
    ) -> Result<browser_session::Model, StoreError> {
        Ok(browser_session::ActiveModel {
            account_id: Set(account_id),
            token_hash: Set(token_hash.to_string()),
            created_at: Set(created_at),
            expires_at: Set(expires_at),
            invalidated_at: Set(None),
            ..Default::default()
        }
        .insert(&self.db)
        .await?)
    }

    /// Resolves a live (unexpired, uninvalidated) session by cookie token hash.
    pub async fn session_live(
        &self,
        token_hash: &str,
        now: i64,
    ) -> Result<Option<browser_session::Model>, StoreError> {
        Ok(browser_session::Entity::find()
            .filter(browser_session::Column::TokenHash.eq(token_hash))
            .filter(browser_session::Column::InvalidatedAt.is_null())
            .filter(browser_session::Column::ExpiresAt.gt(now))
            .one(&self.db)
            .await?)
    }

    /// Invalidates one session (logout). Returns whether a live row was retired.
    pub async fn session_invalidate(&self, token_hash: &str, now: i64) -> Result<bool, StoreError> {
        let result = browser_session::Entity::update_many()
            .col_expr(
                browser_session::Column::InvalidatedAt,
                Expr::value(Some(now)),
            )
            .filter(browser_session::Column::TokenHash.eq(token_hash))
            .filter(browser_session::Column::InvalidatedAt.is_null())
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected == 1)
    }

    /// Deletes sessions that expired before `cutoff`; returns the count.
    pub async fn session_sweep(&self, cutoff: i64) -> Result<u64, StoreError> {
        let result = browser_session::Entity::delete_many()
            .filter(browser_session::Column::ExpiresAt.lt(cutoff))
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected)
    }

    /// Deletes verification tokens that expired unconsumed before `cutoff`.
    ///
    /// Consumed/revoked rows are deliberately kept: the verification history
    /// references them, and audit provenance outranks table size.
    pub async fn verification_token_sweep(&self, cutoff: i64) -> Result<u64, StoreError> {
        let result = verification_token::Entity::delete_many()
            .filter(verification_token::Column::ConsumedAt.is_null())
            .filter(verification_token::Column::ExpiresAt.lt(cutoff))
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected)
    }

    /// Deletes reset tokens that expired unconsumed before `cutoff`.
    ///
    /// Consumed/revoked rows are deliberately kept as provenance, matching
    /// `verification_token_sweep`.
    pub async fn password_reset_token_sweep(&self, cutoff: i64) -> Result<u64, StoreError> {
        let result = password_reset_token::Entity::delete_many()
            .filter(password_reset_token::Column::ConsumedAt.is_null())
            .filter(password_reset_token::Column::ExpiresAt.lt(cutoff))
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected)
    }

    // ----- inactivity sweep -----

    /// Accounts whose sign-in is at least `threshold_secs` old at `now`, by id,
    /// starting after `after_id` and bounded to `limit` — one page of the
    /// inactivity sweep.
    ///
    /// "Activity" is the later of the last sign-in (or, for an account that has
    /// never signed in, its activation) and the newest day any of its services
    /// was metered — folding `usage_daily` and the live day together. A day
    /// counts at its UTC midnight, which is deliberately a hair conservative:
    /// the threshold is measured in months, so sub-day precision would only ever
    /// delay the sweep. The sign-in prefilter is exact because usage can only
    /// make an account *more* recent.
    ///
    /// Accounts with a live browser session are flagged, not filtered here, so
    /// the caller can still count them.
    pub async fn inactivity_candidates(
        &self,
        now: i64,
        threshold_secs: i64,
        after_id: i32,
        limit: u64,
    ) -> Result<Vec<InactivityCandidate>, StoreError> {
        let cutoff = now.saturating_sub(threshold_secs);
        let accounts = account::Entity::find()
            .filter(account::Column::Id.gt(after_id))
            .filter(account::Column::ActivatedAt.lte(cutoff))
            .filter(
                Condition::any()
                    .add(account::Column::LastLoginAt.is_null())
                    .add(account::Column::LastLoginAt.lte(cutoff)),
            )
            .order_by_asc(account::Column::Id)
            .limit(limit)
            .all(&self.db)
            .await?;
        if accounts.is_empty() {
            return Ok(Vec::new());
        }
        let account_ids: Vec<i32> = accounts.iter().map(|a| a.id).collect();

        let newest_usage = self.newest_usage_day_by_account(Some(&account_ids)).await?;
        let live_sessions: HashSet<i32> = browser_session::Entity::find()
            .filter(browser_session::Column::AccountId.is_in(account_ids.clone()))
            .filter(browser_session::Column::InvalidatedAt.is_null())
            .filter(browser_session::Column::ExpiresAt.gt(now))
            .select_only()
            .column(browser_session::Column::AccountId)
            .into_tuple::<i32>()
            .all(&self.db)
            .await?
            .into_iter()
            .collect();
        let emails: HashMap<i32, String> = email_identity::Entity::find()
            .filter(email_identity::Column::AccountId.is_in(account_ids))
            .all(&self.db)
            .await?
            .into_iter()
            .map(|identity| (identity.account_id, identity.email))
            .collect();

        Ok(accounts
            .into_iter()
            .map(|account| {
                let last_activity = activity_of(
                    account.last_login_at.unwrap_or(account.activated_at),
                    newest_usage.get(&account.id).copied(),
                );
                InactivityCandidate {
                    account_id: account.id,
                    name: account.name,
                    email: emails.get(&account.id).cloned().unwrap_or_default(),
                    last_activity,
                    warning_at: account.inactivity_warning_at,
                    has_live_session: live_sessions.contains(&account.id),
                }
            })
            .collect())
    }

    /// The earliest inactivity event strictly after `after` (Unix seconds), or
    /// `None` when no account has one pending.
    ///
    /// An account's events are its warning, at `activity + warn_after` unless
    /// already sent for this stretch of idleness, and its deletion, at
    /// `activity + delete_after`. Events at or before `after` belong to a tick
    /// that already ran.
    pub async fn inactivity_next_event(
        &self,
        after: i64,
        warn_after: i64,
        delete_after: i64,
    ) -> Result<Option<i64>, StoreError> {
        let accounts: Vec<(i32, i64, Option<i64>, Option<i64>)> = account::Entity::find()
            .select_only()
            .column(account::Column::Id)
            .column(account::Column::ActivatedAt)
            .column(account::Column::LastLoginAt)
            .column(account::Column::InactivityWarningAt)
            .into_tuple()
            .all(&self.db)
            .await?;
        if accounts.is_empty() {
            return Ok(None);
        }
        let newest_usage = self.newest_usage_day_by_account(None).await?;

        Ok(accounts
            .into_iter()
            .flat_map(|(id, activated_at, last_login_at, warning_at)| {
                let activity = activity_of(
                    last_login_at.unwrap_or(activated_at),
                    newest_usage.get(&id).copied(),
                );
                let warned = warning_at.is_some_and(|warned| warned >= activity);
                let warning = (!warned).then(|| activity.saturating_add(warn_after));
                let deletion = activity.saturating_add(delete_after);
                warning.into_iter().chain([deletion])
            })
            .filter(|&at| at > after)
            .min())
    }

    /// The newest metered day per account, across `usage_daily` and the live
    /// day, for the accounts named in `account_ids` (every account on `None`).
    ///
    /// Walks `account → person → machine → service` in a handful of queries
    /// rather than one join per account, and lets the database reduce usage to
    /// one `MAX(day)` per service.
    async fn newest_usage_day_by_account(
        &self,
        account_ids: Option<&[i32]>,
    ) -> Result<HashMap<i32, i64>, StoreError> {
        let mut people = person::Entity::find();
        if let Some(account_ids) = account_ids {
            people = people.filter(person::Column::AccountId.is_in(account_ids.to_vec()));
        }
        let person_to_account: HashMap<i32, i32> = people
            .select_only()
            .column(person::Column::Id)
            .column(person::Column::AccountId)
            .into_tuple::<(i32, i32)>()
            .all(&self.db)
            .await?
            .into_iter()
            .collect();
        if person_to_account.is_empty() {
            return Ok(HashMap::new());
        }

        let mut machines = machine::Entity::find();
        if account_ids.is_some() {
            machines = machines.filter(
                machine::Column::PersonId
                    .is_in(person_to_account.keys().copied().collect::<Vec<_>>()),
            );
        }
        let machine_to_account: HashMap<i32, i32> = machines
            .select_only()
            .column(machine::Column::Id)
            .column(machine::Column::PersonId)
            .into_tuple::<(i32, i32)>()
            .all(&self.db)
            .await?
            .into_iter()
            .filter_map(|(machine, person)| {
                person_to_account
                    .get(&person)
                    .map(|account| (machine, *account))
            })
            .collect();
        if machine_to_account.is_empty() {
            return Ok(HashMap::new());
        }

        let mut services = service::Entity::find();
        if account_ids.is_some() {
            services = services.filter(
                service::Column::MachineId
                    .is_in(machine_to_account.keys().copied().collect::<Vec<_>>()),
            );
        }
        let service_to_account: HashMap<i32, i32> = services
            .select_only()
            .column(service::Column::Id)
            .column(service::Column::MachineId)
            .into_tuple::<(i32, i32)>()
            .all(&self.db)
            .await?
            .into_iter()
            .filter_map(|(service, machine)| {
                machine_to_account
                    .get(&machine)
                    .map(|account| (service, *account))
            })
            .collect();
        if service_to_account.is_empty() {
            return Ok(HashMap::new());
        }

        let service_ids: Option<Vec<i32>> =
            account_ids.map(|_| service_to_account.keys().copied().collect());
        let mut newest: HashMap<i32, i64> = HashMap::new();
        for (service_id, day) in self.newest_day_by_service(service_ids.as_deref()).await? {
            if let Some(account_id) = service_to_account.get(&service_id) {
                newest
                    .entry(*account_id)
                    .and_modify(|current| *current = (*current).max(day))
                    .or_insert(day);
            }
        }
        Ok(newest)
    }

    /// The newest metered day per service, folded or live, for `service_ids`
    /// (every service on `None`).
    async fn newest_day_by_service(
        &self,
        service_ids: Option<&[i32]>,
    ) -> Result<Vec<(i32, i64)>, StoreError> {
        let mut folded = usage_daily::Entity::find();
        let mut live = usage_live::Entity::find();
        if let Some(service_ids) = service_ids {
            folded = folded.filter(usage_daily::Column::ServiceId.is_in(service_ids.to_vec()));
            live = live.filter(usage_live::Column::ServiceId.is_in(service_ids.to_vec()));
        }
        let mut days: Vec<(i32, i64)> = folded
            .select_only()
            .column(usage_daily::Column::ServiceId)
            .column_as(usage_daily::Column::Day.max(), "day")
            .group_by(usage_daily::Column::ServiceId)
            .into_tuple::<(i32, i64)>()
            .all(&self.db)
            .await?;
        days.extend(
            live.select_only()
                .column(usage_live::Column::ServiceId)
                .column_as(usage_live::Column::Day.max(), "day")
                .group_by(usage_live::Column::ServiceId)
                .into_tuple::<(i32, i64)>()
                .all(&self.db)
                .await?,
        );
        Ok(days)
    }
}

/// An account's last activity: its sign-in (or activation) or, when later, the
/// UTC midnight of its newest metered day.
fn activity_of(sign_in: i64, newest_day: Option<i64>) -> i64 {
    newest_day.map_or(sign_in, |day| sign_in.max(day.saturating_mul(86_400)))
}

/// One account the inactivity sweep should consider (WVR-160).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InactivityCandidate {
    pub account_id: i32,
    /// Display name, for logs and the email's greeting.
    pub name: String,
    /// The account's verified address, empty when it has none.
    pub email: String,
    /// Unix seconds of last activity: the later of the last sign-in (or
    /// activation) and the newest metered day.
    pub last_activity: i64,
    /// When the inactivity warning was last sent, if ever.
    pub warning_at: Option<i64>,
    /// Whether a live (unexpired, uninvalidated) browser session exists. A live
    /// session means "active right now" and must never be swept.
    pub has_live_session: bool,
}

/// Marks a pending registration complete inside a caller's transaction.
async fn mark_pending_complete<C: sea_orm::ConnectionTrait>(
    conn: &C,
    pending_registration_id: i32,
    now: i64,
) -> Result<(), StoreError> {
    pending_registration::Entity::update_many()
        .col_expr(
            pending_registration::Column::CompletedAt,
            Expr::value(Some(now)),
        )
        .filter(pending_registration::Column::Id.eq(pending_registration_id))
        .exec(conn)
        .await?;
    Ok(())
}

/// Retires an account's current credential, writes the replacement, and ends
/// every live session — the shared body of the reset and change-password paths,
/// so the two cannot diverge in what they guarantee.
///
/// The retire step is conditional on the row still being live and is required to
/// affect exactly one row: if it does not, the account has no credential to
/// rotate and the caller's transaction is abandoned. That also closes the race
/// where two concurrent changes both pass their (out-of-transaction) check of the
/// current password — only one can retire the credential, the other is refused.
async fn rotate_credential<C: sea_orm::ConnectionTrait>(
    conn: &C,
    account_id: i32,
    encoded_hash: &str,
    now: i64,
) -> Result<account::Model, StoreError> {
    let retired = password_credential::Entity::update_many()
        .col_expr(
            password_credential::Column::RetiredAt,
            Expr::value(Some(now)),
        )
        .filter(password_credential::Column::AccountId.eq(account_id))
        .filter(password_credential::Column::RetiredAt.is_null())
        .exec(conn)
        .await?;
    if retired.rows_affected != 1 {
        return Err(StoreError::Conflict(
            "account has no live password credential to rotate".into(),
        ));
    }

    password_credential::Entity::insert(password_credential::ActiveModel {
        account_id: Set(account_id),
        encoded_hash: Set(encoded_hash.to_string()),
        created_at: Set(now),
        retired_at: Set(None),
        ..Default::default()
    })
    .exec_without_returning(conn)
    .await?;

    // A credential change ends every existing session ("signed out everywhere").
    invalidate_sessions_for_account(conn, account_id, now).await?;

    account::Entity::find_by_id(account_id)
        .one(conn)
        .await?
        .ok_or_else(|| StoreError::Conflict("account missing during credential rotation".into()))
}

/// Invalidates every live session for an account inside a caller's transaction.
async fn invalidate_sessions_for_account<C: sea_orm::ConnectionTrait>(
    conn: &C,
    account_id: i32,
    now: i64,
) -> Result<u64, StoreError> {
    let result = browser_session::Entity::update_many()
        .col_expr(
            browser_session::Column::InvalidatedAt,
            Expr::value(Some(now)),
        )
        .filter(browser_session::Column::AccountId.eq(account_id))
        .filter(browser_session::Column::InvalidatedAt.is_null())
        .exec(conn)
        .await?;
    Ok(result.rows_affected)
}
