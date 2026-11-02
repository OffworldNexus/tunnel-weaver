//! Keeping linked provider grants live, and revoking the sessions they act for
//! when a provider rejects one (WVR-169, provider-neutral since WVR-175).
//!
//! A rejected refresh is the only account-status signal a third-party relying
//! party gets from a direct provider, so it is handled fail-closed: the stored
//! grant is dropped and every live session of the account has its trail ended
//! with an `identity_provider_grant_invalid` row, which the level derivation
//! treats exactly like a logout. It is never recorded as "the account was
//! deleted": a provider rejection says the grant is no longer valid, not why.

use tracing::warn;

use super::{RefreshOutcome, SsoProviders};
use crate::account::auth::EventKind;
use crate::scheduler::Task;
use crate::store::account::NewAuthEvent;
use crate::store::entity::external_identity;
use crate::store::{Store, StoreError};

/// How often the refresh runs: well inside the shortest access-token lifetime,
/// so a revoked grant is noticed long before anything it guards would lapse.
const INTERVAL_SECS: i64 = 3600;

/// The housekeeping task over every stored grant, for every enabled provider.
pub struct SsoRefreshTask {
    providers: SsoProviders,
    store: Store,
}

impl SsoRefreshTask {
    pub fn new(providers: SsoProviders, store: Store) -> Self {
        Self { providers, store }
    }

    async fn refresh_all(&self, now: i64) -> Result<(), StoreError> {
        for identity in self.store.external_identity_with_refresh().await? {
            // A provider the operator has disabled keeps its linked identities
            // working (and its grants intact): only an enabled one can refresh.
            let Some(provider) = self.providers.get(&identity.provider) else {
                continue;
            };
            self.refresh_one(&*provider, &identity, now).await?;
        }
        Ok(())
    }

    async fn refresh_one(
        &self,
        provider: &dyn super::IdentityProvider,
        identity: &external_identity::Model,
        now: i64,
    ) -> Result<(), StoreError> {
        // A grant that cannot be opened (a rotated `sso_key`) is dropped rather
        // than retried forever.
        let Ok(refresh_token) = self
            .providers
            .open(&identity.provider, &identity.refresh_token)
        else {
            return self
                .store
                .external_identity_clear_refresh(identity.id)
                .await;
        };
        match provider.refresh(&refresh_token).await {
            RefreshOutcome::Rotated(fresh) => {
                if let Ok(sealed) = self.providers.seal_refresh(&identity.provider, &fresh) {
                    self.store
                        .external_identity_rotate_refresh(identity.id, &sealed, now)
                        .await?;
                }
            }
            RefreshOutcome::Rejected => {
                self.store
                    .external_identity_clear_refresh(identity.id)
                    .await?;
                self.revoke_sessions(identity.account_id, now).await?;
            }
            RefreshOutcome::Unavailable(error) => {
                warn!(%error, provider = identity.provider, "provider refresh unavailable; will retry");
            }
            // Nothing to rotate (a broker token, or a provider that kept the
            // stored grant valid): the identity keeps what it has.
            RefreshOutcome::Unsupported => {}
        }
        Ok(())
    }

    /// Ends the trail of every live session of the account.
    async fn revoke_sessions(&self, account_id: i32, now: i64) -> Result<(), StoreError> {
        warn!(
            account_id,
            "upstream grant no longer valid; revoking its sessions"
        );
        for session_id in self
            .store
            .live_session_ids_for_account(account_id, now)
            .await?
        {
            self.store
                .auth_event_insert(NewAuthEvent {
                    account_id: Some(account_id),
                    session_id: Some(session_id),
                    kind: EventKind::IdentityProviderGrantInvalid.as_str().to_string(),
                    occurred_at: now,
                    ip_address: String::new(),
                    user_agent: String::new(),
                    attempted: String::new(),
                    detail: String::new(),
                })
                .await?;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Task for SsoRefreshTask {
    fn name(&self) -> &'static str {
        "sso-refresh"
    }

    async fn next_tick(&self, last_tick: Option<i64>, now: i64) -> i64 {
        match last_tick {
            None => now,
            Some(tick) => tick.saturating_add(INTERVAL_SECS),
        }
    }

    async fn run(&self, tick: i64) {
        if let Err(error) = self.refresh_all(tick).await {
            warn!(%error, "provider grant refresh failed");
        }
    }
}
