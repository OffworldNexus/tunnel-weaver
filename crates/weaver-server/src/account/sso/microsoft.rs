//! Microsoft Entra ID as an external identity provider (WVR-169, ported onto the
//! provider registry by WVR-175).
//!
//! Everything protocol-shaped lives in [`super::oidc`]. This file holds only the
//! facts Entra brings: where its tenant-scoped discovery document lives, that
//! `iss` is `https://login.microsoftonline.com/{tid}/v2.0` rather than a single
//! fixed string when the authority is a shared endpoint, the `common`/
//! `organizations`/`consumers` tenant matrix, and how its claims map onto an
//! [`Assertion`].

use std::sync::Arc;

use super::RefreshOutcome;
use super::oidc::{IssuerRule, OidcClient, OidcSettings, TokenError, VerifyError};
use super::{Assertion, Entry, IdentityProvider, Prompt, ProviderError};

/// The provider id: the route segment, the registry key and the seal AAD.
pub const ID: &str = "microsoft";

/// The Microsoft identity platform's fixed host.
const LOGIN_HOST: &str = "login.microsoftonline.com";

/// The tenant id Microsoft uses for personal Microsoft accounts.
const MSA_TENANT: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";

/// The scopes every grant asks for: the ID token, and a refresh token.
const SCOPE: &str = "openid profile email offline_access";

/// The enabled Microsoft provider.
pub struct Microsoft {
    client: OidcClient,
    authority: String,
}

impl Microsoft {
    /// Builds the provider from the values its preset carries.
    pub fn from_preset(
        authority: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<Option<Arc<Self>>, String> {
        Ok(Some(Arc::new(Self {
            client: OidcClient::new(OidcSettings {
                discovery_url: format!(
                    "https://{LOGIN_HOST}/{authority}/v2.0/.well-known/openid-configuration"
                ),
                client_id: client_id.to_string(),
                client_secret: client_secret.to_string(),
                scopes: SCOPE.to_string(),
                issuer: IssuerRule::TenantTemplate {
                    prefix: format!("https://{LOGIN_HOST}/"),
                    suffix: "/v2.0".to_string(),
                },
                authorize_params: Vec::new(),
            })?,
            authority: authority.to_string(),
        })))
    }

    /// The `tid` matrix for the configured authority: which tenants may sign in.
    fn tenant_allowed(&self, tid: &str) -> bool {
        let is_guid = tid.len() == 36 && tid.chars().filter(|c| *c == '-').count() == 4;
        if !is_guid {
            return false;
        }
        match self.authority.to_ascii_lowercase().as_str() {
            // Any work or school tenant, but not a personal account.
            "organizations" => !tid.eq_ignore_ascii_case(MSA_TENANT),
            // Work, school, and personal.
            "common" => true,
            // Personal only.
            "consumers" => tid.eq_ignore_ascii_case(MSA_TENANT),
            // A specific tenant.
            tenant => tid.eq_ignore_ascii_case(tenant),
        }
    }
}

/// The authorization `prompt` value for the reason the flow exists.
fn prompt_value(prompt: Prompt) -> &'static str {
    match prompt {
        Prompt::SignIn => "select_account",
        Prompt::StepUp { .. } => "login",
    }
}

#[async_trait::async_trait]
impl IdentityProvider for Microsoft {
    fn id(&self) -> &'static str {
        ID
    }

    fn label(&self) -> &'static str {
        "Microsoft"
    }

    fn entry(&self) -> Entry {
        Entry::Redirect
    }

    async fn authorize_url(
        &self,
        flow: &super::PendingFlow,
        prompt: Prompt,
    ) -> Result<String, ProviderError> {
        let max_age = match prompt {
            Prompt::SignIn => None,
            Prompt::StepUp { max_age } => Some(max_age),
        };
        self.client
            .authorize_url(
                &flow.redirect_uri,
                &flow.state,
                &flow.nonce,
                &flow.code_verifier,
                prompt_value(prompt),
                max_age,
            )
            .await
            .map_err(|error| {
                tracing::warn!(%error, "Microsoft discovery failed");
                ProviderError::Unavailable
            })
    }

    async fn redeem(
        &self,
        code: &str,
        flow: &super::PendingFlow,
    ) -> Result<Assertion, ProviderError> {
        let tokens = match self
            .client
            .exchange_code(code, &flow.redirect_uri, &flow.code_verifier)
            .await
        {
            Ok(tokens) => tokens,
            Err(TokenError::Rejected) => {
                return Err(ProviderError::refused("rejected", "code refused"));
            }
            Err(TokenError::Unavailable(error)) => {
                tracing::warn!(%error, "Microsoft token exchange failed");
                return Err(ProviderError::Unavailable);
            }
        };
        let id_token = tokens
            .id_token
            .ok_or_else(|| ProviderError::refused("token", "no id token"))?;
        let claims = match self.client.verify(&id_token, &flow.nonce).await {
            Ok(claims) => claims,
            Err(VerifyError::Invalid(detail)) => {
                return Err(ProviderError::refused("token", detail));
            }
            Err(VerifyError::Unavailable(error)) => {
                tracing::warn!(%error, "Microsoft signing keys unavailable");
                return Err(ProviderError::Unavailable);
            }
        };
        let tenant = claims.string("tid").to_string();
        if !self.tenant_allowed(&tenant) {
            return Err(ProviderError::refused("token", "tenant not allowed"));
        }
        let subject = claims.string("oid");
        if subject.is_empty() {
            return Err(ProviderError::refused("token", "token has no subject"));
        }
        warn_without_address(&claims);
        Ok(Assertion {
            provider: ID,
            tenant,
            subject: subject.to_string(),
            address: address_of(&claims),
            name: display_name(&claims),
            mfa: claims
                .strings("amr")
                .iter()
                .any(|method| *method == "mfa" || *method == "ngcmfa"),
            auth_time: claims.integer("auth_time"),
            refresh_grant: tokens.refresh_token,
        })
    }

    async fn refresh(&self, grant: &str) -> RefreshOutcome {
        match self.client.refresh(grant).await {
            Ok(tokens) => match tokens.refresh_token {
                Some(fresh) => RefreshOutcome::Rotated(fresh),
                // Some providers omit a new refresh token when the old one
                // stays valid; keeping the stored one is the correct answer.
                None => RefreshOutcome::Unsupported,
            },
            Err(TokenError::Rejected) => RefreshOutcome::Rejected,
            Err(TokenError::Unavailable(error)) => RefreshOutcome::Unavailable(error),
        }
    }
}

/// The address to create or sign in the account with, and whether the provider
/// vouched for it.
///
/// `email` is the real address. Entra often omits it, and then
/// `preferred_username` is the same address in practice — taken as an
/// **unverified** candidate, since our own emailed code is what proves the
/// mailbox. Only a vouched `email` counts as verified.
fn address_of(claims: &super::oidc::VerifiedClaims) -> Option<(String, bool)> {
    let email = claims.string("email").trim();
    if !email.is_empty() {
        return Some((email.to_string(), claims.truthy("email_verified")));
    }
    let username = claims.string("preferred_username").trim();
    username
        .contains('@')
        .then(|| (username.to_string(), false))
}

/// The display name for a new account.
fn display_name(claims: &super::oidc::VerifiedClaims) -> String {
    ["name", "preferred_username", "email"]
        .into_iter()
        .map(|name| claims.string(name).trim())
        .find(|value| !value.is_empty())
        .unwrap_or_default()
        .to_string()
}

/// Logs which claims arrived when none of them names an address.
///
/// Diagnostics only: a refused sign-in with "no email in the token" is otherwise
/// indistinguishable between an app registration that was never granted the
/// `email` scope and one whose tenant withholds the claim.
fn warn_without_address(claims: &super::oidc::VerifiedClaims) {
    if address_of(claims).is_none() {
        tracing::warn!(
            provider = ID,
            claims = ?claims.claim_names(),
            "SSO token carried no usable email claim; refusing the sign-in"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT: &str = "32fb7b25-9b31-4552-a225-7cb8da0afb61";

    fn provider(authority: &str) -> Microsoft {
        Arc::try_unwrap(
            Microsoft::from_preset(authority, "client", "secret")
                .expect("builds")
                .expect("enabled"),
        )
        .ok()
        .expect("sole owner")
    }

    #[test]
    fn the_tenant_matrix_follows_the_authority() {
        assert!(provider("common").tenant_allowed(TENANT));
        assert!(provider("common").tenant_allowed(MSA_TENANT));
        assert!(provider("organizations").tenant_allowed(TENANT));
        assert!(!provider("organizations").tenant_allowed(MSA_TENANT));
        assert!(provider("consumers").tenant_allowed(MSA_TENANT));
        assert!(!provider("consumers").tenant_allowed(TENANT));
        assert!(provider(TENANT).tenant_allowed(TENANT));
        assert!(!provider(TENANT).tenant_allowed(MSA_TENANT));
        assert!(!provider("common").tenant_allowed("not-a-guid"));
    }

    #[test]
    fn a_sign_in_and_a_step_up_ask_for_different_prompts() {
        assert_eq!(prompt_value(Prompt::SignIn), "select_account");
        assert_eq!(prompt_value(Prompt::StepUp { max_age: 300 }), "login");
    }
}
