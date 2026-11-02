//! Google Identity as an external identity provider (WVR-173).
//!
//! Google is the first provider to reuse the shared pipeline unchanged: it sits
//! on [`super::oidc::OidcClient`] with a **fixed** issuer
//! (`https://accounts.google.com`) and adds only its own facts — offline access,
//! the `amr` claims request, and the claim mapping from Google's ID token onto
//! an [`Assertion`].
//!
//! The one thing Google cannot do is tell us the account is disabled: a
//! disabled account never receives an ID token at all. That signal only ever
//! arrives through Cross-Account Protection, which is an optional extra outside
//! this pipeline, never a claim read here.

use std::sync::Arc;

use super::RefreshOutcome;
use super::oidc::{IssuerRule, OidcClient, OidcSettings, TokenError, VerifiedClaims, VerifyError};
use super::{Assertion, Entry, IdentityProvider, Prompt, ProviderError};

/// The provider id: the route segment, the registry key and the seal AAD.
pub const ID: &str = "google";

/// Google's discovery document.
const DISCOVERY: &str = "https://accounts.google.com/.well-known/openid-configuration";

/// Google's fixed issuer, exactly as it appears in an ID token.
const ISSUER: &str = "https://accounts.google.com";

/// The scopes every grant asks for. Google needs no `offline_access` scope:
/// offline access is the `access_type=offline` parameter below.
const SCOPE: &str = "openid email profile";

/// The `claims` parameter that asks Google to report the authentication methods
/// it used. It is best-effort by Google's own documentation — it may be absent
/// even when requested, and that absence is "not MFA", never "maybe MFA".
const AMR_CLAIMS: &str = r#"{"id_token":{"amr":{"essential":true}}}"#;

/// The enabled Google provider.
pub struct Google {
    client: OidcClient,
}

impl Google {
    /// Builds the provider from the values its preset carries.
    ///
    /// `client_secret` is the plaintext secret; unsealing is the registry's job.
    pub fn from_preset(client_id: &str, client_secret: &str) -> Result<Option<Arc<Self>>, String> {
        Ok(Some(Arc::new(Self {
            client: OidcClient::new(OidcSettings {
                discovery_url: DISCOVERY.to_string(),
                client_id: client_id.to_string(),
                client_secret: client_secret.to_string(),
                scopes: SCOPE.to_string(),
                issuer: IssuerRule::Fixed(ISSUER.to_string()),
                authorize_params: vec![
                    // Without this Google issues an access token only, and the
                    // hourly housekeeping has no grant to keep alive.
                    ("access_type".to_string(), "offline".to_string()),
                    ("claims".to_string(), AMR_CLAIMS.to_string()),
                ],
            })?,
        })))
    }
}

/// The authorization `prompt` value for the reason the flow exists.
///
/// `consent` rides along on both: Google only hands out a refresh token when the
/// person has just consented, so a silent reuse of its own session would leave
/// the relay with nothing to keep alive.
fn prompt_value(prompt: Prompt) -> &'static str {
    match prompt {
        Prompt::SignIn => "select_account consent",
        Prompt::StepUp { .. } => "login consent",
    }
}

#[async_trait::async_trait]
impl IdentityProvider for Google {
    fn id(&self) -> &'static str {
        ID
    }

    fn label(&self) -> &'static str {
        "Google"
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
                tracing::warn!(%error, "Google discovery failed");
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
                tracing::warn!(%error, "Google token exchange failed");
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
                tracing::warn!(%error, "Google signing keys unavailable");
                return Err(ProviderError::Unavailable);
            }
        };
        assertion_from_claims(&claims, tokens.refresh_token)
    }

    async fn refresh(&self, grant: &str) -> RefreshOutcome {
        match self.client.refresh(grant).await {
            Ok(tokens) => match tokens.refresh_token {
                Some(fresh) => RefreshOutcome::Rotated(fresh),
                // Google usually keeps the old refresh token valid and omits a
                // new one; the stored grant stays, so there is nothing to rotate.
                None => RefreshOutcome::Unsupported,
            },
            Err(TokenError::Rejected) => RefreshOutcome::Rejected,
            Err(TokenError::Unavailable(error)) => RefreshOutcome::Unavailable(error),
        }
    }
}

/// Maps Google's verified claims onto the provider-neutral assertion.
///
/// Google has no tenant: `tenant` is always empty. The address is only ever
/// taken from a verified `email` claim — an unverified one still creates an
/// account, which our own emailed code then settles, but it must never link to
/// an existing one.
fn assertion_from_claims(
    claims: &VerifiedClaims,
    refresh_grant: Option<String>,
) -> Result<Assertion, ProviderError> {
    let subject = claims.string("sub");
    if subject.is_empty() {
        return Err(ProviderError::refused("token", "token has no subject"));
    }
    let email = claims.string("email").trim();
    if email.is_empty() {
        tracing::warn!(
            provider = ID,
            claims = ?claims.claim_names(),
            "Google token carried no email claim; refusing the sign-in"
        );
        return Err(ProviderError::refused("email", "no email in the token"));
    }
    Ok(Assertion {
        provider: ID,
        tenant: String::new(),
        subject: subject.to_string(),
        address: Some((email.to_string(), claims.truthy("email_verified"))),
        name: [claims.string("name"), email]
            .into_iter()
            .map(str::trim)
            .find(|value| !value.is_empty())
            .unwrap_or_default()
            .to_string(),
        mfa: claims.strings("amr").contains(&"mfa"),
        auth_time: claims.integer("auth_time"),
        refresh_grant,
    })
}

/// Google's claims, for the unit tests below.
#[cfg(test)]
fn claim_map(json: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    json.as_object().cloned().expect("an object")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn mapped(json: Value) -> Result<Assertion, ProviderError> {
        assertion_from_claims(&VerifiedClaims::from_test_claims(claim_map(json)), None)
    }

    #[test]
    fn a_verified_google_address_is_taken_and_an_unverified_one_is_flagged() {
        let verified = mapped(serde_json::json!({
            "sub": "1234",
            "email": "a@b.c",
            "email_verified": true,
            "name": "Alice",
        }))
        .expect("maps");
        assert_eq!(verified.tenant, "");
        assert_eq!(verified.subject, "1234");
        assert_eq!(verified.address, Some(("a@b.c".to_string(), true)));
        assert_eq!(verified.name, "Alice");

        // Google reports the flag as a boolean, but the string spelling has
        // been seen; anything but true is "not verified".
        let unverified = mapped(serde_json::json!({
            "sub": "1234",
            "email": "a@b.c",
            "email_verified": "false",
        }))
        .expect("maps");
        assert_eq!(unverified.address, Some(("a@b.c".to_string(), false)));
        // No name claim: fall back to the address, never an empty account name.
        assert_eq!(unverified.name, "a@b.c");
    }

    #[test]
    fn a_google_token_without_an_address_is_refused() {
        let refused = mapped(serde_json::json!({ "sub": "1234" }));
        assert!(matches!(
            refused,
            Err(ProviderError::Refused {
                reason: "email",
                ..
            })
        ));
        let no_subject = mapped(serde_json::json!({ "email": "a@b.c", "email_verified": true }));
        assert!(matches!(
            no_subject,
            Err(ProviderError::Refused {
                reason: "token",
                ..
            })
        ));
    }

    /// B3: only a concrete `mfa` in `amr` is a second factor. Google warns the
    /// claim may be absent even when requested, and absence is `Basic`.
    #[test]
    fn google_mfa_comes_only_from_amr() {
        assert!(
            mapped(serde_json::json!({
                "sub": "1", "email": "a@b.c", "email_verified": true, "amr": ["pwd", "mfa"],
            }))
            .expect("maps")
            .mfa
        );
        assert!(
            !mapped(serde_json::json!({
                "sub": "1", "email": "a@b.c", "email_verified": true, "amr": ["pwd"],
            }))
            .expect("maps")
            .mfa
        );
        assert!(
            !mapped(serde_json::json!({
                "sub": "1", "email": "a@b.c", "email_verified": true,
            }))
            .expect("maps")
            .mfa
        );
    }

    #[test]
    fn a_hosted_domain_claim_is_not_a_restriction() {
        // Domain filtering is deliberately out of scope for this preset: the
        // `hd` claim may arrive, and it is simply not read.
        let mapped = mapped(serde_json::json!({
            "sub": "1",
            "email": "a@b.c",
            "email_verified": true,
            "hd": "example.com",
        }))
        .expect("maps");
        assert_eq!(mapped.address, Some(("a@b.c".to_string(), true)));
    }
}
