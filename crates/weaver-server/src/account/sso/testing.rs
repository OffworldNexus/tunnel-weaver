//! A fake identity provider for tests (WVR-175).
//!
//! The shared pipeline is exercised once, end to end, through this provider:
//! sign-up, sign-in, settling an unverified address by code, step-up, and the
//! refusal of a takeover. No test — and no CI run — ever needs a real provider.
//!
//! The fake is a `Redirect` provider with no network: its authorization URL is
//! the relay's own callback carrying a code that *is* the assertion the test
//! queued, base64url-encoded. A browser follows it for real (the e2e harness
//! does), and `redeem` decodes it. That keeps the whole browser-visible
//! redirect round-trip honest while making the provider's answer deterministic.

use std::collections::VecDeque;
use std::sync::Mutex;

use base64::Engine as _;
use serde::Deserialize;

use super::RefreshOutcome;
use super::{Assertion, Entry, IdentityProvider, PendingFlow, Prompt, ProviderError};
use crate::wall_clock::unix_secs;

/// What the fake provider should assert for one sign-in.
///
/// The fields mirror the provider-neutral [`Assertion`]; a string that is empty
/// means "the provider gave none", never a missing field.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct FakeAssertion {
    #[serde(default)]
    pub tenant: String,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub mfa: bool,
    #[serde(default)]
    pub auth_time: Option<i64>,
    #[serde(default)]
    pub refresh_grant: Option<String>,
}

impl FakeAssertion {
    /// An assertion for `subject` at `email`.
    pub fn new(subject: &str, email: &str) -> Self {
        Self {
            subject: subject.to_string(),
            email: email.to_string(),
            name: format!("Fake {subject}"),
            ..Default::default()
        }
    }

    /// The provider vouches for the address, so an existing account at it may be
    /// linked.
    pub fn verified(mut self) -> Self {
        self.email_verified = true;
        self
    }

    /// The provider asserted a second factor for this sign-in.
    pub fn with_mfa(mut self) -> Self {
        self.mfa = true;
        self
    }

    /// The display name a new account takes.
    pub fn named(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }

    /// The tenant part of the durable key.
    pub fn in_tenant(mut self, tenant: &str) -> Self {
        self.tenant = tenant.to_string();
        self
    }

    /// A refresh grant the relay should keep.
    pub fn with_grant(mut self, grant: &str) -> Self {
        self.refresh_grant = Some(grant.to_string());
        self
    }
}

/// A provider that answers with queued assertions instead of talking to anyone.
pub struct FakeProvider {
    id: &'static str,
    label: &'static str,
    queued: Mutex<VecDeque<FakeAssertion>>,
    /// What every redirect asserts once the queue is empty; `None` keeps the
    /// built-in throwaway identity.
    default: Option<FakeAssertion>,
}

impl Default for FakeProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeProvider {
    /// The provider the harnesses register, under the id `fake`.
    pub fn new() -> Self {
        Self {
            id: "fake",
            label: "Fake provider",
            queued: Mutex::new(VecDeque::new()),
            default: None,
        }
    }

    /// Answers with `assertion` whenever the queue is empty.
    ///
    /// The dev harness uses this so a click always signs in as the same
    /// configured identity, with no control endpoint to script.
    pub fn with_default(mut self, assertion: FakeAssertion) -> Self {
        self.default = Some(assertion);
        self
    }

    /// Queues the assertion the next redirect will carry.
    pub fn expect(&self, assertion: FakeAssertion) {
        self.queued
            .lock()
            .expect("fake provider queue")
            .push_back(assertion);
    }

    /// The next assertion, falling back to the configured default, then to a
    /// throwaway one when a test did not queue any.
    fn next(&self) -> FakeAssertion {
        self.queued
            .lock()
            .expect("fake provider queue")
            .pop_front()
            .or_else(|| self.default.clone())
            .unwrap_or_else(|| FakeAssertion::new("fake-subject", "fake@example.test").verified())
    }
}

/// Encodes one assertion as the fake provider's authorization code.
fn encode(assertion: &FakeAssertion) -> String {
    let json = serde_json::json!({
        "tenant": assertion.tenant,
        "subject": assertion.subject,
        "email": assertion.email,
        "email_verified": assertion.email_verified,
        "name": assertion.name,
        "mfa": assertion.mfa,
        "auth_time": assertion.auth_time,
        "refresh_grant": assertion.refresh_grant,
    });
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.to_string())
}

/// Decodes an authorization code or token back into an assertion.
fn decode(encoded: &str) -> Result<FakeAssertion, ProviderError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ProviderError::refused("token", "fake assertion is not decodable"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| ProviderError::refused("token", "fake assertion is not an assertion"))
}

impl FakeAssertion {
    /// The provider-neutral assertion the pipeline sees.
    fn into_assertion(self, provider: &'static str) -> Assertion {
        Assertion {
            provider,
            tenant: self.tenant,
            subject: self.subject,
            address: (!self.email.is_empty()).then_some((self.email, self.email_verified)),
            name: self.name,
            mfa: self.mfa,
            auth_time: self.auth_time,
            refresh_grant: self.refresh_grant,
        }
    }
}

#[async_trait::async_trait]
impl IdentityProvider for FakeProvider {
    fn id(&self) -> &'static str {
        self.id
    }

    fn label(&self) -> &'static str {
        self.label
    }

    fn entry(&self) -> Entry {
        Entry::Redirect
    }

    async fn authorize_url(
        &self,
        flow: &PendingFlow,
        prompt: Prompt,
    ) -> Result<String, ProviderError> {
        let mut assertion = self.next();
        // A step-up is meant to prove the person re-authenticated just now, so
        // the fake reports a fresh `auth_time` regardless of what was queued.
        if matches!(prompt, Prompt::StepUp { .. }) {
            assertion.auth_time = Some(unix_secs());
        }
        let code = encode(&assertion);
        Ok(format!(
            "{}?state={}&code={}",
            flow.redirect_uri,
            super::oidc::percent_encode(&flow.state),
            code,
        ))
    }

    async fn redeem(&self, code: &str, _flow: &PendingFlow) -> Result<Assertion, ProviderError> {
        Ok(decode(code)?.into_assertion(self.id))
    }

    async fn verify_token(&self, token: &str) -> Result<Assertion, ProviderError> {
        Ok(decode(token)?.into_assertion(self.id))
    }

    async fn refresh(&self, _grant: &str) -> RefreshOutcome {
        RefreshOutcome::Unsupported
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_queued_assertion_round_trips_through_the_code() {
        let provider = FakeProvider::new();
        provider.expect(
            FakeAssertion::new("subject-1", "one@example.test")
                .verified()
                .with_mfa(),
        );
        let flow = PendingFlow {
            state: "state".into(),
            nonce: "nonce".into(),
            code_verifier: "verifier".into(),
            redirect_uri: "https://admin.test/api/account/sso/fake/callback".into(),
        };
        let url = provider
            .authorize_url(&flow, Prompt::SignIn)
            .await
            .expect("authorize");
        let code = url.split("code=").nth(1).expect("a code");
        let assertion = provider.redeem(code, &flow).await.expect("redeem");
        assert_eq!(assertion.provider, "fake");
        assert_eq!(assertion.subject, "subject-1");
        assert_eq!(
            assertion.address,
            Some(("one@example.test".to_string(), true))
        );
        assert!(assertion.mfa);
    }

    #[tokio::test]
    async fn a_step_up_reports_a_fresh_authentication() {
        let provider = FakeProvider::new();
        provider.expect(FakeAssertion::new("subject-1", "one@example.test").verified());
        let flow = PendingFlow {
            state: "state".into(),
            nonce: "nonce".into(),
            code_verifier: "verifier".into(),
            redirect_uri: "https://admin.test/api/account/sso/fake/callback".into(),
        };
        let url = provider
            .authorize_url(&flow, Prompt::StepUp { max_age: 300 })
            .await
            .expect("authorize");
        let code = url.split("code=").nth(1).expect("a code");
        let assertion = provider.redeem(code, &flow).await.expect("redeem");
        let auth_time = assertion.auth_time.expect("a fresh auth_time");
        assert!(unix_secs() - auth_time <= 1);
    }
}
