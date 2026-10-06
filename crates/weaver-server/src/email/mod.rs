//! Transactional email: provider catalog, typed templates, and transports.
//!
//! The public surface is intentionally small: callers build a [`Mailer`] from
//! the validated [`crate::config::EmailConfig`], compose a typed template, and
//! `send`. Provider quirks live in [`providers`]; rendering lives in the
//! [`template`] module; the transports speak the wire.

pub mod jokes;
pub mod otp;
pub mod providers;
pub mod template;
mod transport;

use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

pub use template::{Joke, Otp};

use crate::config::EmailConfig;

/// A single email participant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mailbox {
    /// Optional display name.
    pub name: Option<String>,
    /// Bare `local@domain` address, already validated by [`Mailbox::parse`].
    pub address: String,
}

impl Mailbox {
    /// Builds a mailbox without validation. Only for addresses the program
    /// itself constructed; operator or user input must go through
    /// [`Mailbox::parse`].
    pub fn new(address: impl Into<String>) -> Self {
        Mailbox {
            name: None,
            address: address.into(),
        }
    }

    /// Attaches a display name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Validates and builds a mailbox from untrusted input.
    pub fn parse(address: &str, name: Option<String>) -> Result<Self, MailerError> {
        if !is_valid_address(address) {
            return Err(MailerError::InvalidRecipient(address.trim().to_string()));
        }
        Ok(Mailbox {
            name: name.filter(|n| !n.trim().is_empty()),
            address: address.trim().to_string(),
        })
    }
}

impl From<&str> for Mailbox {
    fn from(address: &str) -> Self {
        Mailbox::new(address)
    }
}

impl From<String> for Mailbox {
    fn from(address: String) -> Self {
        Mailbox::new(address)
    }
}

impl From<&String> for Mailbox {
    fn from(address: &String) -> Self {
        Mailbox::new(address.clone())
    }
}

/// One normalised outbound message.
///
/// Provider quirks (auth, body shape) are the transport's concern, so this is
/// the only shape callers and transports share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email {
    /// Stamped by the mailer from the configured sender; never hand-set.
    pub from: Mailbox,
    /// Envelope recipients.
    pub to: Vec<Mailbox>,
    /// Optional `Reply-To`; opt in with [`Email::with_reply_to`].
    pub reply_to: Option<Mailbox>,
    /// Message subject.
    pub subject: String,
    /// Plain-text alternative.
    pub text: String,
    /// Responsive HTML body.
    pub html: String,
}

impl Email {
    /// Opts this message into a `Reply-To`.
    pub fn with_reply_to(mut self, reply_to: Mailbox) -> Self {
        self.reply_to = Some(reply_to);
        self
    }
}

/// Provider acknowledgement of an accepted send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendReceipt {
    /// Provider-assigned message id, when it returns one.
    pub message_id: Option<String>,
}

/// One fully rendered templated message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// Message subject.
    pub subject: String,
    /// Plain-text alternative.
    pub text: String,
    /// Responsive HTML body.
    pub html: String,
}

/// Values shared by every template, validated once at context construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateEnv {
    /// Absolute HTTPS support link used by the shared footer.
    pub support_url: String,
}

impl TemplateEnv {
    /// Validates the support link as trusted HTTPS.
    pub fn new(support_url: impl Into<String>) -> Result<Self, RenderError> {
        let support_url = support_url.into();
        if !is_trusted_https(&support_url) {
            return Err(RenderError::UntrustedUrl(support_url));
        }
        Ok(TemplateEnv { support_url })
    }
}

/// A known, typed email. Owned context only — never a stringly dict.
pub trait EmailTemplate {
    /// Stable id, e.g. `"joke"`; used in logs and as the table directory name.
    ///
    /// Exposed as a method rather than an associated const so the trait stays
    /// dyn-compatible: `Mailer::compose` takes a `&dyn EmailTemplate`.
    fn id(&self) -> &'static str;

    /// Renders the subject, text, and responsive HTML.
    fn render(&self, env: &TemplateEnv) -> Result<Rendered, RenderError>;
}

/// Template rendering failures, mapped into [`MailerError::Template`].
#[derive(Debug, Error)]
pub enum RenderError {
    /// The template engine failed.
    #[error("template render failed: {0}")]
    Template(String),
    /// A URL was not a trusted absolute HTTPS URL.
    #[error("untrusted URL: {0}")]
    UntrustedUrl(String),
    /// `mrml` rejected the compiled document.
    #[error("MJML compilation failed: {0}")]
    Mjml(String),
}

/// Typed mail failures. Callers distinguish "email is off" from "the provider
/// refused this address", so the variants are deliberately fine-grained.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum MailerError {
    /// Email is disabled or absent from the configuration.
    #[error("email is not configured")]
    NotConfigured,
    /// A credential field is missing or malformed.
    #[error("email configuration error: {0}")]
    Config(String),
    /// A template failed to render, or a translation is missing.
    #[error("email template error: {0}")]
    Template(String),
    /// The recipient address is not usable.
    #[error("invalid recipient: {0}")]
    InvalidRecipient(String),
    /// Network, TLS, or timeout failure talking to the provider.
    #[error("email transport error: {0}")]
    Transport(String),
    /// The provider accepted the connection but refused the message.
    #[error("email rejected by provider (status {status:?}): {detail}")]
    Rejected {
        /// HTTP status, when the transport is HTTP.
        status: Option<u16>,
        /// Provider-specific error code, when it returns one.
        provider_code: Option<String>,
        /// Provider detail, already redacted of secrets.
        detail: String,
    },
}

/// Replaces every non-empty secret with `[redacted]`.
pub fn redact(input: &str, secrets: &[String]) -> String {
    let mut out = input.to_string();
    for secret in secrets {
        let secret = secret.trim();
        if secret.is_empty() {
            continue;
        }
        out = out.replace(secret, "[redacted]");
    }
    out
}

/// Whether a URL is absolute HTTPS and safe to place in a message.
pub fn is_trusted_https(url: &str) -> bool {
    let url = url.trim();
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    !host.is_empty() && !host.contains('@') && !host.chars().any(char::is_whitespace)
}

/// The transport-independent half of a mailer: sender identity, support link,
/// and the secrets to scrub from every error path.
pub struct MailerIdentity {
    /// Catalog id of the configured provider.
    pub provider: &'static str,
    /// Display name of the configured provider.
    pub display: &'static str,
    /// Injected `From` mailbox.
    pub from: Mailbox,
    /// Validated support link for shared footers.
    pub support_url: String,
    /// Credential strings scrubbed from error output.
    secrets: Vec<String>,
}

impl MailerIdentity {
    /// Validates the sender and support link.
    pub fn new(
        provider: &'static str,
        display: &'static str,
        from: Mailbox,
        support_url: &str,
        secrets: Vec<String>,
    ) -> Result<Self, MailerError> {
        if !is_trusted_https(support_url) {
            return Err(MailerError::Config(format!(
                "support URL '{support_url}' must be absolute HTTPS"
            )));
        }
        Ok(MailerIdentity {
            provider,
            display,
            from,
            support_url: support_url.to_string(),
            secrets,
        })
    }

    /// Scrubs configured secrets from an error/detail string.
    pub fn redact(&self, input: &str) -> String {
        redact(input, &self.secrets)
    }

    /// Renders a typed template and injects the configured sender.
    pub fn compose(&self, to: Mailbox, template: &dyn EmailTemplate) -> Result<Email, MailerError> {
        let env = TemplateEnv {
            support_url: self.support_url.clone(),
        };
        let rendered = template
            .render(&env)
            .map_err(|e| MailerError::Template(e.to_string()))?;
        Ok(Email {
            from: self.from.clone(),
            to: vec![to],
            reply_to: None,
            subject: rendered.subject,
            text: rendered.text,
            html: rendered.html,
        })
    }
}

/// A configured transactional-mail transport.
///
/// Object-safe by design so `setup`, `configure`, and `send-a-joke` can all hold
/// one `Arc<dyn Mailer>` regardless of provider. `compose` takes a `Mailbox`
/// and a `&dyn EmailTemplate` (rather than `impl Into`/`impl EmailTemplate`) to
/// keep that object safety.
#[async_trait]
pub trait Mailer: Send + Sync {
    /// The transport-independent identity and secrets.
    fn identity(&self) -> &MailerIdentity;

    /// Catalog id of the configured provider.
    fn provider(&self) -> &'static str {
        self.identity().provider
    }

    /// Renders a known template, with the configured `From` injected.
    fn compose(&self, to: Mailbox, template: &dyn EmailTemplate) -> Result<Email, MailerError> {
        self.identity().compose(to, template)
    }

    /// Sends a message, awaited by the caller so failures are visible.
    async fn send(&self, email: &Email) -> Result<SendReceipt, MailerError>;
}

/// Builds a transport from a validated email block.
///
/// `None` means email is disabled: callers get [`MailerError::NotConfigured`]
/// rather than a partially built mailer. `support_url` is the absolute HTTPS
/// link placed in shared footers (normally `https://<admin_domain>`).
pub fn mailer_from_config(
    config: Option<&EmailConfig>,
    support_url: &str,
) -> Result<Arc<dyn Mailer>, MailerError> {
    let Some(cfg) = config else {
        return Err(MailerError::NotConfigured);
    };
    let info = providers::find_provider(&cfg.provider).ok_or_else(|| {
        MailerError::Config(format!(
            "email provider '{}' is not in the catalog",
            cfg.provider
        ))
    })?;
    let from = Mailbox::parse(&cfg.from, cfg.from_name.clone())?;
    let identity = MailerIdentity::new(info.id, info.display, from, support_url, secrets_of(cfg))?;

    crate::email::transport::build(identity, cfg)
}

/// Collects the credential strings to scrub from error output.
fn secrets_of(cfg: &EmailConfig) -> Vec<String> {
    [cfg.api_key.as_deref(), cfg.secret.as_deref()]
        .into_iter()
        .flatten()
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
        .collect()
}

/// Validates a bare email address well enough to feed a `From`/`To` envelope.
///
/// Deliberately permissive: exactly one `@`, a non-empty local part, and a
/// dotted, whitespace-free domain. Deliverability is the transport's concern;
/// this only rejects obvious typos before a send is attempted.
pub fn is_valid_address(addr: &str) -> bool {
    let addr = addr.trim();
    if addr.is_empty() || addr.chars().any(char::is_whitespace) {
        return false;
    }
    let mut parts = addr.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_addresses() {
        for good in ["a@b.com", "ops+jobs@relay.example.org", "x@y.z"] {
            assert!(is_valid_address(good), "{good}");
        }
        for bad in ["", "nope", "a@b", "a@@b.com", "a b@c.com", "a@.com", "a@b."] {
            assert!(!is_valid_address(bad), "{bad}");
        }
    }

    #[test]
    fn parse_rejects_bad_recipient() {
        match Mailbox::parse("nope", None) {
            Err(MailerError::InvalidRecipient(addr)) => assert_eq!(addr, "nope"),
            other => panic!("expected InvalidRecipient, got {other:?}"),
        }
    }

    #[test]
    fn trusted_https_only() {
        assert!(is_trusted_https("https://relay.example.org"));
        assert!(is_trusted_https("https://relay.example.org/support"));
        assert!(!is_trusted_https("http://relay.example.org"));
        assert!(!is_trusted_https("https://"));
        assert!(!is_trusted_https("https://user@host"));
    }

    #[test]
    fn absent_config_is_not_configured() {
        let err = mailer_from_config(None, "https://relay.example.org")
            .err()
            .expect("absent config must error");
        assert_eq!(err, MailerError::NotConfigured);
    }

    #[test]
    fn redaction_scrubs_secrets() {
        let secrets = vec!["sk_live_123".to_string()];
        let scrubbed = redact("failed with key sk_live_123 here", &secrets);
        assert!(!scrubbed.contains("sk_live_123"));
        assert!(scrubbed.contains("[redacted]"));
    }

    #[test]
    fn unknown_provider_is_config_error() {
        let cfg = EmailConfig {
            provider: "nope".into(),
            from: "a@b.com".into(),
            ..Default::default()
        };
        match mailer_from_config(Some(&cfg), "https://relay.example.org")
            .err()
            .expect("unknown provider must error")
        {
            MailerError::Config(msg) => assert!(msg.contains("not in the catalog")),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn email_config_debug_redacts_credentials() {
        let cfg = EmailConfig {
            provider: "mailjet".into(),
            from: "a@b.com".into(),
            api_key: Some("sk_live_leaky".into()),
            secret: Some("s3cr3t_leaky".into()),
            ..Default::default()
        };
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("sk_live_leaky"), "{debug}");
        assert!(!debug.contains("s3cr3t_leaky"), "{debug}");
        assert!(debug.contains("[redacted]"), "{debug}");
    }

    #[test]
    fn compose_injects_from_and_leaves_reply_to_unset() {
        use crate::email::template::Joke;
        let identity = MailerIdentity::new(
            "resend",
            "Resend",
            Mailbox::new("from@example.com").with_name("Sender"),
            "https://relay.example.org",
            vec![],
        )
        .unwrap();
        let to = Mailbox::new("to@example.org");
        let email = identity.compose(to, &Joke { line: "hi".into() }).unwrap();
        assert_eq!(email.from.address, "from@example.com");
        assert!(email.reply_to.is_none());
        assert!(email.html.contains("<html"));
        // Opting in is explicit.
        let with_reply = email.with_reply_to(Mailbox::new("reply@example.com"));
        assert_eq!(
            with_reply.reply_to.as_ref().map(|m| m.address.as_str()),
            Some("reply@example.com")
        );
    }
}
