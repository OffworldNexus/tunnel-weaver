//! SMTP transport built on lettre.
//!
//! lettre owns MIME/`Message` building and the SMTP conversation; this module
//! only maps the normalised [`Email`] onto a lettre message and maps failures
//! into [`MailerError`]. Every message is `multipart/alternative`.

use async_trait::async_trait;
use lettre::message::{Mailbox as LettreMailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::EmailConfig;
use crate::email::{Email, Mailbox, Mailer, MailerError, MailerIdentity, SendReceipt};

/// The SMTP mailer.
pub struct SmtpMailer {
    identity: MailerIdentity,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl SmtpMailer {
    /// Builds the transport from an `smtp://`/`smtps://` endpoint.
    pub fn new(identity: MailerIdentity, cfg: &EmailConfig) -> Result<Self, MailerError> {
        let url = cfg
            .endpoint
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                MailerError::Config(
                    "provider 'smtp' requires endpoint, e.g. smtp://host:587".into(),
                )
            })?;

        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::from_url(url)
            .map_err(|e| MailerError::Config(format!("invalid SMTP endpoint: {e}")))?;

        let username = cfg.username.clone().unwrap_or_default();
        let password = cfg.api_key.clone().unwrap_or_default();
        if !username.is_empty() || !password.is_empty() {
            builder = builder.credentials(Credentials::new(username, password));
        }

        Ok(SmtpMailer {
            identity,
            transport: builder.build(),
        })
    }
}

#[async_trait]
impl Mailer for SmtpMailer {
    fn identity(&self) -> &MailerIdentity {
        &self.identity
    }

    async fn send(&self, email: &Email) -> Result<SendReceipt, MailerError> {
        let message = build_message(email)?;
        self.transport
            .send(message)
            .await
            .map_err(|e| MailerError::Transport(self.identity.redact(&e.to_string())))?;
        // SMTP has no provider message id; the server's queue id is not exposed
        // by lettre's response.
        Ok(SendReceipt { message_id: None })
    }
}

/// Maps a normalised mailbox onto a lettre mailbox.
fn to_lettre(mb: &Mailbox) -> Result<LettreMailbox, MailerError> {
    let address = mb
        .address
        .parse::<lettre::Address>()
        .map_err(|e| MailerError::InvalidRecipient(format!("{}: {e}", mb.address)))?;
    Ok(LettreMailbox {
        name: mb.name.clone(),
        email: address,
    })
}

/// Builds the lettre message. Kept separate so tests can serialize it.
fn build_message(email: &Email) -> Result<Message, MailerError> {
    let mut builder = Message::builder()
        .from(to_lettre(&email.from)?)
        .subject(email.subject.clone());

    for to in &email.to {
        builder = builder.to(to_lettre(to)?);
    }
    if let Some(reply_to) = &email.reply_to {
        builder = builder.reply_to(to_lettre(reply_to)?);
    }

    let message = builder
        .multipart(MultiPart::alternative_plain_html(
            email.text.clone(),
            email.html.clone(),
        ))
        .map_err(|e| MailerError::Config(format!("failed to build message: {e}")))?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Email {
        Email {
            from: Mailbox::new("sender@example.com").with_name("Sender Name"),
            to: vec![Mailbox::new("dest@example.org").with_name("Dest")],
            reply_to: Some(Mailbox::new("reply@example.com")),
            subject: "Hello".into(),
            text: "plain body".into(),
            html: "<p>html body</p>".into(),
        }
    }

    #[test]
    fn templated_message_is_multipart_alternative() {
        let raw = build_message(&fixture()).unwrap().formatted();
        let parsed = mailparse::parse_mail(&raw).unwrap();

        assert!(
            parsed.ctype.mimetype.starts_with("multipart/alternative"),
            "got {}",
            parsed.ctype.mimetype
        );
        let subtypes: Vec<String> = parsed
            .subparts
            .iter()
            .map(|p| p.ctype.mimetype.clone())
            .collect();
        assert!(subtypes.iter().any(|t| t == "text/plain"), "{subtypes:?}");
        assert!(subtypes.iter().any(|t| t == "text/html"), "{subtypes:?}");

        let text = parsed
            .subparts
            .iter()
            .find(|p| p.ctype.mimetype == "text/plain")
            .unwrap()
            .get_body()
            .unwrap();
        let html = parsed
            .subparts
            .iter()
            .find(|p| p.ctype.mimetype == "text/html")
            .unwrap()
            .get_body()
            .unwrap();
        assert!(text.contains("plain body"));
        assert!(html.contains("<p>html body</p>"));

        // Envelope headers survived.
        let from = parsed
            .headers
            .iter()
            .find(|h| h.get_key() == "From")
            .unwrap();
        assert!(from.get_value().contains("sender@example.com"));
        let subj = parsed
            .headers
            .iter()
            .find(|h| h.get_key() == "Subject")
            .unwrap();
        assert_eq!(subj.get_value(), "Hello");
    }

    #[test]
    fn invalid_recipient_is_rejected() {
        let mut email = fixture();
        email.to = vec![Mailbox::new("not-an-address")];
        match build_message(&email) {
            Err(MailerError::InvalidRecipient(_)) => {}
            other => panic!("expected InvalidRecipient, got {other:?}"),
        }
    }

    #[test]
    fn smtp_requires_endpoint() {
        let cfg = EmailConfig {
            provider: "smtp".into(),
            from: "a@b.com".into(),
            username: Some("u".into()),
            api_key: Some("p".into()),
            ..Default::default()
        };
        let identity = MailerIdentity::new(
            "smtp",
            "SMTP",
            Mailbox::new("a@b.com"),
            "https://relay.example.org",
            vec![],
        )
        .unwrap();
        match SmtpMailer::new(identity, &cfg)
            .err()
            .expect("missing endpoint must error")
        {
            MailerError::Config(msg) => assert!(msg.contains("requires endpoint")),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn smtp_builds_from_tls_urls() {
        for url in [
            "smtp://mail.example.com:587",
            "smtps://mail.example.com:465",
        ] {
            let cfg = EmailConfig {
                provider: "smtp".into(),
                from: "a@b.com".into(),
                username: Some("u".into()),
                api_key: Some("p".into()),
                endpoint: Some(url.into()),
                ..Default::default()
            };
            let identity = MailerIdentity::new(
                "smtp",
                "SMTP",
                Mailbox::new("a@b.com"),
                "https://relay.example.org",
                vec![],
            )
            .unwrap();
            assert!(SmtpMailer::new(identity, &cfg).is_ok(), "{url}");
        }
    }
}
