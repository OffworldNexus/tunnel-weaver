//! Wire transports for the mailer.
//!
//! `build` maps a validated [`crate::config::EmailConfig`] onto a concrete
//! transport. Provider differences are interpreted from the catalog; only the
//! request-body shape and URL vary and both live in [`http`].

use std::sync::Arc;

use crate::config::EmailConfig;
use crate::email::providers::{ProviderKind, find_provider};
use crate::email::{Mailer, MailerError, MailerIdentity};

/// Constructs the transport for the configured provider kind.
pub(crate) fn build(
    identity: MailerIdentity,
    cfg: &EmailConfig,
) -> Result<Arc<dyn Mailer>, MailerError> {
    let info = find_provider(&cfg.provider).ok_or_else(|| {
        MailerError::Config(format!(
            "email provider '{}' is not in the catalog",
            cfg.provider
        ))
    })?;

    match info.kind {
        ProviderKind::HttpJson | ProviderKind::HttpForm => {
            Ok(Arc::new(http::HttpMailer::new(identity, cfg)?))
        }
        ProviderKind::Smtp => Ok(Arc::new(smtp::SmtpMailer::new(identity, cfg)?)),
    }
}

mod http;
mod smtp;
