//! Transactional-email provider catalog.
//!
//! Mirrors [`crate::cert::providers`]: provider quirks (endpoint, auth scheme,
//! request-body shape, required credentials) are *data*, and a single transport
//! layer interprets them. Adding a provider is one row here plus, at most, a
//! body-shape branch — never a new module.

use crate::config::EmailConfig;

/// How the transport speaks to a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    /// JSON POST body.
    HttpJson,
    /// `application/x-www-form-urlencoded` POST body.
    HttpForm,
    /// Raw SMTP via lettre, over STARTTLS or implicit TLS.
    Smtp,
}

impl ProviderKind {
    /// Short lower-case label for the catalog table.
    pub fn label(self) -> &'static str {
        match self {
            ProviderKind::HttpJson => "http-json",
            ProviderKind::HttpForm => "http-form",
            ProviderKind::Smtp => "smtp",
        }
    }
}

/// How credentials are presented on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthScheme {
    /// `Authorization: Bearer <key>`.
    Bearer,
    /// A custom header (`name`, optional value `prefix`).
    Header {
        name: &'static str,
        prefix: &'static str,
    },
    /// HTTP Basic `username:secret`.
    Basic,
    /// The key travels in the JSON body (Mandrill).
    BodyKey,
    /// No request auth (SMTP handles its own credentials).
    None,
}

/// A credential slot a provider may need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialField {
    /// [`EmailConfig::api_key`].
    ApiKey,
    /// [`EmailConfig::secret`].
    Secret,
    /// [`EmailConfig::username`].
    Username,
    /// [`EmailConfig::domain`].
    Domain,
    /// [`EmailConfig::template_id`].
    TemplateId,
}

/// One required credential, its operator-facing label, and the conventional
/// environment variable the setup wizard may offer as an ambient default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredField {
    /// Which [`EmailConfig`] slot carries the value.
    pub field: CredentialField,
    /// Human label used in prompts and validation errors.
    pub label: &'static str,
    /// Conventional environment variable, when the provider has one.
    pub env: Option<&'static str>,
}

impl EmailConfig {
    /// Reads a credential slot, treating blank strings as absent so an empty
    /// flag cannot masquerade as a supplied secret.
    pub fn credential(&self, field: CredentialField) -> Option<&str> {
        let raw = match field {
            CredentialField::ApiKey => self.api_key.as_deref(),
            CredentialField::Secret => self.secret.as_deref(),
            CredentialField::Username => self.username.as_deref(),
            CredentialField::Domain => self.domain.as_deref(),
            CredentialField::TemplateId => self.template_id.as_deref(),
        };
        raw.filter(|v| !v.trim().is_empty())
    }
}

/// Static description of a supported email provider.
#[derive(Debug, Clone, Copy)]
pub struct EmailProviderInfo {
    /// Stable catalog id, stored in [`EmailConfig::provider`].
    pub id: &'static str,
    /// Human-facing name for the setup menu and catalog table.
    pub display: &'static str,
    /// Transport family.
    pub kind: ProviderKind,
    /// Base API URL. `None` when the endpoint is operator-supplied (SMTP).
    pub api_base: Option<&'static str>,
    /// Auth presentation.
    pub auth: AuthScheme,
    /// Whether the sending domain is part of the request path (Mailgun).
    pub needs_domain: bool,
    /// Whether the provider can only send a pre-registered template (Loops).
    pub template_only: bool,
    /// Credentials the operator must supply (ambient ones are still listed).
    pub credential_fields: &'static [CredField],
    /// One-line operator guidance shown during setup.
    pub guidance: &'static str,
}

/// The catalog of transactional-email providers.
pub const PROVIDERS: &[EmailProviderInfo] = &[
    EmailProviderInfo {
        id: "resend",
        display: "Resend",
        kind: ProviderKind::HttpJson,
        api_base: Some("https://api.resend.com"),
        auth: AuthScheme::Bearer,
        needs_domain: false,
        template_only: false,
        credential_fields: &[CredField {
            field: CredentialField::ApiKey,
            label: "API key",
            env: Some("RESEND_API_KEY"),
        }],
        guidance: "Create an API key under API Keys; the sending domain must be verified. Docs: https://resend.com/docs",
    },
    EmailProviderInfo {
        id: "sendgrid",
        display: "SendGrid",
        kind: ProviderKind::HttpJson,
        api_base: Some("https://api.sendgrid.com"),
        auth: AuthScheme::Bearer,
        needs_domain: false,
        template_only: false,
        credential_fields: &[CredField {
            field: CredentialField::ApiKey,
            label: "API key",
            env: Some("SENDGRID_API_KEY"),
        }],
        guidance: "Settings → API Keys → Create (Mail Send). Use --email-endpoint for the EU host. Docs: https://docs.sendgrid.com/api-reference/mail-send",
    },
    EmailProviderInfo {
        id: "mailgun",
        display: "Mailgun",
        kind: ProviderKind::HttpForm,
        api_base: Some("https://api.mailgun.net/v3"),
        auth: AuthScheme::Basic,
        needs_domain: true,
        template_only: false,
        credential_fields: &[CredField {
            field: CredentialField::ApiKey,
            label: "API key",
            env: Some("MAILGUN_API_KEY"),
        }],
        guidance: "Username is always 'api'; the key is the password. The sending domain is required. EU: --email-endpoint https://api.eu.mailgun.net/v3",
    },
    EmailProviderInfo {
        id: "mailjet",
        display: "Mailjet",
        kind: ProviderKind::HttpJson,
        api_base: Some("https://api.mailjet.com"),
        auth: AuthScheme::Basic,
        needs_domain: false,
        template_only: false,
        credential_fields: &[
            CredField {
                field: CredentialField::ApiKey,
                label: "API key",
                env: Some("MAILJET_API_KEY"),
            },
            CredField {
                field: CredentialField::Secret,
                label: "secret key",
                env: Some("MAILJET_API_SECRET"),
            },
        ],
        guidance: "API Key Management → Primary API key. Docs: https://dev.mailjet.com/email/guides/send-api-v31/",
    },
    EmailProviderInfo {
        id: "mandrill",
        display: "Mandrill",
        kind: ProviderKind::HttpJson,
        api_base: Some("https://mandrillapp.com"),
        auth: AuthScheme::BodyKey,
        needs_domain: false,
        template_only: false,
        credential_fields: &[CredField {
            field: CredentialField::ApiKey,
            label: "API key",
            env: Some("MANDRILL_API_KEY"),
        }],
        guidance: "Settings → SMTP & API Info → API Keys. The key travels in the request body.",
    },
    EmailProviderInfo {
        id: "brevo",
        display: "Brevo",
        kind: ProviderKind::HttpJson,
        api_base: Some("https://api.brevo.com"),
        auth: AuthScheme::Header {
            name: "api-key",
            prefix: "",
        },
        needs_domain: false,
        template_only: false,
        credential_fields: &[CredField {
            field: CredentialField::ApiKey,
            label: "API key",
            env: Some("BREVO_API_KEY"),
        }],
        guidance: "SMTP & API → API Keys. Docs: https://developers.brevo.com/reference/sendtransacemail",
    },
    EmailProviderInfo {
        id: "sparkpost",
        display: "SparkPost",
        kind: ProviderKind::HttpJson,
        api_base: Some("https://api.sparkpost.com"),
        auth: AuthScheme::Header {
            name: "Authorization",
            prefix: "KEY ",
        },
        needs_domain: false,
        template_only: false,
        credential_fields: &[CredField {
            field: CredentialField::ApiKey,
            label: "API key",
            env: Some("SPARKPOST_API_KEY"),
        }],
        guidance: "API key with 'Transmissions: Read/Write'. Authorization uses the KEY scheme, not Bearer.",
    },
    EmailProviderInfo {
        id: "mailersend",
        display: "MailerSend",
        kind: ProviderKind::HttpJson,
        api_base: Some("https://api.mailersend.com"),
        auth: AuthScheme::Bearer,
        needs_domain: false,
        template_only: false,
        credential_fields: &[CredField {
            field: CredentialField::ApiKey,
            label: "API key",
            env: Some("MAILERSEND_API_KEY"),
        }],
        guidance: "Domains → API tokens. Docs: https://developers.mailersend.com",
    },
    EmailProviderInfo {
        id: "zeptomail",
        display: "ZeptoMail",
        kind: ProviderKind::HttpJson,
        api_base: Some("https://api.zeptomail.com"),
        auth: AuthScheme::Header {
            name: "Authorization",
            prefix: "Zoho-enczapikey ",
        },
        needs_domain: false,
        template_only: false,
        credential_fields: &[CredField {
            field: CredentialField::ApiKey,
            label: "send mail token",
            env: Some("ZEPTOMAIL_API_KEY"),
        }],
        guidance: "Send Mail Token from the agent. Regional hosts via --email-endpoint (.in, .eu).",
    },
    EmailProviderInfo {
        id: "elasticemail",
        display: "Elastic Email",
        kind: ProviderKind::HttpJson,
        api_base: Some("https://api.elasticemail.com"),
        auth: AuthScheme::Header {
            name: "X-ElasticEmail-ApiKey",
            prefix: "",
        },
        needs_domain: false,
        template_only: false,
        credential_fields: &[CredField {
            field: CredentialField::ApiKey,
            label: "API key",
            env: Some("ELASTICEMAIL_API_KEY"),
        }],
        guidance: "Settings → API → Create API key. Uses a nested Content/Body request shape.",
    },
    EmailProviderInfo {
        id: "loops",
        display: "Loops",
        kind: ProviderKind::HttpJson,
        api_base: Some("https://app.loops.so"),
        auth: AuthScheme::Bearer,
        needs_domain: false,
        template_only: true,
        credential_fields: &[
            CredField {
                field: CredentialField::ApiKey,
                label: "API key",
                env: Some("LOOPS_API_KEY"),
            },
            CredField {
                field: CredentialField::TemplateId,
                label: "transactional template id",
                env: None,
            },
        ],
        guidance: "Transactional emails must be pre-built in Loops; supply its template id. Docs: https://loops.so/docs/transactional",
    },
    EmailProviderInfo {
        id: "postmark",
        display: "Postmark",
        kind: ProviderKind::HttpJson,
        api_base: Some("https://api.postmarkapp.com"),
        auth: AuthScheme::Header {
            name: "X-Postmark-Server-Token",
            prefix: "",
        },
        needs_domain: false,
        template_only: false,
        credential_fields: &[CredField {
            field: CredentialField::ApiKey,
            label: "server token",
            env: Some("POSTMARK_SERVER_TOKEN"),
        }],
        guidance: "Server → API Tokens. Docs: https://postmarkapp.com/developer/api/email-api",
    },
    EmailProviderInfo {
        id: "smtp",
        display: "SMTP",
        kind: ProviderKind::Smtp,
        api_base: None,
        auth: AuthScheme::None,
        needs_domain: false,
        template_only: false,
        credential_fields: &[
            CredField {
                field: CredentialField::Username,
                label: "SMTP username",
                env: None,
            },
            CredField {
                field: CredentialField::ApiKey,
                label: "SMTP password",
                env: None,
            },
        ],
        guidance: "Operator host:port via --email-endpoint (e.g. smtp://host:587). STARTTLS or implicit TLS.",
    },
];

/// Upper-case display for a provider, falling back to its id.
pub fn display_name(id: &str) -> &str {
    find_provider(id).map(|p| p.display).unwrap_or(id)
}

/// Looks up a provider by id, case-insensitively.
pub fn find_provider(id: &str) -> Option<&'static EmailProviderInfo> {
    let lower = id.trim().to_ascii_lowercase();
    PROVIDERS.iter().find(|p| p.id.eq_ignore_ascii_case(&lower))
}

/// Returns the required credential slots a provider has not been given.
pub fn missing_credentials(info: &EmailProviderInfo, cfg: &EmailConfig) -> Vec<&'static CredField> {
    info.credential_fields
        .iter()
        .filter(|field| cfg.credential(field.field).is_none())
        .collect()
}

/// Validates a present email block, returning operator-facing issue strings.
///
/// An empty vector means the block is usable. Absent configuration is a
/// separate concern: callers treat `None` as [`crate::email::MailerError::NotConfigured`]
/// rather than an error.
pub fn validate_email_config(cfg: &EmailConfig) -> Vec<String> {
    let mut issues = Vec::new();

    let Some(info) = find_provider(&cfg.provider) else {
        issues.push(format!(
            "email provider '{}' is not in the catalog (see `providers email`)",
            cfg.provider
        ));
        return issues;
    };

    if !crate::email::is_valid_address(&cfg.from) {
        issues.push(format!(
            "email.from '{}' is not a valid email address",
            cfg.from
        ));
    }

    for field in missing_credentials(info, cfg) {
        issues.push(format!(
            "email provider '{}' requires {}",
            info.id, field.label
        ));
    }

    if info.needs_domain && cfg.domain.as_deref().unwrap_or("").trim().is_empty() {
        issues.push(format!(
            "email provider '{}' requires domain (the sending domain)",
            info.id
        ));
    }

    if info.template_only && cfg.template_id.as_deref().unwrap_or("").trim().is_empty() {
        issues.push(format!(
            "email provider '{}' requires template_id (a transactional template)",
            info.id
        ));
    }

    issues
}

use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};

/// Formats the email-provider catalog as an operator table.
pub fn format_providers_table() -> String {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("Provider")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Kind")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Endpoint")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Auth")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Guidance")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
    ]);

    for p in PROVIDERS {
        let name = if p.id == "resend" {
            Cell::new(format!("{} (default)", p.id))
                .add_attribute(Attribute::Bold)
                .fg(Color::Green)
        } else {
            Cell::new(p.id)
                .add_attribute(Attribute::Bold)
                .fg(Color::White)
        };

        let endpoint = p.api_base.unwrap_or("operator-supplied");
        let auth = match p.auth {
            AuthScheme::Bearer => "Bearer".to_string(),
            AuthScheme::Header { name, prefix } => {
                if prefix.is_empty() {
                    name.to_string()
                } else {
                    format!("{name}: {prefix}<key>")
                }
            }
            AuthScheme::Basic => "Basic".to_string(),
            AuthScheme::BodyKey => "body key".to_string(),
            AuthScheme::None => "—".to_string(),
        };
        let mut notes = p.guidance;
        if p.template_only {
            notes = "template-only. ";
        }

        table.add_row(vec![
            name,
            Cell::new(p.kind.label()).fg(Color::DarkCyan),
            Cell::new(endpoint).fg(Color::DarkCyan),
            Cell::new(auth),
            Cell::new(notes),
        ]);
    }

    table.to_string()
}

/// Prints the email-provider catalog table to stdout.
pub fn print_providers() {
    println!("{}", format_providers_table());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(provider: &str) -> EmailConfig {
        EmailConfig {
            provider: provider.into(),
            from: "sender@example.com".into(),
            api_key: Some("key".into()),
            ..Default::default()
        }
    }

    #[test]
    fn catalog_ids_are_unique_and_lowercase() {
        let mut seen = std::collections::HashSet::new();
        for p in PROVIDERS {
            assert_eq!(p.id, p.id.to_ascii_lowercase(), "id must be lowercase");
            assert!(seen.insert(p.id), "duplicate provider id {}", p.id);
        }
    }

    #[test]
    fn catalog_covers_the_decided_provider_set() {
        for expected in [
            "resend",
            "sendgrid",
            "mailgun",
            "mailjet",
            "mandrill",
            "brevo",
            "sparkpost",
            "mailersend",
            "zeptomail",
            "elasticemail",
            "loops",
            "postmark",
            "smtp",
        ] {
            assert!(find_provider(expected).is_some(), "missing {expected}");
        }
    }

    #[test]
    fn lookup_is_case_insensitive() {
        assert_eq!(find_provider("ReSeNd").unwrap().id, "resend");
        assert!(find_provider("nope").is_none());
    }

    #[test]
    fn unknown_provider_is_rejected() {
        let issues = validate_email_config(&config("nope"));
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("not in the catalog"));
    }

    #[test]
    fn missing_credential_is_reported() {
        let mut cfg = config("resend");
        cfg.api_key = None;
        let issues = validate_email_config(&cfg);
        assert!(
            issues.iter().any(|i| i.contains("requires API key")),
            "{issues:?}"
        );
    }

    #[test]
    fn blank_credential_counts_as_absent() {
        let mut cfg = config("resend");
        cfg.api_key = Some("   ".into());
        let issues = validate_email_config(&cfg);
        assert!(issues.iter().any(|i| i.contains("requires API key")));
    }

    #[test]
    fn bad_from_is_rejected() {
        let mut cfg = config("resend");
        cfg.from = "not-an-email".into();
        let issues = validate_email_config(&cfg);
        assert!(issues.iter().any(|i| i.contains("not a valid email")));
    }

    #[test]
    fn needs_domain_without_domain_is_rejected() {
        let mut cfg = config("mailgun");
        cfg.api_key = Some("key".into());
        let issues = validate_email_config(&cfg);
        assert!(issues.iter().any(|i| i.contains("requires domain")));

        cfg.domain = Some("mg.example.com".into());
        assert!(validate_email_config(&cfg).is_empty(), "{cfg:?}");
    }

    #[test]
    fn template_only_without_template_is_rejected() {
        let mut cfg = config("loops");
        cfg.api_key = Some("key".into());
        let issues = validate_email_config(&cfg);
        assert!(issues.iter().any(|i| i.contains("requires template_id")));

        cfg.template_id = Some("tmpl_123".into());
        let issues = validate_email_config(&cfg);
        assert!(
            !issues.iter().any(|i| i.contains("template_id")),
            "{issues:?}"
        );
    }

    #[test]
    fn smtp_requires_username_and_password() {
        let mut cfg = config("smtp");
        cfg.api_key = Some("pass".into());
        cfg.username = None;
        let issues = validate_email_config(&cfg);
        assert!(
            issues.iter().any(|i| i.contains("SMTP username")),
            "{issues:?}"
        );

        cfg.username = Some("user".into());
        cfg.api_key = None;
        let issues = validate_email_config(&cfg);
        assert!(
            issues.iter().any(|i| i.contains("SMTP password")),
            "{issues:?}"
        );
    }

    #[test]
    fn mailjet_requires_secret() {
        let mut cfg = config("mailjet");
        cfg.api_key = Some("key".into());
        let issues = validate_email_config(&cfg);
        assert!(
            issues.iter().any(|i| i.contains("secret key")),
            "{issues:?}"
        );
    }
}
