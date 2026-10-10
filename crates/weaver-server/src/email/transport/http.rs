//! HTTP transports for the catalogued providers.
//!
//! One shared `hyper` client, one data-driven request builder. Auth scheme,
//! endpoint, and body shape are interpreted from [`EmailProviderInfo`]; the
//! provider-specific bodies are the only per-id match. Redirects are disabled
//! and every send is bounded by [`SEND_TIMEOUT`].

use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use bytes::Bytes;
use http::{Method, Request};
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde_json::{Value, json};

use crate::config::EmailConfig;
use crate::email::providers::{AuthScheme, EmailProviderInfo, find_provider};
use crate::email::{Email, Mailbox, Mailer, MailerError, MailerIdentity, SendReceipt};

/// Every send is awaited with this timeout so a hanging provider surfaces.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Shared HTTPS-capable client (`https_or_http` keeps the CI mock reachable).
type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// A fully shaped request, separated from the socket so request-shaping tests
/// can assert on it without a network.
#[derive(Clone)]
pub(crate) struct Prepared {
    /// Absolute URL.
    pub url: String,
    /// `Content-Type` header value.
    pub content_type: &'static str,
    /// Auth and other headers (lower-cased names).
    pub headers: Vec<(String, String)>,
    /// Serialized body.
    pub body: Vec<u8>,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the body or headers: both may carry credentials.
        f.debug_struct("Prepared")
            .field("url", &self.url)
            .field("content_type", &self.content_type)
            .finish_non_exhaustive()
    }
}

/// The HTTP mailer.
pub struct HttpMailer {
    identity: MailerIdentity,
    info: &'static EmailProviderInfo,
    cfg: EmailConfig,
    endpoint: String,
    client: HttpClient,
}

impl HttpMailer {
    /// Builds the transport, validating the resolved endpoint.
    pub fn new(identity: MailerIdentity, cfg: &EmailConfig) -> Result<Self, MailerError> {
        let info = find_provider(&cfg.provider).ok_or_else(|| {
            MailerError::Config(format!(
                "email provider '{}' is not in the catalog",
                cfg.provider
            ))
        })?;
        if !matches!(
            info.kind,
            crate::email::providers::ProviderKind::HttpJson
                | crate::email::providers::ProviderKind::HttpForm
        ) {
            return Err(MailerError::Config(format!(
                "email provider '{}' is not an HTTP provider",
                cfg.provider
            )));
        }
        let endpoint = resolve_base(info, cfg)?;
        let client = build_client()?;
        Ok(HttpMailer {
            identity,
            info,
            cfg: cfg.clone(),
            endpoint,
            client,
        })
    }

    /// Shapes the request for a message without sending it.
    pub(crate) fn prepare(&self, email: &Email) -> Result<Prepared, MailerError> {
        prepare_request(self.info, &self.cfg, &self.endpoint, email)
    }
}

#[async_trait]
impl Mailer for HttpMailer {
    fn identity(&self) -> &MailerIdentity {
        &self.identity
    }

    async fn send(&self, email: &Email) -> Result<SendReceipt, MailerError> {
        let prepared = self.prepare(email)?;

        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(&prepared.url)
            .header(http::header::CONTENT_TYPE, prepared.content_type);
        for (name, value) in &prepared.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let request = builder
            .body(Full::new(Bytes::from(prepared.body)))
            .map_err(|e| {
                MailerError::Transport(format!("invalid {}-request: {e}", self.info.id))
            })?;

        let response = tokio::time::timeout(SEND_TIMEOUT, self.client.request(request))
            .await
            .map_err(|_| MailerError::Transport("request timed out".into()))?
            .map_err(|e| MailerError::Transport(self.identity.redact(&format!("{e}"))))?;

        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|e| MailerError::Transport(self.identity.redact(&format!("{e}"))))?
            .to_bytes();

        if status.is_success() {
            return Ok(SendReceipt {
                message_id: extract_message_id(&headers, &body),
            });
        }

        let text = String::from_utf8_lossy(&body);
        Err(MailerError::Rejected {
            status: Some(status.as_u16()),
            provider_code: extract_error_code(&text),
            detail: self.identity.redact(&extract_error_detail(&text)),
        })
    }
}

/// Builds the shared HTTPS client. Platform roots are used, and plain HTTP is
/// allowed so the endpoint override can point at a CI mock.
fn build_client() -> Result<HttpClient, MailerError> {
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .try_with_platform_verifier()
        .map_err(|e| MailerError::Config(format!("failed to load system TLS roots: {e}")))?
        .https_or_http()
        .enable_http1()
        .build();
    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

/// Resolves the provider base URL, honouring the optional override.
pub(crate) fn resolve_base(
    info: &EmailProviderInfo,
    cfg: &EmailConfig,
) -> Result<String, MailerError> {
    let base = cfg
        .endpoint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or(info.api_base)
        .ok_or_else(|| {
            MailerError::Config(format!("email provider '{}' requires an endpoint", info.id))
        })?;
    Ok(base.trim_end_matches('/').to_string())
}

/// Shapes a request from the catalog data and the provider body builder.
pub(crate) fn prepare_request(
    info: &EmailProviderInfo,
    cfg: &EmailConfig,
    endpoint: &str,
    email: &Email,
) -> Result<Prepared, MailerError> {
    let (content_type, body) = build_body(info, cfg, email)?;
    let url = build_url(info, cfg, endpoint)?;
    let mut headers = auth_headers(info, cfg)?;
    headers.push((
        http::header::CONTENT_TYPE.as_str().to_string(),
        content_type.to_string(),
    ));
    Ok(Prepared {
        url,
        content_type,
        headers,
        body,
    })
}

/// Composes the URL from the resolved base and the provider path.
fn build_url(
    info: &EmailProviderInfo,
    cfg: &EmailConfig,
    endpoint: &str,
) -> Result<String, MailerError> {
    let url = match info.id {
        "resend" => format!("{endpoint}/emails"),
        "sendgrid" => format!("{endpoint}/v3/mail/send"),
        "mailgun" => {
            let domain = cfg.domain.as_deref().map(str::trim).unwrap_or("");
            if domain.is_empty() {
                return Err(MailerError::Config(
                    "provider 'mailgun' requires domain".into(),
                ));
            }
            format!("{endpoint}/{domain}/messages")
        }
        "mailjet" => format!("{endpoint}/v3.1/send"),
        "mandrill" => format!("{endpoint}/api/1.0/messages/send.json"),
        "brevo" => format!("{endpoint}/v3/smtp/email"),
        "sparkpost" => format!("{endpoint}/api/v1/transmissions"),
        "mailersend" => format!("{endpoint}/v1/email"),
        "zeptomail" => format!("{endpoint}/v1.1/email"),
        "elasticemail" => format!("{endpoint}/v4/emails"),
        "loops" => format!("{endpoint}/api/v1/transactional"),
        "postmark" => format!("{endpoint}/email"),
        other => {
            return Err(MailerError::Config(format!(
                "no HTTP request shape for provider '{other}'"
            )));
        }
    };
    Ok(url)
}

/// Returns `(content_type, body_bytes)` for the provider.
fn build_body(
    info: &EmailProviderInfo,
    cfg: &EmailConfig,
    email: &Email,
) -> Result<(&'static str, Vec<u8>), MailerError> {
    match info.id {
        "resend" => json_body(&resend_body(email)),
        "sendgrid" => json_body(&sendgrid_body(email)),
        "mailgun" => Ok((
            "application/x-www-form-urlencoded",
            form_body(email).into_bytes(),
        )),
        "mailjet" => json_body(&mailjet_body(email)),
        "mandrill" => json_body(&mandrill_body(cfg, email)),
        "brevo" => json_body(&brevo_body(email)),
        "sparkpost" => json_body(&sparkpost_body(email)),
        "mailersend" => json_body(&mailersend_body(email)),
        "zeptomail" => json_body(&zeptomail_body(email)),
        "elasticemail" => json_body(&elasticemail_body(email)),
        "loops" => json_body(&loops_body(cfg, email)),
        "postmark" => json_body(&postmark_body(email)),
        other => Err(MailerError::Config(format!(
            "no HTTP body shape for provider '{other}'"
        ))),
    }
}

fn json_body(value: &Value) -> Result<(&'static str, Vec<u8>), MailerError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| MailerError::Config(format!("failed to encode request body: {e}")))?;
    Ok(("application/json", bytes))
}

/// `Name <addr>` when a display name is present, else the bare address.
fn addr_spec(mb: &Mailbox) -> String {
    match mb.name.as_deref() {
        Some(name) if !name.is_empty() => format!("{name} <{}>", mb.address),
        _ => mb.address.clone(),
    }
}

/// `{"email": .., "name": ..}` with `name` omitted when absent.
fn object_email(mb: &Mailbox) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("email".into(), json!(mb.address));
    if let Some(name) = mb.name.as_deref().filter(|n| !n.is_empty()) {
        map.insert("name".into(), json!(name));
    }
    Value::Object(map)
}

/// `{"address": .., "name": ..}` (ZeptoMail's shape).
fn object_address(mb: &Mailbox) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("address".into(), json!(mb.address));
    if let Some(name) = mb.name.as_deref().filter(|n| !n.is_empty()) {
        map.insert("name".into(), json!(name));
    }
    Value::Object(map)
}

/// `reply_to` as a single object/string when present.
fn reply_value(email: &Email) -> Option<&Mailbox> {
    email.reply_to.as_ref()
}

fn resend_body(email: &Email) -> Value {
    let mut body = json!({
        "from": addr_spec(&email.from),
        "to": email.to.iter().map(|m| m.address.clone()).collect::<Vec<_>>(),
        "subject": email.subject,
        "text": email.text,
    });
    body["html"] = json!(email.html);
    if let Some(reply) = reply_value(email) {
        body["reply_to"] = json!(reply.address);
    }
    body
}

fn sendgrid_body(email: &Email) -> Value {
    let mut body = json!({
        "personalizations": [{ "to": email.to.iter().map(object_email).collect::<Vec<_>>() }],
        "from": object_email(&email.from),
        "subject": email.subject,
        "content": content_array(email),
    });
    if let Some(reply) = reply_value(email) {
        body["reply_to"] = object_email(reply);
    }
    body
}

/// SendGrid content array: text first, HTML second (the documented order).
fn content_array(email: &Email) -> Value {
    let content = vec![
        json!({ "type": "text/plain", "value": email.text }),
        json!({ "type": "text/html", "value": email.html }),
    ];
    Value::Array(content)
}

fn mailjet_body(email: &Email) -> Value {
    let mut message = json!({
        "From": object_email(&email.from),
        "To": email.to.iter().map(object_email).collect::<Vec<_>>(),
        "Subject": email.subject,
        "TextPart": email.text,
    });
    message["HTMLPart"] = json!(email.html);
    if let Some(reply) = reply_value(email) {
        message["ReplyTo"] = object_email(reply);
    }
    json!({ "Messages": [message] })
}

fn mandrill_body(cfg: &EmailConfig, email: &Email) -> Value {
    let key = cfg.api_key.clone().unwrap_or_default();
    let mut message = json!({
        "html": email.html.clone(),
        "text": email.text,
        "subject": email.subject,
        "from_email": email.from.address,
        "to": email.to.iter().map(|m| json!({ "email": m.address, "type": "to" })).collect::<Vec<_>>(),
    });
    if let Some(name) = email.from.name.as_deref().filter(|n| !n.is_empty()) {
        message["from_name"] = json!(name);
    }
    let mut headers = serde_json::Map::new();
    if let Some(reply) = reply_value(email) {
        headers.insert("Reply-To".into(), json!(reply.address));
    }
    if !headers.is_empty() {
        message["headers"] = Value::Object(headers);
    }
    json!({ "key": key, "message": message })
}

fn brevo_body(email: &Email) -> Value {
    let mut body = json!({
        "sender": object_email(&email.from),
        "to": email.to.iter().map(object_email).collect::<Vec<_>>(),
        "subject": email.subject,
        "textContent": email.text,
    });
    body["htmlContent"] = json!(email.html);
    if let Some(reply) = reply_value(email) {
        body["replyTo"] = object_email(reply);
    }
    body
}

fn sparkpost_body(email: &Email) -> Value {
    let mut content = json!({
        "from": addr_spec(&email.from),
        "subject": email.subject,
        "text": email.text,
    });
    content["html"] = json!(email.html);
    if let Some(reply) = reply_value(email) {
        content["reply_to"] = json!(reply.address);
    }
    json!({
        "recipients": email.to.iter().map(|m| json!({ "address": m.address })).collect::<Vec<_>>(),
        "content": content,
    })
}

fn mailersend_body(email: &Email) -> Value {
    let mut body = json!({
        "from": object_email(&email.from),
        "to": email.to.iter().map(object_email).collect::<Vec<_>>(),
        "subject": email.subject,
        "text": email.text,
    });
    body["html"] = json!(email.html);
    if let Some(reply) = reply_value(email) {
        body["reply_to"] = object_email(reply);
    }
    body
}

fn zeptomail_body(email: &Email) -> Value {
    let mut body = json!({
        "from": object_address(&email.from),
        "to": email.to.iter().map(|m| json!({ "email_address": object_address(m) })).collect::<Vec<_>>(),
        "subject": email.subject,
        "textbody": email.text,
    });
    body["htmlbody"] = json!(email.html);
    body
}

fn elasticemail_body(email: &Email) -> Value {
    let body_parts = vec![
        json!({ "ContentType": "PlainText", "Content": email.text }),
        json!({ "ContentType": "HTML", "Content": email.html }),
    ];
    let mut content = json!({
        "From": addr_spec(&email.from),
        "Subject": email.subject,
        "Body": body_parts,
    });
    if let Some(reply) = reply_value(email) {
        content["ReplyTo"] = json!(reply.address);
    }
    json!({
        "Recipients": email.to.iter().map(|m| {
            match m.name.as_deref().filter(|n| !n.is_empty()) {
                Some(name) => json!({ "Email": m.address, "Fields": { "name": name } }),
                None => json!({ "Email": m.address }),
            }
        }).collect::<Vec<_>>(),
        "Content": content,
    })
}

fn loops_body(cfg: &EmailConfig, email: &Email) -> Value {
    // Template-only: Loops renders its own registered template, so the subject
    // and bodies are not sent. The catalog requires the template id up front.
    json!({
        "transactionalId": cfg.template_id.clone().unwrap_or_default(),
        "email": email.to.first().map(|m| m.address.clone()).unwrap_or_default(),
    })
}

fn postmark_body(email: &Email) -> Value {
    let mut body = json!({
        "From": addr_spec(&email.from),
        "To": email.to.iter().map(addr_spec).collect::<Vec<_>>().join(","),
        "Subject": email.subject,
        "TextBody": email.text,
    });
    body["HtmlBody"] = json!(email.html);
    if let Some(reply) = reply_value(email) {
        body["ReplyTo"] = json!(reply.address);
    }
    body
}

/// Mailgun form body. `h:Reply-To` is Mailgun's header escape.
fn form_body(email: &Email) -> String {
    let mut fields: Vec<(String, String)> = vec![
        ("from".into(), addr_spec(&email.from)),
        (
            "to".into(),
            email.to.iter().map(addr_spec).collect::<Vec<_>>().join(","),
        ),
        ("subject".into(), email.subject.clone()),
        ("text".into(), email.text.clone()),
    ];
    fields.push(("html".into(), email.html.clone()));
    if let Some(reply) = reply_value(email) {
        fields.push(("h:Reply-To".into(), reply.address.clone()));
    }
    fields
        .into_iter()
        .map(|(k, v)| format!("{}={}", urlencode(&k), urlencode(&v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Minimal `application/x-www-form-urlencoded` encoder (RFC 3986 unreserved).
fn urlencode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Auth headers for the provider's catalog scheme.
fn auth_headers(
    info: &EmailProviderInfo,
    cfg: &EmailConfig,
) -> Result<Vec<(String, String)>, MailerError> {
    let key = |field: crate::email::providers::CredentialField| -> Result<String, MailerError> {
        cfg.credential(field).map(str::to_string).ok_or_else(|| {
            MailerError::Config(format!(
                "email provider '{}' is missing a credential",
                info.id
            ))
        })
    };
    use crate::email::providers::CredentialField;
    let headers = match info.auth {
        AuthScheme::Bearer => vec![(
            "authorization".to_string(),
            format!("Bearer {}", key(CredentialField::ApiKey)?),
        )],
        AuthScheme::Header { name, prefix } => vec![(
            name.to_ascii_lowercase(),
            format!("{prefix}{}", key(CredentialField::ApiKey)?),
        )],
        AuthScheme::Basic => {
            let credentials = match info.id {
                // Mailgun: the username is the literal `api`, the key is the password.
                "mailgun" => format!("api:{}", key(CredentialField::ApiKey)?),
                // Mailjet: key is the username, secret is the password.
                "mailjet" => format!(
                    "{}:{}",
                    key(CredentialField::ApiKey)?,
                    key(CredentialField::Secret)?
                ),
                _ => format!(
                    "{}:{}",
                    cfg.username.clone().unwrap_or_default(),
                    key(CredentialField::ApiKey)?
                ),
            };
            let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
            vec![("authorization".to_string(), format!("Basic {encoded}"))]
        }
        // Mandrill carries the key in the body; SMTP does its own thing.
        AuthScheme::BodyKey | AuthScheme::None => Vec::new(),
    };
    Ok(headers)
}

/// Extracts a message id from a response header or JSON body.
fn extract_message_id(headers: &http::HeaderMap, body: &[u8]) -> Option<String> {
    for header in [
        "x-message-id",
        "x-messageid",
        "x-resend-id",
        "x-postmark-messageid",
    ] {
        if let Some(value) = headers.get(header).and_then(|v| v.to_str().ok())
            && !value.is_empty()
        {
            return Some(value.to_string());
        }
    }
    let value: Value = serde_json::from_slice(body).ok()?;
    for key in ["id", "message_id", "messageId", "MessageID", "Id"] {
        if let Some(found) = value.get(key).and_then(Value::as_str)
            && !found.is_empty()
        {
            return Some(found.to_string());
        }
    }
    None
}

/// Extracts a provider error code from an error body, when present.
fn extract_error_code(body: &str) -> Option<String> {
    let value: Value = serde_json::from_str(body).ok()?;
    for key in ["code", "name", "errorCode", "ErrorCode", "statusCode"] {
        if let Some(found) = value.get(key).and_then(Value::as_str) {
            return Some(found.to_string());
        }
    }
    None
}

/// Extracts a human detail from an error body, without echoing credentials.
fn extract_error_detail(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return "provider returned an empty error body".into();
    }
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        for key in [
            "message",
            "error",
            "error_message",
            "Error",
            "Message",
            "detail",
        ] {
            if let Some(found) = value.get(key).and_then(Value::as_str) {
                return found.to_string();
            }
        }
        if let Some(errors) = value.get("errors").and_then(Value::as_array) {
            let joined = errors
                .iter()
                .filter_map(|e| {
                    e.as_str()
                        .map(str::to_string)
                        .or_else(|| e.get("message").and_then(Value::as_str).map(str::to_string))
                })
                .collect::<Vec<_>>()
                .join("; ");
            if !joined.is_empty() {
                return joined;
            }
        }
    }
    // Cap unbounded provider bodies so an error cannot flood logs.
    trimmed.chars().take(512).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::email::providers::find_provider;

    fn config(provider: &str) -> EmailConfig {
        EmailConfig {
            provider: provider.into(),
            from: "Sender Name <sender@example.com>".into(),
            from_name: Some("Sender Name".into()),
            api_key: Some("KEY123".into()),
            secret: Some("SECRET456".into()),
            username: Some("user7".into()),
            domain: Some("mg.example.com".into()),
            template_id: Some("tmpl_abc".into()),
            ..Default::default()
        }
    }

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

    fn prep(provider: &str) -> Prepared {
        let cfg = config(provider);
        let info = find_provider(provider).unwrap();
        let base = resolve_base(info, &cfg).unwrap();
        prepare_request(info, &cfg, &base, &fixture()).unwrap()
    }

    fn body_json(p: &Prepared) -> Value {
        serde_json::from_slice(&p.body).unwrap()
    }

    fn header<'a>(p: &'a Prepared, name: &str) -> Option<&'a str> {
        p.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn resend_shape() {
        let p = prep("resend");
        assert_eq!(p.url, "https://api.resend.com/emails");
        assert_eq!(p.content_type, "application/json");
        assert_eq!(header(&p, "authorization"), Some("Bearer KEY123"));
        let body = body_json(&p);
        assert_eq!(body["from"], "Sender Name <sender@example.com>");
        assert_eq!(body["to"][0], "dest@example.org");
        assert_eq!(body["subject"], "Hello");
        assert_eq!(body["text"], "plain body");
        assert_eq!(body["html"], "<p>html body</p>");
        assert_eq!(body["reply_to"], "reply@example.com");
    }

    #[test]
    fn sendgrid_shape() {
        let p = prep("sendgrid");
        assert_eq!(p.url, "https://api.sendgrid.com/v3/mail/send");
        assert_eq!(header(&p, "authorization"), Some("Bearer KEY123"));
        let body = body_json(&p);
        assert_eq!(
            body["personalizations"][0]["to"][0]["email"],
            "dest@example.org"
        );
        assert_eq!(body["from"]["email"], "sender@example.com");
        assert_eq!(body["from"]["name"], "Sender Name");
        assert_eq!(body["content"][0]["type"], "text/plain");
        assert_eq!(body["content"][0]["value"], "plain body");
        assert_eq!(body["content"][1]["type"], "text/html");
        assert_eq!(body["reply_to"]["email"], "reply@example.com");
    }

    #[test]
    fn mailgun_shape_is_form_with_domain_path() {
        let p = prep("mailgun");
        assert_eq!(p.url, "https://api.mailgun.net/v3/mg.example.com/messages");
        assert_eq!(p.content_type, "application/x-www-form-urlencoded");
        // Basic api:KEY -> base64("api:KEY123")
        let expected = base64::engine::general_purpose::STANDARD.encode("api:KEY123");
        assert_eq!(
            header(&p, "authorization"),
            Some(format!("Basic {expected}").as_str())
        );
        let body = String::from_utf8(p.body.clone()).unwrap();
        assert!(
            body.contains("from=Sender+Name+%3Csender%40example.com%3E"),
            "{body}"
        );
        assert!(body.contains("dest%40example.org"), "{body}");
        assert!(body.contains("subject=Hello"));
        assert!(body.contains("text=plain+body"));
        assert!(body.contains("html=%3Cp%3Ehtml+body%3C%2Fp%3E"));
        assert!(body.contains("h%3AReply-To=reply%40example.com"));
    }

    #[test]
    fn mailjet_shape_uses_basic_key_secret() {
        let p = prep("mailjet");
        assert_eq!(p.url, "https://api.mailjet.com/v3.1/send");
        let expected = base64::engine::general_purpose::STANDARD.encode("KEY123:SECRET456");
        assert_eq!(
            header(&p, "authorization"),
            Some(format!("Basic {expected}").as_str())
        );
        let body = body_json(&p);
        assert_eq!(body["Messages"][0]["From"]["email"], "sender@example.com");
        assert_eq!(body["Messages"][0]["Subject"], "Hello");
        assert_eq!(body["Messages"][0]["TextPart"], "plain body");
        assert_eq!(body["Messages"][0]["HTMLPart"], "<p>html body</p>");
        assert_eq!(body["Messages"][0]["ReplyTo"]["email"], "reply@example.com");
    }

    #[test]
    fn mandrill_shape_puts_key_in_body() {
        let p = prep("mandrill");
        assert_eq!(p.url, "https://mandrillapp.com/api/1.0/messages/send.json");
        assert_eq!(header(&p, "authorization"), None);
        let body = body_json(&p);
        assert_eq!(body["key"], "KEY123");
        assert_eq!(body["message"]["from_email"], "sender@example.com");
        assert_eq!(body["message"]["from_name"], "Sender Name");
        assert_eq!(body["message"]["to"][0]["email"], "dest@example.org");
        assert_eq!(body["message"]["headers"]["Reply-To"], "reply@example.com");
    }

    #[test]
    fn brevo_shape_uses_api_key_header() {
        let p = prep("brevo");
        assert_eq!(p.url, "https://api.brevo.com/v3/smtp/email");
        assert_eq!(header(&p, "api-key"), Some("KEY123"));
        let body = body_json(&p);
        assert_eq!(body["sender"]["email"], "sender@example.com");
        assert_eq!(body["textContent"], "plain body");
        assert_eq!(body["htmlContent"], "<p>html body</p>");
        assert_eq!(body["replyTo"]["email"], "reply@example.com");
    }

    #[test]
    fn sparkpost_shape_uses_key_scheme() {
        let p = prep("sparkpost");
        assert_eq!(p.url, "https://api.sparkpost.com/api/v1/transmissions");
        assert_eq!(header(&p, "authorization"), Some("KEY KEY123"));
        let body = body_json(&p);
        assert_eq!(body["recipients"][0]["address"], "dest@example.org");
        assert_eq!(body["content"]["from"], "Sender Name <sender@example.com>");
        assert_eq!(body["content"]["text"], "plain body");
        assert_eq!(body["content"]["html"], "<p>html body</p>");
        assert_eq!(body["content"]["reply_to"], "reply@example.com");
    }

    #[test]
    fn mailersend_shape() {
        let p = prep("mailersend");
        assert_eq!(p.url, "https://api.mailersend.com/v1/email");
        assert_eq!(header(&p, "authorization"), Some("Bearer KEY123"));
        let body = body_json(&p);
        assert_eq!(body["from"]["email"], "sender@example.com");
        assert_eq!(body["text"], "plain body");
        assert_eq!(body["html"], "<p>html body</p>");
        assert_eq!(body["reply_to"]["email"], "reply@example.com");
    }

    #[test]
    fn zeptomail_shape() {
        let p = prep("zeptomail");
        assert_eq!(p.url, "https://api.zeptomail.com/v1.1/email");
        assert_eq!(header(&p, "authorization"), Some("Zoho-enczapikey KEY123"));
        let body = body_json(&p);
        assert_eq!(body["from"]["address"], "sender@example.com");
        assert_eq!(
            body["to"][0]["email_address"]["address"],
            "dest@example.org"
        );
        assert_eq!(body["textbody"], "plain body");
        assert_eq!(body["htmlbody"], "<p>html body</p>");
    }

    #[test]
    fn elasticemail_shape() {
        let p = prep("elasticemail");
        assert_eq!(p.url, "https://api.elasticemail.com/v4/emails");
        assert_eq!(header(&p, "x-elasticemail-apikey"), Some("KEY123"));
        let body = body_json(&p);
        assert_eq!(body["Recipients"][0]["Email"], "dest@example.org");
        assert_eq!(body["Content"]["From"], "Sender Name <sender@example.com>");
        assert_eq!(body["Content"]["Body"][0]["ContentType"], "PlainText");
        assert_eq!(body["Content"]["Body"][1]["ContentType"], "HTML");
    }

    #[test]
    fn loops_shape_is_template_only() {
        let p = prep("loops");
        assert_eq!(p.url, "https://app.loops.so/api/v1/transactional");
        assert_eq!(header(&p, "authorization"), Some("Bearer KEY123"));
        let body = body_json(&p);
        assert_eq!(body["transactionalId"], "tmpl_abc");
        assert_eq!(body["email"], "dest@example.org");
        assert!(body.get("subject").is_none());
    }

    #[test]
    fn postmark_shape() {
        let p = prep("postmark");
        assert_eq!(p.url, "https://api.postmarkapp.com/email");
        assert_eq!(header(&p, "x-postmark-server-token"), Some("KEY123"));
        let body = body_json(&p);
        assert_eq!(body["From"], "Sender Name <sender@example.com>");
        assert_eq!(body["To"], "Dest <dest@example.org>");
        assert_eq!(body["TextBody"], "plain body");
        assert_eq!(body["HtmlBody"], "<p>html body</p>");
        assert_eq!(body["ReplyTo"], "reply@example.com");
    }

    #[test]
    fn endpoint_override_replaces_the_base() {
        let mut cfg = config("mailgun");
        cfg.endpoint = Some("https://api.eu.mailgun.net/v3/".into());
        let info = find_provider("mailgun").unwrap();
        let base = resolve_base(info, &cfg).unwrap();
        let p = prepare_request(info, &cfg, &base, &fixture()).unwrap();
        assert_eq!(
            p.url,
            "https://api.eu.mailgun.net/v3/mg.example.com/messages"
        );
    }

    #[test]
    fn error_detail_prefers_message_and_is_bounded() {
        assert_eq!(
            extract_error_detail(r#"{"message":"bad key","code":"auth"}"#),
            "bad key"
        );
        assert_eq!(
            extract_error_code(r#"{"code":"auth"}"#),
            Some("auth".into())
        );
        assert!(extract_error_detail("").contains("empty"));
        let long = "x".repeat(2000);
        assert_eq!(extract_error_detail(&long).chars().count(), 512);
    }

    #[test]
    fn message_id_from_header_or_body() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-message-id", "abc".parse().unwrap());
        assert_eq!(extract_message_id(&headers, b"{}"), Some("abc".to_string()));
        let mut empty = http::HeaderMap::new();
        empty.insert("x-message-id", "".parse().unwrap());
        assert_eq!(
            extract_message_id(&empty, br#"{"id":"prov-1"}"#),
            Some("prov-1".to_string())
        );
    }
}
