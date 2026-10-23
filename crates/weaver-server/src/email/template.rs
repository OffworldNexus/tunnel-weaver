//! Typed templates rendered through Askama, then compiled by `mrml`.
//!
//! Each known email ships one MJML source, one plain-text twin, and (for now)
//! English copy. Askama fills the typed context — HTML-escaping every value,
//! including attributes — and renders the shared partials into in-memory
//! strings. A [`MemoryIncludeLoader`] then serves those rendered partials to
//! `mrml`, so compilation never touches the filesystem at runtime.
//!
//! This is the "fill first, then compile" order: every placeholder is substituted
//! and escaped in one pass, then the trusted result is compiled.
//!
//! Localisation is deliberately absent: the project has no i18n yet. The copy
//! below is English, and a future ticket can introduce per-locale tables behind
//! the same typed context.

use std::collections::HashMap;

use askama::Template;
use mrml::prelude::parser::ParserOptions;
use mrml::prelude::parser::memory_loader::MemoryIncludeLoader;
use mrml::prelude::render::RenderOptions;

use crate::email::{EmailTemplate, RenderError, Rendered, TemplateEnv};

/// Gmail clips messages larger than roughly 102 KB; keep compiled HTML under
/// this so the whole message is visible.
const GMAIL_CLIP_BYTES: usize = 100 * 1024;

/// English copy for the joke template.
const SUBJECT: &str = "A joke from Tunnel Weaver";
const PREVIEW: &str = "A small joke, relayed to you.";
const HEADING: &str = "Here's a joke";
const FOOTNOTE: &str = "This is a development message from Tunnel Weaver. No action is needed.";

/// HTML copy for the setup/configure OTP variant. Its subject and plain-text
/// twin already live in [`crate::email::otp`]; these only fill the layout.
const OTP_PREVIEW: &str = "Use this code to prove your Tunnel Weaver email provider.";
const OTP_INTRO: &str = "Enter this code to prove your email provider.";
const OTP_SAFETY: &str = "If you did not request this, you can ignore this message.";

// --- Shared partials (copied from docs/brand/emails/partials) --------------

/// `partials/head.mjml`: title, preview, and the shared MJML attribute table.
#[derive(Template)]
#[template(path = "email/partials/head.mjml", escape = "html", ext = "mjml")]
struct HeadTemplate<'a> {
    subject: &'a str,
    preview: &'a str,
}

/// `partials/header.mjml`: the text-only wordmark and brand rule.
#[derive(Template)]
#[template(path = "email/partials/header.mjml", escape = "html", ext = "mjml")]
struct HeaderTemplate;

/// `partials/footer.mjml`: the account footer with the validated support link.
#[derive(Template)]
#[template(path = "email/partials/footer.mjml", escape = "html", ext = "mjml")]
struct FooterTemplate<'a> {
    support_url: &'a str,
}

/// Renders the shared head/header/footer partials, then compiles `body_mjml`
/// into the base layout with `mrml`. This is the one pipeline every variant
/// shares: `body_mjml` is already filled and escaped by Askama, so the compiled
/// result is trusted. Returns the HTML, or a [`RenderError`] when a partial or
/// the document fails, or the result would cross the Gmail clipping threshold.
fn render_base(
    subject: &str,
    preview: &str,
    body_mjml: &str,
    support_url: &str,
) -> Result<String, RenderError> {
    let head = HeadTemplate { subject, preview }
        .render()
        .map_err(|e| RenderError::Template(e.to_string()))?;
    let header = HeaderTemplate
        .render()
        .map_err(|e| RenderError::Template(e.to_string()))?;
    let footer = FooterTemplate { support_url }
        .render()
        .map_err(|e| RenderError::Template(e.to_string()))?;

    // The include paths here must match `path="./partials/*.mjml"` in every
    // variant. `MemoryIncludeLoader` is the runtime include boundary; a missing
    // partial is a hard error, never a silent empty string.
    let loader = MemoryIncludeLoader::from(HashMap::from([
        ("./partials/head.mjml".to_string(), head),
        ("./partials/header.mjml".to_string(), header),
        ("./partials/footer.mjml".to_string(), footer),
    ]));

    let parsed = mrml::parse_with_options(
        body_mjml,
        &ParserOptions {
            include_loader: Box::new(loader),
        },
    )
    .map_err(|e| RenderError::Mjml(e.to_string()))?;
    let html = parsed
        .element
        .render(&RenderOptions::default())
        .map_err(|e| RenderError::Mjml(e.to_string()))?;

    if html.len() > GMAIL_CLIP_BYTES {
        return Err(RenderError::Mjml(format!(
            "compiled email HTML is {} bytes, over the {GMAIL_CLIP_BYTES}-byte Gmail clipping threshold",
            html.len()
        )));
    }
    Ok(html)
}

// --- The joke template -----------------------------------------------------

/// `joke.mjml`: the variant body; it includes the three shared partials.
#[derive(Template)]
#[template(path = "email/joke.mjml", escape = "html", ext = "mjml")]
struct JokeMjml<'a> {
    heading: &'a str,
    /// Dynamic joke line; escaped like every other value.
    line: &'a str,
    footnote: &'a str,
}

/// `joke.txt`: the authored plain-text twin (no HTML escaping).
#[derive(Template)]
#[template(path = "email/joke.txt", escape = "none", ext = "txt")]
struct JokeTxt<'a> {
    heading: &'a str,
    line: &'a str,
    footnote: &'a str,
    support_url: &'a str,
}

/// The dynamic joke line. It travels as written.
#[derive(Debug, Clone)]
pub struct Joke {
    /// The joke itself.
    pub line: String,
}

impl Joke {
    /// Stable template id.
    pub const ID: &'static str = "joke";
}

impl EmailTemplate for Joke {
    fn id(&self) -> &'static str {
        Self::ID
    }

    fn render(&self, env: &TemplateEnv) -> Result<Rendered, RenderError> {
        let mjml_source = JokeMjml {
            heading: HEADING,
            line: &self.line,
            footnote: FOOTNOTE,
        }
        .render()
        .map_err(|e| RenderError::Template(e.to_string()))?;
        let html = render_base(SUBJECT, PREVIEW, &mjml_source, &env.support_url)?;

        let text = JokeTxt {
            heading: HEADING,
            line: &self.line,
            footnote: FOOTNOTE,
            support_url: &env.support_url,
        }
        .render()
        .map_err(|e| RenderError::Template(e.to_string()))?;

        Ok(Rendered {
            subject: SUBJECT.to_string(),
            text,
            html,
        })
    }
}

// --- The setup/configure OTP variant ---------------------------------------

/// `otp.mjml`: the verification-code body; it includes the three shared partials.
#[derive(Template)]
#[template(path = "email/otp.mjml", escape = "html", ext = "mjml")]
struct OtpMjml<'a> {
    heading: &'a str,
    intro: &'a str,
    /// The numeric code; escaped like every other value.
    code: &'a str,
    expiry: &'a str,
    safety: &'a str,
}

/// The one-time code that proves an email provider during setup/configure.
///
/// Its copy already lives in [`crate::email::otp`]: the subject and the authored
/// plain-text twin are reused as-is, and this type only adds the HTML rendering
/// of the same content through the shared base layout.
#[derive(Debug, Clone)]
pub struct Otp {
    /// The numeric code sent to the operator.
    pub code: String,
}

impl Otp {
    /// Stable template id.
    pub const ID: &'static str = "otp";
}

impl EmailTemplate for Otp {
    fn id(&self) -> &'static str {
        Self::ID
    }

    fn render(&self, env: &TemplateEnv) -> Result<Rendered, RenderError> {
        use crate::email::otp;

        let expiry = format!("It expires in {} minutes.", otp::OTP_TTL_SECS / 60);
        let mjml_source = OtpMjml {
            heading: otp::OTP_SUBJECT,
            intro: OTP_INTRO,
            code: &self.code,
            expiry: &expiry,
            safety: OTP_SAFETY,
        }
        .render()
        .map_err(|e| RenderError::Template(e.to_string()))?;
        let html = render_base(
            otp::OTP_SUBJECT,
            OTP_PREVIEW,
            &mjml_source,
            &env.support_url,
        )?;

        Ok(Rendered {
            subject: otp::OTP_SUBJECT.to_string(),
            text: otp::otp_body(&self.code, &env.support_url),
            html,
        })
    }
}

// --- The email verification template ------------------------------

/// `verification.mjml`: the confirm-address body.
#[derive(Template)]
#[template(path = "email/verification.mjml", escape = "html", ext = "mjml")]
struct VerificationMjml<'a> {
    heading: &'a str,
    intro: &'a str,
    verification_url: &'a str,
    expiry: &'a str,
}

/// `verification.txt`: the authored plain-text twin.
#[derive(Template)]
#[template(path = "email/verification.txt", escape = "none", ext = "txt")]
struct VerificationTxt<'a> {
    heading: &'a str,
    intro: &'a str,
    verification_url: &'a str,
    expiry: &'a str,
    support_url: &'a str,
}

/// English copy for the verification template.
const VERIFICATION_SUBJECT: &str = "Verify your email address";
const VERIFICATION_PREVIEW: &str =
    "Confirm your email address to finish creating your Tunnel Weaver account.";
const VERIFICATION_HEADING: &str = "Verify your email";
const VERIFICATION_INTRO: &str =
    "Confirm this email address to continue creating your Tunnel Weaver account.";

/// The confirm-address email. `expires_in` is a short human phrase supplied by
/// the caller (e.g. `"24 hours"`) so the copy always matches the token lifetime
/// rather than duplicating it as a constant.
#[derive(Debug, Clone)]
pub struct Verification {
    /// Absolute HTTPS link the recipient opens to prove ownership.
    pub verification_url: String,
    /// Human phrase describing the token lifetime.
    pub expires_in: String,
}

impl Verification {
    /// Stable template id.
    pub const ID: &'static str = "verification";
}

impl EmailTemplate for Verification {
    fn id(&self) -> &'static str {
        Self::ID
    }

    fn render(&self, env: &TemplateEnv) -> Result<Rendered, RenderError> {
        if !crate::email::is_trusted_https(&self.verification_url) {
            return Err(RenderError::UntrustedUrl(self.verification_url.clone()));
        }
        let expiry = format!(
            "This link expires in {}. If you didn't create an account, you can ignore this email.",
            self.expires_in
        );
        let mjml_source = VerificationMjml {
            heading: VERIFICATION_HEADING,
            intro: VERIFICATION_INTRO,
            verification_url: &self.verification_url,
            expiry: &expiry,
        }
        .render()
        .map_err(|e| RenderError::Template(e.to_string()))?;
        let html = render_base(
            VERIFICATION_SUBJECT,
            VERIFICATION_PREVIEW,
            &mjml_source,
            &env.support_url,
        )?;

        let text = VerificationTxt {
            heading: VERIFICATION_HEADING,
            intro: VERIFICATION_INTRO,
            verification_url: &self.verification_url,
            expiry: &expiry,
            support_url: &env.support_url,
        }
        .render()
        .map_err(|e| RenderError::Template(e.to_string()))?;

        Ok(Rendered {
            subject: VERIFICATION_SUBJECT.to_string(),
            text,
            html,
        })
    }
}

// --- The password-reset template ----------------------------------

/// `reset.mjml`: the choose-a-new-password body.
#[derive(Template)]
#[template(path = "email/reset.mjml", escape = "html", ext = "mjml")]
struct ResetMjml<'a> {
    heading: &'a str,
    intro: &'a str,
    reset_url: &'a str,
    expiry: &'a str,
}

/// `reset.txt`: the authored plain-text twin.
#[derive(Template)]
#[template(path = "email/reset.txt", escape = "none", ext = "txt")]
struct ResetTxt<'a> {
    heading: &'a str,
    intro: &'a str,
    reset_url: &'a str,
    expiry: &'a str,
    support_url: &'a str,
}

/// English copy for the reset template.
const RESET_SUBJECT: &str = "Reset your password";
const RESET_PREVIEW: &str = "Choose a new password for your Tunnel Weaver account.";
const RESET_HEADING: &str = "Reset your password";
const RESET_INTRO: &str =
    "We received a request to reset your Tunnel Weaver password. Choose a new one to continue.";

/// The password-reset email. `expires_in` is a short human phrase supplied by
/// the caller (e.g. `"1 hour"`) so the copy always matches the token lifetime
/// rather than duplicating it as a constant.
#[derive(Debug, Clone)]
pub struct Reset {
    /// Absolute HTTPS link the recipient opens to choose a new password. The
    /// raw token travels in the URL fragment, so it never reaches HTTP logs.
    pub reset_url: String,
    /// Human phrase describing the token lifetime.
    pub expires_in: String,
}

impl Reset {
    /// Stable template id.
    pub const ID: &'static str = "reset";
}

impl EmailTemplate for Reset {
    fn id(&self) -> &'static str {
        Self::ID
    }

    fn render(&self, env: &TemplateEnv) -> Result<Rendered, RenderError> {
        if !crate::email::is_trusted_https(&self.reset_url) {
            return Err(RenderError::UntrustedUrl(self.reset_url.clone()));
        }
        let expiry = format!(
            "This link expires in {}. If you didn't request a password reset, you can ignore this email.",
            self.expires_in
        );
        let mjml_source = ResetMjml {
            heading: RESET_HEADING,
            intro: RESET_INTRO,
            reset_url: &self.reset_url,
            expiry: &expiry,
        }
        .render()
        .map_err(|e| RenderError::Template(e.to_string()))?;
        let html = render_base(RESET_SUBJECT, RESET_PREVIEW, &mjml_source, &env.support_url)?;

        let text = ResetTxt {
            heading: RESET_HEADING,
            intro: RESET_INTRO,
            reset_url: &self.reset_url,
            expiry: &expiry,
            support_url: &env.support_url,
        }
        .render()
        .map_err(|e| RenderError::Template(e.to_string()))?;

        Ok(Rendered {
            subject: RESET_SUBJECT.to_string(),
            text,
            html,
        })
    }
}

// --- The password-changed notification template -------------------

/// `password-changed.mjml`: the security-notification body.
#[derive(Template)]
#[template(path = "email/password-changed.mjml", escape = "html", ext = "mjml")]
struct PasswordChangedMjml<'a> {
    heading: &'a str,
    intro: &'a str,
    recovery_url: &'a str,
    support_url: &'a str,
}

/// `password-changed.txt`: the authored plain-text twin.
#[derive(Template)]
#[template(path = "email/password-changed.txt", escape = "none", ext = "txt")]
struct PasswordChangedTxt<'a> {
    heading: &'a str,
    intro: &'a str,
    recovery_url: &'a str,
    support_url: &'a str,
}

/// English copy for the password-changed template.
const PASSWORD_CHANGED_SUBJECT: &str = "Your password was changed";
const PASSWORD_CHANGED_PREVIEW: &str = "If this wasn't you, here's what to do.";
const PASSWORD_CHANGED_HEADING: &str = "Your password was changed";

/// The "your password was changed" security notification.
///
/// Sent only *after* a change has committed — whether a reset or a signed-in
/// change — so the copy can never describe an event that rolled back.
/// `event_time` is a human phrase and must carry a timezone, per the brand
/// contract (`docs/brand/emails/README.md`).
#[derive(Debug, Clone)]
pub struct PasswordChanged {
    /// Human time of the change, timezone-qualified.
    pub event_time: String,
    /// Absolute HTTPS link to the normal password-recovery page. Recovery, not a
    /// pre-authorised action, so a forwarded mail cannot be replayed into a
    /// change.
    pub recovery_url: String,
}

impl PasswordChanged {
    /// Stable template id.
    pub const ID: &'static str = "password-changed";
}

impl EmailTemplate for PasswordChanged {
    fn id(&self) -> &'static str {
        Self::ID
    }

    fn render(&self, env: &TemplateEnv) -> Result<Rendered, RenderError> {
        if !crate::email::is_trusted_https(&self.recovery_url) {
            return Err(RenderError::UntrustedUrl(self.recovery_url.clone()));
        }
        let intro = format!(
            "The password for your Tunnel Weaver account was changed on {}.",
            self.event_time
        );
        let mjml_source = PasswordChangedMjml {
            heading: PASSWORD_CHANGED_HEADING,
            intro: &intro,
            recovery_url: &self.recovery_url,
            support_url: &env.support_url,
        }
        .render()
        .map_err(|e| RenderError::Template(e.to_string()))?;
        let html = render_base(
            PASSWORD_CHANGED_SUBJECT,
            PASSWORD_CHANGED_PREVIEW,
            &mjml_source,
            &env.support_url,
        )?;

        let text = PasswordChangedTxt {
            heading: PASSWORD_CHANGED_HEADING,
            intro: &intro,
            recovery_url: &self.recovery_url,
            support_url: &env.support_url,
        }
        .render()
        .map_err(|e| RenderError::Template(e.to_string()))?;

        Ok(Rendered {
            subject: PASSWORD_CHANGED_SUBJECT.to_string(),
            text,
            html,
        })
    }
}

// --- The welcome template -----------------------------------------
/// `welcome.mjml`: the account-ready body.
#[derive(Template)]
#[template(path = "email/welcome.mjml", escape = "html", ext = "mjml")]
struct WelcomeMjml<'a> {
    heading: &'a str,
    intro: &'a str,
    account_url: &'a str,
    footnote: &'a str,
}

/// `welcome.txt`: the authored plain-text twin.
#[derive(Template)]
#[template(path = "email/welcome.txt", escape = "none", ext = "txt")]
struct WelcomeTxt<'a> {
    heading: &'a str,
    intro: &'a str,
    account_url: &'a str,
    footnote: &'a str,
    support_url: &'a str,
}

/// English copy for the welcome template.
const WELCOME_SUBJECT: &str = "Welcome to Tunnel Weaver";
const WELCOME_PREVIEW: &str = "Your Tunnel Weaver account is ready.";
const WELCOME_HEADING: &str = "Welcome to Tunnel Weaver";
const WELCOME_INTRO: &str =
    "Your account is ready. Open Tunnel Weaver when you're ready to get connected.";
const WELCOME_FOOTNOTE: &str =
    "You're all set. Keep this email if you'd like a quick way back to your account.";

/// The account-ready email, sent once after activation completes.
#[derive(Debug, Clone)]
pub struct Welcome {
    /// Absolute HTTPS link back to the signed-in account plane.
    pub account_url: String,
}

impl Welcome {
    /// Stable template id.
    pub const ID: &'static str = "welcome";
}

impl EmailTemplate for Welcome {
    fn id(&self) -> &'static str {
        Self::ID
    }

    fn render(&self, env: &TemplateEnv) -> Result<Rendered, RenderError> {
        if !crate::email::is_trusted_https(&self.account_url) {
            return Err(RenderError::UntrustedUrl(self.account_url.clone()));
        }
        let mjml_source = WelcomeMjml {
            heading: WELCOME_HEADING,
            intro: WELCOME_INTRO,
            account_url: &self.account_url,
            footnote: WELCOME_FOOTNOTE,
        }
        .render()
        .map_err(|e| RenderError::Template(e.to_string()))?;
        let html = render_base(
            WELCOME_SUBJECT,
            WELCOME_PREVIEW,
            &mjml_source,
            &env.support_url,
        )?;

        let text = WelcomeTxt {
            heading: WELCOME_HEADING,
            intro: WELCOME_INTRO,
            account_url: &self.account_url,
            footnote: WELCOME_FOOTNOTE,
            support_url: &env.support_url,
        }
        .render()
        .map_err(|e| RenderError::Template(e.to_string()))?;

        Ok(Rendered {
            subject: WELCOME_SUBJECT.to_string(),
            text,
            html,
        })
    }
}

// --- The inactivity warning template ------------------------------

/// `inactivity-warning.mjml`: the "your account will be deleted" body.
#[derive(Template)]
#[template(path = "email/inactivity-warning.mjml", escape = "html", ext = "mjml")]
struct InactivityWarningMjml<'a> {
    heading: &'a str,
    intro: &'a str,
    signin_url: &'a str,
    expiry: &'a str,
}

/// `inactivity-warning.txt`: the authored plain-text twin.
#[derive(Template)]
#[template(path = "email/inactivity-warning.txt", escape = "none", ext = "txt")]
struct InactivityWarningTxt<'a> {
    heading: &'a str,
    intro: &'a str,
    signin_url: &'a str,
    expiry: &'a str,
    support_url: &'a str,
}

/// English copy for the inactivity warning template.
const INACTIVITY_WARNING_SUBJECT: &str = "Your Tunnel Weaver account will be deleted";
const INACTIVITY_WARNING_PREVIEW: &str =
    "Sign in within a month or your account and its data will be removed.";
const INACTIVITY_WARNING_HEADING: &str = "Your account is about to be deleted";

/// The inactivity warning, sent once when an account has gone unused for almost
/// the whole threshold.
///
/// `delete_on` is a human, timezone-qualified date and `signin_url` is the
/// ordinary sign-in page — signing in there is what resets the clock. Both are
/// supplied by the caller so the copy always matches the configured timeline
/// rather than restating it.
#[derive(Debug, Clone)]
pub struct InactivityWarning {
    /// Absolute HTTPS link to the sign-in page; signing in resets the clock.
    pub signin_url: String,
    /// Human, timezone-qualified deletion date.
    pub delete_on: String,
}

impl InactivityWarning {
    /// Stable template id.
    pub const ID: &'static str = "inactivity-warning";
}

impl EmailTemplate for InactivityWarning {
    fn id(&self) -> &'static str {
        Self::ID
    }

    fn render(&self, env: &TemplateEnv) -> Result<Rendered, RenderError> {
        if !crate::email::is_trusted_https(&self.signin_url) {
            return Err(RenderError::UntrustedUrl(self.signin_url.clone()));
        }
        let intro = format!(
            "Your Tunnel Weaver account has not been used for a long time. It will be deleted on {} unless you sign in. Signing in takes a moment and keeps everything as it is.",
            self.delete_on
        );
        let expiry = "If you do nothing, the account and all of its data will be permanently removed on that date.";
        let mjml_source = InactivityWarningMjml {
            heading: INACTIVITY_WARNING_HEADING,
            intro: &intro,
            signin_url: &self.signin_url,
            expiry,
        }
        .render()
        .map_err(|e| RenderError::Template(e.to_string()))?;
        let html = render_base(
            INACTIVITY_WARNING_SUBJECT,
            INACTIVITY_WARNING_PREVIEW,
            &mjml_source,
            &env.support_url,
        )?;

        let text = InactivityWarningTxt {
            heading: INACTIVITY_WARNING_HEADING,
            intro: &intro,
            signin_url: &self.signin_url,
            expiry,
            support_url: &env.support_url,
        }
        .render()
        .map_err(|e| RenderError::Template(e.to_string()))?;

        Ok(Rendered {
            subject: INACTIVITY_WARNING_SUBJECT.to_string(),
            text,
            html,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> TemplateEnv {
        TemplateEnv::new("https://relay.example.org/support").unwrap()
    }

    fn joke() -> Joke {
        Joke {
            line: "Why did the tunnel cross the road? To get to the other side.".into(),
        }
    }

    #[test]
    fn joke_renders_html_with_partials() {
        let rendered = joke().render(&env()).unwrap();
        assert!(rendered.html.contains("Here&#39;s a joke"));
        assert!(rendered.html.contains("To get to the other side."));
        // The shared footer partial resolved and its support link made it in.
        assert!(rendered.html.contains("https://relay.example.org/support"));
        // The shared header partial resolved; brand wordmark present.
        assert!(rendered.html.contains("TUNNEL WEAVER"));
        // mrml produced a real document, not the raw source.
        assert!(rendered.html.contains("<html"));
        assert!(!rendered.html.contains("mj-include"));
        assert_eq!(rendered.subject, SUBJECT);
    }

    #[test]
    fn text_twin_is_tag_free_and_carries_support_url() {
        let rendered = joke().render(&env()).unwrap();
        assert!(
            !rendered.text.contains('<'),
            "text twin has tags: {}",
            rendered.text
        );
        assert!(rendered.text.contains("To get to the other side."));
        assert!(rendered.text.contains("https://relay.example.org/support"));
    }

    #[test]
    fn dynamic_line_is_escaped_not_injected() {
        let hostile = Joke {
            line: "<script>alert('x')</script> & \"quoted\"".into(),
        };
        let rendered = hostile.render(&env()).unwrap();
        assert!(!rendered.html.contains("<script>"));
        // mrml escapes text with numeric entities; either form is a refusal to
        // emit a real tag.
        assert!(rendered.html.contains("&#60;script&#62;"));
        // Text twin is plain: the raw characters remain, but no tag is formed.
        assert!(rendered.text.contains("<script>"));
    }

    #[test]
    fn compiled_html_is_under_the_gmail_clip() {
        let rendered = joke().render(&env()).unwrap();
        assert!(
            rendered.html.len() < GMAIL_CLIP_BYTES,
            "compiled to {} bytes",
            rendered.html.len()
        );
    }

    #[test]
    fn otp_renders_html_through_the_shared_base_layout() {
        let rendered = Otp {
            code: "042424".into(),
        }
        .render(&env())
        .unwrap();
        // Leading zero survives in both parts.
        assert!(rendered.html.contains("042424"));
        assert!(rendered.text.contains("042424"));
        // The shared partials resolved: header wordmark and footer support link.
        assert!(rendered.html.contains("TUNNEL WEAVER"));
        assert!(rendered.html.contains("https://relay.example.org/support"));
        assert!(rendered.html.contains("<html"));
        assert!(!rendered.html.contains("mj-include"));
        assert_eq!(rendered.subject, crate::email::otp::OTP_SUBJECT);
        // The text twin is the existing tag-free `otp_body`.
        assert!(!rendered.text.contains('<'));
        assert!(rendered.text.contains("5 minutes"));
    }

    #[test]
    fn password_changed_renders_the_event_and_both_links() {
        let rendered = PasswordChanged {
            event_time: "2026-10-12 14:01 UTC".into(),
            recovery_url: "https://relay.example.org/forgot-password".into(),
        }
        .render(&env())
        .unwrap();
        // The event time and the recovery link are carried in both parts.
        assert!(rendered.html.contains("2026-10-12 14:01 UTC"));
        assert!(
            rendered
                .html
                .contains("https://relay.example.org/forgot-password")
        );
        assert!(rendered.text.contains("2026-10-12 14:01 UTC"));
        assert!(
            rendered
                .text
                .contains("https://relay.example.org/forgot-password")
        );
        // Shared partials resolved and the footer's support link is present.
        assert!(rendered.html.contains("TUNNEL WEAVER"));
        assert!(rendered.html.contains("https://relay.example.org/support"));
        assert!(rendered.html.contains("<html"));
        assert!(!rendered.html.contains("mj-include"));
        // A security notice is tag-free in plain text.
        assert!(!rendered.text.contains('<'));
        assert_eq!(rendered.subject, PASSWORD_CHANGED_SUBJECT);
    }

    #[test]
    fn password_changed_rejects_an_untrusted_recovery_url() {
        let err = PasswordChanged {
            event_time: "2026-10-12 14:01 UTC".into(),
            recovery_url: "http://relay.example.org/forgot-password".into(),
        }
        .render(&env())
        .unwrap_err();
        assert!(matches!(err, RenderError::UntrustedUrl(_)));
    }

    #[test]
    fn inactivity_warning_carries_the_date_and_link_in_both_parts() {
        let rendered = InactivityWarning {
            signin_url: "https://relay.example.org/sign-in".into(),
            delete_on: "2027-10-23 12:00 UTC".into(),
        }
        .render(&env())
        .unwrap();
        assert!(rendered.html.contains("2027-10-23 12:00 UTC"));
        assert!(rendered.html.contains("https://relay.example.org/sign-in"));
        assert!(rendered.text.contains("2027-10-23 12:00 UTC"));
        assert!(rendered.text.contains("https://relay.example.org/sign-in"));
        // Shared partials resolved; the footer's support link is present.
        assert!(rendered.html.contains("TUNNEL WEAVER"));
        assert!(rendered.html.contains("https://relay.example.org/support"));
        assert!(rendered.html.contains("<html"));
        assert!(!rendered.html.contains("mj-include"));
        assert!(!rendered.text.contains('<'));
        assert_eq!(rendered.subject, INACTIVITY_WARNING_SUBJECT);
    }

    #[test]
    fn inactivity_warning_rejects_an_untrusted_link() {
        let err = InactivityWarning {
            signin_url: "http://relay.example.org/sign-in".into(),
            delete_on: "2027-10-23 12:00 UTC".into(),
        }
        .render(&env())
        .unwrap_err();
        assert!(matches!(err, RenderError::UntrustedUrl(_)));
    }
}
