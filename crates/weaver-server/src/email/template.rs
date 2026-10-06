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
}
