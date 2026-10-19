//! Terminal primitives: colour, icons, lines, spinners and hyperlinks.
//!
//! * colour follows `NO_COLOR` (wins), then `CLICOLOR_FORCE`, then `CLICOLOR=0`
//!   and `TERM=dumb`, then whether the stream is a terminal, per stream;
//! * spinners animate on stderr only, and only on a terminal;
//! * OSC 8 hyperlinks only where supported, always around the full URL text;
//! * progress goes to stderr, results to stdout.

use std::fmt;
use std::io::IsTerminal;
use std::sync::OnceLock;
use std::time::Duration;

use console::Style;
use indicatif::{ProgressBar, ProgressState, ProgressStyle};

pub const OK: &str = "\u{2714}";
pub const FAIL: &str = "\u{2716}";
pub const WARN: &str = "\u{26A0}";
pub const ARROW: &str = "\u{279C}";
pub const KEY: &str = "\u{1F511}";
pub const STAR: &str = "\u{2605}";
pub const ELLIPSIS: &str = "\u{2026}";

const SPINNER_FRAMES: &[&str] = &[
    "\u{280B}", "\u{2819}", "\u{2839}", "\u{2838}", "\u{283C}", "\u{2834}", "\u{2826}", "\u{2827}",
    "\u{2807}", "\u{280F}", " ",
];

/// Which standard stream a piece of output is bound for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    /// Results.
    Out,
    /// Progress, warnings and errors.
    Err,
}

struct Caps {
    out_tty: bool,
    out_links: bool,
    err_links: bool,
    animate: bool,
}

fn caps() -> &'static Caps {
    static CAPS: OnceLock<Caps> = OnceLock::new();
    CAPS.get_or_init(|| {
        let env = |k: &str| std::env::var(k).ok();
        let out_tty = std::io::stdout().is_terminal();
        let err_tty = std::io::stderr().is_terminal();
        console::set_colors_enabled(color_choice(out_tty, env));
        console::set_colors_enabled_stderr(color_choice(err_tty, env));
        Caps {
            out_tty,
            out_links: out_tty && supports_hyperlinks::on(supports_hyperlinks::Stream::Stdout),
            err_links: err_tty && supports_hyperlinks::on(supports_hyperlinks::Stream::Stderr),
            animate: err_tty && env("TERM").as_deref() != Some("dumb"),
        }
    })
}

/// Whether stdout is a terminal.
pub fn stdout_is_tty() -> bool {
    caps().out_tty
}

/// The terminal's `(rows, columns)`, when stdout is one.
pub fn size() -> Option<(u16, u16)> {
    stdout_is_tty()
        .then(|| console::Term::stdout().size_checked())
        .flatten()
}

/// Whether a stream gets colour, from its TTY-ness and the environment.
pub fn color_choice(tty: bool, env: impl Fn(&str) -> Option<String>) -> bool {
    if env("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return false;
    }
    if env("CLICOLOR_FORCE").is_some_and(|v| !v.is_empty() && v != "0") {
        return true;
    }
    if env("CLICOLOR").as_deref() == Some("0") || env("TERM").as_deref() == Some("dumb") {
        return false;
    }
    tty
}

/// `text` styled for `stream` (plain when the stream has no colour).
pub fn paint(stream: Stream, style: &Style, text: &str) -> String {
    caps();
    let style = match stream {
        Stream::Out => style.clone().for_stdout(),
        Stream::Err => style.clone().for_stderr(),
    };
    style.apply_to(text).to_string()
}

pub fn bold(stream: Stream, text: &str) -> String {
    paint(stream, &Style::new().bold(), text)
}

pub fn dim(stream: Stream, text: &str) -> String {
    paint(stream, &Style::new().dim(), text)
}

/// Hosts, machines, people.
pub fn accent(stream: Stream, text: &str) -> String {
    paint(stream, &Style::new().cyan().bold(), text)
}

pub fn green(stream: Stream, text: &str) -> String {
    paint(stream, &Style::new().green(), text)
}

/// The OSC 8 escape for a hyperlink to `url` reading `text`.
pub fn osc8(url: &str, text: &str) -> String {
    format!("\x1b]8;;{url}\x1b\\{text}\x1b]8;;\x1b\\")
}

/// A hyperlink on `stream`: OSC 8 when supported, else just `text`.
pub fn link(stream: Stream, url: &str, text: &str) -> String {
    let supported = match stream {
        Stream::Out => caps().out_links,
        Stream::Err => caps().err_links,
    };
    if supported {
        osc8(url, text)
    } else {
        text.to_string()
    }
}

fn line(stream: Stream, text: &str) {
    match stream {
        Stream::Out => println!("{text}"),
        Stream::Err => eprintln!("{text}"),
    }
}

/// `<icon> msg` on `stream`.
pub fn step(stream: Stream, icon: &str, msg: &str) {
    line(stream, &format!("{icon} {msg}"));
}

/// `✔ msg`: a result on stdout, a completed step on stderr.
pub fn success(stream: Stream, msg: &str) {
    step(
        stream,
        &paint(stream, &Style::new().green().bold(), OK),
        msg,
    );
}

/// `⚠ msg` on stderr.
pub fn warn(msg: &str) {
    let style = Style::new().yellow().bold();
    step(
        Stream::Err,
        &paint(Stream::Err, &style, WARN),
        &paint(Stream::Err, &Style::new().yellow(), msg),
    );
}

/// `✖ msg` on stderr.
pub fn error(msg: &str) {
    let style = Style::new().red().bold();
    step(
        Stream::Err,
        &paint(Stream::Err, &style, FAIL),
        &paint(Stream::Err, &style, msg),
    );
}

/// A dim, indented next-step line on stderr.
pub fn hint(msg: &str) {
    line(Stream::Err, &format!("  {}", dim(Stream::Err, msg)));
}

/// A spinner on stderr while something is awaited. Off a terminal it draws
/// nothing, unless `announced`, which prints the message once instead.
pub struct Spinner {
    bar: Option<ProgressBar>,
}

impl Spinner {
    pub fn new(msg: &str, announced: bool) -> Self {
        if !caps().animate {
            if announced {
                line(Stream::Err, msg);
            }
            return Self { bar: None };
        }
        let template = if announced {
            "{spinner:.cyan.bold} {msg} {clock:.dim}"
        } else {
            "{spinner:.cyan.bold} {msg}"
        };
        let style = ProgressStyle::with_template(template)
            .expect("static spinner template")
            .tick_strings(SPINNER_FRAMES)
            .with_key("clock", |state: &ProgressState, w: &mut dyn fmt::Write| {
                let _ = w.write_str(&clock_text(state.elapsed()));
            });
        let bar = ProgressBar::new_spinner()
            .with_style(style)
            .with_message(msg.to_string());
        bar.enable_steady_tick(Duration::from_millis(80));
        Self { bar: Some(bar) }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        if let Some(bar) = self.bar.take() {
            bar.finish_and_clear();
        }
    }
}

/// `0:07`, `12:34`, `1:02:03`.
pub fn clock_text(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
    } else {
        format!("{}:{:02}", s / 60, s % 60)
    }
}

/// `0.4s`, `12s`.
pub fn seconds(d: Duration) -> String {
    let s = d.as_secs_f64();
    if s < 10.0 {
        format!("{s:.1}s")
    } else {
        format!("{}s", d.as_secs())
    }
}

/// At most `max` characters, ending with `…` when cut.
pub fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let keep: String = text.chars().take(max.saturating_sub(1)).collect();
    format!("{keep}{ELLIPSIS}")
}

/// At most `max` characters, keeping both ends: the informative parts of a
/// URL or a fingerprint.
pub fn truncate_middle(text: &str, max: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max {
        return text.to_string();
    }
    let head = max.saturating_sub(1) / 2;
    let tail = max.saturating_sub(1) - head;
    let mut out: String = chars[..head].iter().collect();
    out.push_str(ELLIPSIS);
    out.extend(&chars[chars.len() - tail..]);
    out
}

/// A fingerprint shortened for display: `p256:0271af4a…8329`.
pub fn short_fingerprint(text: &str) -> String {
    match text.split_once(':') {
        Some((algorithm, hex)) if hex.len() > 14 => format!(
            "{algorithm}:{}{ELLIPSIS}{}",
            &hex[..8],
            &hex[hex.len() - 4..]
        ),
        _ => text.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn colour_follows_tty_and_environment() {
        assert!(color_choice(true, env(&[])));
        assert!(!color_choice(false, env(&[])));
        assert!(!color_choice(true, env(&[("NO_COLOR", "1")])));
        // An empty NO_COLOR is unset, per no-color.org.
        assert!(color_choice(true, env(&[("NO_COLOR", "")])));
        assert!(color_choice(false, env(&[("CLICOLOR_FORCE", "1")])));
        assert!(!color_choice(false, env(&[("CLICOLOR_FORCE", "0")])));
        assert!(!color_choice(
            false,
            env(&[("CLICOLOR_FORCE", "1"), ("NO_COLOR", "1")])
        ));
        assert!(!color_choice(true, env(&[("CLICOLOR", "0")])));
        assert!(!color_choice(true, env(&[("TERM", "dumb")])));
    }

    #[test]
    fn clocks_and_seconds() {
        assert_eq!(clock_text(Duration::from_secs(7)), "0:07");
        assert_eq!(clock_text(Duration::from_secs(754)), "12:34");
        assert_eq!(clock_text(Duration::from_secs(3723)), "1:02:03");
        assert_eq!(seconds(Duration::from_millis(420)), "0.4s");
        assert_eq!(seconds(Duration::from_secs(12)), "12s");
    }

    #[test]
    fn truncation() {
        assert_eq!(truncate("abcdef", 10), "abcdef");
        assert_eq!(truncate("abcdef", 4), "abc\u{2026}");
        assert_eq!(truncate_middle("abcdefghij", 7), "abc\u{2026}hij");
        let fingerprint = format!("p256:0271af4a{}8329", "0".repeat(54));
        assert_eq!(short_fingerprint(&fingerprint), "p256:0271af4a\u{2026}8329");
        assert_eq!(short_fingerprint("p256:abcd"), "p256:abcd");
    }
}
