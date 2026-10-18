//! Terminal presentation: colour, icons, spinners and hyperlinks.
//!
//! Every user-facing line the CLI prints goes through here, so the rules live
//! in one place:
//!
//! * colour follows `NO_COLOR` (wins), then `CLICOLOR_FORCE`, then `CLICOLOR=0`,
//!   then whether the stream is a terminal — decided per stream;
//! * spinners animate on stderr only, and only when stderr is a terminal;
//! * OSC 8 hyperlinks are emitted only where the terminal supports them, and
//!   the visible text is always the full URL so it can still be copied;
//! * progress goes to stderr, results to stdout. Off a terminal nothing but
//!   plain text is written, so piped output stays greppable.

use std::fmt;
use std::io::IsTerminal;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use console::Style;
use indicatif::{ProgressBar, ProgressState, ProgressStyle};

/// Success.
pub const OK: &str = "\u{2714}";
/// Failure.
pub const FAIL: &str = "\u{2716}";
/// Warning.
pub const WARN: &str = "\u{26A0}";
/// Something to act on.
pub const ARROW: &str = "\u{279C}";
/// The device key.
pub const KEY: &str = "\u{1F511}";
/// A link.
pub const LINK: &str = "\u{1F517}";
/// A list bullet / the default marker.
pub const STAR: &str = "\u{2605}";

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

/// What a stream can render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// The stream is a terminal.
    pub tty: bool,
    /// ANSI colour is on.
    pub color: bool,
    /// OSC 8 hyperlinks are on.
    pub links: bool,
}

struct Ui {
    out: Caps,
    err: Caps,
    animate: bool,
}

fn ui() -> &'static Ui {
    static UI: OnceLock<Ui> = OnceLock::new();
    UI.get_or_init(|| {
        let env = |k: &str| std::env::var(k).ok();
        let dumb = env("TERM").as_deref() == Some("dumb");
        let out_tty = std::io::stdout().is_terminal();
        let err_tty = std::io::stderr().is_terminal();
        let out = Caps {
            tty: out_tty,
            color: color_choice(out_tty, env),
            links: out_tty && supports_hyperlinks::on(supports_hyperlinks::Stream::Stdout),
        };
        let err = Caps {
            tty: err_tty,
            color: color_choice(err_tty, env),
            links: err_tty && supports_hyperlinks::on(supports_hyperlinks::Stream::Stderr),
        };
        console::set_colors_enabled(out.color);
        console::set_colors_enabled_stderr(err.color);
        Ui {
            out,
            err,
            animate: err_tty && !dumb,
        }
    })
}

/// The capabilities of `stream`.
pub fn caps(stream: Stream) -> Caps {
    match stream {
        Stream::Out => ui().out,
        Stream::Err => ui().err,
    }
}

/// Whether a stream gets colour, from its TTY-ness and the environment.
///
/// `NO_COLOR` (non-empty) always wins; `CLICOLOR_FORCE` (non-empty, not `0`)
/// forces colour on a pipe; `CLICOLOR=0` and `TERM=dumb` turn it off.
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

/// The OSC 8 escape for a hyperlink to `url` reading `text`.
pub fn osc8(url: &str, text: &str) -> String {
    format!("\x1b]8;;{url}\x1b\\{text}\x1b]8;;\x1b\\")
}

/// A hyperlink for `stream`: OSC 8 when supported, else just `text`.
pub fn link(stream: Stream, url: &str, text: &str) -> String {
    if caps(stream).links {
        osc8(url, text)
    } else {
        text.to_string()
    }
}

fn paint(stream: Stream, style: Style, text: &str) -> String {
    // Settles console's colour switches before the first styled write.
    ui();
    let style = match stream {
        Stream::Out => style.for_stdout(),
        Stream::Err => style.for_stderr(),
    };
    style.apply_to(text).to_string()
}

/// Bold.
pub fn bold(stream: Stream, text: &str) -> String {
    paint(stream, Style::new().bold(), text)
}

/// Muted.
pub fn dim(stream: Stream, text: &str) -> String {
    paint(stream, Style::new().dim(), text)
}

/// Highlighted names: hosts, machines, people.
pub fn accent(stream: Stream, text: &str) -> String {
    paint(stream, Style::new().cyan().bold(), text)
}

/// Green.
pub fn green(stream: Stream, text: &str) -> String {
    paint(stream, Style::new().green(), text)
}

/// Yellow.
pub fn yellow(stream: Stream, text: &str) -> String {
    paint(stream, Style::new().yellow(), text)
}

/// Red.
pub fn red(stream: Stream, text: &str) -> String {
    paint(stream, Style::new().red(), text)
}

fn line(stream: Stream, text: &str) {
    match stream {
        Stream::Out => println!("{text}"),
        Stream::Err => eprintln!("{text}"),
    }
}

/// `✔ msg` on stdout: a final result.
pub fn success(msg: &str) {
    let icon = paint(Stream::Out, Style::new().green().bold(), OK);
    line(Stream::Out, &format!("{icon} {msg}"));
}

/// `✔ msg` on stderr: a completed step.
pub fn done(msg: &str) {
    let icon = paint(Stream::Err, Style::new().green().bold(), OK);
    line(Stream::Err, &format!("{icon} {msg}"));
}

/// `<icon> msg` on `stream`.
pub fn step(stream: Stream, icon: &str, msg: &str) {
    line(stream, &format!("{icon} {msg}"));
}

/// `⚠ msg` on stderr.
pub fn warn(msg: &str) {
    let icon = paint(Stream::Err, Style::new().yellow().bold(), WARN);
    line(Stream::Err, &format!("{icon} {}", yellow(Stream::Err, msg)));
}

/// `✖ msg` on stderr.
pub fn error(msg: &str) {
    let icon = paint(Stream::Err, Style::new().red().bold(), FAIL);
    line(
        Stream::Err,
        &format!(
            "{icon} {}",
            paint(Stream::Err, Style::new().red().bold(), msg)
        ),
    );
}

/// A dim, indented next-step line on stderr, under an error or warning.
pub fn hint(msg: &str) {
    line(Stream::Err, &format!("  {}", dim(Stream::Err, msg)));
}

/// An aligned `key  value` line on stdout.
pub fn kv(key: &str, width: usize, value: &str) {
    line(
        Stream::Out,
        &format!("  {}  {value}", dim(Stream::Out, &format!("{key:<width$}"))),
    );
}

/// An error carrying a suggested next step.
#[derive(Debug)]
pub struct Hinted {
    /// What went wrong.
    pub message: String,
    /// What to do about it.
    pub hint: String,
}

impl fmt::Display for Hinted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Hinted {}

/// A boxed [`Hinted`] error.
pub fn hinted(
    message: impl Into<String>,
    hint: impl Into<String>,
) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(Hinted {
        message: message.into(),
        hint: hint.into(),
    })
}

/// Prints a fatal error: the red line, then its hint if it has one.
pub fn report(err: &(dyn std::error::Error + 'static)) {
    error(&err.to_string());
    if let Some(h) = err.downcast_ref::<Hinted>() {
        hint(&h.hint);
    }
}

/// A spinner on stderr while something is awaited.
///
/// Off a terminal it draws nothing (unless [`Spinner::announced`]); the
/// outcome line printed by [`Spinner::done`] is the same either way.
pub struct Spinner {
    bar: Option<ProgressBar>,
    started: Instant,
}

impl Spinner {
    /// A spinner reading `msg`.
    pub fn new(msg: impl Into<String>) -> Self {
        Self::build(msg.into(), false, false)
    }

    /// A spinner that also shows a running `m:ss` clock.
    pub fn with_clock(msg: impl Into<String>) -> Self {
        Self::build(msg.into(), true, false)
    }

    /// A clocked spinner that, off a terminal, prints `msg` once instead, for
    /// waits long enough that silence would look like a hang.
    pub fn announced(msg: impl Into<String>) -> Self {
        Self::build(msg.into(), true, true)
    }

    fn build(msg: String, clock: bool, announce: bool) -> Self {
        let started = Instant::now();
        if !ui().animate {
            if announce {
                line(Stream::Err, &msg);
            }
            return Self { bar: None, started };
        }
        let template = if clock {
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
            .with_message(msg);
        bar.enable_steady_tick(Duration::from_millis(80));
        Self {
            bar: Some(bar),
            started,
        }
    }

    /// Replaces the message.
    pub fn set_message(&self, msg: impl Into<String>) {
        if let Some(bar) = &self.bar {
            bar.set_message(msg.into());
        }
    }

    /// Time since the spinner started.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Hides the spinner while `f` writes to the terminal.
    pub fn suspend<R>(&self, f: impl FnOnce() -> R) -> R {
        match &self.bar {
            Some(bar) => bar.suspend(f),
            None => f(),
        }
    }

    /// Removes the spinner and prints `✔ msg`.
    pub fn done(self, msg: &str) {
        self.clear();
        done(msg);
    }

    /// Removes the spinner and prints `✔ msg (1.2s)`.
    pub fn done_timed(self, msg: &str) {
        let took = dim(Stream::Err, &format!("({})", seconds(self.elapsed())));
        self.clear();
        done(&format!("{msg} {took}"));
    }

    /// Removes the spinner without a trace.
    pub fn clear(self) {
        if let Some(bar) = &self.bar {
            bar.finish_and_clear();
        }
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
    fn osc8_wraps_the_visible_text() {
        assert_eq!(
            osc8("https://a.example/pair#x", "https://a.example/pair#x"),
            "\x1b]8;;https://a.example/pair#x\x1b\\https://a.example/pair#x\x1b]8;;\x1b\\"
        );
    }

    #[test]
    fn clocks_and_seconds() {
        assert_eq!(clock_text(Duration::from_secs(7)), "0:07");
        assert_eq!(clock_text(Duration::from_secs(754)), "12:34");
        assert_eq!(clock_text(Duration::from_secs(3723)), "1:02:03");
        assert_eq!(seconds(Duration::from_millis(420)), "0.4s");
        assert_eq!(seconds(Duration::from_secs(12)), "12s");
    }
}
