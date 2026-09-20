//! Terminal request log for `weave start`.
//!
//! The stdout log is the only inspection surface in M1, and within a minute
//! of registering, a public hostname is being hammered by Certificate
//! Transparency scanners. The log therefore has to make two things obvious
//! at a glance: *which service and who* a request came from, and *what
//! happened to it* (status class, size, duration). It does so with a fixed
//! column layout, one colour per status class, and a path column that is
//! truncated to the terminal width instead of wrapping.
//!
//! Colour is enabled only when stdout is a TTY and `NO_COLOR` is unset;
//! piped output is plain, stable, and greppable. `--verbose` appends the
//! request and response headers, indented under the line.

use std::io::IsTerminal;
use std::time::Duration;

use crossterm::style::{Attribute, Color, Stylize};

/// Rendering options resolved once at startup.
#[derive(Debug, Clone, Copy)]
pub struct LogStyle {
    /// Emit ANSI colours.
    pub color: bool,
    /// Terminal width in columns, if known; paths are truncated to fit.
    pub width: Option<u16>,
    /// Suppress the per-request log entirely.
    pub quiet: bool,
    /// Append request/response headers to each line.
    pub verbose: bool,
}

impl LogStyle {
    /// Detect colour support and width from the environment.
    pub fn detect(quiet: bool, verbose: bool) -> Self {
        let tty = std::io::stdout().is_terminal();
        let color = tty && std::env::var_os("NO_COLOR").is_none();
        let width = if tty {
            crossterm::terminal::size().ok().map(|(w, _)| w)
        } else {
            None
        };
        Self {
            color,
            width,
            quiet,
            verbose,
        }
    }

    /// Plain, fixed-width style for tests and piped output.
    pub fn plain(width: Option<u16>) -> Self {
        Self {
            color: false,
            width,
            quiet: false,
            verbose: false,
        }
    }
}

/// What kind of log line this is; drives the marker and the duration field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// A normal request that completed.
    Done,
    /// A long-lived stream (WebSocket, SSE) that just opened; size and
    /// duration are not yet known.
    Opened,
    /// A long-lived stream that closed; totals are final.
    Closed,
}

/// Local wall-clock `HH:MM:SS` for the request line. A foreground session
/// rarely spans a day, so the date is left out to keep the line compact;
/// the local zone is what the operator's own clock shows.
pub fn timestamp(at: std::time::SystemTime) -> String {
    let zoned = jiff::Timestamp::try_from(at)
        .map(|ts| ts.to_zoned(jiff::tz::TimeZone::system()))
        .unwrap_or_else(|_| jiff::Zoned::now());
    zoned.strftime("%H:%M:%S").to_string()
}

/// Everything one log line needs, gathered by the handler.
#[derive(Debug, Clone)]
pub struct Entry<'a> {
    /// Wall-clock time the request head arrived.
    pub at: std::time::SystemTime,
    /// Service name (first column).
    pub service: &'a str,
    /// Visitor IP as stamped by the relay in `x-forwarded-for`, if any.
    pub visitor: Option<&'a str>,
    /// `h1` / `h2` / `ws` — the visitor-side protocol.
    pub proto: &'a str,
    /// HTTP method.
    pub method: &'a str,
    /// Request path and query.
    pub path: &'a str,
    /// Response status, if known.
    pub status: Option<u16>,
    /// Response body bytes forwarded so far.
    pub bytes: u64,
    /// Time since the request head arrived.
    pub elapsed: Duration,
    /// Which line this is.
    pub phase: Phase,
}

/// A stable, distinct colour per service so `a` and `b` can be told apart
/// at a glance across the footer and every log line. Picked by hashing the
/// name into a palette of hues that stay readable on dark and light
/// backgrounds; the palette skips red/yellow/green so a service name never
/// looks like a status.
pub fn service_color(service: &str) -> Color {
    const PALETTE: [Color; 8] = [
        Color::Cyan,
        Color::Magenta,
        Color::Blue,
        Color::DarkCyan,
        Color::DarkMagenta,
        Color::AnsiValue(75),  // steel blue
        Color::AnsiValue(141), // lavender
        Color::AnsiValue(38),  // teal
    ];
    let mut h: u32 = 2166136261;
    for b in service.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(16777619);
    }
    PALETTE[(h % PALETTE.len() as u32) as usize]
}

/// Method colour: safe reads neutral, writes stand out, deletes warn.
fn method_color(method: &str) -> Color {
    match method {
        "GET" | "HEAD" | "OPTIONS" => Color::White,
        "POST" => Color::AnsiValue(214),          // orange
        "PUT" | "PATCH" => Color::AnsiValue(178), // gold
        "DELETE" => Color::Red,
        "CONNECT" | "TRACE" => Color::DarkGrey,
        _ => Color::Grey,
    }
}

/// Render the registration banner: `service  https://…/  →  target`.
pub fn registered_line(style: &LogStyle, service: &str, url: &str, target: &str) -> String {
    let svc = paint(style, service, service_color(service), true);
    let url = paint(style, url, Color::Green, false);
    let arrow = paint(style, "\u{2192}", Color::DarkGrey, false);
    format!("{svc}  {url}  {arrow}  {target}")
}

/// Render the refusal line for a service that failed to register.
pub fn refused_line(style: &LogStyle, service: &str, message: &str) -> String {
    let svc = paint(style, service, service_color(service), true);
    let tag = paint(style, "refused", Color::Red, true);
    format!("{svc}  {tag}  {message}")
}

/// Render a certificate transition (non-TTY fallback for the footer).
pub fn cert_line(style: &LogStyle, service: &str, state: weaver_proto::CertStatus) -> String {
    let svc = paint(style, service, service_color(service), true);
    let color = if state.is_serving() {
        Color::Green
    } else if state == weaver_proto::CertStatus::Failed {
        Color::Red
    } else {
        Color::Yellow
    };
    let tag = paint(style, "cert", Color::DarkGrey, false);
    let st = paint(style, state.label(), color, true);
    format!("{svc}  {tag} {st}")
}

/// Render one request line. Returns `None` when the style is quiet.
pub fn request_line(style: &LogStyle, e: &Entry<'_>) -> Option<String> {
    if style.quiet {
        return None;
    }
    let time = paint(style, &timestamp(e.at), Color::DarkGrey, false);
    let marker = match e.phase {
        Phase::Done => paint(style, "\u{2022}", Color::DarkGrey, false),
        Phase::Opened => paint(style, "\u{25B6}", Color::Magenta, true),
        Phase::Closed => paint(style, "\u{25A0}", Color::Magenta, false),
    };
    let svc = paint(style, &fixed(e.service, 8), service_color(e.service), true);
    let visitor = paint(
        style,
        &fixed(&display_ip(e.visitor.unwrap_or("-")), VISITOR_WIDTH),
        Color::DarkGrey,
        false,
    );
    let proto = paint(style, &fixed(e.proto, 2), Color::DarkGrey, false);
    let method = paint(style, &fixed(e.method, 7), method_color(e.method), true);

    let status_text = match e.status {
        Some(s) => s.to_string(),
        None => "\u{2026}".to_string(),
    };
    let status = paint(style, &fixed(&status_text, 3), status_color(e.status), true);

    let size = match e.phase {
        Phase::Opened => "      ".to_string(),
        _ => fixed_right(&human_bytes(e.bytes), 6),
    };
    let dur = match e.phase {
        Phase::Opened => paint(style, &fixed_right("open", 7), Color::Magenta, false),
        _ => paint(
            style,
            &fixed_right(&human_duration(e.elapsed), 7),
            Color::DarkGrey,
            false,
        ),
    };
    let size = paint(style, &size, Color::DarkGrey, false);

    // Everything but the path is fixed width; the path gets the remainder
    // and is truncated with an ellipsis rather than wrapped.
    let fixed_cols =
        8 + 1 + 1 + 1 + 8 + 2 + VISITOR_WIDTH + 2 + 2 + 2 + 7 + 2 + 3 + 2 + 6 + 2 + 7 + 2;
    let path_width = style
        .width
        .map(|w| (w as usize).saturating_sub(fixed_cols).max(8))
        .unwrap_or(usize::MAX);
    let path = truncate(e.path, path_width);
    let path = paint(style, &path, path_color(e.status), false);

    Some(format!(
        "{time} {marker} {svc}  {visitor}  {proto}  {method}  {status}  {size}  {dur}  {path}"
    ))
}

/// Render an indented header block for `--verbose`.
pub fn header_block(style: &LogStyle, prefix: &str, headers: &[(String, Vec<u8>)]) -> String {
    let mut out = String::new();
    for (name, value) in headers {
        let name = paint(style, name, Color::DarkGrey, false);
        out.push_str(&format!(
            "    {prefix} {name}: {}\n",
            String::from_utf8_lossy(value)
        ));
    }
    out
}

/// Width of the visitor column: any IPv4 (15) fits whole, and an IPv6 shows
/// its first four hextets — the routing prefix, which is what identifies a
/// network — before being cut (`2001:db8:85a3:8d3:…`).
const VISITOR_WIDTH: usize = 20;

/// Normalize an address for display: unwrap an IPv4-mapped IPv6
/// (`::ffff:203.0.113.9` → `203.0.113.9`), strip a port, and shorten a
/// long IPv6 to its first four hextets with an ellipsis instead of
/// letting the column cut it at an arbitrary character.
pub fn display_ip(raw: &str) -> String {
    let s = raw.trim();
    // Strip a port on either family; the relay does not send one, but a
    // forged or upstream-appended value might.
    let s = if let Some(inner) = s.strip_prefix('[').and_then(|r| r.split(']').next()) {
        inner
    } else if s.matches(':').count() == 1 {
        s.split(':').next().unwrap_or(s)
    } else {
        s
    };
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => v4.to_string(),
            std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => v4.to_string(),
                None => shorten_v6(&v6.to_string()),
            },
        };
    }
    s.to_string()
}

/// Keep the first four hextets of a canonical IPv6 string if the whole
/// thing does not fit the column.
fn shorten_v6(canonical: &str) -> String {
    if canonical.chars().count() <= VISITOR_WIDTH {
        return canonical.to_string();
    }
    // Split on ':' but preserve a leading "::".
    let groups: Vec<&str> = canonical.split(':').collect();
    let head: Vec<&str> = groups.iter().take(4).copied().collect();
    let mut out = head.join(":");
    if out.chars().count() > VISITOR_WIDTH - 2 {
        out = out.chars().take(VISITOR_WIDTH - 2).collect();
    }
    format!("{out}:\u{2026}")
}

fn status_color(status: Option<u16>) -> Color {
    match status {
        None => Color::DarkGrey,
        Some(100..=199) => Color::Cyan,
        Some(200..=299) => Color::Green,
        Some(300..=399) => Color::Yellow,
        Some(400..=499) => Color::DarkYellow,
        Some(500..=599) => Color::Red,
        Some(_) => Color::White,
    }
}

fn path_color(status: Option<u16>) -> Color {
    match status {
        Some(400..=599) => Color::DarkGrey,
        _ => Color::Reset,
    }
}

fn paint(style: &LogStyle, text: &str, color: Color, bold: bool) -> String {
    if !style.color {
        return text.to_string();
    }
    let styled = text.with(color);
    if bold {
        styled.attribute(Attribute::Bold).to_string()
    } else {
        styled.to_string()
    }
}

/// Left-align in exactly `width` columns, truncating with `…`.
fn fixed(text: &str, width: usize) -> String {
    let t = truncate(text, width);
    format!("{t:<width$}")
}

/// Right-align in exactly `width` columns.
fn fixed_right(text: &str, width: usize) -> String {
    let t = truncate(text, width);
    format!("{t:>width$}")
}

/// Truncate to `max` characters, ending with `…` when cut.
fn truncate(text: &str, max: usize) -> String {
    let count = text.chars().count();
    if count <= max {
        return text.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let keep: String = text.chars().take(max - 1).collect();
    format!("{keep}\u{2026}")
}

/// `0B`, `463B`, `1.2K`, `17.4M`, `2.0G`.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["K", "M", "G", "T"];
    if n < 1024 {
        return format!("{n}B");
    }
    let mut v = n as f64 / 1024.0;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if v >= 100.0 {
        format!("{v:.0}{}", UNITS[unit])
    } else {
        format!("{v:.1}{}", UNITS[unit])
    }
}

/// `850µs`, `3.4ms`, `1.20s`, `2m03s`.
pub fn human_duration(d: Duration) -> String {
    let us = d.as_micros();
    if us < 1_000 {
        format!("{us}\u{00B5}s")
    } else if us < 1_000_000 {
        format!("{:.1}ms", us as f64 / 1_000.0)
    } else if us < 60_000_000 {
        format!("{:.2}s", us as f64 / 1_000_000.0)
    } else {
        let secs = d.as_secs();
        format!("{}m{:02}s", secs / 60, secs % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry<'a>(path: &'a str, status: Option<u16>, phase: Phase) -> Entry<'a> {
        Entry {
            at: std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            service: "web",
            visitor: Some("203.0.113.9"),
            proto: "h2",
            method: "GET",
            path,
            status,
            bytes: 463,
            elapsed: Duration::from_micros(850),
            phase,
        }
    }

    #[test]
    fn plain_line_has_stable_columns() {
        let style = LogStyle::plain(None);
        let line = request_line(&style, &entry("/hello", Some(200), Phase::Done)).unwrap();
        // `HH:MM:SS` depends on the local zone; check its shape, then the
        // fixed-width remainder exactly.
        let (time, rest) = line.split_once(' ').unwrap();
        assert_eq!(time.len(), 8, "{time}");
        assert!(
            time.as_bytes()[2] == b':' && time.as_bytes()[5] == b':',
            "{time}"
        );
        assert_eq!(
            rest,
            "\u{2022} web       203.0.113.9           h2  GET      200    463B    850\u{00B5}s  /hello"
        );
    }

    #[test]
    fn timestamp_is_compact_hms() {
        let t = timestamp(std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        assert_eq!(t.len(), 8);
        assert_eq!(&t[2..3], ":");
        assert_eq!(&t[5..6], ":");
    }

    #[test]
    fn quiet_suppresses() {
        let mut style = LogStyle::plain(None);
        style.quiet = true;
        assert!(request_line(&style, &entry("/", Some(200), Phase::Done)).is_none());
    }

    #[test]
    fn path_is_truncated_to_width() {
        let style = LogStyle::plain(Some(100));
        let long = "/".to_string() + &"a".repeat(200);
        let line = request_line(&style, &entry(&long, Some(404), Phase::Done)).unwrap();
        assert!(line.chars().count() <= 100, "{}", line.chars().count());
        assert!(line.ends_with('\u{2026}'));
        // Narrower than the fixed columns: the path still gets its minimum
        // and the line does not panic.
        let tiny = LogStyle::plain(Some(40));
        let line = request_line(&tiny, &entry(&long, Some(404), Phase::Done)).unwrap();
        assert!(line.ends_with('\u{2026}'));
    }

    #[test]
    fn opened_and_closed_phases() {
        let style = LogStyle::plain(None);
        let open = request_line(&style, &entry("/ws", Some(101), Phase::Opened)).unwrap();
        assert!(open.contains(" \u{25B6} "));
        assert!(open.contains("   open"));
        let closed = request_line(&style, &entry("/ws", Some(101), Phase::Closed)).unwrap();
        assert!(closed.contains(" \u{25A0} "));
        assert!(closed.contains("463B"));
    }

    #[test]
    fn colour_is_applied_only_when_enabled() {
        let plain = LogStyle::plain(None);
        assert!(!registered_line(&plain, "web", "https://x/", "http://l:1").contains("\x1b["));
        let mut color = plain;
        color.color = true;
        assert!(registered_line(&color, "web", "https://x/", "http://l:1").contains("\x1b["));
    }

    #[test]
    fn humanizers() {
        assert_eq!(human_bytes(0), "0B");
        assert_eq!(human_bytes(463), "463B");
        assert_eq!(human_bytes(1536), "1.5K");
        assert_eq!(human_bytes(200 * 1024 * 1024), "200M");
        assert_eq!(human_duration(Duration::from_micros(850)), "850\u{00B5}s");
        assert_eq!(human_duration(Duration::from_micros(3400)), "3.4ms");
        assert_eq!(human_duration(Duration::from_millis(1200)), "1.20s");
        assert_eq!(human_duration(Duration::from_secs(123)), "2m03s");
    }

    #[test]
    fn visitor_ip_display() {
        assert_eq!(display_ip("::ffff:79.112.1.2"), "79.112.1.2");
        assert_eq!(display_ip("203.0.113.9"), "203.0.113.9");
        assert_eq!(display_ip("203.0.113.9:51234"), "203.0.113.9");
        assert_eq!(display_ip("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(display_ip("2001:db8::1"), "2001:db8::1");
        // Long IPv6: first four hextets, then an ellipsis, within the column.
        let long = display_ip("2001:0db8:85a3:08d3:1319:8a2e:0370:7344");
        assert_eq!(long, "2001:db8:85a3:8d3:\u{2026}");
        assert!(long.chars().count() <= VISITOR_WIDTH);
        assert_eq!(display_ip("-"), "-");
        // Any IPv4 fits whole in the column.
        assert!("255.255.255.255".len() <= VISITOR_WIDTH);
    }

    #[test]
    fn services_get_distinct_stable_colours() {
        assert_eq!(service_color("web"), service_color("web"));
        let mut seen = std::collections::HashSet::new();
        for s in ["a", "b", "web", "api", "docs", "grafana"] {
            seen.insert(format!("{:?}", service_color(s)));
        }
        assert!(seen.len() >= 4, "palette too collision-prone: {seen:?}");
    }

    #[test]
    fn missing_visitor_and_status() {
        let style = LogStyle::plain(None);
        let mut e = entry("/", None, Phase::Opened);
        e.visitor = None;
        let line = request_line(&style, &e).unwrap();
        assert!(line.contains(" -               "));
        assert!(line.contains("\u{2026}  "));
    }
}
