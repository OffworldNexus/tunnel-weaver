//! How `weave start` looks: the request log and the sticky status footer.
//!
//! Within a minute of registering, a public hostname is hit by Certificate
//! Transparency scanners, so the log makes *which service and who* and *what
//! happened* obvious at a glance: fixed columns, one colour per status class,
//! and a path truncated to the terminal width instead of wrapping.
//!
//! On a terminal the bottom rows hold one line per service (certificate state,
//! public link, local target) and the log scrolls above them, using the VT
//! scroll region (`CSI t;b r`). Off a terminal there is no footer and state
//! changes are printed as plain lines instead.

use std::collections::BTreeMap;
use std::io::Write;
use std::time::Duration;

use console::{Color, Style};
use weave::{Phase, RequestEvent, ServiceSpec};
use weaver_proto::CertStatus;

use crate::term::{self, ELLIPSIS, Stream};

fn paint(text: &str, style: Style) -> String {
    term::paint(Stream::Out, &style, text)
}

fn fg(color: Color) -> Style {
    Style::new().fg(color)
}

/// A stable, distinct colour per service, from a palette that avoids the
/// status colours (red, yellow, green).
fn service_color(service: &str) -> Color {
    const PALETTE: [Color; 8] = [
        Color::Cyan,
        Color::Magenta,
        Color::Blue,
        Color::Color256(30),
        Color::Color256(90),
        Color::Color256(75),
        Color::Color256(141),
        Color::Color256(38),
    ];
    let hash = service.bytes().fold(2_166_136_261u32, |h, b| {
        (h ^ u32::from(b)).wrapping_mul(16_777_619)
    });
    PALETTE[hash as usize % PALETTE.len()]
}

fn method_style(method: &str) -> Style {
    match method {
        "GET" | "HEAD" | "OPTIONS" => fg(Color::White),
        "POST" => fg(Color::Color256(214)),
        "PUT" | "PATCH" => fg(Color::Color256(178)),
        "DELETE" => fg(Color::Red),
        _ => Style::new().dim(),
    }
    .bold()
}

fn status_style(status: Option<u16>) -> Style {
    match status {
        Some(100..=199) => fg(Color::Cyan),
        Some(200..=299) => fg(Color::Green),
        Some(300..=399) => fg(Color::Yellow),
        Some(400..=499) => fg(Color::Color256(136)),
        Some(500..=599) => fg(Color::Red),
        _ => Style::new().dim(),
    }
    .bold()
}

/// Width of the visitor column: any IPv4 fits whole, an IPv6 shows its first
/// four hextets (the routing prefix).
const VISITOR_WIDTH: usize = 20;

/// Every column but the path.
const FIXED_COLUMNS: usize =
    8 + 3 + 8 + 2 + VISITOR_WIDTH + 2 + 2 + 2 + 7 + 2 + 3 + 2 + 6 + 2 + 7 + 2;

/// One request line, its path truncated to `width`.
pub fn request_line(e: &RequestEvent<'_>, width: Option<u16>) -> String {
    let time = paint(&timestamp(e.at), Style::new().dim());
    let marker = match e.phase {
        Phase::Done => paint("\u{2022}", Style::new().dim()),
        Phase::Opened => paint("\u{25B6}", fg(Color::Magenta).bold()),
        Phase::Closed => paint("\u{25A0}", fg(Color::Magenta)),
    };
    let service = paint(&fixed(e.service, 8), fg(service_color(e.service)).bold());
    let visitor = paint(
        &fixed(
            &display_ip(if e.visitor.is_empty() { "-" } else { e.visitor }),
            VISITOR_WIDTH,
        ),
        Style::new().dim(),
    );
    let proto = paint(&fixed(e.proto, 2), Style::new().dim());
    let method = paint(&fixed(e.method, 7), method_style(e.method));
    let status = e
        .status
        .map_or_else(|| ELLIPSIS.to_string(), |s| s.to_string());
    let status = paint(&fixed(&status, 3), status_style(e.status));
    let (size, duration) = match e.phase {
        Phase::Opened => (
            " ".repeat(6),
            paint(&format!("{:>7}", "open"), fg(Color::Magenta)),
        ),
        _ => (
            format!("{:>6}", human_bytes(e.bytes)),
            paint(
                &format!("{:>7}", human_duration(e.elapsed)),
                Style::new().dim(),
            ),
        ),
    };
    let size = paint(&size, Style::new().dim());
    let path_width = width
        .map(|w| usize::from(w).saturating_sub(FIXED_COLUMNS).max(8))
        .unwrap_or(usize::MAX);
    let path_style = match e.status {
        Some(400..=599) => Style::new().dim(),
        _ => Style::new(),
    };
    let path = paint(&term::truncate(e.path, path_width), path_style);
    format!(
        "{time} {marker} {service}  {visitor}  {proto}  {method}  {status}  {size}  {duration}  {path}"
    )
}

/// The indented header block `--verbose` adds under a request line.
pub fn header_block(prefix: &str, headers: &[(String, Vec<u8>)]) -> String {
    headers
        .iter()
        .map(|(name, value)| {
            format!(
                "    {prefix} {}: {}\n",
                paint(name, Style::new().dim()),
                String::from_utf8_lossy(value)
            )
        })
        .collect()
}

/// `HH:MM:SS` on the local clock: a foreground session rarely spans a day.
fn timestamp(at: std::time::SystemTime) -> String {
    jiff::Timestamp::try_from(at)
        .map(|ts| ts.to_zoned(jiff::tz::TimeZone::system()))
        .unwrap_or_else(|_| jiff::Zoned::now())
        .strftime("%H:%M:%S")
        .to_string()
}

/// An address for display: an IPv4-mapped IPv6 unwrapped, a long IPv6 cut
/// after its first four hextets.
fn display_ip(raw: &str) -> String {
    match raw.trim().parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let text = v6.to_string();
                if text.len() <= VISITOR_WIDTH {
                    text
                } else {
                    let head: Vec<&str> = text.split(':').take(4).collect();
                    format!("{}:{ELLIPSIS}", head.join(":"))
                }
            }
        },
        Ok(ip) => ip.to_string(),
        Err(_) => raw.to_string(),
    }
}

/// Left-aligned in exactly `width` columns.
fn fixed(text: &str, width: usize) -> String {
    format!("{:<width$}", term::truncate(text, width))
}

/// `0B`, `463B`, `1.2K`, `17.4M`, `2.0G`.
fn human_bytes(n: u64) -> String {
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
fn human_duration(d: Duration) -> String {
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

/// What a service row's indicator shows.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RowState {
    Registering,
    Cert(CertStatus),
    Refused(String),
}

#[derive(Debug, Clone)]
struct Row {
    /// The public URL; empty until registered.
    url: String,
    target: String,
    state: RowState,
}

/// The per-service status rows, drawn as a sticky footer on a terminal and as
/// plain lines otherwise.
pub struct Footer {
    rows: BTreeMap<String, Row>,
    /// Rows reserved at the bottom of the screen; 0 when not drawn.
    reserved: u16,
}

impl Footer {
    pub fn new(services: &[ServiceSpec]) -> Self {
        let rows = services
            .iter()
            .map(|spec| {
                let row = Row {
                    url: String::new(),
                    target: spec.target.to_string(),
                    state: RowState::Registering,
                };
                (spec.service.clone(), row)
            })
            .collect();
        Self { rows, reserved: 0 }
    }

    /// Reserves the bottom rows, when stdout is a terminal tall enough.
    pub fn install(&mut self) {
        let Some((height, _)) = term::size() else {
            return;
        };
        // One row per service plus a separator, at most half the screen.
        let reserved = (self.rows.len() as u16 + 1).min(height / 2).max(2);
        if height <= reserved + 2 {
            return;
        }
        self.reserved = reserved;
        let mut out = std::io::stdout().lock();
        // Scroll the existing content up out of the way, restrict the scroll
        // region to the rows above, and park the cursor at its bottom.
        let _ = write!(out, "{}", "\n".repeat(reserved as usize));
        let _ = write!(out, "\x1b[1;{}r", height - reserved);
        let _ = write!(out, "\x1b[{};1H", height - reserved);
        let _ = out.flush();
        self.redraw();
    }

    /// Gives the whole screen back, leaving the rows as plain lines where the
    /// footer was.
    pub fn uninstall(&mut self) {
        if self.reserved == 0 {
            return;
        }
        let reserved = std::mem::take(&mut self.reserved);
        let Some((height, _)) = term::size() else {
            return;
        };
        let mut out = std::io::stdout().lock();
        // The shell echoes `^C` at the log cursor: start a fresh line.
        let _ = write!(out, "\r\x1b[2K");
        let top = height - reserved + 1;
        for i in 0..reserved {
            let _ = write!(out, "\x1b[{};1H\x1b[2K", top + i);
        }
        let _ = write!(out, "\x1b[r\x1b[{top};1H");
        for line in self.lines(None) {
            let _ = writeln!(out, "{line}");
        }
        let _ = out.flush();
    }

    pub fn registered(&mut self, service: &str, url: &str) {
        self.update(service, |row| {
            row.url = url.to_string();
            row.state = RowState::Cert(CertStatus::Pending);
        });
    }

    pub fn refused(&mut self, service: &str, detail: &str) {
        self.update(service, |row| {
            row.state = RowState::Refused(detail.to_string())
        });
    }

    pub fn certificate(&mut self, service: &str, state: CertStatus) {
        self.update(service, |row| row.state = RowState::Cert(state));
    }

    /// Applies `change` and shows it: redrawn in place on a terminal, else
    /// printed as a line.
    fn update(&mut self, service: &str, change: impl FnOnce(&mut Row)) {
        let Some(row) = self.rows.get_mut(service) else {
            return;
        };
        change(row);
        if self.reserved > 0 {
            self.redraw();
        } else {
            let line = self.render(service, &self.rows[service], service.len(), None);
            println!("{line}");
        }
    }

    fn redraw(&self) {
        let Some((height, width)) = term::size() else {
            return;
        };
        let mut out = std::io::stdout().lock();
        let top = height - self.reserved + 1;
        let separator = paint(&"\u{2500}".repeat(usize::from(width)), Style::new().dim());
        let _ = write!(out, "\x1b7\x1b[{top};1H\x1b[2K{separator}");
        for (i, line) in self
            .lines(Some(usize::from(width)))
            .iter()
            .take(usize::from(self.reserved) - 1)
            .enumerate()
        {
            let _ = write!(out, "\x1b[{};1H\x1b[2K{line}", top + 1 + i as u16);
        }
        let _ = write!(out, "\x1b8");
        let _ = out.flush();
    }

    fn lines(&self, width: Option<usize>) -> Vec<String> {
        let name_width = self
            .rows
            .keys()
            .map(|k| k.chars().count())
            .max()
            .unwrap_or(0);
        self.rows
            .iter()
            .map(|(name, row)| self.render(name, row, name_width, width))
            .collect()
    }

    /// `● web  issued       https://…/  →  http://localhost:8000`
    fn render(&self, name: &str, row: &Row, name_width: usize, width: Option<usize>) -> String {
        let (dot, label, color) = match &row.state {
            RowState::Registering => ("\u{25CB}", "registering", Color::White),
            RowState::Refused(_) => ("\u{2716}", "refused", Color::Red),
            RowState::Cert(state) => match state {
                CertStatus::Issued => ("\u{25CF}", state.label(), Color::Green),
                CertStatus::Renewing => ("\u{25D0}", state.label(), Color::Yellow),
                CertStatus::Pending | CertStatus::Ordering => {
                    ("\u{25CC}", state.label(), Color::Yellow)
                }
                CertStatus::Failed => ("\u{2716}", state.label(), Color::Red),
            },
        };
        let (text, href, link_style) = match &row.state {
            RowState::Refused(detail) => (detail.clone(), None, fg(Color::Red)),
            _ if row.url.is_empty() => (ELLIPSIS.to_string(), None, Style::new()),
            _ => (row.url.clone(), Some(&row.url), fg(service_color(name))),
        };
        // The link gets what the other columns leave; its target is never cut.
        let others = 1 + 1 + name_width + 2 + 11 + 2 + 2 + 1 + 2 + row.target.chars().count();
        let text = width.map_or(text.clone(), |w| {
            term::truncate_middle(&text, w.saturating_sub(others).max(8))
        });
        let shown = paint(&text, link_style);
        let shown = match href {
            Some(url) => term::link(Stream::Out, url, &shown),
            None => shown,
        };
        format!(
            "{} {}  {}  {shown}  {}  {}",
            paint(dot, fg(color).bold()),
            paint(
                &format!("{name:<name_width$}"),
                fg(service_color(name)).bold()
            ),
            paint(&format!("{label:<11}"), fg(color)),
            paint("\u{2192}", Style::new().dim()),
            paint(&row.target, Style::new().dim()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event<'a>(path: &'a str, status: Option<u16>, phase: Phase) -> RequestEvent<'a> {
        RequestEvent {
            at: std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            service: "web",
            visitor: "203.0.113.9",
            proto: "h2",
            method: "GET",
            path,
            status,
            bytes: 463,
            elapsed: Duration::from_micros(850),
            phase,
            request_headers: &[],
            response_headers: &[],
        }
    }

    #[test]
    fn plain_line_has_stable_columns() {
        let line = request_line(&event("/hello", Some(200), Phase::Done), None);
        // `HH:MM:SS` depends on the local zone; check its shape, then the
        // fixed-width remainder exactly.
        let (time, rest) = line.split_once(' ').unwrap();
        assert_eq!(time.len(), 8, "{time}");
        assert_eq!(
            rest,
            "\u{2022} web       203.0.113.9           h2  GET      200    463B    850\u{00B5}s  /hello"
        );
    }

    #[test]
    fn path_is_truncated_to_width() {
        let long = "/".to_string() + &"a".repeat(200);
        let line = request_line(&event(&long, Some(404), Phase::Done), Some(100));
        assert!(line.chars().count() <= 100, "{}", line.chars().count());
        assert!(line.ends_with('\u{2026}'));
        // Narrower than the fixed columns: the path keeps its minimum.
        let line = request_line(&event(&long, Some(404), Phase::Done), Some(40));
        assert!(line.ends_with('\u{2026}'));
    }

    #[test]
    fn opened_and_closed_phases() {
        let open = request_line(&event("/ws", Some(101), Phase::Opened), None);
        assert!(open.contains(" \u{25B6} "));
        assert!(open.contains("   open"));
        let closed = request_line(&event("/ws", Some(101), Phase::Closed), None);
        assert!(closed.contains(" \u{25A0} "));
        assert!(closed.contains("463B"));
    }

    #[test]
    fn humanizers() {
        assert_eq!(human_bytes(0), "0B");
        assert_eq!(human_bytes(1536), "1.5K");
        assert_eq!(human_bytes(200 * 1024 * 1024), "200M");
        assert_eq!(human_duration(Duration::from_micros(3400)), "3.4ms");
        assert_eq!(human_duration(Duration::from_millis(1200)), "1.20s");
        assert_eq!(human_duration(Duration::from_secs(123)), "2m03s");
    }

    #[test]
    fn visitor_ip_display() {
        assert_eq!(display_ip("::ffff:79.112.1.2"), "79.112.1.2");
        assert_eq!(display_ip("203.0.113.9"), "203.0.113.9");
        assert_eq!(display_ip("2001:db8::1"), "2001:db8::1");
        let long = display_ip("2001:0db8:85a3:08d3:1319:8a2e:0370:7344");
        assert_eq!(long, "2001:db8:85a3:8d3:\u{2026}");
        assert_eq!(display_ip("-"), "-");
    }

    #[test]
    fn footer_rows_follow_the_lifecycle() {
        let mut footer = Footer::new(&[
            ServiceSpec::new("web", weave::Target::parse("8000").unwrap()),
            ServiceSpec::new("api", weave::Target::parse("9000").unwrap()),
        ]);
        assert!(footer.lines(None)[1].contains("registering"));
        footer.registered("web", "https://web.example/");
        footer.certificate("web", CertStatus::Ordering);
        footer.refused("api", "already registered");
        let lines = footer.lines(None);
        assert_eq!(
            lines[1],
            "\u{25CC} web  ordering     https://web.example/  \u{2192}  http://localhost:8000"
        );
        assert_eq!(
            lines[0],
            "\u{2716} api  refused      already registered  \u{2192}  http://localhost:9000"
        );
        footer.registered(
            "web",
            "https://web-with-a-long-name.person.weaver1.offworld.nexus/",
        );
        let narrow = footer.lines(Some(70));
        assert!(narrow[1].chars().count() <= 70, "{}", narrow[1]);
        assert!(narrow[1].contains("https://web\u{2026}"), "{}", narrow[1]);
    }
}
