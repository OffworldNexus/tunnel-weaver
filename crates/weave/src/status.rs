//! Sticky per-service status footer for `weave start`.
//!
//! On a TTY the bottom of the terminal is reserved for one line per
//! service — certificate state, public link, local target — and the request
//! log scrolls above it, the way progress bars coexist with output. This is
//! done with the VT scroll-region (`CSI t;b r`, DECSTBM): the scrollable
//! area is the screen minus the footer rows, so ordinary `println!` never
//! overwrites the footer and the footer is redrawn in place on every change.
//!
//! Off a TTY the footer is disabled and state changes are printed as plain
//! lines instead, so piped output stays linear and greppable.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};

use crossterm::style::{Attribute, Color, Stylize};
use weaver_proto::CertStatus;

use crate::log::LogStyle;

/// One service's live row.
#[derive(Debug, Clone)]
pub struct ServiceRow {
    /// Public URL once registered.
    pub url: Option<String>,
    /// Local origin.
    pub target: String,
    /// Registration outcome / certificate lifecycle.
    pub state: RowState,
}

/// What the row's indicator shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowState {
    /// Register sent, no reply yet.
    Registering,
    /// Registered; certificate in the given state.
    Cert(CertStatus),
    /// Registration refused.
    Refused(String),
}

/// Owns the terminal scroll region and redraws the footer.
pub struct StatusFooter {
    rows: BTreeMap<String, ServiceRow>,
    style: LogStyle,
    /// The footer is active (TTY, scroll region set).
    active: bool,
    /// Rows reserved at the bottom.
    reserved: u16,
}

impl StatusFooter {
    /// Create the footer for `services` (name → target). Reserves the scroll
    /// region immediately when on a TTY.
    pub fn new(style: LogStyle, services: impl IntoIterator<Item = (String, String)>) -> Self {
        let rows: BTreeMap<String, ServiceRow> = services
            .into_iter()
            .map(|(name, target)| {
                (
                    name,
                    ServiceRow {
                        url: None,
                        target,
                        state: RowState::Registering,
                    },
                )
            })
            .collect();
        let mut footer = Self {
            rows,
            style,
            active: false,
            reserved: 0,
        };
        footer.install();
        footer
    }

    /// Reserve the bottom rows. No-op when stdout is not a terminal.
    fn install(&mut self) {
        if !std::io::stdout().is_terminal() || self.rows.is_empty() {
            return;
        }
        let Ok((_, height)) = crossterm::terminal::size() else {
            return;
        };
        // One row per service plus a separator; never more than half the
        // screen so the log stays readable.
        let want = self.rows.len() as u16 + 1;
        let reserved = want.min(height / 2).max(2);
        if height <= reserved + 2 {
            return;
        }
        self.reserved = reserved;
        self.active = true;
        let mut out = std::io::stdout().lock();
        // Make room: scroll the existing content up so the footer does not
        // cover it, then restrict the scroll region to the rows above.
        let _ = write!(out, "{}", "\n".repeat(reserved as usize));
        let _ = write!(out, "\x1b[{};{}r", 1, height - reserved);
        // Park the cursor at the bottom of the scroll region.
        let _ = write!(out, "\x1b[{};1H", height - reserved);
        let _ = out.flush();
        self.redraw();
    }

    /// Restore a full-screen scroll region and clear the footer. Called on
    /// shutdown; idempotent.
    pub fn uninstall(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let Ok((_, height)) = crossterm::terminal::size() else {
            return;
        };
        let mut out = std::io::stdout().lock();
        // The shell echoes `^C` at the log cursor: start a fresh line there
        // so nothing we print is glued to it.
        let _ = write!(out, "\r\x1b[2K");
        // Wipe the footer rows, give the whole screen back, and continue
        // writing from where the footer used to start: the log above stays
        // put and the final summary takes the footer's place, with no gap.
        let top = height - self.reserved + 1;
        for i in 0..self.reserved {
            let _ = write!(out, "\x1b[{};1H\x1b[2K", top + i);
        }
        let _ = write!(out, "\x1b[r");
        let _ = write!(out, "\x1b[{top};1H");
        for line in self.render_lines(None) {
            let _ = writeln!(out, "{line}");
        }
        let _ = out.flush();
    }

    /// Whether the footer is drawn (so callers can decide to log plainly).
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Record a registration.
    pub fn registered(&mut self, service: &str, url: String) {
        if let Some(row) = self.rows.get_mut(service) {
            row.url = Some(url);
            row.state = RowState::Cert(CertStatus::Pending);
        }
        self.redraw();
    }

    /// Record a refusal.
    pub fn refused(&mut self, service: &str, message: String) {
        if let Some(row) = self.rows.get_mut(service) {
            row.state = RowState::Refused(message);
        }
        self.redraw();
    }

    /// Record a certificate transition.
    pub fn cert(&mut self, service: &str, state: CertStatus) {
        if let Some(row) = self.rows.get_mut(service) {
            row.state = RowState::Cert(state);
        }
        self.redraw();
    }

    /// Repaint the footer in place.
    fn redraw(&self) {
        if !self.active {
            return;
        }
        let Ok((width, height)) = crossterm::terminal::size() else {
            return;
        };
        let lines = self.render_lines(Some(width as usize));
        let mut out = std::io::stdout().lock();
        let _ = write!(out, "\x1b7");
        let top = height - self.reserved + 1;
        // Separator.
        let sep = "\u{2500}".repeat(width as usize);
        let sep = if self.style.color {
            sep.with(Color::DarkGrey).to_string()
        } else {
            sep
        };
        let _ = write!(out, "\x1b[{top};1H\x1b[2K{sep}");
        for (i, line) in lines.iter().enumerate().take(self.reserved as usize - 1) {
            let _ = write!(out, "\x1b[{};1H\x1b[2K{line}", top + 1 + i as u16);
        }
        let _ = write!(out, "\x1b8");
        let _ = out.flush();
    }

    /// One line per service: `● web  issued   https://…/  →  http://localhost:8000`.
    pub fn render_lines(&self, width: Option<usize>) -> Vec<String> {
        let name_w = self
            .rows
            .keys()
            .map(|k| k.chars().count())
            .max()
            .unwrap_or(3);
        self.rows
            .iter()
            .map(|(name, row)| self.render_row(name, row, name_w, width))
            .collect()
    }

    fn render_row(
        &self,
        name: &str,
        row: &ServiceRow,
        name_w: usize,
        width: Option<usize>,
    ) -> String {
        let (dot, label, color) = match &row.state {
            RowState::Registering => ("\u{25CB}", "registering".to_string(), Color::DarkGrey),
            RowState::Refused(_) => ("\u{2716}", "refused".to_string(), Color::Red),
            RowState::Cert(c) => (
                match c {
                    CertStatus::Issued => "\u{25CF}",
                    CertStatus::Renewing => "\u{25D0}",
                    CertStatus::Pending | CertStatus::Ordering => "\u{25CC}",
                    CertStatus::Failed => "\u{2716}",
                },
                c.label().to_string(),
                match c {
                    CertStatus::Issued => Color::Green,
                    CertStatus::Renewing => Color::Yellow,
                    CertStatus::Pending | CertStatus::Ordering => Color::Yellow,
                    CertStatus::Failed => Color::Red,
                },
            ),
        };
        let paint = |s: &str, c: Color, bold: bool| -> String {
            if !self.style.color {
                return s.to_string();
            }
            let st = s.with(c);
            if bold {
                st.attribute(Attribute::Bold).to_string()
            } else {
                st.to_string()
            }
        };
        let link = match (&row.state, &row.url) {
            (RowState::Refused(msg), _) => msg.clone(),
            (_, Some(url)) => url.clone(),
            (_, None) => "\u{2026}".to_string(),
        };
        let arrow = "\u{2192}";
        // Fixed part: dot, name, label (11 wide), arrow, target, separators.
        let fixed = 1
            + 1
            + name_w
            + 2
            + 11
            + 2
            + 2
            + arrow.chars().count()
            + 2
            + row.target.chars().count();
        let link_w = width
            .map(|w| w.saturating_sub(fixed).max(8))
            .unwrap_or(usize::MAX);
        let link = truncate_middle(&link, link_w);

        // Public link in the service's own hue (it *is* the service's
        // identity), label in the state colour, local target muted: the eye
        // lands on state, then link.
        let link_color = match row.state {
            RowState::Refused(_) => Color::Red,
            _ => crate::log::service_color(name),
        };
        format!(
            "{} {}  {}  {}  {}  {}",
            paint(dot, color, true),
            paint(
                &format!("{name:<name_w$}"),
                crate::log::service_color(name),
                true
            ),
            paint(&format!("{label:<11}"), color, false),
            paint(&link, link_color, false),
            paint(arrow, Color::DarkGrey, false),
            paint(&row.target, Color::DarkGrey, false),
        )
    }
}

/// Keep the start and end of a URL (`https://a.laptop…nexus/`) when it is
/// too long: the service label at the front and the root at the back are
/// the informative parts.
fn truncate_middle(text: &str, max: usize) -> String {
    let n = text.chars().count();
    if n <= max {
        return text.to_string();
    }
    if max < 5 {
        return text.chars().take(max).collect();
    }
    let keep = max - 1;
    let head = keep / 2;
    let tail = keep - head;
    let chars: Vec<char> = text.chars().collect();
    let mut out: String = chars[..head].iter().collect();
    out.push('\u{2026}');
    out.extend(chars[n - tail..].iter());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn footer() -> StatusFooter {
        // Tests are not on a TTY: `install` is a no-op, rows still render.
        StatusFooter::new(
            LogStyle::plain(None),
            [
                ("web".to_string(), "http://localhost:8000".to_string()),
                ("api".to_string(), "http://localhost:9000".to_string()),
            ],
        )
    }

    #[test]
    fn rows_follow_lifecycle() {
        let mut f = footer();
        assert!(!f.is_active());
        let lines = f.render_lines(None);
        assert!(lines[1].contains("registering"), "{lines:?}");
        f.registered("web", "https://web.laptop.poc.example/".into());
        f.cert("web", CertStatus::Ordering);
        f.refused("api", "already registered".into());
        let lines = f.render_lines(None);
        assert_eq!(
            lines[1],
            "\u{25CC} web  ordering     https://web.laptop.poc.example/  \u{2192}  http://localhost:8000"
        );
        assert_eq!(
            lines[0],
            "\u{2716} api  refused      already registered  \u{2192}  http://localhost:9000"
        );
        f.cert("web", CertStatus::Issued);
        assert!(f.render_lines(None)[1].starts_with("\u{25CF} web  issued"));
    }

    #[test]
    fn link_is_truncated_in_the_middle_to_width() {
        let mut f = footer();
        f.registered(
            "web",
            "https://web.some-very-long-machine-name.person.weaver1.offworld.nexus/".into(),
        );
        let line = &f.render_lines(Some(60))[1];
        assert!(
            line.chars().count() <= 60,
            "{line} ({})",
            line.chars().count()
        );
        assert!(line.contains("https://web\u{2026}") || line.contains('\u{2026}'));
        assert!(line.ends_with("http://localhost:8000"));
    }

    #[test]
    fn truncate_middle_keeps_both_ends() {
        assert_eq!(truncate_middle("abcdefghij", 20), "abcdefghij");
        assert_eq!(
            truncate_middle("abcdefghij", 7),
            "abc\u{2026}def".replace("def", "hij")
        );
    }
}
