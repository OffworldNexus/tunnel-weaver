//! The terminal [`Reporter`], and how errors read.

use std::io::IsTerminal;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use weave::{Error, KeyError, Phase, Reporter, RequestEvent, SecurityLevel, ServiceSpec};
use weaver_proto::CertStatus;
use weaver_proto::pair::FailureCode;

use crate::term::{self, Spinner, Stream};
use crate::tunnel::{self, Footer};

/// Presents the client's events on the terminal.
pub struct TermReporter {
    /// No per-request log.
    pub quiet: bool,
    /// Request and response headers under each request line.
    pub verbose: bool,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    spinner: Option<Spinner>,
    footer: Option<Footer>,
}

impl TermReporter {
    pub fn new(quiet: bool, verbose: bool) -> Self {
        Self {
            quiet,
            verbose,
            state: Mutex::default(),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn spin(&self, msg: &str, announced: bool) {
        let mut state = self.state();
        state.spinner = None;
        state.spinner = Some(Spinner::new(msg, announced));
    }

    /// Ends the spinner with `✔ msg`.
    fn settle(&self, msg: &str) {
        self.state().spinner = None;
        term::success(Stream::Err, msg);
    }

    fn clear(&self) {
        self.state().spinner = None;
    }

    /// Clears the spinner and gives the screen back before the outcome prints.
    pub fn finish(&self) {
        let mut state = self.state();
        state.spinner = None;
        if let Some(footer) = &mut state.footer {
            footer.uninstall();
        }
    }
}

impl Reporter for TermReporter {
    fn opening_key(&self) {
        self.spin("Contacting the key agent\u{2026}", false);
    }

    fn waiting_for_key_store(&self) {
        self.spin(
            "Waiting for the key store to unlock (Ctrl-C to cancel)\u{2026}",
            true,
        );
    }

    fn device_key(&self, fingerprint: &str, level: SecurityLevel, replaced: bool) {
        self.clear();
        term::step(
            Stream::Err,
            term::KEY,
            &format!(
                "Device key  {}  {}",
                term::bold(Stream::Err, &term::short_fingerprint(fingerprint)),
                term::dim(Stream::Err, &format!("({level})")),
            ),
        );
        if replaced {
            term::warn(
                "The key agent no longer held this machine's device key; a new one was created.",
            );
        }
    }

    fn allow_below_floor(&self, required: SecurityLevel, available: SecurityLevel) -> bool {
        self.clear();
        term::warn(&format!(
            "This machine's strongest key store is '{available}', below the requested '{required}'."
        ));
        std::io::stdin().is_terminal()
            && inquire::Confirm::new("Create the key at the weaker level anyway?")
                .with_default(false)
                .prompt()
                .unwrap_or(false)
    }

    fn connecting(&self, host: &str) {
        self.spin(&format!("Connecting to {host}\u{2026}"), false);
    }

    fn connected(&self, host: &str) {
        self.settle(&format!("Connected to {}", term::accent(Stream::Err, host)));
    }

    fn moving_machine(&self, machine_id: i32) {
        term::step(
            Stream::Err,
            &term::dim(Stream::Err, term::ARROW),
            &format!("Moving machine {machine_id} onto this key"),
        );
    }

    fn solving_proof_of_work(&self) {
        self.spin("Solving proof of work\u{2026}", false);
    }

    fn proof_of_work_solved(&self, took: Duration) {
        let took = term::dim(Stream::Err, &format!("({})", term::seconds(took)));
        self.settle(&format!("Proof of work solved {took}"));
    }

    fn awaiting_approval(&self, url: &str) {
        self.clear();
        term::step(
            Stream::Out,
            &term::accent(Stream::Out, term::ARROW),
            &term::bold(Stream::Out, "Open this link to approve this machine:"),
        );
        println!(
            "   {}",
            term::link(Stream::Out, url, &term::accent(Stream::Out, url))
        );
        self.spin(
            "Waiting for approval in the browser (Ctrl-C to cancel)\u{2026}",
            true,
        );
    }

    fn revoking(&self, host: &str) {
        self.spin(&format!("Revoking this machine on {host}\u{2026}"), false);
    }

    fn pairing_not_effective(&self, host: &str, reason: &str) {
        self.clear();
        term::warn(&format!(
            "{host} does not accept this machine's key ({reason}): the pairing was not in effect."
        ));
    }

    fn tunnel_up(&self, host: &str, services: &[ServiceSpec]) {
        self.settle(&format!("Connected to {}", term::accent(Stream::Err, host)));
        let mut footer = Footer::new(services);
        footer.install();
        self.state().footer = Some(footer);
    }

    fn registered(&self, service: &str, url: &str) {
        if let Some(footer) = &mut self.state().footer {
            footer.registered(service, url);
        }
    }

    fn refused(&self, service: &str, detail: &str) {
        if let Some(footer) = &mut self.state().footer {
            footer.refused(service, detail);
        }
    }

    fn certificate(&self, service: &str, state: CertStatus) {
        if let Some(footer) = &mut self.state().footer {
            footer.certificate(service, state);
        }
    }

    fn request(&self, request: &RequestEvent<'_>) {
        if self.quiet {
            return;
        }
        let width = term::size().map(|(_, columns)| columns);
        println!("{}", tunnel::request_line(request, width));
        if self.verbose && request.phase != Phase::Closed {
            print!("{}", tunnel::header_block(">", request.request_headers));
            print!("{}", tunnel::header_block("<", request.response_headers));
        }
    }
}

/// Prints a fatal error and the next step, when there is one.
pub fn report_error(error: &Error) {
    term::error(&error.to_string());
    let hint = hint(error);
    if !hint.is_empty() {
        term::hint(&hint);
    }
}

/// The next step after `error`; empty when there is none to suggest.
fn hint(error: &Error) -> String {
    let up_to_date = || "check that weave and the relay are up to date".to_string();
    match error {
        Error::NoRelay => "run `weave pair <admin-host>` first".into(),
        Error::NotPaired(host) => {
            format!("run `weave pair {host}`, or `weave relays` to list paired relays")
        }
        Error::AlreadyPaired { host, .. } => {
            format!("to pair it again, run `weave unpair {host}` first")
        }
        Error::KeyGone { host } | Error::Revoked { host } => {
            format!("re-pair with `weave pair {host}`")
        }
        Error::Rejected { host, .. } => {
            format!("if this machine was unpaired there, run `weave pair {host}`")
        }
        Error::Key(KeyError::Unavailable(_)) => {
            "install and start tpmd (the local key agent), then try again".into()
        }
        Error::Key(KeyError::BelowFloor { available, .. }) => {
            format!("re-run with --allow-below-floor, or --min-key-security {available}")
        }
        Error::Unreachable { .. } => "check the address and your network, then try again".into(),
        Error::Disconnected { .. } => "try again".into(),
        Error::Pairing { host, code, .. } => match code {
            FailureCode::Rejected | FailureCode::BadProof => "run `weave pair` again".into(),
            FailureCode::AlreadyPaired => {
                format!("run `weave unpair {host}` to revoke it, then pair again")
            }
            FailureCode::NotYourMachine => {
                "sign in as the machine's owner, or pair as a new machine without --machine".into()
            }
            FailureCode::Throttled => "wait a minute, then try again".into(),
            FailureCode::Unavailable => "try again later".into(),
            FailureCode::BadKey | FailureCode::BadRequest => up_to_date(),
        },
        Error::ProofOfWork(_) | Error::Protocol(_) => up_to_date(),
        Error::Key(KeyError::Refused(_))
        | Error::Registration { .. }
        | Error::Store(_)
        | Error::Host(_) => String::new(),
    }
}
