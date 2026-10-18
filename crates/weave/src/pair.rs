//! `weave pair` — enrol this machine with a relay.
//!
//! The command holds no secret and carries nothing between the terminal and the
//! browser: it opens a pairing channel to the relay's admin host, solves the
//! proof of work the relay opens with, sends the machine's public key (held in
//! `tpmd`) and which machine it is for, prints the link the relay hands back,
//! and waits. Whoever opens the link approves or rejects the machine there.
//!
//! The pending pairing lives exactly as long as this channel: closing it —
//! Ctrl-C, exit, a dropped network — destroys the pairing and kills the link.

use std::path::PathBuf;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use weaver_abuse::altcha::Solution;
use weaver_abuse::{Challenge, Payload};
use weaver_mux::auth::Signer as _;
use weaver_proto::pair::{self, Begin, FailureCode, ServerMessage, Target};

use crate::connect::{RelaySocket, dial_relay};
use crate::host::normalize_admin_host;
use crate::store::Store;
use crate::tpm::{self, DeviceKey};
use crate::ui::{self, Spinner, Stream, hinted};

/// Boxed error the CLI prints and exits on.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The assurance floor when none is given.
pub const DEFAULT_FLOOR: &str = "sealed";

/// The highest PBKDF2 iteration count the CLI agrees to run per attempt.
pub const MAX_POW_COST: u32 = 200_000;

/// The total PBKDF2 iterations the CLI agrees to spend on one challenge
/// (cost × attempts) — about a minute or two on a slow machine. Bounds a
/// hostile relay's ability to make the CLI spin.
pub const POW_WORK_BUDGET: u64 = 400_000_000;

/// Options for one `weave pair` invocation.
#[derive(Debug, Clone)]
pub struct PairOptions {
    /// The relay's admin host, as typed.
    pub admin_host: String,
    /// Re-attach this machine id instead of letting the CLI decide.
    pub machine: Option<i32>,
    /// The key assurance floor (`file`/`keyring`/`sealed`/`hardware`).
    pub min_key_security: String,
    /// Consent to provision below the floor without prompting.
    pub allow_below_floor: bool,
    /// Extra root CA (PEM), for a relay with a private CA (tests, dev).
    pub insecure_root_ca: Option<PathBuf>,
}

/// The link a person opens to approve this machine.
///
/// The handle is a capability, so it rides in the URL **fragment** — never sent
/// to the server, so it cannot reach a log line or a `Referer`. The `handle=`
/// spelling matches the reset link's `token=` and is exactly what the `/pair`
/// page reads.
pub fn pairing_url(admin_host: &str, handle: &str) -> String {
    format!("https://{admin_host}/pair#handle={handle}")
}

/// Why a proof-of-work challenge was not solved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PowError {
    /// The challenge asks for more work than the CLI agrees to do.
    #[error("the relay asked for an unreasonable proof of work ({0})")]
    TooExpensive(String),
    /// The challenge is malformed or uses an algorithm the CLI cannot run.
    #[error("the relay sent a proof-of-work challenge this client cannot solve")]
    Unsolvable,
}

/// The attempt cap for a challenge, or why it is refused outright.
///
/// Refuses before any work when the per-attempt cost is above
/// [`MAX_POW_COST`], or when the key prefix makes the expected number of
/// attempts exceed what [`POW_WORK_BUDGET`] allows at that cost.
pub fn pow_bounds(challenge: &Challenge) -> Result<u32, PowError> {
    let params = &challenge.parameters;
    if params.cost == 0 || params.cost > MAX_POW_COST {
        return Err(PowError::TooExpensive(format!(
            "cost {} where at most {MAX_POW_COST} is accepted",
            params.cost
        )));
    }
    let max_counter = (POW_WORK_BUDGET / u64::from(params.cost)).min(u64::from(u32::MAX)) as u32;
    // Each hex digit of prefix multiplies the expected attempts by 16 (an odd
    // final nibble is a half-digit, but erring towards solvable is fine).
    let expected = 16f64.powi(params.key_prefix.len().min(16) as i32);
    if expected > f64::from(max_counter) / 4.0 {
        return Err(PowError::TooExpensive(format!(
            "a {}-digit prefix at cost {}",
            params.key_prefix.len(),
            params.cost
        )));
    }
    Ok(max_counter)
}

/// Solves a pairing challenge within [`pow_bounds`]. Blocking, CPU-bound.
pub fn solve_pow(challenge: &Challenge) -> Result<Solution, PowError> {
    let max_counter = pow_bounds(challenge)?;
    weaver_abuse::try_solve_challenge(challenge, MAX_POW_COST, max_counter)
        .ok_or(PowError::Unsolvable)
}

/// Decides which machine a pairing is for.
///
/// An explicit `--machine` wins. Otherwise, when this relay is already known:
/// a different key than the one recorded means the old key is gone, so the
/// known machine moves onto the new key; the same key means there is nothing
/// to do. An unknown relay gets a new machine.
pub fn choose_target(
    explicit: Option<i32>,
    known: Option<(i32, &str)>,
    fingerprint: &str,
    hostname: impl FnOnce() -> String,
) -> Result<Target, AlreadyPaired> {
    if let Some(machine_id) = explicit {
        return Ok(Target::Existing { machine_id });
    }
    match known {
        Some((machine_id, key_id)) if key_id != fingerprint => Ok(Target::Existing { machine_id }),
        Some((machine_id, _)) => Err(AlreadyPaired { machine_id }),
        None => Ok(Target::New {
            hostname: hostname(),
        }),
    }
}

/// The relay already authorises this machine's current key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlreadyPaired {
    /// The machine it is paired as.
    pub machine_id: i32,
}

/// Runs `weave pair`.
pub async fn run_pair(opts: PairOptions) -> Result<(), BoxError> {
    let admin_host = normalize_admin_host(&opts.admin_host)?;
    let floor = tpm::parse_level(&opts.min_key_security).ok_or_else(|| {
        hinted(
            format!("unknown key security level '{}'", opts.min_key_security),
            "use one of: file, keyring, sealed, hardware",
        )
    })?;

    let store = Store::open_default().await?;
    let known = store.relay(&admin_host).await?;

    // Every fingerprint this machine has been known by, this relay's first:
    // they all name the one key tpmd holds, if it still holds it.
    let mut candidates = Vec::new();
    if let Some(relay) = &known {
        candidates.push(relay.key_id.clone());
    }
    for key_id in store.key_ids().await? {
        if !candidates.contains(&key_id) {
            candidates.push(key_id);
        }
    }

    let key = open_device_key(&candidates, floor, opts.allow_below_floor).await?;
    let fingerprint = key.fingerprint();
    ui::step(
        Stream::Err,
        ui::KEY,
        &format!(
            "Device key  {}  {}",
            ui::bold(Stream::Err, &tpm::short_fingerprint(&fingerprint)),
            ui::dim(Stream::Err, &format!("({})", key.security_level())),
        ),
    );
    if key.created() && !candidates.is_empty() {
        ui::warn("The key agent no longer holds this machine's device key; a new one was created.");
    }

    let target = choose_target(
        opts.machine,
        known.as_ref().map(|r| (r.machine_id, r.key_id.as_str())),
        &fingerprint,
        raw_hostname,
    )
    .map_err(|AlreadyPaired { machine_id }| {
        hinted(
            format!("this machine is already paired with {admin_host} (machine {machine_id})"),
            format!("to pair it again, run `weave unpair {admin_host}` first"),
        )
    })?;
    if let Target::Existing { machine_id } = target {
        ui::step(
            Stream::Err,
            &ui::dim(Stream::Err, ui::ARROW),
            &format!("Moving machine {machine_id} onto this key"),
        );
    }

    let spinner = Spinner::new(format!("Connecting to {admin_host}\u{2026}"));
    let (mut ws, _) = dial_relay(
        &admin_host,
        pair::PAIR_CHANNEL_PATH,
        pair::PAIR_SUBPROTOCOL,
        opts.insecure_root_ca.as_deref(),
    )
    .await
    .map_err(|e| connect_error(&admin_host, e))?;
    spinner.done(&format!(
        "Connected to {}",
        ui::accent(Stream::Err, &admin_host)
    ));

    let challenge = match next_message(&mut ws).await? {
        ServerMessage::Challenge { challenge } => challenge,
        ServerMessage::Failed { code, message } => return Err(failure(&admin_host, code, message)),
        other => {
            return Err(format!("the relay opened with {other:?} instead of a challenge").into());
        }
    };

    let spinner = Spinner::new("Solving proof of work\u{2026}");
    let solution = {
        let challenge = challenge.clone();
        tokio::task::spawn_blocking(move || solve_pow(&challenge)).await??
    };
    spinner.done_timed("Proof of work solved");

    let begin = Begin {
        proof: Payload {
            challenge,
            solution,
        },
        key_id: key.key_id(),
        target,
    };
    ws.send(Message::Text(pair::encode_json(&begin)?.into()))
        .await?;

    let handle = match next_message(&mut ws).await? {
        ServerMessage::Handle { handle } => handle,
        ServerMessage::Failed { code, message } => return Err(failure(&admin_host, code, message)),
        other => return Err(format!("unexpected message before the link: {other:?}").into()),
    };

    let url = pairing_url(&admin_host, &handle);
    ui::step(
        Stream::Out,
        &ui::accent(Stream::Out, ui::ARROW),
        &ui::bold(Stream::Out, "Open this link to approve this machine:"),
    );
    println!(
        "   {}",
        ui::link(Stream::Out, &url, &ui::accent(Stream::Out, &url))
    );

    let spinner =
        Spinner::announced("Waiting for approval in the browser (Ctrl-C to cancel)\u{2026}");
    let outcome = tokio::select! {
        outcome = await_outcome(&mut ws) => outcome,
        _ = tokio::signal::ctrl_c() => {
            spinner.clear();
            let _ = ws.close(None).await;
            return Err("cancelled; the link no longer works".into());
        }
    };
    spinner.clear();

    match outcome? {
        Outcome::Approved {
            machine_id,
            person,
            machine,
        } => {
            let saved = store
                .record_pairing(&admin_host, machine_id, &fingerprint)
                .await?;
            let default = if saved.is_default {
                format!(" {}", ui::dim(Stream::Out, "\u{2014} default relay"))
            } else {
                String::new()
            };
            ui::success(&format!(
                "Paired as {} {}{default}",
                ui::accent(Stream::Out, &format!("{person}/{machine}")),
                ui::dim(Stream::Out, &format!("(machine {machine_id})")),
            ));
            let start = if saved.is_default {
                "weave start <service>=<port>".to_string()
            } else {
                format!("weave start --server {admin_host} <service>=<port>")
            };
            ui::hint(&format!("next: {start}"));
            Ok(())
        }
        Outcome::Failed { code, message } => Err(failure(&admin_host, code, message)),
    }
}

/// Probes tpmd, settles the floor (asking when needed), and opens the key.
async fn open_device_key(
    candidates: &[String],
    floor: tpmd_client::SecurityLevel,
    allow_below_floor: bool,
) -> Result<DeviceKey, BoxError> {
    let spinner = Spinner::new("Contacting the key agent\u{2026}");
    let assurance = tpm::probe().await.map_err(tpm_error)?;
    let mut allow_below = allow_below_floor;
    if assurance.achieved < floor && !allow_below {
        spinner.clear();
        ui::warn(&format!(
            "This machine's strongest key store is '{}' (backend '{}'), below the requested '{floor}'.",
            assurance.achieved, assurance.backend
        ));
        if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            return Err(hinted(
                "refusing to create a device key below the requested security level",
                format!(
                    "re-run with --allow-below-floor, or --min-key-security {}",
                    assurance.achieved
                ),
            ));
        }
        if !confirm("Create the key at the weaker level anyway?")? {
            return Err("aborted; nothing was created".into());
        }
        allow_below = true;
        let spinner = Spinner::new("Opening the device key\u{2026}");
        let key = tpm::open_any(candidates, floor, allow_below)
            .await
            .map_err(tpm_error)?;
        spinner.clear();
        return Ok(key);
    }
    let key = tpm::open_any(candidates, floor, allow_below)
        .await
        .map_err(tpm_error)?;
    spinner.clear();
    Ok(key)
}

/// A tpmd failure, with a hint when the agent is simply not there.
pub(crate) fn tpm_error(e: tpm::TpmError) -> BoxError {
    match e {
        tpm::TpmError::Unavailable(_) => hinted(
            e.to_string(),
            "install and start tpmd (the local key agent), then try again",
        ),
        other => other.into(),
    }
}

/// A connection failure, naming the relay.
pub(crate) fn connect_error(admin_host: &str, e: BoxError) -> BoxError {
    hinted(
        format!("could not reach {admin_host}: {e}"),
        "check the address and your network, then try again",
    )
}

/// The machine's raw hostname, for the relay to propose a name from.
fn raw_hostname() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "machine".to_string())
}

enum Outcome {
    Approved {
        machine_id: i32,
        person: String,
        machine: String,
    },
    Failed {
        code: FailureCode,
        message: String,
    },
}

async fn await_outcome(ws: &mut RelaySocket) -> Result<Outcome, BoxError> {
    loop {
        match next_message(ws).await? {
            ServerMessage::Approved {
                machine_id,
                person,
                machine,
            } => {
                return Ok(Outcome::Approved {
                    machine_id,
                    person,
                    machine,
                });
            }
            ServerMessage::Failed { code, message } => {
                return Ok(Outcome::Failed { code, message });
            }
            ServerMessage::Challenge { .. } | ServerMessage::Handle { .. } => continue,
        }
    }
}

/// The next pairing message, skipping control frames.
async fn next_message(ws: &mut RelaySocket) -> Result<ServerMessage, BoxError> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Text(text))) => return Ok(pair::decode_json(&text)?),
            Some(Ok(Message::Close(_))) | None => {
                return Err(hinted(
                    "the relay closed the pairing channel",
                    "run `weave pair` again",
                ));
            }
            Some(Ok(_)) => continue,
            Some(Err(e)) => return Err(e.into()),
        }
    }
}

/// Turns a relay `Failed` into an error with a next step.
fn failure(admin_host: &str, code: FailureCode, message: String) -> BoxError {
    let detail = if message.is_empty() {
        String::new()
    } else {
        format!(": {message}")
    };
    let (what, next) = match code {
        FailureCode::Rejected => (
            "the pairing was rejected in the browser".to_string(),
            "run `weave pair` again to retry".to_string(),
        ),
        FailureCode::AlreadyPaired => (
            format!("{admin_host} already knows this device key"),
            format!("run `weave unpair {admin_host}` to revoke it, then pair again"),
        ),
        FailureCode::NotYourMachine => (
            "that machine does not belong to the account that opened the link".to_string(),
            "sign in as the machine's owner, or pair as a new machine without --machine"
                .to_string(),
        ),
        FailureCode::Throttled => (
            format!("{admin_host} is receiving too many pairing requests"),
            "wait a minute, then try again".to_string(),
        ),
        FailureCode::Unavailable => (
            format!("{admin_host} cannot pair machines right now"),
            "try again later".to_string(),
        ),
        FailureCode::BadProof => (
            "the relay did not accept the proof of work".to_string(),
            "run `weave pair` again".to_string(),
        ),
        FailureCode::BadKey => (
            "the relay does not accept this device key".to_string(),
            "check that tpmd and the relay are up to date".to_string(),
        ),
        FailureCode::BadRequest => (
            "the relay did not understand the pairing request".to_string(),
            "check that weave and the relay are up to date".to_string(),
        ),
    };
    hinted(format!("{what}{detail}"), next)
}

/// Reads a y/N answer from the terminal.
fn confirm(question: &str) -> Result<bool, BoxError> {
    use std::io::Write as _;
    eprint!("{} {question} [y/N] ", ui::yellow(Stream::Err, "?"));
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use super::*;

    fn challenge(cost: u32, prefix: &str) -> Challenge {
        weaver_abuse::create_challenge(weaver_abuse::CreateRequest {
            algorithm: "PBKDF2/SHA-256",
            cost,
            key_length: 32,
            key_prefix: prefix,
            ttl_secs: 60,
            secret: "test",
            data: BTreeMap::new(),
            nonce: [7; 16],
            salt: [9; 16],
            now_ms: 0,
        })
    }

    #[test]
    fn pairing_url_puts_the_handle_in_the_fragment() {
        let url = pairing_url("relay.example.com", "abc123");
        assert_eq!(url, "https://relay.example.com/pair#handle=abc123");
        // The capability must never reach the query string.
        assert!(!url.contains('?'));
    }

    #[test]
    fn an_absurd_cost_is_refused_without_work() {
        let started = std::time::Instant::now();
        assert!(matches!(
            solve_pow(&challenge(u32::MAX, "0")),
            Err(PowError::TooExpensive(_))
        ));
        assert!(matches!(
            solve_pow(&challenge(MAX_POW_COST + 1, "0")),
            Err(PowError::TooExpensive(_))
        ));
        assert!(matches!(
            solve_pow(&challenge(0, "0")),
            Err(PowError::TooExpensive(_))
        ));
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn an_absurd_prefix_is_refused_without_work() {
        assert!(matches!(
            pow_bounds(&challenge(5_000, "000000000000")),
            Err(PowError::TooExpensive(_))
        ));
        // The relay's default (cost 5000, one byte of prefix) is fine.
        assert_eq!(pow_bounds(&challenge(5_000, "00")), Ok(80_000));
    }

    #[test]
    fn a_cheap_challenge_is_solved() {
        let c = challenge(1, "0");
        let solution = solve_pow(&c).unwrap();
        assert!(solution.derived_key.starts_with('0'));
    }

    #[test]
    fn an_unsupported_algorithm_is_unsolvable() {
        let mut c = challenge(1, "0");
        c.parameters.algorithm = "SCRYPT".into();
        assert_eq!(solve_pow(&c), Err(PowError::Unsolvable));
    }

    #[test]
    fn target_selection() {
        let host = || "carter".to_string();
        // Unknown relay: a new machine.
        assert_eq!(
            choose_target(None, None, "p256:aa", host),
            Ok(Target::New {
                hostname: "carter".into()
            })
        );
        // Known relay, key replaced: the machine moves.
        assert_eq!(
            choose_target(None, Some((7, "p256:old")), "p256:new", host),
            Ok(Target::Existing { machine_id: 7 })
        );
        // Known relay, same key: nothing to do.
        assert_eq!(
            choose_target(None, Some((7, "p256:aa")), "p256:aa", host),
            Err(AlreadyPaired { machine_id: 7 })
        );
        // --machine wins over everything.
        assert_eq!(
            choose_target(Some(3), Some((7, "p256:aa")), "p256:aa", host),
            Ok(Target::Existing { machine_id: 3 })
        );
    }
}
