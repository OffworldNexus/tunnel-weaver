//! `weave relays` — list the relays this machine is paired with, and pick the
//! default.

use crate::host::normalize_admin_host;
use crate::store::{Relay, Store};
use crate::tpm::short_fingerprint;
use crate::ui::{self, Stream, hinted};

/// Boxed error the CLI prints and exits on.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Prints every paired relay, the default first.
pub async fn run_list() -> Result<(), BoxError> {
    let store = Store::open_default().await?;
    let relays = store.relays().await?;
    if relays.is_empty() {
        return Err(hinted(
            "this machine is not paired with any relay",
            "run `weave pair <admin-host>` to pair it",
        ));
    }
    for line in render(&relays) {
        println!("{line}");
    }
    Ok(())
}

/// Makes `admin_host` the default relay.
pub async fn run_set_default(admin_host: &str) -> Result<(), BoxError> {
    let host = normalize_admin_host(admin_host)?;
    let store = Store::open_default().await?;
    match store.set_default(&host).await? {
        Some(relay) => {
            ui::success(&format!(
                "{} is now the default relay",
                ui::accent(Stream::Out, &relay.admin_host)
            ));
            Ok(())
        }
        None => Err(hinted(
            format!("this machine is not paired with {host}"),
            format!("run `weave relays` to list paired relays, or `weave pair {host}`"),
        )),
    }
}

/// One aligned row per relay: marker, host, machine, key, default tag.
pub fn render(relays: &[Relay]) -> Vec<String> {
    let host_w = relays
        .iter()
        .map(|r| r.admin_host.chars().count())
        .max()
        .unwrap_or(0);
    let machine_w = relays
        .iter()
        .map(|r| r.machine_id.to_string().len())
        .max()
        .unwrap_or(1);
    relays
        .iter()
        .map(|r| {
            let marker = if r.is_default {
                ui::green(Stream::Out, ui::STAR)
            } else {
                " ".to_string()
            };
            let host = format!("{:<host_w$}", r.admin_host);
            let host = if r.is_default {
                ui::accent(Stream::Out, &host)
            } else {
                ui::bold(Stream::Out, &host)
            };
            let machine = format!("machine {:<machine_w$}", r.machine_id);
            let tag = if r.is_default {
                format!("  {}", ui::green(Stream::Out, "default"))
            } else {
                String::new()
            };
            format!(
                "{marker} {host}  {}  {}{tag}",
                ui::dim(Stream::Out, &machine),
                ui::dim(Stream::Out, &short_fingerprint(&r.key_id)),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_are_aligned_and_mark_the_default() {
        let key = format!("p256:0271af4a{}8329", "0".repeat(54));
        let relays = vec![
            Relay {
                id: 2,
                admin_host: "weaver1.offworld.nexus".into(),
                machine_id: 7,
                key_id: key.clone(),
                is_default: true,
            },
            Relay {
                id: 1,
                admin_host: "relay.example:8443".into(),
                machine_id: 12,
                key_id: key,
                is_default: false,
            },
        ];
        assert_eq!(
            render(&relays),
            [
                "\u{2605} weaver1.offworld.nexus  machine 7   p256:0271af4a\u{2026}8329  default",
                "  relay.example:8443      machine 12  p256:0271af4a\u{2026}8329",
            ]
        );
    }
}
