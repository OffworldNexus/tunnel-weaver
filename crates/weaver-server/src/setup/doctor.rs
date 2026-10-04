//! Shared preflight checks for `weaver-server doctor` and `weaver-server setup`.
//!
//! The checklist and its report are a context-agnostic core: the same builders
//! and the same [`DoctorReport`] are used wherever the relay must answer "may
//! this machine serve these two domains?" — in-process during `setup` (before
//! anything on the host is touched) and inside the running daemon, reached over
//! the control socket, where it owns ports 80/443/53.
//!
//! The only thing that differs between the two contexts is a [`Reachability`]
//! probe and where the facts come from:
//!
//! * [`BindReachability`] binds throwaway listeners, so it only runs
//!   *before* installation, when the relay's own sockets are stopped.
//! * [`SelfConnectReachability`] connects to the running daemon's own public
//!   addresses and never binds, so the daemon can run it in normal life.
//!
//! Every check is deliberately *read-only*: it queries public DNS, reads the
//! parent zone, and binds or connects to throwaway sockets, but never edits the
//! host. This module carries no dependency on the control protocol, the daemon,
//! the certificate manager, or the store.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use crossterm::style::Stylize;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use super::dns;
use super::planner::{Port, PortReachability};
use super::reachability;
use crate::store::names::normalize_domain;

/// Per-attempt timeout for a daemon self-connect probe.
const SELF_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// One item in a [`DoctorReport`]'s checklist.
///
/// `title` is an owned `String` so the report (and its JSON) can cross the
/// control socket and be rendered on a differently-configured host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCheck {
    /// Short human title, e.g. `"Domain split"` or `"Port 80"`.
    pub title: String,
    /// Whether the check passed.
    pub ok: bool,
    /// What was observed, phrased so it reads correctly in both outcomes.
    pub detail: String,
    /// What the operator should change when `ok` is false.
    pub remediation: Option<String>,
    /// Structured verdict for port checks, so the planner never has to parse
    /// the human `detail` to recover it. `None` for non-port checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<PortReachability>,
}

/// Aggregated result of every preflight check.
///
/// Ports are ordinary [`DoctorCheck`]s (`Port 80`, `Port 443`, `Port 53`);
/// there are deliberately no separate port fields, so both contexts produce one
/// shape and the transport stays a plain serialization of this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    /// Tunnel zone under test.
    pub tunnel_domain: String,
    /// Admin hostname under test.
    pub admin_domain: String,
    /// The public addresses the relay answers on: the operator override, else
    /// the public union of the admin A/AAAA and host egress.
    pub relay_ips: Vec<IpAddr>,
    /// Addresses `admin_domain` resolved to through the public resolvers.
    pub admin_resolved: Vec<IpAddr>,
    /// NS targets read from the parent of the tunnel zone.
    pub ns_targets: Vec<String>,
    /// The checklist, in display order.
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    /// True when every checklist item passed.
    pub fn ok(&self) -> bool {
        self.checks.iter().all(|check| check.ok)
    }

    /// Returns the failed checks, in display order.
    pub fn failures(&self) -> Vec<&DoctorCheck> {
        self.checks.iter().filter(|check| !check.ok).collect()
    }

    /// Renders the checklist as operator-facing text with a ✓/✗/• marker per
    /// line and a remediation paragraph under each failure.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "{} {} {}\n",
            "Weaver Server Doctor".bold().cyan(),
            "—".dark_grey(),
            "Domain & Reachability Preflight".white()
        ));
        out.push_str(&format!(
            "  {:<14} {}\n",
            "Tunnel domain:".dark_grey(),
            self.tunnel_domain.as_str().bold()
        ));
        out.push_str(&format!(
            "  {:<14} {}\n",
            "Admin domain:".dark_grey(),
            self.admin_domain.as_str().bold()
        ));
        let relay = if self.relay_ips.is_empty() {
            "-".to_string()
        } else {
            self.relay_ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };
        out.push_str(&format!("  {:<14} {}\n\n", "Relay IPs:".dark_grey(), relay));

        for check in &self.checks {
            let (marker, detail) = if !check.ok {
                ("✗".red().bold(), check.detail.as_str().red())
            } else if check.status == Some(PortReachability::Skipped) {
                ("•".blue(), check.detail.as_str().dark_grey())
            } else {
                ("✓".green().bold(), check.detail.as_str().white())
            };
            out.push_str(&format!(
                "{} {} — {}\n",
                marker,
                check.title.as_str().bold(),
                detail
            ));
            if let Some(remediation) = &check.remediation {
                for line in remediation.lines() {
                    out.push_str(&format!("    {}\n", line.yellow()));
                }
            }
        }

        let summary = if self.ok() {
            format!("{}", "All preflight checks passed.".green().bold())
        } else {
            format!(
                "{} preflight check(s) failed.",
                self.failures().len().to_string().red().bold()
            )
            .red()
            .bold()
            .to_string()
        };
        out.push_str(&format!("\n{}", summary));
        out
    }

    /// Serializes the report for `doctor --json`, adding the derived `ok` flag.
    pub fn to_json(&self) -> serde_json::Value {
        let mut value = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        if let Some(object) = value.as_object_mut() {
            object.insert("ok".to_string(), serde_json::Value::Bool(self.ok()));
        }
        value
    }
}

/// Facts already gathered by a context, plus checks that context can build from
/// its own sources (e.g. the daemon's certificate health).
///
/// [`assemble_report`] turns this into a [`DoctorReport`] using the shared pure
/// builders and a [`Reachability`] probe, so neither context re-implements the
/// checklist order or the port handling.
#[derive(Debug, Clone)]
pub struct ReportInputs {
    /// Tunnel zone under test.
    pub tunnel_domain: String,
    /// Admin hostname under test.
    pub admin_domain: String,
    /// The public addresses the relay answers on.
    pub relay_ips: Vec<IpAddr>,
    /// Addresses the admin hostname resolved to (persisted detection for the
    /// daemon, live public DNS for the in-process context).
    pub admin_resolved: Vec<IpAddr>,
    /// NS targets read from the parent zone, empty when unread.
    pub ns_targets: Vec<String>,
    /// Set when the parent delegation could not be read at all.
    pub delegation_error: Option<String>,
    /// Checks the context contributes from non-doctor sources, inserted after
    /// the domain checks and before the port checks.
    pub extra_checks: Vec<DoctorCheck>,
    /// Skip the port probe, emitting `skipped` `Port 80/443/53` checks.
    pub skip_reachability: bool,
}

/// A port-reachability probe behind one interface, so the in-process and daemon
/// compositions differ only in the implementation they pass to
/// [`assemble_report`].
///
/// The trait is async and object-safe via `async_trait`, letting the caller use
/// a concrete probe without monomorphizing the whole assembly.
#[async_trait]
pub trait Reachability: Send + Sync {
    /// Probes every `ip`, returning exactly one check per required port
    /// (80, 443, 53) in display order.
    async fn check(&self, ips: &[IpAddr]) -> Vec<DoctorCheck>;
}

/// Binds throwaway listeners on 80/443/53 and connects back to each relay
/// address, proving inbound traffic lands on this host.
///
/// This is the pre-install probe: it can only run while the relay's own sockets
/// are stopped, because it needs those ports to itself.
pub struct BindReachability;

#[async_trait]
impl Reachability for BindReachability {
    async fn check(&self, ips: &[IpAddr]) -> Vec<DoctorCheck> {
        let results = reachability::verify_reachability(ips).await;
        Port::ALL
            .iter()
            .zip(results)
            .map(|(port, status)| bind_port_check(*port, &status))
            .collect()
    }
}

/// Converts a bound-probe [`PortReachability`] into a per-port checklist item.
///
/// Port 53 gets extra guidance when `systemd-resolved`'s stub listener is the
/// cause, which is the most common bind failure on a fresh host.
fn bind_port_check(port: Port, status: &PortReachability) -> DoctorCheck {
    let title = port.title();
    let description = port.transport();
    match status {
        PortReachability::ReachedSelf => DoctorCheck {
            title,
            ok: true,
            detail: format!("inbound {description} reaches this host"),
            remediation: None,
            status: Some(status.clone()),
        },
        PortReachability::Skipped => DoctorCheck {
            title,
            ok: true,
            detail: "skipped via --skip-reachability-check".to_string(),
            remediation: None,
            status: Some(status.clone()),
        },
        PortReachability::Failed(reason) => {
            let mut detail = reason.clone();
            let mut remediation = format!(
                "Forward {description} to this host and allow it through the host firewall, \
                 then re-run."
            );
            if port == Port::Dns
                && let Some((pid, comm)) = reachability::find_occupying_process(port.number())
                && comm.to_ascii_lowercase().contains("systemd-resolve")
            {
                detail.push_str(&format!(" (port 53 held by '{comm}', PID {pid})"));
                remediation = format!(
                    "port 53 is held by '{comm}' (PID {pid}); disable the systemd-resolved stub \
                     listener (set DNSStubListener=no in /etc/systemd/resolved.conf, then \
                     systemctl restart systemd-resolved) and re-run."
                );
            }
            DoctorCheck {
                title,
                ok: false,
                detail,
                remediation: Some(remediation),
                status: Some(status.clone()),
            }
        }
    }
}

/// Probes the running daemon's own public addresses without binding anything.
///
/// The daemon already holds 80/443/53; `SelfConnectReachability` therefore
/// connects to `config.relay_ips` instead of stealing the ports. Port 80 sends
/// an HTTP/1.0 request for the admin host, port 443 does a plain TCP connect,
/// and port 53 sends a DNS `A` query for the tunnel apex over UDP; every relay
/// address must succeed for the port to pass.
pub struct SelfConnectReachability {
    /// Admin hostname used as the HTTP `Host` header on the port-80 probe.
    admin_domain: String,
    /// Tunnel apex queried in the port-53 UDP probe.
    tunnel_domain: String,
}

impl SelfConnectReachability {
    /// Builds a self-connect probe for the given admin hostname and apex.
    pub fn new(admin_domain: impl Into<String>, tunnel_domain: impl Into<String>) -> Self {
        Self {
            admin_domain: admin_domain.into(),
            tunnel_domain: tunnel_domain.into(),
        }
    }

    /// Produces the three port checks, allowing tests to substitute the ports
    /// for locally bound listeners (80/443/53 cannot be bound unprivileged).
    async fn checks_with_ports(&self, ips: &[IpAddr], ports: [u16; 3]) -> Vec<DoctorCheck> {
        let mut checks = Vec::with_capacity(Port::ALL.len());
        for port in Port::ALL {
            let check = match port {
                Port::Http => {
                    self.tcp_port_check(port, ips, ports[port.index()], true)
                        .await
                }
                Port::Https => {
                    self.tcp_port_check(port, ips, ports[port.index()], false)
                        .await
                }
                Port::Dns => self.dns_port_check(port, ips, ports[port.index()]).await,
            };
            checks.push(check);
        }
        checks
    }

    /// TCP-connects to `port` on every IP. On port 80 it also sends a minimal
    /// HTTP request for the admin host and accepts any (or no) response — the
    /// connect itself is the probe.
    async fn tcp_port_check(
        &self,
        port: Port,
        ips: &[IpAddr],
        number: u16,
        send_http: bool,
    ) -> DoctorCheck {
        if ips.is_empty() {
            return unreachable_port(port, "no public relay addresses to probe");
        }
        let mut results = Vec::with_capacity(ips.len());
        let mut all_ok = true;
        for &ip in ips {
            match self.probe_tcp(ip, number, send_http).await {
                Ok(()) => results.push(format!("{ip}: reachable")),
                Err(err) => {
                    all_ok = false;
                    results.push(format!("{ip}: {err}"));
                }
            }
        }
        let remediation = (!all_ok).then(|| {
            format!(
                "Check that TCP {number} is forwarded to this relay and not blocked by the host \
                 firewall, then re-run `weaver-server doctor`."
            )
        });
        let status = if all_ok {
            PortReachability::ReachedSelf
        } else {
            PortReachability::Failed(results.join("; "))
        };
        port_check(port, status, results, remediation)
    }

    /// Sends a DNS `A` query for the tunnel apex to `port` on every IP and
    /// requires a response datagram.
    async fn dns_port_check(&self, port: Port, ips: &[IpAddr], number: u16) -> DoctorCheck {
        if ips.is_empty() {
            return unreachable_port(port, "no public relay addresses to probe");
        }
        let mut results = Vec::with_capacity(ips.len());
        let mut all_ok = true;
        for &ip in ips {
            match self.probe_dns(ip, number).await {
                Ok(()) => results.push(format!("{ip}: reachable")),
                Err(err) => {
                    all_ok = false;
                    results.push(format!("{ip}: {err}"));
                }
            }
        }
        let remediation = (!all_ok).then(|| {
            "Check that UDP 53 is forwarded to this relay and that the authoritative DNS \
             responder is running, then re-run `weaver-server doctor`."
                .to_string()
        });
        let status = if all_ok {
            PortReachability::ReachedSelf
        } else {
            PortReachability::Failed(results.join("; "))
        };
        port_check(port, status, results, remediation)
    }

    /// One timed TCP connect, with an optional HTTP request on success.
    async fn probe_tcp(&self, ip: IpAddr, port: u16, send_http: bool) -> Result<(), String> {
        let target = SocketAddr::new(ip, port);
        let mut stream =
            match tokio::time::timeout(SELF_CONNECT_TIMEOUT, TcpStream::connect(target)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(err)) => return Err(format!("connect failed: {err}")),
                Err(_) => return Err(format!("timed out after {SELF_CONNECT_TIMEOUT:?}")),
            };

        if send_http {
            let request = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", self.admin_domain);
            if stream.write_all(request.as_bytes()).await.is_ok() {
                let _ = stream.flush().await;
                let mut buf = [0u8; 128];
                // Best effort: any response (or none) still counts as reachable.
                let _ = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
            }
        }
        Ok(())
    }

    /// One timed DNS query over UDP; any response proves the datagram path.
    async fn probe_dns(&self, ip: IpAddr, port: u16) -> Result<(), String> {
        let target = SocketAddr::new(ip, port);
        let name = Name::from_str(&format!("{}.", self.tunnel_domain))
            .map_err(|err| format!("invalid apex name: {err}"))?;
        let id = u16::from_str_radix(&dns::generate_random_hex(2), 16).unwrap_or(0);
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = false;
        message.add_query(Query::query(name, RecordType::A));
        let bytes = message
            .to_vec()
            .map_err(|err| format!("failed to encode DNS query: {err}"))?;

        let bind_addr = if ip.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|err| format!("failed to bind probe socket: {err}"))?;
        socket
            .connect(target)
            .await
            .map_err(|err| format!("could not connect to {target}: {err}"))?;
        socket
            .send(&bytes)
            .await
            .map_err(|err| format!("failed to send query: {err}"))?;

        let mut buf = [0u8; 512];
        match tokio::time::timeout(SELF_CONNECT_TIMEOUT, socket.recv(&mut buf)).await {
            Ok(Ok(0)) => Err("empty DNS response".to_string()),
            Ok(Ok(_)) => Ok(()),
            Ok(Err(err)) => Err(format!("DNS receive failed: {err}")),
            Err(_) => Err(format!("timed out after {SELF_CONNECT_TIMEOUT:?}")),
        }
    }
}

#[async_trait]
impl Reachability for SelfConnectReachability {
    async fn check(&self, ips: &[IpAddr]) -> Vec<DoctorCheck> {
        let ports = [
            Port::Http.number(),
            Port::Https.number(),
            Port::Dns.number(),
        ];
        self.checks_with_ports(ips, ports).await
    }
}

/// Builds a per-port check from per-address result lines and its verdict.
fn port_check(
    port: Port,
    status: PortReachability,
    mut results: Vec<String>,
    remediation: Option<String>,
) -> DoctorCheck {
    results.sort();
    DoctorCheck {
        title: port.title(),
        ok: matches!(status, PortReachability::ReachedSelf),
        detail: results.join("; "),
        remediation,
        status: Some(status),
    }
}

/// A port check for the case where there is no address to probe at all.
fn unreachable_port(port: Port, detail: &str) -> DoctorCheck {
    DoctorCheck {
        title: port.title(),
        ok: false,
        detail: detail.to_string(),
        remediation: Some(
            "Point the admin A/AAAA at this relay or pass --relay-ip <ADDR>, then re-run."
                .to_string(),
        ),
        status: Some(PortReachability::Failed(detail.to_string())),
    }
}

/// Assembles a report from already-gathered facts and a reachability probe.
///
/// Shared by [`run_in_process`] and the daemon context: it fixes the checklist
/// order (domain split, admin addresses, delegation, context checks, ports) and
/// emits `skipped` port checks when asked, so the two contexts never diverge.
pub async fn assemble_report(
    inputs: ReportInputs,
    reachability: &dyn Reachability,
) -> DoctorReport {
    let mut checks = vec![
        domain_split_check(&inputs.admin_domain, &inputs.tunnel_domain),
        admin_addresses_check(
            &inputs.admin_domain,
            &inputs.relay_ips,
            &inputs.admin_resolved,
        ),
    ];

    match &inputs.delegation_error {
        Some(err) => checks.push(DoctorCheck {
            title: "Delegation".to_string(),
            ok: false,
            detail: format!(
                "could not read the parent delegation for '{}': {err}",
                inputs.tunnel_domain
            ),
            remediation: Some(delegation_records(
                &inputs.admin_domain,
                &inputs.tunnel_domain,
                &inputs.relay_ips,
            )),
            status: None,
        }),
        None => checks.push(delegation_check(
            &inputs.admin_domain,
            &inputs.tunnel_domain,
            &inputs.ns_targets,
        )),
    }

    checks.extend(inputs.extra_checks);

    if inputs.skip_reachability {
        checks.extend(Port::ALL.iter().map(|port| DoctorCheck {
            title: port.title(),
            ok: true,
            detail: "skipped via --skip-reachability-check".to_string(),
            remediation: None,
            status: Some(PortReachability::Skipped),
        }));
    } else {
        checks.extend(reachability.check(&inputs.relay_ips).await);
    }

    DoctorReport {
        tunnel_domain: inputs.tunnel_domain,
        admin_domain: inputs.admin_domain,
        relay_ips: inputs.relay_ips,
        admin_resolved: inputs.admin_resolved,
        ns_targets: inputs.ns_targets,
        checks,
    }
}

/// Runs every preflight check in-process and returns the full report.
///
/// This is the pre-install composition: it resolves the admin name through the
/// public resolvers, unions in the host's own egress addresses when no override
/// was given, reads the delegation from the parent zone, and probes the ports
/// with [`BindReachability`] (throwaway listeners). It never mutates the host.
pub async fn run_in_process(
    tunnel_domain: &str,
    admin_domain: &str,
    relay_ips_override: &[IpAddr],
    skip_reachability: bool,
) -> DoctorReport {
    let root = normalize_domain(tunnel_domain);
    let admin = normalize_domain(admin_domain);

    let admin_resolved = dns::resolve_public(&admin).await;
    // Shared with setup's own planning path so the admin-vs-egress union and
    // public filtering cannot diverge between `doctor` and `setup`.
    let relay_ips = if relay_ips_override.is_empty() {
        dns::detect_relay_ips(&admin).await
    } else {
        relay_ips_override.to_vec()
    };

    let (ns_targets, delegation_error) = match dns::probe_registrar_delegation(&root, &admin).await
    {
        Ok((targets, _)) => (targets, None),
        Err(err) => (Vec::new(), Some(err)),
    };

    let bind = BindReachability;
    assemble_report(
        ReportInputs {
            tunnel_domain: root,
            admin_domain: admin,
            relay_ips,
            admin_resolved,
            ns_targets,
            delegation_error,
            extra_checks: Vec::new(),
            skip_reachability,
        },
        &bind,
    )
    .await
}

/// Reads the planner's [`PortReachability`] verdict for `port` from the
/// report's per-port check.
///
/// The verdict is carried structurally on the check (`status`), not recovered
/// from its human `detail`, so rephrasing a rendered message cannot change the
/// planner's decision.
pub fn port_status(report: &DoctorReport, port: Port) -> PortReachability {
    let title = port.title();
    match report.checks.iter().find(|check| check.title == title) {
        Some(check) => check.status.clone().unwrap_or_else(|| {
            if check.ok {
                PortReachability::ReachedSelf
            } else {
                PortReachability::Failed(check.detail.clone())
            }
        }),
        None => PortReachability::Failed(format!("no '{title}' check in report")),
    }
}

/// Builds the domain-split checklist item without doing any I/O.
///
/// The tunnel zone is delegated in full to this relay, so an admin domain
/// *under* it would put the relay's own DNS (and therefore the admin
/// HTTP-01 DCV) under the zone the relay is meant to control.
pub fn domain_split_check(admin_domain: &str, tunnel_domain: &str) -> DoctorCheck {
    match crate::config::domain_split_issue(admin_domain, tunnel_domain) {
        None => DoctorCheck {
            title: "Domain split".to_string(),
            ok: true,
            detail: format!(
                "admin domain '{admin_domain}' is outside the delegated tunnel zone '{tunnel_domain}'"
            ),
            remediation: None,
            status: None,
        },
        Some(issue) => DoctorCheck {
            title: "Domain split".to_string(),
            ok: false,
            detail: issue,
            remediation: Some(
                "Choose an admin domain that is not the tunnel domain and not a subdomain of it, \
                 e.g. relay.example.net for tunnel example.com."
                    .to_string(),
            ),
            status: None,
        },
    }
}

/// Formats the DNS record an operator must create when the tunnel zone is not
/// delegated to the admin hostname.
///
/// Only the `NS` record is produced here. The admin `A`/`AAAA` is checked (and
/// asked for) separately by [`admin_addresses_check`], so a relay whose admin
/// name already resolves is never told to recreate it.
pub fn delegation_records(
    admin_domain: &str,
    tunnel_domain: &str,
    _relay_ips: &[IpAddr],
) -> String {
    let parent = tunnel_domain
        .split_once('.')
        .map(|(_, rest)| rest)
        .unwrap_or(tunnel_domain);
    format!("In the DNS zone for '{parent}', add:\n  {tunnel_domain}.  NS  {admin_domain}.")
}

/// Builds the delegation checklist item from NS targets read from the parent.
///
/// The tunnel zone must be delegated to the relay's admin hostname, which lives
/// outside the delegation and is therefore always resolvable. Pure so the
/// failure path is unit-testable without touching the network.
pub fn delegation_check(
    admin_domain: &str,
    tunnel_domain: &str,
    ns_targets: &[String],
) -> DoctorCheck {
    if dns::delegation_matches(ns_targets, admin_domain) {
        return DoctorCheck {
            title: "Delegation".to_string(),
            ok: true,
            detail: format!("parent zone delegates '{tunnel_domain}' to '{admin_domain}'"),
            remediation: None,
            status: None,
        };
    }
    let found = if ns_targets.is_empty() {
        "no NS record".to_string()
    } else {
        ns_targets.join(", ")
    };
    DoctorCheck {
        title: "Delegation".to_string(),
        ok: false,
        detail: format!("'{tunnel_domain}' is not delegated to '{admin_domain}' (found: {found})"),
        remediation: Some(delegation_records(admin_domain, tunnel_domain, &[])),
        status: None,
    }
}

/// Builds the admin-address checklist item from already-resolved data.
///
/// The admin name must resolve somewhere public so the HTTP-01 challenge can
/// reach this relay; a resolution that disagrees with the operator's relay
/// addresses is reported as a note rather than a failure.
pub fn admin_addresses_check(
    admin_domain: &str,
    relay_ips: &[IpAddr],
    admin_resolved: &[IpAddr],
) -> DoctorCheck {
    let list = |ips: &[IpAddr]| {
        if ips.is_empty() {
            "-".to_string()
        } else {
            ips.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        }
    };
    let admin_list = list(admin_resolved);
    let relay_list = list(relay_ips);

    if relay_ips.is_empty() {
        return DoctorCheck {
            title: "Admin addresses".to_string(),
            ok: false,
            detail: format!(
                "'{admin_domain}' has no public A/AAAA records and no public host egress address"
            ),
            remediation: Some(format!(
                "Point A/AAAA {admin_domain} at this relay's public address, or pass \
                 --relay-ip <ADDR>."
            )),
            status: None,
        };
    }

    if admin_resolved.is_empty() {
        return DoctorCheck {
            title: "Admin addresses".to_string(),
            ok: false,
            detail: format!("'{admin_domain}' does not resolve publicly"),
            remediation: Some(format!(
                "Point A/AAAA {admin_domain} at {relay_list} so HTTP-01 can reach this relay."
            )),
            status: None,
        };
    }

    if admin_resolved.iter().all(|ip| !relay_ips.contains(ip)) {
        return DoctorCheck {
            title: "Admin addresses".to_string(),
            ok: true,
            detail: format!(
                "'{admin_domain}' resolves to [{admin_list}], which differs from the relay \
                 addresses [{relay_list}]"
            ),
            remediation: None,
            status: None,
        };
    }

    DoctorCheck {
        title: "Admin addresses".to_string(),
        ok: true,
        detail: format!(
            "'{admin_domain}' resolves to [{admin_list}]; relay addresses are [{relay_list}]"
        ),
        remediation: None,
        status: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn check(title: &str, ok: bool) -> DoctorCheck {
        DoctorCheck {
            title: title.to_string(),
            ok,
            detail: String::new(),
            remediation: None,
            status: None,
        }
    }

    #[test]
    fn domain_split_rejects_equal_and_nested_admin() {
        let equal = domain_split_check("example.com", "example.com");
        assert!(!equal.ok);
        assert!(equal.detail.contains("must differ"));
        assert!(equal.remediation.is_some());

        let nested = domain_split_check("relay.example.com", "example.com");
        assert!(!nested.ok);
        assert!(nested.detail.contains("subdomain"));
    }

    #[test]
    fn domain_split_accepts_sibling_admin() {
        let ok = domain_split_check("relay.example.net", "example.com");
        assert!(ok.ok);
        assert!(ok.remediation.is_none());
        assert!(ok.detail.contains("outside"));
    }

    #[test]
    fn delegation_records_list_only_the_ns_record() {
        let ips = vec!["203.0.113.7".parse().unwrap()];
        let records = delegation_records("relay.example.net", "tunnel.example.com", &ips);
        assert!(records.contains("tunnel.example.com.  NS  relay.example.net."));
        // The admin A/AAAA is asked for separately; do not repeat it here.
        assert!(!records.contains("A/AAAA"));
        assert!(records.contains("example.com"));
    }

    #[test]
    fn delegation_check_fails_on_wrong_targets() {
        let bad = delegation_check(
            "relay.example.net",
            "tunnel.example.com",
            &["ns1.parking.example".to_string()],
        );
        assert!(!bad.ok);
        assert!(bad.detail.contains("ns1.parking.example"));
        let remediation = bad.remediation.unwrap();
        assert!(remediation.contains("NS  relay.example.net."));

        let good = delegation_check(
            "relay.example.net",
            "tunnel.example.com",
            &["Relay.Example.NET.".to_string()],
        );
        assert!(good.ok);
    }

    #[test]
    fn report_ok_requires_every_check() {
        let report = DoctorReport {
            tunnel_domain: "example.com".into(),
            admin_domain: "relay.example.net".into(),
            relay_ips: vec!["203.0.113.7".parse().unwrap()],
            admin_resolved: vec![],
            ns_targets: vec![],
            checks: vec![
                check("Domain split", true),
                DoctorCheck {
                    title: "Delegation".to_string(),
                    ok: false,
                    detail: "missing".into(),
                    remediation: Some("add it".into()),
                    status: None,
                },
                check("Port 53", true),
            ],
        };
        assert!(!report.ok());
        assert_eq!(report.failures().len(), 1);
        assert_eq!(report.failures()[0].title, "Delegation");
        let json = report.to_json();
        assert_eq!(json["ok"], false);
        assert_eq!(json["checks"][1]["title"], "Delegation");
        // Ports are ordinary checks: no separate port fields exist.
        assert_eq!(json["checks"][2]["title"], "Port 53");
        assert!(json.get("ports").is_none());
    }

    #[test]
    fn admin_addresses_check_flags_missing_resolution() {
        let relay = vec!["203.0.113.7".parse().unwrap()];
        let check = admin_addresses_check("relay.example.net", &relay, &[]);
        assert!(!check.ok);
        assert!(check.remediation.is_some());
    }

    #[test]
    fn admin_addresses_check_notes_foreign_resolution() {
        let relay = vec!["203.0.113.7".parse().unwrap()];
        let admin = vec!["198.51.100.9".parse().unwrap()];
        let check = admin_addresses_check("relay.example.net", &relay, &admin);
        assert!(check.ok);
        assert!(check.detail.contains("differs"));
    }

    #[test]
    fn port_status_recovers_the_planner_verdict() {
        let mut report = DoctorReport {
            tunnel_domain: "example.com".into(),
            admin_domain: "relay.example.net".into(),
            relay_ips: vec![],
            admin_resolved: vec![],
            ns_targets: vec![],
            checks: vec![
                check("Port 80", true),
                DoctorCheck {
                    title: "Port 443".to_string(),
                    ok: false,
                    detail: "connection refused".into(),
                    remediation: None,
                    status: Some(PortReachability::Failed("connection refused".into())),
                },
                DoctorCheck {
                    title: "Port 53".to_string(),
                    ok: true,
                    detail: "skipped via --skip-reachability-check".into(),
                    remediation: None,
                    status: Some(PortReachability::Skipped),
                },
            ],
        };
        assert_eq!(
            port_status(&report, Port::Http),
            PortReachability::ReachedSelf
        );
        assert_eq!(
            port_status(&report, Port::Https),
            PortReachability::Failed("connection refused".into())
        );
        assert_eq!(port_status(&report, Port::Dns), PortReachability::Skipped);
        // A report that never probed a port reports a failure, not a panic.
        report.checks.clear();
        assert!(matches!(
            port_status(&report, Port::Http),
            PortReachability::Failed(_)
        ));
    }

    #[test]
    fn bind_port_check_marks_failures_with_remediation() {
        let ok = bind_port_check(Port::Http, &PortReachability::ReachedSelf);
        assert!(ok.ok);
        assert!(ok.remediation.is_none());
        assert_eq!(ok.status, Some(PortReachability::ReachedSelf));

        let failed = bind_port_check(
            Port::Https,
            &PortReachability::Failed("connection timed out".into()),
        );
        assert!(!failed.ok);
        assert!(failed.detail.contains("connection timed out"));
        assert!(failed.remediation.is_some());
        assert_eq!(
            failed.status,
            Some(PortReachability::Failed("connection timed out".into()))
        );
    }

    #[tokio::test]
    async fn assemble_emits_three_skipped_port_checks() {
        let bind = BindReachability;
        let report = assemble_report(
            ReportInputs {
                tunnel_domain: "example.com".into(),
                admin_domain: "relay.example.net".into(),
                relay_ips: vec!["203.0.113.7".parse().unwrap()],
                admin_resolved: vec!["203.0.113.7".parse().unwrap()],
                ns_targets: vec!["relay.example.net".to_string()],
                delegation_error: None,
                extra_checks: vec![check("Certificate relay.example.net", true)],
                skip_reachability: true,
            },
            &bind,
        )
        .await;

        assert!(report.ok());
        for title in ["Port 80", "Port 443", "Port 53"] {
            let port = report
                .checks
                .iter()
                .find(|c| c.title == title)
                .expect("port check");
            assert!(port.ok);
            assert!(port.detail.starts_with("skipped"));
        }
        // The context-contributed check sits between delegation and the ports.
        let cert_pos = report
            .checks
            .iter()
            .position(|c| c.title == "Certificate relay.example.net")
            .unwrap();
        let port_pos = report
            .checks
            .iter()
            .position(|c| c.title == "Port 80")
            .unwrap();
        assert!(cert_pos < port_pos);
    }

    #[tokio::test]
    async fn self_connect_reports_reachable_local_listeners() {
        // Bind throwaway listeners on ephemeral ports and point the probe at
        // them, since 80/443/53 cannot be bound unprivileged in tests.
        let tcp80 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port80 = tcp80.local_addr().unwrap().port();
        let tcp443 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port443 = tcp443.local_addr().unwrap().port();
        let udp53 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port53 = udp53.local_addr().unwrap().port();

        // Answer the DNS probe with an echo so any datagram counts as a reply.
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((n, peer)) = udp53.recv_from(&mut buf).await {
                let _ = udp53.send_to(&buf[..n], peer).await;
            }
        });

        let probe = SelfConnectReachability::new("relay.example.net", "tunnel.example.com");
        let checks = probe
            .checks_with_ports(&["127.0.0.1".parse().unwrap()], [port80, port443, port53])
            .await;
        assert_eq!(checks.len(), 3);
        for check in &checks {
            assert!(check.ok, "{} failed: {}", check.title, check.detail);
            assert!(check.detail.contains("reachable"));
        }
        drop(tcp80);
        drop(tcp443);
    }

    #[tokio::test]
    async fn self_connect_reports_unreachable_ports() {
        // Reserve then drop listeners so the ports are closed: TCP fails fast
        // with connection refused and UDP with an ICMP port-unreachable.
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_tcp = tcp.local_addr().unwrap().port();
        drop(tcp);
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let closed_udp = udp.local_addr().unwrap().port();
        drop(udp);

        let probe = SelfConnectReachability::new("relay.example.net", "tunnel.example.com");
        let checks = probe
            .checks_with_ports(
                &["127.0.0.1".parse().unwrap()],
                [closed_tcp, closed_tcp, closed_udp],
            )
            .await;
        assert_eq!(checks.len(), 3);
        for check in &checks {
            assert!(!check.ok, "{} unexpectedly passed", check.title);
            assert!(check.remediation.is_some());
        }
    }

    #[tokio::test]
    async fn self_connect_fails_without_addresses() {
        let probe = SelfConnectReachability::new("relay.example.net", "tunnel.example.com");
        let checks = probe.check(&[]).await;
        assert_eq!(checks.len(), 3);
        assert!(checks.iter().all(|check| !check.ok));
        assert!(checks[0].detail.contains("no public relay addresses"));
    }
}
