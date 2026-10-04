//! Explicit DNS delegation probes for setup host verification.
//!
//! Queries the public recursive resolvers (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`)
//! directly with a hand-built `hickory-proto` message rather than the system
//! resolver. On a relay running `systemd-resolved`, the local stub masks a
//! broken delegation: it happily answers from a stale upstream cache or from
//! the parent zone, so setup would proceed against a zone it cannot actually
//! serve. Talking to public resolvers over a fresh UDP socket shows what the
//! rest of the internet sees.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use sha2::Digest;
use tokio::net::UdpSocket;

use crate::zone::normalize_domain;

/// Public recursive resolvers queried directly during setup.
pub const PUBLIC_RESOLVERS: &[&str] = &["1.1.1.1", "8.8.8.8", "9.9.9.9"];

/// UDP port of a DNS resolver.
const RESOLVER_PORT: u16 = 53;

/// Per-attempt timeout for a single resolver query.
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// Total attempts per query (the first try plus retries).
const QUERY_ATTEMPTS: usize = 3;

/// Result of resolving the delegated zone through the public recursives.
///
/// Distinguishes the apex from a freshly generated one-label probe name so a
/// half-propagated delegation (apex answers, wildcard does not, or vice versa)
/// is caught.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneProbe {
    /// Resolved IP addresses for `<root>`.
    pub root_ips: Vec<IpAddr>,
    /// Ephemeral probe subdomain queried (e.g. `probe-<random>.<root>`).
    pub probe_domain: String,
    /// Resolved IP addresses for `probe-<random>.<root>`.
    pub probe_ips: Vec<IpAddr>,
    /// Whether every public resolver returned the same set for the probe name.
    pub resolvers_ok: bool,
}

/// Generates a random lowercase hex string of specified byte length (produces `len * 2` hex chars).
pub fn generate_random_hex(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        if f.read_exact(&mut bytes).is_ok() {
            return bytes.iter().map(|b| format!("{b:02x}")).collect();
        }
    }

    // Fallback: SHA256 of timestamp and process id
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    let hash = sha2::Sha256::digest(format!("{now}:{pid}").as_bytes());
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = hash[i % hash.len()];
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A random transaction ID for a DNS query.
fn random_query_id() -> u16 {
    let hex = generate_random_hex(2);
    u16::from_str_radix(&hex, 16).unwrap_or(0)
}

/// Sends one DNS query to `resolver`, retrying a couple of times on timeout.
async fn query_resolver(
    resolver: IpAddr,
    qname: &str,
    qtype: RecordType,
) -> Result<Message, String> {
    let mut last_err = String::new();
    for _ in 0..QUERY_ATTEMPTS {
        match query_once(resolver, qname, qtype).await {
            Ok(msg) => return Ok(msg),
            Err(err) => last_err = err,
        }
    }
    Err(last_err)
}

/// Builds, sends, and decodes a single UDP DNS query over a fresh socket.
async fn query_once(resolver: IpAddr, qname: &str, qtype: RecordType) -> Result<Message, String> {
    let name = Name::from_str(&format!("{qname}."))
        .map_err(|e| format!("invalid query name '{qname}': {e}"))?;

    let id = random_query_id();
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name, qtype));

    let bytes = msg
        .to_vec()
        .map_err(|e| format!("failed to encode query for {qname}/{qtype}: {e}"))?;

    let bind_addr = if resolver.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| format!("failed to bind UDP probe socket: {e}"))?;
    let target = SocketAddr::new(resolver, RESOLVER_PORT);
    socket
        .connect(target)
        .await
        .map_err(|e| format!("failed to connect UDP probe socket to {target}: {e}"))?;
    socket
        .send(&bytes)
        .await
        .map_err(|e| format!("failed to send query to {target}: {e}"))?;

    let mut buf = [0u8; 4096];
    let n = match tokio::time::timeout(QUERY_TIMEOUT, socket.recv(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(format!("UDP receive from {target} failed: {e}")),
        Err(_) => {
            return Err(format!(
                "timed out after {QUERY_TIMEOUT:?} waiting on {target}"
            ));
        }
    };

    let resp = Message::from_vec(&buf[..n])
        .map_err(|e| format!("malformed DNS reply from {target}: {e}"))?;

    if resp.metadata.id != id {
        return Err(format!(
            "reply from {target} had mismatched transaction id (expected {id}, got {})",
            resp.metadata.id
        ));
    }
    if resp.metadata.message_type != MessageType::Response {
        return Err(format!("reply from {target} was not a DNS response"));
    }

    Ok(resp)
}

/// Extracts the A/AAAA addresses from a decoded response's answer section.
fn collect_addresses(msg: &Message) -> Vec<IpAddr> {
    msg.answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
            _ => None,
        })
        .collect()
}

/// Extracts normalized NS target names from the answer and authority sections.
fn collect_ns_targets(msg: &Message) -> Vec<String> {
    msg.answers
        .iter()
        .chain(msg.authorities.iter())
        .filter_map(|record| match &record.data {
            RData::NS(ns) => Some(normalize_domain(&ns.0.to_utf8())),
            _ => None,
        })
        .collect()
}

/// Queries one name's A and AAAA records through a single resolver, returning
/// the combined, deduplicated address set. `Err` records transport failure.
async fn resolve_both(resolver: IpAddr, qname: &str) -> Result<Vec<IpAddr>, String> {
    let mut ips = Vec::new();
    let mut last_err = None;
    for qtype in [RecordType::A, RecordType::AAAA] {
        match query_resolver(resolver, qname, qtype).await {
            Ok(msg) => ips.extend(collect_addresses(&msg)),
            Err(err) => last_err = Some(err),
        }
    }
    if ips.is_empty()
        && let Some(err) = last_err
    {
        return Err(format!("{resolver}: {err}"));
    }
    ips.sort();
    ips.dedup();
    Ok(ips)
}

/// Checks that `<root>` is self-delegated: the parent's `NS <root>` must list
/// `<root>` itself. This reads only the parent zone, so it works before the
/// relay's own responder is running — which is what lets `setup` bring DNS up
/// first and verify delegation second.
pub async fn probe_delegation(root_domain: &str) -> Result<(Vec<String>, bool), String> {
    let root = normalize_domain(root_domain);
    let resolvers: Vec<IpAddr> = PUBLIC_RESOLVERS
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .collect();

    let mut ns_targets = Vec::new();
    let mut ns_failures = Vec::new();
    for resolver in &resolvers {
        match query_resolver(*resolver, &root, RecordType::NS).await {
            Ok(msg) => {
                let found = collect_ns_targets(&msg);
                tracing::debug!(
                    resolver = %resolver,
                    answers = msg.answers.len(),
                    authorities = msg.authorities.len(),
                    ?found,
                    "delegation probe: NS reply"
                );
                ns_targets.extend(found);
            }
            Err(err) => {
                tracing::warn!(resolver = %resolver, error = %err, "delegation probe: NS query failed");
                ns_failures.push(err);
            }
        }
    }
    ns_targets.sort();
    ns_targets.dedup();
    let delegation_ok = ns_targets.iter().any(|target| target == &root);

    if ns_targets.is_empty() && ns_failures.len() == resolvers.len() {
        return Err(format!(
            "NS lookup for '{root}' failed through every public resolver; expected self-delegation to '{root}': {}",
            ns_failures.join("; ")
        ));
    }
    Ok((ns_targets, delegation_ok))
}

/// Reads the delegation for `<root>` straight from its parent's authoritative
/// servers.
///
/// Unlike [`probe_delegation`], this does not ask a recursive resolver to walk
/// into the child zone, so it returns the truth even when the child (the relay)
/// is not answering DNS yet — or is already delegated but broken. It is what
/// lets `setup` tell "the operator has not added the NS record" apart from
/// "the responder is not up yet", without depending on resolver caches.
///
/// `expected_ns` is the relay's admin hostname: OFF-198 delegates the tunnel
/// zone to the admin name, which is always resolvable because it lives outside
/// the delegation.
pub async fn probe_registrar_delegation(
    root_domain: &str,
    expected_ns: &str,
) -> Result<(Vec<String>, bool), String> {
    let root = normalize_domain(root_domain);
    let expected = normalize_domain(expected_ns);
    let labels: Vec<&str> = root.split('.').collect();
    if labels.len() < 2 {
        return Err(format!(
            "'{root}' has no parent zone to read a delegation from"
        ));
    }
    let resolvers: Vec<IpAddr> = PUBLIC_RESOLVERS
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .collect();

    // 1. Walk up from the immediate parent to the enclosing zone. The base
    //    domain may itself be a subdomain of a larger zone, in which case the
    //    immediate parent has no NS records of its own; the first name with NS
    //    records is the zone that holds the delegation.
    let mut parent_ns = Vec::new();
    for start in 1..labels.len() {
        let candidate = labels[start..].join(".");
        for resolver in &resolvers {
            if let Ok(msg) = query_resolver(*resolver, &candidate, RecordType::NS).await {
                parent_ns.extend(collect_ns_targets(&msg));
            }
        }
        parent_ns.sort();
        parent_ns.dedup();
        if !parent_ns.is_empty() {
            break;
        }
    }
    if parent_ns.is_empty() {
        return Err(format!(
            "could not discover an enclosing zone with name servers for '{root}'"
        ));
    }

    // 2. Resolve one address per parent NS and query it directly for the
    //    child's NS record. The parent answers authoritatively even while the
    //    child is down.
    let mut targets = Vec::new();
    for ns in &parent_ns {
        let mut ips = Vec::new();
        for resolver in &resolvers {
            if let Ok(found) = resolve_both(*resolver, ns).await
                && !found.is_empty()
            {
                ips = found;
                break;
            }
        }
        for ip in ips {
            if let Ok(msg) = query_resolver(ip, &root, RecordType::NS).await {
                targets.extend(collect_ns_targets(&msg));
            }
        }
    }
    targets.sort();
    targets.dedup();
    // The tunnel zone is delegated to the relay's own admin hostname, which is
    // what the parent's `NS <root>` records must point at.
    let delegation_ok = delegation_matches(&targets, &expected);
    Ok((targets, delegation_ok))
}

/// True when the parent's `NS <root>` targets include `expected_ns`.
///
/// OFF-198 delegates the tunnel zone to the relay's *admin* hostname (which
/// lives outside the delegation and is therefore always resolvable), not to the
/// apex itself. Comparison is case-insensitive with any trailing dot ignored.
pub fn delegation_matches(targets: &[String], expected_ns: &str) -> bool {
    let expected = normalize_domain(expected_ns);
    targets
        .iter()
        .any(|target| normalize_domain(target) == expected)
}

/// Resolves the apex and a fresh probe name through the public recursives.
///
/// This needs the relay's authoritative responder to be up (and the delegation
/// to point at it), so call it *after* the DNS socket is started.
pub async fn probe_zone(root_domain: &str) -> ZoneProbe {
    let root = normalize_domain(root_domain);
    let resolvers: Vec<IpAddr> = PUBLIC_RESOLVERS
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .collect();

    // Apex A/AAAA through the public resolvers (union of both families).
    let mut root_ips = Vec::new();
    for resolver in &resolvers {
        if let Ok(ips) = resolve_both(*resolver, &root).await {
            root_ips.extend(ips);
        }
    }
    root_ips.sort();
    root_ips.dedup();

    // Fresh probe subdomain through EACH resolver; every resolver should return
    // exactly the apex set.
    let probe_domain = format!("probe-{}.{}", generate_random_hex(6), root);
    let mut probe_ips = Vec::new();
    let mut resolvers_ok = true;
    for resolver in &resolvers {
        match resolve_both(*resolver, &probe_domain).await {
            Ok(ips) => {
                if ips != root_ips {
                    resolvers_ok = false;
                }
                probe_ips.extend(ips);
            }
            Err(_) => resolvers_ok = false,
        }
    }
    probe_ips.sort();
    probe_ips.dedup();
    if probe_ips != root_ips {
        resolvers_ok = false;
    }

    ZoneProbe {
        root_ips,
        probe_domain,
        probe_ips,
        resolvers_ok,
    }
}

/// Resolves `name` A and AAAA through every public recursive and returns the
/// deduplicated, public-only address set.
///
/// Used by the setup/doctor preflight to report what the admin hostname
/// currently points at before any host modification.
pub async fn resolve_public(name: &str) -> Vec<IpAddr> {
    let qname = normalize_domain(name);
    let resolvers: Vec<IpAddr> = PUBLIC_RESOLVERS
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .collect();
    let mut ips = Vec::new();
    for resolver in &resolvers {
        if let Ok(found) = resolve_both(*resolver, &qname).await {
            ips.extend(found);
        }
    }
    ips.retain(super::planner::is_public_ip);
    ips.sort();
    ips.dedup();
    ips
}

/// Returns the host's own global egress addresses (IPv4 and IPv6), public only.
///
/// Connecting a UDP socket sends no packet; it only selects the route's source
/// address, which is the address inbound traffic would need to reach.
pub fn host_egress_ips() -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for (bind, target) in [
        ("0.0.0.0:0", "1.1.1.1:53"),
        ("[::]:0", "[2606:4700:4700::1111]:53"),
    ] {
        if let Ok(socket) = std::net::UdpSocket::bind(bind)
            && socket.connect(target).is_ok()
            && let Ok(addr) = socket.local_addr()
        {
            ips.push(addr.ip());
        }
    }
    ips.retain(super::planner::is_public_ip);
    ips.sort();
    ips.dedup();
    ips
}

/// Determines the relay's own public addresses for the socket unit and the
/// authoritative A/AAAA answers.
///
/// Prefers what the admin domain currently resolves to (the operator points
/// `A`/`AAAA <admin>` at the relay in the same visit as the `NS` delegation),
/// then unions in the host's global egress addresses. The egress fallback is
/// what makes a re-run after the delegation already exists work even if the
/// admin record is briefly unreadable. Non-public addresses are dropped; behind
/// NAT the operator overrides with `--relay-ip`.
pub async fn detect_relay_ips(admin_domain: &str) -> Vec<IpAddr> {
    let mut ips = resolve_public(admin_domain).await;
    ips.extend(host_egress_ips());
    ips.retain(super::planner::is_public_ip);
    ips.sort();
    ips.dedup();
    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_hex_is_lowercase_and_sized() {
        let hex = generate_random_hex(6);
        assert_eq!(hex.len(), 12);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn normalize_strips_trailing_dot_and_lowercases() {
        assert_eq!(normalize_domain("Example.COM."), "example.com");
    }

    #[test]
    fn delegation_target_is_the_admin_hostname() {
        // OFF-198: the tunnel zone is delegated to the relay's admin hostname,
        // not to the apex itself.
        let targets = vec![
            "relay.example.net.".to_string(),
            "ns2.example.net".to_string(),
        ];
        assert!(delegation_matches(&targets, "relay.example.net"));
        assert!(delegation_matches(&targets, "Relay.Example.NET."));
        assert!(!delegation_matches(&targets, "tunnel.example.com"));
    }
}
