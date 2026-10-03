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

/// Public recursive resolvers queried directly during setup.
pub const PUBLIC_RESOLVERS: &[&str] = &["1.1.1.1", "8.8.8.8", "9.9.9.9"];

/// UDP port of a DNS resolver.
const RESOLVER_PORT: u16 = 53;

/// Per-attempt timeout for a single resolver query.
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// Total attempts per query (the first try plus retries).
const QUERY_ATTEMPTS: usize = 3;

/// Output of a DNS probe verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsProbeResult {
    /// Resolved IP addresses for `<root>`.
    pub root_ips: Vec<IpAddr>,
    /// Ephemeral probe subdomain queried (e.g. `probe-<random>.<root>`).
    pub probe_domain: String,
    /// Resolved IP addresses for `probe-<random>.<root>`.
    pub probe_ips: Vec<IpAddr>,
    /// NS targets returned for `<root>` by the public resolvers, normalized.
    ///
    /// A correctly delegated relay zone lists itself as its own nameserver, so
    /// this should contain `<root>`.
    pub ns_targets: Vec<String>,
    /// Whether `<root>` is self-delegated (at least one NS target equals the
    /// apex). A parked or parent-held zone fails this and must halt setup.
    pub delegation_ok: bool,
    /// Whether every public resolver returned the apex set for the probe
    /// subdomain. Split-horizon or partially-propagated delegations fail.
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

/// Normalizes a presentation-format name: lowercased, no trailing dot.
fn normalize_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
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
            RData::NS(ns) => Some(normalize_name(&ns.0.to_utf8())),
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

/// Performs the complete explicit DNS probe check for `root_domain`.
///
/// Returns `Err` only when the question could not be answered at all (every
/// public resolver timed out or failed transport). Semantic problems — a
/// non-self delegation, an apex with no A/AAAA, or resolvers that disagree —
/// are reported through the boolean flags so the planner can explain them.
pub async fn probe_dns(root_domain: &str) -> Result<DnsProbeResult, String> {
    let root = normalize_name(root_domain);
    let resolvers: Vec<IpAddr> = PUBLIC_RESOLVERS
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .collect();

    // 1. NS self-delegation through the public resolvers.
    let mut ns_targets = Vec::new();
    let mut ns_failures = Vec::new();
    for resolver in &resolvers {
        match query_resolver(*resolver, &root, RecordType::NS).await {
            Ok(msg) => ns_targets.extend(collect_ns_targets(&msg)),
            Err(err) => ns_failures.push(err),
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
    if !delegation_ok {
        return Err(format!(
            "delegation mismatch for '{root}': expected NS target '{root}', found [{}]",
            ns_targets.join(", ")
        ));
    }

    // 2. Apex A/AAAA through the public resolvers (union of both families).
    let mut root_ips = Vec::new();
    let mut apex_answered = false;
    let mut apex_failures = Vec::new();
    for resolver in &resolvers {
        match resolve_both(*resolver, &root).await {
            Ok(ips) => {
                apex_answered = true;
                root_ips.extend(ips);
            }
            Err(err) => apex_failures.push(err),
        }
    }
    root_ips.sort();
    root_ips.dedup();

    if root_ips.is_empty() && !apex_answered {
        return Err(format!(
            "apex lookup for '{root}' failed through every public resolver; expected the relay's public A/AAAA: {}",
            apex_failures.join("; ")
        ));
    }

    // 3. Fresh probe subdomain through EACH resolver; every resolver must
    //    return exactly the apex set.
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
            Err(_) => {
                resolvers_ok = false;
            }
        }
    }
    probe_ips.sort();
    probe_ips.dedup();
    if probe_ips != root_ips {
        resolvers_ok = false;
    }

    Ok(DnsProbeResult {
        root_ips,
        probe_domain,
        probe_ips,
        ns_targets,
        delegation_ok,
        resolvers_ok,
    })
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
        assert_eq!(normalize_name("Example.COM."), "example.com");
    }
}
