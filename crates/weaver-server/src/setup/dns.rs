//! DNS probe and resolution utilities for host verification.
//!
//! Queries the system resolver for the root domain and an ephemeral random subdomain,
//! ensuring both resolve to matching sets of public IP addresses.

use sha2::Digest;
use std::net::IpAddr;

/// Output of a DNS probe verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsProbeResult {
    /// Resolved IP addresses for `<root>`.
    pub root_ips: Vec<IpAddr>,
    /// Ephemeral probe subdomain queried (e.g. `probe-<random>.<root>`).
    pub probe_domain: String,
    /// Resolved IP addresses for `probe-<random>.<root>`.
    pub probe_ips: Vec<IpAddr>,
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

/// Resolves unique IP addresses for a domain name using the system DNS resolver.
pub async fn resolve_domain_ips(domain: &str) -> Result<Vec<IpAddr>, String> {
    let host_port = format!("{domain}:0");
    match tokio::net::lookup_host(&host_port).await {
        Ok(iter) => {
            let mut ips: Vec<IpAddr> = iter.map(|sa| sa.ip()).collect();
            ips.sort();
            ips.dedup();
            Ok(ips)
        }
        Err(e) => Err(format!("failed to resolve '{domain}': {e}")),
    }
}

/// Performs the complete DNS probe check for `<root>` and `probe-<random>.<root>`.
pub async fn probe_dns(root_domain: &str) -> Result<DnsProbeResult, String> {
    let root_ips = resolve_domain_ips(root_domain).await?;
    let probe_token = generate_random_hex(6);
    let probe_domain = format!("probe-{probe_token}.{root_domain}");
    let probe_ips = resolve_domain_ips(&probe_domain).await?;

    Ok(DnsProbeResult {
        root_ips,
        probe_domain,
        probe_ips,
    })
}
