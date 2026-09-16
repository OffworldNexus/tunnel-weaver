//! Pure planning logic for the `weaver-server setup` command.
//!
//! Evaluates host probe results against installation requirements,
//! deciding whether to proceed with an execution plan or abort with an explanation.

use std::collections::BTreeSet;
use std::net::IpAddr;

/// Validates whether an IP address is a publicly routable global address.
pub fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            if ipv4.is_loopback()
                || ipv4.is_private()
                || ipv4.is_link_local()
                || ipv4.is_broadcast()
                || ipv4.is_unspecified()
                || ipv4.is_documentation()
            {
                return false;
            }
            let octets = ipv4.octets();
            // CGNAT shared address space 100.64.0.0/10
            if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                return false;
            }
            // Benchmarking 198.18.0.0/15
            if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
                return false;
            }
            true
        }
        IpAddr::V6(ipv6) => {
            if ipv6.is_loopback() || ipv6.is_unspecified() {
                return false;
            }
            let segments = ipv6.segments();
            // Unique Local Address fc00::/7
            if (segments[0] & 0xfe00) == 0xfc00 {
                return false;
            }
            // Link-local unicast fe80::/10
            if (segments[0] & 0xffc0) == 0xfe80 {
                return false;
            }
            // Documentation 2001:db8::/32
            if segments[0] == 0x2001 && segments[1] == 0xdb8 {
                return false;
            }
            // IPv4-mapped IPv6 (::ffff:0:0/96)
            if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                return is_public_ip(&IpAddr::V4(ipv4));
            }
            true
        }
    }
}

/// Information about an existing installation found on the system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingInstall {
    /// Currently configured root domain in the existing installation.
    pub root_domain: String,
}

/// Reachability probe result for a specific port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortReachability {
    /// Outbound connection to resolved public IP successfully routed back to our listener and solved the challenge.
    ReachedSelf,
    /// Connection failed to reach self with explanation.
    Failed(String),
    /// Reachability check was bypassed.
    Skipped,
}

/// Aggregated system probe results provided to the pure planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemProbe {
    /// Whether systemd is active on the host and systemctl is available.
    pub systemd_present: bool,
    /// Whether the host CPU architecture is supported (x86_64 or aarch64 on Linux).
    pub supported_arch: bool,
    /// Target root domain being installed.
    pub target_domain: String,
    /// Optional existing installation details.
    pub existing_install: Option<ExistingInstall>,
    /// Resolved IP addresses for the apex domain `<root>`.
    pub root_ips: Vec<IpAddr>,
    /// Resolved IP addresses for the random probe subdomain `probe-<random>.<root>`.
    pub probe_ips: Vec<IpAddr>,
    /// Reachability probe status on port 80.
    pub port_80: PortReachability,
    /// Reachability probe status on port 443.
    pub port_443: PortReachability,
    /// Whether setup was invoked in non-interactive headless mode.
    pub is_headless: bool,
    /// Whether the user confirmed changing an existing installed domain.
    pub confirmed_domain_change: bool,
    /// Whether reachability verification was explicitly skipped via CLI flag.
    pub skip_reachability_check: bool,
    /// Target database path.
    pub db_path: String,
    /// Dedicated service user name.
    pub user: String,
    /// Binary installation prefix.
    pub prefix: String,
    /// Selected ACME provider identifier.
    pub acme_provider: String,
    /// Whether External Account Binding (EAB) credentials will be registered.
    pub has_eab: bool,
}

/// Fatal condition detected during planning that halts setup.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanAbort {
    /// Systemd is not active or systemctl is missing.
    #[error("the server component supports systemd Linux only")]
    SystemdNotSupported,

    /// CPU architecture is not supported.
    #[error("unsupported target platform: Linux x86_64 or aarch64 required")]
    UnsupportedArchitecture,

    /// Existing installation uses a different root domain and change was not confirmed.
    #[error(
        "already installed for domain '{existing}', but target is '{target}'; confirmation required"
    )]
    DomainMismatch { existing: String, target: String },

    /// Apex domain resolved to zero IP addresses.
    #[error("DNS resolution failed for '{0}': no A or AAAA records found")]
    DnsEmpty(String),

    /// Apex and probe subdomain resolved to mismatched sets of IP addresses.
    #[error("DNS mismatch: '{root}' and '{probe}' resolve to different IP address sets")]
    DnsSetMismatch { root: String, probe: String },

    /// Resolved IP address is not a publicly routable IP.
    #[error("DNS resolved to non-public IP address {0}; public DNS records are required")]
    NonPublicIp(IpAddr),

    /// Inbound traffic on port 80 failed to reach our own listener.
    #[error("port 80 reachability check failed: {0}")]
    Port80NotReachable(String),

    /// Inbound traffic on port 443 failed to reach our own listener.
    #[error("port 443 reachability check failed: {0}")]
    Port443NotReachable(String),
}

/// Concrete execution plan approved by the planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Approved root domain.
    pub root_domain: String,
    /// Database path to open and configure.
    pub db_path: String,
    /// System service user.
    pub user: String,
    /// Binary install directory prefix.
    pub prefix: String,
    /// ACME provider identifier.
    pub acme_provider: String,
    /// Whether EAB registration is included.
    pub has_eab: bool,
    /// Whether this setup run updates an existing installation.
    pub is_upgrade: bool,
    /// Whether connect-back reachability checks were bypassed.
    pub reachability_skipped: bool,
}

/// Evaluates a system probe and produces an execution plan or an abort error.
pub fn plan_setup(probe: &SystemProbe) -> Result<Plan, PlanAbort> {
    // 1. Preflight: systemd support
    if !probe.systemd_present {
        return Err(PlanAbort::SystemdNotSupported);
    }

    // 2. Preflight: CPU architecture
    if !probe.supported_arch {
        return Err(PlanAbort::UnsupportedArchitecture);
    }

    // 3. Existing installation domain check
    let mut is_upgrade = false;
    if let Some(existing) = &probe.existing_install {
        is_upgrade = true;
        if existing.root_domain != probe.target_domain
            && !probe.is_headless
            && !probe.confirmed_domain_change
        {
            return Err(PlanAbort::DomainMismatch {
                existing: existing.root_domain.clone(),
                target: probe.target_domain.clone(),
            });
        }
    }

    // 4. DNS check: non-empty
    if probe.root_ips.is_empty() {
        return Err(PlanAbort::DnsEmpty(probe.target_domain.clone()));
    }

    // 5. DNS check: root and probe IPs must match
    let root_set: BTreeSet<IpAddr> = probe.root_ips.iter().copied().collect();
    let probe_set: BTreeSet<IpAddr> = probe.probe_ips.iter().copied().collect();
    if root_set != probe_set {
        return Err(PlanAbort::DnsSetMismatch {
            root: probe.target_domain.clone(),
            probe: format!("probe.<random>.{}", probe.target_domain),
        });
    }

    // 6. DNS check: every resolved IP must be public
    for ip in &root_set {
        if !is_public_ip(ip) {
            return Err(PlanAbort::NonPublicIp(*ip));
        }
    }

    // 7. Reachability checks: both 80 and 443 are mandatory unless skipped
    if !probe.skip_reachability_check {
        match &probe.port_80 {
            PortReachability::ReachedSelf => {}
            PortReachability::Failed(reason) => {
                return Err(PlanAbort::Port80NotReachable(reason.clone()));
            }
            PortReachability::Skipped => {
                return Err(PlanAbort::Port80NotReachable(
                    "reachability was not performed".into(),
                ));
            }
        }

        match &probe.port_443 {
            PortReachability::ReachedSelf => {}
            PortReachability::Failed(reason) => {
                return Err(PlanAbort::Port443NotReachable(reason.clone()));
            }
            PortReachability::Skipped => {
                return Err(PlanAbort::Port443NotReachable(
                    "reachability was not performed".into(),
                ));
            }
        }
    }

    Ok(Plan {
        root_domain: probe.target_domain.clone(),
        db_path: probe.db_path.clone(),
        user: probe.user.clone(),
        prefix: probe.prefix.clone(),
        acme_provider: probe.acme_provider.clone(),
        has_eab: probe.has_eab,
        is_upgrade,
        reachability_skipped: probe.skip_reachability_check,
    })
}
