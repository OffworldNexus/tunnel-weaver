//! Table-driven unit tests for the pure setup execution planner.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use weaver_server::setup::planner::{
    ExistingInstall, PlanAbort, PortReachability, SystemProbe, plan_setup,
};

fn base_probe() -> SystemProbe {
    SystemProbe {
        systemd_present: true,
        supported_arch: true,
        target_domain: "example.com".into(),
        existing_install: None,
        root_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        probe_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        port_80: PortReachability::ReachedSelf,
        port_443: PortReachability::ReachedSelf,
        is_headless: false,
        confirmed_domain_change: false,
        skip_reachability_check: false,
        db_path: "/var/lib/weaver/weaver.db".into(),
        user: "weaver".into(),
        prefix: "/usr/local/bin".into(),
        acme_provider: "letsencrypt".into(),
        has_eab: false,
    }
}

#[test]
fn test_happy_path_fresh_install() {
    let probe = base_probe();
    let plan = plan_setup(&probe).expect("happy path should succeed");
    assert_eq!(plan.root_domain, "example.com");
    assert!(!plan.is_upgrade);
    assert!(!plan.reachability_skipped);
}

// OFF-73: Unsupported host environment preflight — halts setup planning when systemd
// runtime (/run/systemd/system) or supported CPU architecture is absent.
#[test]
fn test_systemd_missing_aborts() {
    let mut probe = base_probe();
    probe.systemd_present = false;
    let err = plan_setup(&probe).unwrap_err();
    assert_eq!(err, PlanAbort::SystemdNotSupported);
    assert_eq!(
        err.to_string(),
        "the server component supports systemd Linux only"
    );
}

#[test]
fn test_unsupported_arch_aborts() {
    let mut probe = base_probe();
    probe.supported_arch = false;
    let err = plan_setup(&probe).unwrap_err();
    assert_eq!(err, PlanAbort::UnsupportedArchitecture);
    assert_eq!(
        err.to_string(),
        "unsupported target platform: Linux x86_64 or aarch64 required"
    );
}

#[test]
fn test_existing_install_same_domain_succeeds_as_upgrade() {
    let mut probe = base_probe();
    probe.existing_install = Some(ExistingInstall {
        root_domain: "example.com".into(),
    });
    let plan = plan_setup(&probe).expect("reinstalling same domain should succeed");
    assert!(plan.is_upgrade);
}

// OFF-73: Conflicting existing installation protection — detects existing installation
// with a different root domain and aborts interactive setup unless confirmed.
#[test]
fn test_existing_install_different_domain_unconfirmed_aborts() {
    let mut probe = base_probe();
    probe.existing_install = Some(ExistingInstall {
        root_domain: "old.com".into(),
    });
    probe.is_headless = false;
    probe.confirmed_domain_change = false;
    let err = plan_setup(&probe).unwrap_err();
    assert!(matches!(err, PlanAbort::DomainMismatch { .. }));
    assert!(
        err.to_string()
            .contains("already installed for domain 'old.com'")
    );
    assert!(err.to_string().contains("target is 'example.com'"));
}

#[test]
fn test_existing_install_different_domain_headless_succeeds() {
    let mut probe = base_probe();
    probe.existing_install = Some(ExistingInstall {
        root_domain: "old.com".into(),
    });
    probe.is_headless = true;
    let plan = plan_setup(&probe).expect("headless mode confirms domain upgrade");
    assert!(plan.is_upgrade);
}

#[test]
fn test_existing_install_different_domain_confirmed_succeeds() {
    let mut probe = base_probe();
    probe.existing_install = Some(ExistingInstall {
        root_domain: "old.com".into(),
    });
    probe.confirmed_domain_change = true;
    let plan = plan_setup(&probe).expect("confirmed domain upgrade succeeds");
    assert!(plan.is_upgrade);
}

#[test]
fn test_dns_empty_aborts() {
    let mut probe = base_probe();
    probe.root_ips = vec![];
    let err = plan_setup(&probe).unwrap_err();
    assert!(matches!(err, PlanAbort::DnsEmpty(_)));
}

#[test]
fn test_dns_mismatch_aborts() {
    let mut probe = base_probe();
    probe.root_ips = vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))];
    probe.probe_ips = vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35))];
    let err = plan_setup(&probe).unwrap_err();
    assert!(matches!(err, PlanAbort::DnsSetMismatch { .. }));
}

// OFF-73: Public IP and DNS consistency enforcement — rejects non-public IP ranges
// (RFC1918, loopback, CGNAT, link-local, documentation, benchmarking, ULA) to prevent SSRF.
#[test]
fn test_dns_non_public_ip_aborts() {
    let non_public_ips = vec![
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V6("fc00::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("fd00::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("fe80::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("::ffff:192.168.1.1".parse::<Ipv6Addr>().unwrap()),
    ];

    for ip in non_public_ips {
        let mut probe = base_probe();
        probe.root_ips = vec![ip];
        probe.probe_ips = vec![ip];
        let err = plan_setup(&probe).unwrap_err();
        assert_eq!(err, PlanAbort::NonPublicIp(ip));
        assert!(
            err.to_string()
                .contains("DNS resolved to non-public IP address")
        );
    }
}

// OFF-73: Inbound port blockage abort — detects when port 80 or 443 fails to route back
// to self and halts setup before requesting certificates or writing units, unless bypassed.
#[test]
fn test_port_80_blocked_aborts() {
    let mut probe = base_probe();
    probe.port_80 = PortReachability::Failed("connection timed out".into());
    let err = plan_setup(&probe).unwrap_err();
    assert!(matches!(err, PlanAbort::Port80NotReachable(_)));
    assert!(
        err.to_string()
            .contains("port 80 reachability check failed: connection timed out")
    );
}

#[test]
fn test_port_443_blocked_aborts() {
    let mut probe = base_probe();
    probe.port_443 = PortReachability::Failed("connection refused".into());
    let err = plan_setup(&probe).unwrap_err();
    assert!(matches!(err, PlanAbort::Port443NotReachable(_)));
    assert!(
        err.to_string()
            .contains("port 443 reachability check failed: connection refused")
    );
}

#[test]
fn test_skip_reachability_allows_blocked_ports() {
    let mut probe = base_probe();
    probe.skip_reachability_check = true;
    probe.port_80 = PortReachability::Failed("blocked".into());
    probe.port_443 = PortReachability::Failed("blocked".into());
    let plan = plan_setup(&probe).expect("skip reachability should bypass port checks");
    assert!(plan.reachability_skipped);
}
