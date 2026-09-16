//! Golden file tests asserting byte-identical rendering of systemd units.

use weaver_server::setup::units::{ServiceUnitParams, render_service_unit, render_socket_unit};

#[test]
fn test_socket_unit_golden_match() {
    let rendered = render_socket_unit();
    let golden = include_str!("golden/weaver-server.socket");
    assert_eq!(
        rendered, golden,
        "Rendered weaver-server.socket does not match golden file"
    );
}

#[test]
fn test_service_unit_golden_match() {
    let params = ServiceUnitParams {
        prefix: "/usr/local/bin",
        db_path: "/var/lib/weaver/weaver.db",
        user: "weaver",
    };
    let rendered = render_service_unit(&params);
    let golden = include_str!("golden/weaver-server.service");
    assert_eq!(
        rendered, golden,
        "Rendered weaver-server.service does not match golden file"
    );

    // OFF-73: Sandboxed systemd privilege isolation — unit templates enforce minimal privilege
    // boundaries (weaver user, empty capability sets, strict filesystem isolation, restricted runtime directory).
    assert!(rendered.contains("User=weaver"));
    assert!(rendered.contains("Group=weaver"));
    assert!(rendered.contains("RuntimeDirectoryMode=0750"));
    assert!(rendered.contains("CapabilityBoundingSet="));
    assert!(rendered.contains("NoNewPrivileges=yes"));
    assert!(rendered.contains("ProtectSystem=strict"));
    assert!(rendered.contains("ProtectHome=yes"));
    assert!(rendered.contains("PrivateTmp=yes"));
    assert!(rendered.contains("PrivateDevices=yes"));
    assert!(rendered.contains("MemoryDenyWriteExecute=yes"));
    assert!(rendered.contains("SystemCallFilter=@system-service"));
    assert!(rendered.contains("ReadWritePaths=/var/lib/weaver"));
}
