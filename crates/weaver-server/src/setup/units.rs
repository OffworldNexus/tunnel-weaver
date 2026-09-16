//! Embedded systemd unit file templates and rendering helpers.
//!
//! Provides templates for `weaver-server.socket` and `weaver-server.service`.
//! The socket unit binds ports 80 and 443 with systemd ownership so the service
//! process runs without requiring privileged net bind capabilities.

/// Static content of the `weaver-server.socket` unit.
pub const SOCKET_UNIT_TEMPLATE: &str = r#"# weaver-server.socket — systemd owns the ports; the service never needs capabilities
[Unit]
Description=Tunnel Weaver relay sockets

[Socket]
ListenStream=[::]:80
ListenStream=[::]:443
BindIPv6Only=both
NoDelay=true
Backlog=1024
Service=weaver-server.service

[Install]
WantedBy=sockets.target
"#;

/// Renders the `weaver-server.socket` unit content.
pub fn render_socket_unit() -> String {
    SOCKET_UNIT_TEMPLATE.to_string()
}

/// Parameters for rendering the `weaver-server.service` systemd unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceUnitParams<'a> {
    /// Installation directory prefix where the `weaver-server` binary resides.
    pub prefix: &'a str,
    /// Path to the SQLite state database.
    pub db_path: &'a str,
    /// Dedicated system user and group name under which the service executes.
    pub user: &'a str,
}

impl Default for ServiceUnitParams<'static> {
    fn default() -> Self {
        Self {
            prefix: "/usr/local/bin",
            db_path: "/var/lib/weaver/weaver.db",
            user: "weaver",
        }
    }
}

/// Renders the `weaver-server.service` unit using the provided parameters.
pub fn render_service_unit(params: &ServiceUnitParams<'_>) -> String {
    let prefix = params.prefix.trim_end_matches('/');
    let db = params.db_path;
    let user = params.user;

    format!(
        r#"# weaver-server.service
[Unit]
Description=Tunnel Weaver relay
Requires=weaver-server.socket
After=network-online.target weaver-server.socket
Wants=network-online.target

[Service]
Type=notify
User={user}
Group={user}
ExecStart={prefix}/weaver-server run --db {db}
Restart=always
RestartSec=2
RuntimeDirectory=weaver
RuntimeDirectoryMode=0750
StateDirectory=weaver
CapabilityBoundingSet=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallArchitectures=native
ReadWritePaths=/var/lib/weaver
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"#
    )
}
