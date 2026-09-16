//! Idempotent host installation for `weaver-server setup`.
//!
//! Handles:
//! - System user creation (`weaver`)
//! - Atomic binary installation to `<prefix>/weaver-server`
//! - State directory permissions (`/var/lib/weaver`, mode 0700)
//! - SQLite database initialization and configuration persistence
//! - Systemd unit deployment (`weaver-server.socket`, `weaver-server.service`)
//! - Service enablement and activation via `systemctl`

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crossterm::style::Stylize;
use sha2::{Digest, Sha256};

use crate::cert::RegisteredAcmeAccount;
use crate::config::Config;
use crate::setup::interactive::GatheredConfig;
use crate::setup::planner::Plan;
use crate::setup::units::{ServiceUnitParams, render_service_unit, render_socket_unit};
use crate::store::Store;

/// Computes the SHA-256 digest of a file.
fn file_sha256(path: &Path) -> Option<[u8; 32]> {
    let data = fs::read(path).ok()?;
    Some(Sha256::digest(&data).into())
}

/// Checks whether a system group exists on Linux.
pub fn group_exists(groupname: &str) -> bool {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        if let Ok(c_grp) = CString::new(groupname) {
            let grp = unsafe { libc::getgrnam(c_grp.as_ptr()) };
            return !grp.is_null();
        }
    }
    false
}

/// Checks whether a system user exists on Linux.
pub fn user_exists(username: &str) -> bool {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        if let Ok(c_user) = CString::new(username) {
            let pwd = unsafe { libc::getpwnam(c_user.as_ptr()) };
            return !pwd.is_null();
        }
    }
    false
}

/// Looks up the UID and GID for a given username.
pub fn get_user_uid_gid(username: &str) -> Option<(u32, u32)> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        let c_user = CString::new(username).ok()?;
        let pwd = unsafe { libc::getpwnam(c_user.as_ptr()) };
        if !pwd.is_null() {
            unsafe { return Some(((*pwd).pw_uid, (*pwd).pw_gid)) };
        }
    }
    None
}

/// Sets file ownership by username.
pub fn chown_path(path: &Path, username: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        if let Some((uid, gid)) = get_user_uid_gid(username) {
            let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            let res = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
            if res != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// Result of an installation execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallResult {
    /// Whether any changes were applied to the host.
    pub changed: bool,
    /// Target binary path.
    pub binary_path: PathBuf,
    /// Database path.
    pub db_path: PathBuf,
}

/// Executes idempotent installation steps according to the plan.
pub fn execute_install(
    plan: &Plan,
    gathered: &GatheredConfig,
    registered_account: Option<&RegisteredAcmeAccount>,
) -> Result<InstallResult, String> {
    let mut changed = false;

    println!("\n{}", "Executing installation...".bold().cyan());

    // 1. System group and user creation
    if !group_exists(&plan.user) {
        println!("  {} Creating system group '{}'...", "•".blue(), plan.user);
        let _ = Command::new("groupadd")
            .args(["--system", &plan.user])
            .status();
        changed = true;
    }

    if !user_exists(&plan.user) {
        println!("  {} Creating system user '{}'...", "•".blue(), plan.user);
        let mut useradd_cmd = Command::new("useradd");
        useradd_cmd.args([
            "--system",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
        ]);
        if group_exists(&plan.user) {
            useradd_cmd.args(["-g", &plan.user]);
        }
        useradd_cmd.arg(&plan.user);

        let status = useradd_cmd
            .status()
            .map_err(|e| format!("failed to execute useradd: {e}"))?;

        if !status.success() {
            return Err(format!(
                "useradd failed with exit code: {:?}",
                status.code()
            ));
        }
        changed = true;
        println!(
            "  {} System user and group '{}' configured",
            "✓".green(),
            plan.user
        );
    } else {
        println!("  {} System user '{}' already exists", "•".dim(), plan.user);
    }

    // 2. Binary installation
    let current_exe =
        std::env::current_exe().map_err(|e| format!("cannot determine current exe: {e}"))?;
    let target_bin_dir = Path::new(&plan.prefix);
    fs::create_dir_all(target_bin_dir)
        .map_err(|e| format!("failed to create prefix directory: {e}"))?;

    let target_binary = target_bin_dir.join("weaver-server");
    let current_hash = file_sha256(&current_exe);
    let target_hash = file_sha256(&target_binary);

    if current_hash != target_hash || target_hash.is_none() {
        println!(
            "  {} Installing binary to {}...",
            "•".blue(),
            target_binary.display()
        );
        let tmp_binary = target_bin_dir.join(format!("weaver-server.tmp.{}", std::process::id()));
        fs::copy(&current_exe, &tmp_binary)
            .map_err(|e| format!("failed to copy binary to temp path: {e}"))?;

        let mut perms = fs::metadata(&tmp_binary)
            .map_err(|e| format!("failed to read metadata: {e}"))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&tmp_binary, perms)
            .map_err(|e| format!("failed to set binary permissions: {e}"))?;

        let _ = chown_path(&tmp_binary, "root");

        fs::rename(&tmp_binary, &target_binary)
            .map_err(|e| format!("failed to rename binary atomically: {e}"))?;

        changed = true;
        println!("  {} Binary installed (mode 0755)", "✓".green());
    } else {
        println!("  {} Binary is already up to date", "•".dim());
    }

    // 3. State directory
    let db_path = PathBuf::from(&plan.db_path);
    let state_dir = db_path
        .parent()
        .unwrap_or_else(|| Path::new("/var/lib/weaver"));

    if !state_dir.exists() {
        println!(
            "  {} Creating state directory {}...",
            "•".blue(),
            state_dir.display()
        );
        fs::create_dir_all(state_dir)
            .map_err(|e| format!("failed to create state directory: {e}"))?;

        let mut perms = fs::metadata(state_dir)
            .map_err(|e| format!("failed to read state dir metadata: {e}"))?
            .permissions();
        perms.set_mode(0o700);
        fs::set_permissions(state_dir, perms)
            .map_err(|e| format!("failed to set state dir permissions: {e}"))?;

        let _ = chown_path(state_dir, &plan.user);
        changed = true;
        println!("  {} State directory configured (mode 0700)", "✓".green());
    } else {
        let _ = chown_path(state_dir, &plan.user);
    }

    // 4. Temporarily stop service if running to apply database changes
    let service_was_active = Command::new("systemctl")
        .args(["is-active", "--quiet", "weaver-server.service"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if service_was_active {
        println!(
            "  {} Stopping weaver-server.service for update...",
            "•".blue()
        );
        let _ = Command::new("systemctl")
            .args(["stop", "weaver-server.service"])
            .status();
    }

    // 5. Open SQLite store and persist configuration
    println!(
        "  {} Initializing database and configuration...",
        "•".blue()
    );
    let store = Store::open(&db_path).map_err(|e| format!("failed to open database: {e}"))?;

    let root_ca_pem = match &gathered.acme_root_ca_path {
        Some(path) => match fs::read_to_string(path) {
            Ok(content) => Some(content),
            Err(err) => {
                return Err(format!(
                    "failed to read root CA at {}: {err}",
                    path.display()
                ));
            }
        },
        None => None,
    };

    let config = Config {
        root_domain: gathered.root_domain.clone(),
        admin_email: gathered.admin_email.clone(),
        acme_provider: gathered.acme_provider.clone(),
        listen_http: "[::]:80".parse().unwrap(),
        listen_https: "[::]:443".parse().unwrap(),
        control_socket: "/run/weaver/control.sock".into(),
        acme_directory: gathered.acme_directory.clone(),
        acme_eab_kid: gathered.acme_eab_kid.clone(),
        acme_eab_hmac: gathered.acme_eab_hmac.clone(),
        acme_root_ca_pem: root_ca_pem,
        acme_fallback_providers: Vec::new(),
    };

    store
        .save_config(&config)
        .map_err(|e| format!("failed to save config: {e}"))?;

    if let Some(acct) = registered_account {
        let dir_url = config.acme_directory.clone().unwrap_or_else(|| {
            crate::cert::providers::resolve_directory_url(&config.acme_provider, None)
                .unwrap()
                .to_string()
        });

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        store
            .write(|conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO acme_account (directory, email, key_pem, kid, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        dir_url,
                        config.admin_email,
                        acct.creds_json,
                        acct.kid,
                        now,
                    ],
                )?;
                Ok(())
            })
            .map_err(|e| format!("failed to store pre-registered ACME credentials: {e}"))?;
    }

    // Set state directory and DB file ownership to weaver user
    let _ = chown_path(&db_path, &plan.user);
    if let Ok(entries) = fs::read_dir(state_dir) {
        for entry in entries.flatten() {
            let _ = chown_path(&entry.path(), &plan.user);
        }
    }
    let _ = chown_path(state_dir, &plan.user);

    // 6. Systemd unit deployment
    let socket_path = Path::new("/etc/systemd/system/weaver-server.socket");
    let service_path = Path::new("/etc/systemd/system/weaver-server.service");

    let socket_content = render_socket_unit();
    let service_params = ServiceUnitParams {
        prefix: &plan.prefix,
        db_path: &plan.db_path,
        user: &plan.user,
    };
    let service_content = render_service_unit(&service_params);

    let socket_changed = fs::read_to_string(socket_path).ok() != Some(socket_content.clone());
    let service_changed = fs::read_to_string(service_path).ok() != Some(service_content.clone());

    if socket_changed || service_changed {
        println!("  {} Writing systemd unit files...", "•".blue());
        fs::write(socket_path, &socket_content)
            .map_err(|e| format!("failed to write socket unit: {e}"))?;
        fs::write(service_path, &service_content)
            .map_err(|e| format!("failed to write service unit: {e}"))?;

        let _ = Command::new("systemctl").arg("daemon-reload").status();
        changed = true;
        println!("  {} Systemd units written and reloaded", "✓".green());
    } else {
        println!("  {} Systemd units already up to date", "•".dim());
    }

    // 7. Enable and start units
    println!("  {} Enabling and starting systemd services...", "•".blue());
    let status = Command::new("systemctl")
        .args([
            "enable",
            "--now",
            "weaver-server.socket",
            "weaver-server.service",
        ])
        .status()
        .map_err(|e| format!("failed to enable and start services: {e}"))?;

    if !status.success() {
        return Err("failed to start weaver-server services".into());
    }

    println!("  {} Sockets and services activated", "✓".green());

    Ok(InstallResult {
        changed,
        binary_path: target_binary,
        db_path,
    })
}
