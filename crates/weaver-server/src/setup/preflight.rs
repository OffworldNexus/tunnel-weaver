//! Preflight checks for host environment validation.
//!
//! Validates:
//! - Systemd environment (`/run/systemd/system` and `systemctl` on PATH)
//! - CPU architecture (Linux x86_64 or aarch64)
//! - Existing installation state and configured root domain

use std::path::Path;

use crate::setup::planner::ExistingInstall;
use crate::store::Store;

/// Checks whether systemd is the active init system on this host.
pub fn is_systemd_present() -> bool {
    if !Path::new("/run/systemd/system").exists() {
        return false;
    }

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join("systemctl");
            if candidate.is_file() {
                return true;
            }
        }
    }
    false
}

/// Checks whether the running CPU architecture and OS are supported.
pub fn is_supported_arch() -> bool {
    cfg!(target_os = "linux") && (cfg!(target_arch = "x86_64") || cfg!(target_arch = "aarch64"))
}

/// Inspects the target database path to check for an existing installation.
pub async fn detect_existing_install(db_path: &Path) -> Option<ExistingInstall> {
    if !db_path.exists() {
        return None;
    }

    let store = Store::open(db_path).await.ok()?;
    let config = store.load_config().await.ok()?;
    Some(ExistingInstall {
        root_domain: config.root_domain,
    })
}
