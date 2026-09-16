//! Host setup, preflight checks, systemd management, reachability probes, and uninstallation.

pub mod dns;
pub mod install;
pub mod interactive;
pub mod planner;
pub mod preflight;
pub mod privilege;
pub mod reachability;
pub mod uninstall;
pub mod units;
pub mod verify;
