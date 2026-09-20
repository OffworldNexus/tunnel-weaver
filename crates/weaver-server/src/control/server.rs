use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::protocol::{
    BackupResponse, CertDetailResponse, CertEventSummary, CertListResponse, CertSummary,
    CertWaitEvent, ControlRequest, ErrorResponse, ListenersInfo, RenewResponse, ShutdownResponse,
    StatusResponse,
};
use crate::cert::{CertManager, CertState};
use crate::config::Config;
use crate::store::Store;

/// Binds the UNIX domain control socket listener, creates parent directories,
/// sets permissions to mode 0660, and changes group to `weaver` if available.
pub fn bind_control_listener(socket_path: &Path) -> Result<UnixListener, std::io::Error> {
    // 1. Create parent directory if missing
    if let Some(parent) = socket_path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)?;
    }

    // 2. Unlink stale socket file if present
    if socket_path.exists() {
        let _ = std::fs::remove_file(socket_path);
    }

    // 3. Bind UnixListener
    let listener = UnixListener::bind(socket_path)?;

    // 4. Set socket file permissions to 0660
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(socket_path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o660);
            if let Err(err) = std::fs::set_permissions(socket_path, perms) {
                warn!(error = %err, path = %socket_path.display(), "Failed to set control socket mode 0660");
            }
        }

        // 5. Change socket group to 'weaver' if group exists
        use std::ffi::CString;
        let gr = unsafe { libc::getgrnam(c"weaver".as_ptr()) };
        if !gr.is_null() {
            let gid = unsafe { (*gr).gr_gid };
            if let Ok(c_path) = CString::new(socket_path.to_string_lossy().as_bytes()) {
                let res = unsafe { libc::chown(c_path.as_ptr(), u32::MAX, gid) };
                if res != 0 {
                    warn!(
                        path = %socket_path.display(),
                        errno = std::io::Error::last_os_error().raw_os_error(),
                        "Failed to chown control socket to group 'weaver'"
                    );
                }
            }
        } else {
            warn!("Group 'weaver' not found on system; proceeding with default group");
        }
    }

    info!(path = %socket_path.display(), "Control socket listener active");
    Ok(listener)
}

/// Runs the control server given an already-bound `UnixListener`.
pub async fn run_control_server_with_listener(
    listener: UnixListener,
    socket_path: PathBuf,
    config: Arc<Config>,
    store: Arc<Store>,
    cert_manager: Arc<CertManager>,
    start_time: Instant,
    shutdown_token: CancellationToken,
) -> Result<(), std::io::Error> {
    loop {
        tokio::select! {
            _ = shutdown_token.cancelled() => {
                debug!("Control socket listener stopping on cancellation");
                break;
            }
            res = listener.accept() => {
                match res {
                    Ok((stream, _)) => {
                        let config = Arc::clone(&config);
                        let store = Arc::clone(&store);
                        let cert_manager = Arc::clone(&cert_manager);
                        let shutdown_token = shutdown_token.clone();

                        tokio::spawn(async move {
                            if let Err(err) = handle_connection(
                                stream,
                                config,
                                store,
                                cert_manager,
                                start_time,
                                shutdown_token,
                            ).await {
                                debug!(error = %err, "Control socket connection handler terminated");
                            }
                        });
                    }
                    Err(err) => {
                        warn!(error = %err, "Control socket accept error");
                    }
                }
            }
        }
    }

    // Cleanup socket file on exit
    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

/// Binds and runs the UNIX domain control socket listener until cancelled by `shutdown_token`.
pub async fn run_control_server(
    socket_path: PathBuf,
    config: Arc<Config>,
    store: Arc<Store>,
    cert_manager: Arc<CertManager>,
    start_time: Instant,
    shutdown_token: CancellationToken,
) -> Result<(), std::io::Error> {
    let listener = bind_control_listener(&socket_path)?;
    run_control_server_with_listener(
        listener,
        socket_path,
        config,
        store,
        cert_manager,
        start_time,
        shutdown_token,
    )
    .await
}

/// Handles a single control socket connection: reads one JSON request, dispatches it, and writes response.
async fn handle_connection(
    mut stream: UnixStream,
    config: Arc<Config>,
    store: Arc<Store>,
    cert_manager: Arc<CertManager>,
    start_time: Instant,
    shutdown_token: CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = stream.split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    let bytes_read = buf_reader.read_line(&mut line).await?;
    if bytes_read == 0 {
        return Ok(());
    }

    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }

    // 1. Parse JSON value
    let val: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => {
            let resp = ErrorResponse::new("Malformed JSON request");
            let mut data = serde_json::to_vec(&resp)?;
            data.push(b'\n');
            writer.write_all(&data).await?;
            writer.flush().await?;
            return Ok(());
        }
    };

    // 2. Validate version envelope `{"v": 1, "cmd": ...}`
    let v = val.get("v").and_then(|v| v.as_u64());
    if v != Some(1) {
        let resp = ErrorResponse::new("Unsupported protocol version: expected 1");
        let mut data = serde_json::to_vec(&resp)?;
        data.push(b'\n');
        writer.write_all(&data).await?;
        writer.flush().await?;
        return Ok(());
    }

    let cmd = match val.get("cmd").and_then(|c| c.as_str()) {
        Some(c) => c,
        None => {
            let resp = ErrorResponse::new("Missing or invalid 'cmd' field");
            let mut data = serde_json::to_vec(&resp)?;
            data.push(b'\n');
            writer.write_all(&data).await?;
            writer.flush().await?;
            return Ok(());
        }
    };

    // 3. Strict 6-verb dispatcher check
    const ALLOWED_VERBS: &[&str] = &[
        "status",
        "cert.status",
        "cert.wait",
        "cert.renew",
        "backup",
        "shutdown",
    ];

    if !ALLOWED_VERBS.contains(&cmd) {
        let resp = ErrorResponse::new(format!("Unknown command '{cmd}'"));
        let mut data = serde_json::to_vec(&resp)?;
        data.push(b'\n');
        writer.write_all(&data).await?;
        writer.flush().await?;
        return Ok(());
    }

    let req: ControlRequest = match serde_json::from_value(val) {
        Ok(r) => r,
        Err(err) => {
            let resp = ErrorResponse::new(format!("Invalid request format: {err}"));
            let mut data = serde_json::to_vec(&resp)?;
            data.push(b'\n');
            writer.write_all(&data).await?;
            writer.flush().await?;
            return Ok(());
        }
    };

    // 4. Dispatch the command
    match req.cmd.as_str() {
        "status" => {
            let uptime = start_time.elapsed().as_secs();
            let pid = std::process::id();
            let root_domain = config.root_domain.clone();
            let listeners = ListenersInfo {
                http: config.listen_http.to_string(),
                https: config.listen_https.to_string(),
            };
            let root_cert = cert_manager.root_cert_status().to_string();
            let cert_counts = cert_manager.cert_counts().await;
            let db_path = store
                .path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| store.url().to_string());
            let db_size = store
                .path()
                .and_then(|p| std::fs::metadata(p).ok())
                .map(|m| m.len())
                .unwrap_or(0);
            let schema_version = store.schema_version().await.unwrap_or(0);

            let resp = StatusResponse {
                ok: true,
                version: env!("CARGO_PKG_VERSION").to_string(),
                uptime,
                pid,
                root_domain,
                listeners,
                root_cert,
                cert_counts,
                db_path,
                db_size,
                schema_version,
                control_socket: config.control_socket.display().to_string(),
            };

            let mut data = serde_json::to_vec(&resp)?;
            data.push(b'\n');
            writer.write_all(&data).await?;
            writer.flush().await?;
        }
        "cert.status" => {
            let root_domain = config.root_domain.to_ascii_lowercase();
            match req.name {
                None => {
                    // Summary list of all certificates
                    let mut names = std::collections::BTreeSet::new();
                    names.insert(root_domain.clone());

                    if let Ok(records) = store.list_certificates().await {
                        for r in records {
                            names.insert(r.name.to_ascii_lowercase());
                        }
                    }
                    for n in cert_manager.list_states().keys() {
                        names.insert(n.to_ascii_lowercase());
                    }

                    // Order root first, then remaining alphabetically
                    let mut ordered_names = Vec::with_capacity(names.len());
                    ordered_names.push(root_domain.clone());
                    for n in names {
                        if n != root_domain {
                            ordered_names.push(n);
                        }
                    }

                    let mut summaries = Vec::with_capacity(ordered_names.len());
                    for name in ordered_names {
                        let state = cert_manager.status(&name).label().to_string();
                        let cert_rec = store.get_certificate(&name).await.ok().flatten();
                        let not_after = cert_rec
                            .as_ref()
                            .map(|c| c.not_after)
                            .or_else(|| cert_manager.status(&name).not_after());
                        let active = cert_manager.is_active(&name);
                        let last_event = store
                            .get_latest_cert_event(&name)
                            .await
                            .ok()
                            .flatten()
                            .map(|e| CertEventSummary {
                                id: e.id,
                                at: e.at,
                                kind: e.kind,
                                detail: e.detail,
                            });

                        summaries.push(CertSummary {
                            name,
                            state,
                            not_after,
                            active,
                            last_event,
                        });
                    }

                    let resp = CertListResponse {
                        ok: true,
                        certificates: summaries,
                    };
                    let mut data = serde_json::to_vec(&resp)?;
                    data.push(b'\n');
                    writer.write_all(&data).await?;
                    writer.flush().await?;
                }
                Some(name) => {
                    let target = if name == "root" {
                        root_domain.clone()
                    } else {
                        name.to_ascii_lowercase()
                    };

                    let cert_rec = store.get_certificate(&target).await.ok().flatten();
                    let in_states = cert_manager.list_states().contains_key(&target);

                    if target != root_domain && cert_rec.is_none() && !in_states {
                        let resp = ErrorResponse::new(format!(
                            "Certificate for hostname '{target}' not found"
                        ));
                        let mut data = serde_json::to_vec(&resp)?;
                        data.push(b'\n');
                        writer.write_all(&data).await?;
                        writer.flush().await?;
                        return Ok(());
                    }

                    let limit = req.limit.unwrap_or(10);
                    let cert_events = store
                        .get_cert_events(&target, limit)
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .map(|e| CertEventSummary {
                            id: e.id,
                            at: e.at,
                            kind: e.kind,
                            detail: e.detail,
                        })
                        .collect();

                    let state = cert_manager.status(&target);
                    let not_before = cert_rec.as_ref().map(|r| r.not_before);
                    let not_after = cert_rec
                        .as_ref()
                        .map(|r| r.not_after)
                        .or_else(|| state.not_after());
                    let issuer = cert_rec.as_ref().and_then(|r| r.issuer.clone());
                    let provider = cert_rec
                        .as_ref()
                        .map(|r| r.directory.clone())
                        .unwrap_or_else(|| config.acme_provider.clone());
                    let active = cert_manager.is_active(&target);
                    let last_active_at = cert_rec.as_ref().and_then(|r| r.last_active_at);

                    let resp = CertDetailResponse {
                        ok: true,
                        name: target,
                        state,
                        not_before,
                        not_after,
                        issuer,
                        provider,
                        active,
                        last_active_at,
                        cert_events,
                    };
                    let mut data = serde_json::to_vec(&resp)?;
                    data.push(b'\n');
                    writer.write_all(&data).await?;
                    writer.flush().await?;
                }
            }
        }
        "cert.wait" => {
            let root_domain = config.root_domain.to_ascii_lowercase();
            let target = match req.name.as_deref() {
                Some("root") | None => root_domain.clone(),
                Some(n) => n.to_ascii_lowercase(),
            };

            // Verify requested hostname is in the certificate store
            let is_root = target == root_domain;
            let exists = is_root
                || cert_manager.list_states().contains_key(&target)
                || store
                    .get_certificate(&target)
                    .await
                    .map(|opt| opt.is_some())
                    .unwrap_or(false);

            if !exists {
                let resp = ErrorResponse::new(format!(
                    "Hostname '{target}' not found in certificate store"
                ));
                let mut data = serde_json::to_vec(&resp)?;
                data.push(b'\n');
                writer.write_all(&data).await?;
                writer.flush().await?;
                return Ok(());
            }

            let mut rx = cert_manager.subscribe_state_changes();
            let timeout_dur = Duration::from_secs(req.timeout_s.unwrap_or(300));
            let start = Instant::now();

            // Emit current initial state
            let initial_state = cert_manager.status(&target);
            let init_event = CertWaitEvent {
                ok: true,
                name: target.clone(),
                state: initial_state.label().to_string(),
                not_after: initial_state.not_after(),
                error: match &initial_state {
                    CertState::Failed { error, .. } => Some(error.clone()),
                    _ => None,
                },
            };
            let mut data = serde_json::to_vec(&init_event)?;
            data.push(b'\n');
            writer.write_all(&data).await?;
            writer.flush().await?;

            // If initial state is already terminal, finish immediately
            if matches!(
                initial_state,
                CertState::Issued { .. } | CertState::Failed { .. }
            ) {
                return Ok(());
            }

            // Stream state transitions until terminal state or timeout
            loop {
                let elapsed = start.elapsed();
                if elapsed >= timeout_dur {
                    let resp =
                        ErrorResponse::new("Timed out waiting for certificate state transition");
                    let mut data = serde_json::to_vec(&resp)?;
                    data.push(b'\n');
                    writer.write_all(&data).await?;
                    writer.flush().await?;
                    break;
                }

                let remaining = timeout_dur - elapsed;
                match tokio::time::timeout(remaining, rx.recv()).await {
                    Ok(Ok((name, state))) => {
                        if name == target {
                            let event = CertWaitEvent {
                                ok: true,
                                name: target.clone(),
                                state: state.label().to_string(),
                                not_after: state.not_after(),
                                error: match &state {
                                    CertState::Failed { error, .. } => Some(error.clone()),
                                    _ => None,
                                },
                            };
                            let mut data = serde_json::to_vec(&event)?;
                            data.push(b'\n');
                            writer.write_all(&data).await?;
                            writer.flush().await?;

                            if matches!(state, CertState::Issued { .. } | CertState::Failed { .. })
                            {
                                break;
                            }
                        }
                    }
                    Ok(Err(_)) => {
                        // Channel lagged or closed
                        break;
                    }
                    Err(_) => {
                        let resp = ErrorResponse::new(
                            "Timed out waiting for certificate state transition",
                        );
                        let mut data = serde_json::to_vec(&resp)?;
                        data.push(b'\n');
                        writer.write_all(&data).await?;
                        writer.flush().await?;
                        break;
                    }
                }
            }
        }
        "cert.renew" => {
            let force = req.force.unwrap_or(false);
            if req.all == Some(true) {
                match cert_manager.renew_all(force).await {
                    Ok(resp) => {
                        let mut data = serde_json::to_vec(&resp)?;
                        data.push(b'\n');
                        writer.write_all(&data).await?;
                        writer.flush().await?;
                    }
                    Err(err) => {
                        let resp = ErrorResponse::new(err.to_string());
                        let mut data = serde_json::to_vec(&resp)?;
                        data.push(b'\n');
                        writer.write_all(&data).await?;
                        writer.flush().await?;
                    }
                }
            } else {
                let root_domain = config.root_domain.to_ascii_lowercase();
                let target = match req.name.as_deref() {
                    Some("root") | None => root_domain.clone(),
                    Some(n) => n.to_ascii_lowercase(),
                };

                match cert_manager.renew_hostname(&target, force).await {
                    Ok(()) => {
                        let resp = RenewResponse {
                            ok: true,
                            renewed: vec![target],
                            status: "queued".to_string(),
                            skipped_inactive: Vec::new(),
                        };
                        let mut data = serde_json::to_vec(&resp)?;
                        data.push(b'\n');
                        writer.write_all(&data).await?;
                        writer.flush().await?;
                    }
                    Err(err) => {
                        let resp = ErrorResponse::new(err.to_string());
                        let mut data = serde_json::to_vec(&resp)?;
                        data.push(b'\n');
                        writer.write_all(&data).await?;
                        writer.flush().await?;
                    }
                }
            }
        }
        "backup" => {
            let path_str = match req.path {
                Some(p) => p,
                None => {
                    let resp = ErrorResponse::new("Missing target backup path");
                    let mut data = serde_json::to_vec(&resp)?;
                    data.push(b'\n');
                    writer.write_all(&data).await?;
                    writer.flush().await?;
                    return Ok(());
                }
            };

            let backup_path = PathBuf::from(&path_str);
            match store.backup(&backup_path).await {
                Ok(()) => {
                    let size = std::fs::metadata(&backup_path)
                        .map(|m| m.len())
                        .unwrap_or(0);
                    let resp = BackupResponse {
                        ok: true,
                        path: path_str,
                        size,
                    };
                    let mut data = serde_json::to_vec(&resp)?;
                    data.push(b'\n');
                    writer.write_all(&data).await?;
                    writer.flush().await?;
                }
                Err(err) => {
                    let resp = ErrorResponse::new(format!("Backup failed: {err}"));
                    let mut data = serde_json::to_vec(&resp)?;
                    data.push(b'\n');
                    writer.write_all(&data).await?;
                    writer.flush().await?;
                }
            }
        }
        "shutdown" => {
            let resp = ShutdownResponse {
                ok: true,
                message: "Server shutting down".to_string(),
            };
            let mut data = serde_json::to_vec(&resp)?;
            data.push(b'\n');
            writer.write_all(&data).await?;
            writer.flush().await?;

            info!("Control socket received shutdown command, triggering graceful daemon stop");
            shutdown_token.cancel();
        }
        _ => unreachable!(),
    }

    Ok(())
}
