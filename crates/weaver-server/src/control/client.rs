use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};
use crossterm::style::Stylize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use super::protocol::{
    BackupResponse, CertDetailResponse, CertListResponse, ControlRequest, RenewResponse,
    StatusResponse,
};
use crate::cert::format_unix_timestamp;

/// Connects to the UNIX domain control socket, printing diagnostic hints on failure.
async fn connect_control_socket(socket_path: &Path) -> Result<UnixStream, i32> {
    match UnixStream::connect(socket_path).await {
        Ok(stream) => Ok(stream),
        Err(err) => match err.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                eprintln!(
                    "Error: Cannot connect to control socket at {}",
                    socket_path.display()
                );
                eprintln!("Hint: systemctl status weaver-server");
                Err(3)
            }
            std::io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "Error: Permission denied connecting to control socket at {}",
                    socket_path.display()
                );
                eprintln!("Hint: run with sudo or join group 'weaver'");
                Err(1)
            }
            _ => {
                eprintln!(
                    "Error: Failed to connect to control socket at {}: {}",
                    socket_path.display(),
                    err
                );
                Err(1)
            }
        },
    }
}

/// Creates a preconfigured `comfy-table` with rounded UTF-8 borders and dynamic layout.
fn create_styled_table() -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);
    table
}

/// Sends a single request across the control socket and reads one line response.
async fn send_request_and_read_line(
    socket_path: &Path,
    req: &ControlRequest,
) -> Result<String, i32> {
    let mut stream = connect_control_socket(socket_path).await?;

    let mut data = match serde_json::to_vec(req) {
        Ok(d) => d,
        Err(err) => {
            eprintln!(
                "{} Failed to serialize request: {err}",
                "✗ Error:".red().bold()
            );
            return Err(1);
        }
    };
    data.push(b'\n');

    if let Err(err) = stream.write_all(&data).await {
        eprintln!(
            "{} Failed to write to control socket: {err}",
            "✗ Error:".red().bold()
        );
        return Err(1);
    }
    if let Err(err) = stream.flush().await {
        eprintln!(
            "{} Failed to flush control socket: {err}",
            "✗ Error:".red().bold()
        );
        return Err(1);
    }

    let (reader, _) = stream.split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    let n = buf_reader.read_line(&mut line).await.map_err(|err| {
        eprintln!(
            "{} Failed to read from control socket: {err}",
            "✗ Error:".red().bold()
        );
        1
    })?;

    if n == 0 {
        eprintln!(
            "{} Control socket closed connection without response",
            "✗ Error:".red().bold()
        );
        return Err(1);
    }

    Ok(line)
}

/// Helper to format byte count into human-readable representation.
fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Helper to format seconds into uptime string.
fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;

    if days > 0 {
        format!("{days}d {hours}h {mins}m {s}s")
    } else if hours > 0 {
        format!("{hours}h {mins}m {s}s")
    } else if mins > 0 {
        format!("{mins}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// Helper to format age in seconds relative to current time.
fn format_age(now: i64, ts: i64) -> String {
    let diff = (now - ts).max(0);
    if diff < 60 {
        format!("{diff}s ago")
    } else if diff < 3600 {
        format!("{}m ago", diff / 60)
    } else if diff < 86400 {
        format!("{}h ago", diff / 3600)
    } else {
        format!("{}d ago", diff / 86400)
    }
}

/// Helper to format a certificate state label into a colored cell.
fn styled_state_cell(state: &str) -> Cell {
    match state {
        "issued" => Cell::new("● issued")
            .fg(Color::Green)
            .add_attribute(Attribute::Bold),
        "ordering" => Cell::new("● ordering")
            .fg(Color::Yellow)
            .add_attribute(Attribute::Bold),
        "renewing" => Cell::new("● renewing")
            .fg(Color::Cyan)
            .add_attribute(Attribute::Bold),
        "failed" => Cell::new("● failed")
            .fg(Color::Red)
            .add_attribute(Attribute::Bold),
        "pending" => Cell::new("○ pending").fg(Color::DarkGrey),
        other => Cell::new(other),
    }
}

/// Executes the `weaver-server status` CLI command.
pub async fn client_status(socket_path: &Path, json: bool) -> i32 {
    let req = ControlRequest {
        v: 1,
        cmd: "status".to_string(),
        name: None,
        limit: None,
        timeout_s: None,
        all: None,
        force: None,
        path: None,
        no_only_best: None,
    };

    let line = match send_request_and_read_line(socket_path, &req).await {
        Ok(l) => l,
        Err(code) => return code,
    };

    let trimmed = line.trim();
    if json {
        println!("{trimmed}");
        let val: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => return 1,
        };
        if val.get("ok") == Some(&serde_json::Value::Bool(false)) {
            return 1;
        }
        return 0;
    }

    let resp: StatusResponse = match serde_json::from_str(trimmed) {
        Ok(r) => r,
        Err(_) => {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                let err = val.get("error").and_then(|e| e.as_str()).unwrap_or(trimmed);
                eprintln!("{} {err}", "✗ Error:".red().bold());
            } else {
                eprintln!("{} {trimmed}", "✗ Error:".red().bold());
            }
            return 1;
        }
    };

    if !resp.ok {
        eprintln!("{} Status query returned not ok", "✗ Error:".red().bold());
        return 1;
    }

    println!(
        "{} {} {} {} {}",
        "Weaver Server Status".bold().cyan(),
        "—".dark_grey(),
        format!(
            "v{} (protocol v{})",
            resp.version,
            weaver_proto::PROTOCOL_VERSION
        )
        .white(),
        "•".dark_grey(),
        format!("PID {}", resp.pid).dark_grey()
    );
    println!(
        "  {:<14} {}",
        "Uptime:".dark_grey(),
        format_uptime(resp.uptime)
    );
    println!();

    println!("{}", "Endpoints".bold().white());
    println!(
        "  {:<14} {}",
        "Root Domain:".dark_grey(),
        resp.root_domain.bold()
    );
    println!("  {:<14} {}", "HTTP:".dark_grey(), resp.listeners.http);
    println!("  {:<14} {}", "HTTPS:".dark_grey(), resp.listeners.https);
    if !resp.control_socket.is_empty() {
        println!("  {:<14} {}", "Control:".dark_grey(), resp.control_socket);
    }
    println!();

    println!("{}", "Certificates".bold().white());
    let root_styled = match resp.root_cert.as_str() {
        "issued" => format!("{}", "● issued (valid)".green().bold()),
        "ordering" => format!("{}", "● ordering".yellow().bold()),
        "renewing" => format!("{}", "● renewing".cyan().bold()),
        "failed" => format!("{}", "● failed".red().bold()),
        other => format!("○ {other}"),
    };
    println!("  {:<14} {}", "Root:".dark_grey(), root_styled);
    println!(
        "  {:<14} {} issued  •  {} ordering  •  {} failed  •  {} inactive",
        "Inventory:".dark_grey(),
        resp.cert_counts.issued.to_string().green().bold(),
        resp.cert_counts.ordering.to_string().yellow(),
        resp.cert_counts.failed.to_string().red(),
        resp.cert_counts.inactive.to_string().dark_grey(),
    );
    println!();

    println!("{}", "Storage".bold().white());
    println!(
        "  {:<14} {} ({})",
        "Database:".dark_grey(),
        resp.db_path,
        format_bytes(resp.db_size)
    );
    println!("  {:<14} v{}", "Schema:".dark_grey(), resp.schema_version);

    0
}

/// Executes the `weaver-server cert status [NAME]` CLI command.
pub async fn client_cert_status(
    socket_path: &Path,
    name: Option<String>,
    limit: Option<usize>,
    no_only_best: bool,
    json: bool,
) -> i32 {
    let has_name = name.is_some();
    let req = ControlRequest {
        v: 1,
        cmd: "cert.status".to_string(),
        name,
        limit,
        timeout_s: None,
        all: None,
        force: None,
        path: None,
        no_only_best: if no_only_best { Some(true) } else { None },
    };

    let line = match send_request_and_read_line(socket_path, &req).await {
        Ok(l) => l,
        Err(code) => return code,
    };

    let trimmed = line.trim();
    if json {
        println!("{trimmed}");
        let val: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => return 1,
        };
        if val.get("ok") == Some(&serde_json::Value::Bool(false)) {
            return 1;
        }
        return 0;
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    if !has_name {
        // Table view
        let resp: CertListResponse = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(_) => {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                    let err = val.get("error").and_then(|e| e.as_str()).unwrap_or(trimmed);
                    eprintln!("{} {err}", "✗ Error:".red().bold());
                } else {
                    eprintln!("{} {trimmed}", "✗ Error:".red().bold());
                }
                return 1;
            }
        };

        if !resp.ok {
            eprintln!(
                "{} cert.status query returned not ok",
                "✗ Error:".red().bold()
            );
            return 1;
        }

        let mut table = create_styled_table();
        let mut header = Vec::new();
        if no_only_best {
            header.push(
                Cell::new("CERT-ID")
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Cyan),
            );
        }
        header.extend(vec![
            Cell::new("NAME")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
            Cell::new("STATE")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
            Cell::new("DAYS-LEFT")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
            Cell::new("ACTIVE")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
            Cell::new("LAST EVENT AGE")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
        ]);
        table.set_header(header);

        for (idx, cert) in resp.certificates.iter().enumerate() {
            let is_root = idx == 0;
            let name_cell = if is_root {
                Cell::new(format!("★ {}", cert.name))
                    .add_attribute(Attribute::Bold)
                    .fg(Color::White)
            } else {
                Cell::new(format!("  {}", cert.name))
            };

            let state_cell = styled_state_cell(&cert.state);

            let (days_str, days_color) = match cert.not_after {
                Some(ts) => {
                    let diff = ts - now;
                    if diff <= 0 {
                        ("expired".to_string(), Color::Red)
                    } else {
                        let d = diff / 86400;
                        if d < 10 {
                            (format!("{d}d"), Color::Yellow)
                        } else {
                            (format!("{d}d"), Color::Green)
                        }
                    }
                }
                None => ("-".to_string(), Color::DarkGrey),
            };
            let days_cell = Cell::new(days_str).fg(days_color);

            let active_cell = if cert.active {
                Cell::new("✔ yes").fg(Color::Green)
            } else {
                Cell::new("✖ no").fg(Color::DarkGrey)
            };

            let age_str = match &cert.last_event {
                Some(ev) => format_age(now, ev.at),
                None => "-".to_string(),
            };
            let age_cell = Cell::new(age_str).fg(Color::DarkGrey);

            let mut row = Vec::new();
            if no_only_best {
                let id_str = cert.cert_id.map_or("-".to_string(), |id| id.to_string());
                row.push(Cell::new(id_str).fg(Color::Cyan));
            }
            row.extend(vec![
                name_cell,
                state_cell,
                days_cell,
                active_cell,
                age_cell,
            ]);
            table.add_row(row);
        }

        println!("{table}");
        println!(
            "  {} Root Domain    {} Active    {} Inactive",
            "★".yellow().bold(),
            "✔".green(),
            "✖".dark_grey()
        );
        0
    } else {
        // Detail view
        let resp: CertDetailResponse = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(_) => {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                    let err = val.get("error").and_then(|e| e.as_str()).unwrap_or(trimmed);
                    eprintln!("{} {err}", "✗ Error:".red().bold());
                } else {
                    eprintln!("{} {trimmed}", "✗ Error:".red().bold());
                }
                return 1;
            }
        };

        if !resp.ok {
            eprintln!(
                "{} cert.status detail query returned not ok",
                "✗ Error:".red().bold()
            );
            return 1;
        }

        let mut table = create_styled_table();
        table.set_header(vec![
            Cell::new("Property")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
            Cell::new(format!("Certificate: {}", resp.name))
                .add_attribute(Attribute::Bold)
                .fg(Color::White),
        ]);

        table.add_row(vec![
            Cell::new("State").fg(Color::DarkCyan),
            styled_state_cell(resp.state.label()),
        ]);
        table.add_row(vec![
            Cell::new("Active").fg(Color::DarkCyan),
            if resp.active {
                Cell::new("✔ yes")
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
            } else {
                Cell::new("✖ no").fg(Color::DarkGrey)
            },
        ]);
        table.add_row(vec![
            Cell::new("Provider").fg(Color::DarkCyan),
            Cell::new(&resp.provider),
        ]);
        table.add_row(vec![
            Cell::new("Issuer").fg(Color::DarkCyan),
            Cell::new(resp.issuer.as_deref().unwrap_or("-")),
        ]);
        table.add_row(vec![
            Cell::new("Valid From").fg(Color::DarkCyan),
            Cell::new(
                resp.not_before
                    .map(format_unix_timestamp)
                    .unwrap_or_else(|| "-".to_string()),
            ),
        ]);

        let (not_after_str, not_after_color) = match resp.not_after {
            Some(ts) => {
                let formatted = format_unix_timestamp(ts);
                let diff = ts - now;
                if diff > 0 {
                    (
                        format!("{formatted} ({} days remaining)", diff / 86400),
                        Color::Green,
                    )
                } else {
                    (format!("{formatted} (expired)"), Color::Red)
                }
            }
            None => ("-".to_string(), Color::DarkGrey),
        };
        table.add_row(vec![
            Cell::new("Valid Until").fg(Color::DarkCyan),
            Cell::new(not_after_str).fg(not_after_color),
        ]);

        table.add_row(vec![
            Cell::new("Last Active").fg(Color::DarkCyan),
            Cell::new(
                resp.last_active_at
                    .map(format_unix_timestamp)
                    .unwrap_or_else(|| "-".to_string()),
            ),
        ]);

        if let Some(cert_id) = resp.cert_id {
            table.add_row(vec![
                Cell::new("Certificate ID").fg(Color::DarkCyan),
                Cell::new(cert_id.to_string()),
            ]);
        }

        println!("{table}");

        if !resp.cert_events.is_empty() {
            println!("\n{}", "Recent Lifecycle Events:".bold().cyan());
            let mut events_table = create_styled_table();
            events_table.set_header(vec![
                Cell::new("Timestamp")
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Cyan),
                Cell::new("Event")
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Cyan),
                Cell::new("Detail")
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Cyan),
            ]);

            for ev in resp.cert_events {
                let kind_cell = match ev.kind.as_str() {
                    "issued" | "renewed" => Cell::new(format!("● {}", ev.kind))
                        .fg(Color::Green)
                        .add_attribute(Attribute::Bold),
                    "failed" => Cell::new(format!("● {}", ev.kind))
                        .fg(Color::Red)
                        .add_attribute(Attribute::Bold),
                    other => Cell::new(format!("● {other}")).fg(Color::Yellow),
                };
                events_table.add_row(vec![
                    Cell::new(format_unix_timestamp(ev.at)),
                    kind_cell,
                    Cell::new(ev.detail.as_deref().unwrap_or("-")),
                ]);
            }
            println!("{events_table}");
        }

        0
    }
}

/// Executes the `weaver-server cert wait [NAME]` CLI command.
pub async fn client_cert_wait(
    socket_path: &Path,
    name: Option<String>,
    timeout_s: Option<u64>,
    json: bool,
) -> i32 {
    let req = ControlRequest {
        v: 1,
        cmd: "cert.wait".to_string(),
        name,
        limit: None,
        timeout_s,
        all: None,
        force: None,
        path: None,
        no_only_best: None,
    };

    let mut stream = match connect_control_socket(socket_path).await {
        Ok(s) => s,
        Err(code) => return code,
    };

    let mut data = match serde_json::to_vec(&req) {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "{} Failed to serialize request: {e}",
                "✗ Error:".red().bold()
            );
            return 1;
        }
    };
    data.push(b'\n');

    if let Err(e) = stream.write_all(&data).await {
        eprintln!(
            "{} Failed to write to control socket: {e}",
            "✗ Error:".red().bold()
        );
        return 1;
    }
    if let Err(e) = stream.flush().await {
        eprintln!(
            "{} Failed to flush control socket: {e}",
            "✗ Error:".red().bold()
        );
        return 1;
    }

    let (reader, _) = stream.split();
    let mut buf_reader = BufReader::new(reader);
    let mut exit_code = 0;

    loop {
        let mut line = String::new();
        match buf_reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if json {
                    println!("{trimmed}");
                }

                if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                    if let Some(state) = val.get("state").and_then(|s| s.as_str()) {
                        let name_str = val.get("name").and_then(|n| n.as_str()).unwrap_or("");
                        if !json {
                            match state {
                                "issued" => {
                                    println!(
                                        "{} Certificate '{}' -> {}",
                                        "✓".green().bold(),
                                        name_str.bold().cyan(),
                                        "issued (valid)".green().bold()
                                    );
                                }
                                "failed" => {
                                    println!(
                                        "{} Certificate '{}' -> {}",
                                        "✗".red().bold(),
                                        name_str.bold().cyan(),
                                        "failed".red().bold()
                                    );
                                }
                                "ordering" => {
                                    println!(
                                        "{} Certificate '{}' -> {}",
                                        "●".yellow(),
                                        name_str.bold().cyan(),
                                        "ordering...".yellow()
                                    );
                                }
                                "renewing" => {
                                    println!(
                                        "{} Certificate '{}' -> {}",
                                        "●".cyan(),
                                        name_str.bold().cyan(),
                                        "renewing...".cyan()
                                    );
                                }
                                other => {
                                    println!(
                                        "● Certificate '{}' -> {}",
                                        name_str.bold().cyan(),
                                        other
                                    );
                                }
                            }
                        }
                        if state == "issued" {
                            exit_code = 0;
                            break;
                        } else if state == "failed" {
                            if !json && let Some(err) = val.get("error").and_then(|e| e.as_str()) {
                                eprintln!("{} Issuance failed: {err}", "✗ Error:".red().bold());
                            }
                            exit_code = 4;
                            break;
                        }
                    } else if val.get("ok") == Some(&serde_json::Value::Bool(false)) {
                        let err = val
                            .get("error")
                            .and_then(|e| e.as_str())
                            .unwrap_or("Wait error");
                        if !json {
                            eprintln!("{} {err}", "✗ Error:".red().bold());
                        }
                        return 1;
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "{} Failed reading from control socket: {e}",
                    "✗ Error:".red().bold()
                );
                return 1;
            }
        }
    }

    exit_code
}

/// Executes the `weaver-server cert renew [NAME | --all] [--force] [--wait]` CLI command.
pub async fn client_cert_renew(
    socket_path: &Path,
    name: Option<String>,
    all: bool,
    force: bool,
    wait: bool,
    json: bool,
) -> i32 {
    let req = ControlRequest {
        v: 1,
        cmd: "cert.renew".to_string(),
        name,
        limit: None,
        timeout_s: None,
        all: if all { Some(true) } else { None },
        force: if force { Some(true) } else { None },
        path: None,
        no_only_best: None,
    };

    let line = match send_request_and_read_line(socket_path, &req).await {
        Ok(l) => l,
        Err(code) => return code,
    };

    let trimmed = line.trim();
    if json {
        println!("{trimmed}");
        let val: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => return 1,
        };
        if val.get("ok") == Some(&serde_json::Value::Bool(false)) {
            return 1;
        }
        if wait && let Some(renewed) = val.get("renewed").and_then(|r| r.as_array()) {
            for h in renewed {
                if let Some(host) = h.as_str() {
                    let wait_code =
                        client_cert_wait(socket_path, Some(host.to_string()), None, true).await;
                    if wait_code != 0 {
                        return wait_code;
                    }
                }
            }
        }
        return 0;
    }

    let resp: RenewResponse = match serde_json::from_str(trimmed) {
        Ok(r) => r,
        Err(_) => {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                let err = val.get("error").and_then(|e| e.as_str()).unwrap_or(trimmed);
                eprintln!("{} {err}", "✗ Error:".red().bold());
            } else {
                eprintln!("{} {trimmed}", "✗ Error:".red().bold());
            }
            return 1;
        }
    };

    if !resp.ok {
        eprintln!("{} Renewal rejected", "✗ Error:".red().bold());
        return 1;
    }

    println!("{} Certificate renewal queued", "✓".green().bold());
    println!(
        "  {:<12} {}",
        "Target:".dark_grey(),
        resp.renewed.join(", ").bold().cyan()
    );
    if !resp.skipped_inactive.is_empty() {
        println!(
            "  {:<12} {} (inactive)",
            "Skipped:".dark_grey(),
            resp.skipped_inactive.join(", ").dark_grey()
        );
    }

    if wait {
        println!();
        for host in &resp.renewed {
            println!(
                "{} Waiting for certificate issuance for '{}'...",
                "●".cyan(),
                host.as_str().bold().cyan()
            );
            let wait_code = client_cert_wait(socket_path, Some(host.clone()), None, false).await;
            if wait_code != 0 {
                return wait_code;
            }
        }
    }

    0
}

/// Executes the `weaver-server backup <PATH>` CLI command.
pub async fn client_backup(socket_path: &Path, path: String, json: bool) -> i32 {
    let req = ControlRequest {
        v: 1,
        cmd: "backup".to_string(),
        name: None,
        limit: None,
        timeout_s: None,
        all: None,
        force: None,
        path: Some(path),
        no_only_best: None,
    };

    let line = match send_request_and_read_line(socket_path, &req).await {
        Ok(l) => l,
        Err(code) => return code,
    };

    let trimmed = line.trim();
    if json {
        println!("{trimmed}");
        let val: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => return 1,
        };
        if val.get("ok") == Some(&serde_json::Value::Bool(false)) {
            return 1;
        }
        return 0;
    }

    let resp: BackupResponse = match serde_json::from_str(trimmed) {
        Ok(r) => r,
        Err(_) => {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                let err = val.get("error").and_then(|e| e.as_str()).unwrap_or(trimmed);
                eprintln!("{} {err}", "✗ Error:".red().bold());
            } else {
                eprintln!("{} {trimmed}", "✗ Error:".red().bold());
            }
            return 1;
        }
    };

    if !resp.ok {
        eprintln!("{} Backup failed", "✗ Error:".red().bold());
        return 1;
    }

    println!("{} Database backup created", "✓".green().bold());
    println!("  {:<14} {}", "Destination:".dark_grey(), resp.path.bold());
    println!(
        "  {:<14} {}",
        "File Size:".dark_grey(),
        format_bytes(resp.size)
    );

    0
}

/// Executes the `weaver-server shutdown` CLI command.
pub async fn client_shutdown(socket_path: &Path, json: bool) -> i32 {
    let req = ControlRequest {
        v: 1,
        cmd: "shutdown".to_string(),
        name: None,
        limit: None,
        timeout_s: None,
        all: None,
        force: None,
        path: None,
        no_only_best: None,
    };

    let line = match send_request_and_read_line(socket_path, &req).await {
        Ok(l) => l,
        Err(code) => return code,
    };

    let trimmed = line.trim();
    if json {
        println!("{trimmed}");
        let val: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => return 1,
        };
        if val.get("ok") == Some(&serde_json::Value::Bool(false)) {
            return 1;
        }
        return 0;
    }

    println!("{} Server shutdown initiated", "✓".yellow().bold());
    0
}
