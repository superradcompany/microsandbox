//! `msb status` command — show sandbox status.

use clap::Args;
use microsandbox::sandbox::{Sandbox, SandboxConfig, SandboxHandle, SandboxStatus};

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Show sandbox status.
#[derive(Debug, Args)]
pub struct PsArgs {
    /// Sandbox to inspect. Omit to show running sandboxes.
    pub name: Option<String>,

    /// Show all sandboxes, not just running ones.
    #[arg(short, long, conflicts_with = "name")]
    pub all: bool,

    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_parser = ["json"])]
    pub format: Option<String>,

    /// Show only sandbox names.
    #[arg(short, long)]
    pub quiet: bool,
}

struct StatusRow {
    name: String,
    image: String,
    command: String,
    status: String,
    ports: String,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb status` command.
pub async fn run(args: PsArgs) -> anyhow::Result<()> {
    let single = args.name.is_some();
    let handles: Vec<SandboxHandle> = if let Some(name) = args.name.as_deref() {
        vec![Sandbox::get(name).await?]
    } else {
        let mut sandboxes = Sandbox::list().await?;
        if !args.all {
            sandboxes.retain(|s| {
                s.status() == SandboxStatus::Running || s.status() == SandboxStatus::Draining
            });
        }
        sandboxes.sort_by(|left, right| left.name().cmp(right.name()));
        sandboxes
    };

    if args.format.as_deref() == Some("json") {
        print_json(&handles, single)?;
        return Ok(());
    }

    if args.quiet {
        for s in &handles {
            println!("{}", s.name());
        }
        return Ok(());
    }

    if handles.is_empty() {
        if args.all {
            eprintln!("No sandboxes found.");
        } else {
            eprintln!("No running sandboxes.");
        }
        return Ok(());
    }

    let mut table = ui::Table::new(&["NAME", "IMAGE", "COMMAND", "STATUS", "PORTS"]);
    for row in handles.iter().map(status_row) {
        table.add_row(vec![
            row.name,
            row.image,
            row.command,
            row.status,
            row.ports,
        ]);
    }

    table.print();
    Ok(())
}

fn print_json(handles: &[SandboxHandle], single: bool) -> anyhow::Result<()> {
    if single {
        let row = handles
            .first()
            .map(status_json)
            .unwrap_or(serde_json::Value::Null);
        println!("{}", serde_json::to_string_pretty(&row)?);
        return Ok(());
    }

    let rows: Vec<_> = handles.iter().map(status_json).collect();
    println!("{}", serde_json::to_string_pretty(&rows)?);
    Ok(())
}

fn status_row(handle: &SandboxHandle) -> StatusRow {
    let config = serde_json::from_str::<SandboxConfig>(handle.config_json()).ok();
    let image = config
        .as_ref()
        .map(extract_image)
        .unwrap_or_else(|| "-".to_string());
    let command = config
        .as_ref()
        .map(format_command)
        .unwrap_or_else(|| "-".to_string());
    let ports = config
        .as_ref()
        .map(format_ports)
        .unwrap_or_else(|| "-".to_string());
    let status = format!("{:?}", handle.status());

    StatusRow {
        name: handle.name().to_string(),
        image,
        command,
        status: ui::format_status(&status),
        ports,
    }
}

fn status_json(handle: &SandboxHandle) -> serde_json::Value {
    let config = serde_json::from_str::<SandboxConfig>(handle.config_json()).ok();
    let status = format!("{:?}", handle.status());

    serde_json::json!({
        "name": handle.name(),
        "status": status,
        "image": config.as_ref().map(extract_image_raw).unwrap_or_else(|| "-".to_string()),
        "command": config.as_ref().map(format_command_raw).unwrap_or_else(|| "-".to_string()),
        "ports": config.as_ref().map(format_ports_raw).unwrap_or_default(),
    })
}

fn extract_image(config: &SandboxConfig) -> String {
    truncate(&extract_image_raw(config), 36)
}

fn format_command(config: &SandboxConfig) -> String {
    truncate(&format_command_raw(config), 40)
}

fn format_ports(config: &SandboxConfig) -> String {
    let ports = format_ports_raw(config);
    if ports.is_empty() {
        return "-".to_string();
    }

    truncate(&ports.join(", "), 32)
}

fn extract_image_raw(config: &SandboxConfig) -> String {
    match &config.image {
        microsandbox::sandbox::RootfsSource::Oci(s) => s.clone(),
        microsandbox::sandbox::RootfsSource::Bind(p) => p.display().to_string(),
        microsandbox::sandbox::RootfsSource::DiskImage { path, .. } => path.display().to_string(),
    }
}

fn format_command_raw(config: &SandboxConfig) -> String {
    let mut parts = Vec::new();

    if let Some(entrypoint) = &config.entrypoint {
        parts.extend(entrypoint.iter().cloned());
    }
    if let Some(cmd) = &config.cmd {
        parts.extend(cmd.iter().cloned());
    }

    if parts.is_empty() {
        return "-".to_string();
    }

    format!("\"{}\"", parts.join(" "))
}

fn format_ports_raw(config: &SandboxConfig) -> Vec<String> {
    #[cfg(feature = "net")]
    {
        if !config.network.enabled || config.network.ports.is_empty() {
            return Vec::new();
        }

        config
            .network
            .ports
            .iter()
            .map(|port| {
                let protocol = match port.protocol {
                    microsandbox_network::config::PortProtocol::Tcp => "tcp",
                    microsandbox_network::config::PortProtocol::Udp => "udp",
                };
                format!(
                    "{}:{}->{}/{}",
                    port.host_bind, port.host_port, port.guest_port, protocol
                )
            })
            .collect()
    }

    #[cfg(not(feature = "net"))]
    {
        let _ = config;
        Vec::new()
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    let char_count = value.chars().count();
    if char_count <= max_chars {
        return value.to_string();
    }

    if max_chars <= 3 {
        return ".".repeat(max_chars);
    }

    let truncated: String = value.chars().take(max_chars - 3).collect();
    format!("{truncated}...")
}
