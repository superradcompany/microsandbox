//! `msb status` command — show sandbox status.

use clap::Args;
use microsandbox::sandbox::{Sandbox, SandboxConfig, SandboxHandle, SandboxStatus};

use crate::ui;

use super::common;

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

    /// Show only sandboxes carrying this label (`KEY=VALUE`). Repeatable;
    /// AND-matched.
    #[arg(long, conflicts_with = "name")]
    pub label: Vec<String>,

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
    cpus: String,
    mem: String,
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
        let mut sandboxes = Sandbox::list_with(common::label_filter(&args.label)).await?;
        if !args.all {
            sandboxes.retain(|s| {
                s.status_snapshot() == SandboxStatus::Running
                    || s.status_snapshot() == SandboxStatus::Draining
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

    let mut table = ui::Table::new(&["NAME", "IMAGE", "COMMAND", "CPUS", "MEM", "STATUS", "PORTS"]);
    for row in handles.iter().map(status_row) {
        table.add_row(vec![
            row.name,
            row.image,
            row.command,
            row.cpus,
            row.mem,
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
    let status = format!("{:?}", handle.status_snapshot());
    let resources = resource_config(handle, config.as_ref());
    let (cpus, mem) = resources
        .as_ref()
        .map(format_resources)
        .unwrap_or_else(|| ("-".to_string(), "-".to_string()));

    StatusRow {
        name: handle.name().to_string(),
        image,
        command,
        cpus,
        mem,
        status: ui::format_status(&status),
        ports,
    }
}

fn status_json(handle: &SandboxHandle) -> serde_json::Value {
    let config = serde_json::from_str::<SandboxConfig>(handle.config_json()).ok();
    let status = format!("{:?}", handle.status_snapshot());
    let resources = resource_config(handle, config.as_ref());
    let resources = resources.as_ref().map(|c| &c.spec.resources);

    serde_json::json!({
        "name": handle.name(),
        "status": status,
        "image": config.as_ref().map(extract_image_raw).unwrap_or_else(|| "-".to_string()),
        "command": config.as_ref().map(format_command_raw).unwrap_or_else(|| "-".to_string()),
        "cpus": resources.map(|r| r.vcpus),
        "max_cpus": resources.map(|r| r.max_vcpus.max(r.vcpus)),
        "memory_mib": resources.map(|r| r.memory_mib),
        "max_memory_mib": resources.map(|r| r.max_memory_mib.max(r.memory_mib)),
        "ports": config.as_ref().map(format_ports_raw).unwrap_or_default(),
    })
}

/// Resolve the config whose resource allocations describe the sandbox now:
/// the active-config snapshot for running sandboxes (tracks live resizes),
/// falling back to the desired config.
fn resource_config(
    handle: &SandboxHandle,
    desired: Option<&SandboxConfig>,
) -> Option<SandboxConfig> {
    handle
        .active_config()
        .ok()
        .flatten()
        .or_else(|| desired.cloned())
}

/// Render `(CPUS, MEM)` cells as `effective / max`, where max is the boot-time
/// hotplug ceiling — the headroom available to a live resize.
fn format_resources(config: &SandboxConfig) -> (String, String) {
    let resources = &config.spec.resources;
    let cpus = format!(
        "{} / {}",
        resources.vcpus,
        resources.max_vcpus.max(resources.vcpus)
    );
    let mem = format!(
        "{} / {}",
        format_mem_mib(resources.memory_mib),
        format_mem_mib(resources.max_memory_mib.max(resources.memory_mib)),
    );
    (cpus, mem)
}

fn format_mem_mib(mib: u32) -> String {
    if mib >= 1024 && mib.is_multiple_of(1024) {
        format!("{} GiB", mib / 1024)
    } else {
        format!("{mib} MiB")
    }
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
    match &config.spec.image {
        microsandbox::sandbox::RootfsSource::Oci(oci) => oci.reference.clone(),
        microsandbox::sandbox::RootfsSource::Bind(p) => p.display().to_string(),
        microsandbox::sandbox::RootfsSource::DiskImage { path, .. } => path.display().to_string(),
    }
}

fn format_command_raw(config: &SandboxConfig) -> String {
    let mut parts = Vec::new();

    if let Some(entrypoint) = &config.spec.runtime.entrypoint {
        parts.extend(entrypoint.iter().cloned());
    }
    if let Some(cmd) = &config.spec.runtime.cmd {
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
        let network = &config.spec.network;
        if !network.enabled || network.ports.is_empty() {
            return Vec::new();
        }

        network
            .ports
            .iter()
            .map(|port| {
                let protocol = match port.protocol {
                    microsandbox::sandbox::PortProtocol::Tcp => "tcp",
                    microsandbox::sandbox::PortProtocol::Udp => "udp",
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
