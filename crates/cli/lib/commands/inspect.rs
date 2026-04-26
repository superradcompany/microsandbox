//! `msb inspect` command — show detailed sandbox information.

use clap::Args;
use microsandbox::sandbox::{Sandbox, SandboxConfig, VolumeMount};

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Show detailed sandbox configuration and status.
#[derive(Debug, Args)]
pub struct InspectArgs {
    /// Sandbox to inspect.
    pub name: String,

    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_parser = ["json"])]
    pub format: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb inspect` command.
pub async fn run(args: InspectArgs) -> anyhow::Result<()> {
    let handle = Sandbox::get(&args.name).await?;

    if args.format.as_deref() == Some("json") {
        let config: serde_json::Value =
            serde_json::from_str(handle.config_json()).unwrap_or(serde_json::Value::Null);
        let json = serde_json::json!({
            "name": handle.name(),
            "status": format!("{:?}", handle.status()),
            "config": config,
            "created_at": handle.created_at().map(|dt| ui::format_datetime(&dt)),
            "updated_at": handle.updated_at().map(|dt| ui::format_datetime(&dt)),
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    let status = format!("{:?}", handle.status());

    ui::detail_kv("Name", handle.name());
    ui::detail_kv("Status", &ui::format_status(&status));

    if let Some(dt) = handle.created_at() {
        ui::detail_kv("Created", &ui::format_datetime(&dt));
    }
    if let Some(dt) = handle.updated_at() {
        ui::detail_kv("Updated", &ui::format_datetime(&dt));
    }

    // Parse and display config details.
    if let Ok(config) = serde_json::from_str::<SandboxConfig>(handle.config_json()) {
        let image = match &config.image {
            microsandbox::sandbox::RootfsSource::Oci(s) => s.clone(),
            microsandbox::sandbox::RootfsSource::Bind(p) => p.display().to_string(),
            microsandbox::sandbox::RootfsSource::DiskImage { path, .. } => {
                path.display().to_string()
            }
        };
        ui::detail_kv("Image", &image);

        ui::detail_header("Resources");
        ui::detail_kv_indent("CPUs", &config.cpus.to_string());
        ui::detail_kv_indent("Memory", &format!("{} MiB", config.memory_mib));

        if let Some(ref workdir) = config.workdir {
            ui::detail_kv("Workdir", workdir);
        }
        if let Some(ref shell) = config.shell {
            ui::detail_kv("Shell", shell);
        }

        if !config.env.is_empty() {
            ui::detail_header("Environment");
            for (k, v) in &config.env {
                println!("  {k}={v}");
            }
        }

        if !config.mounts.is_empty() {
            ui::detail_header("Mounts");
            for mount in &config.mounts {
                match mount {
                    VolumeMount::Bind {
                        host,
                        guest,
                        readonly,
                    } => {
                        let ro = if *readonly { " (ro)" } else { " (rw)" };
                        println!("  {guest:<16}\u{2192} {}{ro}", host.display());
                    }
                    VolumeMount::Named {
                        name,
                        guest,
                        readonly,
                    } => {
                        let ro = if *readonly { " (ro)" } else { " (rw)" };
                        println!("  {guest:<16}\u{2192} volume:{name}{ro}");
                    }
                    VolumeMount::Tmpfs {
                        guest,
                        size_mib,
                        readonly,
                    } => {
                        let size = size_mib.map(|s| format!(" ({s} MiB)")).unwrap_or_default();
                        let ro = if *readonly { " (ro)" } else { "" };
                        println!("  {guest:<16}\u{2192} tmpfs{size}{ro}");
                    }
                    VolumeMount::DiskImage {
                        host,
                        guest,
                        format,
                        fstype,
                        readonly,
                    } => {
                        let ro = if *readonly { " (ro)" } else { " (rw)" };
                        let fstype = fstype.as_deref().unwrap_or("auto");
                        println!(
                            "  {guest:<16}\u{2192} disk:{} ({}) [{fstype}]{ro}",
                            host.display(),
                            format.as_str()
                        );
                    }
                }
            }
        }
    }

    Ok(())
}
