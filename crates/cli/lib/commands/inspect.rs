//! `msb inspect` command — show detailed sandbox information.

use clap::Args;
use microsandbox::sandbox::{Sandbox, SandboxConfig, VolumeMount};

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Show detailed sandbox information.
#[derive(Debug, Args)]
pub struct InspectArgs {
    /// Name of the sandbox to inspect.
    pub name: String,

    /// Output format.
    #[arg(long, value_name = "FORMAT")]
    pub format: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb inspect` command.
pub async fn run(args: InspectArgs) -> anyhow::Result<()> {
    let info = Sandbox::get(&args.name).await?;

    if args.format.as_deref() == Some("json") {
        let config: serde_json::Value =
            serde_json::from_str(&info.config).unwrap_or(serde_json::Value::Null);
        let json = serde_json::json!({
            "name": info.name,
            "status": format!("{:?}", info.status),
            "config": config,
            "created_at": info.created_at.map(|dt| ui::format_datetime(&dt)),
            "updated_at": info.updated_at.map(|dt| ui::format_datetime(&dt)),
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    let status = format!("{:?}", info.status);

    ui::detail_kv("Name", &info.name);
    ui::detail_kv("Status", &ui::format_status(&status));

    if let Some(ref dt) = info.created_at {
        ui::detail_kv("Created", &ui::format_datetime(dt));
    }
    if let Some(ref dt) = info.updated_at {
        ui::detail_kv("Updated", &ui::format_datetime(dt));
    }

    // Parse and display config details.
    if let Ok(config) = serde_json::from_str::<SandboxConfig>(&info.config) {
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
                    VolumeMount::Tmpfs { guest, size_mib } => {
                        let size = size_mib.map(|s| format!(" ({s} MiB)")).unwrap_or_default();
                        println!("  {guest:<16}\u{2192} tmpfs{size}");
                    }
                }
            }
        }
    }

    Ok(())
}
