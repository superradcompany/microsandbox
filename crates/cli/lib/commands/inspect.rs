//! `msb inspect` command — show detailed sandbox information.

use clap::Args;
use microsandbox::sandbox::{
    HostPermissions, MountOptions, Sandbox, SandboxConfig, StatVirtualization, VolumeMount,
};

use crate::ui;

/// Render a non-default mount policy suffix for `msb inspect` output.
///
/// Returns an empty string when both policies are at their conservative
/// defaults (`Strict` + `Private`), so common mounts stay terse.
fn mount_policy_suffix(sv: StatVirtualization, hp: HostPermissions) -> String {
    let sv_str = match sv {
        StatVirtualization::Strict => None,
        StatVirtualization::Relaxed => Some("stat-virt=relaxed"),
        StatVirtualization::Off => Some("stat-virt=off"),
    };
    let hp_str = match hp {
        HostPermissions::Private => None,
        HostPermissions::Mirror => Some("host-perms=mirror"),
    };
    match (sv_str, hp_str) {
        (None, None) => String::new(),
        (Some(s), None) => format!(" [{s}]"),
        (None, Some(h)) => format!(" [{h}]"),
        (Some(s), Some(h)) => format!(" [{s},{h}]"),
    }
}

/// Render mount access and execution flags for `msb inspect` output.
fn mount_flags_suffix(options: MountOptions) -> String {
    let access = if options.readonly { "ro" } else { "rw" };
    if options.noexec {
        format!(" ({access},noexec)")
    } else {
        format!(" ({access})")
    }
}

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
            "created_at": handle.created_at().map(|dt| ui::format_json_datetime(&dt)),
            "updated_at": handle.updated_at().map(|dt| ui::format_json_datetime(&dt)),
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
            microsandbox::sandbox::RootfsSource::Oci(oci) => oci.reference.clone(),
            microsandbox::sandbox::RootfsSource::Bind(p) => p.display().to_string(),
            microsandbox::sandbox::RootfsSource::DiskImage { path, .. } => {
                path.display().to_string()
            }
        };
        ui::detail_kv("Image", &image);
        if let Some(upper_size_mib) = config.image.oci_upper_size_mib() {
            ui::detail_kv("OCI Upper", &format!("{upper_size_mib} MiB"));
        }

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

        if !config.labels.is_empty() {
            ui::detail_header("Labels");
            let mut labels: Vec<_> = config.labels.iter().collect();
            labels.sort_by(|a, b| a.0.cmp(b.0));
            for (k, v) in labels {
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
                        options,
                        stat_virtualization,
                        host_permissions,
                    } => {
                        let flags = mount_flags_suffix(*options);
                        let suffix = mount_policy_suffix(*stat_virtualization, *host_permissions);
                        println!("  {guest:<16}\u{2192} {}{flags}{suffix}", host.display());
                    }
                    VolumeMount::Named {
                        name,
                        guest,
                        options,
                        stat_virtualization,
                        host_permissions,
                    } => {
                        let flags = mount_flags_suffix(*options);
                        let suffix = mount_policy_suffix(*stat_virtualization, *host_permissions);
                        println!("  {guest:<16}\u{2192} volume:{name}{flags}{suffix}");
                    }
                    VolumeMount::Tmpfs {
                        guest,
                        size_mib,
                        options,
                    } => {
                        let size = size_mib.map(|s| format!(" ({s} MiB)")).unwrap_or_default();
                        let flags = mount_flags_suffix(*options);
                        println!("  {guest:<16}\u{2192} tmpfs{size}{flags}");
                    }
                    VolumeMount::DiskImage {
                        host,
                        guest,
                        format,
                        fstype,
                        options,
                    } => {
                        let flags = mount_flags_suffix(*options);
                        let fstype = fstype.as_deref().unwrap_or("auto");
                        println!(
                            "  {guest:<16}\u{2192} disk:{} ({}) [{fstype}]{flags}",
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
