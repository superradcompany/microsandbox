//! `msb inspect` command — show detailed sandbox information.

use clap::Args;
use microsandbox::sandbox::{
    HostPermissions, MountOptions, Sandbox, SandboxConfig, SecurityProfile, StatVirtualization,
    VolumeMount,
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
    let mut flags = vec![if options.readonly { "ro" } else { "rw" }];
    if options.noexec {
        flags.push("noexec");
    }
    if options.nosuid {
        flags.push("nosuid");
    }
    if options.nodev {
        flags.push("nodev");
    }
    format!(" ({})", flags.join(","))
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
            "status": format!("{:?}", handle.status_snapshot()),
            "config": config,
            "created_at": handle.created_at().map(|dt| ui::format_json_datetime(&dt)),
            "updated_at": handle.updated_at().map(|dt| ui::format_json_datetime(&dt)),
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    let status = format!("{:?}", handle.status_snapshot());

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
        let image = match &config.spec.image {
            microsandbox::sandbox::RootfsSource::Oci(oci) => oci.reference.clone(),
            microsandbox::sandbox::RootfsSource::Bind(p) => p.display().to_string(),
            microsandbox::sandbox::RootfsSource::DiskImage { path, .. } => {
                path.display().to_string()
            }
        };
        ui::detail_kv("Image", &image);
        if let Some(disk_size_mib) = config.spec.image.oci_upper_size_mib() {
            ui::detail_kv("Disk", &format!("{disk_size_mib} MiB"));
        }

        ui::detail_header("Resources");
        ui::detail_kv_indent("CPUs", &config.spec.resources.cpus.to_string());
        ui::detail_kv_indent(
            "Memory",
            &format!("{} MiB", config.spec.resources.memory_mib),
        );
        let security = match config.spec.security_profile {
            SecurityProfile::Default => "default",
            SecurityProfile::Restricted => "restricted",
        };
        ui::detail_kv("Security", security);

        if let Some(ref workdir) = config.spec.runtime.workdir {
            ui::detail_kv("Workdir", workdir);
        }
        if let Some(ref shell) = config.spec.runtime.shell {
            ui::detail_kv("Shell", shell);
        }

        if !config.spec.env.is_empty() {
            ui::detail_header("Environment");
            for var in &config.spec.env {
                println!("  {}={}", var.key, var.value);
            }
        }

        if !config.spec.labels.is_empty() {
            ui::detail_header("Labels");
            let mut labels: Vec<_> = config.spec.labels.iter().collect();
            labels.sort_by(|a, b| a.0.cmp(b.0));
            for (k, v) in labels {
                println!("  {k}={v}");
            }
        }

        if !config.spec.mounts.is_empty() {
            ui::detail_header("Mounts");
            for mount in &config.spec.mounts {
                match mount {
                    VolumeMount::Bind {
                        host,
                        guest,
                        options,
                        stat_virtualization,
                        host_permissions,
                        quota_mib,
                    } => {
                        let flags = mount_flags_suffix(*options);
                        let suffix = mount_policy_suffix(*stat_virtualization, *host_permissions);
                        let quota = quota_mib
                            .map(|mib| format!(" [quota={mib}MiB]"))
                            .unwrap_or_default();
                        println!(
                            "  {guest:<16}\u{2192} {}{flags}{suffix}{quota}",
                            host.display()
                        );
                    }
                    VolumeMount::Named {
                        name,
                        guest,
                        options,
                        stat_virtualization,
                        host_permissions,
                        ..
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
