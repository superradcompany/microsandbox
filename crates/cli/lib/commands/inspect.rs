//! `msb inspect` command — show detailed sandbox information.

use clap::Args;
use console::style;
use microsandbox::sandbox::{
    HostPermissions, MountOptions, Sandbox, SandboxConfig, SandboxStatus, SecurityProfile,
    StatVirtualization, VolumeMount,
};
use serde::Serialize;

use crate::ui;

/// Render a non-default mount policy suffix for `msb inspect` output.
///
/// Returns an empty string when every policy is at its conservative default
/// (`Strict` + `Private` + no-follow root), so common mounts stay terse.
fn mount_policy_suffix(
    sv: StatVirtualization,
    hp: HostPermissions,
    follow_root_symlinks: bool,
) -> String {
    let mut tokens = Vec::new();
    match sv {
        StatVirtualization::Strict => {}
        StatVirtualization::Relaxed => tokens.push("stat-virt=relaxed"),
        StatVirtualization::Off => tokens.push("stat-virt=off"),
    }
    match hp {
        HostPermissions::Private => {}
        HostPermissions::Mirror => tokens.push("host-perms=mirror"),
    }
    if follow_root_symlinks {
        tokens.push("follow-root-symlinks");
    }
    if tokens.is_empty() {
        String::new()
    } else {
        format!(" [{}]", tokens.join(","))
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

#[derive(Debug, Serialize)]
struct PendingConfigChange {
    field: &'static str,
    active: String,
    desired: String,
    effect: &'static str,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb inspect` command.
pub async fn run(args: InspectArgs) -> anyhow::Result<()> {
    let handle = Sandbox::get(&args.name).await?;
    let desired_config = handle.config().ok();
    let active_config = handle.active_config().ok().flatten();
    let pending_changes = pending_config_changes(
        handle.status_snapshot(),
        desired_config.as_ref(),
        active_config.as_ref(),
    );

    if args.format.as_deref() == Some("json") {
        let config: serde_json::Value =
            serde_json::from_str(handle.config_json()).unwrap_or(serde_json::Value::Null);
        let mut json = serde_json::json!({
            "name": handle.name(),
            "status": format!("{:?}", handle.status_snapshot()),
            "config": config,
            "created_at": handle.created_at().map(|dt| ui::format_json_datetime(&dt)),
            "updated_at": handle.updated_at().map(|dt| ui::format_json_datetime(&dt)),
        });
        let active_config_json = handle
            .active_config_json()
            .map(|json| serde_json::from_str(json).unwrap_or(serde_json::Value::Null))
            .unwrap_or(serde_json::Value::Null);
        json["active_config"] = active_config_json;
        json["pending_changes"] = serde_json::to_value(&pending_changes)?;
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
    if let Some(config) = desired_config {
        let image = match &config.spec.image {
            microsandbox::sandbox::RootfsSource::Oci(oci) => oci.reference.clone(),
            microsandbox::sandbox::RootfsSource::Bind { path, .. } => path.display().to_string(),
            microsandbox::sandbox::RootfsSource::DiskImage { path, .. } => {
                path.display().to_string()
            }
        };
        ui::detail_kv("Image", &image);
        match config.spec.image.oci_root_disk() {
            Some(microsandbox::sandbox::RootDisk::Managed { size_mib }) => {
                let size = size_mib.map_or("default".to_string(), |mib| format!("{mib} MiB"));
                ui::detail_kv("Root Disk", &format!("{size} (managed, ext4)"));
            }
            Some(microsandbox::sandbox::RootDisk::Tmpfs { size_mib }) => {
                let size = size_mib.map_or("default".to_string(), |mib| format!("{mib} MiB"));
                ui::detail_kv("Root Disk", &format!("{size} (tmpfs)"));
            }
            Some(microsandbox::sandbox::RootDisk::DiskImage {
                path,
                format,
                fstype,
            }) => {
                ui::detail_kv(
                    "Root Disk",
                    &format!(
                        "{} (disk-image, {}, {})",
                        path.display(),
                        format.as_str(),
                        fstype.as_deref().unwrap_or("ext4")
                    ),
                );
            }
            None => {}
        }

        let change_for = |field: &str| pending_changes.iter().find(|c| c.field == field);
        ui::detail_header("Resources");
        ui::detail_kv_indent(
            "CPUs",
            &resource_value(&config.spec.resources.cpus.to_string(), change_for("cpus")),
        );
        ui::detail_kv_indent(
            "Max CPUs",
            &resource_value(
                &config.spec.resources.max_cpus.to_string(),
                change_for("max_cpus"),
            ),
        );
        ui::detail_kv_indent(
            "Memory",
            &resource_value(
                &format!("{} MiB", config.spec.resources.memory_mib),
                change_for("memory"),
            ),
        );
        ui::detail_kv_indent(
            "Max Memory",
            &resource_value(
                &format!("{} MiB", config.spec.resources.max_memory_mib),
                change_for("max_memory"),
            ),
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
                        follow_root_symlinks,
                        quota_mib,
                    } => {
                        let flags = mount_flags_suffix(*options);
                        let suffix = mount_policy_suffix(
                            *stat_virtualization,
                            *host_permissions,
                            *follow_root_symlinks,
                        );
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
                        follow_root_symlinks,
                        ..
                    } => {
                        let flags = mount_flags_suffix(*options);
                        let suffix = mount_policy_suffix(
                            *stat_virtualization,
                            *host_permissions,
                            *follow_root_symlinks,
                        );
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

fn pending_config_changes(
    status: SandboxStatus,
    desired: Option<&SandboxConfig>,
    active: Option<&SandboxConfig>,
) -> Vec<PendingConfigChange> {
    if !status_has_active_config(status) {
        return Vec::new();
    }

    let (Some(desired), Some(active)) = (desired, active) else {
        return Vec::new();
    };

    let mut changes = Vec::new();
    if desired.spec.resources.cpus != active.spec.resources.cpus {
        changes.push(PendingConfigChange {
            field: "cpus",
            active: active.spec.resources.cpus.to_string(),
            desired: desired.spec.resources.cpus.to_string(),
            effect: "requires restart",
        });
    }
    if desired.spec.resources.max_cpus != active.spec.resources.max_cpus {
        changes.push(PendingConfigChange {
            field: "max_cpus",
            active: active.spec.resources.max_cpus.to_string(),
            desired: desired.spec.resources.max_cpus.to_string(),
            effect: "requires restart",
        });
    }
    if desired.spec.resources.memory_mib != active.spec.resources.memory_mib {
        changes.push(PendingConfigChange {
            field: "memory",
            active: format_mib(active.spec.resources.memory_mib),
            desired: format_mib(desired.spec.resources.memory_mib),
            effect: "requires restart",
        });
    }
    if desired.spec.resources.max_memory_mib != active.spec.resources.max_memory_mib {
        changes.push(PendingConfigChange {
            field: "max_memory",
            active: format_mib(active.spec.resources.max_memory_mib),
            desired: format_mib(desired.spec.resources.max_memory_mib),
            effect: "requires restart",
        });
    }

    changes
}

fn status_has_active_config(status: SandboxStatus) -> bool {
    matches!(
        status,
        SandboxStatus::Running | SandboxStatus::Draining | SandboxStatus::Paused
    )
}

fn format_mib(mib: u32) -> String {
    if mib >= 1024 && mib.is_multiple_of(1024) {
        format!("{} GiB", mib / 1024)
    } else {
        format!("{mib} MiB")
    }
}

/// Render a resource row value, inlining any pending next-start divergence.
///
/// With no pending change the plain (desired) value is shown as-is. With one, the ACTIVE value leads and a dim `→ <desired> next start` suffix flags the divergence.
fn resource_value(plain: &str, change: Option<&PendingConfigChange>) -> String {
    match change {
        Some(change) => format!(
            "{}{}",
            change.active,
            style(format!(" \u{2192} {} next start", change.desired)).dim()
        ),
        None => plain.to_string(),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn config(cpus: u8, memory_mib: u32) -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.spec.resources.cpus = cpus;
        config.spec.resources.memory_mib = memory_mib;
        config.spec.resources.max_cpus = cpus;
        config.spec.resources.max_memory_mib = memory_mib;
        config
    }

    #[test]
    fn pending_config_changes_compare_running_active_and_desired_resources() {
        let desired = config(4, 4096);
        let active = config(2, 1024);

        let changes = pending_config_changes(SandboxStatus::Running, Some(&desired), Some(&active));

        assert_eq!(changes.len(), 4);
        assert_eq!(changes[0].field, "cpus");
        assert_eq!(changes[0].active, "2");
        assert_eq!(changes[0].desired, "4");
        assert_eq!(changes[1].field, "max_cpus");
        assert_eq!(changes[1].active, "2");
        assert_eq!(changes[1].desired, "4");
        assert_eq!(changes[2].field, "memory");
        assert_eq!(changes[2].active, "1 GiB");
        assert_eq!(changes[2].desired, "4 GiB");
        assert_eq!(changes[3].field, "max_memory");
        assert_eq!(changes[3].active, "1 GiB");
        assert_eq!(changes[3].desired, "4 GiB");
    }

    #[test]
    fn resource_value_inlines_pending_divergence() {
        let change = PendingConfigChange {
            field: "memory",
            active: "1 GiB".to_string(),
            desired: "4 GiB".to_string(),
            effect: "requires restart",
        };

        assert_eq!(resource_value("4096 MiB", None), "4096 MiB");

        let rendered = resource_value("4096 MiB", Some(&change));
        let plain = console::strip_ansi_codes(&rendered).to_string();
        assert_eq!(plain, "1 GiB \u{2192} 4 GiB next start");
        assert!(rendered.starts_with("1 GiB"));
    }

    #[test]
    fn pending_config_changes_ignore_stopped_sandboxes() {
        let desired = config(4, 4096);
        let active = config(2, 1024);

        let changes = pending_config_changes(SandboxStatus::Stopped, Some(&desired), Some(&active));

        assert!(changes.is_empty());
    }
}
