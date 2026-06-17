//! `msb volume` command — manage named volumes.

use clap::{Args, Subcommand};
use microsandbox::volume::{Volume, VolumeKind};

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Manage named volumes.
#[derive(Debug, Args)]
pub struct VolumeArgs {
    /// Volume subcommand.
    #[command(subcommand)]
    pub command: VolumeCommands,
}

/// Volume subcommands.
#[derive(Debug, Subcommand)]
pub enum VolumeCommands {
    /// Create a new named volume.
    Create(VolumeCreateArgs),

    /// List all volumes.
    #[command(visible_alias = "ls")]
    List(VolumeListArgs),

    /// Show detailed volume information.
    Inspect(VolumeInspectArgs),

    /// Delete one or more volumes.
    #[command(visible_alias = "rm")]
    Remove(VolumeRemoveArgs),
}

/// Arguments for `msb volume create`.
#[derive(Debug, Args)]
pub struct VolumeCreateArgs {
    /// Name for the new volume.
    pub positional_name: Option<String>,

    /// Name for the new volume.
    #[arg(long)]
    pub name: Option<String>,

    /// Volume kind.
    #[arg(long, value_name = "KIND", value_parser = ["dir", "disk"], default_value = "dir")]
    pub kind: String,

    /// Disk capacity for disk volumes (e.g. 10G, 512M).
    #[arg(long)]
    pub size: Option<String>,

    /// Suppress output.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Arguments for `msb volume list`.
#[derive(Debug, Args)]
pub struct VolumeListArgs {
    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_parser = ["json"])]
    pub format: Option<String>,

    /// Show only volume names.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Arguments for `msb volume inspect`.
#[derive(Debug, Args)]
pub struct VolumeInspectArgs {
    /// Volume to inspect.
    pub name: String,
}

/// Arguments for `msb volume remove`.
#[derive(Debug, Args)]
pub struct VolumeRemoveArgs {
    /// Volume(s) to remove.
    #[arg(required = true)]
    pub names: Vec<String>,

    /// Suppress output.
    #[arg(short, long)]
    pub quiet: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb volume` command.
pub async fn run(args: VolumeArgs) -> anyhow::Result<()> {
    match args.command {
        VolumeCommands::Create(args) => create(args).await,
        VolumeCommands::List(args) => list(args).await,
        VolumeCommands::Inspect(args) => inspect(args).await,
        VolumeCommands::Remove(args) => remove(args).await,
    }
}

async fn create(args: VolumeCreateArgs) -> anyhow::Result<()> {
    let name = resolve_create_volume_name(&args)?;
    let mut builder = Volume::builder(name);
    let kind = parse_volume_kind(&args.kind)?;

    match kind {
        VolumeKind::Directory => {
            builder = builder.directory();
            if args.size.is_some() {
                anyhow::bail!(
                    "--size is only supported with --kind disk until directory quotas are enforced"
                );
            }
        }
        VolumeKind::Disk => {
            builder = builder.disk();
            let size = args
                .size
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--size is required with --kind disk"))?;
            let mib = crate::ui::parse_size_mib(size).map_err(anyhow::Error::msg)?;
            builder = builder.size(mib);
        }
    }

    builder.create().await?;

    if !args.quiet {
        println!("{name}");
    }

    Ok(())
}

async fn list(args: VolumeListArgs) -> anyhow::Result<()> {
    let volumes = Volume::list().await?;

    if args.format.as_deref() == Some("json") {
        let entries: Vec<serde_json::Value> = volumes
            .iter()
            .map(|v| {
                serde_json::json!({
                    "name": v.name(),
                    "kind": v.kind().as_str(),
                    "quota_mib": v.quota_mib(),
                    "used_bytes": v.used_bytes(),
                    "capacity_bytes": v.capacity_bytes(),
                    "disk_format": v.disk_format(),
                    "disk_fstype": v.disk_fstype(),
                    "created_at": v.created_at().map(|dt| ui::format_json_datetime(&dt)),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }

    if args.quiet {
        for v in &volumes {
            println!("{}", v.name());
        }
        return Ok(());
    }

    if volumes.is_empty() {
        eprintln!("No volumes found.");
        return Ok(());
    }

    let mut table = ui::Table::new(&["NAME", "KIND", "SIZE", "CREATED"]);

    for v in &volumes {
        let size = match v.kind() {
            VolumeKind::Directory => v
                .quota_mib()
                .map(format_mib)
                .unwrap_or_else(|| "-".to_string()),
            VolumeKind::Disk => v
                .capacity_bytes()
                .map(format_bytes)
                .unwrap_or_else(|| "-".to_string()),
        };
        let created = v
            .created_at()
            .as_ref()
            .map(ui::format_datetime)
            .unwrap_or_else(|| "-".to_string());

        table.add_row(vec![
            v.name().to_string(),
            v.kind().as_str().to_string(),
            size,
            created,
        ]);
    }

    table.print();
    Ok(())
}

async fn inspect(args: VolumeInspectArgs) -> anyhow::Result<()> {
    let handle = Volume::get(&args.name).await?;

    let created = handle
        .created_at()
        .as_ref()
        .map(ui::format_datetime)
        .unwrap_or_else(|| "-".to_string());

    let labels = handle.labels();
    let labels_str = if labels.is_empty() {
        "-".to_string()
    } else {
        labels
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ")
    };

    let backend = crate::commands::common::resolve_local_backend()?;
    let local = crate::commands::common::local_backend_ref(&backend)?;
    let path = local.volume_path(handle.name());

    ui::detail_kv("Name", handle.name());
    ui::detail_kv("Kind", handle.kind().as_str());
    match handle.kind() {
        VolumeKind::Directory => {
            let quota = handle
                .quota_mib()
                .map(format_mib)
                .unwrap_or_else(|| "unlimited".to_string());
            ui::detail_kv("Quota", &quota);
            ui::detail_kv("Path", &path.display().to_string());
        }
        VolumeKind::Disk => {
            ui::detail_kv("Format", handle.disk_format().unwrap_or("raw"));
            ui::detail_kv("Filesystem", handle.disk_fstype().unwrap_or("ext4"));
            let capacity = handle
                .capacity_bytes()
                .map(format_bytes)
                .unwrap_or_else(|| "-".to_string());
            ui::detail_kv("Capacity", &capacity);
            let disk_path = handle.disk_path().unwrap_or_else(|| path.join("disk.raw"));
            ui::detail_kv("Path", &disk_path.display().to_string());
        }
    }
    ui::detail_kv("Created", &created);
    ui::detail_kv("Labels", &labels_str);

    Ok(())
}

async fn remove(args: VolumeRemoveArgs) -> anyhow::Result<()> {
    let mut failed = false;

    for name in &args.names {
        let spinner = if args.quiet {
            ui::Spinner::quiet()
        } else {
            ui::Spinner::start("Removing", name)
        };

        match Volume::remove(name).await {
            Ok(()) => {
                spinner.finish_success("Removed");
            }
            Err(e) => {
                spinner.finish_clear();
                if !args.quiet {
                    ui::error(&format!("{e}"));
                }
                failed = true;
            }
        }
    }

    if failed {
        std::process::exit(1);
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Format MiB as a human-readable string.
fn format_mib(mib: u32) -> String {
    if mib >= 1024 && mib.is_multiple_of(1024) {
        format!("{} GiB", mib / 1024)
    } else {
        format!("{mib} MiB")
    }
}

fn format_bytes(bytes: u64) -> String {
    let mib = bytes / (1024 * 1024);
    format_mib(mib as u32)
}

fn parse_volume_kind(kind: &str) -> anyhow::Result<VolumeKind> {
    match kind {
        "dir" => Ok(VolumeKind::Directory),
        "disk" => Ok(VolumeKind::Disk),
        _ => anyhow::bail!("unknown volume kind: {kind}"),
    }
}

fn resolve_create_volume_name(args: &VolumeCreateArgs) -> anyhow::Result<&str> {
    match (args.positional_name.as_deref(), args.name.as_deref()) {
        (Some(positional), Some(flag)) if positional != flag => {
            anyhow::bail!(
                "volume name specified twice with different values: {positional} and {flag}"
            )
        }
        (Some(name), _) | (_, Some(name)) => Ok(name),
        (None, None) => anyhow::bail!("volume create requires a name"),
    }
}
