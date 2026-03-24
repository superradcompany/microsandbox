//! `msb volume` command — manage named volumes.

use clap::{Args, Subcommand};
use microsandbox::volume::Volume;

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
    /// Create a new volume.
    Create(VolumeCreateArgs),

    /// List all volumes.
    #[command(visible_alias = "ls")]
    List(VolumeListArgs),

    /// Show detailed volume information.
    Inspect(VolumeInspectArgs),

    /// Remove a volume.
    #[command(visible_alias = "rm")]
    Remove(VolumeRemoveArgs),
}

/// Arguments for `msb volume create`.
#[derive(Debug, Args)]
pub struct VolumeCreateArgs {
    /// Volume name.
    pub name: String,

    /// Size quota (e.g., "10G", "512M").
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
    /// Volume name.
    pub name: String,
}

/// Arguments for `msb volume remove`.
#[derive(Debug, Args)]
pub struct VolumeRemoveArgs {
    /// Name(s) of the volume(s) to remove.
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
    let mut builder = Volume::builder(&args.name);

    if let Some(ref size) = args.size {
        let mib = crate::ui::parse_size_mib(size).map_err(anyhow::Error::msg)?;
        builder = builder.quota(mib);
    }

    builder.create().await?;

    if !args.quiet {
        println!("{}", args.name);
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
                    "quota_mib": v.quota_mib(),
                    "used_bytes": v.used_bytes(),
                    "created_at": v.created_at().map(|dt| ui::format_datetime(&dt)),
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

    let mut table = ui::Table::new(&["NAME", "QUOTA", "CREATED"]);

    for v in &volumes {
        let quota = v
            .quota_mib()
            .map(format_mib)
            .unwrap_or_else(|| "-".to_string());
        let created = v
            .created_at()
            .as_ref()
            .map(ui::format_datetime)
            .unwrap_or_else(|| "-".to_string());

        table.add_row(vec![v.name().to_string(), quota, created]);
    }

    table.print();
    Ok(())
}

async fn inspect(args: VolumeInspectArgs) -> anyhow::Result<()> {
    let handle = Volume::get(&args.name).await?;

    let quota = handle
        .quota_mib()
        .map(format_mib)
        .unwrap_or_else(|| "unlimited".to_string());
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

    let volumes_dir = microsandbox::config::config().volumes_dir();
    let path = volumes_dir.join(handle.name());

    ui::detail_kv("Name", handle.name());
    ui::detail_kv("Quota", &quota);
    ui::detail_kv("Created", &created);
    ui::detail_kv("Path", &path.display().to_string());
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
                spinner.finish_error();
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
