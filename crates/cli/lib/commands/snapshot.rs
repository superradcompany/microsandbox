//! `msb snapshot` command — manage disk snapshots.

use clap::{Args, Subcommand};
use microsandbox::Snapshot;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Manage disk snapshots.
#[derive(Debug, Args)]
pub struct SnapshotArgs {
    /// Snapshot subcommand.
    #[command(subcommand)]
    pub command: SnapshotCommands,
}

/// Snapshot subcommands.
#[derive(Debug, Subcommand)]
pub enum SnapshotCommands {
    /// Create a snapshot from a stopped sandbox.
    Create(SnapshotCreateArgs),

    /// List indexed snapshots.
    #[command(visible_alias = "ls")]
    List(SnapshotListArgs),

    /// Show detailed snapshot information.
    Inspect(SnapshotInspectArgs),

    /// Verify recorded snapshot content integrity.
    Verify(SnapshotVerifyArgs),

    /// Delete one or more snapshots.
    #[command(visible_alias = "rm")]
    Remove(SnapshotRemoveArgs),

    /// Rebuild the local index from artifacts on disk.
    Reindex(SnapshotReindexArgs),

    /// Save a snapshot into a `.tar.zst` archive.
    Save(SnapshotSaveArgs),

    /// Load a snapshot archive into the snapshots directory.
    Load(SnapshotLoadArgs),
}

/// Arguments for `msb snapshot create`.
#[derive(Debug, Args)]
pub struct SnapshotCreateArgs {
    /// Snapshot name, resolved under `~/.microsandbox/snapshots/<name>/`
    /// (or under `--dest-dir` when given).
    pub name: String,

    /// Source sandbox name. Must be stopped (or crashed).
    #[arg(long, value_name = "SANDBOX")]
    pub from: String,

    /// Parent directory to create the artifact in, instead of the
    /// default snapshots directory. The artifact lands at `DIR/<name>`.
    #[arg(long = "dest-dir", value_name = "DIR")]
    pub dest_dir: Option<std::path::PathBuf>,

    /// Add a `key=value` label. May be repeated.
    #[arg(long = "label", value_name = "K=V")]
    pub labels: Vec<String>,

    /// Overwrite an existing artifact at the destination.
    #[arg(short = 'f', long)]
    pub force: bool,

    /// Compute and record content integrity while creating the snapshot.
    #[arg(long)]
    pub integrity: bool,

    /// Request a resumable snapshot with memory/device state.
    ///
    /// This flag is reserved by the public contract. Current runtimes
    /// return an unsupported-feature error instead of creating a
    /// misleading disk-only artifact.
    #[arg(long)]
    pub resumable: bool,

    /// Suppress output.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Arguments for `msb snapshot list`.
#[derive(Debug, Args)]
pub struct SnapshotListArgs {
    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_parser = ["json"])]
    pub format: Option<String>,

    /// Show only digests.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Arguments for `msb snapshot inspect`.
#[derive(Debug, Args)]
pub struct SnapshotInspectArgs {
    /// Snapshot to inspect (path, name, or digest).
    pub snapshot: String,

    /// Also verify recorded content integrity.
    #[arg(long)]
    pub verify: bool,
}

/// Arguments for `msb snapshot verify`.
#[derive(Debug, Args)]
pub struct SnapshotVerifyArgs {
    /// Snapshot to verify (path, name, or digest).
    pub snapshot: String,
}

/// Arguments for `msb snapshot remove`.
#[derive(Debug, Args)]
pub struct SnapshotRemoveArgs {
    /// Snapshot(s) to remove (path, name, or digest).
    #[arg(required = true)]
    pub snapshots: Vec<String>,

    /// Remove even if the snapshot has indexed children.
    #[arg(short = 'f', long)]
    pub force: bool,

    /// Suppress output.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Arguments for `msb snapshot reindex`.
#[derive(Debug, Args)]
pub struct SnapshotReindexArgs {
    /// Directory to scan (defaults to `~/.microsandbox/snapshots/`).
    pub dir: Option<std::path::PathBuf>,
}

/// Arguments for `msb snapshot save`.
#[derive(Debug, Args)]
pub struct SnapshotSaveArgs {
    /// Snapshot to save (path, name, or digest).
    pub snapshot: String,

    /// Output archive path (`.tar.zst` recommended).
    pub out: std::path::PathBuf,

    /// Walk the parent chain and include each ancestor in the archive.
    #[arg(long)]
    pub with_parents: bool,

    /// Include the OCI image artifacts (EROFS layers + VMDK) so the
    /// archive boots offline on the target machine.
    #[arg(long)]
    pub with_image: bool,

    /// Write a plain `.tar` instead of `.tar.zst`. Tradeoff: smaller
    /// CPU but much larger file for sparse uppers.
    #[arg(long)]
    pub plain_tar: bool,
}

/// Arguments for `msb snapshot load`.
#[derive(Debug, Args)]
pub struct SnapshotLoadArgs {
    /// Archive to unpack.
    pub archive: std::path::PathBuf,

    /// Destination directory (defaults to `~/.microsandbox/snapshots/`).
    pub dest: Option<std::path::PathBuf>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb snapshot` command.
pub async fn run(args: SnapshotArgs) -> anyhow::Result<()> {
    match args.command {
        SnapshotCommands::Create(args) => create(args).await,
        SnapshotCommands::List(args) => list(args).await,
        SnapshotCommands::Inspect(args) => inspect(args).await,
        SnapshotCommands::Verify(args) => verify(args).await,
        SnapshotCommands::Remove(args) => remove(args).await,
        SnapshotCommands::Reindex(args) => reindex(args).await,
        SnapshotCommands::Save(args) => save(args).await,
        SnapshotCommands::Load(args) => load(args).await,
    }
}

async fn create(args: SnapshotCreateArgs) -> anyhow::Result<()> {
    let mut builder = Snapshot::builder(&args.name).from_sandbox(&args.from);
    if let Some(ref dest_dir) = args.dest_dir {
        builder = builder.dest_dir(dest_dir);
    }
    for label in &args.labels {
        let (k, v) = label
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("invalid --label '{label}': expected K=V"))?;
        builder = builder.label(k, v);
    }
    if args.force {
        builder = builder.force();
    }
    if args.integrity {
        builder = builder.record_integrity();
    }
    if args.resumable {
        builder = builder.resumable();
    }

    let spinner = if args.quiet {
        ui::Spinner::quiet()
    } else {
        ui::Spinner::start("Snapshotting", &args.from)
    };

    match builder.create().await {
        Ok(snap) => {
            spinner.finish_success("Snapshotted");
            if !args.quiet {
                println!("{}", snap.digest());
                println!("{}", snap.path().display());
            }
            Ok(())
        }
        Err(e) => {
            spinner.finish_clear();
            Err(e.into())
        }
    }
}

async fn list(args: SnapshotListArgs) -> anyhow::Result<()> {
    let snapshots = Snapshot::list().await?;

    if args.format.as_deref() == Some("json") {
        let entries: Vec<serde_json::Value> = snapshots
            .iter()
            .map(|s| {
                serde_json::json!({
                    "digest": s.digest(),
                    "name": s.name(),
                    "parent_digest": s.parent_digest(),
                    "scope": format_scope(s.scope()),
                    "image_ref": s.image_ref(),
                    "format": format_str(s.format()),
                    "size_bytes": s.size_bytes(),
                    "created_at": ui::format_json_datetime(&s.created_at().and_utc()),
                    "artifact_path": s.path().display().to_string(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }

    if args.quiet {
        for s in &snapshots {
            println!("{}", s.digest());
        }
        return Ok(());
    }

    if snapshots.is_empty() {
        eprintln!("No snapshots indexed.");
        return Ok(());
    }

    let mut table = ui::Table::new(&["NAME", "SCOPE", "IMAGE", "SIZE", "CREATED", "DIGEST"]);
    for s in &snapshots {
        let name = s.name().unwrap_or("-").to_string();
        let size = s
            .size_bytes()
            .map(format_size)
            .unwrap_or_else(|| "-".to_string());
        let created = ui::format_datetime(&s.created_at().and_utc());
        let digest = short_digest(s.digest());
        table.add_row(vec![
            name,
            format_scope(s.scope()).to_string(),
            s.image_ref().to_string(),
            size,
            created,
            digest,
        ]);
    }
    table.print();
    Ok(())
}

async fn inspect(args: SnapshotInspectArgs) -> anyhow::Result<()> {
    let snap = Snapshot::open(&args.snapshot).await?;
    let m = snap.manifest();

    ui::detail_kv("Digest", snap.digest());
    ui::detail_kv("Path", &snap.path().display().to_string());
    ui::detail_kv("Image", &m.image.reference);
    ui::detail_kv("Image Manifest", &m.image.manifest_digest);
    ui::detail_kv("Scope", format_scope(m.scope));
    ui::detail_kv("Format", format_str(snap.manifest().format));
    ui::detail_kv("Filesystem", &m.fstype);
    ui::detail_kv("Parent", m.parent.as_deref().unwrap_or("-"));
    ui::detail_kv("Created", &ui::format_rfc3339_datetime(&m.created_at)?);
    ui::detail_kv("Upper File", &m.upper.file);
    ui::detail_kv("Upper Size", &format_size(m.upper.size_bytes));
    ui::detail_kv("Integrity", &format_integrity(m.upper.integrity.as_ref()));
    if !m.requires.is_empty() {
        ui::detail_kv("Requires", &m.requires.join(", "));
        let unsupported = m.unsupported_requires();
        if !unsupported.is_empty() {
            ui::detail_kv(
                "Restore",
                &format!("blocked: needs {}", unsupported.join(", ")),
            );
        }
    }
    if args.verify {
        let report = snap.verify().await?;
        ui::detail_kv("Verification", &format_verify_status(&report.upper));
    }
    if let Some(ref src) = m.source_sandbox {
        ui::detail_kv("Source Sandbox", src);
    }
    if !m.labels.is_empty() {
        let labels = m
            .labels
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ");
        ui::detail_kv("Labels", &labels);
    }
    Ok(())
}

async fn verify(args: SnapshotVerifyArgs) -> anyhow::Result<()> {
    let snap = Snapshot::open(&args.snapshot).await?;
    let report = snap.verify().await?;
    ui::detail_kv("Digest", &report.digest);
    ui::detail_kv("Path", &report.path.display().to_string());
    ui::detail_kv("Verification", &format_verify_status(&report.upper));
    Ok(())
}

async fn remove(args: SnapshotRemoveArgs) -> anyhow::Result<()> {
    let mut failed = false;
    for s in &args.snapshots {
        let spinner = if args.quiet {
            ui::Spinner::quiet()
        } else {
            ui::Spinner::start("Removing", s)
        };
        match Snapshot::remove(s, args.force).await {
            Ok(()) => spinner.finish_success("Removed"),
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

async fn reindex(args: SnapshotReindexArgs) -> anyhow::Result<()> {
    let dir = match args.dir {
        Some(d) => d,
        None => {
            let backend = crate::commands::common::resolve_local_backend()?;
            let local = crate::commands::common::local_backend_ref(&backend)?;
            local.snapshots_dir()
        }
    };
    let n = Snapshot::reindex(&dir).await?;
    println!("indexed {n} snapshot(s) from {}", dir.display());
    Ok(())
}

async fn save(args: SnapshotSaveArgs) -> anyhow::Result<()> {
    let opts = microsandbox::snapshot::SaveOpts {
        with_parents: args.with_parents,
        with_image: args.with_image,
        plain_tar: args.plain_tar,
    };
    Snapshot::save(&args.snapshot, &args.out, opts).await?;
    println!("{}", args.out.display());
    Ok(())
}

async fn load(args: SnapshotLoadArgs) -> anyhow::Result<()> {
    let handle = Snapshot::load(&args.archive, args.dest.as_deref()).await?;
    println!("{}", handle.digest());
    println!("{}", handle.path().display());
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn format_str(f: microsandbox::SnapshotFormat) -> &'static str {
    match f {
        microsandbox::SnapshotFormat::Raw => "raw",
        microsandbox::SnapshotFormat::Qcow2 => "qcow2",
    }
}

fn format_scope(scope: microsandbox::SnapshotScope) -> &'static str {
    match scope {
        microsandbox::SnapshotScope::Disk => "disk",
        microsandbox::SnapshotScope::Resumable => "resumable",
    }
}

fn format_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn short_digest(d: &str) -> String {
    if let Some(hex) = d.strip_prefix("sha256:") {
        format!("sha256:{}", &hex[..hex.len().min(12)])
    } else {
        d.chars().take(20).collect()
    }
}

fn format_integrity(integrity: Option<&microsandbox::UpperIntegrity>) -> String {
    match integrity {
        Some(integrity) => format!("{} {}", integrity.algorithm, integrity.digest),
        None => "not recorded".into(),
    }
}

fn format_verify_status(status: &microsandbox::snapshot::UpperVerifyStatus) -> String {
    match status {
        microsandbox::snapshot::UpperVerifyStatus::NotRecorded => {
            "not recorded (metadata checks only)".into()
        }
        microsandbox::snapshot::UpperVerifyStatus::Verified { algorithm, digest } => {
            format!("verified ({algorithm} {digest})")
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(flatten)]
        args: SnapshotArgs,
    }

    fn parse_snapshot_args(args: &[&str]) -> SnapshotArgs {
        TestCli::parse_from(std::iter::once("msb").chain(args.iter().copied())).args
    }

    #[test]
    fn create_parses_resumable_contract_flag() {
        let args = parse_snapshot_args(&["create", "clean", "--from", "box", "--resumable"]);
        let SnapshotCommands::Create(args) = args.command else {
            panic!("expected create command");
        };
        assert_eq!(args.name, "clean");
        assert_eq!(args.from, "box");
        assert!(args.resumable);
    }

    #[test]
    fn create_parses_dest_dir() {
        let args =
            parse_snapshot_args(&["create", "clean", "--from", "box", "--dest-dir", "/mnt/big"]);
        let SnapshotCommands::Create(args) = args.command else {
            panic!("expected create command");
        };
        assert_eq!(
            args.dest_dir.as_deref(),
            Some(std::path::Path::new("/mnt/big"))
        );
    }

    #[test]
    fn reindex_parses_dir() {
        let parsed = parse_snapshot_args(&["reindex", "/tmp/snaps"]);
        let SnapshotCommands::Reindex(args) = parsed.command else {
            panic!("expected reindex command");
        };
        assert_eq!(
            args.dir.as_deref(),
            Some(std::path::Path::new("/tmp/snaps"))
        );
    }

    #[test]
    fn save_parses_args() {
        let parsed = parse_snapshot_args(&["save", "clean", "bundle.tar", "--plain-tar"]);
        let SnapshotCommands::Save(args) = parsed.command else {
            panic!("expected save command");
        };
        assert_eq!(args.snapshot, "clean");
        assert_eq!(args.out, std::path::PathBuf::from("bundle.tar"));
        assert!(args.plain_tar);
    }

    #[test]
    fn load_parses_args() {
        let parsed = parse_snapshot_args(&["load", "bundle.tar", "/tmp/snaps"]);
        let SnapshotCommands::Load(args) = parsed.command else {
            panic!("expected load command");
        };
        assert_eq!(args.archive, std::path::PathBuf::from("bundle.tar"));
        assert_eq!(
            args.dest.as_deref(),
            Some(std::path::Path::new("/tmp/snaps"))
        );
    }
}
