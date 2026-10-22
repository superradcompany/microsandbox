//! `msb snapshot` command — capture, restore, and manage snapshots.

use std::collections::BTreeSet;
use std::path::PathBuf;

use clap::{Args, Subcommand};
use microsandbox::{Checkpoint as Snapshot, Snapshot as SnapshotGroup, SnapshotReference};
use microsandbox_utils::format::format_bytes;

use crate::{
    commands::restore::{self, RestoreArgs},
    ui::{self, OutputFormat},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Capture, restore, and manage disk or full snapshots.
#[derive(Debug, Args)]
#[command(
    after_help = "Examples:\n  msb snap create templates --sandbox app --name ready\n  msb snap checkpoint templates --name next\n  msb snap list templates\n  msb snap modify templates --set-head ready\n  msb snap export templates --output ready.msb\n\n'snap' and 'snapshot' are equivalent. Live forking uses 'msb fork'."
)]
pub struct SnapshotArgs {
    /// Snapshot subcommand.
    #[command(subcommand)]
    pub command: SnapshotCommands,
}

/// Snapshot subcommands.
#[derive(Debug, Subcommand)]
pub enum SnapshotCommands {
    /// Create a group and its first checkpoint, or capture directly to an archive.
    Create(SnapshotCreateArgs),

    /// Append a checkpoint to an existing group from its bound source sandbox.
    Checkpoint(SnapshotCheckpointArgs),

    /// Restore saved state into a new sandbox running in the background.
    Restore(Box<RestoreArgs>),

    /// List groups, or checkpoints within a selected group.
    #[command(visible_alias = "ls")]
    List(SnapshotListArgs),

    /// Inspect a group or an explicitly selected checkpoint.
    Inspect(SnapshotInspectArgs),

    /// Verify recorded snapshot content integrity.
    Verify(SnapshotVerifyArgs),

    /// Remove an exact checkpoint or explicitly remove a whole group.
    #[command(visible_alias = "rm")]
    Remove(SnapshotRemoveArgs),

    /// Rebuild the local index from artifacts on disk.
    Reindex(SnapshotReindexArgs),

    /// Export a snapshot to a `.msb` archive (tar + zstd).
    #[command(name = "export", visible_alias = "save")]
    Save(SnapshotSaveArgs),

    /// Import snapshot archives into a local snapshot group.
    #[command(name = "import", visible_alias = "load")]
    Load(SnapshotLoadArgs),

    /// Read a group's selected head without changing it.
    Head(SnapshotHeadArgs),

    /// Select or clear a group's head without capturing a checkpoint.
    Modify(SnapshotModifyArgs),
}

/// Arguments for `msb snapshot create`.
#[derive(Debug, Args)]
#[command(
    after_help = "Create a new bound group, or capture directly to an archive without installing a group.\n\nExamples:\n  msb snap create templates --sandbox app --name ready\n  msb snap create --sandbox app -o ready.msb\n\nUse checkpoint to append to an existing group."
)]
pub struct SnapshotCreateArgs {
    /// New snapshot group; mutually exclusive with --output.
    #[arg(
        value_name = "GROUP",
        required_unless_present = "output",
        conflicts_with = "output"
    )]
    pub group: Option<String>,

    /// Sandbox to capture.
    #[arg(long, alias = "from-sandbox", value_name = "SANDBOX")]
    pub sandbox: String,

    /// Initial checkpoint name; generated when omitted.
    #[arg(short, long, value_name = "NAME")]
    pub name: Option<String>,

    /// Parent directory to create the artifact in, instead of the
    /// default snapshots directory. The group is created under this root.
    #[arg(long = "dest-dir", value_name = "DIR")]
    pub dest_dir: Option<PathBuf>,

    /// Write directly to an archive without installing a snapshot directory.
    #[arg(short = 'o', long, value_name = "PATH", conflicts_with = "dest_dir")]
    pub output: Option<PathBuf>,

    /// Write a plain tar archive instead of zstd-compressed tar.
    #[arg(long, requires = "output", conflicts_with = "group")]
    pub plain_tar: bool,

    /// Add a `key=value` label. May be repeated.
    #[arg(long = "label", value_name = "K=V")]
    pub labels: Vec<String>,

    /// Overwrite an existing archive file; installed group members are immutable.
    #[arg(short = 'f', long, requires = "output", conflicts_with = "group")]
    pub force: bool,

    /// Compute and record content integrity while creating the snapshot.
    #[arg(long)]
    pub integrity: bool,

    /// Capture disk, memory, execution, and device state from a running sandbox.
    #[arg(long)]
    pub full: bool,
    /// Guest writeback: auto (disk-only default), required, or skip. Mandatory barriers remain.
    #[arg(long, default_value = "auto")]
    pub guest_flush: microsandbox::snapshot::GuestFlush,

    /// Suppress output.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Arguments for source-bound checkpoint capture. A sandbox is a selector, never a rebind.
#[derive(Debug, Args)]
pub struct SnapshotCheckpointArgs {
    /// Existing snapshot group. Required unless --sandbox is supplied.
    #[arg(value_name = "GROUP", required_unless_present = "sandbox")]
    pub group: Option<String>,

    /// Select this sandbox's sole associated group, or verify the explicit group's source.
    #[arg(long, value_name = "SANDBOX")]
    pub sandbox: Option<String>,

    /// Checkpoint name within the group; generated when omitted.
    #[arg(short, long, value_name = "NAME")]
    pub name: Option<String>,

    /// Group-store root instead of the configured snapshot directory.
    #[arg(long = "dest-dir", value_name = "DIR")]
    pub dest_dir: Option<PathBuf>,

    /// Add a key=value label. May be repeated.
    #[arg(long = "label", value_name = "K=V")]
    pub labels: Vec<String>,

    /// Record content integrity for the checkpoint.
    #[arg(long)]
    pub integrity: bool,

    /// Include memory, execution, and device state.
    #[arg(long)]
    pub full: bool,

    /// Guest writeback policy. Mandatory capture barriers remain enforced.
    #[arg(long, default_value = "auto")]
    pub guest_flush: microsandbox::snapshot::GuestFlush,

    /// Suppress output.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Arguments for `msb snapshot list`.
#[derive(Debug, Args)]
pub struct SnapshotListArgs {
    /// List checkpoints in this group; omit to list groups.
    #[arg(value_name = "GROUP")]
    pub group: Option<String>,

    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_enum)]
    pub format: Option<OutputFormat>,

    /// Show only group names or checkpoint IDs.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Arguments for `msb snapshot inspect`.
#[derive(Debug, Args)]
pub struct SnapshotInspectArgs {
    /// Group to inspect, or the group containing an explicitly selected checkpoint.
    #[arg(value_name = "GROUP")]
    pub snapshot: String,

    /// Inspect this group-local member name or ID instead of the history.
    #[arg(long)]
    pub checkpoint: Option<String>,

    /// Also verify the selected checkpoint; use `verify GROUP --all` for a whole history.
    #[arg(long, requires = "checkpoint")]
    pub verify: bool,
}

/// Arguments for `msb snapshot verify`.
#[derive(Debug, Args)]
pub struct SnapshotVerifyArgs {
    /// Snapshot group whose head, exact member, or whole history should be verified.
    pub snapshot: String,

    /// Verify this group-local checkpoint name or ID instead of head.
    #[arg(long, conflicts_with = "all")]
    pub checkpoint: Option<String>,

    /// Verify all members, including when the group has no selected head.
    #[arg(short = 'a', long)]
    pub all: bool,
}

/// Arguments for `msb snapshot remove`.
#[derive(Debug, Args)]
pub struct SnapshotRemoveArgs {
    /// Group containing the checkpoint or history to remove.
    #[arg(value_name = "GROUP")]
    pub group: String,

    /// Exact group-local member name or ID; bare group removal is never implied.
    #[arg(long, required_unless_present = "all", conflicts_with = "all")]
    pub checkpoint: Option<String>,

    /// Remove the entire group, refusing surviving external dependents and active readers.
    #[arg(short = 'a', long, conflicts_with = "force")]
    pub all: bool,

    /// Allow indexed children when removing one checkpoint; never bypass reader protection.
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
    pub dir: Option<PathBuf>,
}

/// Arguments for `msb snapshot export` (also available as `save`).
#[derive(Debug, Args)]
pub struct SnapshotSaveArgs {
    /// Archive reader target: current or 0.7.8; unsupported required behavior is refused.
    #[arg(long, default_value = "current")]
    pub compatibility: microsandbox::ArchiveCompatibility,
    /// Group whose selected head to export.
    #[arg(value_name = "GROUP")]
    pub snapshot: String,

    /// Export this exact group-local checkpoint name or ID instead of head.
    #[arg(long, value_name = "MEMBER")]
    pub checkpoint: Option<String>,

    /// Legacy positional output archive path; alternatively use --output.
    #[arg(
        value_name = "OUT",
        required_unless_present = "output",
        conflicts_with = "output"
    )]
    pub out: Option<PathBuf>,

    /// Output archive path (`.msb` recommended; explicit filenames are preserved).
    #[arg(short = 'o', long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Walk the parent chain and include each ancestor in the archive.
    #[arg(long)]
    pub with_parents: bool,

    /// Include the OCI image artifacts (EROFS layers + VMDK) so the
    /// archive boots offline on the target machine.
    #[arg(long)]
    pub with_image: bool,

    /// Write plain tar instead of zstd-compressed tar. Tradeoff: smaller
    /// CPU but much larger file for sparse uppers.
    #[arg(long)]
    pub plain_tar: bool,
    /// Omit disk layers and RAM objects supplied by an exact base snapshot or standalone archive.
    #[arg(long, conflicts_with_all = ["last_layers", "with_parents"])]
    pub since: Option<String>,
    /// Export only the newest N sealed disk layers (load requires the omitted base).
    #[arg(long, conflicts_with = "with_parents", value_name = "N")]
    pub last_layers: Option<usize>,
}

/// Arguments for `msb snapshot import` (also available as `load`).
#[derive(Debug, Args)]
pub struct SnapshotLoadArgs {
    /// Destination snapshot group, created only when the complete batch commits.
    pub group: String,

    /// Archives to import together; dependencies are resolved regardless of argument order.
    #[arg(long = "file", required = true, num_args = 1.., value_name = "ARCHIVE")]
    pub archives: Vec<PathBuf>,

    /// Destination directory (defaults to `~/.microsandbox/snapshots/`).
    #[arg(long, value_name = "DIR")]
    pub dest: Option<PathBuf>,
    /// External base snapshot or standalone archive if batch/group members cannot supply dependencies.
    #[arg(long)]
    pub base: Option<String>,

    /// Select the batch's unique tip as head even if it is not a fast-forward.
    #[arg(long)]
    pub set_head: bool,
}

/// Arguments for `msb snapshot head`.
#[derive(Debug, Args)]
pub struct SnapshotHeadArgs {
    /// Group whose head to read.
    pub selector: String,

    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_enum)]
    pub format: Option<OutputFormat>,
}

/// Explicit head mutation. Bare modify and conflicting selections are refused by the parser.
#[derive(Debug, Args)]
pub struct SnapshotModifyArgs {
    /// Group whose head selection to change.
    pub group: String,
    /// Select an existing checkpoint by local name or stable ID.
    #[arg(
        long,
        value_name = "MEMBER",
        required_unless_present = "clear_head",
        conflicts_with = "clear_head"
    )]
    pub set_head: Option<String>,
    /// Clear selection while retaining all checkpoints.
    #[arg(long)]
    pub clear_head: bool,
    /// Emit the head mutation report as JSON.
    #[arg(long, value_parser = ["json"])]
    pub format: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SnapshotCreateArgs {
    fn snapshot_name(&self) -> &str {
        self.name.as_deref().unwrap_or_default()
    }
}

impl SnapshotSaveArgs {
    fn archive_path(&self) -> &std::path::Path {
        self.output
            .as_deref()
            .or(self.out.as_deref())
            .expect("clap requires an output archive path")
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb snapshot` command.
pub async fn run(args: SnapshotArgs) -> anyhow::Result<()> {
    match args.command {
        SnapshotCommands::Create(args) => create(args).await,
        SnapshotCommands::Checkpoint(args) => checkpoint(args).await,
        SnapshotCommands::Restore(args) => restore::run(*args, None).await,
        SnapshotCommands::List(args) => list(args).await,
        SnapshotCommands::Inspect(args) => inspect(args).await,
        SnapshotCommands::Verify(args) => verify(args).await,
        SnapshotCommands::Remove(args) => remove(args).await,
        SnapshotCommands::Reindex(args) => reindex(args).await,
        SnapshotCommands::Save(args) => save(args).await,
        SnapshotCommands::Load(args) => load(args).await,
        SnapshotCommands::Head(args) => head(args).await,
        SnapshotCommands::Modify(args) => modify(args).await,
    }
}

async fn checkpoint(args: SnapshotCheckpointArgs) -> anyhow::Result<()> {
    let labels = args
        .labels
        .iter()
        .map(|label| {
            label
                .split_once('=')
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .ok_or_else(|| anyhow::anyhow!("invalid --label '{label}': expected K=V"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let selector = args
        .group
        .as_deref()
        .or(args.sandbox.as_deref())
        .expect("clap requires a selector");
    let spinner = if args.quiet {
        ui::Spinner::quiet()
    } else {
        ui::Spinner::start("Checkpointing", selector)
    };
    let config = microsandbox::SnapshotConfig {
        name: args.name.unwrap_or_default(),
        group: args.group,
        source_sandbox: args.sandbox.unwrap_or_default(),
        dest_dir: args.dest_dir,
        labels,
        force: false,
        record_integrity: args.integrity,
        full: args.full,
        guest_flush: args.guest_flush,
    };
    let backend = microsandbox::backend::default_backend();
    match backend
        .snapshots()
        .checkpoint(backend.clone(), config)
        .await
    {
        Ok(checkpoint) => {
            spinner.finish_success("Checkpointed");
            if !args.quiet {
                if let Some(update) = checkpoint.head_update() {
                    report_head_update(update);
                }
                println!("{}", checkpoint.id());
                println!("{}", checkpoint.path()?.display());
            }
            Ok(())
        }
        Err(error) => {
            spinner.finish_clear();
            Err(error.into())
        }
    }
}

async fn create(args: SnapshotCreateArgs) -> anyhow::Result<()> {
    let source = args.sandbox.clone();
    let mut builder = Snapshot::builder(args.snapshot_name())
        .from_sandbox(&source)
        .guest_flush(args.guest_flush);
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
    if args.full {
        builder = builder.full();
    }

    let spinner = if args.quiet {
        ui::Spinner::quiet()
    } else {
        ui::Spinner::start("Snapshotting", &source)
    };

    if let Some(archive_path) = args.output.as_ref() {
        return match builder.create_archive(archive_path, args.plain_tar).await {
            Ok(archive) => {
                spinner.finish_success("Snapshotted");
                if !args.quiet {
                    println!("{}", archive.id());
                    println!("{}", archive.path().display());
                }
                Ok(())
            }
            Err(error) => {
                spinner.finish_clear();
                Err(error.into())
            }
        };
    }

    // Group creation never turns a name collision into append. The receiver also
    // carries the source row identity, protecting against same-name replacement.
    let config = builder.build()?;
    let source = microsandbox::Sandbox::get(&source).await?;
    let mut options = microsandbox::SnapshotCaptureOptions::default()
        .initial_checkpoint(config.name)
        .guest_flush(config.guest_flush);
    if config.full {
        options = options.full();
    }
    if config.record_integrity {
        options = options.record_integrity();
    }
    if let Some(dest) = config.dest_dir {
        options = options.dest_dir(dest);
    }
    for (key, value) in config.labels {
        options = options.label(key, value);
    }
    match source
        .snapshot_with(
            args.group
                .as_deref()
                .expect("clap requires group or output"),
            |_| options,
        )
        .await
    {
        Ok(created) => {
            let snap = created.checkpoint;
            spinner.finish_success("Snapshotted");
            if !args.quiet {
                if let Some(update) = snap.head_update() {
                    report_head_update(update);
                }
                println!("{}", snap.id());
                println!("{}", format_reference(&snap.reference()));
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
    let Some(group_name) = args.group else {
        let groups = SnapshotGroup::list().await?;
        if args.quiet {
            for group in groups {
                println!("{}", group.name());
            }
            return Ok(());
        }
        let mut rows = Vec::new();
        for group in groups {
            let head = group.head().await?;
            let members = group.checkpoints().await?;
            rows.push(serde_json::json!({
                "name": group.name(),
                "head": head.as_ref().map(|checkpoint| checkpoint.id().as_str()),
                "count": members.len(),
            }));
        }
        if args.format == Some(OutputFormat::Json) {
            println!("{}", serde_json::to_string_pretty(&rows)?);
        } else if rows.is_empty() {
            eprintln!("No snapshot groups found.");
        } else {
            let mut table = ui::Table::new(&["NAME", "COUNT", "HEAD"]);
            for row in rows {
                table.add_row(vec![
                    row["name"].as_str().unwrap().into(),
                    row["count"].to_string(),
                    row["head"].as_str().unwrap_or("-").into(),
                ]);
            }
            table.print();
        }
        return Ok(());
    };
    let snapshots = SnapshotGroup::get(&group_name).await?.checkpoints().await?;

    if args.format == Some(OutputFormat::Json) {
        let entries: Vec<serde_json::Value> = snapshots
            .iter()
            .map(|s| {
                serde_json::json!({
                    "snapshot_id": s.id(),
                    "digest": s.digest(),
                    "name": s.name(),
                    "group": s.group(),
                    "parent_digest": s.parent_digest(),
                    "scope": format_scope(s.scope()),
                    "state_kind": s.state_kind(),
                    "image_ref": s.image_ref(),
                    "format": s.format().map(format_str),
                    "fstype": s.fstype(),
                    "checkpoint_manifest_digest": s.checkpoint_manifest_digest(),
                    "size_bytes": s.size_bytes(),
                    "locality": s.locality(),
                    "availability": s.availability(),
                    "migration_state": s.migration_state(),
                    "migration_error_code": s.migration_error_code(),
                    "created_at": ui::format_json_datetime(&s.created_at().and_utc()),
                    // Keep the released local JSON field without inventing a client-host
                    // path for snapshots held by a remote backend.
                    "artifact_path": s.path().ok().map(|path| path.display().to_string()),
                    "reference": format_reference(&s.reference()),
                    "reference_kind": s.reference().kind(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }

    if args.quiet {
        for s in &snapshots {
            println!("{}", s.id());
        }
        return Ok(());
    }

    if snapshots.is_empty() {
        eprintln!("No snapshots indexed.");
        return Ok(());
    }

    let mut table = ui::Table::new(&[
        "NAME",
        "SCOPE",
        "MIGRATION",
        "IMAGE",
        "SIZE",
        "CREATED",
        "DIGEST",
    ]);
    for s in &snapshots {
        let name = format_member_selector(s.group(), s.name(), s.id());
        let size = s
            .size_bytes()
            .map(format_bytes)
            .unwrap_or_else(|| "-".to_string());
        let created = ui::format_datetime(&s.created_at().and_utc());
        let digest = short_digest(s.digest());
        table.add_row(vec![
            name,
            format_scope(s.scope()).to_string(),
            s.migration_state().to_string(),
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
    let group = SnapshotGroup::get(&args.snapshot).await?;
    let Some(member) = args.checkpoint else {
        let info = group.inspect().await?;
        ui::detail_kv("Group", &info.name);
        ui::detail_kv("Path", &info.path.display().to_string());
        ui::detail_kv(
            "Head",
            info.head.as_ref().map(|head| head.as_str()).unwrap_or("-"),
        );
        ui::detail_kv("Checkpoints", &info.checkpoint_count.to_string());
        if let Some(source) = info.source {
            let status = match source.status {
                microsandbox::SnapshotSourceStatus::Available => "available",
                microsandbox::SnapshotSourceStatus::MissingSandbox => "missing sandbox",
                microsandbox::SnapshotSourceStatus::DifferentCatalog => "different catalog",
            };
            ui::detail_kv("Source", status);
            ui::detail_kv("Recorded Source", &source.recorded_name);
            ui::detail_kv(
                "Current Source",
                source.current_name.as_deref().unwrap_or("-"),
            );
            ui::detail_kv("Source ID", &source.sandbox_id.to_string());
            ui::detail_kv("Source Catalog", &source.database_uuid);
        } else {
            ui::detail_kv("Source", "unbound");
        }
        return Ok(());
    };
    let snap = group.get_checkpoint(&member).await?;
    let m = snap.manifest();

    ui::detail_kv("Snapshot ID", snap.id().as_str());
    ui::detail_kv("Descriptor Digest", snap.digest());
    ui::detail_kv("Reference", &format_reference(&snap.reference()));
    ui::detail_kv("Image", &m.image.reference);
    ui::detail_kv("Image Manifest", &m.image.manifest_digest);
    ui::detail_kv("Scope", format_scope(m.scope));
    ui::detail_kv("Root Disk", format_root_disk(&m.root_disk));
    ui::detail_kv(
        "Parent",
        m.parent
            .as_ref()
            .map(|parent| parent.as_str())
            .unwrap_or("-"),
    );
    ui::detail_kv(
        "Created",
        &ui::format_rfc3339_datetime(&m.capture.created_at)?,
    );
    match &m.state {
        microsandbox::SnapshotState::File(state) => {
            ui::detail_kv("State", "file");
            ui::detail_kv("Format", format_str(state.disk_format));
            ui::detail_kv("Filesystem", &state.filesystem);
            ui::detail_kv("Virtual Size", &format_bytes(state.virtual_size));
            ui::detail_kv("Layers", &state.layers.len().to_string());
            let integrity = state
                .layers
                .last()
                .and_then(|layer| layer.payload.integrity.as_ref());
            ui::detail_kv("Head Integrity", &format_integrity(&integrity.cloned()));
        }
        microsandbox::SnapshotState::Checkpoint(state) => {
            ui::detail_kv("State", "checkpoint");
            ui::detail_kv("Checkpoint", &state.checkpoint_id);
            ui::detail_kv("Checkpoint Root", &state.checkpoint_root);
        }
    }
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
        require_complete_verification(&report.coverage)?;
    }
    if let Some(ref src) = m.capture.source_lineage {
        ui::detail_kv("Source Sandbox", src);
    }
    if !snap.labels().is_empty() {
        let labels = snap
            .labels()
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(", ");
        ui::detail_kv("Labels", &labels);
    }
    match snap.storage_usage().await {
        Ok(usage) => super::storage::display_item(&usage),
        Err(error) => {
            ui::detail_header("Storage");
            ui::detail_kv_indent("Unavailable", &error.to_string());
        }
    }
    Ok(())
}

async fn verify(args: SnapshotVerifyArgs) -> anyhow::Result<()> {
    if args.all {
        let group = SnapshotGroup::get(&args.snapshot).await?;
        return match group.verify().await {
            Ok(report) => display_group_verification(&report),
            Err(microsandbox::MicrosandboxError::SnapshotVerification(report)) => {
                // Print the structured partial report before returning failure. A corrupt
                // sibling must not hide the results for the rest of the selected history.
                display_group_verification(&report)?;
                anyhow::bail!("snapshot group verification failed");
            }
            Err(error) => Err(error.into()),
        };
    }
    let snap = select_checkpoint(&args.snapshot, args.checkpoint.as_deref()).await?;
    let report = snap.verify().await?;
    ui::detail_kv("Digest", &report.digest);
    ui::detail_kv("Path", &report.path.display().to_string());
    if let Some(checkpoint) = report.checkpoint {
        ui::detail_kv(
            "Checkpoint",
            &format!(
                "metadata and recorded integrity verified ({})",
                checkpoint.root
            ),
        );
    } else {
        ui::detail_kv("Verification", &format_verify_status(&report.upper));
    }
    require_complete_verification(&report.coverage)
}

fn display_group_verification(
    report: &microsandbox::snapshot::SnapshotGroupVerifyReport,
) -> anyhow::Result<()> {
    use microsandbox::snapshot::SnapshotVerificationState;
    let state = |state| match state {
        SnapshotVerificationState::Complete => "complete",
        SnapshotVerificationState::Incomplete => "incomplete",
        SnapshotVerificationState::Invalid => "invalid",
        SnapshotVerificationState::Empty => "empty (0 checkpoints checked)",
    };
    ui::detail_kv("Group", &report.group);
    ui::detail_kv("Verification", state(report.state));
    ui::detail_kv(
        "Selected checkpoints",
        &report.checkpoints.len().to_string(),
    );
    for member in &report.checkpoints {
        ui::detail_header(
            &member
                .id
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| member.path.display().to_string()),
        );
        ui::detail_kv_indent("Verification", state(member.state));
        for finding in &member.findings {
            ui::detail_kv_indent(&finding.path.display().to_string(), &finding.detail);
        }
    }
    match report.state {
        SnapshotVerificationState::Complete | SnapshotVerificationState::Empty => Ok(()),
        SnapshotVerificationState::Incomplete => {
            anyhow::bail!("snapshot group verification incomplete")
        }
        SnapshotVerificationState::Invalid => anyhow::bail!("snapshot group verification failed"),
    }
}

fn require_complete_verification(
    coverage: &microsandbox::snapshot::SnapshotVerifyCoverage,
) -> anyhow::Result<()> {
    match coverage {
        microsandbox::snapshot::SnapshotVerifyCoverage::Complete => {
            ui::detail_kv("Coverage", "complete");
            Ok(())
        }
        microsandbox::snapshot::SnapshotVerifyCoverage::Incomplete { unrecorded } => {
            ui::detail_kv("Coverage", "incomplete");
            for path in unrecorded {
                ui::detail_kv("Not recorded", &path.display().to_string());
            }
            anyhow::bail!(
                "verification incomplete: {} required payload(s) have no recorded integrity",
                unrecorded.len()
            );
        }
    }
}

async fn remove(args: SnapshotRemoveArgs) -> anyhow::Result<()> {
    let spinner = if args.quiet {
        ui::Spinner::quiet()
    } else {
        ui::Spinner::start("Removing", &args.group)
    };
    let result = async {
        let group = SnapshotGroup::get(&args.group).await?;
        if args.all {
            let report = group.remove().await?;
            Ok((Some(report.head_update), report.warnings))
        } else {
            // Resolve the member once; later head edits cannot retarget this removal.
            let checkpoint = group
                .get_checkpoint(
                    args.checkpoint
                        .as_deref()
                        .expect("clap requires checkpoint or all"),
                )
                .await?;
            let report = checkpoint
                .remove_with(|options| if args.force { options.force() } else { options })
                .await?;
            Ok::<_, microsandbox::MicrosandboxError>((report.head_update, report.warnings))
        }
    }
    .await;
    match result {
        Ok((head, warnings)) => {
            spinner.finish_success("Removed");
            if !args.quiet {
                if let Some(head) = head {
                    report_head_update(&head);
                }
                for warning in warnings {
                    ui::warn(&warning);
                }
            }
            Ok(())
        }
        Err(error) => {
            spinner.finish_clear();
            if args.quiet {
                std::process::exit(1);
            }
            Err(error.into())
        }
    }
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

/// Canonical group selectors never guess whether a string is a path or cloud ID.
async fn select_checkpoint(group: &str, member: Option<&str>) -> anyhow::Result<Snapshot> {
    let group = SnapshotGroup::get(group).await?;
    match member {
        Some(member) => Ok(group.get_checkpoint(member).await?),
        None => group.head().await?.ok_or_else(|| {
            anyhow::anyhow!(
                "snapshot group '{}' has no selected head; use --checkpoint MEMBER",
                group.name()
            )
        }),
    }
}

async fn save(args: SnapshotSaveArgs) -> anyhow::Result<()> {
    let out = args.archive_path().to_owned();
    let opts = microsandbox::snapshot::SaveOpts {
        compatibility: args.compatibility,
        with_parents: args.with_parents,
        with_image: args.with_image,
        plain_tar: args.plain_tar,
        since: args.since,
        last_layers: args.last_layers,
    };
    // Pin the immutable member before export; a concurrent head change must not
    // change the artifact or dependencies selected by this operation.
    let checkpoint = select_checkpoint(&args.snapshot, args.checkpoint.as_deref()).await?;
    checkpoint.save_to(&out, opts).await?;
    println!("{}", out.display());
    Ok(())
}

async fn load(args: SnapshotLoadArgs) -> anyhow::Result<()> {
    let result = SnapshotGroup::load_with(&args.group, &args.archives, |mut options| {
        options.dest = args.dest;
        options.base = args.base;
        options.set_head = args.set_head;
        options
    })
    .await?;
    report_head_update(&result.head_update);
    for warning in &result.warnings {
        ui::warn(warning);
    }
    // Report only committed members. Include reuse explicitly so retrying a batch
    // cannot be mistaken for importing another copy of the same checkpoints.
    let added: BTreeSet<_> = result.added.iter().map(|id| id.as_str()).collect();
    for checkpoint in &result.checkpoints {
        let action = if added.contains(checkpoint.id()) {
            "Added"
        } else {
            "Reused"
        };
        println!("{action}: {}", checkpoint.id());
    }
    Ok(())
}

async fn head(args: SnapshotHeadArgs) -> anyhow::Result<()> {
    let group = SnapshotGroup::get(&args.selector).await?;
    let head = group.head().await?;
    if args.format == Some(OutputFormat::Json) {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "group": group.name(), "head": head.as_ref().map(|checkpoint| checkpoint.id().as_str()),
            }))?
        );
    } else {
        ui::detail_kv("Group", group.name());
        ui::detail_kv(
            "Head",
            head.as_ref()
                .map(|checkpoint| checkpoint.id().as_str())
                .unwrap_or("-"),
        );
    }
    Ok(())
}

async fn modify(args: SnapshotModifyArgs) -> anyhow::Result<()> {
    let group = SnapshotGroup::get(&args.group).await?;
    let update = match args.set_head {
        Some(member) => group.set_head(member).await?,
        None => group.clear_head().await?,
    };
    if args.format.as_deref() == Some("json") {
        println!("{}", serde_json::to_string_pretty(&update)?);
    } else {
        report_head_update(&update);
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn format_member_selector(group: Option<&str>, name: Option<&str>, id: &str) -> String {
    let member = name.unwrap_or(id);
    // Friendly member names are scoped to one group; qualify them so rows stay distinct.
    match group {
        Some(group) => format!("{group}:{member}"),
        None => member.to_string(),
    }
}

fn report_head_update(update: &microsandbox::snapshot::HeadUpdate) {
    eprintln!(
        "group {}: head {} ({:?})",
        update.group,
        update.head.as_deref().unwrap_or("-"),
        update.reason
    );
}

fn format_str(f: microsandbox::SnapshotFormat) -> &'static str {
    match f {
        microsandbox::SnapshotFormat::Raw => "raw",
        microsandbox::SnapshotFormat::Qcow2 => "qcow2",
    }
}

fn format_scope(scope: microsandbox::SnapshotScope) -> &'static str {
    match scope {
        microsandbox::SnapshotScope::Disk => "disk",
        microsandbox::SnapshotScope::Full => "full",
    }
}

fn format_root_disk(root_disk: &microsandbox::SnapshotRootDisk) -> &'static str {
    match root_disk {
        microsandbox::SnapshotRootDisk::Managed => "managed",
        microsandbox::SnapshotRootDisk::Flat => "flat",
        microsandbox::SnapshotRootDisk::Tmpfs { .. } => "tmpfs",
    }
}

fn format_reference(reference: &SnapshotReference) -> String {
    reference.value().to_string()
}

fn short_digest(d: &str) -> String {
    if let Some(hex) = d.strip_prefix("sha256:") {
        format!("sha256:{}", &hex[..hex.len().min(12)])
    } else {
        d.chars().take(20).collect()
    }
}

fn format_integrity(integrity: &Option<microsandbox::UpperIntegrity>) -> String {
    integrity
        .as_ref()
        .map(|integrity| format!("{} {}", integrity.algorithm(), integrity.value()))
        .unwrap_or_else(|| "not recorded".into())
}

fn format_verify_status(status: &microsandbox::snapshot::UpperVerifyStatus) -> String {
    match status {
        microsandbox::snapshot::UpperVerifyStatus::NotRecorded => "not recorded".into(),
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
    fn incomplete_verification_cannot_exit_successfully() {
        use microsandbox::snapshot::SnapshotVerifyCoverage;
        assert!(require_complete_verification(&SnapshotVerifyCoverage::Complete).is_ok());
        let error = require_complete_verification(&SnapshotVerifyCoverage::Incomplete {
            unrecorded: vec![PathBuf::from("base.raw")],
        })
        .unwrap_err();
        assert!(error.to_string().contains("verification incomplete"));
    }

    #[test]
    fn checkpoint_requires_selectors_and_keeps_capture_controls() {
        assert!(TestCli::try_parse_from(["msb", "checkpoint"]).is_err());
        for form in [
            vec!["checkpoint", "history"],
            vec!["checkpoint", "--sandbox", "app"],
            vec!["checkpoint", "history", "--sandbox", "app"],
        ] {
            let SnapshotCommands::Checkpoint(args) = parse_snapshot_args(&form).command else {
                panic!("wrong command")
            };
            assert!(args.group.is_some() || args.sandbox.is_some());
        }
        let SnapshotCommands::Checkpoint(args) = parse_snapshot_args(&[
            "checkpoint",
            "history",
            "--name",
            "saved",
            "--full",
            "--integrity",
            "--guest-flush",
            "required",
            "--label",
            "stage=ready",
            "--quiet",
        ])
        .command
        else {
            panic!("wrong command")
        };
        assert_eq!(args.name.as_deref(), Some("saved"));
        assert!(args.full && args.integrity && args.quiet);
        assert_eq!(args.labels, ["stage=ready"]);
        for invalid in [
            vec!["checkpoint", "history", "--output", "backup.msb"],
            vec!["checkpoint", "history", "--force"],
        ] {
            assert!(TestCli::try_parse_from(std::iter::once("msb").chain(invalid)).is_err());
        }
    }

    #[test]
    fn create_requires_exactly_one_new_group_or_archive_destination() {
        for args in [
            vec!["create"],
            vec!["create", "history"],
            vec!["create", "--sandbox", "app"],
            vec!["create", "history", "--sandbox", "app", "-o", "backup.msb"],
            vec!["create", "history", "--sandbox", "app", "--group", "other"],
            vec!["create", "history", "--sandbox", "app", "--force"],
        ] {
            assert!(
                TestCli::try_parse_from(std::iter::once("msb").chain(args.clone())).is_err(),
                "unexpected accepted arguments: {args:?}"
            );
        }
        for command in [
            vec![
                "create",
                "history",
                "--sandbox",
                "app",
                "--name",
                "base",
                "--full",
            ],
            vec![
                "create",
                "history",
                "--from-sandbox",
                "app",
                "-n",
                "base",
                "--full",
            ],
        ] {
            let SnapshotCommands::Create(args) = parse_snapshot_args(&command).command else {
                panic!("create")
            };
            assert_eq!(args.group.as_deref(), Some("history"));
            assert_eq!(args.snapshot_name(), "base");
            assert!(args.full);
        }
        let SnapshotCommands::Create(args) =
            parse_snapshot_args(&["create", "history", "--sandbox", "app"]).command
        else {
            panic!("create")
        };
        assert_eq!(args.snapshot_name(), "");
    }

    #[test]
    fn create_parses_dest_dir() {
        let args = parse_snapshot_args(&[
            "create",
            "clean",
            "--from-sandbox",
            "box",
            "--dest-dir",
            "/mnt/big",
        ]);
        let SnapshotCommands::Create(args) = args.command else {
            panic!("expected create command");
        };
        assert_eq!(
            args.dest_dir.as_deref(),
            Some(std::path::Path::new("/mnt/big"))
        );
    }

    #[test]
    fn create_parses_direct_archive_without_installed_destination() {
        let args = parse_snapshot_args(&[
            "create",
            "--name",
            "clean",
            "--from-sandbox",
            "box",
            "--output",
            "/tmp/clean.tar",
            "--plain-tar",
        ]);
        let SnapshotCommands::Create(args) = args.command else {
            panic!("expected create command");
        };
        assert_eq!(
            args.output.as_deref(),
            Some(std::path::Path::new("/tmp/clean.tar"))
        );
        assert!(args.plain_tar);
        assert!(args.dest_dir.is_none());
    }

    #[test]
    fn create_parses_short_output_for_full_archive() {
        let parsed = parse_snapshot_args(&[
            "create",
            "--from-sandbox",
            "box",
            "--full",
            "-o",
            "/tmp/full.msb",
        ]);
        let SnapshotCommands::Create(args) = parsed.command else {
            panic!("expected create command");
        };
        assert_eq!(
            args.output.as_deref(),
            Some(std::path::Path::new("/tmp/full.msb"))
        );
        assert!(args.full);
        assert!(!args.plain_tar);
        assert!(args.dest_dir.is_none());
    }

    #[test]
    fn create_output_constraints_are_enforced() {
        for flag in ["--output", "-o"] {
            let conflict = TestCli::try_parse_from([
                "msb",
                "create",
                "--from-sandbox",
                "box",
                flag,
                "saved.msb",
                "--dest-dir",
                "/tmp/snapshots",
            ])
            .unwrap_err();
            assert_eq!(conflict.kind(), clap::error::ErrorKind::ArgumentConflict);
            assert!(
                TestCli::try_parse_from(["msb", "create", "--from-sandbox", "box", flag,]).is_err()
            );
        }
        let missing_output =
            TestCli::try_parse_from(["msb", "create", "--from-sandbox", "box", "--plain-tar"])
                .unwrap_err();
        assert_eq!(
            missing_output.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        assert!(missing_output.to_string().contains("--output"));
    }

    #[test]
    fn create_without_output_installs_snapshot_and_old_archive_flag_is_rejected() {
        let parsed = parse_snapshot_args(&["create", "saved", "--from-sandbox", "box"]);
        let SnapshotCommands::Create(args) = parsed.command else {
            panic!("expected create command");
        };
        assert!(args.output.is_none());
        // This unreleased spelling is deliberately replaced, not kept as an alias.
        let old_flag = TestCli::try_parse_from([
            "msb",
            "create",
            "saved",
            "--from-sandbox",
            "box",
            "--archive",
            "saved.msb",
        ])
        .unwrap_err();
        assert_eq!(old_flag.kind(), clap::error::ErrorKind::UnknownArgument);
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
        assert_eq!(args.archive_path(), std::path::Path::new("bundle.tar"));
        assert!(args.plain_tar);
    }

    #[test]
    fn export_accepts_named_or_positional_output_without_changing_options() {
        for command in ["export", "save"] {
            for output in [
                vec!["bundle.msb"],
                vec!["--output", "bundle.msb"],
                vec!["-o", "bundle.msb"],
            ] {
                let args = [command, "app", "--checkpoint", "ready"]
                    .into_iter()
                    .chain(output)
                    .chain(["--since", "app:base", "--with-image"])
                    .collect::<Vec<_>>();
                let SnapshotCommands::Save(args) = parse_snapshot_args(&args).command else {
                    panic!("expected export command");
                };
                assert_eq!(args.archive_path(), std::path::Path::new("bundle.msb"));
                assert_eq!(args.snapshot, "app");
                assert_eq!(args.checkpoint.as_deref(), Some("ready"));
                assert_eq!(args.since.as_deref(), Some("app:base"));
                assert!(args.with_image);
            }
            for tail in [
                vec![],
                vec!["one.msb", "--output", "two.msb"],
                vec!["--output"],
                vec![
                    "--output",
                    "one.msb",
                    "--since",
                    "app:base",
                    "--with-parents",
                ],
            ] {
                assert!(
                    TestCli::try_parse_from(["msb", command, "app:ready"].into_iter().chain(tail))
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn import_alias_preserves_batch_dependencies_and_head_options() {
        for command in ["import", "load"] {
            let SnapshotCommands::Load(args) = parse_snapshot_args(&[
                command,
                "received",
                "--file",
                "changes.msb",
                "base.msb",
                "--base",
                "app:base",
                "--dest",
                "/tmp/snaps",
                "--set-head",
            ])
            .command
            else {
                panic!("expected import command");
            };
            assert_eq!(
                args.archives,
                [
                    std::path::PathBuf::from("changes.msb"),
                    std::path::PathBuf::from("base.msb")
                ]
            );
            assert_eq!(args.base.as_deref(), Some("app:base"));
            assert_eq!(args.group, "received");
            assert_eq!(
                args.dest.as_deref(),
                Some(std::path::Path::new("/tmp/snaps"))
            );
            assert!(args.set_head);
        }
    }

    #[test]
    fn group_filter_parses_with_each_listing_output() {
        for command in ["list", "ls"] {
            for output in [vec![], vec!["--quiet"], vec!["--format", "json"]] {
                let args = [command, "app"]
                    .into_iter()
                    .chain(output)
                    .collect::<Vec<_>>();
                let SnapshotCommands::List(args) = parse_snapshot_args(&args).command else {
                    panic!("expected list command");
                };
                assert_eq!(args.group.as_deref(), Some("app"));
            }
        }
    }

    #[test]
    fn load_parses_args() {
        let parsed = parse_snapshot_args(&[
            "load",
            "received",
            "--file",
            "bundle.tar",
            "--dest",
            "/tmp/snaps",
        ]);
        let SnapshotCommands::Load(args) = parsed.command else {
            panic!("expected load command");
        };
        assert_eq!(args.archives, vec![std::path::PathBuf::from("bundle.tar")]);
        assert_eq!(
            args.dest.as_deref(),
            Some(std::path::Path::new("/tmp/snaps"))
        );
    }

    #[test]
    fn verify_selects_head_exact_member_or_whole_group() {
        for (tail, exact, all) in [
            (vec![], None, false),
            (vec!["--checkpoint", "ready"], Some("ready"), false),
            (vec!["--all"], None, true),
        ] {
            let args = ["verify", "work"]
                .into_iter()
                .chain(tail)
                .collect::<Vec<_>>();
            let SnapshotCommands::Verify(args) = parse_snapshot_args(&args).command else {
                panic!("expected verify command");
            };
            assert_eq!(args.snapshot, "work");
            assert_eq!(args.checkpoint.as_deref(), exact);
            assert_eq!(args.all, all);
        }
        assert!(
            TestCli::try_parse_from(["msb", "verify", "work", "--all", "--checkpoint", "ready"])
                .is_err()
        );
    }

    #[test]
    fn load_parses_multiple_archives_and_a_named_destination() {
        let parsed = parse_snapshot_args(&[
            "load",
            "received",
            "--file",
            "changes.msb",
            "--file",
            "base.msb",
            "--dest",
            "/tmp/snaps",
        ]);
        let SnapshotCommands::Load(args) = parsed.command else {
            panic!("expected load command");
        };
        assert_eq!(
            args.archives,
            vec![
                std::path::PathBuf::from("changes.msb"),
                std::path::PathBuf::from("base.msb"),
            ]
        );
        assert_eq!(
            args.dest.as_deref(),
            Some(std::path::Path::new("/tmp/snaps"))
        );
        assert_eq!(args.group, "received");
    }

    #[test]
    fn load_requires_at_least_one_archive() {
        assert!(TestCli::try_parse_from(["msb", "load", "received"]).is_err());
    }

    #[test]
    fn load_accepts_group_and_explicit_head_selection() {
        let parsed = parse_snapshot_args(&[
            "load",
            "work",
            "--file",
            "changes.msb",
            "--base",
            "work:base",
            "--set-head",
        ]);
        let SnapshotCommands::Load(args) = parsed.command else {
            panic!("expected load command");
        };
        assert_eq!(args.base.as_deref(), Some("work:base"));
        assert_eq!(args.group, "work");
        assert!(args.set_head);
    }

    #[test]
    fn head_is_read_only_and_modify_requires_an_explicit_mutation() {
        for args in [
            vec!["modify", "work"],
            vec!["modify", "work", "--set-head", "base", "--clear-head"],
            vec!["head", "work", "--set-head", "base"],
        ] {
            assert!(TestCli::try_parse_from(std::iter::once("msb").chain(args)).is_err());
        }
        for args in [
            vec!["modify", "work", "--set-head", "base"],
            vec!["modify", "work", "--clear-head"],
        ] {
            assert!(matches!(
                parse_snapshot_args(&args).command,
                SnapshotCommands::Modify(_)
            ));
        }
        let parsed = parse_snapshot_args(&["head", "work", "--format", "json"]);
        let SnapshotCommands::Head(args) = parsed.command else {
            panic!("expected head command");
        };
        assert_eq!(args.selector, "work");
        assert_eq!(args.format, Some(OutputFormat::Json));
    }

    #[test]
    fn list_disambiguates_aliases_and_unnamed_members_by_group() {
        assert_eq!(
            format_member_selector(Some("work"), Some("base"), "snap_1"),
            "work:base"
        );
        assert_eq!(
            format_member_selector(Some("copy"), Some("base"), "snap_1"),
            "copy:base"
        );
        assert_eq!(
            format_member_selector(Some("copy"), None, "snap_1"),
            "copy:snap_1"
        );
        assert_eq!(format_member_selector(None, None, "snap_1"), "snap_1");
    }
    #[test]
    fn removal_requires_explicit_member_or_entire_history() {
        for command in ["remove", "rm"] {
            assert!(TestCli::try_parse_from(["msb", command, "history"]).is_err());
            assert!(
                TestCli::try_parse_from([
                    "msb",
                    command,
                    "history",
                    "--checkpoint",
                    "one",
                    "--all"
                ])
                .is_err()
            );
            assert!(
                TestCli::try_parse_from(["msb", command, "history", "--all", "--force"]).is_err()
            );
            assert!(
                TestCli::try_parse_from([
                    "msb",
                    command,
                    "history",
                    "--checkpoint",
                    "one",
                    "--force"
                ])
                .is_ok()
            );
            assert!(
                TestCli::try_parse_from(["msb", command, "history", "--all", "--quiet"]).is_ok()
            );
            assert!(
                TestCli::try_parse_from(["msb", command, "history", "other", "--all"]).is_err()
            );
        }
    }
    #[test]
    fn inspect_distinguishes_history_from_an_explicit_checkpoint() {
        assert!(TestCli::try_parse_from(["msb", "inspect", "history"]).is_ok());
        assert!(
            TestCli::try_parse_from(["msb", "inspect", "history", "--checkpoint", "one"]).is_ok()
        );
        assert!(TestCli::try_parse_from(["msb", "inspect", "history", "--verify"]).is_err());
        assert!(
            TestCli::try_parse_from([
                "msb",
                "inspect",
                "history",
                "--checkpoint",
                "one",
                "--verify"
            ])
            .is_ok()
        );
        assert!(TestCli::try_parse_from(["msb", "inspect", "history", "extra"]).is_err());
    }
    #[test]
    fn export_compatibility_requires_an_exact_supported_target() {
        for target in ["current", "0.7.8"] {
            assert!(
                TestCli::try_parse_from([
                    "msb",
                    "export",
                    "history",
                    "--output",
                    "saved.msb",
                    "--compatibility",
                    target
                ])
                .is_ok()
            );
        }
        assert!(
            TestCli::try_parse_from([
                "msb",
                "export",
                "history",
                "--output",
                "saved.msb",
                "--compatibility",
                "0.7"
            ])
            .is_err()
        );
    }
}
