//! `msb snapshot` command — capture, restore, and manage snapshots.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use microsandbox::{Snapshot, SnapshotReference};

use crate::{
    commands::restore::{self, RestoreArgs},
    ui,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Capture, restore, and manage disk or full snapshots.
#[derive(Debug, Args)]
#[command(
    after_help = "Examples:\n  msb snap create ready --sandbox app --full\n  \
    msb snap restore app:ready --name worker\n  msb snap ls --group app\n  \
    msb snap export app:ready --output ready.msb\n  \
    msb snap import ready.msb --group received\n\n\
    'snap' and 'snapshot' are equivalent. Live branching uses 'msb branch'."
)]
pub struct SnapshotArgs {
    /// Snapshot subcommand.
    #[command(subcommand)]
    pub command: SnapshotCommands,
}

/// Snapshot subcommands.
#[derive(Debug, Subcommand)]
pub enum SnapshotCommands {
    /// Create a disk snapshot, or include memory and execution state with --full.
    Create(SnapshotCreateArgs),

    /// Restore saved state into a new sandbox running in the background.
    Restore(Box<RestoreArgs>),

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

    /// Export a snapshot to a `.msb` archive (tar + zstd).
    #[command(name = "export", visible_alias = "save")]
    Save(SnapshotSaveArgs),

    /// Import snapshot archives into a local snapshot group.
    #[command(name = "import", visible_alias = "load")]
    Load(SnapshotLoadArgs),

    /// Read a group's head, or select a member as its head.
    Head(SnapshotHeadArgs),
}

/// Arguments for `msb snapshot create`.
#[derive(Debug, Args)]
#[command(
    after_help = "Disk capture is the default. Use --full to include memory and running processes.\n\
    The group defaults to the source sandbox's name; ready --sandbox app creates app:ready.\n\
    Use --name instead of a positional name, or omit both to generate a snapshot name.\n\n\
    Examples:\n  \
    msb snap create ready --sandbox app\n  \
    msb snap create ready --sandbox app --full\n  \
    msb snap create ready --sandbox app --group templates\n\n\
    Compatibility: snapshot create ready --from-sandbox app is still supported."
)]
pub struct SnapshotCreateArgs {
    /// Snapshot name within the group (generated when omitted).
    #[arg(value_name = "NAME")]
    pub positional_name: Option<String>,

    /// Sandbox to capture.
    #[arg(long, alias = "from-sandbox", value_name = "SANDBOX")]
    pub sandbox: String,

    /// Set the snapshot name instead of using the positional argument.
    #[arg(short, long, conflicts_with = "positional_name")]
    pub name: Option<String>,

    /// Snapshot group to create or add to (defaults to the source sandbox name).
    #[arg(long, value_name = "GROUP")]
    pub group: Option<String>,

    /// Parent directory to create the artifact in, instead of the
    /// default snapshots directory. The group is created under this root.
    #[arg(long = "dest-dir", value_name = "DIR")]
    pub dest_dir: Option<PathBuf>,

    /// Write directly to an archive without installing a snapshot directory.
    #[arg(short = 'o', long, value_name = "PATH", conflicts_with = "dest_dir")]
    pub output: Option<PathBuf>,

    /// Write a plain tar archive instead of zstd-compressed tar.
    #[arg(long, requires = "output")]
    pub plain_tar: bool,

    /// Add a `key=value` label. May be repeated.
    #[arg(long = "label", value_name = "K=V")]
    pub labels: Vec<String>,

    /// Overwrite an existing archive file; installed group members are immutable.
    #[arg(short = 'f', long)]
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

/// Arguments for `msb snapshot list`.
#[derive(Debug, Args)]
pub struct SnapshotListArgs {
    /// Show only snapshots in this local group.
    #[arg(long, value_name = "GROUP")]
    pub group: Option<String>,

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
    pub dir: Option<PathBuf>,
}

/// Arguments for `msb snapshot export` (also available as `save`).
#[derive(Debug, Args)]
pub struct SnapshotSaveArgs {
    /// Snapshot to save (path, name, or digest).
    pub snapshot: String,

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
    /// Archives to import together; dependencies are resolved regardless of argument order.
    #[arg(required = true, num_args = 1.., value_name = "ARCHIVE")]
    pub archives: Vec<PathBuf>,

    /// Destination directory (defaults to `~/.microsandbox/snapshots/`).
    #[arg(long, value_name = "DIR")]
    pub dest: Option<PathBuf>,
    /// External base snapshot or standalone archive if batch/group members cannot supply dependencies.
    #[arg(long)]
    pub base: Option<String>,

    /// Import into this group (generated when omitted).
    #[arg(long, value_name = "GROUP")]
    pub group: Option<String>,

    /// Select the batch's unique tip as head even if it is not a fast-forward.
    #[arg(long)]
    pub set_head: bool,
}

/// Arguments for `msb snapshot head`.
#[derive(Debug, Args)]
pub struct SnapshotHeadArgs {
    /// Group to read, or GROUP:MEMBER to select a new head.
    pub selector: String,

    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_parser = ["json"])]
    pub format: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SnapshotCreateArgs {
    fn snapshot_name(&self) -> &str {
        self.name
            .as_deref()
            .or(self.positional_name.as_deref())
            .unwrap_or_default()
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
        SnapshotCommands::Restore(args) => restore::run(*args, None).await,
        SnapshotCommands::List(args) => list(args).await,
        SnapshotCommands::Inspect(args) => inspect(args).await,
        SnapshotCommands::Verify(args) => verify(args).await,
        SnapshotCommands::Remove(args) => remove(args).await,
        SnapshotCommands::Reindex(args) => reindex(args).await,
        SnapshotCommands::Save(args) => save(args).await,
        SnapshotCommands::Load(args) => load(args).await,
        SnapshotCommands::Head(args) => head(args).await,
    }
}

async fn create(args: SnapshotCreateArgs) -> anyhow::Result<()> {
    let source = args.sandbox.clone();
    let mut builder = Snapshot::builder(args.snapshot_name())
        .from_sandbox(&source)
        .guest_flush(args.guest_flush);
    if let Some(group) = args.group {
        builder = builder.group(group);
    }
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

    match builder.create().await {
        Ok(snap) => {
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
    if args.group.is_some() {
        // Groups are local metadata; do not silently return an empty cloud listing.
        super::common::resolve_local_backend()?;
    }

    let snapshots: Vec<_> = Snapshot::list()
        .await?
        .into_iter()
        .filter(|snapshot| {
            args.group
                .as_deref()
                .is_none_or(|group| snapshot.group() == Some(group))
        })
        .collect();

    if args.format.as_deref() == Some("json") {
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
            println!("{}", s.digest());
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
            .map(format_size)
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
    let snap = Snapshot::open(&args.snapshot).await?;
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
            ui::detail_kv("Virtual Size", &format_size(state.virtual_size));
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
    Ok(())
}

async fn verify(args: SnapshotVerifyArgs) -> anyhow::Result<()> {
    let snap = Snapshot::open(&args.snapshot).await?;
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
    let out = args.archive_path().to_owned();
    let opts = microsandbox::snapshot::SaveOpts {
        with_parents: args.with_parents,
        with_image: args.with_image,
        plain_tar: args.plain_tar,
        since: args.since,
        last_layers: args.last_layers,
    };
    Snapshot::save(&args.snapshot, &out, opts).await?;
    println!("{}", out.display());
    Ok(())
}

async fn load(args: SnapshotLoadArgs) -> anyhow::Result<()> {
    let handles = Snapshot::load_many(
        &args.archives,
        microsandbox::snapshot::LoadOpts {
            dest: args.dest,
            base: args.base,
            group: args.group,
            set_head: args.set_head,
        },
    )
    .await?;
    // Every imported member belongs to one batch; report its single head decision once.
    if let Some(update) = handles.iter().find_map(|handle| handle.head_update()) {
        report_head_update(update);
    } else if let Some(group) = handles.first().and_then(|handle| handle.group()) {
        eprintln!(
            "group {group}: imported members without selecting a head; choose a member explicitly"
        );
    }
    for (index, handle) in handles.iter().enumerate() {
        if handles.len() > 1 {
            if index > 0 {
                println!();
            }
            println!("Snapshot: {}", handle.id());
        }
        println!("{}", handle.digest());
        // Preserve the single-archive digest/path output consumed by shell scripts.
        println!("{}", format_reference(&handle.reference()));
    }
    Ok(())
}

async fn head(args: SnapshotHeadArgs) -> anyhow::Result<()> {
    let update = Snapshot::group_head(&args.selector).await?;
    if args.format.as_deref() == Some("json") {
        println!("{}", serde_json::to_string_pretty(&update)?);
    } else {
        ui::detail_kv("Group", &update.group);
        ui::detail_kv("Previous head", update.previous.as_deref().unwrap_or("-"));
        ui::detail_kv("Head", &update.head);
        ui::detail_kv("Reason", &format!("{:?}", update.reason));
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
        update.group, update.head, update.reason
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
    fn create_requires_a_source_and_rejects_mixed_naming_forms() {
        let error = TestCli::try_parse_from(["msb", "create"]).unwrap_err();
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        for args in [
            vec!["create", "--name", "ready"],
            vec![
                "create",
                "ready",
                "--from-sandbox",
                "app",
                "--name",
                "other",
            ],
            vec!["create", "ready", "--sandbox", "app", "--name", "other"],
            vec!["create", "--sandbox", "app", "--from-sandbox", "other"],
            vec!["create", "--sandbox", "app", "--sandbox", "other"],
            vec!["create", "app", "--name", "ready"],
            vec!["create", "--snapshot", "app:ready", "--name", "other"],
            vec!["create", "app", "ready"],
        ] {
            assert!(TestCli::try_parse_from(std::iter::once("msb").chain(args)).is_err());
        }

        // Do not reintroduce the previously rejected ambiguous spelling.
        let error =
            TestCli::try_parse_from(["msb", "create", "clean", "--from", "box"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn explicit_and_legacy_capture_resolve_the_same_names_and_defaults() {
        for full in [false, true] {
            for (source, name) in [("app", "ready"), ("create", "restore")] {
                let mut forms = [
                    vec!["create", name, "--sandbox", source],
                    vec!["create", "--sandbox", source, name],
                    vec!["create", "--sandbox", source, "--name", name],
                    vec!["create", "--sandbox", source, "-n", name],
                    vec!["create", name, "--from-sandbox", source],
                    vec!["create", "--from-sandbox", source, "--name", name],
                ];
                for form in &mut forms {
                    form.extend(["--group", "templates"]);
                    if full {
                        form.push("--full");
                    }
                    let SnapshotCommands::Create(args) = parse_snapshot_args(form).command else {
                        panic!("expected create command");
                    };
                    assert_eq!(args.sandbox, source);
                    assert_eq!(args.snapshot_name(), name);
                    assert_eq!(args.group.as_deref(), Some("templates"));
                    assert_eq!(args.full, full);
                    assert_eq!(args.guest_flush, microsandbox::snapshot::GuestFlush::Auto);
                    assert!(args.output.is_none());
                }
            }
        }
        for form in [
            vec!["create", "--sandbox", "app"],
            vec!["create", "--from-sandbox", "app"],
        ] {
            let SnapshotCommands::Create(args) = parse_snapshot_args(&form).command else {
                panic!("expected create command");
            };
            assert_eq!(args.sandbox, "app");
            assert_eq!(args.snapshot_name(), "");
            assert!(args.group.is_none());
            assert!(!args.full);
        }
    }

    #[test]
    fn create_parses_full_capture_flag() {
        let args = parse_snapshot_args(&["create", "clean", "--from-sandbox", "box", "--full"]);
        let SnapshotCommands::Create(args) = args.command else {
            panic!("expected create command");
        };
        assert_eq!(args.snapshot_name(), "clean");
        assert_eq!(args.sandbox, "box");
        assert!(args.full);
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
                let args = [command, "app:ready"]
                    .into_iter()
                    .chain(output)
                    .chain(["--since", "app:base", "--with-image"])
                    .collect::<Vec<_>>();
                let SnapshotCommands::Save(args) = parse_snapshot_args(&args).command else {
                    panic!("expected export command");
                };
                assert_eq!(args.archive_path(), std::path::Path::new("bundle.msb"));
                assert_eq!(args.snapshot, "app:ready");
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
                "changes.msb",
                "base.msb",
                "--base",
                "app:base",
                "--group",
                "received",
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
            assert_eq!(args.group.as_deref(), Some("received"));
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
                let args = [command, "--group", "app"]
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
        let parsed = parse_snapshot_args(&["load", "bundle.tar", "--dest", "/tmp/snaps"]);
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
    fn load_parses_multiple_archives_and_a_named_destination() {
        let parsed = parse_snapshot_args(&[
            "load",
            "changes.msb",
            "base.msb",
            "--dest",
            "/tmp/snaps",
            "--group",
            "received",
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
        assert_eq!(args.group.as_deref(), Some("received"));
    }

    #[test]
    fn load_requires_at_least_one_archive() {
        assert!(TestCli::try_parse_from(["msb", "load", "--group", "received"]).is_err());
    }

    #[test]
    fn create_accepts_generated_member_in_explicit_group() {
        let parsed = parse_snapshot_args(&["create", "--from-sandbox", "box", "--group", "work"]);
        let SnapshotCommands::Create(args) = parsed.command else {
            panic!("expected create command");
        };
        assert_eq!(args.snapshot_name(), "");
        assert_eq!(args.group.as_deref(), Some("work"));
        assert_eq!(args.sandbox, "box");
    }

    #[test]
    fn load_accepts_group_and_explicit_head_selection() {
        let parsed = parse_snapshot_args(&[
            "load",
            "changes.msb",
            "--base",
            "work:base",
            "--group",
            "work",
            "--set-head",
        ]);
        let SnapshotCommands::Load(args) = parsed.command else {
            panic!("expected load command");
        };
        assert_eq!(args.base.as_deref(), Some("work:base"));
        assert_eq!(args.group.as_deref(), Some("work"));
        assert!(args.set_head);
    }

    #[test]
    fn head_accepts_member_selector_and_json_format() {
        let parsed = parse_snapshot_args(&["head", "work:baseline", "--format", "json"]);
        let SnapshotCommands::Head(args) = parsed.command else {
            panic!("expected head command");
        };
        assert_eq!(args.selector, "work:baseline");
        assert_eq!(args.format.as_deref(), Some("json"));
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
}
