//! Operator inspection of independent disk views, before storage admission.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use microsandbox_image::checkpoint::{
    CompactLayer, materialize_raw_prefix, sparse_file_integrity_handle,
};

use super::super::layout;
use super::budget::ParserBudget;
use super::engine::{MigrationPlan, plan_selected};
use super::io;
use super::namespace;
use super::source::{self, Acquired, Disk};
use super::types::{CandidateSummary, MigrationBindings, RecoverySelection};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// An ephemeral, independent capture. No original file or writer lock is held while the
/// operator inspects it. The caller owns any rescue VM and must stop it before dropping this.
pub struct RecoveryPreview {
    runtime: PathBuf,
    bindings: MigrationBindings,
    directory: tempfile::TempDir,
    _private_parent: namespace::Guard,
    candidates: Vec<CandidateSummary>,
    views: BTreeMap<String, Disk>,
    copies: BTreeMap<String, CapturedLayer>,
    outputs: BTreeMap<String, (PathBuf, io::Identity)>,
    output_bytes: u64,
}

struct CapturedLayer {
    path: PathBuf,
    content_root: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RecoveryPreview {
    /// Opaque stable identifiers for the complete disk views captured in this session.
    pub fn candidates(&self) -> &[CandidateSummary] {
        &self.candidates
    }

    /// Produce a disposable, standalone raw disk for a read-only rescue attachment. Never
    /// attach the source layers themselves. Guest writes to an inspection image cannot
    /// change the proof used for adoption or write through to an external original.
    pub fn materialize(&mut self, disk_id: &str, candidate_id: &str) -> Result<PathBuf, String> {
        let view = self
            .views
            .get(candidate_id)
            .filter(|disk| disk.id == disk_id)
            .ok_or("unknown private recovery view")?;
        if let Some((path, stamp)) = self.outputs.get(candidate_id) {
            verify_output(path, stamp)?;
            return Ok(path.clone());
        }
        let capacity = view.sources.last().ok_or("empty recovery view")?.capacity;
        let output_bytes = self
            .output_bytes
            .checked_add(capacity)
            .filter(|bytes| *bytes <= io::MAX_TOTAL_BYTES)
            .ok_or("materialized recovery views exceed the session output bound")?;
        let target = self
            .directory
            .path()
            .join(format!("view-{}.raw", self.outputs.len()));
        let mut layers = Vec::with_capacity(view.sources.len());
        for (index, source) in view.sources.iter().enumerate() {
            let copy = self
                .copies
                .get(&source.identity.object)
                .ok_or("missing private recovery layer")?;
            let file = io::exact(&copy.path)?;
            verify_content(&file, &copy.content_root)?;
            let (capacity, backing) = io::header(&file, source.format == "qcow2")?;
            let expected = index
                .checked_sub(1)
                .and_then(|i| view.sources[i].path.file_name())
                .and_then(|name| name.to_str());
            if capacity != source.capacity || backing.as_deref() != expected {
                return Err("private recovery view has an invalid explicit dependency".into());
            }
            layers.push(CompactLayer {
                path: copy.path.clone(),
                qcow2: source.format == "qcow2",
            });
        }
        // The explicit chain opener denies implicit backing and external data opens.
        // A joined worker also works when called from an existing Tokio runtime.
        let write = if layers.len() == 1 && !layers[0].qcow2 {
            io::capture(&io::exact(&layers[0].path)?, &target)
        } else {
            std::thread::scope(|scope| {
                scope
                    .spawn(|| -> Result<(), String> {
                        let executor = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .map_err(|_| "cannot start private recovery materializer")?;
                        let result = executor
                            .block_on(materialize_raw_prefix(&layers, &target))
                            .map_err(|_| "cannot read this private recovery chain")?;
                        if result.virtual_size != capacity {
                            return Err(
                                "materialized private recovery disk has an unexpected size".into(),
                            );
                        }
                        Ok(())
                    })
                    .join()
            })
            .map_err(|_| "private recovery materializer stopped unexpectedly")?
        };
        if let Err(error) = write.and_then(|()| io::harden_created(&target, false)) {
            if target.exists() {
                fs::remove_file(&target)
                    .map_err(|_| "cannot discard incomplete recovery image; close the session")?;
            }
            return Err(error);
        }
        let stamp = io::identity(&io::exact(&target)?)?;
        self.outputs
            .insert(candidate_id.to_owned(), (target.clone(), stamp));
        self.output_bytes = output_bytes;
        Ok(target)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Create ephemeral private storage for an SDK-owned rescue machine and its captures.
pub fn private_preview_parent() -> Result<tempfile::TempDir, String> {
    private_temp_in(&std::env::temp_dir(), "msb-storage-preview-")
}

/// Short private scratch home for one reader VM, independent of the operator's TMPDIR.
/// Darwin's normal per-user temporary path alone can exhaust its Unix socket name allowance.
pub fn private_reader_home() -> Result<tempfile::TempDir, String> {
    #[cfg(unix)]
    let anchor = std::path::PathBuf::from("/tmp");
    #[cfg(not(unix))]
    let anchor = std::env::temp_dir();
    private_temp_in(&anchor, "mr-")
}

fn private_temp_in(temporary: &Path, prefix: &str) -> Result<tempfile::TempDir, String> {
    let _guard = namespace::temporary_parent(temporary)?;
    let mut builder = tempfile::Builder::new();
    builder.prefix(prefix);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    let directory = builder
        .tempdir_in(temporary)
        .map_err(|_| "cannot create private recovery workspace")?;
    io::harden_created(directory.path(), true)?;
    namespace::private_parent(directory.path())?;
    Ok(directory)
}

/// Capture every authorized alternative once, including external write-through disks.
/// Caller must hold the same stopped-sandbox, alias and platform maintenance guards as
/// migration. The private parent is caller-owned and must lie outside the source sandbox.
pub fn capture_preview(
    runtime: &Path,
    bindings: &MigrationBindings,
    private_parent: &Path,
) -> Result<RecoveryPreview, String> {
    let parent_guard = namespace::private_parent(private_parent)?;
    let parent =
        fs::canonicalize(private_parent).map_err(|_| "cannot resolve private recovery parent")?;
    let sandbox = fs::canonicalize(layout::host_root(runtime)?)
        .map_err(|_| "cannot resolve recovery source sandbox")?;
    if parent.starts_with(&sandbox) {
        return Err("recovery staging must be outside the source sandbox".into());
    }
    let _source_namespace = namespace::acquire(runtime, bindings, true)?;
    let (views, mut acquired) = inventory(runtime, bindings)?;
    source::protect(&mut acquired)?;
    budget_all_heads(&acquired)?;
    let directory = tempfile::Builder::new()
        .prefix("recovery-views-")
        .tempdir_in(&parent)
        .map_err(|_| "cannot create private recovery staging")?;
    io::harden_created(directory.path(), true)?;
    let mut paths = BTreeMap::new();
    for (disk, files) in acquired.disks.iter().zip(&acquired.files) {
        for (source, file) in disk.sources.iter().zip(files) {
            let path = directory.path().join(format!("layer-{}", paths.len()));
            io::capture(file, &path)?;
            let pin = io::exact(&path)?;
            let captured = io::identity(&pin)?;
            if captured.object == source.identity.object
                || captured.links != 1
                || captured.length != source.identity.length
            {
                return Err("recovery layer is not a complete independent copy".into());
            }
            paths.insert(source.identity.object.clone(), path);
        }
    }
    let current = current_views(runtime, bindings)?;
    compare_views(&views, &current)?;
    // Reopen every frozen source and alias to verify object identity and linkage, then
    // certify one continuous writer-exclusion epoch after the final original read.
    source::reacquire(runtime, bindings, &acquired.disks)?;
    acquired
        .writers
        .as_ref()
        .ok_or("recovery source protection is missing")?
        .audit()?;
    // Hash independent copies after releasing platform writer exclusion. An operator can
    // compare a large set without making a writer wait through an extra disk traversal.
    drop(acquired);
    drop(_source_namespace);
    let copies = paths
        .into_iter()
        .map(|(object, path)| {
            let content_root = content_root(&io::exact(&path)?)?;
            Ok((object, CapturedLayer { path, content_root }))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let candidates = summaries(&views, bindings)?;
    Ok(RecoveryPreview {
        runtime: runtime.to_owned(),
        bindings: bindings.clone(),
        directory,
        _private_parent: parent_guard,
        candidates,
        views,
        copies,
        outputs: BTreeMap::new(),
        output_bytes: 0,
    })
}

/// Bind an operator's choices to the exact captured bytes. Reacquire the original lifecycle,
/// storage and alias guards before calling. Intent and catalog admission remain separate.
pub fn plan_previewed(
    runtime: &Path,
    bindings: &MigrationBindings,
    preview: &RecoveryPreview,
    selections: &[RecoverySelection],
) -> Result<MigrationPlan, String> {
    if runtime != preview.runtime || bindings != &preview.bindings || selections.is_empty() {
        return Err("recovery host configuration or selection changed; inspect again".into());
    }
    let _namespace = namespace::acquire(runtime, bindings, true)?;
    compare_views(&preview.views, &current_views(runtime, bindings)?)?;
    let mut roots = Vec::new();
    let mut journals = Vec::new();
    for selection in selections {
        let view = preview
            .views
            .get(&selection.candidate_id)
            .filter(|disk| disk.id == selection.disk_id)
            .ok_or("selection was not captured in this private recovery session")?;
        if let Some((path, stamp)) = preview.outputs.get(&selection.candidate_id) {
            verify_output(path, stamp)?;
        }
        journals.push(view.journal.as_deref());
        roots.push(
            view.sources
                .iter()
                .map(|source| {
                    preview
                        .copies
                        .get(&source.identity.object)
                        .map(|copy| copy.content_root.clone())
                        .ok_or("missing reviewed recovery layer")
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    let mut plan = plan_selected(runtime, bindings, selections)?;
    plan.bind_review(roots, &journals)?;
    Ok(plan)
}

pub(super) fn inspect_candidates(
    runtime: &Path,
    bindings: &MigrationBindings,
) -> Result<(Vec<CandidateSummary>, bool), String> {
    let _namespace = namespace::acquire(runtime, bindings, false)?;
    let views = current_views(runtime, bindings)?;
    let available = pin_union(runtime, bindings, &views).is_ok();
    // Preserve diagnostic candidate IDs even when capturing the whole set exceeds a limit.
    // Explicit selection still applies the independent limits to its chosen complete group.
    Ok((summaries(&views, bindings)?, available))
}

fn summaries(
    views: &BTreeMap<String, Disk>,
    bindings: &MigrationBindings,
) -> Result<Vec<CandidateSummary>, String> {
    let identity = format!("{}:{}", bindings.identity, bindings.config_revision);
    views.values().map(|view| view.summary(&identity)).collect()
}

fn current_views(
    runtime: &Path,
    bindings: &MigrationBindings,
) -> Result<BTreeMap<String, Disk>, String> {
    let sandbox = layout::host_root(runtime)?;
    for name in [
        "state-layout.json",
        ".storage-migration",
        "root-disk.json",
        "owned-disks",
        "checkpoints",
        "checkpoint-store",
        "guest-state",
    ] {
        match fs::symlink_metadata(sandbox.join(name)) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err("existing protected storage must resume its recorded operation".into());
            }
            Err(_) => return Err("cannot establish protected storage state".into()),
        }
    }
    if bindings.identity.is_empty()
        || bindings.identity.len() > 4096
        || bindings.config_revision.is_empty()
        || bindings.config_revision.len() > 4096
        || bindings.aliases.len() > 4096
        || runtime.file_name() != Some(std::ffi::OsStr::new("runtime"))
    {
        return Err("invalid recovery host bindings".into());
    }
    if let Some(root) = &bindings.root
        && (!matches!(root.format.as_str(), "raw" | "qcow2") || root.path.starts_with(runtime))
    {
        return Err("unsupported recovery root binding".into());
    }
    let identity = format!("{}:{}", bindings.identity, bindings.config_revision);
    let mut views = BTreeMap::new();
    let mut roles = BTreeSet::new();
    for view in source::recovery_views(runtime, bindings)? {
        roles.insert(view.id.clone());
        views.insert(view.candidate_id(&identity)?, view);
    }
    if views.is_empty()
        || roles.len() != usize::from(bindings.root.is_some()) + bindings.owned_disks.len()
    {
        return Err("every configured disk needs a complete authorized recovery view".into());
    }
    Ok(views)
}

fn compare_views(
    before: &BTreeMap<String, Disk>,
    after: &BTreeMap<String, Disk>,
) -> Result<(), String> {
    // Candidate IDs bind the ordered sources and their OS stamps, but deliberately omit
    // legacy journal bytes. Compare both before taking a decision based on prior inspection.
    if before.len() != after.len()
        || before.iter().any(|(id, disk)| {
            after
                .get(id)
                .is_none_or(|current| current.journal != disk.journal)
        })
    {
        return Err("recovery sources or selection changed; inspect again".into());
    }
    Ok(())
}

fn inventory(
    runtime: &Path,
    bindings: &MigrationBindings,
) -> Result<(BTreeMap<String, Disk>, Acquired), String> {
    let views = current_views(runtime, bindings)?;
    let acquired = pin_union(runtime, bindings, &views)?;
    Ok((views, acquired))
}

fn pin_union(
    runtime: &Path,
    bindings: &MigrationBindings,
    views: &BTreeMap<String, Disk>,
) -> Result<Acquired, String> {
    // Never enumerate the Cartesian product of alternatives. Pin and charge each distinct
    // object once, and still reject objects shared between unrelated configured roles.
    let mut disks = BTreeMap::new();
    let mut objects = BTreeMap::new();
    for view in views.values() {
        let disk = disks.entry(view.id.clone()).or_insert_with(|| {
            let mut disk = view.clone();
            disk.sources.clear();
            disk
        });
        for source in &view.sources {
            if let Some(role) = objects.get(&source.identity.object) {
                if role != &view.id {
                    return Err("different recovery disk roles share an inode".into());
                }
            } else {
                objects.insert(source.identity.object.clone(), view.id.clone());
                disk.sources.push(source.clone());
            }
        }
    }
    let acquired = source::reacquire(runtime, bindings, &disks.into_values().collect::<Vec<_>>())?;
    budget_all_heads(&acquired)?;
    Ok(acquired)
}

fn budget_all_heads(acquired: &Acquired) -> Result<(), String> {
    let mut budget = ParserBudget::default();
    for (disk, files) in acquired.disks.iter().zip(&acquired.files) {
        for (source, file) in disk.sources.iter().zip(files) {
            // Any authorized prefix can be a chosen writable head. Charge that role even
            // when an object is shared as a predecessor by another candidate.
            budget.layer(file, source.format == "qcow2", !disk.readonly)?;
        }
    }
    Ok(())
}

fn verify_output(path: &Path, stamp: &io::Identity) -> Result<(), String> {
    if io::identity(&io::exact(path)?)? != *stamp {
        return Err(
            "the disposable inspection image changed; inspect a fresh recovery session".into(),
        );
    }
    Ok(())
}

fn content_root(file: &File) -> Result<String, String> {
    sparse_file_integrity_handle(file)
        .map(|proof| proof.root)
        .map_err(|_| "cannot authenticate reviewed disk content".into())
}

pub(super) fn verify_content(file: &File, expected: &str) -> Result<(), String> {
    if content_root(file)? != expected {
        return Err("disk bytes differ from the reviewed recovery view; preserve the original and inspect again".into());
    }
    Ok(())
}
