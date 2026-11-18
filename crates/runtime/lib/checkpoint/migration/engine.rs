//! Frozen plans and forward-only multi-disk publication.

use std::fs;
use std::path::{Path, PathBuf};

use microsandbox_image::checkpoint::{CompactLayer, layer_capacities, sparse_file_integrity};
use serde::{Deserialize, Serialize};

use super::super::layout;
use super::budget::ParserBudget;
use super::io::{self, Identity};
use super::source::{self, Acquired, Disk};
use super::types::{
    AliasSource, Inspection, MigrationBindings, MigrationStatus, RecoverySelection,
};
use super::{namespace, preview};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const OPERATION_SCHEMA: &str = "microsandbox.storage-migration/1";
const IN_PROGRESS_SCHEMA: &str = "microsandbox.protected-layout/migrating-2";
const DIRECTORY: &str = ".storage-migration";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A pinned, validated selection. The SDK retains lifecycle/storage ownership throughout its
/// lifetime, records intent, durably fences the catalog, then calls `complete` synchronously.
pub struct MigrationPlan {
    runtime: PathBuf,
    inspection: Inspection,
    operation: Option<Operation>,
    acquired: Option<Acquired>,
    recorded: bool,
    _namespace: Option<namespace::Guard>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    schema: String,
    id: String,
    bindings: MigrationBindings,
    disks: Vec<Disk>,
    captures: Vec<Vec<Option<Identity>>>,
    layer_ids: Vec<Vec<String>>,
    volume_ids: Vec<String>,
    barrier: bool,
    /// Durable proof that every capture belongs to one continuously protected source epoch.
    #[serde(default)]
    group_captured: bool,
    /// A reviewed operation must preserve the exact pre-normalization bytes of every
    /// chosen layer, including after process death and source reacquisition.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    reviewed_roots: Vec<Vec<String>>,
    /// Original host-created schema-1 simple preparation, if present.
    previous_layout: Option<Vec<u8>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MigrationPlan {
    /// True when ordinary bounded readiness checks completed without legacy discovery.
    pub fn is_ready(&self) -> bool {
        self.operation.is_none()
    }

    /// Read-only summary of the selected view and estimated capture requirements.
    pub fn inspection(&self) -> &Inspection {
        &self.inspection
    }

    /// Persist intent and original journal bytes before the caller's durable catalog fence.
    /// Does not install guards, change source disks, or publish authoritative journals.
    pub fn record_intent(&mut self) -> Result<(), String> {
        if self.is_ready() || self.recorded {
            return Ok(());
        }
        self.revalidate()?;
        let sandbox = layout::host_root(&self.runtime)?;
        let directory = sandbox.join(DIRECTORY);
        if fs::symlink_metadata(&directory).is_ok() {
            return Err(
                "migration intent directory already exists without the expected operation".into(),
            );
        }
        // Publish the intent directory as one durable rename. A crash between creating an
        // empty directory and writing its record must not strand an otherwise untouched sandbox.
        let staging = tempfile::Builder::new()
            .prefix(".storage-migration-intent-")
            .tempdir_in(sandbox)
            .map_err(|error| format!("create migration intent staging: {error}"))?;
        io::harden_created(staging.path(), true)?;
        let bytes = serde_json::to_vec(self.operation.as_ref().unwrap())
            .map_err(|_| "cannot encode migration intent")?;
        layout::atomic_write(&staging.path().join("operation.json"), &bytes)?;
        io::publish(staging.path(), &directory)?;
        self.recorded = true;
        Ok(())
    }

    /// Finish a recorded operation after durable catalog protection is established.
    ///
    /// This is synchronous by design: cancellation cannot release caller-owned lifecycle locks
    /// while a detached copy worker keeps accessing the sandbox. Every worker is joined.
    pub fn complete(self) -> Result<(), String> {
        self.complete_with_checkpoint(|_| Ok(()))
    }

    fn complete_with_checkpoint(
        mut self,
        mut checkpoint: impl FnMut(&str) -> Result<(), String>,
    ) -> Result<(), String> {
        if self.is_ready() {
            return Ok(());
        }
        if !self.recorded {
            return Err("migration intent must precede catalog admission and capture".into());
        }
        self.revalidate()?;
        let sandbox = layout::host_root(&self.runtime)?.to_path_buf();
        let marker = serde_json::json!({"schema":IN_PROGRESS_SCHEMA,"operation":self.operation.as_ref().unwrap().id});
        // This actual entry-point schema, not merely a sidecar, makes schema-1 readers refuse.
        layout::atomic_write(
            &sandbox.join("state-layout.json"),
            &serde_json::to_vec(&marker).map_err(|_| "cannot encode migration barrier")?,
        )?;
        checkpoint("layout-barrier")?;
        layout::install_import_guards(&self.runtime)?;
        checkpoint("legacy-guards")?;
        self.operation.as_mut().unwrap().barrier = true;
        self.persist()?;
        checkpoint("admitted")?;
        self.revalidate()?;
        let count = self.operation.as_ref().unwrap().disks.len();
        if !self.operation.as_ref().unwrap().group_captured {
            self.reset_uncertified_captures()?;
            for disk_index in 0..count {
                self.capture_disk(disk_index)?;
                checkpoint("captured-disk")?;
            }
            // A per-layer completion record is not a coherent group. Audit every original
            // source after the last source read while the same writer guards remain held.
            self.revalidate()?;
            self.operation.as_mut().unwrap().group_captured = true;
            self.persist()?;
            checkpoint("captured-group")?;
        }
        // Recheck the complete private group, including records certified by an older
        // importer, before any full parser or authoritative journal publication.
        verify_captured_group(&self.runtime, self.operation.as_ref().unwrap())?;
        for disk_index in 0..count {
            self.validate_captured_disk(disk_index)?;
        }
        // No ready consumer may see only part of the group. Publish all journals under the
        // rejecting marker; an interrupted publication repeats these exact generated bytes.
        for index in 0..count {
            self.publish_disk(index)?;
            checkpoint("published-journal")?;
        }
        checkpoint("before-ready")?;
        // External write-through disks remain authoritative at their original paths. Their
        // protection must still be intact when Ready is published; private internal copies
        // no longer depend on the original sources after the group certificate.
        if self
            .operation
            .as_ref()
            .unwrap()
            .disks
            .iter()
            .any(|disk| disk.external)
        {
            self.revalidate()?;
        }
        layout::publish_import_ready(&self.runtime)?;
        Ok(())
    }

    fn persist(&self) -> Result<(), String> {
        let bytes = serde_json::to_vec(
            self.operation
                .as_ref()
                .ok_or("missing migration operation")?,
        )
        .map_err(|_| "cannot encode migration operation")?;
        if bytes.len() as u64 > io::MAX_METADATA {
            return Err("migration operation exceeds its metadata bound".into());
        }
        layout::atomic_write(
            &layout::host_root(&self.runtime)?
                .join(DIRECTORY)
                .join("operation.json"),
            &bytes,
        )
    }

    pub(super) fn bind_review(
        &mut self,
        roots: Vec<Vec<String>>,
        journals: &[Option<&[u8]>],
    ) -> Result<(), String> {
        let operation = self
            .operation
            .as_mut()
            .ok_or("missing recovery selection")?;
        // Selection is reacquired after provisional discovery. Bind its actual frozen
        // journals to what the operator reviewed, closing the interval between the two.
        if operation.disks.len() != journals.len()
            || operation
                .disks
                .iter()
                .zip(journals)
                .any(|(disk, expected)| disk.journal.as_deref() != *expected)
        {
            return Err("reviewed disk selection changed during final acquisition".into());
        }
        operation.reviewed_roots = roots;
        validate_record_bound(operation)?;
        verify_reviewed_sources(
            operation,
            self.acquired
                .as_ref()
                .ok_or("missing pinned recovery sources")?,
        )?;
        self.revalidate()
    }

    fn revalidate(&self) -> Result<(), String> {
        let operation = self
            .operation
            .as_ref()
            .ok_or("missing migration operation")?;
        let acquired = self
            .acquired
            .as_ref()
            .ok_or("missing pinned migration sources")?;
        acquired
            .writers
            .as_ref()
            .ok_or("execution has no source writer protection")?
            .audit()?;
        if operation.group_captured {
            verify_captured_group(&self.runtime, operation)?;
        }
        for (disk, files) in acquired.disks.iter().zip(&acquired.files) {
            for (source, file) in disk.sources.iter().zip(files) {
                if io::identity(file)? != source.identity {
                    return Err("migration source changed; retry inspection without modifying original data".into());
                }
            }
        }
        if !operation.barrier {
            let sandbox = layout::host_root(&self.runtime)?;
            let anchor = io::directory(sandbox)?;
            let marker = io::bytes(&anchor, Path::new("state-layout.json"))?;
            let partial_barrier = marker
                .as_ref()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(bytes).ok())
                .is_some_and(|value| {
                    value.get("schema").and_then(|v| v.as_str()) == Some(IN_PROGRESS_SCHEMA)
                        && value.get("operation").and_then(|v| v.as_str())
                            == Some(operation.id.as_str())
                });
            for disk in &operation.disks {
                let path = if disk.id == "root" {
                    PathBuf::from("runtime/root-disk.json")
                } else {
                    Path::new("runtime/owned-disks")
                        .join(&disk.id)
                        .join("disk.json")
                };
                let current = io::bytes(&anchor, &path)?;
                let root_guard = disk.id == "root"
                    && current.as_deref()
                        == Some(
                            b"{\"schema\":\"microsandbox.upgrade-required/protected-state\"}\n",
                        );
                let historical_barrier = operation.previous_layout.as_ref() == marker.as_ref()
                    && operation.previous_layout.is_some();
                if current != disk.journal
                    && !((partial_barrier || historical_barrier) && root_guard)
                {
                    return Err("legacy selection changed before admission; preserve the frozen operation for recovery".into());
                }
            }
        }
        // Reopening here checks namespace identities as well as retained handles. It never
        // chooses a different journal head, including after an interruption during fencing.
        let _verified = source::reacquire(&self.runtime, &operation.bindings, &acquired.disks)?;
        // Keep the final audit after namespace/alias checks too: certification follows this
        // audit without any subsequent reads from original source objects.
        acquired.writers.as_ref().unwrap().audit()?;
        Ok(())
    }

    fn reset_uncertified_captures(&mut self) -> Result<(), String> {
        let operation = self.operation.as_ref().unwrap();
        let sandbox = layout::host_root(&self.runtime)?;
        for (disk_index, disk) in operation.disks.iter().enumerate() {
            if !needs_capture(disk) {
                continue;
            }
            let directory = destination_directory(sandbox, operation, disk_index);
            for (layer_index, expected) in operation.captures[disk_index].iter().enumerate() {
                if let Some(expected) = expected {
                    io::verify_private_directory(&directory)?;
                    let path = destination_path(
                        &directory,
                        layer_index,
                        &disk.sources[layer_index].format,
                    );
                    if io::identity(&io::exact(&path)?)? != *expected {
                        return Err(
                            "uncertified private capture changed; preserve it for recovery".into(),
                        );
                    }
                }
            }
        }
        // Persist the reset before unlinking any prior output. A crash during recapture sees
        // only uncommitted destinations and cannot combine layers from two source epochs.
        for disk in &mut self.operation.as_mut().unwrap().captures {
            disk.fill(None);
        }
        self.persist()
    }

    fn capture_disk(&mut self, index: usize) -> Result<(), String> {
        let operation = self.operation.as_ref().unwrap();
        let disk = &operation.disks[index];
        if !needs_capture(disk) {
            return Ok(());
        }
        let destination =
            destination_directory(layout::host_root(&self.runtime)?, operation, index);
        io::private_directory(&destination)?;
        let layers = disk.sources.len();
        for layer_index in 0..layers {
            let operation = self.operation.as_ref().unwrap();
            let disk = &operation.disks[index];
            let target =
                destination_path(&destination, layer_index, &disk.sources[layer_index].format);
            if let Some(expected) = &operation.captures[index][layer_index] {
                let file = io::exact(&target)?;
                if io::identity(&file)? != *expected {
                    return Err(
                        "completed private capture changed; preserve migration state for recovery"
                            .into(),
                    );
                }
                continue;
            }
            // A file without a completion record is our interrupted output, never a source.
            // Its generated path lies in the private operation namespace; unlinking a planted
            // symlink does not follow it. Completed captures are never silently overwritten.
            match fs::symlink_metadata(&target) {
                Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
                    fs::remove_file(&target).map_err(|_| "cannot remove incomplete capture")?
                }
                Ok(_) => return Err("incomplete capture has an unexpected file type".into()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("inspect incomplete capture: {error}")),
            }
            let file = &self.acquired.as_ref().unwrap().files[index][layer_index];
            io::capture(file, &target)?;
            // Normalize embedded dependency names only after authenticating the bytes
            // reviewed by the operator. The durable group certificate covers the results.
            if let Some(roots) = operation.reviewed_roots.get(index) {
                preview::verify_content(&io::exact(&target)?, &roots[layer_index])?;
            }
            let (capacity, backing) = io::header(
                &io::exact(&target)?,
                disk.sources[layer_index].format == "qcow2",
            )?;
            let expected_backing = layer_index
                .checked_sub(1)
                .and_then(|previous| disk.sources[previous].path.file_name())
                .and_then(|name| name.to_str());
            if capacity != disk.sources[layer_index].capacity
                || backing.as_deref() != expected_backing
            {
                return Err("captured disk header differs from the frozen selected closure".into());
            }
            if layer_index > 0 {
                let previous = destination_path(
                    &destination,
                    layer_index - 1,
                    &disk.sources[layer_index - 1].format,
                );
                microsandbox_image::checkpoint::relocate_qcow2_backing(&target, &previous)
                    .map_err(|_| "cannot normalize private qcow dependency")?;
            }
            let captured = io::exact(&target)?;
            // capture and backing normalization each flush their writable handles. This
            // read-only pin cannot be flushed on Windows (FlushFileBuffers needs write access).
            let identity = io::identity(&captured)?;
            if identity.object == disk.sources[layer_index].identity.object || identity.links != 1 {
                return Err("private capture is not an independent inode".into());
            }
            self.operation.as_mut().unwrap().captures[index][layer_index] = Some(identity);
            self.persist()?;
        }
        Ok(())
    }

    fn validate_captured_disk(&self, index: usize) -> Result<(), String> {
        let operation = self.operation.as_ref().unwrap();
        let disk = &operation.disks[index];
        if !needs_capture(disk) {
            return Ok(());
        }
        let destination =
            destination_directory(layout::host_root(&self.runtime)?, operation, index);
        let mut previous_capacity = 0;
        for (layer_index, source) in disk.sources.iter().enumerate() {
            let path = destination_path(&destination, layer_index, &source.format);
            let (capacity, backing) = io::header(&io::exact(&path)?, source.format == "qcow2")?;
            let expected = layer_index
                .checked_sub(1)
                .map(|previous| format!("layer-{previous:03}.{}", disk.sources[previous].format));
            if capacity != source.capacity || capacity < previous_capacity || backing != expected {
                return Err("private captured dependency or capacity changed".into());
            }
            previous_capacity = capacity;
        }
        let layers = disk
            .sources
            .iter()
            .enumerate()
            .map(|(i, source)| CompactLayer {
                path: destination_path(&destination, i, &source.format),
                qcow2: source.format == "qcow2",
            })
            .collect::<Vec<_>>();
        // The closure was checked above; linking parser objects adds no validation and
        // would retain every ancestor's L1 table. This joined worker fully parses one private
        // capture at a time, denies implicit dependency opens, and drops its parser before
        // opening the next. Only bounded capacity values survive between layers.
        let capacities =
            layer_capacities(layers).map_err(|_| "captured disk chain is invalid".to_string())?;
        if capacities.len() != disk.sources.len()
            || capacities
                .iter()
                .zip(&disk.sources)
                .any(|(size, source)| *size != source.capacity)
        {
            return Err("private captured dependency or capacity changed".into());
        }
        Ok(())
    }

    fn publish_disk(&self, index: usize) -> Result<(), String> {
        let operation = self.operation.as_ref().unwrap();
        let disk = &operation.disks[index];
        let sandbox = layout::host_root(&self.runtime)?;
        let directory = destination_directory(sandbox, operation, index);
        let mut layers = Vec::new();
        for (layer_index, source) in disk.sources.iter().enumerate() {
            let path = if disk.external {
                source.path.clone()
            } else {
                destination_path(&directory, layer_index, &source.format)
            };
            let integrity = if disk.id != "root" && layer_index + 1 < disk.sources.len() {
                Some(
                    sparse_file_integrity(&path)
                        .map_err(|_| "cannot verify captured owned ancestor")?
                        .root,
                )
            } else {
                None
            };
            let journal_path = if disk.id == "root" {
                path
            } else {
                io::relative(&path, sandbox)?
            };
            layers.push(serde_json::json!({"layer_id":operation.layer_ids[index][layer_index],"path":journal_path,"format":source.format,"integrity_root":integrity}));
        }
        let (path, value) = if disk.id == "root" {
            (
                sandbox.join("root-disk.json"),
                serde_json::json!({
                    "schema":"microsandbox.runtime-root-disk/1","volume_id":operation.volume_ids[index],
                    "device_id":if disk.flat {"vda"}else{"vdb"},"layout":if disk.flat {"flat-root"}else{"managed-upper"},
                    "published_generation":0,"launch_base":disk.launch_base,"layers":layers
                }),
            )
        } else {
            let parent = sandbox.join("owned-disks");
            io::private_directory(&parent)?;
            let parent = parent.join(&disk.id);
            io::private_directory(&parent)?;
            (
                parent.join("disk.json"),
                serde_json::json!({
                    "schema":"microsandbox.runtime-owned-disk/1","volume_id":operation.volume_ids[index],
                    "device_id":disk.id,"launch_base":io::relative(&disk.launch_base,sandbox)?,"read_only":disk.readonly,
                    "generation":0,"layers":layers
                }),
            )
        };
        layout::atomic_write(
            &path,
            &serde_json::to_vec(&value).map_err(|_| "cannot encode protected disk journal")?,
        )
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Inspect only the requested sandbox; never mutate guards, catalogs, permissions, or disks.
/// Live inspection is provisional and must be repeated under lifecycle ownership before import.
pub fn inspect(runtime: &Path, bindings: &MigrationBindings) -> Result<Inspection, String> {
    // Inspection can run while legacy writers exist. Only bounded metadata/header parsing is
    // permitted here; full image parsing uses only independent private captures during execution.
    match plan_inner(runtime, bindings, false) {
        Ok(plan) => Ok(plan.inspection),
        Err(reason) => {
            let (candidates, preview_available) =
                preview::inspect_candidates(runtime, bindings).unwrap_or_default();
            // Alternatives are mutually exclusive within one disk role, but every role
            // must be imported. Sum each role's largest complete candidate, with overflow checks.
            let mut per_disk = std::collections::BTreeMap::<&str, u64>::new();
            for candidate in &candidates {
                let estimate = per_disk.entry(&candidate.disk_id).or_default();
                *estimate = (*estimate).max(candidate.estimated_bytes);
            }
            let estimated_bytes = per_disk
                .values()
                .try_fold(0u64, |sum, bytes| sum.checked_add(*bytes))
                .ok_or("recovery capture estimate exceeds its size bound")?;
            Ok(Inspection {
                status: MigrationStatus::RecoveryRequired,
                preview_available,
                reasons: vec![reason],
                candidates,
                estimated_bytes,
            })
        }
    }
}

/// Plan an explicitly selected complete group. Candidate IDs are recomputed from current host
/// bindings and pinned source identities; serialized inspection output never grants authority.
/// An existing intent must resume its frozen view and cannot accept a different selection.
pub fn plan_selected(
    runtime: &Path,
    bindings: &MigrationBindings,
    selections: &[RecoverySelection],
) -> Result<MigrationPlan, String> {
    if selections.is_empty() {
        return plan(runtime, bindings);
    }
    let sandbox = layout::host_root(runtime)?;
    if fs::symlink_metadata(sandbox.join("state-layout.json")).is_ok()
        || fs::symlink_metadata(sandbox.join(DIRECTORY)).is_ok()
    {
        return Err(
            "recorded migration must resume its frozen selection without recovery overrides".into(),
        );
    }
    let namespace = namespace::acquire(runtime, bindings, true)?;
    let candidates = source::recovery_views(runtime, bindings)?;
    let required = usize::from(bindings.root.is_some()) + bindings.owned_disks.len();
    if selections.len() != required {
        return Err(
            "explicit recovery must select one complete view for every configured disk".into(),
        );
    }
    let mut selected = Vec::new();
    let mut roles = std::collections::BTreeSet::new();
    for selection in selections {
        if !roles.insert(&selection.disk_id) {
            return Err("recovery repeats a disk role".into());
        }
        let disk = candidates
            .iter()
            .find(|candidate| {
                candidate.id == selection.disk_id
                    && candidate
                        .candidate_id(&format!(
                            "{}:{}",
                            bindings.identity, bindings.config_revision
                        ))
                        .is_ok_and(|id| id == selection.candidate_id)
            })
            .ok_or("recovery candidate changed or is no longer authorized; inspect again")?;
        selected.push(disk.clone());
    }
    let mut acquired = source::reacquire(runtime, bindings, &selected)?;
    source::protect(&mut acquired)?;
    new_plan(runtime, bindings, acquired, namespace)
}

/// Resolve and retain a complete host-authorized view. No mutation occurs until record_intent.
/// Caller must retain lifecycle/storage ownership and exclude all corresponding alias writers.
pub fn plan(runtime: &Path, bindings: &MigrationBindings) -> Result<MigrationPlan, String> {
    plan_inner(runtime, bindings, true)
}

fn plan_inner(
    runtime: &Path,
    bindings: &MigrationBindings,
    protect_sources: bool,
) -> Result<MigrationPlan, String> {
    let sandbox = layout::host_root(runtime)?;
    let marker = layout::read_optional(&sandbox.join("state-layout.json"))?;
    if let Some(bytes) = &marker {
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| "invalid protected layout record")?;
        if value.get("schema").and_then(|v| v.as_str()) == Some("microsandbox.protected-layout/1")
            && value.get("phase").and_then(|v| v.as_str()) == Some("ready")
        {
            layout::require_ready(runtime)?;
            return Ok(MigrationPlan {
                runtime: runtime.into(),
                inspection: Inspection {
                    status: MigrationStatus::Ready,
                    preview_available: false,
                    reasons: Vec::new(),
                    candidates: Vec::new(),
                    estimated_bytes: 0,
                },
                operation: None,
                acquired: None,
                recorded: false,
                _namespace: None,
            });
        }
    }
    let namespace = namespace::acquire(runtime, bindings, protect_sources)?;
    let historical_preparing =
        layout::retained_legacy_root(runtime, bindings.root.as_ref())?.is_some();
    if let Some(bytes) = &marker {
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| "invalid protected layout record")?;
        if value.get("schema").and_then(|v| v.as_str()) != Some(IN_PROGRESS_SCHEMA)
            && !historical_preparing
        {
            return Err("layout preparation needs a supporting recovery version; preserve the original record".into());
        }
    }
    let anchor = io::directory(sandbox)?;
    if sandbox.join(DIRECTORY).exists() {
        io::verify_private_directory(&sandbox.join(DIRECTORY))?;
    }
    if let Some(bytes) = io::bytes(&anchor, &Path::new(DIRECTORY).join("operation.json"))? {
        let mut operation: Operation =
            serde_json::from_slice(&bytes).map_err(|_| "invalid migration operation record")?;
        let mut comparable = bindings.clone();
        if operation.group_captured {
            comparable.aliases = operation.bindings.aliases.clone();
        }
        if operation.schema != OPERATION_SCHEMA
            || operation.bindings != comparable
            || !valid_operation(&operation)
        {
            return Err(
                "migration record or host configuration changed; preserve it for recovery".into(),
            );
        }
        if let Some(marker) = marker {
            let value: serde_json::Value =
                serde_json::from_slice(&marker).map_err(|_| "invalid migration layout marker")?;
            let new_marker = value.get("schema").and_then(|v| v.as_str())
                == Some(IN_PROGRESS_SCHEMA)
                && value.get("operation").and_then(|v| v.as_str()) == Some(operation.id.as_str());
            if !new_marker
                && (operation.barrier || operation.previous_layout.as_ref() != Some(&marker))
            {
                return Err("migration entry-point and operation identity differ".into());
            }
        }
        let sources = if operation.group_captured {
            verify_captured_group(runtime, &operation)?;
            operation
                .disks
                .iter()
                .filter(|disk| disk.external)
                .cloned()
                .collect()
        } else {
            operation.disks.clone()
        };
        let mut acquired = source::reacquire(runtime, bindings, &sources)?;
        if protect_sources {
            source::protect(&mut acquired)?;
            verify_reviewed_sources(&operation, &acquired)?;
        }
        if operation.group_captured {
            operation.bindings.aliases = bindings.aliases.clone();
        }
        let inspection = summary(
            MigrationStatus::InProgress,
            &operation.disks,
            &format!("{}:{}", bindings.identity, bindings.config_revision),
        )?;
        return Ok(MigrationPlan {
            runtime: runtime.into(),
            inspection,
            operation: Some(operation),
            acquired: Some(acquired),
            recorded: true,
            _namespace: Some(namespace),
        });
    }
    if marker.is_some() && !historical_preparing {
        return Err("migration entry-point is missing its durable operation".into());
    }
    for name in [
        "root-disk.json",
        "owned-disks",
        "checkpoints",
        "checkpoint-store",
        "guest-state",
        DIRECTORY,
    ] {
        if fs::symlink_metadata(sandbox.join(name)).is_ok() {
            if historical_preparing && matches!(name, "root-disk.json" | "guest-state") {
                if name == "guest-state" {
                    io::directory(&sandbox.join(name))?;
                    if fs::read_dir(sandbox.join(name))
                        .map_err(|_| "cannot inspect historical guest directory")?
                        .next()
                        .is_some()
                    {
                        return Err(
                            "historical preparing layout contains unexpected guest state".into(),
                        );
                    }
                } else {
                    let retained = layout::retained_legacy_root(runtime, bindings.root.as_ref())?
                        .flatten()
                        .ok_or("unexpected protected root during historical preparation")?;
                    let existing = layout::read_optional(&sandbox.join(name))?
                        .ok_or("historical protected root missing")?;
                    if serde_json::from_slice::<serde_json::Value>(&existing).ok()
                        != serde_json::from_slice::<serde_json::Value>(&retained).ok()
                    {
                        return Err(
                            "historical protected root differs from its retained simple view"
                                .into(),
                        );
                    }
                }
                continue;
            }
            return Err("unrecorded protected storage requires recovery".into());
        }
    }
    let acquired = if protect_sources {
        source::acquire(runtime, bindings)?
    } else {
        source::acquire_metadata(runtime, bindings)?
    };
    new_plan(runtime, bindings, acquired, namespace)
}

fn new_plan(
    runtime: &Path,
    bindings: &MigrationBindings,
    acquired: Acquired,
    namespace: namespace::Guard,
) -> Result<MigrationPlan, String> {
    let inspection = summary(
        MigrationStatus::Eligible,
        &acquired.disks,
        &format!("{}:{}", bindings.identity, bindings.config_revision),
    )?;
    let operation = Operation {
        schema: OPERATION_SCHEMA.into(),
        id: hex::encode(rand::random::<[u8; 16]>()),
        bindings: bindings.clone(),
        disks: acquired.disks.clone(),
        captures: acquired
            .disks
            .iter()
            .map(|d| vec![None; d.sources.len()])
            .collect(),
        layer_ids: acquired
            .disks
            .iter()
            .map(|d| d.sources.iter().map(|_| fresh_id("layer")).collect())
            .collect(),
        volume_ids: acquired.disks.iter().map(|_| fresh_id("vol")).collect(),
        barrier: false,
        group_captured: false,
        reviewed_roots: Vec::new(),
        previous_layout: layout::read_optional(
            &layout::host_root(runtime)?.join("state-layout.json"),
        )?,
    };
    validate_record_bound(&operation)?;
    Ok(MigrationPlan {
        runtime: runtime.into(),
        inspection,
        operation: Some(operation),
        acquired: Some(acquired),
        recorded: false,
        _namespace: Some(namespace),
    })
}

fn validate_record_bound(operation: &Operation) -> Result<(), String> {
    // Capture slots start as null but later hold independent file identities. Reserve their
    // largest encoding before intent/admission so a valid initial record cannot become
    // permanently unpersistable after copying. Unix object IDs contain two u64 decimals
    // (41 bytes); Windows uses three u32 decimals (32 bytes). All other numeric fields use
    // their full type widths. Later false -> true phase flags only shorten the record.
    let largest_capture = Identity {
        object: format!("{}:{}", u64::MAX, u64::MAX),
        length: u64::MAX,
        links: u64::MAX,
        modified: (u64::MAX, u32::MAX),
        changed: Some((i64::MIN, i64::MIN)),
    };
    let capture_growth = serde_json::to_vec(&largest_capture)
        .map_err(|_| "cannot encode migration capture identity")?
        .len()
        - b"null".len();
    let capture_count = operation
        .disks
        .iter()
        .filter(|disk| needs_capture(disk))
        .try_fold(0usize, |count, disk| count.checked_add(disk.sources.len()));
    let initial_size = serde_json::to_vec(operation)
        .map_err(|_| "cannot encode migration operation")?
        .len();
    let maximum_size = capture_count
        .and_then(|count| count.checked_mul(capture_growth))
        .and_then(|growth| initial_size.checked_add(growth))
        .ok_or("migration operation exceeds its metadata bound")?;
    if maximum_size as u64 > io::MAX_METADATA {
        return Err("migration operation exceeds its metadata bound".into());
    }
    Ok(())
}

pub(super) fn frozen_disks(
    runtime: &Path,
    bindings: &MigrationBindings,
) -> Result<Option<Vec<Disk>>, String> {
    let sandbox = layout::host_root(runtime)?;
    if !sandbox.join(DIRECTORY).exists() {
        return Ok(None);
    }
    let _namespace = namespace::acquire(runtime, bindings, false)?;
    io::verify_private_directory(&sandbox.join(DIRECTORY))?;
    let anchor = io::directory(sandbox)?;
    let bytes = io::bytes(&anchor, &Path::new(DIRECTORY).join("operation.json"))?
        .ok_or("migration intent is missing its operation record")?;
    let operation: Operation =
        serde_json::from_slice(&bytes).map_err(|_| "invalid migration operation record")?;
    // The SDK rediscovers alias writers before admission. Only its host identity and configured
    // roles, rather than a provisional alias list, define the recorded selection's authority.
    if operation.schema != OPERATION_SCHEMA
        || operation.bindings.identity != bindings.identity
        || operation.bindings.config_revision != bindings.config_revision
        || operation.bindings.root != bindings.root
        || operation.bindings.owned_disks != bindings.owned_disks
        || !valid_operation(&operation)
    {
        return Err("migration host bindings changed; preserve recorded recovery state".into());
    }
    if operation.group_captured {
        verify_captured_group(runtime, &operation)?;
        Ok(Some(
            operation
                .disks
                .into_iter()
                .filter(|disk| disk.external)
                .collect(),
        ))
    } else {
        Ok(Some(operation.disks))
    }
}

pub(super) fn retained_sources(
    runtime: &Path,
    bindings: &MigrationBindings,
) -> Result<Vec<AliasSource>, String> {
    layout::require_ready(runtime)?;
    let sandbox = layout::host_root(runtime)?;
    if !sandbox.join(DIRECTORY).exists() {
        return Ok(Vec::new());
    }
    let _namespace = namespace::acquire(runtime, bindings, false)?;
    io::verify_private_directory(&sandbox.join(DIRECTORY))?;
    let anchor = io::directory(sandbox)?;
    let Some(bytes) = io::bytes(&anchor, &Path::new(DIRECTORY).join("operation.json"))? else {
        return Err("completed migration is missing its retained-source record".into());
    };
    let operation: Operation =
        serde_json::from_slice(&bytes).map_err(|_| "invalid retained migration record")?;
    if operation.schema != OPERATION_SCHEMA
        || !operation.barrier
        || !valid_operation(&operation)
        || operation.bindings.identity != bindings.identity
    {
        return Err("retained migration source bindings do not match this sandbox".into());
    }
    let mut result = Vec::new();
    for (index, disk) in operation.disks.iter().enumerate() {
        // External write-through resources were intentionally not detached and are not inert.
        if disk.external {
            continue;
        }
        if operation.captures[index].iter().any(Option::is_none) {
            return Err("ready migration has incomplete capture records".into());
        }
        for source in &disk.sources {
            let relative = io::relative(&source.path, sandbox)?;
            if !source::source_role(&relative, &disk.id, disk.flat, &source.format) {
                return Err("retained source has an invalid historical producer role".into());
            }
            let file = match io::open(&anchor, &relative) {
                Ok(file) => file,
                Err(_) => continue,
            };
            let identity = io::identity(&file)?;
            if identity.object != source.identity.object {
                continue;
            }
            result.push(AliasSource {
                disk_id: disk.id.clone(),
                path: source.path.clone(),
                identity_object: identity.object,
                links: identity.links,
                readonly: true,
            });
        }
    }
    Ok(result)
}

fn summary(status: MigrationStatus, disks: &[Disk], identity: &str) -> Result<Inspection, String> {
    let candidates = disks
        .iter()
        .map(|disk| disk.summary(identity))
        .collect::<Result<Vec<_>, _>>()?;
    let estimated_bytes = candidates.iter().try_fold(0u64, |sum, candidate| {
        sum.checked_add(candidate.estimated_bytes)
            .ok_or("capture estimate overflow")
    })?;
    Ok(Inspection {
        status,
        preview_available: false,
        reasons: Vec::new(),
        candidates,
        estimated_bytes,
    })
}

fn needs_capture(disk: &Disk) -> bool {
    !disk.external || disk.sources.iter().any(|source| source.format == "qcow2")
}

fn verify_captured_group(runtime: &Path, operation: &Operation) -> Result<(), String> {
    let sandbox = layout::host_root(runtime)?;
    let mut budget = ParserBudget::default();
    for (index, disk) in operation.disks.iter().enumerate() {
        if !needs_capture(disk) {
            for (layer, source) in disk.sources.iter().enumerate() {
                budget.layer(
                    &io::exact(&source.path)?,
                    source.format == "qcow2",
                    !disk.readonly && layer + 1 == disk.sources.len(),
                )?;
            }
            continue;
        }
        let directory = destination_directory(sandbox, operation, index);
        io::verify_private_directory(&directory)?;
        for (layer, source) in disk.sources.iter().enumerate() {
            let expected = operation.captures[index][layer]
                .as_ref()
                .ok_or("certified capture is incomplete")?;
            let file = io::exact(&destination_path(&directory, layer, &source.format))?;
            if io::identity(&file)? != *expected {
                return Err("certified private capture changed; preserve recovery state".into());
            }
            budget.layer(
                &file,
                source.format == "qcow2",
                !disk.readonly && layer + 1 == disk.sources.len(),
            )?;
        }
    }
    Ok(())
}

fn destination_directory(sandbox: &Path, operation: &Operation, index: usize) -> PathBuf {
    let disk = &operation.disks[index];
    if disk.id == "root" {
        sandbox
            .join(DIRECTORY)
            .join(format!("root-{}", operation.id))
    } else {
        sandbox
            .join("owned-volumes")
            .join(&disk.id)
            .join(format!(".migration-{}", operation.id))
    }
}
fn destination_path(directory: &Path, index: usize, format: &str) -> PathBuf {
    directory.join(format!("layer-{index:03}.{format}"))
}
fn fresh_id(prefix: &str) -> String {
    format!("{prefix}_{}", hex::encode(rand::random::<[u8; 16]>()))
}
fn verify_reviewed_sources(operation: &Operation, acquired: &Acquired) -> Result<(), String> {
    if operation.reviewed_roots.is_empty() {
        return Ok(());
    }
    for (disk, files) in acquired.disks.iter().zip(&acquired.files) {
        let index = operation
            .disks
            .iter()
            .position(|item| item.id == disk.id)
            .ok_or("reviewed disk no longer has a configured role")?;
        let roots = operation
            .reviewed_roots
            .get(index)
            .filter(|roots| roots.len() == files.len())
            .ok_or("incomplete reviewed disk content binding")?;
        for (file, root) in files.iter().zip(roots) {
            preview::verify_content(file, root)?;
        }
    }
    acquired
        .writers
        .as_ref()
        .ok_or("reviewed disks need writer protection")?
        .audit()
}

fn valid_operation(operation: &Operation) -> bool {
    operation.id.len() == 32
        && operation
            .id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && (operation.reviewed_roots.is_empty()
            || (operation.reviewed_roots.len() == operation.disks.len()
                && operation
                    .reviewed_roots
                    .iter()
                    .zip(&operation.disks)
                    .all(|(roots, disk)| {
                        roots.len() == disk.sources.len()
                            && roots.iter().all(|root| {
                                root.strip_prefix("blake3:").is_some_and(|hash| {
                                    hash.len() == 64
                                        && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                                })
                            })
                    })))
        && operation.disks.len() <= 65
        && (!operation.group_captured || operation.barrier)
        && operation.captures.len() == operation.disks.len()
        && operation.layer_ids.len() == operation.disks.len()
        && operation.volume_ids.len() == operation.disks.len()
        && operation.disks.len()
            == usize::from(operation.bindings.root.is_some()) + operation.bindings.owned_disks.len()
        && operation
            .disks
            .iter()
            .map(|d| &d.id)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == operation.disks.len()
        && operation.disks.iter().enumerate().all(|(i, d)| {
            let binding_valid = if d.id == "root" {
                operation.bindings.root.as_ref().is_some_and(|root| {
                    d.launch_base == root.path
                        && d.flat == root.flat
                        && !d.readonly
                        && (!d.external
                            || (d.sources.len() == 1
                                && d.sources[0].path == root.path
                                && d.sources[0].format == root.format))
                })
            } else {
                operation.bindings.owned_disks.iter().any(|owned| {
                    owned.id == d.id
                        && owned.path == d.launch_base
                        && owned.readonly == d.readonly
                        && !d.external
                        && !d.flat
                })
            };
            binding_valid
                && operation.volume_ids[i]
                    .strip_prefix("vol_")
                    .is_some_and(hex_identity)
                && operation.layer_ids[i]
                    .iter()
                    .all(|id| id.strip_prefix("layer_").is_some_and(hex_identity))
                && !d.sources.is_empty()
                && d.sources.len() <= 256
                && operation.captures[i].len() == d.sources.len()
                && (!operation.group_captured
                    || !needs_capture(d)
                    || operation.captures[i].iter().all(Option::is_some))
                && operation.layer_ids[i].len() == d.sources.len()
        })
}

fn hex_identity(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write};

    use super::super::types::{AuthorizedAlias, OwnedDiskBinding};
    use super::*;
    use crate::checkpoint::{load_runtime_owned_disk_chain, load_runtime_owned_root_chain};

    fn fixture() -> (tempfile::TempDir, PathBuf, MigrationBindings) {
        fixture_at(tempfile::tempdir().unwrap())
    }

    fn fixture_at(temp: tempfile::TempDir) -> (tempfile::TempDir, PathBuf, MigrationBindings) {
        let sandbox = temp.path().canonicalize().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Match a private sandbox home even on hosts whose ambient umask is 0002.
            // Namespace refusal fixtures explicitly make this directory searchable later.
            fs::set_permissions(&sandbox, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let runtime = sandbox.join("runtime");
        fs::create_dir(&runtime).unwrap();
        let path = sandbox.join("upper.ext4");
        fs::write(&path, vec![23u8; 131072]).unwrap();
        let bindings = MigrationBindings {
            identity: "sandbox-incarnation".into(),
            config_revision: "saved-config-revision".into(),
            root: Some(layout::LegacyRootBinding {
                path,
                format: "raw".into(),
                flat: false,
            }),
            owned_disks: Vec::new(),
            aliases: Vec::new(),
        };
        (temp, runtime, bindings)
    }

    #[cfg(unix)]
    fn reachable_namespace_fixture() -> (tempfile::TempDir, PathBuf, MigrationBindings) {
        use std::os::unix::fs::PermissionsExt;
        let result = fixture_at(tempfile::tempdir_in("/tmp").unwrap());
        for path in [result.1.parent().unwrap(), result.1.as_path()] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        result
    }

    #[cfg(unix)]
    #[test]
    fn namespace_refusal_precedes_intent_and_private_resume_record_parsing() {
        use std::os::unix::fs::PermissionsExt;
        let (_temp, runtime, bindings) = reachable_namespace_fixture();
        let sandbox = runtime.parent().unwrap();
        let original = fs::read(&bindings.root.as_ref().unwrap().path).unwrap();
        fs::set_permissions(sandbox, fs::Permissions::from_mode(0o777)).unwrap();
        let error = plan(&runtime, &bindings).err().unwrap();
        assert!(error.contains("destination namespace"), "{error}");
        assert!(!sandbox.join(DIRECTORY).exists());
        assert!(!sandbox.join("state-layout.json").exists());
        assert!(!runtime.join("root-disk.json").exists());
        assert_eq!(
            fs::read(&bindings.root.as_ref().unwrap().path).unwrap(),
            original
        );
        fs::set_permissions(sandbox, fs::Permissions::from_mode(0o755)).unwrap();
        let mut selected = plan(&runtime, &bindings).unwrap();
        selected.record_intent().unwrap();
        drop(selected);
        let record = sandbox.join(DIRECTORY).join("operation.json");
        fs::write(&record, b"untrusted malformed record").unwrap();
        fs::set_permissions(sandbox, fs::Permissions::from_mode(0o777)).unwrap();
        let error = plan(&runtime, &bindings).err().unwrap();
        assert!(error.contains("destination namespace"), "{error}");
        assert_eq!(fs::read(&record).unwrap(), b"untrusted malformed record");
        assert!(!sandbox.join("state-layout.json").exists());
        assert_eq!(
            fs::read(&bindings.root.as_ref().unwrap().path).unwrap(),
            original
        );
    }

    #[cfg(unix)]
    #[test]
    fn independently_writable_owned_capture_parent_refuses_before_intent() {
        use std::os::unix::fs::PermissionsExt;
        let (_temp, runtime, mut bindings) = reachable_namespace_fixture();
        let sandbox = runtime.parent().unwrap();
        let parent = sandbox.join("owned-volumes").join("owned_test");
        fs::create_dir_all(&parent).unwrap();
        fs::set_permissions(parent.parent().unwrap(), fs::Permissions::from_mode(0o755)).unwrap();
        let path = parent.join("disk.raw");
        fs::write(&path, vec![71; 131072]).unwrap();
        bindings.owned_disks.push(OwnedDiskBinding {
            id: "owned_test".into(),
            path: path.clone(),
            capacity: 131072,
            readonly: false,
        });
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
        let error = plan(&runtime, &bindings).err().unwrap();
        assert!(error.contains("destination namespace"), "{error}");
        assert!(!sandbox.join(DIRECTORY).exists());
        assert_eq!(fs::read(path).unwrap(), vec![71; 131072]);
    }

    #[cfg(unix)]
    #[test]
    fn completed_ready_layout_skips_the_migration_namespace_policy() {
        use std::os::unix::fs::PermissionsExt;
        let (_temp, runtime, bindings) = reachable_namespace_fixture();
        execute(&runtime, &bindings);
        fs::set_permissions(runtime.parent().unwrap(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(plan(&runtime, &bindings).unwrap().is_ready());
        assert_eq!(
            inspect(&runtime, &bindings).unwrap().status,
            MigrationStatus::Ready
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn inherited_mutation_acl_refuses_before_metadata_publication() {
        use std::process::Command;
        let (_temp, runtime, bindings) = reachable_namespace_fixture();
        let sandbox = runtime.parent().unwrap();
        assert!(
            Command::new("chmod")
                .args([
                    "+a",
                    "everyone allow write,append,file_inherit,directory_inherit,only_inherit"
                ])
                .arg(sandbox)
                .output()
                .unwrap()
                .status
                .success()
        );
        let before = Command::new("ls")
            .arg("-lde")
            .arg(sandbox)
            .output()
            .unwrap()
            .stdout;
        let error = plan(&runtime, &bindings).err().unwrap();
        assert!(error.contains("destination namespace"), "{error}");
        assert!(!sandbox.join(DIRECTORY).exists());
        assert!(!sandbox.join("state-layout.json").exists());
        let after = Command::new("ls")
            .arg("-lde")
            .arg(sandbox)
            .output()
            .unwrap()
            .stdout;
        assert_eq!(before, after);
    }

    #[cfg(windows)]
    #[test]
    fn windows_namespace_refuses_before_intent_and_resume_but_leaves_ready_unaffected() {
        use std::process::Command;
        let grant = |path: &Path| {
            assert!(
                Command::new("icacls.exe")
                    .arg(path)
                    .arg("/grant:r")
                    .arg("*S-1-5-11:(DC,WD,AD)")
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
        };
        let (_temp, runtime, bindings) = fixture();
        let sandbox = runtime.parent().unwrap();
        io::harden_created(sandbox, true).unwrap();
        io::harden_created(&runtime, true).unwrap();
        let original = fs::read(&bindings.root.as_ref().unwrap().path).unwrap();
        grant(sandbox);
        let error = plan(&runtime, &bindings).err().unwrap();
        assert!(error.contains("destination namespace"), "{error}");
        assert!(!sandbox.join(DIRECTORY).exists());
        assert!(!sandbox.join("state-layout.json").exists());
        assert_eq!(
            fs::read(&bindings.root.as_ref().unwrap().path).unwrap(),
            original
        );
        io::harden_created(sandbox, true).unwrap();
        let mut selected = plan(&runtime, &bindings).unwrap();
        selected.record_intent().unwrap();
        drop(selected);
        let record = sandbox.join(DIRECTORY).join("operation.json");
        fs::write(&record, b"untrusted malformed record").unwrap();
        grant(sandbox);
        let error = plan(&runtime, &bindings).err().unwrap();
        assert!(error.contains("destination namespace"), "{error}");
        assert_eq!(fs::read(&record).unwrap(), b"untrusted malformed record");
        assert!(!sandbox.join("state-layout.json").exists());
        assert_eq!(
            fs::read(&bindings.root.as_ref().unwrap().path).unwrap(),
            original
        );

        let (_ready_temp, ready_runtime, ready_bindings) = fixture();
        io::harden_created(ready_runtime.parent().unwrap(), true).unwrap();
        io::harden_created(&ready_runtime, true).unwrap();
        execute(&ready_runtime, &ready_bindings);
        grant(ready_runtime.parent().unwrap());
        assert!(plan(&ready_runtime, &ready_bindings).unwrap().is_ready());
    }

    fn root_journal(runtime: &Path, bindings: &MigrationBindings, layers: &[(PathBuf, &str)]) {
        let root = bindings.root.as_ref().unwrap();
        let value = serde_json::json!({"schema":"microsandbox.runtime-root-disk/1","volume_id":format!("vol_{}","a".repeat(32)),"device_id":if root.flat{"vda"}else{"vdb"},"layout":if root.flat{"flat-root"}else{"managed-upper"},"published_generation":3,"launch_base":root.path,"layers":layers.iter().enumerate().map(|(index,(path,format))|serde_json::json!({"layer_id":format!("layer_{index:032x}"),"path":path,"format":format,"integrity_root":null})).collect::<Vec<_>>()});
        fs::write(
            runtime.join("root-disk.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
    }

    fn overlay(path: &Path, base: &Path, format: &str) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(microsandbox_image::checkpoint::create_qcow2_overlay(
                path, 131072, base, format,
            ))
            .unwrap();
    }

    fn execute(runtime: &Path, bindings: &MigrationBindings) {
        let mut operation = plan(runtime, bindings).unwrap();
        operation.record_intent().unwrap();
        operation.complete().unwrap();
        layout::require_ready(runtime).unwrap();
    }

    fn pad_journal_near_operation_bound(
        runtime: &Path,
        bindings: &MigrationBindings,
        spare: usize,
    ) {
        let mut selected = plan(runtime, bindings).unwrap();
        let operation = selected.operation.as_mut().unwrap();
        let initial_size = serde_json::to_vec(operation).unwrap().len();
        // Retained journal bytes serialize as a JSON integer array: each ASCII space adds
        // exactly three bytes (32,) while remaining valid trailing journal whitespace.
        let padding = (io::MAX_METADATA as usize - initial_size - spare) / 3;
        operation.disks[0]
            .journal
            .as_mut()
            .unwrap()
            .extend(std::iter::repeat_n(b' ', padding));
        let padded_size = serde_json::to_vec(operation).unwrap().len();
        assert!(padded_size <= io::MAX_METADATA as usize);
        assert!(io::MAX_METADATA as usize - padded_size < spare + 3);
        fs::write(
            runtime.join("root-disk.json"),
            operation.disks[0].journal.as_ref().unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn near_bound_plan_reserves_capture_growth_before_intent_or_guards() {
        let (_temp, runtime, bindings) = fixture();
        let original = bindings.root.as_ref().unwrap().path.clone();
        root_journal(&runtime, &bindings, &[(original.clone(), "raw")]);
        pad_journal_near_operation_bound(&runtime, &bindings, 32);
        let retained_journal = fs::read(runtime.join("root-disk.json")).unwrap();
        let error = plan(&runtime, &bindings)
            .err()
            .expect("capture metadata cannot fit despite an initially fitting intent");
        assert!(error.contains("metadata bound"), "{error}");
        let sandbox = layout::host_root(&runtime).unwrap();
        assert!(!sandbox.join(DIRECTORY).exists());
        assert!(!sandbox.join("state-layout.json").exists());
        assert!(!sandbox.join("root-disk.json").exists());
        assert_eq!(
            fs::read(runtime.join("root-disk.json")).unwrap(),
            retained_journal
        );
        assert_eq!(fs::read(original).unwrap(), vec![23; 131072]);
    }

    #[test]
    fn near_bound_capture_record_completes_after_interruption() {
        let (_temp, runtime, bindings) = fixture();
        let original = bindings.root.as_ref().unwrap().path.clone();
        root_journal(&runtime, &bindings, &[(original.clone(), "raw")]);
        pad_journal_near_operation_bound(&runtime, &bindings, 512);
        let mut selected = plan(&runtime, &bindings).unwrap();
        selected.record_intent().unwrap();
        let error = selected
            .complete_with_checkpoint(|phase| {
                if phase == "captured-disk" {
                    Err("test interruption after durable capture".into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert_eq!(error, "test interruption after durable capture");
        let record = layout::host_root(&runtime)
            .unwrap()
            .join(DIRECTORY)
            .join("operation.json");
        let bytes = fs::read(&record).unwrap();
        assert!(bytes.len() > io::MAX_METADATA as usize - 512);
        assert!(bytes.len() as u64 <= io::MAX_METADATA);
        let recorded: Operation = serde_json::from_slice(&bytes).unwrap();
        assert!(recorded.captures[0][0].is_some());
        assert!(!recorded.group_captured);
        plan(&runtime, &bindings).unwrap().complete().unwrap();
        layout::require_ready(&runtime).unwrap();
        assert!(fs::metadata(record).unwrap().len() <= io::MAX_METADATA);
        let chain = load_runtime_owned_root_chain(&runtime).unwrap().unwrap();
        assert_eq!(fs::read(&chain.layers[0].path).unwrap(), vec![23; 131072]);
        assert_eq!(fs::read(original).unwrap(), vec![23; 131072]);
    }

    fn chain_fixture(
        overlays: usize,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        MigrationBindings,
        Vec<(PathBuf, &'static str)>,
    ) {
        let (temporary, runtime, bindings) = fixture();
        let mut layers = vec![(bindings.root.as_ref().unwrap().path.clone(), "raw")];
        for index in 1..=overlays {
            let path = layout::host_root(&runtime)
                .unwrap()
                .join(format!("upper-{index:032x}.qcow2"));
            let (previous, format) = layers.last().unwrap();
            overlay(&path, previous, format);
            layers.push((path, "qcow2"));
        }
        root_journal(&runtime, &bindings, &layers);
        (temporary, runtime, bindings, layers)
    }

    fn capture_without_publication(runtime: &Path, bindings: &MigrationBindings) {
        let mut selected = plan(runtime, bindings).unwrap();
        selected.record_intent().unwrap();
        assert_eq!(
            selected
                .complete_with_checkpoint(|phase| {
                    if phase == "captured-group" {
                        Err("test pause before full metadata validation".into())
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err(),
            "test pause before full metadata validation"
        );
    }

    #[test]
    fn captured_validation_parses_malformed_ancestor_and_final_layer() {
        for malformed in [1usize, 2] {
            let (_temporary, runtime, bindings, layers) = chain_fixture(2);
            let mut bytes = fs::read(&layers[malformed].0).unwrap();
            let offset = u64::from_be_bytes(bytes[40..48].try_into().unwrap());
            // The bounded admission header accepts this in-file offset; the full parser
            // must still reject its unaligned L1 table, even when it belongs to an ancestor.
            bytes[40..48].copy_from_slice(&(offset - 1).to_be_bytes());
            fs::write(&layers[malformed].0, &bytes).unwrap();
            io::header(&io::exact(&layers[malformed].0).unwrap(), true).unwrap();
            let originals = layers
                .iter()
                .map(|(path, _)| fs::read(path).unwrap())
                .collect::<Vec<_>>();
            let mut selected = plan(&runtime, &bindings).unwrap();
            selected.record_intent().unwrap();
            assert_eq!(
                selected.complete().unwrap_err(),
                "captured disk chain is invalid"
            );
            assert!(layout::require_ready(&runtime).is_err());
            for ((path, _), original) in layers.iter().zip(originals) {
                assert_eq!(fs::read(path).unwrap(), original);
            }
        }
    }

    #[test]
    fn captured_validation_preserves_dependency_and_capacity_checks() {
        for change_capacity in [false, true] {
            let (_temporary, runtime, bindings, _) = chain_fixture(1);
            capture_without_publication(&runtime, &bindings);
            let selected = plan(&runtime, &bindings).unwrap();
            let operation = selected.operation.as_ref().unwrap();
            let directory =
                destination_directory(layout::host_root(&runtime).unwrap(), operation, 0);
            let head = destination_path(&directory, 1, "qcow2");
            if change_capacity {
                let mut file = fs::OpenOptions::new().write(true).open(&head).unwrap();
                file.seek(SeekFrom::Start(24)).unwrap();
                file.write_all(&262144u64.to_be_bytes()).unwrap();
            } else {
                microsandbox_image::checkpoint::relocate_qcow2_backing(
                    &head,
                    &directory.join("not-an-authorized-layer.raw"),
                )
                .unwrap();
            }
            // Exercise validation itself: a new single-layer parser must not replace the
            // explicit closure checks with a successful parse of each unrelated file.
            assert_eq!(
                selected.validate_captured_disk(0).unwrap_err(),
                "private captured dependency or capacity changed"
            );
            assert!(layout::require_ready(&runtime).is_err());
        }
    }

    #[test]
    fn single_layer_parser_never_opens_an_embedded_predecessor() {
        let (_temporary, runtime, bindings, layers) = chain_fixture(1);
        fs::remove_file(&layers[0].0).unwrap();
        let capacities = microsandbox_image::checkpoint::layer_capacities(vec![CompactLayer {
            path: layers[1].0.clone(),
            qcow2: true,
        }])
        .unwrap();
        assert_eq!(capacities, vec![131072]);
        // Independent metadata parsing intentionally ignores header paths; the migration
        // engine must nevertheless refuse the missing first predecessor before intent.
        root_journal(&runtime, &bindings, &layers[1..]);
        assert!(
            plan(&runtime, &bindings)
                .unwrap_err_text()
                .contains("implicit predecessor")
        );
        assert!(
            !layout::host_root(&runtime)
                .unwrap()
                .join(DIRECTORY)
                .exists()
        );
    }

    #[test]
    fn bounded_header_rejects_encryption_before_private_parser() {
        let (_temporary, runtime, bindings, layers) = chain_fixture(1);
        let mut bytes = fs::read(&layers[1].0).unwrap();
        bytes[32..36].copy_from_slice(&1u32.to_be_bytes());
        fs::write(&layers[1].0, bytes).unwrap();
        // The pinned image parser does not reject crypt_method itself. Keep encryption
        // policy at the bounded admission header, before any migration intent is created.
        assert!(io::header(&io::exact(&layers[1].0).unwrap(), true).is_err());
        assert!(plan(&runtime, &bindings).is_err());
        assert!(
            !layout::host_root(&runtime)
                .unwrap()
                .join(DIRECTORY)
                .exists()
        );
    }

    #[test]
    fn single_layer_parser_rejects_external_data_and_unsupported_features() {
        let (_temporary, runtime, bindings, layers) = chain_fixture(1);
        let original = fs::read(&layers[1].0).unwrap();
        for (offset, value) in [
            (72usize, 4u64.to_be_bytes().to_vec()),
            (72usize, (1u64 << 63).to_be_bytes().to_vec()),
        ] {
            let mut bytes = original.clone();
            bytes[offset..offset + value.len()].copy_from_slice(&value);
            fs::write(&layers[1].0, bytes).unwrap();
            assert!(
                layer_capacities(vec![CompactLayer {
                    path: layers[1].0.clone(),
                    qcow2: true,
                }])
                .is_err()
            );
            assert!(plan(&runtime, &bindings).is_err());
            assert!(
                !layout::host_root(&runtime)
                    .unwrap()
                    .join(DIRECTORY)
                    .exists()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn captured_validation_releases_parsers_before_opening_the_next_layer() {
        let (_temporary, runtime, bindings, _) = chain_fixture(48);
        capture_without_publication(&runtime, &bindings);
        {
            let selected = plan(&runtime, &bindings).unwrap();
            assert!(selected.acquired.as_ref().unwrap().files.is_empty());
            // The same real captured chain must validate normally. The child isolates the
            // resource limit from the SDK test process and from original capture handles.
            selected.validate_captured_disk(0).unwrap();
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "checkpoint::migration::engine::tests::captured_validation_handle_limit_worker",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("MSB_MIGRATION_VALIDATION_RUNTIME", &runtime)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(unix)]
    #[test]
    fn captured_validation_handle_limit_worker() {
        let Some(runtime) = std::env::var_os("MSB_MIGRATION_VALIDATION_RUNTIME") else {
            return;
        };
        let runtime = PathBuf::from(runtime);
        let record = layout::host_root(&runtime)
            .unwrap()
            .join(DIRECTORY)
            .join("operation.json");
        let operation: Operation = serde_json::from_slice(&fs::read(record).unwrap()).unwrap();
        assert!(operation.group_captured);
        let selected = plan(&runtime, &operation.bindings).unwrap();
        assert!(selected.acquired.as_ref().unwrap().files.is_empty());
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        assert!(limit.rlim_cur >= 32);
        limit.rlim_cur = 32;
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        // Each live parser owns its file handle and L1 table. Forty-nine layers under a
        // thirty-two-handle process limit prove parsers are released rather than linked.
        // This is a lifetime bound, not an RSS measurement or an out-of-memory test.
        selected.validate_captured_disk(0).unwrap();
    }

    #[test]
    fn simple_capture_is_independent_preserves_unknown_notes_and_has_ready_fast_path() {
        let (_temp, runtime, bindings) = fixture();
        fs::write(runtime.join("notes.txt"), b"keep this untrusted note").unwrap();
        let original = bindings.root.as_ref().unwrap().path.clone();
        execute(&runtime, &bindings);
        let chain = load_runtime_owned_root_chain(&runtime).unwrap().unwrap();
        assert_ne!(chain.layers[0].path, original);
        assert_eq!(
            fs::read(&chain.layers[0].path).unwrap(),
            fs::read(&original).unwrap()
        );
        fs::write(&original, vec![99u8; 131072]).unwrap();
        assert_eq!(fs::read(&chain.layers[0].path).unwrap()[0], 23);
        assert_eq!(
            fs::read(runtime.join("notes.txt")).unwrap(),
            b"keep this untrusted note"
        );
        assert!(
            !layout::guest_root(&runtime)
                .unwrap()
                .join("notes.txt")
                .exists()
        );
        // A ready path must not inspect legacy sources, even when original storage is removed.
        fs::remove_file(&original).unwrap();
        fs::remove_file(
            layout::host_root(&runtime)
                .unwrap()
                .join(DIRECTORY)
                .join("operation.json"),
        )
        .unwrap();
        assert!(plan(&runtime, &bindings).unwrap().is_ready());
    }

    #[test]
    fn selected_snapshot_source_chain_and_completed_growth_keep_all_layers() {
        for stage in [None, Some(".grow-Ab12Cd"), Some(".compact-Ab12Cd")] {
            let (_temp, runtime, bindings) = fixture();
            let base = bindings.root.as_ref().unwrap().path.clone();
            let head = base
                .parent()
                .unwrap()
                .join(format!("upper-{}.qcow2", "b".repeat(32)));
            overlay(&head, &base, "raw");
            let (selected_base, selected_head) = if let Some(stage) = stage {
                let directory = runtime.join(stage);
                fs::create_dir(&directory).unwrap();
                let a = directory.join("upper.ext4");
                let b = directory.join(head.file_name().unwrap());
                fs::hard_link(&base, &a).unwrap();
                fs::hard_link(&head, &b).unwrap();
                (a, b)
            } else {
                (base.clone(), head.clone())
            };
            root_journal(
                &runtime,
                &bindings,
                &[(selected_base, "raw"), (selected_head, "qcow2")],
            );
            execute(&runtime, &bindings);
            let chain = load_runtime_owned_root_chain(&runtime).unwrap().unwrap();
            assert_eq!(chain.layers.len(), 2);
            assert_eq!(chain.virtual_size, 131072);
            assert_eq!(fs::read(&base).unwrap()[0], 23);
            let backing =
                microsandbox_image::checkpoint::qcow2_backing_basename(&chain.layers[1].path)
                    .unwrap();
            assert_eq!(
                backing,
                chain.layers[0].path.file_name().unwrap().to_str().unwrap()
            );
        }
    }

    #[test]
    fn intact_root_journal_imports_selected_state_without_choosing_alternatives() {
        for stage in [".grow-Ab12Cd", ".compact-Ab12Cd"] {
            let (_temp, runtime, bindings) = fixture();
            let nominal = &bindings.root.as_ref().unwrap().path;
            let previous_head = nominal
                .parent()
                .unwrap()
                .join(format!("upper-{}.qcow2", "1".repeat(32)));
            overlay(&previous_head, nominal, "raw");

            // Completed growth/compaction can retain the old complete disk view. Its mere
            // presence must not override or make ambiguous the validated current selection.
            let directory = runtime.join(stage);
            fs::create_dir(&directory).unwrap();
            let current_base = directory.join("upper.ext4");
            fs::write(&current_base, vec![91; 131072]).unwrap();
            let current_head = directory.join(format!("upper-{}.qcow2", "2".repeat(32)));
            overlay(&current_head, &current_base, "raw");
            root_journal(
                &runtime,
                &bindings,
                &[
                    (current_base.clone(), "raw"),
                    (current_head.clone(), "qcow2"),
                ],
            );
            let originals = [nominal, &previous_head, &current_base, &current_head]
                .into_iter()
                .map(|path| (path.clone(), fs::read(path).unwrap()))
                .collect::<Vec<_>>();

            let inspection = inspect(&runtime, &bindings).unwrap();
            assert_eq!(inspection.status, MigrationStatus::Eligible);
            assert_eq!(inspection.candidates.len(), 1);
            assert!(!inspection.can_preview());
            execute(&runtime, &bindings);

            let chain = load_runtime_owned_root_chain(&runtime).unwrap().unwrap();
            assert_eq!(chain.layers.len(), 2);
            assert_eq!(fs::read(&chain.layers[0].path).unwrap(), vec![91; 131072]);
            assert_eq!(
                microsandbox_image::checkpoint::qcow2_backing_basename(&chain.layers[1].path)
                    .unwrap(),
                chain.layers[0].path.file_name().unwrap().to_str().unwrap()
            );
            for (path, contents) in originals {
                assert_eq!(fs::read(path).unwrap(), contents);
            }
        }
    }

    #[test]
    fn restored_root_can_have_no_nominal_base_and_deleted_parent() {
        let (_temp, runtime, bindings) = fixture();
        let nominal = &bindings.root.as_ref().unwrap().path;
        let sealed = nominal.parent().unwrap().join("upper-sealed-000.qcow2");
        let source = CompactLayer {
            path: nominal.clone(),
            qcow2: false,
        };
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(microsandbox_image::checkpoint::materialize_compact_prefix(
                &[source],
                &sealed,
            ))
            .unwrap();
        let head = nominal
            .parent()
            .unwrap()
            .join("upper-restore-1234567890abcdef.qcow2");
        overlay(&head, &sealed, "qcow2");
        root_journal(&runtime, &bindings, &[(sealed, "qcow2"), (head, "qcow2")]);
        fs::remove_file(nominal).unwrap();
        execute(&runtime, &bindings);
        assert_eq!(
            load_runtime_owned_root_chain(&runtime)
                .unwrap()
                .unwrap()
                .layers
                .len(),
            2
        );
    }

    #[test]
    fn root_and_owned_restored_chain_publish_together() {
        let (_temp, runtime, mut bindings) = fixture();
        let sandbox = layout::host_root(&runtime).unwrap();
        let id = "owned_test";
        let directory = sandbox.join("owned-volumes").join(id);
        fs::create_dir_all(&directory).unwrap();
        let base = directory.join("sealed-000.raw");
        fs::write(&base, vec![74u8; 131072]).unwrap();
        // A retained nominal disk and an older complete branch are not a reason to ask the
        // operator to reconstruct a choice already recorded by a valid owned-disk journal.
        let nominal = directory.join("disk.raw");
        fs::write(&nominal, vec![13u8; 131072]).unwrap();
        let previous_head = directory.join(format!("head_{}.qcow2", "d".repeat(32)));
        overlay(&previous_head, &nominal, "raw");
        let previous_bytes = fs::read(&previous_head).unwrap();
        let head = directory.join("writable.qcow2");
        overlay(&head, &base, "raw");
        let journal_dir = runtime.join("owned-disks").join(id);
        fs::create_dir_all(&journal_dir).unwrap();
        let value = serde_json::json!({"schema":"microsandbox.runtime-owned-disk/1","volume_id":format!("vol_{}","c".repeat(32)),"device_id":id,"launch_base":format!("owned-volumes/{id}/disk.raw"),"read_only":false,"generation":4,"layers":[{"layer_id":format!("layer_{}","a".repeat(32)),"path":format!("owned-volumes/{id}/sealed-000.raw"),"format":"raw","integrity_root":"untrusted"},{"layer_id":format!("layer_{}","b".repeat(32)),"path":format!("owned-volumes/{id}/writable.qcow2"),"format":"qcow2","integrity_root":null}]});
        fs::write(
            journal_dir.join("disk.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        bindings.owned_disks.push(OwnedDiskBinding {
            id: id.into(),
            path: directory.join("disk.raw"),
            capacity: 131072,
            readonly: false,
        });

        let inspection = inspect(&runtime, &bindings).unwrap();
        assert_eq!(inspection.status, MigrationStatus::Eligible);
        assert_eq!(inspection.candidates.len(), 2);
        execute(&runtime, &bindings);

        let chain = load_runtime_owned_disk_chain(&runtime, id)
            .unwrap()
            .unwrap();
        assert_eq!(chain.layers.len(), 2);
        assert_eq!(fs::read(&chain.layers[0].path).unwrap()[0], 74);
        assert!(load_runtime_owned_root_chain(&runtime).unwrap().is_some());
        assert!(journal_dir.join("disk.json").exists());
        assert_eq!(fs::read(nominal).unwrap(), vec![13u8; 131072]);
        assert_eq!(fs::read(previous_head).unwrap(), previous_bytes);
    }

    #[test]
    fn alias_to_metadata_and_unknown_external_alias_refuse_before_intent() {
        for metadata in [true, false] {
            let (_temp, runtime, bindings) = fixture();
            let base = &bindings.root.as_ref().unwrap().path;
            let outside = tempfile::tempdir().unwrap();
            let alias = if metadata {
                base.parent().unwrap().join("external-mounts.json")
            } else {
                outside.path().join("secret.raw")
            };
            fs::hard_link(base, &alias).unwrap();
            assert!(plan(&runtime, &bindings).is_err());
            assert!(!base.parent().unwrap().join(DIRECTORY).exists());
            assert_eq!(fs::read(&alias).unwrap()[0], 23);
        }
    }

    #[test]
    fn independently_authorized_related_alias_is_copied_without_mutating_it() {
        let (_temp, runtime, mut bindings) = fixture();
        let related = tempfile::tempdir().unwrap();
        let alias = related.path().join("sealed.raw");
        fs::hard_link(&bindings.root.as_ref().unwrap().path, &alias).unwrap();
        assert!(plan(&runtime, &bindings).is_err());
        bindings.aliases.push(AuthorizedAlias {
            disk_id: "root".into(),
            path: alias.clone(),
        });
        execute(&runtime, &bindings);
        let chain = load_runtime_owned_root_chain(&runtime).unwrap().unwrap();
        fs::write(&chain.layers[0].path, vec![11u8; 131072]).unwrap();
        assert_eq!(fs::read(alias).unwrap()[0], 23);
    }

    #[test]
    fn missing_selection_with_replacement_refuses_without_old_base_fallback() {
        let (_temp, runtime, bindings) = fixture();
        let base = &bindings.root.as_ref().unwrap().path;
        let head = base
            .parent()
            .unwrap()
            .join(format!("upper-{}.qcow2", "a".repeat(32)));
        overlay(&head, base, "raw");
        assert!(
            plan(&runtime, &bindings)
                .unwrap_err_text()
                .contains("active-head")
        );
    }

    #[test]
    fn interrupted_intent_resumes_frozen_selection_and_changed_input_refuses() {
        for changed in [false, true] {
            let (_temp, runtime, bindings) = fixture();
            let mut operation = plan(&runtime, &bindings).unwrap();
            operation.record_intent().unwrap();
            drop(operation);
            if changed {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .open(&bindings.root.as_ref().unwrap().path)
                    .unwrap();
                file.seek(SeekFrom::Start(4096)).unwrap();
                file.write_all(&[99; 512]).unwrap();
                file.sync_all().unwrap();
                assert!(plan(&runtime, &bindings).is_err());
                assert!(layout::require_ready(&runtime).is_err());
            } else {
                let resumed = plan(&runtime, &bindings).unwrap();
                assert_eq!(resumed.inspection().status, MigrationStatus::InProgress);
                resumed.complete().unwrap();
            }
        }
    }

    #[test]
    fn unrelated_external_neighbor_is_ignored_and_write_through_is_preserved() {
        let (_temp, runtime, mut bindings) = fixture();
        let external = tempfile::tempdir().unwrap();
        let disk = external.path().join("external.raw");
        fs::write(&disk, vec![8u8; 131072]).unwrap();
        fs::write(
            external
                .path()
                .join(format!("upper-{}.qcow2", "a".repeat(32))),
            b"unrelated",
        )
        .unwrap();
        bindings.root.as_mut().unwrap().path = disk.clone();
        execute(&runtime, &bindings);
        let chain = load_runtime_owned_root_chain(&runtime).unwrap().unwrap();
        assert_eq!(chain.layers[0].path, disk);
    }

    fn preview_parent() -> tempfile::TempDir {
        preview::private_preview_parent().unwrap()
    }

    #[test]
    fn preview_distinguishes_equal_size_branches_and_adopts_reviewed_bytes_after_restart() {
        let (_temp, runtime, bindings) = fixture();
        let base = &bindings.root.as_ref().unwrap().path;
        let prefix = base.parent().unwrap();
        let left = prefix.join(format!("upper-{}.qcow2", "1".repeat(32)));
        overlay(&left, base, "raw");
        let staging = runtime.join(".grow-ABC123");
        fs::create_dir(&staging).unwrap();
        let alternate_base = staging.join("upper.ext4");
        fs::write(&alternate_base, vec![91; 131072]).unwrap();
        let right = staging.join(format!("upper-{}.qcow2", "2".repeat(32)));
        overlay(&right, &alternate_base, "raw");
        let parent = preview_parent();
        let mut preview = preview::capture_preview(&runtime, &bindings, parent.path()).unwrap();
        let views = preview
            .candidates()
            .iter()
            .filter(|view| view.layers == 2)
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(views.len(), 2);
        assert_eq!(views[0].virtual_size, views[1].virtual_size);
        let mut recognized = std::collections::BTreeSet::new();
        let mut selection = None;
        for view in views {
            let image = preview.materialize("root", &view.id).unwrap();
            let bytes = fs::read(&image).unwrap();
            assert!(bytes.iter().all(|value| value == &bytes[0]));
            recognized.insert(bytes[0]);
            if bytes[0] == 91 {
                selection = Some(RecoverySelection {
                    disk_id: "root".into(),
                    candidate_id: view.id,
                });
            }
        }
        assert_eq!(recognized, std::collections::BTreeSet::from([23, 91]));
        let selected = [selection.unwrap()];
        let mut migration =
            preview::plan_previewed(&runtime, &bindings, &preview, &selected).unwrap();
        assert!(!prefix.join(DIRECTORY).exists());
        migration.record_intent().unwrap();
        drop(preview);
        drop(migration);
        // Durable pre-normalization proofs survive the preview process; resume can only
        // import the same private content even though every ephemeral inspection file is gone.
        plan(&runtime, &bindings).unwrap().complete().unwrap();
        let owned = load_runtime_owned_root_chain(&runtime).unwrap().unwrap();
        assert_eq!(owned.layers.len(), 2);
        assert_eq!(fs::read(&owned.layers[0].path).unwrap(), vec![91; 131072]);
        assert_eq!(fs::read(base).unwrap(), vec![23; 131072]);
        assert_eq!(fs::read(alternate_base).unwrap(), vec![91; 131072]);
    }

    #[test]
    fn preview_cancel_preserves_originals_and_removes_private_copies() {
        let (_temp, runtime, bindings) = fixture();
        let parent = preview_parent();
        let base = &bindings.root.as_ref().unwrap().path;
        let stamp = io::identity(&io::exact(base).unwrap()).unwrap();
        let sandbox = runtime.parent().unwrap();
        let mut preview = preview::capture_preview(&runtime, &bindings, parent.path()).unwrap();
        let id = preview.candidates()[0].id.clone();
        let path = preview.materialize("root", &id).unwrap();
        assert!(path.exists());
        drop(preview);
        assert!(!path.exists());
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
        assert_eq!(io::identity(&io::exact(base).unwrap()).unwrap(), stamp);
        for marker in [
            "state-layout.json",
            DIRECTORY,
            "root-disk.json",
            "runtime/root-disk.json",
        ] {
            assert!(!sandbox.join(marker).exists());
        }
        assert!(preview::capture_preview(&runtime, &bindings, sandbox).is_err());
    }

    #[test]
    fn preview_stale_source_or_journal_does_not_record_intent() {
        for change_journal in [false, true] {
            let (_temp, runtime, bindings) = fixture();
            let parent = preview_parent();
            let preview = preview::capture_preview(&runtime, &bindings, parent.path()).unwrap();
            let selection = [RecoverySelection {
                disk_id: "root".into(),
                candidate_id: preview.candidates()[0].id.clone(),
            }];
            if change_journal {
                fs::write(runtime.join("root-disk.json"), b"changed selection").unwrap();
            } else {
                fs::write(&bindings.root.as_ref().unwrap().path, vec![14; 131072]).unwrap();
            }
            assert!(preview::plan_previewed(&runtime, &bindings, &preview, &selection).is_err());
            assert!(!runtime.parent().unwrap().join(DIRECTORY).exists());
            assert!(!runtime.parent().unwrap().join("state-layout.json").exists());
        }
    }

    #[test]
    fn preview_external_inspection_cannot_write_through_and_modified_image_requires_new_session() {
        let (_temp, runtime, mut bindings) = fixture();
        let external = tempfile::tempdir().unwrap();
        let path = external.path().join("external.raw");
        fs::write(&path, vec![83; 131072]).unwrap();
        bindings.root.as_mut().unwrap().path = path.clone();
        let parent = preview_parent();
        let mut preview = preview::capture_preview(&runtime, &bindings, parent.path()).unwrap();
        let selection = [RecoverySelection {
            disk_id: "root".into(),
            candidate_id: preview.candidates()[0].id.clone(),
        }];
        let image = preview
            .materialize("root", &selection[0].candidate_id)
            .unwrap();
        assert_ne!(
            io::identity(&io::exact(&image).unwrap()).unwrap().object,
            io::identity(&io::exact(&path).unwrap()).unwrap().object
        );
        fs::write(&image, vec![44; 131072]).unwrap();
        assert_eq!(fs::read(&path).unwrap(), vec![83; 131072]);
        assert!(preview::plan_previewed(&runtime, &bindings, &preview, &selection).is_err());
        assert!(!runtime.parent().unwrap().join(DIRECTORY).exists());
    }

    #[test]
    fn preview_content_proof_is_checked_against_pinned_bytes_on_resume() {
        let (_temp, runtime, bindings) = fixture();
        let parent = preview_parent();
        let preview = preview::capture_preview(&runtime, &bindings, parent.path()).unwrap();
        let selection = [RecoverySelection {
            disk_id: "root".into(),
            candidate_id: preview.candidates()[0].id.clone(),
        }];
        let mut migration =
            preview::plan_previewed(&runtime, &bindings, &preview, &selection).unwrap();
        migration.record_intent().unwrap();
        drop(migration);
        let file = runtime
            .parent()
            .unwrap()
            .join(DIRECTORY)
            .join("operation.json");
        let mut retained: Operation = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        retained.reviewed_roots[0][0] = format!("blake3:{}", "0".repeat(64));
        fs::write(file, serde_json::to_vec(&retained).unwrap()).unwrap();
        assert!(
            plan(&runtime, &bindings)
                .unwrap_err_text()
                .contains("disk bytes differ")
        );
        assert!(!runtime.parent().unwrap().join("state-layout.json").exists());
    }

    #[test]
    fn explicit_recovery_is_identity_bound_and_never_guesses_latest() {
        let (_temp, runtime, bindings) = fixture();
        let base = &bindings.root.as_ref().unwrap().path;
        let head = base
            .parent()
            .unwrap()
            .join(format!("upper-{}.qcow2", "d".repeat(32)));
        overlay(&head, base, "raw");
        let report = inspect(&runtime, &bindings).unwrap();
        assert_eq!(report.status, MigrationStatus::RecoveryRequired);
        assert_eq!(report.candidates.len(), 2);
        assert!(super::super::alias_sources(&runtime, &bindings).is_ok());
        let candidate = report
            .candidates
            .iter()
            .find(|view| view.layers == 2)
            .unwrap();
        let selections = [RecoverySelection {
            disk_id: "root".into(),
            candidate_id: candidate.id.clone(),
        }];
        let forged = [RecoverySelection {
            disk_id: "root".into(),
            candidate_id: "view-forged".into(),
        }];
        assert!(plan_selected(&runtime, &bindings, &forged).is_err());
        assert!(!base.parent().unwrap().join(DIRECTORY).exists());
        let mut selected = plan_selected(&runtime, &bindings, &selections).unwrap();
        selected.record_intent().unwrap();
        assert!(plan_selected(&runtime, &bindings, &selections).is_err());
        selected.complete().unwrap();
        assert_eq!(
            load_runtime_owned_root_chain(&runtime)
                .unwrap()
                .unwrap()
                .layers
                .len(),
            2
        );
    }

    #[test]
    fn every_transaction_boundary_resumes_and_old_readers_reject() {
        for stop in [
            "layout-barrier",
            "legacy-guards",
            "admitted",
            "captured-disk",
            "captured-group",
            "published-journal",
            "before-ready",
        ] {
            let (_temp, runtime, bindings) = fixture();
            let mut operation = plan(&runtime, &bindings).unwrap();
            operation.record_intent().unwrap();
            assert!(
                operation
                    .complete_with_checkpoint(|phase| if phase == stop {
                        Err("injected interruption".into())
                    } else {
                        Ok(())
                    })
                    .is_err()
            );
            assert!(layout::require_ready(&runtime).is_err());
            // The previous protected reader must reject the real entry point, not finish a
            // schema-1 Preparing record while the new multi-disk operation is incomplete.
            assert!(layout::prepare(&runtime, bindings.root.as_ref()).is_err());
            let aliases = super::super::alias_sources(&runtime, &bindings).unwrap();
            assert_eq!(
                aliases.len(),
                usize::from(!matches!(
                    stop,
                    "captured-group" | "published-journal" | "before-ready"
                ))
            );
            plan(&runtime, &bindings).unwrap().complete().unwrap();
            layout::require_ready(&runtime).unwrap();
        }
    }

    #[test]
    fn narrow_schema_one_preparing_record_converts_without_legacy_fallback() {
        for guards in [false, true] {
            let (_temp, runtime, bindings) = fixture();
            let root = bindings.root.as_ref().unwrap();
            let retained = serde_json::json!({"schema":"microsandbox.runtime-root-disk/1","volume_id":format!("vol_{}","a".repeat(32)),"device_id":"vdb","layout":"managed-upper","published_generation":0,"layers":[{"layer_id":format!("layer_{}","b".repeat(32)),"path":root.path,"format":"raw","integrity_root":null}]});
            fs::write(
                runtime.join("root-disk.json"),
                serde_json::to_vec(&retained).unwrap(),
            )
            .unwrap();
            let record = serde_json::json!({"schema":"microsandbox.protected-layout/1","phase":"preparing","binding":root,"root":retained});
            fs::write(
                layout::host_root(&runtime)
                    .unwrap()
                    .join("state-layout.json"),
                serde_json::to_vec(&record).unwrap(),
            )
            .unwrap();
            if guards {
                layout::install_import_guards(&runtime).unwrap();
            }
            let mut operation = plan(&runtime, &bindings).unwrap();
            operation.record_intent().unwrap();
            drop(operation);
            plan(&runtime, &bindings).unwrap().complete().unwrap();
            layout::require_ready(&runtime).unwrap();
        }
    }

    #[test]
    fn external_alias_does_not_authorize_guest_staging_to_read_sibling_bytes() {
        let (_temp, runtime, mut bindings) = fixture();
        let sibling = tempfile::tempdir().unwrap();
        let secret = sibling.path().join("upper.ext4");
        fs::write(&secret, vec![88u8; 131072]).unwrap();
        let stage = runtime.join(".grow-ABC123");
        fs::create_dir(&stage).unwrap();
        let planted = stage.join("upper.ext4");
        fs::hard_link(&secret, &planted).unwrap();
        root_journal(&runtime, &bindings, &[(planted, "raw")]);
        bindings.aliases.push(AuthorizedAlias {
            disk_id: "root".into(),
            path: secret.clone(),
        });
        assert!(plan(&runtime, &bindings).is_err());
        assert!(
            !layout::host_root(&runtime)
                .unwrap()
                .join(DIRECTORY)
                .exists()
        );
        assert_eq!(fs::read(secret).unwrap()[0], 88);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_source_and_parent_are_refused_without_reading_target() {
        use std::os::unix::fs::symlink;
        for parent in [false, true] {
            let (_temp, runtime, bindings) = fixture();
            let elsewhere = tempfile::tempdir().unwrap();
            let source = elsewhere.path().join("upper.ext4");
            fs::write(&source, vec![6u8; 131072]).unwrap();
            let stage = runtime.join(".grow-ABC123");
            if parent {
                symlink(elsewhere.path(), &stage).unwrap();
            } else {
                fs::create_dir(&stage).unwrap();
                symlink(&source, stage.join("upper.ext4")).unwrap();
            }
            root_journal(&runtime, &bindings, &[(stage.join("upper.ext4"), "raw")]);
            assert!(plan(&runtime, &bindings).is_err());
            assert!(
                !layout::host_root(&runtime)
                    .unwrap()
                    .join(DIRECTORY)
                    .exists()
            );
            assert_eq!(fs::read(source).unwrap()[0], 6);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cloned_disk_does_not_retain_extended_acl_grants() {
        let (_temp, runtime, bindings) = fixture();
        let source = &bindings.root.as_ref().unwrap().path;
        let status = std::process::Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(source)
            .status()
            .unwrap();
        assert!(status.success());
        execute(&runtime, &bindings);
        let captured = load_runtime_owned_root_chain(&runtime)
            .unwrap()
            .unwrap()
            .layers
            .remove(0)
            .path;
        microsandbox_utils::private_file::verify(&fs::File::open(captured).unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn alternate_parent_spelling_cannot_hide_an_unknown_hardlink() {
        use std::os::unix::fs::symlink;
        let (_temp, runtime, mut bindings) = fixture();
        let base = bindings.root.as_ref().unwrap().path.clone();
        let other = tempfile::tempdir().unwrap();
        let hidden = other.path().join("hidden.raw");
        fs::hard_link(&base, &hidden).unwrap();
        let alias_parent = other.path().join("parent-alias");
        symlink(base.parent().unwrap(), &alias_parent).unwrap();
        bindings.aliases.push(AuthorizedAlias {
            disk_id: "root".into(),
            path: alias_parent.join("upper.ext4"),
        });
        assert!(plan(&runtime, &bindings).is_err());
        let upper = base.parent().unwrap().join("UPPER.EXT4");
        if upper.exists() {
            bindings.aliases[0].path = upper;
            assert!(plan(&runtime, &bindings).is_err());
        }
        assert!(!base.parent().unwrap().join(DIRECTORY).exists());
    }

    #[test]
    fn unrecognized_orphan_filename_blocks_implicit_base_reconstruction() {
        let (_temp, runtime, bindings) = fixture();
        fs::write(
            layout::host_root(&runtime)
                .unwrap()
                .join("upper-orphan.qcow2"),
            b"uncommitted candidate",
        )
        .unwrap();
        assert!(plan(&runtime, &bindings).is_err());
        let report = inspect(&runtime, &bindings).unwrap();
        assert_eq!(report.status, MigrationStatus::RecoveryRequired);
        assert_eq!(report.candidates.len(), 1);
        assert!(
            !layout::host_root(&runtime)
                .unwrap()
                .join(DIRECTORY)
                .exists()
        );
    }

    #[test]
    fn completed_peer_reports_retained_original_as_inert_without_overriding_current_head() {
        let (_temp, runtime, bindings) = fixture();
        let original = bindings.root.as_ref().unwrap().path.clone();
        let original_id = io::identity(&fs::File::open(&original).unwrap())
            .unwrap()
            .object;
        execute(&runtime, &bindings);
        let sources = super::super::selected_sources(&runtime, &bindings).unwrap();
        assert!(
            sources
                .iter()
                .any(|source| source.identity_object == original_id && source.readonly)
        );
        assert!(
            sources
                .iter()
                .any(|source| source.identity_object != original_id && !source.readonly)
        );
    }

    #[test]
    fn renamed_staging_without_selection_never_reconstructs_the_old_base() {
        for name in ["renamed-growth", "renamed-compaction", "checkpoint-store"] {
            let (_temp, runtime, bindings) = fixture();
            let directory = runtime.join(name);
            fs::create_dir(&directory).unwrap();
            fs::write(directory.join("upper.ext4"), vec![37; 131072]).unwrap();
            assert!(plan(&runtime, &bindings).is_err());
            assert!(
                !layout::host_root(&runtime)
                    .unwrap()
                    .join(DIRECTORY)
                    .exists()
            );
            assert_eq!(
                fs::read(directory.join("upper.ext4")).unwrap(),
                vec![37; 131072]
            );
        }
    }

    #[test]
    fn missing_owned_selection_rejects_retained_raw_and_renamed_staging() {
        for nested in [false, true] {
            let (_temp, runtime, mut bindings) = fixture();
            let sandbox = layout::host_root(&runtime).unwrap();
            let id = "owned_test";
            let directory = sandbox.join("owned-volumes").join(id);
            fs::create_dir_all(&directory).unwrap();
            let base = directory.join("disk.raw");
            fs::write(&base, vec![1; 131072]).unwrap();
            let newer = if nested {
                let staging = directory.join("renamed-compaction");
                fs::create_dir(&staging).unwrap();
                staging.join("disk.raw")
            } else {
                directory.join("sealed-000.raw")
            };
            fs::write(&newer, vec![2; 131072]).unwrap();
            bindings.owned_disks.push(OwnedDiskBinding {
                id: id.into(),
                path: base,
                capacity: 131072,
                readonly: false,
            });
            assert!(plan(&runtime, &bindings).is_err());
            assert!(!sandbox.join(DIRECTORY).exists());
            assert_eq!(fs::read(newer).unwrap(), vec![2; 131072]);
        }
    }

    #[test]
    fn changing_legacy_journal_after_intent_never_installs_guards() {
        let (_temp, runtime, bindings) = fixture();
        let base = bindings.root.as_ref().unwrap().path.clone();
        root_journal(&runtime, &bindings, &[(base, "raw")]);
        let mut operation = plan(&runtime, &bindings).unwrap();
        operation.record_intent().unwrap();
        drop(operation);
        fs::write(runtime.join("root-disk.json"), b"changed selection").unwrap();
        assert!(plan(&runtime, &bindings).unwrap().complete().is_err());
        assert!(
            !layout::host_root(&runtime)
                .unwrap()
                .join("state-layout.json")
                .exists()
        );
        assert_eq!(
            fs::read(runtime.join("root-disk.json")).unwrap(),
            b"changed selection"
        );
    }

    #[test]
    fn config_revision_fences_unfinished_operation_but_not_completed_retained_aliases() {
        let (_temp, runtime, mut bindings) = fixture();
        let mut operation = plan(&runtime, &bindings).unwrap();
        operation.record_intent().unwrap();
        drop(operation);
        bindings.config_revision = "changed-config".into();
        assert!(plan(&runtime, &bindings).is_err());
        bindings.config_revision = "saved-config-revision".into();
        plan(&runtime, &bindings).unwrap().complete().unwrap();
        bindings.config_revision = "changed-config".into();
        assert!(plan(&runtime, &bindings).unwrap().is_ready());
        assert!(
            super::super::selected_sources(&runtime, &bindings)
                .unwrap()
                .iter()
                .any(|s| s.path == bindings.root.as_ref().unwrap().path && s.readonly)
        );
    }

    #[test]
    fn recovery_capture_estimate_accounts_for_every_disk_role() {
        let (_temp, runtime, mut bindings) = fixture();
        let sandbox = layout::host_root(&runtime).unwrap();
        for id in ["disk_a", "disk_b"] {
            let directory = sandbox.join("owned-volumes").join(id);
            fs::create_dir_all(&directory).unwrap();
            let path = directory.join("disk.raw");
            fs::write(&path, vec![1; 131072]).unwrap();
            bindings.owned_disks.push(OwnedDiskBinding {
                id: id.into(),
                path,
                capacity: 131072,
                readonly: false,
            });
        }
        fs::write(sandbox.join("upper-orphan.qcow2"), b"unknown selection").unwrap();
        let report = inspect(&runtime, &bindings).unwrap();
        assert_eq!(report.candidates.len(), 3);
        assert_eq!(report.estimated_bytes, 3 * 131072);
    }

    #[test]
    fn terminated_process_resumes_without_destructor_cleanup() {
        for phase in [
            "intent",
            "layout-barrier",
            "legacy-guards",
            "admitted",
            "captured-disk",
            "captured-group",
            "published-journal",
            "before-ready",
        ] {
            let (temporary, runtime, bindings) = fixture();
            let input = temporary.path().join("termination-input.json");
            fs::write(
                &input,
                serde_json::to_vec(&(runtime.clone(), bindings.clone(), phase)).unwrap(),
            )
            .unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "checkpoint::migration::engine::tests::termination_worker",
                    "--nocapture",
                ])
                .env("MSB_MIGRATION_TERMINATION_INPUT", &input)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(!status.success(), "worker did not terminate at {phase}");
            assert!(!runtime.join("destructor-ran").exists());
            assert!(layout::require_ready(&runtime).is_err());
            if phase != "intent" {
                assert!(layout::prepare(&runtime, bindings.root.as_ref()).is_err());
            }
            plan(&runtime, &bindings).unwrap().complete().unwrap();
            layout::require_ready(&runtime).unwrap();
            let path = load_runtime_owned_root_chain(&runtime)
                .unwrap()
                .unwrap()
                .layers
                .remove(0)
                .path;
            assert_eq!(fs::read(path).unwrap(), vec![23; 131072]);
        }
    }

    #[test]
    fn termination_worker() {
        let Some(input) = std::env::var_os("MSB_MIGRATION_TERMINATION_INPUT") else {
            return;
        };
        let (runtime, bindings, stop): (PathBuf, MigrationBindings, String) =
            serde_json::from_slice(&fs::read(input).unwrap()).unwrap();
        struct UnwindMarker(PathBuf);
        impl Drop for UnwindMarker {
            fn drop(&mut self) {
                let _ = fs::write(&self.0, b"unexpected cleanup");
            }
        }
        let _marker = UnwindMarker(runtime.join("destructor-ran"));
        let terminate = || -> ! {
            #[cfg(unix)]
            unsafe {
                libc::kill(libc::getpid(), libc::SIGKILL);
            }
            // Windows exits immediately without unwinding or running Rust destructors.
            std::process::exit(79)
        };
        let mut operation = plan(&runtime, &bindings).unwrap();
        operation.record_intent().unwrap();
        if stop == "intent" {
            terminate();
        }
        operation
            .complete_with_checkpoint(|phase| {
                if phase == stop {
                    terminate();
                }
                Ok(())
            })
            .unwrap();
        panic!("termination checkpoint was not reached");
    }

    #[cfg(windows)]
    #[test]
    fn windows_same_size_rewrite_with_restored_mtime_invalidates_identity() {
        let (_temp, runtime, bindings) = fixture();
        let path = bindings.root.as_ref().unwrap().path.clone();
        let before = io::identity(&fs::File::open(&path).unwrap()).unwrap();
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        let mut operation = plan(&runtime, &bindings).unwrap();
        operation.record_intent().unwrap();
        drop(operation);
        let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.write_all(&vec![42; 131072]).unwrap();
        file.set_times(fs::FileTimes::new().set_modified(modified))
            .unwrap();
        file.sync_all().unwrap();
        drop(file);
        let after = io::identity(&fs::File::open(path).unwrap()).unwrap();
        assert_eq!(before.modified, after.modified);
        assert_ne!(before.changed, after.changed);
        assert!(plan(&runtime, &bindings).is_err());
    }

    #[test]
    fn uncertified_completion_is_recaptured_in_one_new_epoch() {
        let (_temporary, runtime, bindings) = fixture();
        let mut operation = plan(&runtime, &bindings).unwrap();
        operation.record_intent().unwrap();
        assert!(
            operation
                .complete_with_checkpoint(|phase| if phase == "captured-disk" {
                    Err("interrupted before group certification".into())
                } else {
                    Ok(())
                })
                .is_err()
        );
        let sandbox = layout::host_root(&runtime).unwrap();
        let record: Operation = serde_json::from_slice(
            &fs::read(sandbox.join(DIRECTORY).join("operation.json")).unwrap(),
        )
        .unwrap();
        assert!(!record.group_captured);
        let path = destination_path(&destination_directory(sandbox, &record, 0), 0, "raw");
        // Retain the old inode, preventing immediate inode-number reuse after replacement.
        let old = fs::File::open(&path).unwrap();
        let old_identity = io::identity(&old).unwrap().object;
        plan(&runtime, &bindings).unwrap().complete().unwrap();
        assert_ne!(
            io::identity(&fs::File::open(path).unwrap()).unwrap().object,
            old_identity
        );
        assert_eq!(io::identity(&old).unwrap().length, 131072);
    }

    #[test]
    fn certified_capture_resumes_without_original_internal_sources() {
        let (_temporary, runtime, bindings) = fixture();
        let mut operation = plan(&runtime, &bindings).unwrap();
        operation.record_intent().unwrap();
        assert!(
            operation
                .complete_with_checkpoint(|phase| if phase == "captured-group" {
                    Err("interrupted after group certification".into())
                } else {
                    Ok(())
                })
                .is_err()
        );
        fs::remove_file(&bindings.root.as_ref().unwrap().path).unwrap();
        assert!(
            super::super::alias_sources(&runtime, &bindings)
                .unwrap()
                .is_empty()
        );
        plan(&runtime, &bindings).unwrap().complete().unwrap();
        let path = load_runtime_owned_root_chain(&runtime)
            .unwrap()
            .unwrap()
            .layers
            .remove(0)
            .path;
        assert_eq!(fs::read(path).unwrap(), vec![23; 131072]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lease_break_prevents_group_certification_even_without_a_completed_write() {
        use std::os::unix::fs::OpenOptionsExt;
        let (_temporary, runtime, bindings) = fixture();
        let path = bindings.root.as_ref().unwrap().path.clone();
        let mut operation = plan(&runtime, &bindings).unwrap();
        operation.record_intent().unwrap();
        assert!(
            operation
                .complete_with_checkpoint(|phase| {
                    if phase == "captured-disk" {
                        let error = fs::OpenOptions::new()
                            .write(true)
                            .custom_flags(libc::O_NONBLOCK)
                            .open(&path)
                            .unwrap_err();
                        assert_eq!(error.raw_os_error(), Some(libc::EWOULDBLOCK));
                    }
                    Ok(())
                })
                .is_err()
        );
        let record: Operation = serde_json::from_slice(
            &fs::read(
                layout::host_root(&runtime)
                    .unwrap()
                    .join(DIRECTORY)
                    .join("operation.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!record.group_captured);
        assert!(layout::require_ready(&runtime).is_err());
        plan(&runtime, &bindings).unwrap().complete().unwrap();
    }

    #[test]
    fn standalone_external_qcow_is_validated_privately_and_keeps_write_through_path() {
        let (_temporary, runtime, mut bindings) = fixture();
        let external = tempfile::tempdir().unwrap();
        let path = external.path().join("external.qcow2");
        let predecessor = external.path().join("raw-base");
        fs::write(&predecessor, vec![0; 131072]).unwrap();
        overlay(&path, &predecessor, "raw");
        // A standalone container has no implicit dependency; untouched sparse guest sectors
        // read as zero. Remove only the backing-name fields from this empty fixture overlay.
        let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(8)).unwrap();
        file.write_all(&[0; 12]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        bindings.root.as_mut().unwrap().path = path.clone();
        bindings.root.as_mut().unwrap().format = "qcow2".into();
        let report = inspect(&runtime, &bindings).unwrap();
        assert!(report.estimated_bytes > 0);
        execute(&runtime, &bindings);
        assert_eq!(
            load_runtime_owned_root_chain(&runtime)
                .unwrap()
                .unwrap()
                .layers[0]
                .path,
            path
        );
    }

    fn expand_budget_table(path: &Path) {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let offset = file.metadata().unwrap().len().next_multiple_of(65536);
        // Sparse table bytes are never passed to the full parser in these refusal tests.
        // Each header remains individually acceptable under the existing eight-MiB bound.
        file.set_len(offset + 8 * 1024 * 1024).unwrap();
        file.seek(SeekFrom::Start(36)).unwrap();
        file.write_all(&(1024 * 1024u32).to_be_bytes()).unwrap();
        file.write_all(&offset.to_be_bytes()).unwrap();
    }

    #[test]
    fn parser_budget_refuses_start_doctor_and_selection_before_intent() {
        let (_temporary, runtime, bindings, layers) = chain_fixture(16);
        for (path, _) in &layers[1..] {
            expand_budget_table(path);
            io::header(&io::exact(path).unwrap(), true).unwrap();
        }
        let originals = layers
            .iter()
            .map(|(path, _)| io::identity(&io::exact(path).unwrap()).unwrap())
            .collect::<Vec<_>>();
        let journal = fs::read(runtime.join("root-disk.json")).unwrap();
        assert!(
            plan(&runtime, &bindings)
                .unwrap_err_text()
                .contains("256 MiB")
        );
        let report = inspect(&runtime, &bindings).unwrap();
        assert_eq!(report.status, MigrationStatus::RecoveryRequired);
        assert!(
            report
                .reasons
                .iter()
                .any(|reason| reason.contains("256 MiB"))
        );
        assert!(!report.can_preview());
        let candidate = report
            .candidates
            .iter()
            .find(|candidate| candidate.layers == 17)
            .unwrap();
        assert!(
            plan_selected(
                &runtime,
                &bindings,
                &[RecoverySelection {
                    disk_id: "root".into(),
                    candidate_id: candidate.id.clone(),
                }]
            )
            .unwrap_err_text()
            .contains("256 MiB")
        );
        let sandbox = layout::host_root(&runtime).unwrap();
        for name in [
            DIRECTORY,
            "state-layout.json",
            "root-disk.json",
            "guest-state",
        ] {
            assert!(
                !sandbox.join(name).exists(),
                "created {name} before budget refusal"
            );
        }
        assert_eq!(fs::read(runtime.join("root-disk.json")).unwrap(), journal);
        for ((path, _), original) in layers.iter().zip(originals) {
            assert_eq!(io::identity(&io::exact(path).unwrap()).unwrap(), original);
        }
    }

    #[test]
    fn parser_budget_is_shared_by_root_and_owned_disks() {
        let (_temporary, runtime, mut bindings, root_layers) = chain_fixture(8);
        for (path, _) in &root_layers[1..] {
            expand_budget_table(path);
        }
        // One half fits in isolation, but the atomic sandbox group must not reset its budget.
        drop(plan(&runtime, &bindings).unwrap());
        let sandbox = layout::host_root(&runtime).unwrap();
        let id = "owned_budget";
        let directory = sandbox.join("owned-volumes").join(id);
        fs::create_dir_all(&directory).unwrap();
        let base = directory.join("disk.raw");
        fs::write(&base, vec![37u8; 131072]).unwrap();
        let mut layers = vec![(base, "raw")];
        for index in 1..=8 {
            let path = directory.join(format!("head_{index:032x}.qcow2"));
            let (previous, format) = layers.last().unwrap();
            overlay(&path, previous, format);
            expand_budget_table(&path);
            layers.push((path, "qcow2"));
        }
        let journal = runtime.join("owned-disks").join(id);
        fs::create_dir_all(&journal).unwrap();
        fs::write(journal.join("disk.json"), serde_json::to_vec(&serde_json::json!({
            "schema":"microsandbox.runtime-owned-disk/1", "volume_id":format!("vol_{}","a".repeat(32)),
            "device_id":id, "launch_base":format!("owned-volumes/{id}/disk.raw"), "read_only":false, "generation":0,
            "layers": layers.iter().enumerate().map(|(index,(path,format))| serde_json::json!({
                "layer_id":format!("layer_{index:032x}"), "path":io::relative(path,sandbox).unwrap(),
                "format":format, "integrity_root":null
            })).collect::<Vec<_>>()
        })).unwrap()).unwrap();
        bindings.owned_disks.push(OwnedDiskBinding {
            id: id.into(),
            path: directory.join("disk.raw"),
            capacity: 131072,
            readonly: false,
        });
        assert!(
            plan(&runtime, &bindings)
                .unwrap_err_text()
                .contains("256 MiB")
        );
        assert!(!sandbox.join(DIRECTORY).exists());
        assert!(!sandbox.join("state-layout.json").exists());
    }

    #[test]
    fn parser_budget_rechecks_uncertified_and_certified_historical_operations() {
        for certified in [false, true] {
            let (_temporary, runtime, bindings, layers) = chain_fixture(16);
            if certified {
                capture_without_publication(&runtime, &bindings);
            } else {
                let mut selected = plan(&runtime, &bindings).unwrap();
                selected.record_intent().unwrap();
            }
            let sandbox = layout::host_root(&runtime).unwrap();
            let record = sandbox.join(DIRECTORY).join("operation.json");
            let mut operation: Operation =
                serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
            // Model an older importer that admitted these individually bounded tables.
            // Update its recorded identities as that importer would have observed them.
            for (index, (path, _)) in layers.iter().enumerate().skip(1) {
                expand_budget_table(path);
                operation.disks[0].sources[index].identity =
                    io::identity(&io::exact(path).unwrap()).unwrap();
                if certified {
                    let captured = destination_path(
                        &destination_directory(sandbox, &operation, 0),
                        index,
                        "qcow2",
                    );
                    expand_budget_table(&captured);
                    operation.captures[0][index] =
                        Some(io::identity(&io::exact(&captured).unwrap()).unwrap());
                }
            }
            let original_record = serde_json::to_vec(&operation).unwrap();
            fs::write(&record, &original_record).unwrap();
            let originals = layers
                .iter()
                .map(|(path, _)| io::identity(&io::exact(path).unwrap()).unwrap())
                .collect::<Vec<_>>();
            assert!(
                plan(&runtime, &bindings)
                    .unwrap_err_text()
                    .contains("256 MiB")
            );
            let report = inspect(&runtime, &bindings).unwrap();
            assert!(
                report
                    .reasons
                    .iter()
                    .any(|reason| reason.contains("256 MiB"))
            );
            assert_eq!(fs::read(&record).unwrap(), original_record);
            assert!(layout::require_ready(&runtime).is_err());
            assert!(!sandbox.join("root-disk.json").exists());
            for ((path, _), original) in layers.iter().zip(originals) {
                assert_eq!(io::identity(&io::exact(path).unwrap()).unwrap(), original);
            }
        }
    }

    #[test]
    fn ready_layout_skips_legacy_parser_budget_even_when_old_files_change() {
        let (_temporary, runtime, bindings, layers) = chain_fixture(16);
        execute(&runtime, &bindings);
        for (path, _) in &layers[1..] {
            expand_budget_table(path);
        }
        assert!(plan(&runtime, &bindings).unwrap().is_ready());
        assert_eq!(
            inspect(&runtime, &bindings).unwrap().status,
            MigrationStatus::Ready
        );
    }

    trait ErrorText {
        fn unwrap_err_text(self) -> String;
    }
    impl ErrorText for Result<MigrationPlan, String> {
        fn unwrap_err_text(self) -> String {
            match self {
                Err(error) => error,
                Ok(_) => panic!("expected migration refusal"),
            }
        }
    }
}
