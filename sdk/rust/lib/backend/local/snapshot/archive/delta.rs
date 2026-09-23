//! Local backend: Explicit disk-prefix and immutable RAM-object dependencies for incremental exports.

use microsandbox_image::checkpoint::{
    DiskGenerationManifest, DiskLayerExportPlan, DiskLayerRef, MemoryManifest,
};
use microsandbox_image::snapshot::{DiskLayer, Manifest};

use super::*;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(super) const REQUIREMENT: &str = "msb-snapshot-dependencies-v1";
const MAX_METADATA: u64 = 8 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "layer",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
enum LayerIdentity {
    File(DiskLayer),
    Checkpoint(DiskLayerRef),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequiredLayer {
    path: String,
    identity: LayerIdentity,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Dependencies {
    disks: Vec<RequiredLayer>,
    memory: Vec<ObjectId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    owned: Vec<RequiredOwnedPayload>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum OwnedPayloadIdentity {
    Directory { digest: String, bytes: u64 },
    // `bytes` is the guest-visible capacity; qcow2 container length differs. The hash binds
    // the exact physical payload, including its archive-local backing header.
    Disk { integrity_root: String, bytes: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequiredOwnedPayload {
    path: String,
    identity: OwnedPayloadIdentity,
}

struct PhysicalLayer {
    required: RequiredLayer,
    source: PathBuf,
    /// Root selectors address this chain; owned `since` prefixes are planned separately.
    root_chain: bool,
}

pub(super) struct BaseSnapshot {
    pub(super) snapshot: Snapshot,
    // Keep archive staging alive until all required payloads belong to the destination.
    _stage: Option<tempfile::TempDir>,
}

/// Sources are scoped to this load, never persisted or discovered through global path scans.
/// Payload identity, not parentage, connects archives that can reconstruct one another.
#[derive(Default)]
pub(super) struct Sources {
    disks: BTreeMap<String, PathBuf>,
    memory: BTreeMap<ObjectId, PathBuf>,
    owned: BTreeMap<String, PathBuf>,
}

type SourceIndex = (
    Vec<(String, PathBuf)>,
    Vec<(ObjectId, PathBuf)>,
    Vec<(String, PathBuf)>,
);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sources {
    pub(super) async fn add(
        &mut self,
        manifest: &Manifest,
        directory: &Path,
        archive_stage: Option<&Path>,
    ) -> MicrosandboxResult<()> {
        let manifest = manifest.clone();
        let directory = directory.to_path_buf();
        let archive_stage = archive_stage.map(Path::to_path_buf);
        let (disks, memory, owned) = tokio::task::spawn_blocking(move || {
            inspect_sources(&manifest, &directory, archive_stage.as_deref())
        })
        .await
        .map_err(|error| {
            MicrosandboxError::Runtime(format!("snapshot source inspection: {error}"))
        })??;
        // Prefer batch bytes over destination-group copies. Every borrowed payload is checked in
        // its owned destination, so this index is a location hint, not an integrity receipt.
        for (identity, path) in disks {
            self.disks.entry(identity).or_insert(path);
        }
        for (identity, path) in memory {
            self.memory.entry(identity).or_insert(path);
        }
        for (identity, path) in owned {
            self.owned.entry(identity).or_insert(path);
        }
        Ok(())
    }

    pub(super) fn require(&self, inventory: &ArchiveInventory) -> MicrosandboxResult<()> {
        let Some(dependencies) = validate(inventory)? else {
            return Ok(());
        };
        let mut missing = Vec::new();
        for layer in &dependencies.disks {
            if !self
                .disks
                .contains_key(&serde_json::to_string(&layer.identity)?)
            {
                missing.push(format!("disk layer {}", layer.path));
            }
        }
        for object in &dependencies.memory {
            if !self.memory.contains_key(object) {
                missing.push(format!("RAM object {object}"));
            }
        }
        for payload in &dependencies.owned {
            if !self
                .owned
                .contains_key(&serde_json::to_string(&payload.identity)?)
            {
                missing.push(format!("owned payload {}", payload.path));
            }
        }
        if !missing.is_empty() {
            return Err(MicrosandboxError::SnapshotIntegrity(format!(
                "snapshot {} is missing dependencies: {}; supply the missing archives or an external --base",
                inventory.head,
                missing.join(", ")
            )));
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Inspect only descriptors and small identity-verified manifests. Missing payloads in dependent
/// archives are expected; admission still happens after filling their complete target closure.
fn inspect_sources(
    manifest: &Manifest,
    directory: &Path,
    archive_stage: Option<&Path>,
) -> MicrosandboxResult<SourceIndex> {
    let mut disks = Vec::new();
    let mut memory = Vec::new();
    match &manifest.state {
        SnapshotState::File(file) => {
            for layer in &file.layers {
                let relative = file.layer_path(layer);
                let path = match archive_stage {
                    Some(root) => root
                        .join(".archive-layers")
                        .join(relative.file_name().expect("canonical layer filename")),
                    None => directory.join(relative),
                };
                if regular_source(&path)? {
                    disks.push((
                        serde_json::to_string(&LayerIdentity::File(layer.clone()))?,
                        path,
                    ));
                }
            }
        }
        SnapshotState::Checkpoint(state) => {
            let root = directory.join(CHECKPOINT_DIRECTORY);
            let expected = ObjectId::new(&state.checkpoint_root).map_err(source_error)?;
            let checkpoint = CheckpointClosure::inspect_manifest(&root, Some(&expected))
                .map_err(source_error)?;
            super::super::validate_checkpoint_owned_inventory(manifest, &checkpoint)?;
            let ram = MemoryManifest::from_bytes(&read_metadata_object(&root, &checkpoint.memory)?)
                .map_err(source_error)?;
            let mut metadata = BTreeSet::from([
                checkpoint.memory.clone(),
                checkpoint.execution_state.clone(),
            ]);
            metadata.extend(checkpoint.disks.iter().cloned());
            metadata.extend(checkpoint.devices.iter().map(|device| device.state.clone()));
            let objects: BTreeSet<_> = ram
                .extents
                .iter()
                .filter_map(|extent| match &extent.content {
                    MemoryExtentContent::Object(content) if !metadata.contains(&content.object) => {
                        Some(content.object.clone())
                    }
                    _ => None,
                })
                .collect();
            for object in objects {
                let path = checkpoint_object_path(&root, &object);
                if regular_source(&path)? {
                    memory.push((object, path));
                }
            }
            for disk in &checkpoint.disks {
                let disk = DiskGenerationManifest::from_bytes(&read_metadata_object(&root, disk)?)
                    .map_err(source_error)?;
                for layer in disk.layers {
                    let path = root
                        .join("layers")
                        .join(format!("{}.{}", layer.layer_id, layer.format));
                    if regular_source(&path)? {
                        disks.push((
                            serde_json::to_string(&LayerIdentity::Checkpoint(layer))?,
                            path,
                        ));
                    }
                }
            }
        }
    }
    let owned = owned_payloads(manifest, directory)?
        .into_iter()
        .filter_map(|(payload, path)| match regular_source(&path) {
            Ok(true) => Some(
                serde_json::to_string(&payload.identity)
                    .map(|identity| (identity, path))
                    .map_err(Into::into),
            ),
            Ok(false) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<MicrosandboxResult<Vec<_>>>()?;
    Ok((disks, memory, owned))
}

/// Namespace descriptors always travel in full, so omissions cannot hide deletions or renames.
/// Only immutable bulk content is reused from an explicitly supplied base.
fn owned_payloads(
    manifest: &Manifest,
    directory: &Path,
) -> MicrosandboxResult<Vec<(RequiredOwnedPayload, PathBuf)>> {
    use microsandbox_image::snapshot::OwnedVolumeData;
    let checkpoint = matches!(manifest.state, SnapshotState::Checkpoint(_));
    let root = if checkpoint {
        directory.join(CHECKPOINT_DIRECTORY)
    } else {
        directory.to_path_buf()
    };
    let prefix = format!(
        "{}/{}",
        if checkpoint {
            "checkpoints"
        } else {
            "snapshots"
        },
        manifest.snapshot_id
    );
    let mut payloads = Vec::new();
    for volume in manifest.owned_volumes()? {
        match &volume.data {
            OwnedVolumeData::Directory { files, .. } => {
                for file in files {
                    let relative = volume.directory_path().join("files").join(&file.digest);
                    payloads.push((
                        RequiredOwnedPayload {
                            path: format!("{prefix}/{}", super::portable_archive_path(&relative)?),
                            identity: OwnedPayloadIdentity::Directory {
                                digest: file.digest.clone(),
                                bytes: file.bytes,
                            },
                        },
                        root.join(relative),
                    ));
                }
            }
            OwnedVolumeData::Disk { generation } => {
                for layer in &generation.layers {
                    // This dependency identity predates optional capture hashes. A hashless
                    // owned layer remains included in the archive; do not omit it as borrowed
                    // data or consult a relative host path during manifest-only planning.
                    let Some(integrity_root) = &layer.integrity_root else {
                        continue;
                    };
                    let relative =
                        Path::new("layers").join(format!("{}.{}", layer.layer_id, layer.format));
                    payloads.push((
                        RequiredOwnedPayload {
                            path: format!("{prefix}/{}", super::portable_archive_path(&relative)?),
                            identity: OwnedPayloadIdentity::Disk {
                                integrity_root: integrity_root.clone(),
                                bytes: layer.virtual_size,
                            },
                        },
                        root.join(relative),
                    ));
                }
            }
        }
    }
    payloads.sort_by(|left, right| left.0.path.cmp(&right.0.path));
    Ok(payloads)
}

async fn verify_owned_payload(
    path: &Path,
    identity: &OwnedPayloadIdentity,
) -> MicrosandboxResult<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(source_error("borrowed owned payload is not a regular file"));
    }
    let matches = match identity {
        OwnedPayloadIdentity::Directory { digest, bytes } => {
            metadata.len() == *bytes && hex::encode(Box::pin(file_sha256(path)).await?) == *digest
        }
        OwnedPayloadIdentity::Disk {
            integrity_root,
            bytes,
        } => {
            let path = path.to_path_buf();
            // The image reader uses thread-local futures. Keep it and the blocking physical
            // hash on one worker so archive-loading futures remain Send for every SDK backend.
            let (capacity, actual_integrity) = tokio::task::spawn_blocking(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                let capacity =
                    runtime.block_on(microsandbox_image::checkpoint::compact_layer_capacity(
                        microsandbox_image::checkpoint::CompactLayer {
                            path: path.clone(),
                            qcow2: path
                                .extension()
                                .is_some_and(|extension| extension == "qcow2"),
                        },
                    ))?;
                let integrity = microsandbox_image::checkpoint::sparse_file_integrity(&path)
                    .map_err(std::io::Error::other)?;
                Ok::<_, std::io::Error>((capacity, integrity.root))
            })
            .await
            .map_err(|error| {
                MicrosandboxError::Runtime(format!("owned disk payload verification: {error}"))
            })??;
            capacity == *bytes && actual_integrity == *integrity_root
        }
    };
    if !matches {
        return Err(source_error(
            "borrowed owned payload differs from its required identity",
        ));
    }
    Ok(())
}

/// Disk deltas require the same device's exact physical prefix. Equal content from a replaced
/// or compacted representation is not a baseline; new devices are exported in full.
fn owned_since_dependencies(
    target: &Manifest,
    baseline: &Manifest,
) -> MicrosandboxResult<Vec<RequiredOwnedPayload>> {
    use microsandbox_image::snapshot::OwnedVolumeData;

    let baseline_volumes = baseline.owned_volumes()?;
    let mut disk_prefixes = BTreeSet::new();
    for volume in target.owned_volumes()? {
        let OwnedVolumeData::Disk { generation } = &volume.data else {
            continue;
        };
        let Some(base) = baseline_volumes
            .iter()
            .find(|base| base.mount_id == volume.mount_id)
        else {
            continue;
        };
        let OwnedVolumeData::Disk { generation: base } = &base.data else {
            continue;
        };
        let mismatch = || {
            MicrosandboxError::InvalidConfig(format!(
                "owned disk {:?} baseline is not an exact physical prefix; export the new base first or save a complete archive",
                volume.mount.guest,
            ))
        };
        if base.device_id != generation.device_id {
            return Err(mismatch());
        }
        let plan =
            DiskLayerExportPlan::since(&generation.layers, &base.layers).map_err(|_| mismatch())?;
        for layer in &generation.layers[plan.required()] {
            disk_prefixes.insert(format!("{}.{}", layer.layer_id, layer.format));
        }
    }
    let baseline_payloads = owned_payloads(baseline, Path::new(""))?
        .into_iter()
        .filter_map(|(payload, _)| match payload.identity {
            identity @ OwnedPayloadIdentity::Directory { .. } => {
                Some(serde_json::to_string(&identity))
            }
            OwnedPayloadIdentity::Disk { .. } => None,
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    owned_payloads(target, Path::new(""))?
        .into_iter()
        .filter_map(|(payload, _)| {
            let required = match &payload.identity {
                OwnedPayloadIdentity::Directory { .. } => {
                    match serde_json::to_string(&payload.identity) {
                        Ok(identity) => baseline_payloads.contains(&identity),
                        Err(error) => return Some(Err(error.into())),
                    }
                }
                OwnedPayloadIdentity::Disk { .. } => payload
                    .path
                    .rsplit('/')
                    .next()
                    .is_some_and(|name| disk_prefixes.contains(name)),
            };
            required.then_some(Ok(payload))
        })
        .collect()
}

fn regular_source(path: &Path) -> MicrosandboxResult<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(MicrosandboxError::SnapshotIntegrity(format!(
            "snapshot payload is not a regular file: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn read_metadata_object(root: &Path, id: &ObjectId) -> MicrosandboxResult<Vec<u8>> {
    use std::io::Read;
    let path = checkpoint_object_path(root, id);
    if !regular_source(&path)? {
        return Err(MicrosandboxError::SnapshotIntegrity(format!(
            "missing checkpoint metadata {id}"
        )));
    }
    // Match the checkpoint resolver's 8 MiB metadata limit; a changing file cannot cause an
    // unbounded allocation. This is not a RAM-payload read or a new admission format.
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_METADATA + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_METADATA
        || &ObjectId::from_bytes(&bytes).map_err(source_error)? != id
    {
        return Err(MicrosandboxError::SnapshotIntegrity(format!(
            "invalid checkpoint metadata {id}"
        )));
    }
    Ok(bytes)
}

fn source_error(error: impl std::fmt::Display) -> MicrosandboxError {
    MicrosandboxError::SnapshotIntegrity(error.to_string())
}

pub(super) async fn resolve_sources(
    local: &LocalBackend,
    inventory: &ArchiveInventory,
    snapshots_dir: &Path,
    cache_dir: &Path,
    sources: &Sources,
) -> MicrosandboxResult<()> {
    let Some(dependencies) = validate(inventory)? else {
        return Ok(());
    };
    sources.require(inventory)?;
    for layer in &dependencies.disks {
        let source = &sources.disks[&serde_json::to_string(&layer.identity)?];
        let target = inventory_entry_target(&layer.path, snapshots_dir, cache_dir)?;
        copy_dependency(source, &target).await?;
        if let LayerIdentity::File(layer) = &layer.identity {
            super::super::verify::verify_file_payload(&target, layer.payload.integrity.as_ref())
                .await?;
        }
    }
    for id in &dependencies.memory {
        let target = inventory_entry_target(
            &memory_archive_path(&inventory.head, id),
            snapshots_dir,
            cache_dir,
        )?;
        copy_dependency(&sources.memory[id], &target).await?;
        let actual = format!(
            "sha256:{}",
            hex::encode(Box::pin(file_sha256(&target)).await?)
        );
        if actual != id.as_str() {
            return Err(MicrosandboxError::SnapshotIntegrity(format!(
                "borrowed RAM object content does not match {id}"
            )));
        }
    }
    for payload in &dependencies.owned {
        let source = &sources.owned[&serde_json::to_string(&payload.identity)?];
        let target = inventory_entry_target(&payload.path, snapshots_dir, cache_dir)?;
        copy_dependency(source, &target).await?;
        verify_owned_payload(&target, &payload.identity).await?;
    }
    validate_resolved(local, inventory, snapshots_dir, cache_dir, &dependencies).await
}

pub(super) async fn selection(
    local: &LocalBackend,
    head: &Snapshot,
    opts: &SaveOpts,
) -> MicrosandboxResult<Option<Dependencies>> {
    if opts.since.is_none() && opts.last_layers.is_none() {
        return Ok(None);
    }
    if opts.with_parents || (opts.since.is_some() && opts.last_layers.is_some()) {
        return Err(MicrosandboxError::InvalidConfig(
            "incremental export takes either since or last_layers, without with_parents".into(),
        ));
    }
    let layers = physical_layers(head.manifest(), head.path())?;
    let selected_layers = layers
        .iter()
        .filter(|layer| layer.root_chain)
        .collect::<Vec<_>>();
    let mut memory = Vec::new();
    let mut owned = Vec::new();
    let required = if let Some(base) = &opts.since {
        // Base archives carry buffered decoder/verification futures; keep them off the caller's
        // stack, including when this planner is nested inside a direct restore or SDK call.
        let base = Box::pin(open_base(local, base)).await?;
        let baseline = physical_layers(base.snapshot.manifest(), base.snapshot.path())?;
        let baseline = baseline
            .iter()
            .filter(|layer| layer.root_chain)
            .collect::<Vec<_>>();
        let available = memory_objects(&base.snapshot)?;
        owned = owned_since_dependencies(head.manifest(), base.snapshot.manifest())?;
        memory = memory_objects(head)?
            .intersection(&available)
            .cloned()
            .collect();
        // Tmpfs-root full snapshots have no disks, but may still depend on RAM objects.
        // Do not let disk completeness suppress an independent memory dependency.
        if selected_layers.is_empty() && baseline.is_empty() {
            0..0
        } else {
            DiskLayerExportPlan::since(
                &selected_layers
                    .iter()
                    .map(|layer| &layer.required.identity)
                    .collect::<Vec<_>>(),
                &baseline
                    .iter()
                    .map(|layer| &layer.required.identity)
                    .collect::<Vec<_>>(),
            )
            .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))?
            .required()
        }
    } else {
        DiskLayerExportPlan::last(
            selected_layers.len(),
            opts.last_layers.expect("selector checked"),
        )
        .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))?
        .required()
    };
    if required.is_empty() && memory.is_empty() && owned.is_empty() {
        return Ok(None);
    }
    Ok(Some(Dependencies {
        disks: selected_layers[required]
            .iter()
            .map(|layer| layer.required.clone())
            .collect(),
        memory,
        owned,
    }))
}

pub(super) fn apply(
    inventory: &mut ArchiveInventory,
    dependencies: &Dependencies,
) -> MicrosandboxResult<()> {
    let paths = dependency_paths(&inventory.head, dependencies);
    let mut found = 0;
    for entry in &mut inventory.entries {
        if !paths.contains(entry.path.as_str()) {
            continue;
        }
        found += 1;
        entry.included = false;
        entry.encoded_size = 0;
        entry.sparse_ranges.clear();
        entry.transport_integrity = None;
    }
    if found != paths.len() {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "required payload is absent from archive inventory".into(),
        ));
    }
    inventory.completeness = "dependent".into();
    inventory.requires.push(REQUIREMENT.into());
    inventory.requires.sort();
    inventory
        .extensions
        .insert(REQUIREMENT.into(), serde_json::to_value(dependencies)?);
    inventory.limits.entry_count = inventory
        .entries
        .iter()
        .filter(|entry| entry.included)
        .count() as u64;
    inventory.limits.encoded_bytes = inventory
        .entries
        .iter()
        .filter(|entry| entry.included)
        .map(|entry| entry.encoded_size)
        .sum();
    inventory.limits.apparent_bytes = inventory
        .entries
        .iter()
        .filter(|entry| entry.included)
        .map(|entry| entry.apparent_size)
        .sum();
    Ok(())
}

pub(super) fn validate(inventory: &ArchiveInventory) -> MicrosandboxResult<Option<Dependencies>> {
    let extension = inventory.extensions.get(REQUIREMENT);
    let required = inventory.requires.iter().any(|value| value == REQUIREMENT);
    if inventory.completeness == "boot-complete" && !required && extension.is_none() {
        if inventory.entries.iter().any(|entry| !entry.included) {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "complete archive cannot omit payloads".into(),
            ));
        }
        return Ok(None);
    }
    if inventory.completeness != "dependent" || !required || extension.is_none() {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "invalid snapshot dependency capability/completeness binding".into(),
        ));
    }
    let dependencies: Dependencies = serde_json::from_value(extension.unwrap().clone())?;
    if (dependencies.disks.is_empty()
        && dependencies.memory.is_empty()
        && dependencies.owned.is_empty())
        || dependencies.disks.len() > 256
        || dependencies.memory.len() > inventory.entries.len()
        || dependencies.owned.len() > inventory.entries.len()
        || dependencies
            .owned
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
        || dependencies
            .memory
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "invalid snapshot dependency count or object ordering".into(),
        ));
    }
    let entries: HashMap<_, _> = inventory
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    let paths = dependency_paths(&inventory.head, &dependencies);
    if paths.len()
        != dependencies.disks.len() + dependencies.memory.len() + dependencies.owned.len()
    {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "duplicate snapshot dependency".into(),
        ));
    }
    for path in &paths {
        let entry = entries.get(path.as_str()).ok_or_else(|| {
            MicrosandboxError::SnapshotIntegrity("dependency lacks an inventory entry".into())
        })?;
        let is_memory = dependencies
            .memory
            .binary_search_by(|id| memory_archive_path(&inventory.head, id).cmp(path))
            .is_ok();
        let is_owned = dependencies
            .owned
            .iter()
            .any(|payload| payload.path == *path);
        let valid_kind = if is_owned {
            matches!(
                entry.kind.as_str(),
                "owned-directory-payload" | "owned-disk-layer" | "checkpoint-disk-layer"
            )
        } else if is_memory {
            entry.kind == "checkpoint-object"
        } else {
            matches!(
                entry.kind.as_str(),
                "file-payload" | "checkpoint-disk-layer"
            )
        };
        if entry.included
            || !valid_kind
            || entry.owner_snapshot.as_deref() != Some(inventory.head.as_str())
            || entry.encoded_size != 0
            || !entry.sparse_ranges.is_empty()
            || entry.transport_integrity.is_some()
        {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "invalid omitted payload binding".into(),
            ));
        }
    }
    if inventory
        .entries
        .iter()
        .filter(|entry| !entry.included)
        .count()
        != paths.len()
    {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "archive omits an undeclared dependency".into(),
        ));
    }
    Ok(Some(dependencies))
}

/// Resolve only a caller-supplied base; never search ambient directories or backing paths.
pub(super) async fn resolve(
    local: &LocalBackend,
    inventory: &ArchiveInventory,
    snapshots_dir: &Path,
    cache_dir: &Path,
    base: Option<&str>,
) -> MicrosandboxResult<()> {
    let Some(dependencies) = validate(inventory)? else {
        return Ok(());
    };
    let base = base.ok_or_else(|| {
        MicrosandboxError::InvalidConfig(
            "this dependent archive requires an explicit base snapshot or standalone base archive"
                .into(),
        )
    })?;
    let base = Box::pin(open_base(local, base)).await?;
    let required_disks = dependencies
        .owned
        .iter()
        .filter(|payload| matches!(payload.identity, OwnedPayloadIdentity::Disk { .. }))
        .collect::<Vec<_>>();
    if !required_disks.is_empty() {
        let target_manifest = Manifest::from_bytes(
            &tokio::fs::read(
                snapshots_dir
                    .join(&inventory.head)
                    .join(DESCRIPTOR_FILENAME),
            )
            .await?,
        )
        .map_err(source_error)?;
        let expected_owned = owned_since_dependencies(&target_manifest, base.snapshot.manifest())?;
        let expected_disks = expected_owned
            .iter()
            .filter(|payload| matches!(payload.identity, OwnedPayloadIdentity::Disk { .. }))
            .collect::<Vec<_>>();
        if expected_disks != required_disks {
            return Err(source_error(
                "supplied base is not the exact required owned disk prefix",
            ));
        }
    }
    let available = physical_layers(base.snapshot.manifest(), base.snapshot.path())?;
    // This dependency list describes only the root chain. Owned prefixes have their own
    // inventory; other additional disks stay complete regardless of checkpoint ordering.
    let available = available
        .iter()
        .filter(|layer| layer.root_chain)
        .collect::<Vec<_>>();
    if !dependencies.disks.is_empty()
        && (available.len() != dependencies.disks.len()
            || available
                .iter()
                .zip(&dependencies.disks)
                .any(|(layer, required)| layer.required.identity != required.identity))
    {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "supplied base is not the exact required physical disk prefix".into(),
        ));
    }
    let available_memory = memory_objects(&base.snapshot)?;
    if dependencies
        .memory
        .iter()
        .any(|id| !available_memory.contains(id))
    {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "supplied base does not contain the required RAM objects".into(),
        ));
    }

    // Every dependency is copied into operation-owned staging. In particular, a restored child
    // must not inherit a writable hardlink into the base; deleting the base must be harmless.
    for (source, required) in available.iter().zip(&dependencies.disks) {
        let target = inventory_entry_target(&required.path, snapshots_dir, cache_dir)?;
        copy_dependency(&source.source, &target).await?;
    }
    for id in &dependencies.memory {
        let source = checkpoint_object_path(&base.snapshot.path().join(CHECKPOINT_DIRECTORY), id);
        let target = inventory_entry_target(
            &memory_archive_path(&inventory.head, id),
            snapshots_dir,
            cache_dir,
        )?;
        copy_dependency(&source, &target).await?;
        // Verify only the objects actually borrowed, in the destination-owned copy. Export
        // selection is metadata-only for RAM; it must not scan the base's entire guest memory.
        // This reader owns a 64 KiB buffer; boxing prevents every enclosing archive/SDK
        // future from embedding another copy of that buffer in its own stack frame.
        let actual = format!(
            "sha256:{}",
            hex::encode(Box::pin(file_sha256(&target)).await?)
        );
        if actual != id.as_str() {
            return Err(MicrosandboxError::SnapshotIntegrity(format!(
                "base RAM object content does not match {id}"
            )));
        }
    }

    let available_owned = owned_payloads(base.snapshot.manifest(), base.snapshot.path())?
        .into_iter()
        .map(|(payload, path)| Ok((serde_json::to_string(&payload.identity)?, path)))
        .collect::<MicrosandboxResult<BTreeMap<_, _>>>()?;
    for payload in &dependencies.owned {
        let source = available_owned
            .get(&serde_json::to_string(&payload.identity)?)
            .ok_or_else(|| {
                source_error(format!("base is missing owned payload {}", payload.path))
            })?;
        let target = inventory_entry_target(&payload.path, snapshots_dir, cache_dir)?;
        copy_dependency(source, &target).await?;
        verify_owned_payload(&target, &payload.identity).await?;
    }

    validate_resolved(local, inventory, snapshots_dir, cache_dir, &dependencies).await
}

async fn validate_resolved(
    local: &LocalBackend,
    inventory: &ArchiveInventory,
    snapshots_dir: &Path,
    cache_dir: &Path,
    dependencies: &Dependencies,
) -> MicrosandboxResult<()> {
    // Open the complete target only after filling omissions. This retains its normal metadata,
    // range, epoch and disk-integrity validation instead of introducing a partial-closure mode.
    let artifact = snapshots_dir.join(&inventory.head);
    let manifest =
        Manifest::from_bytes(&tokio::fs::read(artifact.join(DESCRIPTOR_FILENAME)).await?)
            .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let target = physical_layers(&manifest, &artifact)?;
    let target_owned = owned_payloads(&manifest, &artifact)?;
    for payload in &dependencies.owned {
        if !target_owned.iter().any(|(expected, _)| expected == payload) {
            return Err(source_error(
                "omitted owned payload differs from target required inventory",
            ));
        }
    }
    // Batch sources can satisfy a prefix without one explicit baseline, but the target must
    // still omit only an oldest-first prefix of each owned device, never arbitrary layers.
    let omitted: BTreeSet<_> = dependencies
        .owned
        .iter()
        .map(|payload| payload.path.as_str())
        .collect();
    let namespace = if matches!(manifest.state, SnapshotState::Checkpoint(_)) {
        "checkpoints"
    } else {
        "snapshots"
    };
    for volume in manifest.owned_volumes()? {
        if let microsandbox_image::snapshot::OwnedVolumeData::Disk { generation } = volume.data {
            let mut included = false;
            for layer in generation.layers {
                let path = format!(
                    "{namespace}/{}/layers/{}.{}",
                    manifest.snapshot_id, layer.layer_id, layer.format
                );
                if omitted.contains(path.as_str()) {
                    if included {
                        return Err(source_error(
                            "owned disk dependencies are not an exact oldest-first prefix",
                        ));
                    }
                } else {
                    included = true;
                }
            }
        }
    }
    let target = target
        .iter()
        .filter(|layer| layer.root_chain)
        .collect::<Vec<_>>();
    if target.len() < dependencies.disks.len()
        || target
            .iter()
            .zip(&dependencies.disks)
            .any(|(layer, required)| &layer.required != required)
    {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "dependency list is not the target descriptor's exact disk prefix".into(),
        ));
    }
    let target_memory = if dependencies.memory.is_empty() {
        BTreeSet::new()
    } else {
        let snapshot = store::open_snapshot(local, artifact.to_string_lossy().as_ref()).await?;
        memory_objects(&snapshot)?
    };
    if dependencies
        .memory
        .iter()
        .any(|id| !target_memory.contains(id))
    {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "omitted object is not a target RAM payload; metadata must remain included".into(),
        ));
    }
    let entries: HashMap<_, _> = inventory
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    for id in &dependencies.memory {
        let path = memory_archive_path(&inventory.head, id);
        let entry = entries
            .get(path.as_str())
            .expect("dependency inventory was validated");
        let target = inventory_entry_target(&path, snapshots_dir, cache_dir)?;
        if tokio::fs::metadata(target).await?.len() != entry.apparent_size {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "resolved RAM object size differs from inventory".into(),
            ));
        }
    }
    Ok(())
}

async fn copy_dependency(source: &Path, target: &Path) -> MicrosandboxResult<()> {
    if tokio::fs::symlink_metadata(target).await.is_ok() {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "dependency collides with an extracted member".into(),
        ));
    }
    if let Some(parent) = target.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let source = source.to_path_buf();
    let target = target.to_path_buf();
    tokio::task::spawn_blocking(move || microsandbox_utils::copy::fast_copy(&source, &target))
        .await
        .map_err(|error| MicrosandboxError::Runtime(format!("base payload copy: {error}")))??;
    Ok(())
}

fn memory_archive_path(snapshot_id: &str, id: &ObjectId) -> String {
    let hash = id
        .as_str()
        .strip_prefix("sha256:")
        .expect("validated ObjectId");
    format!(
        "checkpoints/{snapshot_id}/objects/sha256/{}/{hash}",
        &hash[..2]
    )
}

fn checkpoint_object_path(root: &Path, id: &ObjectId) -> PathBuf {
    let hash = id
        .as_str()
        .strip_prefix("sha256:")
        .expect("validated ObjectId");
    root.join("objects")
        .join("sha256")
        .join(&hash[..2])
        .join(hash)
}

fn dependency_paths(head: &str, dependencies: &Dependencies) -> BTreeSet<String> {
    dependencies
        .disks
        .iter()
        .map(|layer| layer.path.clone())
        .chain(
            dependencies
                .memory
                .iter()
                .map(|id| memory_archive_path(head, id)),
        )
        .chain(
            dependencies
                .owned
                .iter()
                .map(|payload| payload.path.clone()),
        )
        .collect()
}

/// Return reusable RAM payload IDs, never metadata objects, even if bytes happen to coincide.
fn memory_objects(snapshot: &Snapshot) -> MicrosandboxResult<BTreeSet<ObjectId>> {
    let SnapshotState::Checkpoint(state) = &snapshot.manifest().state else {
        return Ok(BTreeSet::new());
    };
    let expected = ObjectId::new(&state.checkpoint_root)
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let closure = CheckpointClosure::open_portable(
        snapshot.path().join(CHECKPOINT_DIRECTORY),
        Some(&expected),
    )
    .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let checkpoint = closure.checkpoint();
    let mut objects: BTreeSet<_> = closure
        .memory()
        .extents
        .iter()
        .filter_map(|extent| match &extent.content {
            MemoryExtentContent::Object(content) => Some(content.object.clone()),
            MemoryExtentContent::Zero => None,
        })
        .collect();
    objects.remove(&checkpoint.memory);
    objects.remove(&checkpoint.execution_state);
    for id in &checkpoint.disks {
        objects.remove(id);
    }
    for device in &checkpoint.devices {
        objects.remove(&device.state);
    }
    Ok(objects)
}

fn physical_layers(
    manifest: &Manifest,
    directory: &Path,
) -> MicrosandboxResult<Vec<PhysicalLayer>> {
    match &manifest.state {
        SnapshotState::File(file) => file
            .layers
            .iter()
            .map(|layer| {
                Ok(PhysicalLayer {
                    root_chain: true,
                    required: RequiredLayer {
                        path: portable_archive_path(&file.layer_path(layer))?,
                        identity: LayerIdentity::File(layer.clone()),
                    },
                    source: directory.join(file.layer_path(layer)),
                })
            })
            .collect(),
        SnapshotState::Checkpoint(state) => {
            let root = directory.join(CHECKPOINT_DIRECTORY);
            let expected = ObjectId::new(&state.checkpoint_root)
                .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
            let closure = CheckpointClosure::open_portable(&root, Some(&expected))
                .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
            Ok(closure
                .disks()
                .iter()
                .flat_map(|disk| disk.layers.iter().map(move |layer| (disk, layer)))
                .map(|(disk, layer)| PhysicalLayer {
                    root_chain: Some(disk.device_id.as_str())
                        == super::super::restore::root_device(&manifest.root_disk),
                    required: RequiredLayer {
                        path: format!(
                            "checkpoints/{}/layers/{}.{}",
                            manifest.snapshot_id, layer.layer_id, layer.format
                        ),
                        identity: LayerIdentity::Checkpoint(layer.clone()),
                    },
                    source: closure.disk_layer_path(layer),
                })
                .collect())
        }
    }
}

pub(super) async fn open_base(
    local: &LocalBackend,
    input: &str,
) -> MicrosandboxResult<BaseSnapshot> {
    let path = Path::new(input);
    if !path.is_file() {
        let snapshot = store::open_snapshot(local, input).await?;
        if matches!(snapshot.manifest().state, SnapshotState::File(_)) {
            Box::pin(snapshot.verify()).await?;
        }
        return Ok(BaseSnapshot {
            snapshot,
            _stage: None,
        });
    }
    let stage = tempfile::tempdir()?;
    let snapshots_dir = stage.path().join("snapshots");
    let cache_dir = stage.path().join("cache");
    tokio::fs::create_dir_all(&snapshots_dir).await?;
    tokio::fs::create_dir_all(&cache_dir).await?;
    let mut reader = BufReader::new(tokio::fs::File::open(path).await?);
    let compressed = reader
        .fill_buf()
        .await?
        .starts_with(&[0x28, 0xb5, 0x2f, 0xfd]);
    let unpacked = if compressed {
        Box::pin(unpack_archive(
            ZstdDecoder::new(reader),
            &snapshots_dir,
            &cache_dir,
        ))
        .await?
    } else {
        Box::pin(unpack_archive(reader, &snapshots_dir, &cache_dir)).await?
    };
    if let Some(inventory) = &unpacked.inventory {
        if validate(inventory)?.is_some() {
            return Err(MicrosandboxError::InvalidConfig("the supplied base archive must be standalone; load dependent bases explicitly first".into()));
        }
        materialize_inventory_layers(inventory, &snapshots_dir).await?;
    } else {
        super::super::migration::normalize_staged(local.db().await?, &unpacked.manifest_dirs)
            .await?;
    }
    let imported = verify_imported_snapshots(local, &unpacked.manifest_dirs).await?;
    let head = match unpacked.head {
        Some(head) => imported
            .iter()
            .position(|snapshot| snapshot.id().as_str() == head)
            .ok_or_else(|| {
                MicrosandboxError::SnapshotIntegrity("base archive head is missing".into())
            })?,
        None => select_head_snapshot(&imported)?,
    };
    if let Some(inventory) = &unpacked.inventory {
        validate_inventory_snapshot_bindings(inventory, &imported)?;
    }
    if matches!(imported[head].manifest().state, SnapshotState::File(_)) {
        Box::pin(imported[head].verify()).await?;
    }
    Ok(BaseSnapshot {
        snapshot: imported[head].clone(),
        _stage: Some(stage),
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
#[path = "delta_tests.rs"]
mod memory_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_image::snapshot::{
        DiskLayerId, FileSnapshotState, ImageRef, LayerFileKind, LayerPayload, SnapshotCapture,
        SnapshotConsistency, SnapshotFormat, SnapshotId, SnapshotRootDisk, SnapshotScope,
    };

    #[tokio::test]
    async fn batch_rejects_corrupt_borrowed_file_layer_before_publication() {
        let temp = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(temp.path().join("home"))
            .build()
            .await
            .unwrap();
        let base_dir = temp.path().join("base-source");
        let child_dir = temp.path().join("child-source");
        std::fs::create_dir_all(base_dir.join("layers")).unwrap();
        std::fs::create_dir_all(child_dir.join("layers")).unwrap();
        let mut base_layer = DiskLayer {
            layer_id: DiskLayerId::new("layer_00000000000000000000000000000001").unwrap(),
            format: SnapshotFormat::Raw,
            virtual_size: 65536,
            backing: None,
            payload: LayerPayload {
                file_kind: LayerFileKind::Regular,
                integrity: None,
            },
        };
        let base_path =
            microsandbox_image::snapshot::layer_path(&base_layer.layer_id, base_layer.format);
        std::fs::write(base_dir.join(&base_path), vec![91u8; 65536]).unwrap();
        std::fs::copy(base_dir.join(&base_path), child_dir.join(&base_path)).unwrap();
        base_layer.payload.integrity = Some(
            super::super::super::verify::compute_merkle_integrity(&base_dir.join(&base_path))
                .await
                .unwrap(),
        );
        let top = DiskLayer {
            layer_id: DiskLayerId::new("layer_00000000000000000000000000000002").unwrap(),
            format: SnapshotFormat::Qcow2,
            virtual_size: 65536,
            backing: Some(base_layer.layer_id.clone()),
            payload: LayerPayload {
                file_kind: LayerFileKind::Regular,
                integrity: None,
            },
        };
        let top_path = microsandbox_image::snapshot::layer_path(&top.layer_id, top.format);
        microsandbox_image::checkpoint::create_qcow2_overlay(
            &child_dir.join(top_path),
            65536,
            &child_dir.join(&base_path),
            "raw",
        )
        .await
        .unwrap();
        let descriptor = |value: u128, layers: Vec<DiskLayer>, parent| Manifest {
            schema: "microsandbox.snapshot/1".into(),
            snapshot_id: SnapshotId::new(format!("snap_{value:032x}")).unwrap(),
            scope: SnapshotScope::Disk,
            root_disk: SnapshotRootDisk::Managed,
            state: SnapshotState::File(FileSnapshotState {
                disk_format: layers.last().unwrap().format,
                filesystem: "ext4".into(),
                virtual_size: 65536,
                head: layers.last().unwrap().layer_id.clone(),
                layers,
            }),
            capture: SnapshotCapture {
                created_at: "2026-09-10T00:00:00Z".into(),
                source_lineage: None,
                source_checkpoint: None,
                consistency: SnapshotConsistency::CrashConsistent,
            },
            image: ImageRef {
                reference: "docker.io/library/alpine:3.20".into(),
                manifest_digest: format!("sha256:{}", "0".repeat(64)),
            },
            parent,
            extensions: BTreeMap::new(),
            requires: Vec::new(),
        };
        let base = descriptor(1, vec![base_layer.clone()], None);
        let child = descriptor(2, vec![base_layer, top], Some(base.snapshot_id.clone()));
        for (directory, manifest) in [(&base_dir, &base), (&child_dir, &child)] {
            std::fs::write(
                directory.join(DESCRIPTOR_FILENAME),
                manifest.to_canonical_bytes().unwrap(),
            )
            .unwrap();
        }
        let base_archive = temp.path().join("base.msb");
        save_snapshot(
            &local,
            base_dir.to_str().unwrap(),
            &base_archive,
            SaveOpts::default(),
        )
        .await
        .unwrap();
        let child_archive = temp.path().join("child.msb");
        save_snapshot(
            &local,
            child_dir.to_str().unwrap(),
            &child_archive,
            SaveOpts {
                since: Some(base_dir.to_string_lossy().into_owned()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let options = || LoadOpts {
            group: Some("corrupt-source".into()),
            ..Default::default()
        };
        let installed = load_snapshots(&local, &[base_archive], options())
            .await
            .unwrap();
        let group_dir = installed[0].path().parent().unwrap().to_path_buf();
        let previous_head = std::fs::read(group_dir.join("group.json")).unwrap();
        // Metadata and length still agree: only payload verification can detect this change.
        std::fs::write(installed[0].path().join(&base_path), vec![92u8; 65536]).unwrap();
        let error = load_snapshots(&local, &[child_archive], options())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("integrity mismatch"), "{error}");
        assert!(!group_dir.join(child.snapshot_id.as_str()).exists());
        assert_eq!(
            std::fs::read(group_dir.join("group.json")).unwrap(),
            previous_head
        );
        assert_eq!(
            super::super::super::group::dependency_members(
                &local.snapshots_dir(),
                "corrupt-source",
            )
            .await
            .unwrap(),
            vec![installed[0].path().to_path_buf()]
        );
    }

    #[tokio::test]
    async fn delta_load_and_direct_restore_require_exact_base_and_own_their_closure() {
        let temp = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(temp.path().join("home"))
            .build()
            .await
            .unwrap();
        let base_dir = temp.path().join("base");
        let head_dir = temp.path().join("head");
        tokio::fs::create_dir_all(base_dir.join("layers"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(head_dir.join("layers"))
            .await
            .unwrap();
        let base_layer = DiskLayer {
            layer_id: DiskLayerId::new("layer_00000000000000000000000000000001").unwrap(),
            format: SnapshotFormat::Raw,
            virtual_size: 65536,
            backing: None,
            payload: LayerPayload {
                file_kind: LayerFileKind::Regular,
                integrity: None,
            },
        };
        let top = DiskLayer {
            layer_id: DiskLayerId::new("layer_00000000000000000000000000000002").unwrap(),
            format: SnapshotFormat::Qcow2,
            virtual_size: 65536,
            backing: Some(base_layer.layer_id.clone()),
            payload: base_layer.payload.clone(),
        };
        let descriptor = |id: &str, layers: Vec<DiskLayer>| Manifest {
            schema: "microsandbox.snapshot/1".into(),
            snapshot_id: SnapshotId::new(id).unwrap(),
            scope: SnapshotScope::Disk,
            root_disk: SnapshotRootDisk::Managed,
            state: SnapshotState::File(FileSnapshotState {
                disk_format: layers.last().unwrap().format,
                filesystem: "ext4".into(),
                virtual_size: 65536,
                head: layers.last().unwrap().layer_id.clone(),
                layers,
            }),
            capture: SnapshotCapture {
                created_at: "2026-09-05T00:00:00Z".into(),
                source_lineage: None,
                source_checkpoint: None,
                consistency: SnapshotConsistency::CrashConsistent,
            },
            image: ImageRef {
                reference: "docker.io/library/alpine:3.20".into(),
                manifest_digest: format!("sha256:{}", "0".repeat(64)),
            },
            parent: None,
            extensions: BTreeMap::new(),
            requires: vec![],
        };
        let base = descriptor(
            "snap_00000000000000000000000000000001",
            vec![base_layer.clone()],
        );
        let head = descriptor(
            "snap_00000000000000000000000000000002",
            vec![base_layer.clone(), top.clone()],
        );
        let base_path =
            microsandbox_image::snapshot::layer_path(&base_layer.layer_id, base_layer.format);
        let top_path = microsandbox_image::snapshot::layer_path(&top.layer_id, top.format);
        std::fs::write(base_dir.join(&base_path), vec![91u8; 65536]).unwrap();
        std::fs::copy(base_dir.join(&base_path), head_dir.join(&base_path)).unwrap();
        microsandbox_image::checkpoint::create_qcow2_overlay(
            &head_dir.join(top_path),
            65536,
            &head_dir.join(&base_path),
            "raw",
        )
        .await
        .unwrap();
        std::fs::write(
            base_dir.join(DESCRIPTOR_FILENAME),
            base.to_canonical_bytes().unwrap(),
        )
        .unwrap();
        std::fs::write(
            head_dir.join(DESCRIPTOR_FILENAME),
            head.to_canonical_bytes().unwrap(),
        )
        .unwrap();
        let base_name = base_dir.to_str().unwrap();
        let head_name = head_dir.to_str().unwrap();
        let archive = temp.path().join("delta.tar.zst");
        save_snapshot(
            &local,
            head_name,
            &archive,
            SaveOpts {
                since: Some(base_name.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(load_snapshot(&local, &archive, None).await.is_err());
        // Loading now resolves exact payload identities from a source pool. A complete newer
        // snapshot can supply the required prefix even when it contains additional layers.
        let supplied_by_newer = load_snapshot_with_base(&local, &archive, None, Some(head_name))
            .await
            .unwrap();
        assert!(supplied_by_newer.path().join(&base_path).exists());
        let loaded = load_snapshot_with_base(&local, &archive, None, Some(base_name))
            .await
            .unwrap();
        assert!(loaded.path().join(&base_path).exists());
        let child = temp.path().join("child");
        let result = materialize_archive_for_child_with_base(
            &local,
            &archive,
            &child,
            false,
            Some(base_name),
            &Default::default(),
        )
        .await
        .unwrap();
        assert_eq!(result.upper_layers.len(), 3);
        let base_archive = temp.path().join("base.tar");
        save_snapshot(
            &local,
            base_name,
            &base_archive,
            SaveOpts {
                plain_tar: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let last = temp.path().join("last.tar");
        save_snapshot(
            &local,
            head_name,
            &last,
            SaveOpts {
                last_layers: Some(1),
                plain_tar: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let other_dest = temp.path().join("imported");
        load_snapshot_with_base(
            &local,
            &last,
            Some(&other_dest),
            Some(base_archive.to_str().unwrap()),
        )
        .await
        .unwrap();
        // File-state archives use a shared layers directory, unlike full checkpoint payloads.
        // Both input orders must finish all borrowing reads before consuming those directories.
        for (group, inputs) in [
            ("file-reverse", vec![archive.clone(), base_archive.clone()]),
            ("file-forward", vec![base_archive.clone(), archive.clone()]),
        ] {
            let batch = load_snapshots(
                &local,
                &inputs,
                LoadOpts {
                    group: Some(group.into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            for snapshot in &batch {
                assert_eq!(
                    std::fs::read(snapshot.path().join(&base_path)).unwrap(),
                    vec![91u8; 65536]
                );
            }
        }
        std::fs::remove_dir_all(&base_dir).unwrap();
        assert_eq!(
            std::fs::read(loaded.path().join(&base_path)).unwrap(),
            vec![91u8; 65536]
        );
        assert!(result.upper_layers.iter().all(|layer| layer.path.exists()));
        for count in [0, 3] {
            assert!(
                save_snapshot(
                    &local,
                    head_name,
                    &temp.path().join("invalid.tar"),
                    SaveOpts {
                        last_layers: Some(count),
                        ..Default::default()
                    }
                )
                .await
                .is_err()
            );
        }
        // An intact head must not hide a corrupt recorded ancestor in a file-state chain.
        let mut recorded = head.clone();
        let SnapshotState::File(file) = &mut recorded.state else {
            unreachable!()
        };
        file.layers[0].payload.integrity = Some(
            super::super::super::verify::compute_merkle_integrity(&head_dir.join(&base_path))
                .await
                .unwrap(),
        );
        std::fs::write(
            head_dir.join(DESCRIPTOR_FILENAME),
            recorded.to_canonical_bytes().unwrap(),
        )
        .unwrap();
        let snapshot = store::open_snapshot(&local, head_name).await.unwrap();
        snapshot.verify().await.unwrap();
        std::fs::write(head_dir.join(&base_path), vec![92u8; 65536]).unwrap();
        assert!(snapshot.verify().await.is_err());
    }
}
