//! Prepare explicit snapshot paths for one launch without publishing a snapshot group.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use microsandbox_image::GlobalCache;
use microsandbox_image::checkpoint::{CheckpointClosure, ObjectId};
use microsandbox_image::snapshot::{OwnedVolumeData, SnapshotId, SnapshotState, UpperIntegrity};

use super::super::{Snapshot, dispatch, migration, store};
use super::batch::{StagedArchive, read_manifest, unpack};
use super::{
    delta, install_staged_cache, materialize_inventory_layers, normalize_imported_descriptor,
    validate_inventory_snapshot_bindings, verify_imported_snapshots,
};
use crate::backend::{Backend, LocalBackend};
use crate::sandbox::SandboxConfig;
use crate::{MicrosandboxError, MicrosandboxResult, Operation, UnsupportedReason};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Own all temporary bytes and cache leases until a destination has its own payloads.
/// Drop the selected reader before private directories, including on Windows.
pub(crate) struct PreparedLaunchSource {
    snapshot: Snapshot,
    _archives: Vec<StagedArchive>,
    _images: Vec<GlobalCache>,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for PreparedLaunchSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedLaunchSource")
            .field("checkpoint", self.snapshot.id())
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve and validate explicit local inputs before any destination replacement.
pub(crate) async fn prepare(
    backend: Arc<dyn Backend>,
    config: &mut SandboxConfig,
    paths: Vec<PathBuf>,
    target: Option<SnapshotId>,
) -> MicrosandboxResult<()> {
    if backend.as_local().is_none() {
        return Err(MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable("snapshot path sets require a local backend".into()),
        ));
    }
    if paths.is_empty() || paths.iter().any(|path| !path.is_absolute()) {
        return Err(MicrosandboxError::InvalidConfig(
            "snapshot path sets require nonempty, anchored local paths".into(),
        ));
    }
    // A cancelled waiter must not delete staging while a blocking copy/hash still
    // uses it. This worker owns staging until preparation finishes; cancellation
    // cannot advance from preparation into sandbox creation.
    let owner = backend.clone();
    let prepared = tokio::spawn(async move {
        prepare_inner(
            owner.as_local().expect("local backend checked"),
            &paths,
            target.as_ref(),
        )
        .await
    })
    .await
    .map_err(|error| {
        MicrosandboxError::Runtime(format!("snapshot source preparation: {error}"))
    })??;
    let snapshot = dispatch::from_artifact(backend, prepared.snapshot.clone());
    crate::sandbox::prepare_local_snapshot_restore(config, &snapshot)?;
    config.snapshot_lease = prepared.snapshot.lease.clone();
    config.snapshot_expected_digest = Some(prepared.snapshot.digest().to_owned());
    config.snapshot_prepared_sources = Some(Arc::new(prepared));
    config.snapshot_reference = None;
    Ok(())
}

async fn prepare_inner(
    local: &LocalBackend,
    paths: &[PathBuf],
    target: Option<&SnapshotId>,
) -> MicrosandboxResult<PreparedLaunchSource> {
    let temporary = local.cache_dir().join("tmp");
    tokio::fs::create_dir_all(&temporary).await?;
    let mut archives = Vec::new();
    let mut directories = Vec::new();
    let mut seen_paths = BTreeSet::new();
    for path in paths {
        // Repeated identical inputs are one observation, not another unpack/hash pass.
        // Distinct aliases still undergo descriptor and payload conflict checks.
        if !seen_paths.insert(path) {
            continue;
        }
        let metadata = tokio::fs::metadata(path).await.map_err(|error| {
            MicrosandboxError::Io(std::io::Error::new(
                error.kind(),
                format!("snapshot input {}: {error}", path.display()),
            ))
        })?;
        if metadata.is_dir() {
            let selector = path.to_str().ok_or_else(|| {
                MicrosandboxError::InvalidConfig("snapshot paths must be valid UTF-8".into())
            })?;
            directories.push(store::open_snapshot_leased(local, selector).await?);
        } else if metadata.is_file() {
            archives.push(unpack(path, &temporary, &temporary).await?);
        } else {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "snapshot input {} is not a regular archive or artifact directory",
                path.display()
            )));
        }
    }

    let mut sources = delta::Sources::default();
    for snapshot in &directories {
        sources
            .add_strict(snapshot.manifest(), snapshot.path(), None)
            .await?;
    }
    for archive in &archives {
        if archive.unpacked.inventory.is_none() {
            // Normalize only private unpacked copies. Never publish or reindex a group.
            migration::normalize_staged(local.db().await?, &archive.unpacked.manifest_dirs).await?;
            for snapshot in
                verify_imported_snapshots(local, &archive.unpacked.manifest_dirs).await?
            {
                normalize_imported_descriptor(&snapshot).await?;
            }
        }
        for directory in &archive.unpacked.manifest_dirs {
            let manifest = read_manifest(directory).await?;
            sources
                .add_strict(
                    &manifest,
                    directory,
                    archive
                        .unpacked
                        .inventory
                        .as_ref()
                        .map(|_| archive.snapshots.path()),
                )
                .await?;
        }
    }
    // Check every required identity before copying anything from another input.
    // The whole supplied set participates, independent of argument order; no ambient scan.
    for archive in &archives {
        if let Some(inventory) = &archive.unpacked.inventory {
            sources
                .require(inventory)
                .map_err(|error| input_error(&archive.source, error))?;
        }
    }
    for archive in &archives {
        if let Some(inventory) = &archive.unpacked.inventory {
            delta::resolve_sources(
                local,
                inventory,
                archive.snapshots.path(),
                archive.cache.path(),
                &sources,
            )
            .await
            .map_err(|error| input_error(&archive.source, error))?;
        }
    }
    let mut members = BTreeMap::new();
    for snapshot in directories {
        add_member(local, &mut members, snapshot).await?;
    }
    for archive in &archives {
        if let Some(inventory) = &archive.unpacked.inventory {
            materialize_inventory_layers(inventory, archive.snapshots.path()).await?;
        }
        let snapshots = verify_imported_snapshots(local, &archive.unpacked.manifest_dirs).await?;
        if let Some(inventory) = &archive.unpacked.inventory {
            validate_inventory_snapshot_bindings(
                inventory,
                &snapshots,
                local.config().fs_state_limit(),
            )?;
        }
        for snapshot in snapshots {
            add_member(local, &mut members, snapshot).await?;
        }
    }
    let selected = select_target(&members, target)?;
    let snapshot = members.remove(&selected).expect("selected supplied member");
    let mut images = Vec::new();
    for archive in &archives {
        // An unrelated supplied archive must not install another image. Bundled image
        // bytes are used only when that archive's advertised head pins this image too.
        let head = archive.unpacked.head.as_deref();
        let manifest = match head {
            Some(head) => {
                let directory = archive.unpacked.manifest_dirs.iter().find(|directory| {
                    directory.file_name().and_then(|name| name.to_str()) == Some(head)
                });
                match directory {
                    Some(directory) => Some(read_manifest(directory).await?),
                    None => None,
                }
            }
            None if archive.unpacked.manifest_dirs.len() == 1 => {
                Some(read_manifest(&archive.unpacked.manifest_dirs[0]).await?)
            }
            None => None,
        };
        if manifest.as_ref().is_some_and(|manifest| {
            manifest.image == snapshot.manifest().image
                && manifest.root_disk == snapshot.manifest().root_disk
        }) {
            images.push(
                install_staged_cache(
                    archive.cache.path(),
                    &local.cache_dir(),
                    snapshot.manifest(),
                )
                .await?,
            );
        }
    }
    Ok(PreparedLaunchSource {
        snapshot,
        _archives: archives,
        _images: images,
    })
}

async fn add_member(
    local: &LocalBackend,
    members: &mut BTreeMap<SnapshotId, Snapshot>,
    snapshot: Snapshot,
) -> MicrosandboxResult<()> {
    snapshot.verify(local.config().fs_state_limit()).await?;
    if let Some(previous) = members.get(snapshot.id()) {
        if previous.digest() != snapshot.digest() || previous.labels() != snapshot.labels() {
            return Err(MicrosandboxError::SnapshotIntegrity(format!(
                "snapshot ID {} has conflicting descriptors or labels in the supplied paths",
                snapshot.id()
            )));
        }
        compare_payloads(local, previous, &snapshot).await?;
    } else {
        members.insert(snapshot.id().clone(), snapshot);
    }
    Ok(())
}

/// Parent links choose a target, not payload dependencies. A standalone complete
/// checkpoint may refer to an absent ancestor; a supplied cycle is always invalid.
fn select_target(
    members: &BTreeMap<SnapshotId, Snapshot>,
    target: Option<&SnapshotId>,
) -> MicrosandboxResult<SnapshotId> {
    let mut children: BTreeMap<_, usize> = members.keys().cloned().map(|id| (id, 0)).collect();
    for snapshot in members.values() {
        if let Some(count) = snapshot
            .manifest()
            .parent
            .as_ref()
            .and_then(|parent| children.get_mut(parent))
        {
            *count += 1;
        }
    }
    let tips: BTreeSet<_> = children
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut pending = tips.clone();
    let mut visited = 0;
    while let Some(id) = pending.pop_first() {
        visited += 1;
        if let Some(parent) = members[&id].manifest().parent.as_ref()
            && let Some(count) = children.get_mut(parent)
        {
            *count -= 1;
            if *count == 0 {
                pending.insert(parent.clone());
            }
        }
    }
    if visited != members.len() {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "snapshot input parent graph contains a cycle".into(),
        ));
    }
    if let Some(target) = target {
        return members
            .contains_key(target)
            .then(|| target.clone())
            .ok_or_else(|| {
                MicrosandboxError::InvalidConfig(format!(
                    "checkpoint {target} is not present in the supplied paths"
                ))
            });
    }
    if tips.len() == 1 {
        return Ok(tips.into_iter().next().expect("one tip"));
    }
    Err(MicrosandboxError::InvalidConfig(if tips.is_empty() {
        "snapshot inputs contain no checkpoint".into()
    } else {
        format!(
            "snapshot inputs have multiple terminal checkpoints ({}); select an exact checkpoint ID",
            tips.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }))
}

fn input_error(path: &Path, error: MicrosandboxError) -> MicrosandboxError {
    MicrosandboxError::SnapshotIntegrity(format!("snapshot input {}: {error}", path.display()))
}

async fn compare_payloads(
    local: &LocalBackend,
    left: &Snapshot,
    right: &Snapshot,
) -> MicrosandboxResult<()> {
    // Equal descriptors may omit disk checksums. Do not silently select whichever
    // conflicting payload appeared first. Other closure objects/owned directories
    // are content-addressed and were checked by each snapshot's verification above.
    if disk_fingerprints(local, left).await? != disk_fingerprints(local, right).await? {
        return Err(MicrosandboxError::SnapshotIntegrity(format!(
            "snapshot ID {} has conflicting disk payloads in the supplied paths",
            left.id()
        )));
    }
    Ok(())
}

async fn disk_fingerprints(
    local: &LocalBackend,
    snapshot: &Snapshot,
) -> MicrosandboxResult<BTreeMap<String, UpperIntegrity>> {
    let mut paths = BTreeMap::new();
    match &snapshot.manifest().state {
        SnapshotState::File(file) => {
            for (index, layer) in file.layers.iter().enumerate() {
                let previous = index
                    .checked_sub(1)
                    .map(|i| file.layer_path(&file.layers[i]));
                paths.insert(
                    format!("root/{}", layer.layer_id),
                    (snapshot.layer_path(layer), previous),
                );
            }
            for (index, volume) in snapshot.manifest().owned_volumes()?.iter().enumerate() {
                if let OwnedVolumeData::Disk { generation } = &volume.data {
                    for (layer_index, layer) in generation.layers.iter().enumerate() {
                        let path =
                            PathBuf::from(format!("layers/{}.{}", layer.layer_id, layer.format));
                        let previous = layer_index.checked_sub(1).map(|i| {
                            let previous = &generation.layers[i];
                            PathBuf::from(format!(
                                "layers/{}.{}",
                                previous.layer_id, previous.format
                            ))
                        });
                        paths.insert(
                            format!("owned/{index}/{}", layer.layer_id),
                            (snapshot.path().join(path), previous),
                        );
                    }
                }
            }
        }
        SnapshotState::Checkpoint(state) => {
            let expected = ObjectId::new(&state.checkpoint_root)
                .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
            let closure = CheckpointClosure::open_portable(
                snapshot.path().join(super::CHECKPOINT_DIRECTORY),
                Some(&expected),
                local.config().fs_state_limit(),
            )
            .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
            for (index, disk) in closure.disks().iter().enumerate() {
                for (layer_index, layer) in disk.layers.iter().enumerate() {
                    let previous = layer_index.checked_sub(1).map(|i| {
                        let previous = &disk.layers[i];
                        PathBuf::from(format!("layers/{}.{}", previous.layer_id, previous.format))
                    });
                    paths.insert(
                        format!("disk/{index}/{}", layer.layer_id),
                        (closure.disk_layer_path(layer), previous),
                    );
                }
            }
        }
    }
    let mut fingerprints = BTreeMap::new();
    for (key, (path, previous)) in paths {
        // Direct archives deliberately relocate backing headers. Compare the same
        // exported byte representation without rewriting or copying source disks.
        let prefix = previous
            .map(|previous| {
                microsandbox_image::checkpoint::relocated_qcow2_header(&path, &previous)
            })
            .transpose()?
            .unwrap_or_default();
        let fingerprint =
            super::super::verify::compute_merkle_integrity_with_prefix(&path, prefix).await?;
        fingerprints.insert(key, fingerprint);
    }
    Ok(fingerprints)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
#[path = "launch_tests.rs"]
mod tests;
