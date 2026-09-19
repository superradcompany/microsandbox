//! Private block-chain journals for sandbox-owned volumes.
//!
//! Root and named-volume journals are deliberately untouched. Paths in this new owned-only
//! journal are sandbox-relative, so restore staging can be renamed before the child starts.

use std::collections::BTreeSet;
#[cfg(unix)]
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use microsandbox_image::checkpoint::{
    CompactLayer, DiskCompactionPlan, DiskGenerationManifest, DiskLayerRef,
    materialize_compact_prefix, sparse_file_integrity,
};
use microsandbox_types::DiskCompactionResult;
use serde::{Deserialize, Serialize};

#[cfg(feature = "runner")]
use super::disk::RootDiskRollover;
use super::disk::{RootDiskRolloverError, RuntimeOwnedRootChain, RuntimeOwnedRootLayer};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const SCHEMA: &str = "microsandbox.runtime-owned-disk/1";
const MAX_JOURNAL_BYTES: u64 = 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One sandbox's authoritative owned-disk chain, protected by its lifecycle/disk lease.
pub(super) struct RuntimeOwnedDisk {
    runtime_dir: PathBuf,
    state_path: PathBuf,
    state: OwnedDiskState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedDiskState {
    schema: String,
    device_id: String,
    volume_id: String,
    launch_base: PathBuf,
    read_only: bool,
    generation: u64,
    layers: Vec<OwnedDiskLayer>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedDiskLayer {
    layer_id: String,
    path: PathBuf,
    format: String,
    integrity_root: Option<String>,
}

/// Expensive materialization is complete; the coordinator owns the final shared pause.
pub(super) struct OwnedDiskCompaction {
    pub(super) result: DiskCompactionResult,
    runtime_dir: PathBuf,
    stage: Option<tempfile::TempDir>,
    next: Option<OwnedDiskState>,
}

/// Only the source sandbox's links may be retired after successful backend adoption.
pub(super) struct OwnedDiskRetired {
    paths: Vec<PathBuf>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeOwnedDisk {
    pub(super) fn open(
        runtime_dir: &Path,
        mount_id: &str,
        launch_base: &Path,
        read_only: bool,
    ) -> Result<Self, String> {
        if journal_exists(runtime_dir, mount_id)? {
            let disk = Self::read(runtime_dir, mount_id)?;
            let expected = relative_owned_path(runtime_dir, mount_id, launch_base)?;
            if disk.state.launch_base != expected || disk.state.read_only != read_only {
                return Err("owned disk journal disagrees with its configured binding".into());
            }
            return Ok(disk);
        }
        validate_fresh_storage(runtime_dir, mount_id)?;
        seed_runtime_owned_disk_chain(
            runtime_dir,
            mount_id,
            launch_base,
            &[RuntimeOwnedRootLayer {
                path: launch_base.to_path_buf(),
                format: "raw".into(),
            }],
            read_only,
        )?;
        Self::read(runtime_dir, mount_id)
    }

    pub(super) fn read(runtime_dir: &Path, mount_id: &str) -> Result<Self, String> {
        let state_path = journal_path(runtime_dir, mount_id)?;
        validate_journal_parents(runtime_dir, mount_id)?;
        let metadata = std::fs::symlink_metadata(&state_path).map_err(|error| error.to_string())?;
        if !metadata.is_file() || metadata.len() > MAX_JOURNAL_BYTES {
            return Err("owned disk journal is not a bounded regular file".into());
        }
        let state: OwnedDiskState =
            serde_json::from_slice(&std::fs::read(&state_path).map_err(|error| error.to_string())?)
                .map_err(|error| format!("parse owned disk journal: {error}"))?;
        let disk = Self {
            runtime_dir: runtime_dir.into(),
            state_path,
            state,
        };
        disk.validate(mount_id)?;
        Ok(disk)
    }

    fn validate(&self, mount_id: &str) -> Result<(), String> {
        if self.state.schema != SCHEMA
            || self.state.device_id != mount_id
            || !valid_id(&self.state.volume_id, "vol")
            || self.state.layers.is_empty()
            || self.state.layers.len() > 256
            || self.state.launch_base != Path::new("owned-volumes").join(mount_id).join("disk.raw")
        {
            return Err("owned disk journal has invalid identity or bounds".into());
        }
        let mut paths = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for (index, layer) in self.state.layers.iter().enumerate() {
            if !valid_id(&layer.layer_id, "layer")
                || !ids.insert(&layer.layer_id)
                || !paths.insert(&layer.path)
                || !matches!(layer.format.as_str(), "raw" | "qcow2")
                || (index > 0 && layer.format != "qcow2")
                || (index + 1 < self.state.layers.len() && layer.integrity_root.is_none())
            {
                return Err("owned disk journal has an invalid layer".into());
            }
            validate_relative_owned_path(mount_id, &layer.path)?;
            verify_owned_file(&self.runtime_dir, mount_id, &layer.path)?;
            if index == 0 && layer.format == "qcow2" {
                // Explicit backing(None) may hide an ambient filename during capacity reads.
                // A chain's first layer must actually be standalone, not merely openable.
                let source = self
                    .runtime_dir
                    .parent()
                    .expect("validated runtime parent")
                    .join(&layer.path);
                microsandbox_image::checkpoint::validate_standalone_qcow2(
                    &std::fs::File::open(source).map_err(|error| error.to_string())?,
                )
                .map_err(|error| error.to_string())?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "runner")]
    pub(super) fn device_id(&self) -> &str {
        &self.state.device_id
    }

    pub(super) fn layers(&self) -> Vec<RuntimeOwnedRootLayer> {
        resolved_layers(&self.runtime_dir, &self.state)
    }

    fn capacity(&self) -> Result<u64, String> {
        let capacities = microsandbox_image::checkpoint::layer_capacities(
            self.layers()
                .into_iter()
                .map(|layer| CompactLayer {
                    path: layer.path,
                    qcow2: layer.format == "qcow2",
                })
                .collect(),
        )
        .map_err(|error| format!("owned disk capacity: {error}"))?;
        let capacity = *capacities.last().ok_or("owned disk chain is empty")?;
        if capacity == 0
            || !capacity.is_multiple_of(512)
            || capacities.iter().any(|value| *value != capacity)
        {
            return Err("owned disk layers have inconsistent capacities".into());
        }
        Ok(capacity)
    }

    #[cfg(feature = "runner")]
    pub(super) fn rollover(
        &mut self,
        vm: &msb_krun::VmControl,
        runtime: &tokio::runtime::Handle,
        checkpoint_root: &Path,
        pause_generation: u64,
    ) -> Result<RootDiskRollover, RootDiskRolloverError> {
        let captured = vm
            .capture_block_device_state(&self.state.device_id)
            .map_err(RootDiskRolloverError::pre_rebind)?;
        if captured.pause_generation != pause_generation
            || captured.device.read_only != self.state.read_only
            || captured.device.id != self.state.device_id
            || captured.device.capacity_sectors.checked_mul(512)
                != Some(self.capacity().map_err(RootDiskRolloverError::pre_rebind)?)
        {
            return Err(RootDiskRolloverError::pre_rebind(
                "owned disk state differs from the capture epoch or binding",
            ));
        }
        let device_state = captured
            .encode()
            .map_err(RootDiskRolloverError::pre_rebind)?;
        let (next, manifest) = self
            .prepare_capture(runtime, checkpoint_root, pause_generation)
            .map_err(RootDiskRolloverError::pre_rebind)?;
        let backend =
            prepare_backend(&self.runtime_dir, &next).map_err(RootDiskRolloverError::pre_rebind)?;
        // Once this forward record may have changed, never resume the old writable backend.
        write_state(&self.state_path, &next)?;
        self.state = next;
        vm.replace_block_backend(&self.state.device_id, backend)
            .map_err(RootDiskRolloverError::post_journal)?;
        Ok(RootDiskRollover {
            manifest,
            device_state,
        })
    }

    /// Prepare an immutable closure and a new private head, without changing the live journal.
    fn prepare_capture(
        &self,
        runtime: &tokio::runtime::Handle,
        checkpoint_root: &Path,
        pause_generation: u64,
    ) -> Result<(OwnedDiskState, DiskGenerationManifest), String> {
        if self.state.layers.len() >= 256 {
            return Err("owned disk chain is full; compact its sealed layers first".into());
        }
        let capacity = self.capacity()?;
        let sandbox = self
            .runtime_dir
            .parent()
            .ok_or("runtime has no sandbox parent")?;
        let mut next = self.state.clone();
        let generation = next
            .generation
            .checked_add(1)
            .ok_or("owned disk generation exhausted")?;
        let directory = checkpoint_root.join("layers");
        std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        let mut captured = Vec::with_capacity(next.layers.len());
        for (index, layer) in next.layers.iter_mut().enumerate() {
            let source = sandbox.join(&layer.path);
            if layer.integrity_root.is_none() {
                // Windows FlushFileBuffers requires write access even when the guest disk is RO.
                OpenOptions::new()
                    .write(true)
                    .open(&source)
                    .and_then(|file| file.sync_all())
                    .map_err(|error| format!("flush owned disk: {error}"))?;
                layer.integrity_root = Some(
                    sparse_file_integrity(&source)
                        .map_err(|error| error.to_string())?
                        .root,
                );
            }
            let target = directory.join(format!("{}.{}", layer.layer_id, layer.format));
            let integrity = if index == 0 {
                let expected = layer.integrity_root.as_ref().expect("sealed layer hash");
                publish_link(&source, &target, expected)?;
                expected.clone()
            } else {
                // Relocating a backing filename changes physical bytes. Never rewrite a shared
                // inode, and hash the archive-local representation rather than reusing its source.
                let stage = tempfile::tempdir_in(&directory).map_err(|error| error.to_string())?;
                let staged = stage.path().join("layer.qcow2");
                microsandbox_utils::copy::fast_copy(&source, &staged)
                    .map_err(|error| error.to_string())?;
                let previous: &DiskLayerRef = &captured[index - 1];
                let backing = directory.join(format!("{}.{}", previous.layer_id, previous.format));
                microsandbox_image::checkpoint::relocate_qcow2_backing(&staged, &backing)
                    .map_err(|error| error.to_string())?;
                OpenOptions::new()
                    .write(true)
                    .open(&staged)
                    .and_then(|file| file.sync_all())
                    .map_err(|error| error.to_string())?;
                let hash = sparse_file_integrity(&staged)
                    .map_err(|error| error.to_string())?
                    .root;
                publish_link(&staged, &target, &hash)?;
                hash
            };
            captured.push(DiskLayerRef {
                layer_id: layer.layer_id.clone(),
                format: layer.format.clone(),
                file_size: std::fs::metadata(&target)
                    .map_err(|error| error.to_string())?
                    .len(),
                virtual_size: capacity,
                predecessor: captured.last().map(|previous| previous.layer_id.clone()),
                integrity_root: Some(integrity),
            });
        }
        sync_directory(&directory)?;
        let manifest = DiskGenerationManifest {
            schema: "microsandbox.disk-generation/1".into(),
            volume_id: next.volume_id.clone(),
            device_id: next.device_id.clone(),
            generation,
            head: captured.last().expect("nonempty chain").layer_id.clone(),
            layers: captured,
            pause_generation,
        };
        manifest.validate().map_err(|error| error.to_string())?;
        let previous = next.layers.last().expect("nonempty chain");
        // Keep all active chain members beside one another, including after compaction. The
        // QCOW2 header stores only a basename; an overlay in a different directory would break
        // independent tooling even though the runtime uses an explicit dependency resolver.
        let path = previous
            .path
            .parent()
            .ok_or("owned head has no parent")?
            .join(format!("{}.qcow2", new_id("head")));
        runtime
            .block_on(microsandbox_image::checkpoint::create_qcow2_overlay(
                &sandbox.join(&path),
                capacity,
                &sandbox.join(&previous.path),
                &previous.format,
            ))
            .map_err(|error| error.to_string())?;
        sync_directory(sandbox.join(&path).parent().expect("owned head parent"))?;
        next.layers.push(OwnedDiskLayer {
            layer_id: new_id("layer"),
            path,
            format: "qcow2".into(),
            integrity_root: None,
        });
        next.generation = generation;
        Ok((next, manifest))
    }

    pub(super) fn prepare_compaction(
        &self,
        runtime: &tokio::runtime::Handle,
        layers: Option<usize>,
        dry_run: bool,
    ) -> Result<OwnedDiskCompaction, RootDiskRolloverError> {
        let started = Instant::now();
        let plan = DiskCompactionPlan::new(self.state.layers.len(), layers)
            .map_err(RootDiskRolloverError::pre_rebind)?;
        let mut result = DiskCompactionResult {
            dry_run,
            input_layers: self.state.layers.len(),
            selected_layers: plan.prefix().len(),
            output_layers: plan.output_layers(),
            ..Default::default()
        };
        if dry_run || plan.is_noop() {
            return Ok(OwnedDiskCompaction {
                result,
                runtime_dir: self.runtime_dir.clone(),
                stage: None,
                next: None,
            });
        }
        let sandbox = self.runtime_dir.parent().expect("validated sandbox root");
        let storage = sandbox.join("owned-volumes").join(&self.state.device_id);
        let stage = tempfile::Builder::new()
            .prefix(".compact-")
            .tempdir_in(&storage)
            .map_err(RootDiskRolloverError::pre_rebind)?;
        let prefix = &self.state.layers[plan.prefix()];
        let boundary = prefix.last().expect("nonempty compact prefix");
        let base = stage.path().join(
            boundary
                .path
                .file_name()
                .ok_or_else(|| RootDiskRolloverError::pre_rebind("owned base filename missing"))?,
        );
        let sources = prefix
            .iter()
            .map(|layer| CompactLayer {
                path: sandbox.join(&layer.path),
                qcow2: layer.format == "qcow2",
            })
            .collect::<Vec<_>>();
        let materialized = runtime
            .block_on(materialize_compact_prefix(&sources, &base))
            .map_err(RootDiskRolloverError::pre_rebind)?;
        result.materialized_bytes = materialized.materialized_bytes;
        let mut next = self.state.clone();
        next.layers = vec![OwnedDiskLayer {
            layer_id: new_id("layer"),
            path: relative_owned_path(&self.runtime_dir, &self.state.device_id, &base)
                .map_err(RootDiskRolloverError::pre_rebind)?,
            format: "qcow2".into(),
            integrity_root: Some(
                sparse_file_integrity(&base)
                    .map_err(RootDiskRolloverError::pre_rebind)?
                    .root,
            ),
        }];
        for layer in &self.state.layers[plan.retained()] {
            let path = stage.path().join(layer.path.file_name().ok_or_else(|| {
                RootDiskRolloverError::pre_rebind("owned suffix filename missing")
            })?);
            // Retain the very same mutable head inode, without touching shared QCOW2 headers.
            std::fs::hard_link(sandbox.join(&layer.path), &path)
                .map_err(RootDiskRolloverError::pre_rebind)?;
            let mut replacement = layer.clone();
            replacement.path = relative_owned_path(&self.runtime_dir, &self.state.device_id, &path)
                .map_err(RootDiskRolloverError::pre_rebind)?;
            replacement.layer_id = new_id("layer");
            next.layers.push(replacement);
        }
        sync_directory(stage.path()).map_err(RootDiskRolloverError::pre_rebind)?;
        result.total_us = started.elapsed().as_micros() as u64;
        Ok(OwnedDiskCompaction {
            result,
            runtime_dir: self.runtime_dir.clone(),
            stage: Some(stage),
            next: Some(next),
        })
    }
}

impl OwnedDiskCompaction {
    pub(super) fn is_noop(&self) -> bool {
        self.next.is_none()
    }

    #[cfg(feature = "runner")]
    pub(super) fn prepare_backend(&self) -> Result<Option<msb_krun::PreparedBlockBackend>, String> {
        self.next
            .as_ref()
            .map(|next| prepare_backend(&self.runtime_dir, next))
            .transpose()
    }

    pub(super) fn validate_stopped(&self, runtime: &tokio::runtime::Handle) -> Result<(), String> {
        if let Some(next) = &self.next {
            let layers = resolved_layers(&self.runtime_dir, next)
                .into_iter()
                .map(|layer| CompactLayer {
                    path: layer.path,
                    qcow2: layer.format == "qcow2",
                })
                .collect::<Vec<_>>();
            runtime
                .block_on(microsandbox_image::checkpoint::validate_compact_chain(
                    &layers,
                ))
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    pub(super) fn commit(
        mut self,
        disk: &mut RuntimeOwnedDisk,
    ) -> Result<OwnedDiskRetired, RootDiskRolloverError> {
        let Some(next) = self.next.take() else {
            return Ok(OwnedDiskRetired { paths: Vec::new() });
        };
        let paths = disk.layers().into_iter().map(|layer| layer.path).collect();
        // An uncertain journal rename may already be durable. Keep staged data for recovery.
        let _published = self
            .stage
            .take()
            .expect("changed owned chain has staging")
            .keep();
        write_state(&disk.state_path, &next)?;
        disk.state = next;
        Ok(OwnedDiskRetired { paths })
    }
}

impl OwnedDiskRetired {
    pub(super) fn cleanup(self) {
        for path in self.paths {
            let _ = std::fs::remove_file(path);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Seed a new owned disk from child-private files. No existing journal is overwritten.
/// The last layer is the child's mutable head; captured predecessors are hashed after relocation.
pub fn seed_runtime_owned_disk_chain(
    runtime_dir: &Path,
    mount_id: &str,
    launch_base: &Path,
    layers: &[RuntimeOwnedRootLayer],
    readonly: bool,
) -> Result<(), String> {
    let state_path = journal_path(runtime_dir, mount_id)?;
    if journal_exists(runtime_dir, mount_id)? {
        return Err("owned disk journal already exists".into());
    }
    let mut projected = Vec::with_capacity(layers.len());
    for (index, layer) in layers.iter().enumerate() {
        let path = relative_owned_path(runtime_dir, mount_id, &layer.path)?;
        verify_owned_file(runtime_dir, mount_id, &path)?;
        projected.push(OwnedDiskLayer {
            layer_id: new_id("layer"),
            path,
            format: layer.format.clone(),
            integrity_root: if index + 1 < layers.len() {
                Some(
                    sparse_file_integrity(&layer.path)
                        .map_err(|error| error.to_string())?
                        .root,
                )
            } else {
                None
            },
        });
    }
    let disk = RuntimeOwnedDisk {
        runtime_dir: runtime_dir.into(),
        state_path,
        state: OwnedDiskState {
            schema: SCHEMA.into(),
            device_id: mount_id.into(),
            volume_id: new_id("vol"),
            launch_base: relative_owned_path(runtime_dir, mount_id, launch_base)?,
            read_only: readonly,
            generation: 0,
            layers: projected,
        },
    };
    disk.validate(mount_id)?;
    disk.capacity()?;
    write_state(&disk.state_path, &disk.state).map_err(|error| error.to_string())
}

/// Read an owned disk's complete chain while the caller holds its stopped lifecycle lease.
pub fn load_runtime_owned_disk_chain(
    runtime_dir: &Path,
    mount_id: &str,
) -> Result<Option<RuntimeOwnedRootChain>, String> {
    if !journal_exists(runtime_dir, mount_id)? {
        validate_fresh_storage(runtime_dir, mount_id)?;
        return Ok(None);
    }
    let disk = RuntimeOwnedDisk::read(runtime_dir, mount_id)?;
    Ok(Some(RuntimeOwnedRootChain {
        device_id: mount_id.into(),
        virtual_size: disk.capacity()?,
        layers: disk.layers(),
    }))
}

/// Seal stopped owned storage and record a fresh private head. The caller must retain both
/// sandbox lifecycle and owned-disk leases until completion; future starts follow this journal.
pub fn capture_stopped_owned_disk(
    runtime_dir: &Path,
    mount_id: &str,
    source: &Path,
    readonly: bool,
    checkpoint_root: &Path,
) -> Result<DiskGenerationManifest, String> {
    let mut disk = RuntimeOwnedDisk::open(runtime_dir, mount_id, source, readonly)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let (next, manifest) = disk.prepare_capture(runtime.handle(), checkpoint_root, 0)?;
    write_state(&disk.state_path, &next).map_err(|error| error.to_string())?;
    disk.state = next;
    Ok(manifest)
}

//--------------------------------------------------------------------------------------------------
// Functions: Journal And Path Validation
//--------------------------------------------------------------------------------------------------

fn journal_path(runtime_dir: &Path, mount_id: &str) -> Result<PathBuf, String> {
    if mount_id.is_empty()
        || mount_id.len() > 128
        || matches!(mount_id, "vda" | "vdb")
        || !mount_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("invalid owned disk mount identity".into());
    }
    Ok(runtime_dir
        .join("owned-disks")
        .join(mount_id)
        .join("disk.json"))
}

fn journal_exists(runtime_dir: &Path, mount_id: &str) -> Result<bool, String> {
    let path = journal_path(runtime_dir, mount_id)?;
    validate_journal_parents(runtime_dir, mount_id)?;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err("owned disk journal is not a regular file".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}

/// A missing journal means fresh raw storage only. Never silently reopen disk.raw when chain
/// files prove this disk was previously restored or rolled over and lost authoritative metadata.
fn validate_fresh_storage(runtime_dir: &Path, mount_id: &str) -> Result<(), String> {
    let relative = Path::new("owned-volumes").join(mount_id).join("disk.raw");
    verify_owned_file(runtime_dir, mount_id, &relative)?;
    let directory = runtime_dir
        .parent()
        .ok_or("runtime has no sandbox parent")?
        .join("owned-volumes")
        .join(mount_id);
    for entry in std::fs::read_dir(directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        if !matches!(
            name.to_str(),
            Some("disk.raw" | ".disk-owner" | ".disk-owner.lock" | "disk.raw.lock")
        ) {
            return Err(
                "owned disk has chain storage but its authoritative journal is missing".into(),
            );
        }
    }
    Ok(())
}

fn validate_journal_parents(runtime_dir: &Path, mount_id: &str) -> Result<(), String> {
    for path in [
        runtime_dir.to_path_buf(),
        runtime_dir.join("owned-disks"),
        runtime_dir.join("owned-disks").join(mount_id),
    ] {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err("owned disk journal parent is not a real directory".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

fn relative_owned_path(runtime_dir: &Path, mount_id: &str, path: &Path) -> Result<PathBuf, String> {
    let sandbox = runtime_dir
        .parent()
        .ok_or("runtime has no sandbox parent")?;
    let relative = path
        .strip_prefix(sandbox)
        .map_err(|_| "owned disk is outside its sandbox")?;
    validate_relative_owned_path(mount_id, relative)?;
    Ok(relative.into())
}

fn validate_relative_owned_path(mount_id: &str, path: &Path) -> Result<(), String> {
    if !path.starts_with(Path::new("owned-volumes").join(mount_id))
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        || path.components().count() < 3
    {
        return Err("owned disk layer escapes its owned storage directory".into());
    }
    Ok(())
}

fn verify_owned_file(runtime_dir: &Path, mount_id: &str, relative: &Path) -> Result<(), String> {
    validate_relative_owned_path(mount_id, relative)?;
    let mut cursor = runtime_dir
        .parent()
        .ok_or("runtime has no sandbox parent")?
        .to_path_buf();
    for component in relative.components() {
        cursor.push(component);
        let metadata = std::fs::symlink_metadata(&cursor).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err("owned disk storage cannot traverse symlinks".into());
        }
    }
    if !cursor.is_file() {
        return Err("owned disk layer is not a regular file".into());
    }
    Ok(())
}

fn resolved_layers(runtime_dir: &Path, state: &OwnedDiskState) -> Vec<RuntimeOwnedRootLayer> {
    let sandbox = runtime_dir.parent().expect("validated runtime parent");
    state
        .layers
        .iter()
        .map(|layer| RuntimeOwnedRootLayer {
            path: sandbox.join(&layer.path),
            format: layer.format.clone(),
        })
        .collect()
}

#[cfg(feature = "runner")]
fn prepare_backend(
    runtime_dir: &Path,
    state: &OwnedDiskState,
) -> Result<msb_krun::PreparedBlockBackend, String> {
    msb_krun::PreparedBlockBackend::open(&backend_spec(runtime_dir, state))
        .map_err(|error| error.to_string())
}

#[cfg(feature = "runner")]
fn backend_spec(runtime_dir: &Path, state: &OwnedDiskState) -> msb_krun::BlockBackendSpec {
    let layers = resolved_layers(runtime_dir, state)
        .into_iter()
        .map(|layer| {
            let format = if layer.format == "raw" {
                msb_krun::BlockImageFormat::Raw
            } else {
                msb_krun::BlockImageFormat::Qcow2
            };
            msb_krun::BlockLayerSpec::new(layer.path, format)
        })
        .collect();
    let direct_io = cfg!(target_os = "linux")
        && state
            .layers
            .last()
            .is_some_and(|layer| layer.format == "qcow2");
    // Match the original disk builder: read-only disks advertise no guest flush support.
    // Changing that policy at rollover/compaction would change the live virtio feature set.
    let sync_mode = if state.read_only {
        msb_krun::BlockSyncMode::None
    } else {
        msb_krun::BlockSyncMode::Full
    };
    msb_krun::BlockBackendSpec::new(layers)
        .read_only(state.read_only)
        .direct_io(direct_io)
        .sync_mode(sync_mode)
}

fn write_state(path: &Path, state: &OwnedDiskState) -> Result<(), RootDiskRolloverError> {
    write_state_with_sync(path, state, sync_directory)
}

fn write_state_with_sync(
    path: &Path,
    state: &OwnedDiskState,
    sync: impl FnOnce(&Path) -> Result<(), String>,
) -> Result<(), RootDiskRolloverError> {
    let parent = path
        .parent()
        .ok_or_else(|| RootDiskRolloverError::pre_rebind("owned journal has no parent"))?;
    let runtime = parent
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| RootDiskRolloverError::pre_rebind("owned journal root missing"))?;
    validate_journal_parents(runtime, &state.device_id)
        .map_err(RootDiskRolloverError::pre_rebind)?;
    std::fs::create_dir_all(parent).map_err(RootDiskRolloverError::pre_rebind)?;
    // Persist newly created journal-directory bindings before publishing the journal itself.
    sync_directory(parent.parent().expect("owned journal collection"))
        .map_err(RootDiskRolloverError::pre_rebind)?;
    sync_directory(runtime).map_err(RootDiskRolloverError::pre_rebind)?;
    let mut file =
        tempfile::NamedTempFile::new_in(parent).map_err(RootDiskRolloverError::pre_rebind)?;
    let bytes = serde_json::to_vec(state).map_err(RootDiskRolloverError::pre_rebind)?;
    file.write_all(&bytes)
        .and_then(|()| file.as_file().sync_all())
        .map_err(RootDiskRolloverError::pre_rebind)?;
    let (file, staged) = file.keep().map_err(RootDiskRolloverError::pre_rebind)?;
    drop(file);
    if let Err(error) = super::replace_file(&staged, path) {
        let _ = std::fs::remove_file(&staged);
        return Err(RootDiskRolloverError::post_journal(error));
    }
    sync(parent).map_err(RootDiskRolloverError::post_journal)
}

fn publish_link(source: &Path, target: &Path, expected: &str) -> Result<(), String> {
    match std::fs::hard_link(source, target) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if sparse_file_integrity(target)
                .map_err(|cause| cause.to_string())?
                .root
                == expected
            {
                Ok(())
            } else {
                Err("owned snapshot layer identity conflicts".into())
            }
        }
        Err(error) => Err(error.to_string()),
    }
}

fn sync_directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| error.to_string())?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn new_id(prefix: &str) -> String {
    let bytes: [u8; 16] = rand::random();
    format!("{prefix}_{}", hex::encode(bytes))
}

fn valid_id(value: &str, prefix: &str) -> bool {
    value.len() == prefix.len() + 33
        && value.starts_with(prefix)
        && value.as_bytes().get(prefix.len()) == Some(&b'_')
        && value[prefix.len() + 1..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, PathBuf, String, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("sandbox");
        let runtime = root.join("runtime");
        let id = microsandbox_types::owned_volume_mount_id("/data");
        let source = root.join("owned-volumes").join(&id).join("disk.raw");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&runtime).unwrap();
        let mut bytes = vec![0_u8; 131072];
        bytes[..6].copy_from_slice(b"before");
        std::fs::write(&source, bytes).unwrap();
        (temp, runtime, id, source)
    }

    fn capture(runtime: &Path, id: &str, source: &Path, target: &Path) -> DiskGenerationManifest {
        capture_stopped_owned_disk(runtime, id, source, false, target).unwrap()
    }

    fn assert_relative_backing(layers: &[RuntimeOwnedRootLayer]) {
        for (index, layer) in layers.iter().enumerate().skip(1) {
            let bytes = std::fs::read(&layer.path).unwrap();
            let offset = u64::from_be_bytes(bytes[8..16].try_into().unwrap()) as usize;
            let len = u32::from_be_bytes(bytes[16..20].try_into().unwrap()) as usize;
            let filename = std::str::from_utf8(&bytes[offset..offset + len]).unwrap();
            let backing = layer.path.parent().unwrap().join(filename);
            assert!(
                backing.is_file(),
                "backing {} must exist",
                backing.display()
            );
            assert_eq!(backing, layers[index - 1].path);
        }
    }

    #[test]
    fn owned_capture_rotates_head_and_preserves_exact_prefix() {
        let (temp, runtime, id, source) = fixture();
        let first = capture(&runtime, &id, &source, &temp.path().join("cp1"));
        let second = capture(&runtime, &id, &source, &temp.path().join("cp2"));
        let third = capture(&runtime, &id, &source, &temp.path().join("cp3"));
        assert_eq!(first.layers.len(), 1);
        assert_eq!(&second.layers[..1], &first.layers);
        assert_eq!(&third.layers[..2], &second.layers);
        let chain = load_runtime_owned_disk_chain(&runtime, &id)
            .unwrap()
            .unwrap();
        assert_eq!(chain.layers.len(), 4);
        assert_eq!(chain.virtual_size, 131072);
        assert_eq!(chain.layers[0].format, "raw");
        assert!(
            chain
                .layers
                .iter()
                .skip(1)
                .all(|layer| layer.format == "qcow2")
        );
        assert_relative_backing(&chain.layers);
    }

    #[test]
    fn owned_journal_survives_sandbox_staging_rename_and_missing_nominal_raw() {
        let (temp, runtime, id, source) = fixture();
        let renamed_base = source.with_file_name("sealed.raw");
        std::fs::rename(&source, &renamed_base).unwrap();
        let head = source.with_file_name("writable.qcow2");
        let executor = tokio::runtime::Runtime::new().unwrap();
        executor
            .block_on(microsandbox_image::checkpoint::create_qcow2_overlay(
                &head,
                131072,
                &renamed_base,
                "raw",
            ))
            .unwrap();
        seed_runtime_owned_disk_chain(
            &runtime,
            &id,
            &source,
            &[
                RuntimeOwnedRootLayer {
                    path: renamed_base,
                    format: "raw".into(),
                },
                RuntimeOwnedRootLayer {
                    path: head,
                    format: "qcow2".into(),
                },
            ],
            false,
        )
        .unwrap();
        let before = std::fs::read_to_string(journal_path(&runtime, &id).unwrap()).unwrap();
        assert!(!before.contains(&temp.path().display().to_string()));
        let final_root = temp.path().join("published");
        std::fs::rename(runtime.parent().unwrap(), &final_root).unwrap();
        let chain = load_runtime_owned_disk_chain(&final_root.join("runtime"), &id)
            .unwrap()
            .unwrap();
        assert!(
            chain
                .layers
                .iter()
                .all(|layer| layer.path.starts_with(&final_root))
        );
        assert!(
            !final_root
                .join("owned-volumes")
                .join(&id)
                .join("disk.raw")
                .exists()
        );
        assert_relative_backing(&chain.layers);
    }

    #[test]
    fn owned_capture_keeps_root_journal_and_readonly_binding_unchanged() {
        let (temp, runtime, id, source) = fixture();
        let root = runtime.join("root-disk.json");
        std::fs::write(&root, b"existing root journal").unwrap();
        capture_stopped_owned_disk(&runtime, &id, &source, true, &temp.path().join("cp")).unwrap();
        let disk = RuntimeOwnedDisk::read(&runtime, &id).unwrap();
        assert!(disk.state.read_only);
        assert_eq!(std::fs::read(root).unwrap(), b"existing root journal");
        assert!(RuntimeOwnedDisk::open(&runtime, &id, &source, false).is_err());
        assert_relative_backing(&disk.layers());
    }

    #[test]
    #[cfg(feature = "runner")]
    fn owned_replacement_preserves_readonly_sync_policy_for_raw_and_qcow() {
        for readonly in [false, true] {
            let (temp, runtime, id, source) = fixture();
            for qcow in [false, true] {
                if qcow {
                    capture_stopped_owned_disk(
                        &runtime,
                        &id,
                        &source,
                        readonly,
                        &temp.path().join("cp"),
                    )
                    .unwrap();
                }
                let disk = RuntimeOwnedDisk::open(&runtime, &id, &source, readonly).unwrap();
                let spec = backend_spec(&runtime, &disk.state);
                assert_eq!(spec.read_only, readonly);
                assert_eq!(
                    spec.sync_mode,
                    if readonly {
                        msb_krun::BlockSyncMode::None
                    } else {
                        msb_krun::BlockSyncMode::Full
                    }
                );
                assert_eq!(spec.direct_io, cfg!(target_os = "linux") && qcow);
                assert_eq!(
                    spec.layers.last().unwrap().format,
                    if qcow {
                        msb_krun::BlockImageFormat::Qcow2
                    } else {
                        msb_krun::BlockImageFormat::Raw
                    }
                );
            }
        }
    }

    #[test]
    fn owned_compaction_clamps_count_keeps_head_and_old_snapshots() {
        let (temp, runtime, id, source) = fixture();
        for n in 0..3 {
            capture(&runtime, &id, &source, &temp.path().join(format!("cp{n}")));
        }
        let mut disk = RuntimeOwnedDisk::read(&runtime, &id).unwrap();
        let before_head = std::fs::read(&disk.layers().last().unwrap().path).unwrap();
        let executor = tokio::runtime::Runtime::new().unwrap();
        let dry = disk
            .prepare_compaction(executor.handle(), Some(999), true)
            .unwrap();
        assert_eq!(dry.result.selected_layers, 3);
        assert!(dry.is_noop());
        assert_eq!(disk.layers().len(), 4);
        let prepared = disk
            .prepare_compaction(executor.handle(), Some(999), false)
            .unwrap();
        assert_eq!(prepared.result.output_layers, 2);
        prepared.validate_stopped(executor.handle()).unwrap();
        let retired = prepared.commit(&mut disk).unwrap();
        retired.cleanup();
        assert_eq!(disk.layers().len(), 2);
        assert_eq!(std::fs::read(&disk.layers()[1].path).unwrap(), before_head);
        assert_relative_backing(&disk.layers());
        let checkpoint = temp.path().join("cp0/layers");
        let retained = std::fs::read_dir(checkpoint)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(&std::fs::read(retained).unwrap()[..6], b"before");
        capture(&runtime, &id, &source, &temp.path().join("after"));
        assert_relative_backing(
            &load_runtime_owned_disk_chain(&runtime, &id)
                .unwrap()
                .unwrap()
                .layers,
        );
    }

    #[test]
    fn failed_owned_capture_does_not_advance_authoritative_head() {
        let (temp, runtime, id, source) = fixture();
        RuntimeOwnedDisk::open(&runtime, &id, &source, false).unwrap();
        let before = std::fs::read(journal_path(&runtime, &id).unwrap()).unwrap();
        let target = temp.path().join("not-a-directory");
        std::fs::write(&target, b"sentinel").unwrap();
        assert!(capture_stopped_owned_disk(&runtime, &id, &source, false, &target).is_err());
        assert_eq!(
            std::fs::read(journal_path(&runtime, &id).unwrap()).unwrap(),
            before
        );
        assert_eq!(std::fs::read(target).unwrap(), b"sentinel");
    }

    #[test]
    fn owned_seed_rejects_escape_unknown_format_and_capacity_mismatch() {
        let (temp, runtime, id, source) = fixture();
        let outside = temp.path().join("outside.raw");
        std::fs::write(&outside, [0u8; 512]).unwrap();
        assert!(
            seed_runtime_owned_disk_chain(
                &runtime,
                &id,
                &source,
                &[RuntimeOwnedRootLayer {
                    path: outside,
                    format: "raw".into()
                },],
                false
            )
            .is_err()
        );
        assert!(
            seed_runtime_owned_disk_chain(
                &runtime,
                &id,
                &source,
                &[RuntimeOwnedRootLayer {
                    path: source.clone(),
                    format: "vmdk".into()
                },],
                false
            )
            .is_err()
        );
        let head = source.with_file_name("short.qcow2");
        let executor = tokio::runtime::Runtime::new().unwrap();
        executor
            .block_on(microsandbox_image::checkpoint::create_qcow2_overlay(
                &head, 65536, &source, "raw",
            ))
            .unwrap();
        assert!(
            seed_runtime_owned_disk_chain(
                &runtime,
                &id,
                &source,
                &[RuntimeOwnedRootLayer {
                    path: head.clone(),
                    format: "qcow2".into()
                },],
                false
            )
            .unwrap_err()
            .contains("standalone")
        );
        assert!(
            seed_runtime_owned_disk_chain(
                &runtime,
                &id,
                &source,
                &[
                    RuntimeOwnedRootLayer {
                        path: source.clone(),
                        format: "raw".into()
                    },
                    RuntimeOwnedRootLayer {
                        path: head,
                        format: "qcow2".into()
                    },
                ],
                false
            )
            .is_err()
        );
        assert!(!journal_path(&runtime, &id).unwrap().exists());
    }

    #[test]
    fn owned_journal_uncertain_sync_keeps_durable_forward_record() {
        let (_temp, runtime, id, source) = fixture();
        let disk = RuntimeOwnedDisk::open(&runtime, &id, &source, false).unwrap();
        let mut next = disk.state.clone();
        next.generation = 7;
        let error = write_state_with_sync(&disk.state_path, &next, |_| {
            Err("injected journal sync failure".into())
        })
        .unwrap_err();
        assert!(error.to_string().contains("injected"));
        #[cfg(feature = "runner")]
        assert!(error.keep_paused);
        assert_eq!(
            RuntimeOwnedDisk::read(&runtime, &id)
                .unwrap()
                .state
                .generation,
            7
        );
    }

    #[test]
    fn owned_lost_journal_never_falls_back_to_sealed_raw() {
        let (temp, runtime, id, source) = fixture();
        assert!(
            load_runtime_owned_disk_chain(&runtime, &id)
                .unwrap()
                .is_none()
        );
        capture(&runtime, &id, &source, &temp.path().join("cp"));
        std::fs::remove_file(journal_path(&runtime, &id).unwrap()).unwrap();
        assert!(
            load_runtime_owned_disk_chain(&runtime, &id)
                .unwrap_err()
                .contains("journal is missing")
        );
        assert!(RuntimeOwnedDisk::open(&runtime, &id, &source, false).is_err());
        assert!(!journal_path(&runtime, &id).unwrap().exists());
    }

    #[cfg(unix)]
    #[test]
    fn owned_dangling_journal_is_not_an_absent_journal() {
        let (temp, runtime, id, source) = fixture();
        let path = journal_path(&runtime, &id).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(temp.path().join("missing"), &path).unwrap();
        assert!(
            load_runtime_owned_disk_chain(&runtime, &id)
                .unwrap_err()
                .contains("not a regular file")
        );
        assert!(RuntimeOwnedDisk::open(&runtime, &id, &source, false).is_err());
        assert!(
            std::fs::symlink_metadata(path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn owned_seed_rejects_symlink_storage_and_journal_parent() {
        let (temp, runtime, id, source) = fixture();
        let linked = source.with_file_name("alias.raw");
        std::os::unix::fs::symlink(&source, &linked).unwrap();
        assert!(
            seed_runtime_owned_disk_chain(
                &runtime,
                &id,
                &source,
                &[RuntimeOwnedRootLayer {
                    path: linked,
                    format: "raw".into()
                },],
                false
            )
            .is_err()
        );
        let elsewhere = temp.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, runtime.join("owned-disks")).unwrap();
        assert!(
            seed_runtime_owned_disk_chain(
                &runtime,
                &id,
                &source,
                &[RuntimeOwnedRootLayer {
                    path: source.clone(),
                    format: "raw".into()
                },],
                false
            )
            .is_err()
        );
        assert_eq!(std::fs::read_dir(elsewhere).unwrap().count(), 0);
    }
}
