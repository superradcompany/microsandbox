//! Crash-forward rollover for sandbox-owned root disks.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[cfg(unix)]
use std::fs::File;

use microsandbox_image::checkpoint::sparse_file_integrity;
#[cfg(feature = "runner")]
use microsandbox_image::checkpoint::{
    CheckpointClosure, DiskGenerationManifest, DiskLayerRef,
    qcow2_backing_basename as qcow_backing_basename,
};
use microsandbox_image::checkpoint::{
    CompactLayer, DiskCompactionPlan, compact_layer_capacity, materialize_compact_prefix,
};
pub use microsandbox_types::DiskCompactionResult;
use serde::{Deserialize, Serialize};

#[cfg(feature = "runner")]
use crate::vm::{UpperLayerSpec, UpperSpec, VmConfig};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const ROOT_DISK_STATE_FILE: &str = "root-disk.json";
const ROOT_DISK_STATE_SCHEMA: &str = "microsandbox.runtime-root-disk/1";
const MAX_ROOT_DISK_STATE_BYTES: u64 = 1024 * 1024;
const MANAGED_ROOT_DEVICE_ID: &str = "vdb";
const FLAT_ROOT_DEVICE_ID: &str = "vda";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Borrowed lookup of integrity already admitted for an unchanged immutable layer.
#[cfg(feature = "runner")]
type AdmittedLayerLookup<'a> = dyn Fn(&Path) -> Result<Option<String>, String> + 'a;

/// Runtime owner of a sandbox-owned writable-root chain.
pub(crate) struct RuntimeOwnedRootDisk {
    state_path: PathBuf,
    state: RootDiskState,
}

/// Stable stopped view of one sandbox-owned root-disk chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeOwnedRootChain {
    /// Guest-visible block device backed by this chain.
    pub device_id: String,
    /// Guest-visible capacity of the writable head; sealed ancestors may be smaller.
    pub virtual_size: u64,
    /// Complete oldest-to-head physical closure.
    pub layers: Vec<RuntimeOwnedRootLayer>,
}

/// One physical member of a stopped sandbox-owned root-disk chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeOwnedRootLayer {
    /// Runtime-owned host path.
    pub path: PathBuf,
    /// Explicit physical format (`raw` or `qcow2`).
    pub format: String,
}

/// Successfully sealed disk generation and the block state captured at its pause boundary.
#[cfg(feature = "runner")]
pub(crate) struct RootDiskRollover {
    pub(crate) manifest: DiskGenerationManifest,
    pub(crate) device_state: Vec<u8>,
}

/// A rollover failure that distinguishes safely resumable preparation from uncertain rebind.
#[derive(Debug)]
pub(crate) struct RootDiskRolloverError {
    message: String,
    #[cfg(feature = "runner")]
    pub(crate) keep_paused: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootDiskState {
    schema: String,
    volume_id: String,
    device_id: String,
    #[serde(default)]
    layout: RootDiskLayout,
    published_generation: u64,
    /// Original launch configuration binding, retained across representation-only compaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    launch_base: Option<PathBuf>,
    /// Unfinished forward-only growth. Older runtime readers refuse this field rather than
    /// accepting a chain whose filesystem expansion has not been acknowledged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    growth_target: Option<u64>,
    layers: Vec<RootDiskLayer>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RootDiskLayout {
    #[default]
    ManagedUpper,
    FlatRoot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RootDiskFormat {
    Raw,
    Qcow2,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootDiskLayer {
    layer_id: String,
    path: PathBuf,
    format: RootDiskFormat,
    integrity_root: Option<String>,
}

/// Prepared storage only; it does not change the existing root-journal representation.
pub(super) struct RootDiskCompaction {
    stage: Option<tempfile::TempDir>,
    next: Option<RootDiskState>,
    pub(super) result: DiskCompactionResult,
}

/// Keep old entries until the caller has successfully rebound every selected device.
pub(super) struct RetiredRootDisk {
    parent: PathBuf,
    paths: Vec<PathBuf>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeOwnedRootDisk {
    pub(super) fn read(runtime_dir: &Path) -> Result<Option<Self>, String> {
        let state_path = runtime_dir.join(ROOT_DISK_STATE_FILE);
        if !state_path.exists() {
            return Ok(None);
        }
        Ok(Some(Self {
            state: read_state(&state_path)?,
            state_path,
        }))
    }
    pub(crate) fn growth_pending(&self) -> bool {
        self.state.growth_target.is_some()
    }

    #[cfg(feature = "runner")]
    pub(crate) fn begin_growth(&mut self, target: u64) -> Result<(), String> {
        let capacities = microsandbox_image::checkpoint::layer_capacities(
            self.state
                .layers
                .iter()
                .map(|layer| CompactLayer {
                    path: layer.path.clone(),
                    qcow2: layer.format == RootDiskFormat::Qcow2,
                })
                .collect(),
        )
        .map_err(|e| e.to_string())?;
        let current = *capacities.last().expect("validated nonempty chain");
        if target < current
            || target == 0
            || !target.is_multiple_of(4096)
            || capacities.iter().any(|size| *size > current)
        {
            return Err("root growth requires an aligned nondecreasing capacity with no larger backing ancestor".into());
        }
        if self
            .state
            .growth_target
            .is_some_and(|pending| pending != target)
        {
            return Err(
                "complete the pending root-disk growth target before requesting another size"
                    .into(),
            );
        }
        let mut next = self.state.clone();
        next.growth_target = Some(target);
        // A failed earlier capture may have cached a head hash. Growth changes its bytes;
        // no future snapshot may reuse that cached identity after mutation starts.
        if let Some(head) = next.layers.last_mut() {
            head.integrity_root = None;
        }
        write_state(&self.state_path, &next)?;
        self.state = next;
        Ok(())
    }

    #[cfg(feature = "runner")]
    pub(crate) fn finish_growth(&mut self) -> Result<(), String> {
        let mut next = self.state.clone();
        next.growth_target = None;
        write_state(&self.state_path, &next)?;
        self.state = next;
        Ok(())
    }

    /// Open the authoritative chain journal or initialize it from a sandbox-owned root disk.
    #[cfg(feature = "runner")]
    pub(crate) fn open(runtime_dir: &Path, vm: &VmConfig) -> Result<Option<Self>, String> {
        Self::open_with_admitted(runtime_dir, vm, None)
    }

    #[cfg(feature = "runner")]
    fn open_with_admitted(
        runtime_dir: &Path,
        vm: &VmConfig,
        admitted: Option<&AdmittedLayerLookup<'_>>,
    ) -> Result<Option<Self>, String> {
        let Some(layout) = configured_layout(vm) else {
            return Ok(None);
        };
        let state_path = runtime_dir.join(ROOT_DISK_STATE_FILE);
        let state = if state_path.exists() {
            read_state(&state_path)?
        } else {
            let layers = configured_layers(vm, layout)?;
            if layers.is_empty() {
                return Ok(None);
            }
            let mut state = RootDiskState {
                schema: ROOT_DISK_STATE_SCHEMA.into(),
                volume_id: new_id("vol"),
                device_id: layout.device_id().into(),
                layout,
                published_generation: 0,
                launch_base: restored_launch_base(runtime_dir, layout, &layers),
                growth_target: None,
                layers: layers
                    .into_iter()
                    .map(|layer| RootDiskLayer {
                        layer_id: new_id("layer"),
                        path: layer.path,
                        format: RootDiskFormat::try_from(layer.format)
                            .expect("configured upper layers were validated before VM build"),
                        integrity_root: None,
                    })
                    .collect(),
            };
            let last = state.layers.len() - 1;
            let mut reused_layers = 0_u64;
            let hashed_layers = 0_u64;
            let started = Instant::now();
            for layer in state.layers.iter_mut().take(last) {
                let reused = admitted
                    .map(|reuse| reuse(&layer.path))
                    .transpose()
                    .map_err(|error| format!("reuse admitted root ancestor: {error}"))?
                    .flatten();
                layer.integrity_root = if let Some(root) = reused {
                    reused_layers += 1;
                    Some(root)
                } else {
                    // A copied or relocated file cannot inherit the original content hash.
                    // Journal construction must not silently opt into scanning its payload.
                    None
                };
            }
            tracing::info!(target: "microsandbox_checkpoint_timing", operation = "root_journal_admission", reused_layers, hashed_layers, total_us = started.elapsed().as_micros(), "root journal admission timing");
            write_state(&state_path, &state)?;
            state
        };
        state.validate()?;
        Ok(Some(Self { state_path, state }))
    }

    /// Guest-visible block identity owned by this rollover provider.
    #[cfg(feature = "runner")]
    pub(crate) fn device_id(&self) -> &str {
        &self.state.device_id
    }

    pub(super) fn prepare_compaction(
        &self,
        runtime: &tokio::runtime::Handle,
        layers: Option<usize>,
        dry_run: bool,
    ) -> Result<RootDiskCompaction, RootDiskRolloverError> {
        if self.growth_pending() {
            return Err(RootDiskRolloverError::pre_rebind(
                "complete pending root-disk growth before compaction",
            ));
        }
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
            return Ok(RootDiskCompaction {
                stage: None,
                next: None,
                result,
            });
        }
        let parent = self.state_path.parent().expect("root journal has parent");
        let stage = tempfile::Builder::new()
            .prefix(".compact-")
            .tempdir_in(parent)
            .map_err(RootDiskRolloverError::pre_rebind)?;
        let prefix = &self.state.layers[plan.prefix()];
        let boundary = prefix.last().expect("nonempty compact prefix");
        if boundary.format != RootDiskFormat::Qcow2 {
            return Err(RootDiskRolloverError::pre_rebind(
                "compaction boundary must be qcow2",
            ));
        }
        let base_path = stage.path().join(
            boundary
                .path
                .file_name()
                .ok_or_else(|| RootDiskRolloverError::pre_rebind("invalid base name"))?,
        );
        let sources = prefix
            .iter()
            .map(|layer| CompactLayer {
                path: layer.path.clone(),
                qcow2: layer.format == RootDiskFormat::Qcow2,
            })
            .collect::<Vec<_>>();
        let materialized = runtime
            .block_on(materialize_compact_prefix(&sources, &base_path))
            .map_err(RootDiskRolloverError::pre_rebind)?;
        result.materialized_bytes = materialized.materialized_bytes;
        let mut next = self.state.clone();
        // Startup still carries the original configured root path. Preserve that binding rather
        // than weakening recovery to accept a journal belonging to an unrelated root.
        if next.launch_base.is_none() {
            next.launch_base = self.state.layers.first().map(|layer| layer.path.clone());
        }
        next.layers = vec![RootDiskLayer {
            layer_id: new_id("layer"),
            path: base_path,
            format: RootDiskFormat::Qcow2,
            integrity_root: None,
        }];
        next.layers[0].integrity_root = if self.state.layers[plan.prefix()]
            .iter()
            .all(|layer| layer.integrity_root.is_some())
        {
            Some(
                sparse_file_integrity(&next.layers[0].path)
                    .map_err(RootDiskRolloverError::pre_rebind)?
                    .root,
            )
        } else {
            None
        };
        for layer in &self.state.layers[plan.retained()] {
            let path = stage.path().join(
                layer
                    .path
                    .file_name()
                    .ok_or_else(|| RootDiskRolloverError::pre_rebind("invalid suffix name"))?,
            );
            // Same inode, different owned directory binding. Do not copy the changing writable
            // head and do not rewrite shared metadata. Backing basenames and formats stay valid.
            std::fs::hard_link(&layer.path, &path).map_err(|error| {
                RootDiskRolloverError::pre_rebind(format!(
                    "compaction requires same-filesystem hardlink bindings: {error}"
                ))
            })?;
            let mut replacement = layer.clone();
            replacement.path = path;
            // Archive relocation will change predecessor names after this representation cut.
            // Fresh IDs prevent later exports from confusing old and new physical prefixes.
            replacement.layer_id = new_id("layer");
            next.layers.push(replacement);
        }
        sync_directory(stage.path()).map_err(RootDiskRolloverError::pre_rebind)?;
        result.total_us = started.elapsed().as_micros() as u64;
        Ok(RootDiskCompaction {
            stage: Some(stage),
            next: Some(next),
            result,
        })
    }

    /// Retain single-root behavior while exposing preparation to the shared-pause coordinator.
    pub(crate) fn compact(
        &mut self,
        #[cfg(feature = "runner")] vm: Option<&msb_krun::VmControl>,
        runtime: &tokio::runtime::Handle,
        layers: Option<usize>,
        dry_run: bool,
    ) -> Result<DiskCompactionResult, RootDiskRolloverError> {
        let started = Instant::now();
        let prepared = self.prepare_compaction(runtime, layers, dry_run)?;
        let mut result = prepared.result.clone();
        if prepared.next.is_none() {
            return Ok(result);
        }
        #[cfg(feature = "runner")]
        let (pause, backend, paused_at) = {
            let paused_at = Instant::now();
            let pause = vm
                .map(|vm| vm.pause())
                .transpose()
                .map_err(RootDiskRolloverError::pre_rebind)?;
            let backend = match prepared.prepare_backend() {
                Ok(backend) => backend.expect("nonempty compaction checked above"),
                Err(error) => {
                    if let (Some(vm), Some(pause)) = (vm, pause) {
                        vm.resume(pause)
                            .map_err(RootDiskRolloverError::post_journal)?;
                    }
                    return Err(RootDiskRolloverError::pre_rebind(error));
                }
            };

            (pause, backend, paused_at)
        };
        #[cfg(not(feature = "runner"))]
        {
            // Stopped SDK maintenance validates the same explicit closure without importing
            // hypervisor types. No header-selected backing paths may be opened implicitly.
            let layers = prepared
                .next
                .as_ref()
                .expect("nonempty compaction checked above")
                .layers
                .iter()
                .map(|layer| CompactLayer {
                    path: layer.path.clone(),
                    qcow2: layer.format == RootDiskFormat::Qcow2,
                })
                .collect::<Vec<_>>();
            runtime
                .block_on(microsandbox_image::checkpoint::validate_compact_chain(
                    &layers,
                ))
                .map_err(RootDiskRolloverError::pre_rebind)?;
        }
        let retired = prepared.commit(self)?;
        #[cfg(feature = "runner")]
        {
            if let (Some(vm), Some(pause)) = (vm, pause) {
                vm.replace_block_backend(&self.state.device_id, backend)
                    .map_err(RootDiskRolloverError::post_journal)?;
                vm.resume(pause)
                    .map_err(RootDiskRolloverError::post_journal)?;
                result.pause_us = paused_at.elapsed().as_micros() as u64;
            } else {
                drop(backend);
            }
        }
        retired.cleanup();
        result.total_us = started.elapsed().as_micros() as u64;
        Ok(result)
    }

    /// Seal the current head, publish its closure, and switch the paused device to a fresh head.
    #[cfg(feature = "runner")]
    pub(crate) fn rollover(
        &mut self,
        vm: &msb_krun::VmControl,
        runtime: &tokio::runtime::Handle,
        checkpoint_root: &Path,
        pause_generation: u64,
        local: bool,
        record_integrity: bool,
    ) -> Result<RootDiskRollover, RootDiskRolloverError> {
        let device_state = vm
            .capture_block_device_state(&self.state.device_id)
            .map_err(RootDiskRolloverError::pre_rebind)?;
        if device_state.pause_generation != pause_generation {
            return Err(RootDiskRolloverError::pre_rebind(
                "root block state belongs to another pause generation",
            ));
        }
        let virtual_size = device_state
            .device
            .capacity_sectors
            .checked_mul(512)
            .ok_or_else(|| RootDiskRolloverError::pre_rebind("root disk size overflows bytes"))?;
        let encoded_state = device_state
            .encode()
            .map_err(RootDiskRolloverError::pre_rebind)?;

        // Hash only a tentative generation: preparation may fail and resume this same writable
        // head. Its captured root becomes reusable only after the forward journal commits.
        let mut next_state = self.state.sealed_generation(record_integrity)?;
        let published_integrities = if local {
            publish_local_layer_closure(checkpoint_root, &next_state.layers)
        } else {
            publish_layer_closure(checkpoint_root, &next_state.layers)
        }
        .map_err(RootDiskRolloverError::pre_rebind)?;

        let generation = self
            .state
            .published_generation
            .checked_add(1)
            .ok_or_else(|| RootDiskRolloverError::pre_rebind("disk generation is exhausted"))?;
        let capacities = microsandbox_image::checkpoint::layer_capacities(
            self.state
                .layers
                .iter()
                .map(|layer| microsandbox_image::checkpoint::CompactLayer {
                    path: layer.path.clone(),
                    qcow2: layer.format == RootDiskFormat::Qcow2,
                })
                .collect(),
        )
        .map_err(RootDiskRolloverError::pre_rebind)?;
        let sealed_layers = self
            .state
            .layers
            .iter()
            .enumerate()
            .map(|(index, layer)| {
                Ok(DiskLayerRef {
                    layer_id: layer.layer_id.clone(),
                    format: layer.format.as_str().into(),
                    virtual_size: capacities[index],
                    file_size: std::fs::metadata(checkpoint_root.join("layers").join(format!(
                        "{}.{}",
                        layer.layer_id,
                        layer.format.as_str()
                    )))
                    .map_err(RootDiskRolloverError::pre_rebind)?
                    .len(),
                    predecessor: index
                        .checked_sub(1)
                        .map(|previous| self.state.layers[previous].layer_id.clone()),
                    integrity_root: published_integrities[index].clone(),
                })
            })
            .collect::<Result<Vec<_>, RootDiskRolloverError>>()?;
        let manifest = DiskGenerationManifest {
            schema: "microsandbox.disk-generation/1".into(),
            volume_id: self.state.volume_id.clone(),
            device_id: self.state.device_id.clone(),
            generation,
            head: sealed_layers
                .last()
                .expect("managed root chain is non-empty")
                .layer_id
                .clone(),
            layers: sealed_layers,
            pause_generation,
        };
        manifest
            .validate()
            .map_err(RootDiskRolloverError::pre_rebind)?;

        let previous_head = self
            .state
            .layers
            .last()
            .expect("managed root chain is non-empty");
        let new_path = next_overlay_path(&previous_head.path, self.state.layout);
        runtime
            .block_on(microsandbox_image::checkpoint::create_qcow2_overlay(
                &new_path,
                virtual_size,
                &previous_head.path,
                previous_head.format.as_str(),
            ))
            .map_err(RootDiskRolloverError::pre_rebind)?;

        next_state.published_generation = generation;
        next_state.layers.push(RootDiskLayer {
            layer_id: new_id("layer"),
            path: new_path,
            format: RootDiskFormat::Qcow2,
            integrity_root: None,
        });
        let backend = prepare_backend(&next_state).map_err(RootDiskRolloverError::pre_rebind)?;

        // This durable forward record is written before touching the running backend. Once it
        // exists, process restart always opens the new head whether the following rebind completed
        // or returned an uncertain error.
        write_state_with_sync(&self.state_path, &next_state, sync_directory)?;
        self.state = next_state;
        vm.replace_block_backend(&self.state.device_id, backend)
            .map_err(RootDiskRolloverError::post_journal)?;

        Ok(RootDiskRollover {
            manifest,
            device_state: encoded_state,
        })
    }
}

impl RootDiskCompaction {
    pub(super) fn is_noop(&self) -> bool {
        self.next.is_none()
    }

    pub(super) fn validate_stopped(&self, runtime: &tokio::runtime::Handle) -> Result<(), String> {
        if let Some(next) = &self.next {
            let layers = next
                .layers
                .iter()
                .map(|layer| CompactLayer {
                    path: layer.path.clone(),
                    qcow2: layer.format == RootDiskFormat::Qcow2,
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
    /// The changing suffix is opened only while the VM is quiesced (or fully stopped).
    #[cfg(feature = "runner")]
    pub(super) fn prepare_backend(&self) -> Result<Option<msb_krun::PreparedBlockBackend>, String> {
        self.next.as_ref().map(prepare_backend).transpose()
    }

    pub(super) fn commit(
        self,
        disk: &mut RuntimeOwnedRootDisk,
    ) -> Result<RetiredRootDisk, RootDiskRolloverError> {
        let parent = disk
            .state_path
            .parent()
            .expect("root journal has parent")
            .to_path_buf();
        let Some(next) = self.next else {
            return Ok(RetiredRootDisk {
                parent,
                paths: Vec::new(),
            });
        };
        // Preserve the existing commit ordering and schema. A directory-sync failure can
        // follow a successful rename, so neither closure may be removed on uncertainty.
        let _published = self.stage.expect("prepared root state owns staging").keep();
        write_state(&disk.state_path, &next).map_err(RootDiskRolloverError::post_journal)?;
        let old = std::mem::replace(&mut disk.state, next);
        Ok(RetiredRootDisk {
            parent,
            paths: old.layers.into_iter().map(|layer| layer.path).collect(),
        })
    }
}

impl RetiredRootDisk {
    pub(super) fn cleanup(self) {
        // Same ownership boundary as before: only this root journal's directory entries.
        // Snapshots and children retain their own hardlinks; unlink errors merely retain data.
        for path in self.paths {
            if path.starts_with(&self.parent) {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

impl RootDiskState {
    #[cfg(feature = "runner")]
    fn sealed_generation(&self, record_integrity: bool) -> Result<Self, RootDiskRolloverError> {
        let mut next = self.clone();
        for layer in &mut next.layers {
            if record_integrity && layer.integrity_root.is_none() {
                layer.integrity_root = Some(
                    sparse_file_integrity(&layer.path)
                        .map_err(RootDiskRolloverError::pre_rebind)?
                        .root,
                );
            }
        }
        Ok(next)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != ROOT_DISK_STATE_SCHEMA
            || !valid_id(&self.volume_id, "vol")
            || self.device_id != self.layout.device_id()
            || self.layers.is_empty()
            || self.layers.len() > 256
            || self
                .growth_target
                .is_some_and(|target| target == 0 || !target.is_multiple_of(4096))
        {
            return Err("runtime-owned root-disk state has invalid identity or bounds".into());
        }
        let mut paths = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for (index, layer) in self.layers.iter().enumerate() {
            if !valid_id(&layer.layer_id, "layer")
                || layer.path.as_os_str().is_empty()
                || !paths.insert(layer.path.clone())
                || !ids.insert(layer.layer_id.clone())
                || (index > 0 && layer.format != RootDiskFormat::Qcow2)
            {
                return Err(format!("runtime-owned root-disk layer {index} is invalid"));
            }
        }
        Ok(())
    }

    #[cfg(feature = "runner")]
    fn disk_spec(&self) -> UpperSpec {
        UpperSpec {
            layers: self
                .layers
                .iter()
                .map(|layer| UpperLayerSpec {
                    path: layer.path.clone(),
                    format: layer.format.into(),
                })
                .collect(),
            read_only: false,
        }
    }
}

impl RootDiskLayout {
    fn device_id(self) -> &'static str {
        match self {
            Self::ManagedUpper => MANAGED_ROOT_DEVICE_ID,
            Self::FlatRoot => FLAT_ROOT_DEVICE_ID,
        }
    }
}

impl RootDiskFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Qcow2 => "qcow2",
        }
    }
}

#[cfg(feature = "runner")]
impl TryFrom<msb_krun::DiskImageFormat> for RootDiskFormat {
    type Error = String;

    fn try_from(value: msb_krun::DiskImageFormat) -> Result<Self, Self::Error> {
        match value {
            msb_krun::DiskImageFormat::Raw => Ok(Self::Raw),
            msb_krun::DiskImageFormat::Qcow2 => Ok(Self::Qcow2),
            msb_krun::DiskImageFormat::Vmdk => {
                Err("runtime-owned root chains do not support VMDK layers".into())
            }
        }
    }
}

#[cfg(feature = "runner")]
impl From<RootDiskFormat> for msb_krun::DiskImageFormat {
    fn from(value: RootDiskFormat) -> Self {
        match value {
            RootDiskFormat::Raw => Self::Raw,
            RootDiskFormat::Qcow2 => Self::Qcow2,
        }
    }
}

#[cfg(feature = "runner")]
impl From<RootDiskFormat> for msb_krun::BlockImageFormat {
    fn from(value: RootDiskFormat) -> Self {
        match value {
            RootDiskFormat::Raw => Self::Raw,
            RootDiskFormat::Qcow2 => Self::Qcow2,
        }
    }
}

impl RootDiskRolloverError {
    pub(super) fn pre_rebind(error: impl fmt::Display) -> Self {
        Self {
            message: error.to_string(),
            #[cfg(feature = "runner")]
            keep_paused: false,
        }
    }

    pub(crate) fn post_journal(error: impl fmt::Display) -> Self {
        Self {
            message: error.to_string(),
            #[cfg(feature = "runner")]
            keep_paused: true,
        }
    }
}

impl fmt::Display for RootDiskRolloverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(formatter)
    }
}

impl std::error::Error for RootDiskRolloverError {}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Seed a new child's journal from disk admission already completed in this runtime process.
/// The existing journal remains authoritative. Transformed or copied files start without a
/// cached root rather than inheriting an identity belonging to their source representation.
#[cfg(feature = "runner")]
pub(crate) fn seed_restored_root_disk(
    runtime_dir: &Path,
    vm: &VmConfig,
    admitted: &CheckpointClosure,
) -> Result<(), String> {
    let reuse = |path: &Path| {
        admitted
            .reused_disk_integrity(path)
            .map_err(|e| e.to_string())
    };
    RuntimeOwnedRootDisk::open_with_admitted(runtime_dir, vm, Some(&reuse))?;
    Ok(())
}

/// Local receipts bind roots to the exact immutable files owned by this child's handoff.
#[cfg(feature = "runner")]
pub(super) fn seed_local_root_disk(
    runtime_dir: &Path,
    vm: &VmConfig,
    admitted: &super::local_disk::LocalDiskAdmissions,
) -> Result<(), String> {
    let reuse = |path: &Path| admitted.reuse_for(path);
    RuntimeOwnedRootDisk::open_with_admitted(runtime_dir, vm, Some(&reuse))?;
    Ok(())
}

/// Apply the durable forward chain before VM construction after a runtime restart.
#[cfg(feature = "runner")]
pub(crate) fn recover_runtime_owned_root(
    runtime_dir: &Path,
    vm: &mut VmConfig,
) -> Result<(), String> {
    let state_path = runtime_dir.join(ROOT_DISK_STATE_FILE);
    if !state_path.exists() {
        return Ok(());
    }
    let state = read_state(&state_path)?;
    if configured_layout(vm) != Some(state.layout) {
        return Err("root-disk journal does not match the configured root layout".into());
    }
    let configured = configured_layers(vm, state.layout)?;
    let configured_base = configured.first().map(|layer| &layer.path);
    let journal_base = state
        .launch_base
        .as_ref()
        .or_else(|| state.layers.first().map(|layer| &layer.path));
    if configured_base != journal_base {
        return Err("root-disk journal does not match the configured base layer".into());
    }
    match state.layout {
        RootDiskLayout::ManagedUpper => {
            vm.rootfs_upper = None;
            vm.rootfs_upper_spec = Some(state.disk_spec());
        }
        RootDiskLayout::FlatRoot => {
            vm.rootfs_disk = None;
            vm.rootfs_disk_format = None;
            vm.rootfs_disk_spec = Some(state.disk_spec());
        }
    }
    Ok(())
}

/// Read the authoritative root-disk chain after the caller has proven the sandbox stopped.
///
/// `None` means no rollover journal exists yet. Read the head's declared capacity, not the
/// container size or an older base's capacity: compaction and grow can change both assumptions.
pub fn load_runtime_owned_root_chain(
    runtime_dir: &Path,
) -> Result<Option<RuntimeOwnedRootChain>, String> {
    let state_path = runtime_dir.join(ROOT_DISK_STATE_FILE);
    if !state_path.exists() {
        return Ok(None);
    }
    let state = read_state(&state_path)?;
    if state.growth_target.is_some() {
        return Err("complete pending root-disk growth before snapshotting".into());
    }
    let head = state
        .layers
        .last()
        .expect("validated runtime root chain is non-empty");
    // This sync projection can be called inside an async SDK. A dedicated thread owns its tiny
    // runtime so nested block_on cannot panic and no implicit backing dependency is opened.
    let layer = CompactLayer {
        path: head.path.clone(),
        qcow2: head.format == RootDiskFormat::Qcow2,
    };
    let virtual_size = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(compact_layer_capacity(layer))
    })
    .join()
    .map_err(|_| "disk capacity reader panicked".to_string())?
    .map_err(|error| format!("read runtime-owned root capacity: {error}"))?;
    if virtual_size == 0 {
        return Err("runtime-owned root base has zero capacity".into());
    }
    Ok(Some(RuntimeOwnedRootChain {
        device_id: state.device_id,
        virtual_size,
        layers: state
            .layers
            .into_iter()
            .map(|layer| RuntimeOwnedRootLayer {
                path: layer.path,
                format: layer.format.as_str().into(),
            })
            .collect(),
    }))
}

/// Grow a stopped journal-backed root using a private staging head. Returns false without a journal.
/// The caller must hold the sandbox lifecycle lock and prove all VM writers have stopped.
pub fn grow_stopped_root(runtime_dir: &Path, target: u64) -> Result<bool, String> {
    let state_path = runtime_dir.join(ROOT_DISK_STATE_FILE);
    if !state_path.exists() {
        return Ok(false);
    }
    let state = read_state(&state_path)?;
    if state.growth_target.is_some_and(|pending| pending != target) {
        return Err(format!(
            "complete pending root-disk growth to {} bytes first",
            state.growth_target.unwrap()
        ));
    }
    let capacities = microsandbox_image::checkpoint::layer_capacities(
        state
            .layers
            .iter()
            .map(|layer| CompactLayer {
                path: layer.path.clone(),
                qcow2: layer.format == RootDiskFormat::Qcow2,
            })
            .collect(),
    )
    .map_err(|e| e.to_string())?;
    let current = *capacities.last().expect("validated nonempty chain");
    if target < current && state.growth_target.is_none() {
        return Ok(true);
    }
    if target == current && state.growth_target.is_none() {
        return Ok(true);
    }
    if capacities.iter().any(|size| *size > current) {
        return Err("cannot grow a chain with a backing layer larger than its head".into());
    }
    let stage = tempfile::Builder::new()
        .prefix(".grow-")
        .tempdir_in(runtime_dir)
        .map_err(|e| e.to_string())?;
    let mut next = state.clone();
    if next.launch_base.is_none() {
        next.launch_base = state.layers.first().map(|layer| layer.path.clone());
    }
    let last = state.layers.len() - 1;
    for (index, layer) in next.layers.iter_mut().enumerate() {
        let path = stage
            .path()
            .join(layer.path.file_name().ok_or("invalid root layer name")?);
        if index == last {
            microsandbox_utils::copy::fast_copy(&layer.path, &path).map_err(|e| e.to_string())?;
            layer.layer_id = new_id("layer");
            layer.integrity_root = None;
        } else {
            // Preserve qcow2's relative backing bindings for independent inspection as well as
            // the runtime's explicit closure. Ancestor inodes are never opened writable.
            std::fs::hard_link(&layer.path, &path).map_err(|e| e.to_string())?;
        }
        layer.path = path;
    }
    let closure = next
        .layers
        .iter()
        .map(|layer| CompactLayer {
            path: layer.path.clone(),
            qcow2: layer.format == RootDiskFormat::Qcow2,
        })
        .collect::<Vec<_>>();
    microsandbox_image::ext4::grow_chain(&closure, target).map_err(|e| e.to_string())?;
    next.growth_target = None;
    sync_directory(stage.path()).map_err(|e| e.to_string())?;
    // Preserve staging across an uncertain journal rename/fsync. Recovery can then follow
    // whichever durable journal won, without ever opening a partially rewritten filesystem.
    let _published = stage.keep();
    write_state(&state_path, &next)?;
    Ok(true)
}

/// Finish a previously recorded online growth before cold boot, under the stopped lifecycle lock.
pub fn recover_stopped_root_growth(runtime_dir: &Path) -> Result<(), String> {
    let path = runtime_dir.join(ROOT_DISK_STATE_FILE);
    if path.exists()
        && let Some(target) = read_state(&path)?.growth_target
    {
        grow_stopped_root(runtime_dir, target)?;
    }
    Ok(())
}

/// Compact a stopped runtime-owned root after the caller acquires the sandbox lifecycle lock.
/// The caller must prove no live process can write this disk until the operation finishes.
pub fn compact_stopped_root(
    runtime_dir: &Path,
    layers: Option<usize>,
    dry_run: bool,
) -> Result<DiskCompactionResult, String> {
    let state_path = runtime_dir.join(ROOT_DISK_STATE_FILE);
    if !state_path.exists() {
        let plan = DiskCompactionPlan::new(1, layers).map_err(|error| error.to_string())?;
        return Ok(DiskCompactionResult {
            dry_run,
            input_layers: 1,
            output_layers: plan.output_layers(),
            ..Default::default()
        });
    }
    let mut disk = RuntimeOwnedRootDisk {
        state: read_state(&state_path)?,
        state_path,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    disk.compact(
        #[cfg(feature = "runner")]
        None,
        runtime.handle(),
        layers,
        dry_run,
    )
    .map_err(|error| error.to_string())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "runner")]
fn configured_layout(vm: &VmConfig) -> Option<RootDiskLayout> {
    if vm.rootfs_vmdk.is_some() {
        Some(RootDiskLayout::ManagedUpper)
    } else if vm.rootfs_disk_runtime_owned {
        Some(RootDiskLayout::FlatRoot)
    } else {
        None
    }
}

#[cfg(feature = "runner")]
fn configured_layers(vm: &VmConfig, layout: RootDiskLayout) -> Result<Vec<UpperLayerSpec>, String> {
    let (spec, path, format) = match layout {
        RootDiskLayout::ManagedUpper => (
            vm.rootfs_upper_spec.as_ref(),
            vm.rootfs_upper.as_ref(),
            msb_krun::DiskImageFormat::Raw,
        ),
        RootDiskLayout::FlatRoot => (
            vm.rootfs_disk_spec.as_ref(),
            vm.rootfs_disk.as_ref(),
            crate::vm::validate_disk_format(vm.rootfs_disk_format.as_deref())
                .map_err(|error| error.to_string())?,
        ),
    };
    if let Some(spec) = spec {
        return Ok(spec.layers.clone());
    }
    Ok(path
        .map(|path| {
            vec![UpperLayerSpec {
                path: path.clone(),
                format,
            }]
        })
        .unwrap_or_default())
}

/// SDK restore materialization names compacted bases differently from ordinary launch bindings.
/// Preserve the latter in the existing journal field: later starts intentionally discard the
/// transient restore chain and let this journal select the actual files. Arbitrary explicit
/// chains retain their original base identity; a matching basename outside this child is not
/// sufficient to opt into the SDK's managed-root naming contract.
#[cfg(feature = "runner")]
fn restored_launch_base(
    runtime_dir: &Path,
    layout: RootDiskLayout,
    layers: &[UpperLayerSpec],
) -> Option<PathBuf> {
    let base = layers.first()?;
    if !matches!(base.format, msb_krun::DiskImageFormat::Qcow2) {
        return None;
    }
    let sandbox = runtime_dir.parent()?;
    let (restored, ordinary) = match layout {
        RootDiskLayout::ManagedUpper => ("upper-sealed-000.qcow2", "upper.ext4"),
        RootDiskLayout::FlatRoot => ("root-sealed-000.qcow2", "rootfs.raw"),
    };
    (base.path == sandbox.join(restored)).then(|| sandbox.join(ordinary))
}

#[cfg(feature = "runner")]
fn prepare_backend(state: &RootDiskState) -> Result<msb_krun::PreparedBlockBackend, String> {
    // Linux raw uppers use bounded buffered writeback. Their qcow2 successors must bypass the
    // page cache because raw guest offsets cannot account for qcow2 metadata and allocation I/O.
    let direct_io = cfg!(target_os = "linux")
        && matches!(
            state.layers.last().map(|layer| layer.format),
            Some(RootDiskFormat::Qcow2)
        );
    let layers = state
        .layers
        .iter()
        .map(|layer| msb_krun::BlockLayerSpec::new(&layer.path, layer.format.into()))
        .collect();
    let backend = msb_krun::BlockBackendSpec::new(layers).direct_io(direct_io);
    msb_krun::PreparedBlockBackend::open(&backend)
        .map_err(|error| format!("prepare runtime-owned root backend: {error}"))
}

#[cfg(feature = "runner")]
fn publish_local_layer_closure(
    root: &Path,
    layers: &[RootDiskLayer],
) -> Result<Vec<Option<String>>, String> {
    use super::local_disk::{LocalDiskAdmissions, link_exact};

    let directory = root.join("layers");
    std::fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    let targets = layers
        .iter()
        .map(|layer| directory.join(format!("{}.{}", layer.layer_id, layer.format.as_str())))
        .collect::<Vec<_>>();
    let mut receipts: Vec<(PathBuf, Option<String>)> = Vec::with_capacity(layers.len());
    for (index, layer) in layers.iter().enumerate() {
        let target = &targets[index];
        let mut integrity = layer.integrity_root.clone();
        if index == 0 {
            link_exact(&layer.path, target).map_err(|e| e.to_string())?;
        } else {
            // Keep original header basenames and bind them to child-owned predecessor files.
            // Never let a basename reserve another canonical layer's identity accidentally.
            let previous = &receipts[index - 1].0;
            let linked = qcow_backing_basename(&layer.path).and_then(|name| {
                let alias = directory.join(name);
                if targets.contains(&alias) && alias != *previous {
                    return Err(std::io::Error::other(
                        "backing alias conflicts with a layer name",
                    ));
                }
                link_exact(previous, &alias)?;
                link_exact(&layer.path, target)
            });
            if linked.is_err() {
                // Imported/older chains may contain nonportable names or alias collisions.
                // Relocate just that physical layer, never a linked source inode. This is the
                // existing conversion path, not permission to change a captured predecessor.
                let staging = tempfile::tempdir_in(&directory).map_err(|e| e.to_string())?;
                let staged = staging.path().join("layer.qcow2");
                microsandbox_utils::copy::fast_copy(&layer.path, &staged)
                    .map_err(|e| e.to_string())?;
                microsandbox_image::checkpoint::relocate_qcow2_backing(&staged, previous)
                    .map_err(|e| e.to_string())?;
                if integrity.is_some() {
                    integrity = Some(
                        sparse_file_integrity(&staged)
                            .map_err(|e| e.to_string())?
                            .root,
                    );
                }
                link_exact(&staged, target).map_err(|e| e.to_string())?;
            }
        }
        receipts.push((target.clone(), integrity));
    }
    LocalDiskAdmissions::publish(root, &receipts).map_err(|e| e.to_string())?;
    Ok(receipts.into_iter().map(|(_, root)| root).collect())
}

#[cfg(feature = "runner")]
fn publish_layer_closure(
    root: &Path,
    layers: &[RootDiskLayer],
) -> Result<Vec<Option<String>>, String> {
    let directory = root.join("layers");
    std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let mut integrities = Vec::with_capacity(layers.len());
    for (index, layer) in layers.iter().enumerate() {
        let target = directory.join(format!("{}.{}", layer.layer_id, layer.format.as_str()));
        if index > 0 && matches!(layer.format, RootDiskFormat::Qcow2) {
            // Published names differ from the active journal. Reflink/copy before rewriting:
            // the running VM and earlier checkpoints may still reference the source inode.
            let staging = tempfile::tempdir_in(&directory).map_err(|error| error.to_string())?;
            let staged = staging.path().join("layer.qcow2");
            microsandbox_utils::copy::fast_copy(&layer.path, &staged)
                .map_err(|error| error.to_string())?;
            let previous = &layers[index - 1];
            let backing = directory.join(format!(
                "{}.{}",
                previous.layer_id,
                previous.format.as_str()
            ));
            microsandbox_image::checkpoint::relocate_qcow2_backing(&staged, &backing)
                .map_err(|error| error.to_string())?;
            let expected = layer
                .integrity_root
                .as_ref()
                .map(|_| {
                    sparse_file_integrity(&staged)
                        .map(|integrity| integrity.root)
                        .map_err(|error| error.to_string())
                })
                .transpose()?;
            publish_sealed_layer(&staged, &target, expected.as_deref())?;
            integrities.push(expected);
        } else {
            let expected = layer.integrity_root.clone();
            publish_sealed_layer(&layer.path, &target, expected.as_deref())?;
            integrities.push(expected);
        }
    }
    sync_directory(&directory).map_err(|error| error.to_string())?;
    Ok(integrities)
}

#[cfg(feature = "runner")]
fn publish_sealed_layer(
    source: &Path,
    target: &Path,
    expected: Option<&str>,
) -> Result<(), String> {
    // Without a recorded digest, only the exact owned inode can satisfy an existing target.
    // Same length, names or disk geometry are not evidence that two files are interchangeable.
    if expected.is_none() {
        return super::local_disk::link_exact(source, target).map_err(|error| error.to_string());
    }
    match std::fs::hard_link(source, target) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let actual = sparse_file_integrity(target).map_err(|error| error.to_string())?;
            if Some(actual.root.as_str()) == expected {
                Ok(())
            } else {
                Err(format!("checkpoint layer {} conflicts", target.display()))
            }
        }
        Err(error) => Err(error.to_string()),
    }
}

fn read_state(path: &Path) -> Result<RootDiskState, String> {
    let metadata = path.metadata().map_err(|error| error.to_string())?;
    if metadata.len() > MAX_ROOT_DISK_STATE_BYTES {
        return Err("runtime-owned root-disk state exceeds its size bound".into());
    }
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let state: RootDiskState = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse root-disk state: {error}"))?;
    state.validate()?;
    Ok(state)
}

fn write_state(path: &Path, state: &RootDiskState) -> Result<(), String> {
    write_state_with_sync(path, state, sync_directory).map_err(|error| error.to_string())
}

fn write_state_with_sync(
    path: &Path,
    state: &RootDiskState,
    sync_parent: impl FnOnce(&Path) -> std::io::Result<()>,
) -> Result<(), RootDiskRolloverError> {
    state
        .validate()
        .map_err(RootDiskRolloverError::pre_rebind)?;
    let parent = path
        .parent()
        .ok_or_else(|| RootDiskRolloverError::pre_rebind("root-disk state path has no parent"))?;
    std::fs::create_dir_all(parent).map_err(RootDiskRolloverError::pre_rebind)?;
    let temporary = parent.join(format!(
        ".{ROOT_DISK_STATE_FILE}.{}.tmp",
        rand::random::<u64>()
    ));
    let bytes = serde_json::to_vec(state).map_err(RootDiskRolloverError::pre_rebind)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(RootDiskRolloverError::pre_rebind)?;
    file.write_all(&bytes)
        .map_err(RootDiskRolloverError::pre_rebind)?;
    file.sync_all().map_err(RootDiskRolloverError::pre_rebind)?;
    drop(file);
    if let Err(error) = super::replace_file(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        // Treat replacement failures conservatively across platforms: the visible journal may
        // already have changed even when the platform reports uncertain durable completion.
        return Err(RootDiskRolloverError::post_journal(error));
    }
    sync_parent(parent).map_err(RootDiskRolloverError::post_journal)
}

#[cfg(feature = "runner")]
fn next_overlay_path(previous: &Path, layout: RootDiskLayout) -> PathBuf {
    let parent = previous.parent().unwrap_or_else(|| Path::new("."));
    let prefix = match layout {
        RootDiskLayout::ManagedUpper => "upper",
        RootDiskLayout::FlatRoot => "root",
    };
    parent.join(format!("{prefix}-{}.qcow2", &new_id("head")[5..]))
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

fn sync_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[cfg(feature = "runner")]
    #[tokio::test]
    async fn local_publication_preserves_headers_aliases_and_exact_admission() {
        use super::*;
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        std::fs::create_dir(&source).unwrap();
        let base = source.join("upper.ext4");
        std::fs::write(&base, vec![41; 131072]).unwrap();
        let overlay = source.join("upper-original.qcow2");
        microsandbox_image::checkpoint::create_qcow2_overlay(&overlay, 131072, &base, "raw")
            .await
            .unwrap();
        let original = std::fs::read(&overlay).unwrap();
        let input = vec![
            RootDiskLayer {
                layer_id: new_id("layer"),
                path: base.clone(),
                format: RootDiskFormat::Raw,
                integrity_root: Some(sparse_file_integrity(&base).unwrap().root),
            },
            RootDiskLayer {
                layer_id: new_id("layer"),
                path: overlay.clone(),
                format: RootDiskFormat::Qcow2,
                integrity_root: Some(sparse_file_integrity(&overlay).unwrap().root),
            },
        ];
        let child = dir.path().join("child");
        let roots = publish_local_layer_closure(&child, &input).unwrap();
        let base_target = child
            .join("layers")
            .join(format!("{}.raw", input[0].layer_id));
        let overlay_target = child
            .join("layers")
            .join(format!("{}.qcow2", input[1].layer_id));
        assert_eq!(roots[0], input[0].integrity_root.clone());
        assert_eq!(roots[1], input[1].integrity_root.clone());
        assert_eq!(std::fs::read(&overlay_target).unwrap(), original);
        assert_eq!(
            qcow_backing_basename(&overlay_target).unwrap(),
            "upper.ext4"
        );
        let manifest = DiskGenerationManifest {
            schema: "microsandbox.disk-generation/1".into(),
            volume_id: new_id("vol"),
            device_id: "vdb".into(),
            generation: 1,
            pause_generation: 9,
            head: input[1].layer_id.clone(),
            layers: input
                .iter()
                .enumerate()
                .map(|(i, layer)| DiskLayerRef {
                    file_size: std::fs::metadata(&layer.path).unwrap().len(),
                    layer_id: layer.layer_id.clone(),
                    format: layer.format.as_str().into(),
                    virtual_size: 131072,
                    predecessor: i.checked_sub(1).map(|p| input[p].layer_id.clone()),
                    integrity_root: roots[i].clone(),
                })
                .collect(),
        };
        let admitted = super::super::local_disk::LocalDiskAdmissions::open(&child, &[manifest])
            .unwrap()
            .unwrap();
        assert_eq!(admitted.reuse_for(&base_target).unwrap(), roots[0].clone());
        // A grandchild uses canonical source paths while old qcow headers still name aliases.
        let grandchild = dir.path().join("grandchild");
        let mut child_input = input.clone();
        child_input[0].path = base_target;
        child_input[1].path = overlay_target;
        assert_eq!(
            publish_local_layer_closure(&grandchild, &child_input).unwrap(),
            roots
        );
        std::fs::remove_dir_all(source).unwrap();
        std::fs::remove_dir_all(child).unwrap();
        assert_eq!(
            std::fs::read(grandchild.join("layers/upper.ext4")).unwrap(),
            vec![41; 131072]
        );
    }

    #[cfg(feature = "runner")]
    #[tokio::test]
    async fn local_publication_relocates_only_a_nonportable_backing_name() {
        use super::*;
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base.raw");
        let overlay = dir.path().join("head.qcow2");
        std::fs::write(&base, vec![11; 131072]).unwrap();
        microsandbox_image::checkpoint::create_qcow2_overlay(&overlay, 131072, &base, "raw")
            .await
            .unwrap();
        let mut original = std::fs::read(&overlay).unwrap();
        let offset = u64::from_be_bytes(original[8..16].try_into().unwrap()) as usize;
        let old_name = b"/older/location/base.raw";
        original[offset..offset + old_name.len()].copy_from_slice(old_name);
        original[16..20].copy_from_slice(&(old_name.len() as u32).to_be_bytes());
        std::fs::write(&overlay, &original).unwrap();
        let input = vec![
            RootDiskLayer {
                layer_id: new_id("layer"),
                path: base.clone(),
                format: RootDiskFormat::Raw,
                integrity_root: Some(sparse_file_integrity(&base).unwrap().root),
            },
            RootDiskLayer {
                layer_id: new_id("layer"),
                path: overlay.clone(),
                format: RootDiskFormat::Qcow2,
                integrity_root: Some(sparse_file_integrity(&overlay).unwrap().root),
            },
        ];
        let destination = dir.path().join("child");
        let roots = publish_local_layer_closure(&destination, &input).unwrap();
        let output = destination
            .join("layers")
            .join(format!("{}.qcow2", input[1].layer_id));
        assert_eq!(std::fs::read(overlay).unwrap(), original);
        assert_eq!(
            qcow_backing_basename(&output).unwrap(),
            format!("{}.raw", input[0].layer_id)
        );
        assert_ne!(roots[1], input[1].integrity_root.clone());
        assert_eq!(roots[1], Some(sparse_file_integrity(&output).unwrap().root));
    }

    #[cfg(feature = "runner")]
    #[tokio::test]
    async fn local_admission_seeds_a_recoverable_cold_boot_chain() {
        use super::*;
        for layout in [RootDiskLayout::ManagedUpper, RootDiskLayout::FlatRoot] {
            let dir = tempfile::tempdir().unwrap();
            let sandbox = dir.path().join("child");
            std::fs::create_dir(&sandbox).unwrap();
            let base = sandbox.join(if layout == RootDiskLayout::ManagedUpper {
                "upper.ext4"
            } else {
                "rootfs.raw"
            });
            std::fs::write(&base, vec![17; 131072]).unwrap();
            let closure = sandbox.join(".branch-restore");
            let layer_id = new_id("layer");
            let integrity = sparse_file_integrity(&base).unwrap().root;
            let input = vec![RootDiskLayer {
                layer_id: layer_id.clone(),
                path: base.clone(),
                format: RootDiskFormat::Raw,
                integrity_root: Some(integrity.clone()),
            }];
            publish_local_layer_closure(&closure, &input).unwrap();
            let manifest = DiskGenerationManifest {
                schema: "microsandbox.disk-generation/1".into(),
                volume_id: new_id("vol"),
                device_id: layout.device_id().into(),
                generation: 1,
                layers: vec![DiskLayerRef {
                    file_size: std::fs::metadata(&base).unwrap().len(),
                    layer_id: layer_id.clone(),
                    format: "raw".into(),
                    virtual_size: 131072,
                    predecessor: None,
                    integrity_root: Some(integrity.clone()),
                }],
                head: layer_id.clone(),
                pause_generation: 1,
            };
            let admitted =
                super::super::local_disk::LocalDiskAdmissions::open(&closure, &[manifest])
                    .unwrap()
                    .unwrap();
            let head = closure.join("layers/private.qcow2");
            microsandbox_image::checkpoint::create_qcow2_overlay(
                &head,
                131072,
                &closure.join("layers").join(format!("{layer_id}.raw")),
                "raw",
            )
            .await
            .unwrap();
            let runtime = sandbox.join("runtime");
            let vm = root_vm(
                layout,
                vec![
                    UpperLayerSpec {
                        path: base.clone(),
                        format: msb_krun::DiskImageFormat::Raw,
                    },
                    UpperLayerSpec {
                        path: head.clone(),
                        format: msb_krun::DiskImageFormat::Qcow2,
                    },
                ],
            );
            seed_local_root_disk(&runtime, &vm, &admitted).unwrap();
            assert_eq!(
                read_state(&runtime.join(ROOT_DISK_STATE_FILE))
                    .unwrap()
                    .layers[0]
                    .integrity_root
                    .as_ref(),
                Some(&integrity)
            );
            drop(admitted);
            std::fs::remove_file(closure.join("local-disk-admission.json")).unwrap();
            let mut cold = root_vm(
                layout,
                vec![UpperLayerSpec {
                    path: base,
                    format: msb_krun::DiskImageFormat::Raw,
                }],
            );
            recover_runtime_owned_root(&runtime, &mut cold).unwrap();
            assert_eq!(
                configured_layers(&cold, layout)
                    .unwrap()
                    .last()
                    .unwrap()
                    .path,
                head
            );
            assert!(load_runtime_owned_root_chain(&runtime).unwrap().is_some());
        }
    }

    #[cfg(feature = "runner")]
    #[tokio::test]
    async fn failed_preparation_does_not_retain_a_writable_head_integrity() {
        use std::io::{Seek, SeekFrom};

        use super::*;

        for qcow2 in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let base = directory.path().join("base.raw");
            std::fs::write(&base, vec![17u8; 131072]).unwrap();
            let mut layers = vec![RootDiskLayer {
                layer_id: new_id("layer"),
                path: base.clone(),
                format: RootDiskFormat::Raw,
                integrity_root: None,
            }];
            if qcow2 {
                let head = directory.path().join("head.qcow2");
                microsandbox_image::checkpoint::create_qcow2_overlay(&head, 131072, &base, "raw")
                    .await
                    .unwrap();
                layers[0].integrity_root = Some(sparse_file_integrity(&base).unwrap().root);
                layers.push(RootDiskLayer {
                    layer_id: new_id("layer"),
                    path: head,
                    format: RootDiskFormat::Qcow2,
                    integrity_root: None,
                });
            }
            let state = RootDiskState {
                schema: ROOT_DISK_STATE_SCHEMA.into(),
                volume_id: new_id("vol"),
                device_id: FLAT_ROOT_DEVICE_ID.into(),
                layout: RootDiskLayout::FlatRoot,
                published_generation: 0,
                launch_base: None,
                growth_target: None,
                layers,
            };
            let tentative = state.sealed_generation(true).unwrap();
            let blocked = directory.path().join("blocked");
            std::fs::write(&blocked, b"not a directory").unwrap();
            assert!(publish_layer_closure(&blocked, &tentative.layers).is_err());
            assert!(state.layers.last().unwrap().integrity_root.is_none());

            // Model a resumed guest changing the same head before a retry. The abandoned cut
            // must not supply a reusable root to the next attempt, for raw or qcow2 heads.
            let head = &state.layers.last().unwrap().path;
            let mut writer = OpenOptions::new().write(true).open(head).unwrap();
            writer.seek(SeekFrom::End(0)).unwrap();
            writer.write_all(b"resumed write").unwrap();
            writer.sync_all().unwrap();
            drop(writer);
            let retry = state.sealed_generation(true).unwrap();
            assert_ne!(
                retry.layers.last().unwrap().integrity_root,
                tentative.layers.last().unwrap().integrity_root,
            );
            assert_eq!(
                retry
                    .layers
                    .last()
                    .unwrap()
                    .integrity_root
                    .as_ref()
                    .unwrap(),
                &sparse_file_integrity(head).unwrap().root,
            );
        }
    }

    #[cfg(feature = "runner")]
    #[test]
    fn sealing_integrity_is_opt_in_and_unhashed_journals_remain_valid() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("root.raw");
        std::fs::write(&path, [17; 4096]).unwrap();
        let state = RootDiskState {
            schema: ROOT_DISK_STATE_SCHEMA.into(),
            volume_id: new_id("vol"),
            device_id: "vdb".into(),
            layout: RootDiskLayout::ManagedUpper,
            published_generation: 0,
            launch_base: None,
            growth_target: None,
            layers: vec![RootDiskLayer {
                layer_id: new_id("layer"),
                path: path.clone(),
                format: RootDiskFormat::Raw,
                integrity_root: None,
            }],
        };
        let unhashed = state.sealed_generation(false).unwrap();
        assert!(unhashed.layers[0].integrity_root.is_none());
        let root = directory.path().join("handoff");
        assert_eq!(
            publish_local_layer_closure(&root, &unhashed.layers).unwrap(),
            vec![None]
        );
        let recorded = state.sealed_generation(true).unwrap();
        assert_eq!(
            recorded.layers[0].integrity_root,
            Some(sparse_file_integrity(&path).unwrap().root)
        );
        assert!(
            state.layers[0].integrity_root.is_none(),
            "tentative sealing must not cache a writable head's hash"
        );
        assert_eq!(
            recorded.sealed_generation(false).unwrap().layers[0].integrity_root,
            recorded.layers[0].integrity_root
        );
        let mut journal = unhashed;
        journal.layers.push(RootDiskLayer {
            layer_id: new_id("layer"),
            path: directory.path().join("head.qcow2"),
            format: RootDiskFormat::Qcow2,
            integrity_root: None,
        });
        journal.validate().unwrap();
    }

    #[cfg(feature = "runner")]
    #[tokio::test]
    async fn journal_sync_failure_is_fenced_after_forward_publication() {
        use super::*;

        let directory = tempfile::tempdir().unwrap();
        let base = directory.path().join("base.raw");
        std::fs::write(&base, vec![17u8; 4096]).unwrap();
        let mut state = RootDiskState {
            schema: ROOT_DISK_STATE_SCHEMA.into(),
            volume_id: new_id("vol"),
            device_id: FLAT_ROOT_DEVICE_ID.into(),
            layout: RootDiskLayout::FlatRoot,
            published_generation: 0,
            launch_base: None,
            growth_target: None,
            layers: vec![RootDiskLayer {
                layer_id: new_id("layer"),
                path: base.clone(),
                format: RootDiskFormat::Raw,
                integrity_root: None,
            }],
        };
        let path = directory.path().join(ROOT_DISK_STATE_FILE);
        write_state(&path, &state).unwrap();
        let successor = directory.path().join("successor.qcow2");
        microsandbox_image::checkpoint::create_qcow2_overlay(&successor, 4096, &base, "raw")
            .await
            .unwrap();
        state = state.sealed_generation(true).unwrap();
        state.layers.push(RootDiskLayer {
            layer_id: new_id("layer"),
            path: successor.clone(),
            format: RootDiskFormat::Qcow2,
            integrity_root: None,
        });
        state.published_generation = 1;
        let error = write_state_with_sync(&path, &state, |_| {
            Err(std::io::Error::other("injected directory sync failure"))
        })
        .unwrap_err();
        assert!(error.keep_paused);
        assert_eq!(read_state(&path).unwrap().published_generation, 1);
        let recovered = load_runtime_owned_root_chain(directory.path())
            .unwrap()
            .unwrap();
        assert_eq!(recovered.layers.len(), 2);
        assert_eq!(recovered.layers[1].path, successor);
        assert_eq!(recovered.virtual_size, 4096);

        let published = std::fs::read(&path).unwrap();
        state.schema = "invalid".into();
        let error = write_state_with_sync(&path, &state, |_| {
            panic!("invalid state must fail before journal publication")
        })
        .unwrap_err();
        assert!(!error.keep_paused);
        assert_eq!(std::fs::read(&path).unwrap(), published);
    }

    #[cfg(feature = "runner")]
    fn admitted_fixture(
        root: &std::path::Path,
        sources: &[super::UpperLayerSpec],
    ) -> microsandbox_image::checkpoint::CheckpointClosure {
        use microsandbox_image::checkpoint::{
            CaptureIntent, CheckpointClosure, CheckpointManifest, DiskGenerationManifest,
            DiskLayerRef, LocalObjectStore, MemoryCaptureMode, MemoryExtent, MemoryExtentContent,
            MemoryManifest, ObjectId, sparse_file_integrity,
        };

        let store = LocalObjectStore::open(root).unwrap();
        std::fs::create_dir(root.join("layers")).unwrap();
        let memory = MemoryManifest {
            schema: "microsandbox.memory/1".into(),
            architecture: std::env::consts::ARCH.into(),
            guest_page_size: 4096,
            topology_generation: 1,
            generation: 1,
            capture_mode: MemoryCaptureMode::Full,
            pause_generation: 7,
            extents: vec![MemoryExtent {
                start: 0,
                length: 4096,
                content: MemoryExtentContent::Zero,
            }],
        };
        let layers: Vec<_> = sources
            .iter()
            .enumerate()
            .map(|(index, source)| {
                let layer_id = format!("sealed_{index}");
                let format = match source.format {
                    msb_krun::DiskImageFormat::Raw => "raw",
                    msb_krun::DiskImageFormat::Qcow2 => "qcow2",
                    _ => panic!("unsupported fixture format"),
                };
                let target = root.join("layers").join(format!("{layer_id}.{format}"));
                std::fs::hard_link(&source.path, &target).unwrap();
                DiskLayerRef {
                    file_size: std::fs::metadata(&target).unwrap().len(),
                    layer_id,
                    format: format.into(),
                    virtual_size: 131072,
                    predecessor: index
                        .checked_sub(1)
                        .map(|previous| format!("sealed_{previous}")),
                    integrity_root: Some(sparse_file_integrity(&target).unwrap().root),
                }
            })
            .collect();
        let disk = DiskGenerationManifest {
            schema: "microsandbox.disk-generation/1".into(),
            volume_id: "root".into(),
            device_id: "vda".into(),
            generation: 1,
            head: layers.last().unwrap().layer_id.clone(),
            layers,
            pause_generation: 7,
        };
        // The closure checks opaque execution bytes; only live restore decodes their codec.
        let checkpoint = CheckpointManifest {
            schema: "microsandbox.checkpoint/1".into(),
            checkpoint_id: "journal-fixture".into(),
            capture_intent: CaptureIntent::FullSnapshot,
            geometry: microsandbox_image::checkpoint::CheckpointGeometry {
                vcpus: 1,
                max_vcpus: 1,
                memory_mib: 128,
                max_memory_mib: 128,
            },
            architecture: std::env::consts::ARCH.into(),
            pause_generation: 7,
            execution_state: store.put_bytes(b"execution fixture").unwrap(),
            memory: store
                .put_bytes(&memory.to_canonical_bytes().unwrap())
                .unwrap(),
            disks: vec![
                store
                    .put_bytes(&disk.to_canonical_bytes().unwrap())
                    .unwrap(),
            ],
            devices: Vec::new(),
            resources: Vec::new(),
            owned_volumes: Vec::new(),
            requires: Vec::new(),
        };
        let bytes = checkpoint.to_canonical_bytes().unwrap();
        let id = ObjectId::from_bytes(&bytes).unwrap();
        std::fs::write(root.join("checkpoint.json"), bytes).unwrap();
        CheckpointClosure::open(root, Some(&id)).unwrap()
    }

    #[cfg(feature = "runner")]
    fn root_vm(
        layout: super::RootDiskLayout,
        layers: Vec<super::UpperLayerSpec>,
    ) -> super::VmConfig {
        let spec = super::UpperSpec {
            layers,
            read_only: false,
        };
        let mut vm = super::VmConfig {
            libkrunfw_path: Default::default(),
            thp: Default::default(),
            memory_cache_dir: None,
            vcpus: 1,
            memory_mib: 256,
            max_cpus: 1,
            max_memory_mib: 256,
            cpu_placement: Default::default(),
            placement_profile_name: None,
            placement_profile: None,
            block_writeback_limit_bytes: None,
            rootfs_path: None,
            rootfs_follow_root_symlinks: false,
            rootfs_disk: None,
            rootfs_disk_format: None,
            rootfs_disk_readonly: false,
            rootfs_disk_spec: None,
            rootfs_disk_runtime_owned: false,
            rootfs_vmdk: None,
            rootfs_upper: None,
            rootfs_upper_spec: None,
            mounts: Vec::new(),
            file_mounts: Vec::new(),
            owned_volumes: Vec::new(),
            disks: Vec::new(),
            vsock: Vec::new(),
            #[cfg(unix)]
            backends: Vec::new(),
            init_path: None,
            bootstrap: Default::default(),
            exec_path: None,
            exec_args: Vec::new(),
            #[cfg(feature = "net")]
            network: Default::default(),
            #[cfg(feature = "net")]
            deployment_profile: Default::default(),
            #[cfg(feature = "net")]
            sandbox_slot: 1,
            checkpoint_restore: None,
        };
        match layout {
            super::RootDiskLayout::ManagedUpper => {
                vm.rootfs_vmdk = Some("fixture.vmdk".into());
                vm.rootfs_upper_spec = Some(spec);
            }
            super::RootDiskLayout::FlatRoot => {
                vm.rootfs_disk_runtime_owned = true;
                vm.rootfs_disk_spec = Some(spec);
            }
        }
        vm
    }

    #[tokio::test]
    #[cfg(feature = "runner")]
    async fn admitted_raw_hardlink_seeds_once_and_reopens_without_the_snapshot() {
        use super::*;
        for layout in [RootDiskLayout::ManagedUpper, RootDiskLayout::FlatRoot] {
            let directory = tempfile::tempdir().unwrap();
            let source = directory.path().join("source.raw");
            std::fs::write(&source, vec![17; 131072]).unwrap();
            let admitted = admitted_fixture(
                &directory.path().join("snapshot"),
                &[UpperLayerSpec {
                    path: source.clone(),
                    format: msb_krun::DiskImageFormat::Raw,
                }],
            );
            let child_base = directory.path().join("child.raw");
            std::fs::hard_link(&source, &child_base).unwrap();
            let expected = admitted.disks()[0].layers[0]
                .integrity_root
                .clone()
                .unwrap();
            assert_eq!(
                admitted.reused_disk_integrity(&child_base).unwrap(),
                Some(expected.clone())
            );
            let runtime = directory.path().join("runtime");
            std::fs::create_dir(&runtime).unwrap();
            let head = runtime.join("head.qcow2");
            microsandbox_image::checkpoint::create_qcow2_overlay(&head, 131072, &child_base, "raw")
                .await
                .unwrap();
            let vm = root_vm(
                layout,
                vec![
                    UpperLayerSpec {
                        path: child_base.clone(),
                        format: msb_krun::DiskImageFormat::Raw,
                    },
                    UpperLayerSpec {
                        path: head,
                        format: msb_krun::DiskImageFormat::Qcow2,
                    },
                ],
            );
            seed_restored_root_disk(&runtime, &vm, &admitted).unwrap();
            let journal = runtime.join(ROOT_DISK_STATE_FILE);
            let first = std::fs::read(&journal).unwrap();
            let state = read_state(&journal).unwrap();
            assert_eq!(state.layers[0].integrity_root.as_ref(), Some(&expected));
            assert!(
                state.layers[1].integrity_root.is_none(),
                "writable head must not be sealed"
            );
            assert_eq!(state.layout, layout);
            seed_restored_root_disk(&runtime, &vm, &admitted).unwrap();
            assert_eq!(std::fs::read(&journal).unwrap(), first);
            let snapshot_layer = admitted.disk_layer_path(&admitted.disks()[0].layers[0]);
            drop(admitted);
            std::fs::remove_file(source).unwrap();
            std::fs::remove_file(snapshot_layer).unwrap();
            RuntimeOwnedRootDisk::open(&runtime, &vm).unwrap().unwrap();
            assert_eq!(std::fs::read(&journal).unwrap(), first);
            assert_eq!(std::fs::read(child_base).unwrap(), vec![17; 131072]);
        }
    }

    #[tokio::test]
    #[cfg(feature = "runner")]
    async fn compacted_restore_roots_recover_their_ordinary_launch_binding() {
        use super::*;
        use microsandbox_image::checkpoint::{create_qcow2_overlay, materialize_compact_prefix};

        for layout in [RootDiskLayout::ManagedUpper, RootDiskLayout::FlatRoot] {
            for full in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let runtime = directory.path().join("runtime");
                std::fs::create_dir(&runtime).unwrap();
                let raw = directory.path().join("source.raw");
                std::fs::write(&raw, vec![43u8; 131072]).unwrap();
                let sealed = directory.path().join("source.qcow2");
                create_qcow2_overlay(&sealed, 131072, &raw, "raw")
                    .await
                    .unwrap();
                let (restored, ordinary) = match layout {
                    RootDiskLayout::ManagedUpper => ("upper-sealed-000.qcow2", "upper.ext4"),
                    RootDiskLayout::FlatRoot => ("root-sealed-000.qcow2", "rootfs.raw"),
                };
                let base = directory.path().join(restored);
                materialize_compact_prefix(
                    &[
                        CompactLayer {
                            path: raw,
                            qcow2: false,
                        },
                        CompactLayer {
                            path: sealed,
                            qcow2: true,
                        },
                    ],
                    &base,
                )
                .await
                .unwrap();
                let head = directory.path().join("private-head.qcow2");
                create_qcow2_overlay(&head, 131072, &base, "qcow2")
                    .await
                    .unwrap();
                let layers = vec![
                    UpperLayerSpec {
                        path: base.clone(),
                        format: msb_krun::DiskImageFormat::Qcow2,
                    },
                    UpperLayerSpec {
                        path: head.clone(),
                        format: msb_krun::DiskImageFormat::Qcow2,
                    },
                ];
                let vm = root_vm(layout, layers.clone());
                if full {
                    let admitted =
                        admitted_fixture(&directory.path().join("snapshot"), &layers[..1]);
                    seed_restored_root_disk(&runtime, &vm, &admitted).unwrap();
                } else {
                    // Disk-only restore does not invoke the execution-admission seed helper.
                    RuntimeOwnedRootDisk::open(&runtime, &vm).unwrap().unwrap();
                }
                let journal = runtime.join(ROOT_DISK_STATE_FILE);
                let original = std::fs::read(&journal).unwrap();
                let nominal = directory.path().join(ordinary);
                assert!(
                    !nominal.exists(),
                    "restart must not require a fictitious raw image"
                );
                assert_eq!(
                    read_state(&journal).unwrap().launch_base,
                    Some(nominal.clone())
                );

                // Persisted SDK config no longer contains the transient restored layer list.
                let mut restart = root_vm(
                    layout,
                    vec![UpperLayerSpec {
                        path: nominal,
                        format: msb_krun::DiskImageFormat::Raw,
                    }],
                );
                recover_runtime_owned_root(&runtime, &mut restart).unwrap();
                let recovered = configured_layers(&restart, layout).unwrap();
                assert_eq!(recovered[0].path, base);
                assert_eq!(recovered[1].path, head);
                assert_eq!(std::fs::read(&journal).unwrap(), original);

                let mut unrelated = root_vm(
                    layout,
                    vec![UpperLayerSpec {
                        path: directory.path().join("unrelated.raw"),
                        format: msb_krun::DiskImageFormat::Raw,
                    }],
                );
                assert!(
                    recover_runtime_owned_root(&runtime, &mut unrelated)
                        .unwrap_err()
                        .contains("configured base layer")
                );
                assert_eq!(std::fs::read(&journal).unwrap(), original);
            }
        }
    }

    #[test]
    #[cfg(feature = "runner")]
    fn restored_binding_does_not_alias_arbitrary_explicit_chains() {
        use super::*;
        for layout in [RootDiskLayout::ManagedUpper, RootDiskLayout::FlatRoot] {
            let directory = tempfile::tempdir().unwrap();
            let runtime = directory.path().join("child/runtime");
            let filename = match layout {
                RootDiskLayout::ManagedUpper => "upper-sealed-000.qcow2",
                RootDiskLayout::FlatRoot => "root-sealed-000.qcow2",
            };
            for path in [
                directory.path().join("other-child").join(filename),
                directory.path().join("child/custom.qcow2"),
            ] {
                assert!(
                    restored_launch_base(
                        &runtime,
                        layout,
                        &[UpperLayerSpec {
                            path,
                            format: msb_krun::DiskImageFormat::Qcow2,
                        }]
                    )
                    .is_none()
                );
            }
        }
    }

    #[tokio::test]
    #[cfg(feature = "runner")]
    async fn copied_raw_and_relocated_qcow_do_not_implicitly_hash_on_journal_creation() {
        use super::*;
        use microsandbox_image::checkpoint::{create_qcow2_overlay, relocate_qcow2_backing};
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.raw");
        let overlay = directory.path().join("source.qcow2");
        std::fs::write(&source, vec![31; 131072]).unwrap();
        create_qcow2_overlay(&overlay, 131072, &source, "raw")
            .await
            .unwrap();
        let original_overlay = std::fs::read(&overlay).unwrap();
        let admitted = admitted_fixture(
            &directory.path().join("snapshot"),
            &[
                UpperLayerSpec {
                    path: source.clone(),
                    format: msb_krun::DiskImageFormat::Raw,
                },
                UpperLayerSpec {
                    path: overlay.clone(),
                    format: msb_krun::DiskImageFormat::Qcow2,
                },
            ],
        );
        let base_copy = directory.path().join("copied-base.raw");
        let overlay_copy = directory.path().join("copied-overlay.qcow2");
        std::fs::copy(&source, &base_copy).unwrap();
        std::fs::copy(&overlay, &overlay_copy).unwrap();
        relocate_qcow2_backing(&overlay_copy, &base_copy).unwrap();
        assert!(
            admitted
                .reused_disk_integrity(&base_copy)
                .unwrap()
                .is_none()
        );
        assert!(
            admitted
                .reused_disk_integrity(&overlay_copy)
                .unwrap()
                .is_none()
        );
        let expected_qcow = sparse_file_integrity(&overlay_copy).unwrap().root;
        assert_ne!(
            Some(expected_qcow.clone()),
            admitted.disks()[0].layers[1].integrity_root
        );
        let runtime = directory.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        let head = runtime.join("head.qcow2");
        create_qcow2_overlay(&head, 131072, &overlay_copy, "qcow2")
            .await
            .unwrap();
        let vm = root_vm(
            RootDiskLayout::FlatRoot,
            vec![
                UpperLayerSpec {
                    path: base_copy,
                    format: msb_krun::DiskImageFormat::Raw,
                },
                UpperLayerSpec {
                    path: overlay_copy,
                    format: msb_krun::DiskImageFormat::Qcow2,
                },
                UpperLayerSpec {
                    path: head,
                    format: msb_krun::DiskImageFormat::Qcow2,
                },
            ],
        );
        seed_restored_root_disk(&runtime, &vm, &admitted).unwrap();
        let state = read_state(&runtime.join(ROOT_DISK_STATE_FILE)).unwrap();
        // A physical copy/header rewrite loses hash reuse, but does not opt startup into hashing.
        assert!(state.layers[0].integrity_root.is_none());
        assert!(state.layers[1].integrity_root.is_none());
        assert!(state.layers[2].integrity_root.is_none());
        assert_eq!(std::fs::read(overlay).unwrap(), original_overlay);
    }

    #[test]
    fn stopped_growth_preserves_ancestors_and_recovers_pending_target() {
        use super::*;
        use microsandbox_image::ext4::{Ext4FormatOptions, format_ext4};
        for layout in [RootDiskLayout::ManagedUpper, RootDiskLayout::FlatRoot] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("runtime");
            std::fs::create_dir(&root).unwrap();
            let base = dir.path().join("base.raw");
            let mib = 1024 * 1024;
            format_ext4(
                &base,
                &Ext4FormatOptions {
                    size_bytes: 256 * mib,
                    journal_blocks: 4096,
                },
            )
            .unwrap();
            let original = sparse_file_integrity(&base).unwrap().root;
            let head = root.join("head.qcow2");
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(microsandbox_image::checkpoint::create_qcow2_overlay(
                &head,
                256 * mib,
                &base,
                "raw",
            ))
            .unwrap();
            let mut state = RootDiskState {
                schema: ROOT_DISK_STATE_SCHEMA.into(),
                volume_id: new_id("vol"),
                device_id: layout.device_id().into(),
                layout,
                published_generation: 1,
                launch_base: None,
                growth_target: Some(512 * mib),
                layers: vec![
                    RootDiskLayer {
                        layer_id: new_id("layer"),
                        path: base.clone(),
                        format: RootDiskFormat::Raw,
                        integrity_root: Some(original.clone()),
                    },
                    RootDiskLayer {
                        layer_id: new_id("layer"),
                        path: head,
                        format: RootDiskFormat::Qcow2,
                        integrity_root: None,
                    },
                ],
            };
            let journal = root.join(ROOT_DISK_STATE_FILE);
            write_state(&journal, &state).unwrap();
            assert!(load_runtime_owned_root_chain(&root).is_err());
            assert!(compact_stopped_root(&root, None, false).is_err());
            assert!(grow_stopped_root(&root, 768 * mib).is_err());
            recover_stopped_root_growth(&root).unwrap();
            let chain = load_runtime_owned_root_chain(&root).unwrap().unwrap();
            assert_eq!(chain.virtual_size, 512 * mib);
            assert_eq!(chain.layers.len(), 2);
            assert_eq!(sparse_file_integrity(&base).unwrap().root, original);
            // Simulate loss of the final acknowledgment after the filesystem already grew.
            state = read_state(&journal).unwrap();
            state.growth_target = Some(512 * mib);
            write_state(&journal, &state).unwrap();
            recover_stopped_root_growth(&root).unwrap();
            assert!(read_state(&journal).unwrap().growth_target.is_none());
            let before = std::fs::read(&journal).unwrap();
            assert!(grow_stopped_root(&root, 512 * mib + 1).is_err());
            assert_eq!(std::fs::read(&journal).unwrap(), before);
            assert_eq!(sparse_file_integrity(&base).unwrap().root, original);
        }
    }

    #[test]
    fn stopped_compaction_preserves_head_and_recovers_both_layouts() {
        use super::*;
        for layout in [RootDiskLayout::ManagedUpper, RootDiskLayout::FlatRoot] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("runtime");
            std::fs::create_dir(&root).unwrap();
            let base = dir.path().join("base.raw");
            std::fs::write(&base, vec![71u8; 131072]).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let mut layers = vec![RootDiskLayer {
                layer_id: new_id("layer"),
                path: base.clone(),
                format: RootDiskFormat::Raw,
                integrity_root: Some(sparse_file_integrity(&base).unwrap().root),
            }];
            for i in 0..3 {
                let path = root.join(format!("next-{i}.qcow2"));
                let prior = layers.last().unwrap();
                rt.block_on(microsandbox_image::checkpoint::create_qcow2_overlay(
                    &path,
                    131072,
                    &prior.path,
                    prior.format.as_str(),
                ))
                .unwrap();
                layers.push(RootDiskLayer {
                    layer_id: new_id("layer"),
                    format: RootDiskFormat::Qcow2,
                    integrity_root: if i == 2 {
                        None
                    } else {
                        Some(sparse_file_integrity(&path).unwrap().root)
                    },
                    path,
                });
            }
            let head = layers.last().unwrap().path.clone();
            let head_bytes = std::fs::read(&head).unwrap();
            // An old published snapshot owns its own links, not the runtime's retired names.
            let retained = dir.path().join("published-layer.qcow2");
            std::fs::hard_link(&layers[1].path, &retained).unwrap();
            let retained_bytes = std::fs::read(&retained).unwrap();
            let journal = root.join(ROOT_DISK_STATE_FILE);
            write_state(
                &journal,
                &RootDiskState {
                    schema: ROOT_DISK_STATE_SCHEMA.into(),
                    volume_id: new_id("vol"),
                    device_id: layout.device_id().into(),
                    layout,
                    published_generation: 3,
                    launch_base: None,
                    growth_target: None,
                    layers,
                },
            )
            .unwrap();
            let before = std::fs::read(&journal).unwrap();
            let clamped = compact_stopped_root(&root, Some(4), true).unwrap();
            assert_eq!((clamped.selected_layers, clamped.output_layers), (3, 2));
            let plan = compact_stopped_root(&root, Some(2), true).unwrap();
            assert_eq!(
                (plan.input_layers, plan.selected_layers, plan.output_layers),
                (4, 2, 3)
            );
            assert_eq!(std::fs::read(&journal).unwrap(), before);
            // Preparation failure must neither publish a journal nor retain staging files.
            let moved_base = dir.path().join("unavailable.raw");
            std::fs::rename(&base, &moved_base).unwrap();
            assert!(compact_stopped_root(&root, Some(2), false).is_err());
            assert_eq!(std::fs::read(&journal).unwrap(), before);
            assert!(std::fs::read_dir(&root).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".compact-")
            }));
            std::fs::rename(&moved_base, &base).unwrap();
            let result = compact_stopped_root(&root, Some(2), false).unwrap();
            assert_eq!(
                (result.input_layers, result.output_layers, result.pause_us),
                (4, 3, 0)
            );
            let state = read_state(&journal).unwrap();
            assert_eq!(state.launch_base.as_ref(), Some(&base));
            assert_eq!(
                std::fs::read(&state.layers.last().unwrap().path).unwrap(),
                head_bytes
            );
            assert_eq!(std::fs::read(&retained).unwrap(), retained_bytes);
            let chain = load_runtime_owned_root_chain(&root).unwrap().unwrap();
            assert_eq!(chain.virtual_size, 131072);
            assert_eq!(chain.layers[0].format, "qcow2");
            let compacted = compact_stopped_root(&root, None, false).unwrap();
            assert_eq!(compacted.output_layers, 2);
            assert_eq!(
                read_state(&journal).unwrap().launch_base.as_ref(),
                Some(&base)
            );
            assert_eq!(
                compact_stopped_root(&root, None, false)
                    .unwrap()
                    .selected_layers,
                0
            );
        }
    }

    use super::*;

    #[cfg(feature = "runner")]
    use crate::vm::UpperLayerSpec;

    #[test]
    #[cfg(feature = "runner")]
    fn journal_round_trip_preserves_the_forward_chain() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path().join("upper.ext4");
        let next = directory.path().join("upper-next.qcow2");
        std::fs::write(&base, b"base").unwrap();
        std::fs::write(&next, b"next").unwrap();
        let state = RootDiskState {
            schema: ROOT_DISK_STATE_SCHEMA.into(),
            volume_id: new_id("vol"),
            device_id: MANAGED_ROOT_DEVICE_ID.into(),
            layout: RootDiskLayout::ManagedUpper,
            published_generation: 1,
            launch_base: None,
            growth_target: None,
            layers: vec![
                RootDiskLayer {
                    layer_id: new_id("layer"),
                    path: base.clone(),
                    format: RootDiskFormat::Raw,
                    integrity_root: Some(format!("blake3:{}", "0".repeat(64))),
                },
                RootDiskLayer {
                    layer_id: new_id("layer"),
                    path: next.clone(),
                    format: RootDiskFormat::Qcow2,
                    integrity_root: None,
                },
            ],
        };
        let path = directory.path().join("root-disk.json");
        write_state(&path, &state).unwrap();
        let recovered = read_state(&path).unwrap().disk_spec();

        assert_eq!(
            recovered.layers,
            vec![
                UpperLayerSpec {
                    path: base,
                    format: msb_krun::DiskImageFormat::Raw,
                },
                UpperLayerSpec {
                    path: next,
                    format: msb_krun::DiskImageFormat::Qcow2,
                },
            ]
        );
    }

    #[test]
    #[cfg(feature = "runner")]
    fn flat_journal_uses_root_device_and_root_overlay_names() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path().join("rootfs.raw");
        std::fs::write(&base, b"base").unwrap();
        let state = RootDiskState {
            schema: ROOT_DISK_STATE_SCHEMA.into(),
            volume_id: new_id("vol"),
            device_id: FLAT_ROOT_DEVICE_ID.into(),
            layout: RootDiskLayout::FlatRoot,
            published_generation: 0,
            launch_base: None,
            growth_target: None,
            layers: vec![RootDiskLayer {
                layer_id: new_id("layer"),
                path: base.clone(),
                format: RootDiskFormat::Raw,
                integrity_root: None,
            }],
        };
        let state_path = directory.path().join("root-disk.json");
        write_state(&state_path, &state).unwrap();

        let next = next_overlay_path(&base, state.layout);
        assert_eq!(next.parent(), Some(directory.path()));
        assert!(
            next.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("root-")
        );
        assert_eq!(
            next.extension().and_then(|value| value.to_str()),
            Some("qcow2")
        );
        let loaded = load_runtime_owned_root_chain(directory.path())
            .unwrap()
            .unwrap();
        assert_eq!(loaded.device_id, FLAT_ROOT_DEVICE_ID);
        assert_eq!(loaded.virtual_size, 4);
        assert_eq!(loaded.layers[0].path, base);
        assert_eq!(loaded.layers[0].format, "raw");
    }

    #[test]
    fn journal_without_layout_defaults_to_managed_upper() {
        let state = RootDiskState {
            schema: ROOT_DISK_STATE_SCHEMA.into(),
            volume_id: new_id("vol"),
            device_id: MANAGED_ROOT_DEVICE_ID.into(),
            layout: RootDiskLayout::ManagedUpper,
            published_generation: 0,
            launch_base: None,
            growth_target: None,
            layers: vec![RootDiskLayer {
                layer_id: new_id("layer"),
                path: "upper.ext4".into(),
                format: RootDiskFormat::Raw,
                integrity_root: None,
            }],
        };
        let mut value = serde_json::to_value(state).unwrap();
        value.as_object_mut().unwrap().remove("layout");
        let parsed: RootDiskState = serde_json::from_value(value).unwrap();

        assert_eq!(parsed.layout, RootDiskLayout::ManagedUpper);
        parsed.validate().unwrap();
    }
}
