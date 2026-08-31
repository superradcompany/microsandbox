//! Crash-forward managed root-disk rollover.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use microsandbox_image::checkpoint::{DiskGenerationManifest, DiskLayerRef, sparse_file_integrity};
use serde::{Deserialize, Serialize};

use crate::vm::{UpperLayerSpec, UpperSpec, VmConfig};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const ROOT_DISK_STATE_FILE: &str = "root-disk.json";
const ROOT_DISK_STATE_SCHEMA: &str = "microsandbox.runtime-root-disk/1";
const MAX_ROOT_DISK_STATE_BYTES: u64 = 1024 * 1024;
const ROOT_UPPER_DEVICE_ID: &str = "vdb";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Runtime owner of the managed OCI writable-root chain.
pub(crate) struct ManagedRootDisk {
    state_path: PathBuf,
    state: RootDiskState,
}

/// Successfully sealed disk generation and the block state captured at its pause boundary.
pub(crate) struct RootDiskRollover {
    pub(crate) manifest: DiskGenerationManifest,
    pub(crate) device_state: Vec<u8>,
}

/// A rollover failure that distinguishes safely resumable preparation from uncertain rebind.
#[derive(Debug)]
pub(crate) struct RootDiskRolloverError {
    message: String,
    pub(crate) keep_paused: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootDiskState {
    schema: String,
    volume_id: String,
    device_id: String,
    published_generation: u64,
    layers: Vec<RootDiskLayer>,
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

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ManagedRootDisk {
    /// Open the authoritative chain journal or initialize it from the VM's managed OCI upper.
    pub(crate) fn open(runtime_dir: &Path, vm: &VmConfig) -> Result<Option<Self>, String> {
        if vm.rootfs_vmdk.is_none() {
            return Ok(None);
        }
        let state_path = runtime_dir.join(ROOT_DISK_STATE_FILE);
        let state = if state_path.exists() {
            read_state(&state_path)?
        } else {
            let layers = configured_layers(vm)?;
            if layers.is_empty() {
                return Ok(None);
            }
            let mut state = RootDiskState {
                schema: ROOT_DISK_STATE_SCHEMA.into(),
                volume_id: new_id("vol"),
                device_id: ROOT_UPPER_DEVICE_ID.into(),
                published_generation: 0,
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
            for layer in state.layers.iter_mut().take(last) {
                layer.integrity_root = Some(
                    sparse_file_integrity(&layer.path)
                        .map_err(|error| format!("hash sealed root ancestor: {error}"))?
                        .root,
                );
            }
            write_state(&state_path, &state)?;
            state
        };
        state.validate()?;
        Ok(Some(Self { state_path, state }))
    }

    /// Seal the current head, publish its closure, and switch the paused device to a fresh head.
    pub(crate) fn rollover(
        &mut self,
        vm: &msb_krun::VmControl,
        runtime: &tokio::runtime::Handle,
        checkpoint_root: &Path,
        pause_generation: u64,
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

        for layer in &mut self.state.layers {
            if layer.integrity_root.is_none() {
                let integrity = sparse_file_integrity(&layer.path)
                    .map_err(RootDiskRolloverError::pre_rebind)?;
                layer.integrity_root = Some(integrity.root);
            }
        }
        publish_layer_closure(checkpoint_root, &self.state.layers)
            .map_err(RootDiskRolloverError::pre_rebind)?;

        let generation = self
            .state
            .published_generation
            .checked_add(1)
            .ok_or_else(|| RootDiskRolloverError::pre_rebind("disk generation is exhausted"))?;
        let sealed_layers = self
            .state
            .layers
            .iter()
            .enumerate()
            .map(|(index, layer)| DiskLayerRef {
                layer_id: layer.layer_id.clone(),
                format: layer.format.as_str().into(),
                virtual_size,
                predecessor: index
                    .checked_sub(1)
                    .map(|previous| self.state.layers[previous].layer_id.clone()),
                integrity_root: layer
                    .integrity_root
                    .clone()
                    .expect("all sealed layers were hashed"),
            })
            .collect::<Vec<_>>();
        let manifest = DiskGenerationManifest {
            schema: "microsandbox.disk-generation/1".into(),
            volume_id: self.state.volume_id.clone(),
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
        let new_path = next_overlay_path(&previous_head.path);
        runtime
            .block_on(microsandbox_image::checkpoint::create_qcow2_overlay(
                &new_path,
                virtual_size,
                &previous_head.path,
                previous_head.format.as_str(),
            ))
            .map_err(RootDiskRolloverError::pre_rebind)?;

        let mut next_state = self.state.clone();
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
        write_state(&self.state_path, &next_state).map_err(RootDiskRolloverError::pre_rebind)?;
        self.state = next_state;
        vm.replace_block_backend(&self.state.device_id, backend)
            .map_err(RootDiskRolloverError::post_journal)?;

        Ok(RootDiskRollover {
            manifest,
            device_state: encoded_state,
        })
    }
}

impl RootDiskState {
    fn validate(&self) -> Result<(), String> {
        if self.schema != ROOT_DISK_STATE_SCHEMA
            || !valid_id(&self.volume_id, "vol")
            || self.device_id != ROOT_UPPER_DEVICE_ID
            || self.layers.is_empty()
            || self.layers.len() > 256
        {
            return Err("managed root-disk state has invalid identity or bounds".into());
        }
        let mut paths = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for (index, layer) in self.layers.iter().enumerate() {
            if !valid_id(&layer.layer_id, "layer")
                || layer.path.as_os_str().is_empty()
                || !paths.insert(layer.path.clone())
                || !ids.insert(layer.layer_id.clone())
                || (index > 0 && layer.format != RootDiskFormat::Qcow2)
                || (index + 1 < self.layers.len() && layer.integrity_root.is_none())
            {
                return Err(format!("managed root-disk layer {index} is invalid"));
            }
        }
        Ok(())
    }

    fn upper_spec(&self) -> UpperSpec {
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

impl RootDiskFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Qcow2 => "qcow2",
        }
    }
}

impl TryFrom<msb_krun::DiskImageFormat> for RootDiskFormat {
    type Error = String;

    fn try_from(value: msb_krun::DiskImageFormat) -> Result<Self, Self::Error> {
        match value {
            msb_krun::DiskImageFormat::Raw => Ok(Self::Raw),
            msb_krun::DiskImageFormat::Qcow2 => Ok(Self::Qcow2),
            msb_krun::DiskImageFormat::Vmdk => {
                Err("managed root chains do not support VMDK layers".into())
            }
        }
    }
}

impl From<RootDiskFormat> for msb_krun::DiskImageFormat {
    fn from(value: RootDiskFormat) -> Self {
        match value {
            RootDiskFormat::Raw => Self::Raw,
            RootDiskFormat::Qcow2 => Self::Qcow2,
        }
    }
}

impl From<RootDiskFormat> for msb_krun::BlockImageFormat {
    fn from(value: RootDiskFormat) -> Self {
        match value {
            RootDiskFormat::Raw => Self::Raw,
            RootDiskFormat::Qcow2 => Self::Qcow2,
        }
    }
}

impl RootDiskRolloverError {
    fn pre_rebind(error: impl fmt::Display) -> Self {
        Self {
            message: error.to_string(),
            keep_paused: false,
        }
    }

    fn post_journal(error: impl fmt::Display) -> Self {
        Self {
            message: error.to_string(),
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

/// Apply the durable forward chain before VM construction after a runtime restart.
pub(crate) fn recover_managed_upper(runtime_dir: &Path, vm: &mut VmConfig) -> Result<(), String> {
    let state_path = runtime_dir.join(ROOT_DISK_STATE_FILE);
    if !state_path.exists() {
        return Ok(());
    }
    if vm.rootfs_vmdk.is_none() {
        return Err("managed root-disk state exists for a VM without an OCI block root".into());
    }
    let state = read_state(&state_path)?;
    let configured = configured_layers(vm)?;
    let configured_base = configured.first().map(|layer| &layer.path);
    let journal_base = state.layers.first().map(|layer| &layer.path);
    if configured_base != journal_base {
        return Err("managed root-disk journal does not match the configured base layer".into());
    }
    vm.rootfs_upper = None;
    vm.rootfs_upper_spec = Some(state.upper_spec());
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn configured_layers(vm: &VmConfig) -> Result<Vec<UpperLayerSpec>, String> {
    if let Some(spec) = &vm.rootfs_upper_spec {
        return Ok(spec.layers.clone());
    }
    Ok(vm
        .rootfs_upper
        .as_ref()
        .map(|path| {
            vec![UpperLayerSpec {
                path: path.clone(),
                format: msb_krun::DiskImageFormat::Raw,
            }]
        })
        .unwrap_or_default())
}

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
        .map_err(|error| format!("prepare managed root backend: {error}"))
}

fn publish_layer_closure(root: &Path, layers: &[RootDiskLayer]) -> Result<(), String> {
    let directory = root.join("layers");
    std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    for layer in layers {
        let target = directory.join(format!("{}.{}", layer.layer_id, layer.format.as_str()));
        if target.exists() {
            let expected = layer
                .integrity_root
                .as_deref()
                .ok_or_else(|| "sealed layer is missing integrity".to_string())?;
            let actual = sparse_file_integrity(&target).map_err(|error| error.to_string())?;
            if actual.root != expected {
                return Err(format!("checkpoint layer {} conflicts", layer.layer_id));
            }
            continue;
        }
        std::fs::hard_link(&layer.path, &target).map_err(|error| {
            format!(
                "link sealed layer {} into checkpoint closure: {error}",
                layer.path.display()
            )
        })?;
    }
    sync_directory(&directory).map_err(|error| error.to_string())
}

fn read_state(path: &Path) -> Result<RootDiskState, String> {
    let metadata = path.metadata().map_err(|error| error.to_string())?;
    if metadata.len() > MAX_ROOT_DISK_STATE_BYTES {
        return Err("managed root-disk state exceeds its size bound".into());
    }
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let state: RootDiskState = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse root-disk state: {error}"))?;
    state.validate()?;
    Ok(state)
}

fn write_state(path: &Path, state: &RootDiskState) -> Result<(), String> {
    state.validate()?;
    let parent = path
        .parent()
        .ok_or_else(|| "root-disk state path has no parent".to_string())?;
    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let temporary = parent.join(format!(
        ".{ROOT_DISK_STATE_FILE}.{}.tmp",
        rand::random::<u64>()
    ));
    let bytes = serde_json::to_vec(state).map_err(|error| error.to_string())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    drop(file);
    if let Err(error) = super::replace_file(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.to_string());
    }
    sync_directory(parent).map_err(|error| error.to_string())
}

fn next_overlay_path(previous: &Path) -> PathBuf {
    let parent = previous.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("upper-{}.qcow2", &new_id("head")[5..]))
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
    use super::{
        ROOT_DISK_STATE_SCHEMA, ROOT_UPPER_DEVICE_ID, RootDiskFormat, RootDiskLayer, RootDiskState,
        new_id, read_state, write_state,
    };

    use crate::vm::UpperLayerSpec;

    #[test]
    fn journal_round_trip_preserves_the_forward_chain() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path().join("upper.ext4");
        let next = directory.path().join("upper-next.qcow2");
        std::fs::write(&base, b"base").unwrap();
        std::fs::write(&next, b"next").unwrap();
        let state = RootDiskState {
            schema: ROOT_DISK_STATE_SCHEMA.into(),
            volume_id: new_id("vol"),
            device_id: ROOT_UPPER_DEVICE_ID.into(),
            published_generation: 1,
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
        let recovered = read_state(&path).unwrap().upper_spec();

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
}
