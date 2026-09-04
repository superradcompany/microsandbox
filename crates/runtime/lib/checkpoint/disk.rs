//! Crash-forward rollover for sandbox-owned root disks.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::fs::File;

use microsandbox_image::checkpoint::{DiskGenerationManifest, DiskLayerRef, sparse_file_integrity};
use serde::{Deserialize, Serialize};

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
    /// Guest-visible capacity shared by every layer in the chain.
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
    #[serde(default)]
    layout: RootDiskLayout,
    published_generation: u64,
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

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeOwnedRootDisk {
    /// Open the authoritative chain journal or initialize it from a sandbox-owned root disk.
    pub(crate) fn open(runtime_dir: &Path, vm: &VmConfig) -> Result<Option<Self>, String> {
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

    /// Guest-visible block identity owned by this rollover provider.
    pub(crate) fn device_id(&self) -> &str {
        &self.state.device_id
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
            || self.device_id != self.layout.device_id()
            || self.layers.is_empty()
            || self.layers.len() > 256
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
                || (index + 1 < self.layers.len() && layer.integrity_root.is_none())
            {
                return Err(format!("runtime-owned root-disk layer {index} is invalid"));
            }
        }
        Ok(())
    }

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
    let journal_base = state.layers.first().map(|layer| &layer.path);
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
/// `None` means no rollover journal exists yet. The first layer of runtime-produced roots is raw,
/// so its apparent size is the shared guest-visible capacity. A foreign qcow2-only base fails
/// explicitly instead of being assigned the container file's smaller apparent size.
pub fn load_runtime_owned_root_chain(
    runtime_dir: &Path,
) -> Result<Option<RuntimeOwnedRootChain>, String> {
    let state_path = runtime_dir.join(ROOT_DISK_STATE_FILE);
    if !state_path.exists() {
        return Ok(None);
    }
    let state = read_state(&state_path)?;
    let first = state
        .layers
        .first()
        .expect("validated runtime root chain is non-empty");
    if first.format != RootDiskFormat::Raw {
        return Err("runtime-owned root chain has no raw capacity-bearing base".into());
    }
    let virtual_size = std::fs::metadata(&first.path)
        .map_err(|error| format!("read runtime-owned root base size: {error}"))?
        .len();
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

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn configured_layout(vm: &VmConfig) -> Option<RootDiskLayout> {
    if vm.rootfs_vmdk.is_some() {
        Some(RootDiskLayout::ManagedUpper)
    } else if vm.rootfs_disk_runtime_owned {
        Some(RootDiskLayout::FlatRoot)
    } else {
        None
    }
}

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
        return Err("runtime-owned root-disk state exceeds its size bound".into());
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
    use super::{
        FLAT_ROOT_DEVICE_ID, MANAGED_ROOT_DEVICE_ID, ROOT_DISK_STATE_SCHEMA, RootDiskFormat,
        RootDiskLayer, RootDiskLayout, RootDiskState, load_runtime_owned_root_chain, new_id,
        next_overlay_path, read_state, write_state,
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
            device_id: MANAGED_ROOT_DEVICE_ID.into(),
            layout: RootDiskLayout::ManagedUpper,
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
