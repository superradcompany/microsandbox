//! Same-epoch capture of owned chains and independent named block volumes.

use std::collections::BTreeMap;
use std::fs::{File, Metadata};
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use microsandbox_image::checkpoint::{
    CompactLayer, DiskGenerationManifest, DiskLayerRef, compact_layer_capacity,
    sparse_file_integrity, validate_standalone_qcow2,
};
use microsandbox_protocol::bootstrap::GuestBootstrap;

use super::disk::{RootDiskRollover, RootDiskRolloverError};
use super::owned_disk::RuntimeOwnedDisk;
use crate::vm::DiskMountSpec;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The launcher keeps the managed volume's disk lock for the VM lifetime. This provider retains
/// the source inode too, and only copies it after the virtio worker has drained and flushed.
pub(super) struct RuntimeOwnedAdditionalDisk {
    /// Only lifecycle-owned disks may replace their backend and authoritative journal.
    owned: Option<RuntimeOwnedDisk>,
    device_id: String,
    source: PathBuf,
    file: File,
    identity: (u64, u64),
    format: &'static str,
    readonly: bool,
    volume_id: String,
    generation: u64,
    binding: BTreeMap<String, String>,
}

#[derive(Debug, Eq, PartialEq)]
struct SourceStamp {
    identity: (u64, u64),
    length: u64,
    modified: SystemTime,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeOwnedAdditionalDisk {
    pub(super) fn open_all(
        disks: &[DiskMountSpec],
        bootstrap: &GuestBootstrap,
        runtime_dir: &Path,
    ) -> Result<BTreeMap<String, Self>, String> {
        let mut providers = BTreeMap::new();
        for disk in disks.iter().filter(|disk| disk.snapshot_owned) {
            if !portable_id(&disk.id) || matches!(disk.id.as_str(), "vda" | "vdb") {
                return Err("managed additional disk has an invalid or reserved device id".into());
            }
            let format = match disk.format {
                msb_krun::DiskImageFormat::Raw => "raw",
                msb_krun::DiskImageFormat::Qcow2 => "qcow2",
                // Ordinary startup retains its existing format support. Snapshot admission
                // refuses devices without a complete immutable-generation provider instead.
                _ => continue,
            };
            let mounts = bootstrap
                .disk_mounts
                .iter()
                .filter(|mount| mount.id == disk.id)
                .collect::<Vec<_>>();
            if mounts.len() != 1 {
                return Err(format!(
                    "managed disk {} requires exactly one guest mount binding",
                    disk.id
                ));
            }
            let mount = mounts[0];
            if mount.flags.readonly != disk.readonly
                || !mount.guest_path.starts_with('/')
                || mount
                    .guest_path
                    .split('/')
                    .any(|part| matches!(part, "." | ".."))
            {
                return Err(format!(
                    "managed disk {} has an inconsistent guest mount binding",
                    disk.id
                ));
            }
            let owned = disk
                .lifecycle_owned
                .then(|| RuntimeOwnedDisk::open(runtime_dir, &disk.id, &disk.host, disk.readonly))
                .transpose()?;
            // disk.raw is a stable launch binding, not necessarily the active file after restore
            // or compaction. Retain a real head handle without reopening a retired raw path.
            let selected = owned
                .as_ref()
                .and_then(|chain| chain.layers().last().map(|layer| layer.path.clone()))
                .unwrap_or_else(|| disk.host.clone());
            let source = selected
                .canonicalize()
                .map_err(|error| format!("resolve managed disk {}: {error}", disk.id))?;
            let file = File::open(&source).map_err(|error| error.to_string())?;
            let metadata = file.metadata().map_err(|error| error.to_string())?;
            if !metadata.is_file() {
                return Err(format!("managed disk {} is not a regular file", disk.id));
            }
            let identity = file_identity(&file, &metadata).map_err(|error| error.to_string())?;
            let mut binding = BTreeMap::from([
                ("device_id".into(), disk.id.clone()),
                ("managed_disk".into(), "true".into()),
                ("guest_path".into(), mount.guest_path.clone()),
                (
                    "mount_options".into(),
                    serde_json::to_string(&mount.flags).map_err(|error| error.to_string())?,
                ),
            ]);
            if let Some(fstype) = &mount.fstype {
                binding.insert("fstype".into(), fstype.clone());
            }
            if disk.lifecycle_owned {
                binding.insert("lifecycle_owned".into(), "true".into());
            }
            let provider = Self {
                owned,
                device_id: disk.id.clone(),
                source,
                file,
                identity,
                format,
                readonly: disk.readonly,
                volume_id: new_id("vol"),
                generation: 0,
                binding,
            };
            if providers.insert(disk.id.clone(), provider).is_some() {
                return Err(format!("duplicate managed disk {}", disk.id));
            }
        }
        Ok(providers)
    }

    pub(super) fn binding(&self) -> &BTreeMap<String, String> {
        &self.binding
    }

    pub(super) fn owned_mut(&mut self) -> Option<&mut RuntimeOwnedDisk> {
        self.owned.as_mut()
    }

    pub(super) fn capture(
        &mut self,
        vm: &msb_krun::VmControl,
        runtime: &tokio::runtime::Handle,
        checkpoint_root: &Path,
        pause_generation: u64,
        record_integrity: bool,
    ) -> Result<RootDiskRollover, RootDiskRolloverError> {
        if let Some(owned) = &mut self.owned {
            // Owned disks retain their journal's required integrity checks. The optional
            // capture policy below applies to copied external/named disks, not that journal.
            return owned.rollover(vm, runtime, checkpoint_root, pause_generation);
        }
        self.capture_copy(
            vm,
            runtime,
            checkpoint_root,
            pause_generation,
            record_integrity,
        )
        .map_err(RootDiskRolloverError::pre_rebind)
    }

    fn capture_copy(
        &mut self,
        vm: &msb_krun::VmControl,
        runtime: &tokio::runtime::Handle,
        checkpoint_root: &Path,
        pause_generation: u64,
        record_integrity: bool,
    ) -> Result<RootDiskRollover, String> {
        // Quiescence waits for in-flight I/O and flushes format metadata before source inspection.
        // No backend rebind or named-volume journal mutation is needed: the source remains owned
        // and unchanged while a new private inode becomes this checkpoint's immutable payload.
        let state = vm
            .capture_block_device_state(&self.device_id)
            .map_err(|error| error.to_string())?;
        if state.pause_generation != pause_generation
            || state.device.id != self.device_id
            || state.device.read_only != self.readonly
        {
            return Err(format!(
                "managed disk {} state disagrees with the capture epoch or binding",
                self.device_id
            ));
        }
        let virtual_size = state
            .device
            .capacity_sectors
            .checked_mul(512)
            .ok_or_else(|| "additional disk capacity overflows bytes".to_string())?;
        let device_state = state.encode().map_err(|error| error.to_string())?;
        let manifest = self.seal(
            runtime,
            checkpoint_root,
            pause_generation,
            virtual_size,
            record_integrity,
        )?;
        Ok(RootDiskRollover {
            manifest,
            device_state,
        })
    }

    fn seal(
        &mut self,
        runtime: &tokio::runtime::Handle,
        checkpoint_root: &Path,
        pause_generation: u64,
        virtual_size: u64,
        record_integrity: bool,
    ) -> Result<DiskGenerationManifest, String> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| "additional disk generation exhausted".to_string())?;
        let before = SourceStamp::read(&self.file).map_err(|error| error.to_string())?;
        if before.identity != self.identity
            || SourceStamp::read(&File::open(&self.source).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?
                != before
        {
            return Err("managed additional disk path no longer names its owned file".into());
        }
        // Deny implicit backing/data-file opens. Copying just the qcow2 head of an ambient chain
        // would produce an incomplete snapshot even if its guest-visible size happened to match.
        if self.format == "qcow2" {
            validate_standalone_qcow2(&self.file)
                .map_err(|error| format!("validate managed disk {}: {error}", self.device_id))?;
        }
        let capacity = runtime
            .block_on(compact_layer_capacity(CompactLayer {
                path: self.source.clone(),
                qcow2: self.format == "qcow2",
            }))
            .map_err(|error| {
                format!(
                    "validate standalone managed disk {}: {error}",
                    self.device_id
                )
            })?;
        if capacity == 0 || capacity != virtual_size {
            return Err(format!(
                "managed disk {} capacity differs from captured device state",
                self.device_id
            ));
        }
        let directory = checkpoint_root.join("layers");
        std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        let staging = tempfile::tempdir_in(&directory).map_err(|error| error.to_string())?;
        let staged = staging.path().join(format!("disk.{}", self.format));
        let (file_bytes, strategy) =
            microsandbox_utils::copy::fast_copy_with_strategy(&self.source, &staged)
                .map_err(|error| format!("copy managed disk {}: {error}", self.device_id))?;
        let integrity = record_integrity
            .then(|| {
                sparse_file_integrity(&staged)
                    .map(|integrity| integrity.root)
                    .map_err(|error| error.to_string())
            })
            .transpose()?;
        let current = File::open(&self.source).map_err(|error| error.to_string())?;
        if SourceStamp::read(&self.file).map_err(|error| error.to_string())? != before
            || SourceStamp::read(&current).map_err(|error| error.to_string())? != before
        {
            return Err("managed additional disk changed while its worker was quiesced".into());
        }
        std::fs::OpenOptions::new()
            .write(true)
            .open(&staged)
            .and_then(|file| file.sync_all())
            .map_err(|error| error.to_string())?;
        let layer_id = new_id("layer");
        let manifest = DiskGenerationManifest {
            schema: "microsandbox.disk-generation/1".into(),
            volume_id: self.volume_id.clone(),
            device_id: self.device_id.clone(),
            generation,
            layers: vec![DiskLayerRef {
                layer_id: layer_id.clone(),
                format: self.format.into(),
                virtual_size,
                file_size: std::fs::metadata(&staged)
                    .map_err(|error| error.to_string())?
                    .len(),
                predecessor: None,
                integrity_root: integrity,
            }],
            head: layer_id.clone(),
            pause_generation,
        };
        manifest.validate().map_err(|error| error.to_string())?;
        let target = directory.join(format!("{layer_id}.{}", self.format));
        // The link only publishes our newly cloned inode, never the still-writable source inode.
        std::fs::hard_link(&staged, &target).map_err(|error| error.to_string())?;
        #[cfg(unix)]
        File::open(&directory)
            .and_then(|file| file.sync_all())
            .map_err(|error| error.to_string())?;
        self.generation = generation;
        tracing::info!(target: "microsandbox_checkpoint_timing", operation = "additional_disk_capture", device_id = %self.device_id, file_bytes, ?strategy, "additional disk capture timing");
        Ok(manifest)
    }
}

impl SourceStamp {
    fn read(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            identity: file_identity(file, &metadata)?,
            length: metadata.len(),
            modified: metadata.modified()?,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn portable_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn new_id(prefix: &str) -> String {
    let bytes: [u8; 16] = rand::random();
    format!("{prefix}_{}", hex::encode(bytes))
}

#[cfg(unix)]
fn file_identity(_file: &File, metadata: &Metadata) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn file_identity(file: &File, _metadata: &Metadata) -> io::Result<(u64, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // The live File owns the handle while Windows fills the fixed-size identity structure.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        u64::from(information.dwVolumeSerialNumber),
        u64::from(information.nFileIndexHigh) << 32 | u64::from(information.nFileIndexLow),
    ))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::{Seek, Write};

    use microsandbox_protocol::bootstrap::{BootstrapDiskMount, BootstrapMountFlags};

    use super::*;

    fn fixture(path: &Path, format: msb_krun::DiskImageFormat) -> (DiskMountSpec, GuestBootstrap) {
        let disk = DiskMountSpec {
            id: "data_ab12".into(),
            host: path.into(),
            guest: String::new(),
            format,
            fstype: None,
            readonly: false,
            snapshot_owned: true,
            lifecycle_owned: false,
            layers: Vec::new(),
        };
        let bootstrap = GuestBootstrap {
            disk_mounts: vec![BootstrapDiskMount {
                id: disk.id.clone(),
                guest_path: "/data".into(),
                fstype: Some("ext4".into()),
                flags: BootstrapMountFlags {
                    noexec: true,
                    nodev: true,
                    ..Default::default()
                },
            }],
            ..Default::default()
        };
        (disk, bootstrap)
    }

    fn provider(disk: DiskMountSpec, bootstrap: &GuestBootstrap) -> RuntimeOwnedAdditionalDisk {
        let parent = disk.host.parent().unwrap();
        let runtime = if disk.lifecycle_owned {
            parent.parent().unwrap().parent().unwrap().join("runtime")
        } else {
            parent.join("runtime")
        };
        RuntimeOwnedAdditionalDisk::open_all(&[disk], bootstrap, &runtime)
            .unwrap()
            .pop_first()
            .unwrap()
            .1
    }

    fn layer(root: &Path, generation: &DiskGenerationManifest) -> PathBuf {
        root.join("layers").join(format!(
            "{}.{}",
            generation.head, generation.layers[0].format
        ))
    }

    #[test]
    fn registration_requires_managed_provenance_and_exact_guest_binding() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.raw");
        std::fs::write(&path, [0u8; 4096]).unwrap();
        let (mut disk, mut bootstrap) = fixture(&path, msb_krun::DiskImageFormat::Raw);
        disk.snapshot_owned = false;
        assert!(
            RuntimeOwnedAdditionalDisk::open_all(
                &[disk.clone()],
                &bootstrap,
                &dir.path().join("runtime")
            )
            .unwrap()
            .is_empty()
        );
        disk.snapshot_owned = true;
        disk.format = msb_krun::DiskImageFormat::Vmdk;
        assert!(
            RuntimeOwnedAdditionalDisk::open_all(
                &[disk.clone()],
                &bootstrap,
                &dir.path().join("runtime")
            )
            .unwrap()
            .is_empty()
        );
        disk.format = msb_krun::DiskImageFormat::Raw;
        let registered = provider(disk.clone(), &bootstrap);
        assert_eq!(registered.binding()["managed_disk"], "true");
        assert!(!registered.binding().contains_key("lifecycle_owned"));
        disk.lifecycle_owned = true;
        let owned_path = dir
            .path()
            .join("owned-volumes")
            .join(&disk.id)
            .join("disk.raw");
        std::fs::create_dir_all(owned_path.parent().unwrap()).unwrap();
        std::fs::copy(&disk.host, &owned_path).unwrap();
        disk.host = owned_path;
        assert_eq!(
            provider(disk.clone(), &bootstrap).binding()["lifecycle_owned"],
            "true"
        );
        assert_eq!(registered.binding()["guest_path"], "/data");
        assert_eq!(registered.binding()["fstype"], "ext4");
        assert_eq!(
            serde_json::from_str::<BootstrapMountFlags>(&registered.binding()["mount_options"])
                .unwrap(),
            bootstrap.disk_mounts[0].flags
        );
        bootstrap.disk_mounts[0].flags.readonly = true;
        assert!(
            RuntimeOwnedAdditionalDisk::open_all(
                &[disk.clone()],
                &bootstrap,
                &dir.path().join("runtime")
            )
            .is_err()
        );
        bootstrap.disk_mounts[0].flags.readonly = false;
        bootstrap.disk_mounts.push(bootstrap.disk_mounts[0].clone());
        assert!(
            RuntimeOwnedAdditionalDisk::open_all(
                &[disk.clone()],
                &bootstrap,
                &dir.path().join("runtime")
            )
            .is_err()
        );
        bootstrap.disk_mounts.clear();
        assert!(
            RuntimeOwnedAdditionalDisk::open_all(&[disk], &bootstrap, &dir.path().join("runtime"))
                .is_err()
        );
    }

    #[test]
    fn raw_generations_have_independent_bytes_and_never_rebind_the_source() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.raw");
        let mut writer = File::create(&path).unwrap();
        writer.set_len(1024 * 1024).unwrap();
        writer.write_all(b"first generation").unwrap();
        writer.sync_all().unwrap();
        let (disk, bootstrap) = fixture(&path, msb_krun::DiskImageFormat::Raw);
        let mut provider = provider(disk, &bootstrap);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let first_root = dir.path().join("first");
        let first = provider
            .seal(runtime.handle(), &first_root, 7, 1024 * 1024, true)
            .unwrap();
        let first_path = layer(&first_root, &first);
        let first_bytes = std::fs::read(&first_path).unwrap();
        assert_eq!(&first_bytes[..16], b"first generation");
        assert_ne!(
            SourceStamp::read(&File::open(&first_path).unwrap())
                .unwrap()
                .identity,
            provider.identity
        );
        writer.rewind().unwrap();
        writer.write_all(b"other generation").unwrap();
        writer.sync_all().unwrap();
        let second_root = dir.path().join("second");
        let second = provider
            .seal(runtime.handle(), &second_root, 8, 1024 * 1024, true)
            .unwrap();
        assert_eq!(first.generation, 1);
        assert_eq!(second.generation, 2);
        assert_eq!(first.volume_id, second.volume_id);
        assert_ne!(first.head, second.head);
        assert_eq!(std::fs::read(&first_path).unwrap(), first_bytes);
        assert_eq!(
            &std::fs::read(layer(&second_root, &second)).unwrap()[..16],
            b"other generation"
        );
        assert_eq!(
            SourceStamp::read(&File::open(&path).unwrap())
                .unwrap()
                .identity,
            provider.identity
        );
    }

    #[test]
    fn source_replacement_and_capacity_mismatch_fail_without_publication() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.raw");
        std::fs::write(&path, [0u8; 4096]).unwrap();
        let (disk, bootstrap) = fixture(&path, msb_krun::DiskImageFormat::Raw);
        let mut provider = provider(disk, &bootstrap);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let target = dir.path().join("snapshot");
        assert!(
            provider
                .seal(runtime.handle(), &target, 1, 8192, true)
                .is_err()
        );
        assert!(!target.exists());
        assert_eq!(provider.generation, 0);
        std::fs::rename(&path, dir.path().join("original.raw")).unwrap();
        std::fs::write(&path, [0u8; 4096]).unwrap();
        assert!(
            provider
                .seal(runtime.handle(), &target, 1, 4096, true)
                .is_err()
        );
        assert!(!target.exists());
        assert_eq!(provider.generation, 0);
    }

    #[test]
    fn qcow2_capture_requires_complete_standalone_storage() {
        use microsandbox_image::checkpoint::{create_qcow2_overlay, materialize_compact_prefix};

        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base.raw");
        std::fs::write(&base, vec![0xa5u8; 131072]).unwrap();
        let overlay = dir.path().join("overlay.qcow2");
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime
            .block_on(create_qcow2_overlay(&overlay, 131072, &base, "raw"))
            .unwrap();
        let (disk, bootstrap) = fixture(&overlay, msb_krun::DiskImageFormat::Qcow2);
        let mut invalid = provider(disk, &bootstrap);
        let refused = dir.path().join("refused");
        let error = invalid
            .seal(runtime.handle(), &refused, 1, 131072, true)
            .unwrap_err();
        assert!(error.contains("backing file"));
        assert!(!refused.exists());

        let standalone = dir.path().join("standalone.qcow2");
        runtime
            .block_on(materialize_compact_prefix(
                &[CompactLayer {
                    path: base,
                    qcow2: false,
                }],
                &standalone,
            ))
            .unwrap();
        let (disk, bootstrap) = fixture(&standalone, msb_krun::DiskImageFormat::Qcow2);
        let mut valid = provider(disk, &bootstrap);
        let captured = dir.path().join("captured");
        let generation = valid
            .seal(runtime.handle(), &captured, 2, 131072, true)
            .unwrap();
        assert_eq!(
            std::fs::read(layer(&captured, &generation)).unwrap(),
            std::fs::read(&standalone).unwrap()
        );

        // The incompatible-feature bit for an external data file must be refused even if its
        // data-file filename extension is absent or malformed.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&standalone)
            .unwrap();
        file.seek(io::SeekFrom::Start(72)).unwrap();
        file.write_all(&(1u64 << 2).to_be_bytes()).unwrap();
        assert!(validate_standalone_qcow2(&File::open(&standalone).unwrap()).is_err());
    }
}
