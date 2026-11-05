//! Read bounded restore metadata without extracting archive payloads.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use async_compression::tokio::bufread::ZstdDecoder;
use microsandbox_image::checkpoint::CheckpointManifest;
use microsandbox_image::snapshot::migration::{
    V066_DESCRIPTOR_FILENAME, V066PayloadIdentity, inspect_v066_source,
    translate_released_flat_forward, translate_v066_forward,
};
use microsandbox_image::snapshot::{DESCRIPTOR_FILENAME, Manifest, SnapshotState};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncSeekExt, BufReader};
use tokio_tar::{EntryType, Header};

use crate::sandbox::{RootfsSource, SandboxConfig, config::SnapshotRestoreMode};
use crate::snapshot::validate_checkpoint_owned_inventory;
use crate::{MicrosandboxError, MicrosandboxResult, Operation, UnsupportedReason};

use super::{
    ArchiveInventory, ArchiveSnapshot, SparseMap, archive_entry_target, discard_exact,
    normal_utf8_components, portable_archive_path, read_entry_header, tar_pad,
    validate_archive_directory,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const READ_BUFFER_BYTES: usize = 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Plain tar payloads can be skipped with seeks; compressed streams must be decoded.
enum MetadataReader {
    Plain(BufReader<tokio::fs::File>, u64),
    Compressed(ZstdDecoder<BufReader<tokio::fs::File>>),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxConfig {
    /// Read and apply captured archive settings without extracting payloads.
    pub(crate) async fn apply_archive_metadata(
        &mut self,
        archive: &Path,
    ) -> MicrosandboxResult<()> {
        let (manifest, checkpoint) = MetadataReader::open(archive)
            .await?
            .read_metadata(archive)
            .await?;

        let unsupported = manifest.unsupported_requires();
        if !unsupported.is_empty() {
            return Err(MicrosandboxError::unsupported(
                Operation::SnapshotOps,
                UnsupportedReason::NotAvailable(format!(
                    "snapshot requires unsupported runtime capabilities: {}",
                    unsupported.join(", ")
                )),
            ));
        }

        self.validate_restore_options(manifest.scope, self.snapshot_restore_mode)?;

        self.spec.image = RootfsSource::oci(manifest.image.reference.clone());
        if self.spec.runtime.user.is_none() {
            self.spec.runtime.user = manifest.restore_defaults()?.user;
        }

        crate::sandbox::apply_snapshot_guest_clock(self, &manifest)?;
        self.manifest_digest = Some(manifest.image.manifest_digest.clone());
        self.snapshot_parent = Some(manifest.snapshot_id.to_string());
        crate::sandbox::apply_snapshot_root_layout(self, &manifest.root_disk)?;
        crate::sandbox::require_recorded_mounts(self, &manifest)?;

        match (&manifest.state, checkpoint) {
            (SnapshotState::Checkpoint(state), Some(checkpoint)) => {
                validate_checkpoint_owned_inventory(&manifest, &checkpoint)?;

                if self.snapshot_restore_mode == SnapshotRestoreMode::DiskOnly {
                    crate::sandbox::require_guest_mounts(
                        self,
                        crate::sandbox::external_bind_guest_paths(&checkpoint.resources)?,
                    )?;
                } else {
                    if checkpoint.architecture != std::env::consts::ARCH {
                        return Err(MicrosandboxError::SnapshotIntegrity(
                            "checkpoint architecture cannot restore on this host".into(),
                        ));
                    }

                    crate::sandbox::apply_checkpoint_restore_constraints(self, state, &checkpoint)?;
                    self.suppress_launch_for_full_restore();
                }
            }
            (SnapshotState::File(_), _) => {
                if self.snapshot_restore_mode == SnapshotRestoreMode::DiskOnly {
                    return Err(MicrosandboxError::InvalidConfig(
                        "disk_only requires a full snapshot with checkpoint state".into(),
                    ));
                }

                if self.forked {
                    return Err(MicrosandboxError::InvalidConfig(
                        "copy-on-write memory requires a full snapshot restore".into(),
                    ));
                }
            }
            _ => {
                return Err(MicrosandboxError::SnapshotIntegrity(
                    "archive checkpoint metadata is missing".into(),
                ));
            }
        }

        self.snapshot_archive_source = Some(archive.to_path_buf());
        self.restore_resources.archive_manifest = Some(std::sync::Arc::new(manifest));

        Ok(())
    }
}

impl MetadataReader {
    /// Inspect members one at a time. Keep only descriptor identities and the most recent
    /// descriptor/checkpoint bodies; ordinary parent-first archives need no second scan.
    async fn read_metadata(
        mut self,
        archive: &Path,
    ) -> MicrosandboxResult<(Manifest, Option<CheckpointManifest>)> {
        let mut descriptors = BTreeMap::new();
        let mut parents = HashSet::new();
        let mut last_manifest = None;
        let mut last_checkpoint = None;
        let mut inventory = None;
        let mut seen = HashSet::new();

        while let Some((header, path)) = self.next().await? {
            let name = portable_archive_path(&path)?;
            if header.entry_type() == EntryType::Directory {
                continue;
            }

            if !seen.insert(name.clone()) {
                return Err(MicrosandboxError::SnapshotIntegrity(format!(
                    "archive contains duplicate entry: {name}"
                )));
            }

            match metadata_limit(&path) {
                Some(limit) => {
                    let bytes = self.metadata(&header, limit).await?;
                    if name == "archive.json" {
                        inventory = Some(bytes);
                    } else if path
                        .file_name()
                        .is_some_and(|name| name == "checkpoint.json")
                    {
                        last_checkpoint = Some((name, CheckpointManifest::from_bytes(&bytes)?));
                    } else {
                        let manifest = decode_descriptor(&path, &bytes)?;
                        if let Some(parent) = &manifest.parent {
                            parents.insert(parent.to_string());
                        }

                        descriptors.insert(
                            name.clone(),
                            ArchiveSnapshot {
                                snapshot_id: manifest.snapshot_id.to_string(),
                                descriptor_path: name.clone(),
                                descriptor_digest: manifest.digest()?,
                            },
                        );
                        last_manifest = Some((name, manifest));
                    }
                }
                None => self.skip_payload(&header).await?,
            }
        }

        let member = if let Some(bytes) = inventory {
            let value: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
            if value.get("schema").and_then(serde_json::Value::as_u64) == Some(1) {
                select_head(&descriptors, &parents)?
            } else {
                let inventory: ArchiveInventory = serde_json::from_slice(&bytes)
                    .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
                if serde_json::to_vec(&inventory)? != bytes {
                    return Err(MicrosandboxError::SnapshotIntegrity(
                        "archive inventory is not canonical".into(),
                    ));
                }

                inventory.validate_metadata()?;

                let member = inventory
                    .members
                    .iter()
                    .find(|member| member.snapshot_id == inventory.head)
                    .ok_or_else(|| {
                        MicrosandboxError::SnapshotIntegrity("archive head is missing".into())
                    })?;
                let observed = descriptors.get(&member.descriptor_path).ok_or_else(|| {
                    MicrosandboxError::SnapshotIntegrity(
                        "archive head descriptor is missing".into(),
                    )
                })?;

                if observed.snapshot_id != member.snapshot_id
                    || observed.descriptor_digest != member.descriptor_digest
                {
                    return Err(MicrosandboxError::SnapshotIntegrity(
                        "archive head descriptor identity mismatch".into(),
                    ));
                }

                member.clone()
            }
        } else {
            select_head(&descriptors, &parents)?
        };

        let checkpoint_path = format!("checkpoints/{}/checkpoint.json", member.snapshot_id);
        let cached = last_manifest.filter(|(path, manifest)| {
            path == &member.descriptor_path
                && (matches!(manifest.state, SnapshotState::File(_))
                    || last_checkpoint
                        .as_ref()
                        .is_some_and(|(path, _)| path == &checkpoint_path))
        });

        let (manifest, checkpoint) = if let Some((_, manifest)) = cached {
            (manifest, last_checkpoint.map(|(_, checkpoint)| checkpoint))
        } else {
            // Unusual member ordering must not require retaining every checkpoint in RAM.
            Self::read_selected_metadata(archive, &member, &checkpoint_path).await?
        };

        if manifest.digest()? != member.descriptor_digest {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "snapshot archive changed during metadata inspection".into(),
            ));
        }

        let checkpoint = if let SnapshotState::Checkpoint(state) = &manifest.state {
            let checkpoint = checkpoint.ok_or_else(|| {
                MicrosandboxError::SnapshotIntegrity(
                    "archive checkpoint metadata is missing".into(),
                )
            })?;

            if checkpoint.checkpoint_id != state.checkpoint_id
                || checkpoint.digest()?.as_str() != state.checkpoint_root
            {
                return Err(MicrosandboxError::SnapshotIntegrity(
                    "snapshot and checkpoint closure identities differ".into(),
                ));
            }

            Some(checkpoint)
        } else {
            None
        };

        Ok((manifest, checkpoint))
    }

    async fn read_selected_metadata(
        archive: &Path,
        member: &ArchiveSnapshot,
        checkpoint_path: &str,
    ) -> MicrosandboxResult<(Manifest, Option<CheckpointManifest>)> {
        let mut reader = MetadataReader::open(archive).await?;
        let mut manifest = None;
        let mut checkpoint = None;

        while let Some((header, path)) = reader.next().await? {
            let name = portable_archive_path(&path)?;
            if name == member.descriptor_path {
                let bytes = reader
                    .metadata(
                        &header,
                        microsandbox_types::snapshot::MAX_DESCRIPTOR_BYTES as u64,
                    )
                    .await?;
                manifest = Some(decode_descriptor(&path, &bytes)?);
            } else if name == checkpoint_path {
                let bytes = reader.metadata(&header, 8 * 1024 * 1024).await?;
                checkpoint = Some(CheckpointManifest::from_bytes(&bytes)?);
            } else {
                reader.skip_payload(&header).await?;
            }

            if manifest.as_ref().is_some_and(|manifest| {
                matches!(manifest.state, SnapshotState::File(_)) || checkpoint.is_some()
            }) {
                break;
            }
        }

        Ok((
            manifest.ok_or_else(|| {
                MicrosandboxError::SnapshotIntegrity("archive head descriptor is missing".into())
            })?,
            checkpoint,
        ))
    }

    async fn open(path: &Path) -> MicrosandboxResult<Self> {
        let file = tokio::fs::File::open(path).await.map_err(|error| {
            MicrosandboxError::SnapshotIntegrity(format!(
                "cannot open snapshot archive {}: {error}",
                path.display()
            ))
        })?;
        let length = file.metadata().await?.len();
        let mut reader = BufReader::with_capacity(READ_BUFFER_BYTES, file);

        if reader
            .fill_buf()
            .await?
            .starts_with(&[0x28, 0xb5, 0x2f, 0xfd])
        {
            Ok(Self::Compressed(ZstdDecoder::new(reader)))
        } else {
            Ok(Self::Plain(reader, length))
        }
    }

    fn input(&mut self) -> &mut (dyn AsyncRead + Unpin + Send) {
        match self {
            Self::Plain(reader, _) => reader,
            Self::Compressed(reader) => reader,
        }
    }

    async fn next(&mut self) -> MicrosandboxResult<Option<(Header, PathBuf)>> {
        let Some((header, path)) = read_entry_header(&mut self.input()).await? else {
            return Ok(None);
        };

        let parts = normal_utf8_components(&path)?;
        if header.entry_type() == EntryType::Directory {
            validate_archive_directory(&parts, &path)?;
            if header.entry_size()? != 0 {
                return Err(MicrosandboxError::SnapshotIntegrity(
                    "archive directory has a non-empty body".into(),
                ));
            }
        } else {
            // Share extraction's complete path grammar without creating any targets.
            archive_entry_target(&parts, &path, Path::new(""), Path::new(""))?;
        }

        Ok(Some((header, path)))
    }

    async fn skip(&mut self, size: u64) -> MicrosandboxResult<()> {
        match self {
            Self::Plain(reader, length) => {
                // Preserve read-ahead for padding and small members. Seeking would discard
                // the buffer and repeatedly reread the same bytes in dense small-file archives.
                if size <= reader.buffer().len() as u64 {
                    reader.consume(size as usize);

                    return Ok(());
                }

                if size <= READ_BUFFER_BYTES as u64 {
                    return discard_exact(reader, size).await;
                }

                let end = reader
                    .stream_position()
                    .await?
                    .checked_add(size)
                    .filter(|end| end <= length)
                    .ok_or_else(|| {
                        MicrosandboxError::SnapshotIntegrity(
                            "archive entry exceeds the remaining file length".into(),
                        )
                    })?;

                reader.seek(std::io::SeekFrom::Start(end)).await?;

                Ok(())
            }
            Self::Compressed(reader) => discard_exact(reader, size).await,
        }
    }

    async fn skip_payload(&mut self, header: &Header) -> MicrosandboxResult<()> {
        let size = header.entry_size()?;
        if header.entry_type() == EntryType::GNUSparse {
            SparseMap::read(&mut self.input(), header, size).await?;
        }

        self.skip(size).await?;
        self.skip(tar_pad(size)).await
    }

    async fn metadata(&mut self, header: &Header, limit: u64) -> MicrosandboxResult<Vec<u8>> {
        let size = header.entry_size()?;
        if size > limit || header.entry_type() == EntryType::GNUSparse {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "archive metadata exceeds its size limit or is sparse".into(),
            ));
        }

        let mut bytes = vec![0; size as usize];
        self.input().read_exact(&mut bytes).await?;
        self.skip(tar_pad(size)).await?;

        Ok(bytes)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn metadata_limit(path: &Path) -> Option<u64> {
    let parts = normal_utf8_components(path).ok()?;

    match parts.as_slice() {
        ["archive.json"] => Some(4 * 1024 * 1024),
        ["snapshots", _, DESCRIPTOR_FILENAME] | [_, V066_DESCRIPTOR_FILENAME] => {
            Some(microsandbox_types::snapshot::MAX_DESCRIPTOR_BYTES as u64)
        }
        ["checkpoints", _, "checkpoint.json"] => Some(8 * 1024 * 1024),
        _ => None,
    }
}

fn decode_descriptor(path: &Path, bytes: &[u8]) -> MicrosandboxResult<Manifest> {
    if path
        .file_name()
        .is_some_and(|name| name == V066_DESCRIPTOR_FILENAME)
    {
        let source = inspect_v066_source(bytes)?;

        // Metadata translation uses the declared payload size. Extraction verifies it
        // against the actual payload before the snapshot can be restored.
        Ok(translate_v066_forward(
            bytes,
            &V066PayloadIdentity {
                size_bytes: source.size_bytes,
            },
            source.parent_digest,
        )?
        .target)
    } else {
        match Manifest::from_bytes(bytes) {
            Ok(manifest) => Ok(manifest),
            Err(final_error) => translate_released_flat_forward(bytes)
                .map(|translation| translation.target)
                .map_err(|legacy_error| {
                    MicrosandboxError::SnapshotIntegrity(format!(
                        "cannot decode archive descriptor {}: final format: {final_error}; released flat format: {legacy_error}",
                        path.display()
                    ))
                }),
        }
    }
}

fn select_head(
    descriptors: &BTreeMap<String, ArchiveSnapshot>,
    parents: &HashSet<String>,
) -> MicrosandboxResult<ArchiveSnapshot> {
    let mut heads = descriptors
        .values()
        .filter(|member| !parents.contains(&member.snapshot_id));

    match (heads.next(), heads.next()) {
        (Some(head), None) => Ok(head.clone()),
        _ => Err(MicrosandboxError::SnapshotIntegrity(
            "archive must contain exactly one snapshot head".into(),
        )),
    }
}
