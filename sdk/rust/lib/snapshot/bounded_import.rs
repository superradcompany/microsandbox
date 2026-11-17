//! Existing raw-only embedding API. New callers supply limits and policy explicitly.

use std::path::{Component, Path};

use microsandbox_types::SnapshotManifest;
use microsandbox_types::snapshot::SnapshotFormat;

use super::{ImportLimits, ImportPolicy};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_ENTRIES: usize = 256;
const MAX_PATH_BYTES: usize = 4096;
const MAX_METADATA_BYTES: u64 = 4 * 1024 * 1024;
const METADATA_FILES: u64 = 3;
const IMPORT_COPIES: u64 = 4;
const ENTRY_ALLOCATION_BYTES: u64 = 64 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(crate) struct RawDiskImport {
    maximum_disk: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RawDiskImport {
    pub(crate) fn new(maximum_disk: u64) -> MicrosandboxResult<Self> {
        peak_bytes(maximum_disk)?;
        Ok(Self { maximum_disk })
    }

    pub(crate) fn limits(&self) -> ImportLimits {
        ImportLimits {
            expanded_bytes: self.maximum_disk + METADATA_FILES * MAX_METADATA_BYTES,
            metadata_bytes: MAX_METADATA_BYTES,
            entries: MAX_ENTRIES,
            path_bytes: MAX_PATH_BYTES,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl ImportPolicy for RawDiskImport {
    fn validate_entry(&self, path: &Path, logical_bytes: u64) -> MicrosandboxResult<()> {
        for component in path.components() {
            if let Component::Normal(name) = component
                && matches!(
                    name.to_str(),
                    Some("cache" | "images" | "checkpoints" | "owned" | "owned-volumes")
                )
            {
                return Err(invalid(
                    "bounded snapshot import accepts disk-only payloads without bundled images or volumes",
                ));
            }
        }

        let metadata = path.file_name().is_some_and(|name| {
            matches!(
                name.to_str(),
                Some("archive.json" | "snapshot.json" | "manifest.json" | "metadata.json")
            )
        });
        if !metadata && logical_bytes > self.maximum_disk {
            return Err(invalid(
                "snapshot import member exceeds the maximum disk size",
            ));
        }

        Ok(())
    }

    fn validate_archive(&self, snapshots: usize, complete: bool) -> MicrosandboxResult<()> {
        if snapshots != 1 || !complete {
            return Err(invalid(
                "bounded import requires one complete snapshot without dependencies",
            ));
        }

        Ok(())
    }

    fn validate_manifest(&self, manifest: &SnapshotManifest) -> MicrosandboxResult<()> {
        let file = manifest
            .state
            .as_file()
            .ok_or_else(|| invalid("bounded import requires a disk-only snapshot"))?;

        if file.virtual_size == 0 || file.virtual_size > self.maximum_disk {
            return Err(invalid("snapshot import exceeds the maximum disk size"));
        }
        if file.layers.len() != 1 || file.disk_format != SnapshotFormat::Raw {
            return Err(invalid(
                "bounded import requires one self-contained raw disk",
            ));
        }

        let layer = &file.layers[0];
        if layer.format != SnapshotFormat::Raw
            || layer.virtual_size != file.virtual_size
            || layer.backing.is_some()
        {
            return Err(invalid(
                "bounded import requires one self-contained raw disk",
            ));
        }
        if !manifest.owned_volumes()?.is_empty() {
            return Err(invalid("bounded import does not accept owned volumes"));
        }

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Reserve extraction, layer placement, normalization and publication copies.
/// No reflink support is assumed. Metadata and per-entry filesystem allocation
/// are included separately from the maximum virtual disk size.
pub(crate) fn peak_bytes(maximum_disk: u64) -> MicrosandboxResult<u64> {
    if maximum_disk == 0 {
        return Err(invalid("snapshot maximum disk size must be positive"));
    }

    let metadata = METADATA_FILES * MAX_METADATA_BYTES;
    let entries = MAX_ENTRIES as u64 * ENTRY_ALLOCATION_BYTES;
    maximum_disk
        .checked_add(metadata)
        .and_then(|bytes| bytes.checked_mul(IMPORT_COPIES))
        .and_then(|bytes| bytes.checked_add(entries))
        .ok_or_else(|| invalid("snapshot import byte bound overflow"))
}

fn invalid(message: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(message.into())
}
