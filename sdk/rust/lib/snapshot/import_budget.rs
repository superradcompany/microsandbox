//! Optional size limits passed explicitly through snapshot archive extraction.

use std::path::Path;

use microsandbox_types::SnapshotManifest;
use tokio_tar::Header;

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_METADATA_BYTES: u64 = 4 * 1024 * 1024;
const MAX_METADATA_TOTAL_BYTES: u64 = 12 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(crate) struct ImportBudget {
    maximum_disk_bytes: u64,
    remaining_payload_bytes: u64,
    remaining_metadata_bytes: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ImportBudget {
    pub(crate) fn new(maximum_disk_bytes: u64) -> MicrosandboxResult<Self> {
        if maximum_disk_bytes == 0 {
            return Err(invalid("snapshot maximum disk size must be positive"));
        }

        Ok(Self {
            maximum_disk_bytes,
            remaining_payload_bytes: maximum_disk_bytes,
            remaining_metadata_bytes: MAX_METADATA_TOTAL_BYTES,
        })
    }

    pub(crate) fn charge(&mut self, path: &Path, header: &Header) -> MicrosandboxResult<()> {
        if path.as_os_str().len() > MAX_PATH_BYTES {
            return Err(invalid("snapshot import exceeds its archive path limit"));
        }

        // GNU sparse files can encode a tiny body with a huge logical size.
        let logical_bytes = header.size()?;
        let metadata = path.file_name().is_some_and(|name| {
            matches!(
                name.to_str(),
                Some("archive.json" | "snapshot.json" | "manifest.json" | "metadata.json")
            )
        });
        if metadata {
            if logical_bytes > MAX_METADATA_BYTES {
                return Err(invalid("snapshot import exceeds its metadata size limit"));
            }
            self.remaining_metadata_bytes = self
                .remaining_metadata_bytes
                .checked_sub(logical_bytes)
                .ok_or_else(|| invalid("snapshot import exceeds its aggregate metadata limit"))?;
        } else {
            self.charge_payload(logical_bytes)?;
        }

        Ok(())
    }

    pub(crate) fn charge_payload(&mut self, bytes: u64) -> MicrosandboxResult<()> {
        self.remaining_payload_bytes =
            self.remaining_payload_bytes
                .checked_sub(bytes)
                .ok_or_else(|| {
                    invalid(
                        "snapshot import exceeds its maximum disk size (expanded payload bytes)",
                    )
                })?;
        Ok(())
    }

    pub(crate) fn validate_manifest(&self, manifest: &SnapshotManifest) -> MicrosandboxResult<()> {
        if let Some(file) = manifest.state.as_file()
            && file.virtual_size > self.maximum_disk_bytes
        {
            return Err(invalid("snapshot import exceeds its maximum disk size"));
        }

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn invalid(message: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(message.into())
}
