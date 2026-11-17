//! Optional size limits passed explicitly through snapshot archive extraction.

use microsandbox_types::SnapshotManifest;

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(crate) struct ImportBudget {
    maximum_disk_bytes: u64,
    remaining_bytes: u64,
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
            remaining_bytes: maximum_disk_bytes,
        })
    }

    pub(crate) fn charge(&mut self, bytes: u64) -> MicrosandboxResult<()> {
        self.remaining_bytes = self.remaining_bytes.checked_sub(bytes).ok_or_else(|| {
            invalid("snapshot import exceeds its maximum disk size (expanded file bytes)")
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
