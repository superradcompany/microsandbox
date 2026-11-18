//! Guest paths of external mounts that a disk snapshot does not carry.

use serde::{Deserialize, Serialize};

use super::Manifest;
use crate::error::{SnapshotManifestError, SnapshotManifestResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Optional (not must-understand) key listing guest paths whose host-side backing is not captured.
pub const EXTERNAL_MOUNTS_EXTENSION: &str = "microsandbox.external-mounts";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExternalMountsExtension {
    guest_paths: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Manifest {
    /// Record the guest paths of source mounts this snapshot does not carry. Never host paths.
    ///
    /// The extension is advisory for older readers, so it is never added to `requires`.
    pub fn set_external_mounts(
        &mut self,
        mut guest_paths: Vec<String>,
    ) -> SnapshotManifestResult<()> {
        guest_paths.sort();
        guest_paths.dedup();

        if guest_paths.is_empty() {
            self.extensions.remove(EXTERNAL_MOUNTS_EXTENSION);
            return Ok(());
        }

        let value = serde_json::to_value(ExternalMountsExtension { guest_paths })
            .map_err(|error| SnapshotManifestError::ManifestParse(error.to_string()))?;
        self.extensions
            .insert(EXTERNAL_MOUNTS_EXTENSION.into(), value);

        Ok(())
    }

    /// Read the recorded guest paths; snapshots without the extension record none.
    pub fn external_mounts(&self) -> SnapshotManifestResult<Vec<String>> {
        let Some(value) = self.extensions.get(EXTERNAL_MOUNTS_EXTENSION) else {
            return Ok(Vec::new());
        };

        let extension: ExternalMountsExtension =
            serde_json::from_value(value.clone()).map_err(|error| {
                SnapshotManifestError::ManifestParse(format!("invalid external mounts: {error}"))
            })?;

        Ok(extension.guest_paths)
    }
}
