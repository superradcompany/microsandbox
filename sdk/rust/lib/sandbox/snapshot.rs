//! Capture a new source-bound history from an existing sandbox.

use crate::MicrosandboxResult;
use crate::snapshot::{Snapshot, SnapshotCaptureOptions, SnapshotCreateResult};

use super::Sandbox;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Create a new history and its initial disk checkpoint. Existing group names are refused.
    pub async fn snapshot(&self, group: &str) -> MicrosandboxResult<SnapshotCreateResult> {
        self.snapshot_with(group, |capture| capture).await
    }

    /// Configure initial capture while retaining this sandbox's backend and source identity.
    pub async fn snapshot_with(
        &self,
        group: &str,
        configure: impl FnOnce(SnapshotCaptureOptions) -> SnapshotCaptureOptions,
    ) -> MicrosandboxResult<SnapshotCreateResult> {
        Snapshot::create_for(
            self.backend.clone(),
            &self.name,
            self.id(),
            group,
            configure(SnapshotCaptureOptions::default()),
        )
        .await
    }
}
