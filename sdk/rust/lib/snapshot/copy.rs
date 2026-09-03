//! Snapshot archive copies with replacement metadata.

use std::collections::BTreeMap;
use std::path::PathBuf;

use super::{Manifest, Snapshot};
use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Builder for packaging a snapshot as a new archive with replacement metadata.
///
/// Created by [`Snapshot::copy_to`]. The source snapshot is never modified.
pub struct SnapshotCopyBuilder {
    snapshot: Snapshot,
    output_archive_path: PathBuf,
    labels: BTreeMap<String, String>,
    record_integrity: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SnapshotCopyBuilder {
    pub(super) fn new(snapshot: Snapshot, output_archive_path: PathBuf) -> Self {
        Self {
            snapshot,
            output_archive_path,
            labels: BTreeMap::new(),
            record_integrity: false,
        }
    }

    /// Replace the copied snapshot's labels.
    pub fn labels(mut self, labels: BTreeMap<String, String>) -> Self {
        self.labels = labels;
        self
    }

    /// Choose whether to calculate and record disk integrity in the copy.
    pub fn record_integrity(mut self, enabled: bool) -> Self {
        self.record_integrity = enabled;
        self
    }

    /// Package the configured copy and return its manifest.
    pub async fn save(self) -> MicrosandboxResult<Manifest> {
        self.snapshot
            .backend
            .snapshots()
            .copy(
                &self.snapshot,
                &self.output_archive_path,
                self.labels,
                self.record_integrity,
            )
            .await
    }
}
