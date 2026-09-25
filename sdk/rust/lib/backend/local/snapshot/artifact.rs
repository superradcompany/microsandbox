//! Local snapshot metadata; storage operations stay in their owning backend.

use crate::MicrosandboxResult;
use crate::snapshot::{DiskLayer, HeadUpdate, Manifest, SnapshotFormat, SnapshotId, SnapshotScope};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A snapshot artifact on disk.
///
/// The directory holds the canonical descriptor and complete local payload closure.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub(super) path: PathBuf,
    pub(super) digest: String,
    pub(super) manifest: Manifest,
    pub(super) labels: BTreeMap<String, String>,
    pub(super) head_update: Option<HeadUpdate>,
    /// Exact payload named by a previous flat descriptor, without rewriting its source.
    pub(super) previous_upper: Option<PathBuf>,
}

impl Snapshot {
    /// Verify the local closure through the single local verification engine.
    pub async fn verify(&self) -> MicrosandboxResult<crate::snapshot::SnapshotVerifyReport> {
        super::verify::verify_snapshot(self).await
    }

    /// Path to the artifact directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Stable opaque snapshot identity.
    pub fn id(&self) -> &SnapshotId {
        &self.manifest.snapshot_id
    }

    /// SHA-256 digest of the canonical descriptor bytes.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Parsed manifest.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Mutable local labels, which do not participate in descriptor identity.
    pub fn labels(&self) -> &BTreeMap<String, String> {
        &self.labels
    }

    /// Apparent size of a file-state upper layer in bytes.
    pub fn size_bytes(&self) -> Option<u64> {
        self.manifest
            .state
            .as_file()
            .map(|state| state.virtual_size)
    }

    /// Resolve a physical layer through the final layout or the exact
    /// released flat-artifact compatibility binding.
    pub(crate) fn layer_path(&self, layer: &DiskLayer) -> PathBuf {
        let canonical = self.path.join(microsandbox_image::snapshot::layer_path(
            &layer.layer_id,
            layer.format,
        ));
        if canonical.exists() {
            canonical
        } else if let Some(path) = &self.previous_upper {
            path.clone()
        } else if self
            .manifest
            .state
            .as_file()
            .is_some_and(|file| file.layers.len() == 1)
            && self.path.join("upper.ext4").exists()
        {
            self.path.join("upper.ext4")
        } else {
            canonical
        }
    }
}
/// Lightweight handle backed by an index row.
///
/// The backend adapter wraps this projection with its owning backend and exact path.
#[derive(Debug, Clone)]
pub struct SnapshotHandle {
    pub(crate) group: Option<String>,
    pub(crate) head_update: Option<HeadUpdate>,
    pub(crate) snapshot_id: String,
    pub(crate) digest: String,
    pub(crate) name: Option<String>,
    pub(crate) parent_digest: Option<String>,
    pub(crate) scope: SnapshotScope,
    pub(crate) image_ref: String,
    pub(crate) state_kind: String,
    pub(crate) format: Option<SnapshotFormat>,
    pub(crate) fstype: Option<String>,
    pub(crate) checkpoint_manifest_digest: Option<String>,
    pub(crate) size_bytes: Option<u64>,
    pub(crate) locality: String,
    pub(crate) availability: String,
    pub(crate) migration_state: String,
    pub(crate) migration_error_code: Option<String>,
    pub(crate) created_at: chrono::NaiveDateTime,
    pub(crate) artifact_path: PathBuf,
}

#[cfg(test)]
impl SnapshotHandle {
    /// Group publication outcome, present when this handle was returned by import.
    pub fn head_update(&self) -> Option<&HeadUpdate> {
        self.head_update.as_ref()
    }
    /// Local group containing this installed copy, if any.
    pub fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }
    /// Stable opaque snapshot identity.
    pub fn id(&self) -> &str {
        &self.snapshot_id
    }

    /// SHA-256 digest of the canonical descriptor.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Local artifact directory path.
    pub fn path(&self) -> &Path {
        &self.artifact_path
    }
}
impl Snapshot {
    pub(crate) fn from_parts(
        path: PathBuf,
        digest: String,
        manifest: Manifest,
        labels: BTreeMap<String, String>,
    ) -> Self {
        Self {
            path,
            digest,
            manifest,
            labels,
            head_update: None,
            previous_upper: None,
        }
    }
}
