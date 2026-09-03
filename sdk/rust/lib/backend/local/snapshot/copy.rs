//! Snapshot archive copies with replacement explicit-snapshot metadata.

use std::collections::BTreeMap;
use std::path::Path;

use microsandbox_types::snapshot::{DESCRIPTOR_FILENAME, Manifest, SnapshotState};

use crate::backend::LocalBackend;
use crate::snapshot::{SaveOpts, Snapshot};
use crate::{MicrosandboxError, MicrosandboxResult, Operation, UnsupportedReason};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalBackend {
    /// Package one snapshot as a new archive without changing the source artifact.
    pub(super) async fn copy_snapshot_archive(
        &self,
        snapshot: &Snapshot,
        output_archive_path: &Path,
        labels: BTreeMap<String, String>,
        record_integrity: bool,
    ) -> MicrosandboxResult<Manifest> {
        let source_artifact_path = super::artifact_path(snapshot)?;
        let mut manifest = snapshot.manifest().clone();
        let upper_file = match &manifest.state {
            SnapshotState::File(state) => state.upper.file.clone(),
            SnapshotState::Checkpoint(_) => {
                return Err(MicrosandboxError::unsupported(
                    Operation::SnapshotOps,
                    UnsupportedReason::NotAvailable(
                        "copying checkpoint-state snapshots is not supported".into(),
                    ),
                ));
            }
        };

        manifest.labels = labels;
        let integrity = if record_integrity {
            Some(
                super::verify::compute_merkle_integrity(&source_artifact_path.join(&upper_file))
                    .await?,
            )
        } else {
            None
        };
        let SnapshotState::File(state) = &mut manifest.state else {
            unreachable!("file state was checked above")
        };
        state.upper.integrity = integrity;

        let digest = manifest
            .digest()
            .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
        let staging_parent = source_artifact_path.parent().ok_or_else(|| {
            MicrosandboxError::InvalidConfig("snapshot artifact has no parent directory".into())
        })?;
        let staging = tempfile::Builder::new()
            .prefix(".msb-snapshot-copy-")
            .tempdir_in(staging_parent)?;
        let artifact_path = staging.path().join(digest.trim_start_matches("sha256:"));
        tokio::fs::create_dir(&artifact_path).await?;

        write_manifest(&artifact_path, &manifest).await?;
        tokio::fs::hard_link(
            source_artifact_path.join(&upper_file),
            artifact_path.join(&upper_file),
        )
        .await?;
        self.save_snapshot_archive(
            artifact_path.to_string_lossy().as_ref(),
            output_archive_path,
            SaveOpts::default(),
        )
        .await?;

        Ok(manifest)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Write the canonical descriptor for a staged snapshot artifact.
async fn write_manifest(artifact_path: &Path, manifest: &Manifest) -> MicrosandboxResult<()> {
    let canonical = manifest
        .to_canonical_bytes()
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let descriptor_path = artifact_path.join(DESCRIPTOR_FILENAME);
    tokio::fs::write(&descriptor_path, canonical).await?;
    let descriptor = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&descriptor_path)
        .await?;
    descriptor.sync_all().await?;

    Ok(())
}
