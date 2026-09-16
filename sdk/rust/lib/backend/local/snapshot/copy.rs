//! Snapshot archive copies retain the complete physical closure and source provenance.

use std::collections::BTreeMap;
use std::path::Path;

use crate::snapshot::{Manifest, Snapshot, SnapshotId, SnapshotState};
use crate::{MicrosandboxError, MicrosandboxResult, Operation, UnsupportedReason};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Copy disk state without installing or indexing an intermediate snapshot.
pub(super) async fn copy_snapshot_archive(
    snapshot: &Snapshot,
    output_archive_path: &Path,
    labels: BTreeMap<String, String>,
    record_integrity: bool,
) -> MicrosandboxResult<Manifest> {
    let source = snapshot.path()?;
    let mut manifest = snapshot.manifest().clone();
    let SnapshotState::File(file) = &mut manifest.state else {
        return Err(MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable("copying checkpoint-state snapshots is not supported; use save_to to export a full snapshot".into()),
        ));
    };
    let mut sources = Vec::with_capacity(file.layers.len());
    for layer in &mut file.layers {
        let path = snapshot.layer_path(layer)?;
        layer.payload.integrity = if record_integrity {
            Some(super::verify::compute_merkle_integrity(&path).await?)
        } else {
            None
        };
        sources.push(path);
    }
    // Labels live outside the descriptor. Copying identical descriptor bytes preserves
    // portable identity; changing recorded integrity creates a new immutable descriptor.
    if manifest != *snapshot.manifest() {
        manifest.snapshot_id = SnapshotId::new(format!("snap_{:032x}", rand::random::<u128>()))?;
    }
    let suggested_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("snapshot");
    super::archive::save_direct_file_snapshot(
        &manifest,
        &labels,
        suggested_name,
        &sources,
        Some(source),
        output_archive_path,
        false,
        true,
    )
    .await?;
    Ok(manifest)
}
