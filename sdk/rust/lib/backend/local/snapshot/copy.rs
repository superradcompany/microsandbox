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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::backend::{LocalBackend, with_backend};
    use crate::{SaveOpts, Snapshot};

    #[tokio::test]
    async fn previous_descriptor_exports_and_copies_without_changing_the_source() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("previous");
        std::fs::create_dir(&source).unwrap();
        let descriptor = serde_json::to_vec(&serde_json::json!({
            "schema": 1, "artifact": "snapshot", "scope": "disk",
            "created_at": "2026-05-01T12:00:00Z", "parent": null,
            "image": {"ref": "alpine:3.21", "manifest_digest": format!("sha256:{}", "a".repeat(64))},
            "source_sandbox": "previous", "labels": {"source": "previous"},
            "state": {"kind": "file", "format": "raw", "fstype": "ext4",
                "upper": {"file": "disk.ext4", "size_bytes": 7, "integrity": null}},
            "extensions": {}, "requires": []
        })).unwrap();
        let path = source.join(crate::snapshot::DESCRIPTOR_FILENAME);
        std::fs::write(&path, &descriptor).unwrap();
        std::fs::write(source.join("disk.ext4"), b"payload").unwrap();
        // A conventional name must not override the descriptor's explicit binding.
        std::fs::write(source.join("upper.ext4"), b"decoy!!").unwrap();
        let backend = LocalBackend::builder()
            .home(temp.path().join("home"))
            .build()
            .await
            .unwrap();
        with_backend(backend, async {
            let snapshot = Snapshot::open(source.to_string_lossy()).await.unwrap();
            let file = snapshot.manifest().state.as_file().unwrap();
            assert_eq!(
                snapshot.layer_path(&file.layers[0]).unwrap(),
                source.join("disk.ext4")
            );
            snapshot.verify().await.unwrap();
            let archive = temp.path().join("previous.tar.zst");
            snapshot
                .save_to(&archive, SaveOpts::default())
                .await
                .unwrap();
            let imported = Snapshot::load(&archive, None)
                .await
                .unwrap()
                .open()
                .await
                .unwrap();
            let copy = temp.path().join("copy.tar.zst");
            let manifest = imported
                .copy_to(&copy)
                .record_integrity(true)
                .save()
                .await
                .unwrap();
            let copied = Snapshot::load(&copy, None)
                .await
                .unwrap()
                .open()
                .await
                .unwrap();
            assert_eq!(copied.manifest(), &manifest);
            assert!(copied.verify().await.is_ok());
            let file = copied.manifest().state.as_file().unwrap();
            assert_eq!(
                std::fs::read(copied.layer_path(&file.layers[0]).unwrap()).unwrap(),
                b"payload"
            );
        })
        .await;
        assert_eq!(std::fs::read(path).unwrap(), descriptor);
        assert_eq!(std::fs::read(source.join("disk.ext4")).unwrap(), b"payload");
        assert_eq!(
            std::fs::read(source.join("upper.ext4")).unwrap(),
            b"decoy!!"
        );
    }
}
