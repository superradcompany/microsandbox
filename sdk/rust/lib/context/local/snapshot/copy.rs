//! Private snapshot payload copies and archive copies that retain source provenance.

use std::collections::BTreeMap;
#[cfg(target_os = "macos")]
use std::ffi::CString;
#[cfg(unix)]
use std::fs::Permissions;
use std::fs::{self, File};
use std::io;
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use microsandbox_utils::copy::copy_file_handles;
use microsandbox_utils::private_file;
#[cfg(any(target_os = "macos", windows))]
use tempfile::TempPath;
use tempfile::{Builder, TempDir};

use super::artifact::Snapshot;
use crate::snapshot::{Manifest, SnapshotId, SnapshotState};
use crate::{MicrosandboxError, MicrosandboxResult, Operation, UnsupportedReason};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Start staging with restricted permissions and clear inherited ACLs before placing data inside.
pub(super) fn private_staging(parent: &Path, prefix: &str, suffix: &str) -> io::Result<TempDir> {
    let mut builder = Builder::new();
    builder.prefix(prefix).suffix(suffix);

    #[cfg(unix)]
    builder.permissions(Permissions::from_mode(0o700));

    let stage = builder.tempdir_in(parent)?;
    private_file::harden_existing_directory(stage.path())?;

    Ok(stage)
}

/// Copy a payload to a new, owner-private inode. Keep clones and sparse copies independent.
pub(super) fn copy_private_payload(source: &Path, destination: &Path) -> io::Result<()> {
    let source = File::open(source)?;

    #[cfg(any(target_os = "macos", windows))]
    {
        // Darwin clones inherit file modes and Windows files inherit the parent's ACL.
        // Expose the final name only after its contents and permissions are ready.
        let parent = destination
            .parent()
            .ok_or_else(|| io::Error::other("missing copy parent"))?;
        let stage = private_staging(parent, ".copy-", "")?;
        let staged = stage.path().join("payload");

        #[cfg(target_os = "macos")]
        let cloned = clone_private_payload(&source, &staged)?;
        #[cfg(windows)]
        let cloned = false;

        if !cloned {
            copy_private_fallback(&source, &staged, copy_file_handles)?;
        }

        TempPath::try_from_path(staged)?.persist_noclobber(destination)?;
        Ok(())
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    {
        // Linux's descriptor copy first attempts FICLONE into the already-private inode.
        copy_private_fallback(&source, destination, copy_file_handles)
    }
}

#[cfg(target_os = "macos")]
fn clone_private_payload(source: &File, staged: &Path) -> io::Result<bool> {
    // Darwin's sys/clonefile.h flag keeps the new inode owned by the copying account.
    const CLONE_NOOWNERCOPY: u32 = 0x0002;

    let path = CString::new(staged.as_os_str().as_bytes())?;

    // fclonefileat creates its destination; the enclosing private stage hides the inherited mode.
    let rc = unsafe {
        libc::fclonefileat(
            source.as_raw_fd(),
            libc::AT_FDCWD,
            path.as_ptr(),
            CLONE_NOOWNERCOPY,
        )
    };
    if rc != 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOTSUP | libc::EOPNOTSUPP | libc::EXDEV | libc::EINVAL | libc::ENOSYS) => {
                Ok(false)
            }
            _ => Err(error),
        };
    }

    private_file::harden_existing_file(staged)?;
    File::open(staged)?.sync_all()?;

    Ok(true)
}

fn copy_private_fallback<T>(
    source: &File,
    destination: &Path,
    transfer: impl FnOnce(&File, &File) -> io::Result<T>,
) -> io::Result<()> {
    let target = private_file::create_new_read_write(destination)?;

    if let Err(error) = transfer(source, &target) {
        drop(target);
        let _ = fs::remove_file(destination);
        return Err(error);
    }

    Ok(())
}

/// Copy disk state without installing or indexing an intermediate snapshot.
pub(super) async fn copy_snapshot_archive(
    snapshot: &Snapshot,
    output_archive_path: &Path,
    labels: BTreeMap<String, String>,
    record_integrity: bool,
) -> MicrosandboxResult<Manifest> {
    let source = snapshot.path();
    let mut manifest = snapshot.manifest().clone();
    let SnapshotState::File(file) = &mut manifest.state else {
        return Err(MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable("copying checkpoint-state snapshots is not supported; use save_to to export a full snapshot".into()),
        ));
    };
    let mut sources = Vec::with_capacity(file.layers.len());
    for layer in &mut file.layers {
        let path = snapshot.layer_path(layer);
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
    use crate::SaveOpts;
    use crate::context::LocalContext;

    #[cfg(unix)]
    #[test]
    fn fallback_payload_is_private_before_transfer() {
        use std::os::unix::fs::MetadataExt;

        let root = tempfile::tempdir().unwrap();
        let stage = super::private_staging(root.path(), ".capture-", "").unwrap();
        assert_eq!(
            super::fs::metadata(stage.path()).unwrap().mode() & 0o777,
            0o700
        );

        let source = root.path().join("source");
        let target = stage.path().join("payload");
        super::fs::write(&source, b"checkpoint bytes").unwrap();

        super::copy_private_fallback(&super::File::open(source).unwrap(), &target, |src, dst| {
            // Observe the actual production destination before the first byte is transferred.
            let visible = super::fs::metadata(&target)?;
            assert_eq!(visible.ino(), dst.metadata()?.ino());
            assert_eq!(visible.len(), 0);
            assert_eq!(visible.mode() & 0o777, 0o600);

            super::private_file::verify(dst)?;
            super::copy_file_handles(src, dst)
        })
        .unwrap();

        assert_eq!(super::fs::read(target).unwrap(), b"checkpoint bytes");
    }

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
        let backend = LocalContext::builder()
            .home(temp.path().join("home"))
            .build()
            .unwrap();
        async {
            let destination: std::sync::Arc<dyn crate::Context> = (backend).into();

            let snapshot = destination
                .checkpoints()
                .open(source.to_string_lossy())
                .await
                .unwrap();
            let manifest = snapshot.manifest().await.unwrap();
            let file = manifest.state.as_file().unwrap();
            assert_eq!(
                snapshot.layer_path(&file.layers[0]).await.unwrap(),
                source.join("disk.ext4")
            );
            snapshot.verify().await.unwrap();
            let archive = temp.path().join("previous.tar.zst");
            snapshot
                .save_to(&archive, SaveOpts::default())
                .await
                .unwrap();
            let imported = destination
                .checkpoints()
                .load(&archive, None)
                .await
                .unwrap();
            let copy = temp.path().join("copy.tar.zst");
            let manifest = imported
                .copy_to(&copy)
                .record_integrity(true)
                .save()
                .await
                .unwrap();
            let copied = destination.checkpoints().load(&copy, None).await.unwrap();
            assert_eq!(copied.manifest().await.unwrap(), manifest);
            assert!(copied.verify().await.is_ok());
            let manifest = copied.manifest().await.unwrap();
            let file = manifest.state.as_file().unwrap();
            assert_eq!(
                std::fs::read(copied.layer_path(&file.layers[0]).await.unwrap()).unwrap(),
                b"payload"
            );
        }
        .await;
        assert_eq!(std::fs::read(path).unwrap(), descriptor);
        assert_eq!(std::fs::read(source.join("disk.ext4")).unwrap(), b"payload");
        assert_eq!(
            std::fs::read(source.join("upper.ext4")).unwrap(),
            b"decoy!!"
        );
    }
}
