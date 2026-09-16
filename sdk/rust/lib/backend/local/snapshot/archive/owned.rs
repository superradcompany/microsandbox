//! Local backend: Archive closure members for required sandbox-owned storage.

use std::path::{Path, PathBuf};

use microsandbox_image::snapshot::{OwnedVolumeCapture, OwnedVolumeData};

use crate::{MicrosandboxError, MicrosandboxResult};

use super::CheckpointArchiveMember;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn members(
    snapshot_id: &str,
    source: &Path,
    volumes: &[OwnedVolumeCapture],
    checkpoint: bool,
) -> MicrosandboxResult<Vec<CheckpointArchiveMember>> {
    microsandbox_image::snapshot::verify_owned_directory_payloads(source, volumes)?;
    let namespace = if checkpoint {
        "checkpoints"
    } else {
        "snapshots"
    };
    let prefix = format!("{namespace}/{snapshot_id}");
    let mut members = Vec::new();
    for volume in volumes {
        for (path, payload) in volume.directory_payloads() {
            members.push(CheckpointArchiveMember {
                source: source.join(&path),
                archive_path: format!("{prefix}/{}", super::portable_archive_path(&path)?),
                apparent_size: payload.bytes,
                kind: "owned-directory-payload",
            });
        }
        // Full checkpoint disk layers already belong to its normal block-device closure.
        if !checkpoint && let OwnedVolumeData::Disk { generation } = &volume.data {
            for layer in &generation.layers {
                let name = format!("{}.{}", layer.layer_id, layer.format);
                let path = source.join("layers").join(&name);
                if std::fs::metadata(&path)?.len() != layer.file_size {
                    return Err(MicrosandboxError::SnapshotIntegrity(
                        "owned disk archive source length differs".into(),
                    ));
                }
                if let Some(expected) = &layer.integrity_root
                    && microsandbox_image::checkpoint::sparse_file_integrity(&path)?.root
                        != *expected
                {
                    return Err(MicrosandboxError::SnapshotIntegrity(
                        "owned disk archive source integrity differs".into(),
                    ));
                }
                members.push(CheckpointArchiveMember {
                    apparent_size: std::fs::metadata(&path)?.len(),
                    source: path,
                    archive_path: format!("{prefix}/layers/{name}"),
                    kind: "owned-disk-layer",
                });
            }
        }
    }
    Ok(members)
}

pub(super) fn archive_target(components: &[&str], root: &Path) -> Option<PathBuf> {
    let (namespace, snapshot, relative) = match components {
        [
            namespace @ ("snapshots" | "checkpoints"),
            snapshot,
            "owned",
            tag,
            "directory.bin",
        ] if valid_tag(tag) => (
            *namespace,
            *snapshot,
            Path::new("owned").join(tag).join("directory.bin"),
        ),
        [
            namespace @ ("snapshots" | "checkpoints"),
            snapshot,
            "owned",
            tag,
            "files",
            digest,
        ] if valid_tag(tag) && super::valid_archive_digest_hex(digest) => (
            *namespace,
            *snapshot,
            Path::new("owned").join(tag).join("files").join(digest),
        ),
        ["snapshots", snapshot, "layers", name] if super::valid_checkpoint_layer_filename(name) => {
            ("snapshots", *snapshot, Path::new("layers").join(name))
        }
        _ => return None,
    };
    microsandbox_image::snapshot::SnapshotId::new(snapshot).ok()?;
    let mut target = root.join(snapshot);
    if namespace == "checkpoints" {
        target.push(super::CHECKPOINT_DIRECTORY);
    }
    Some(target.join(relative))
}

pub(super) fn valid_directory(components: &[&str]) -> bool {
    match components {
        ["snapshots" | "checkpoints", snapshot, "owned"] | ["snapshots", snapshot, "layers"] => {
            microsandbox_image::snapshot::SnapshotId::new(*snapshot).is_ok()
        }
        ["snapshots" | "checkpoints", snapshot, "owned", tag]
        | ["snapshots" | "checkpoints", snapshot, "owned", tag, "files"] => {
            microsandbox_image::snapshot::SnapshotId::new(*snapshot).is_ok() && valid_tag(tag)
        }
        _ => false,
    }
}

fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 128
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}
