//! The released flat descriptor's existing deterministic identity projection.
//!
//! This module describes an SDK view of a legacy artifact. It does not publish a
//! new artifact or replace a provider's resource identifier or descriptor digest.

use crate::error::{SnapshotManifestError, SnapshotManifestResult};

use super::cloud_manifest;
use super::{
    DiskLayer, DiskLayerId, FileSnapshotState, ImageRef, LayerFileKind, LayerPayload, Manifest,
    SCHEMA, SnapshotCapture, SnapshotConsistency, SnapshotFormat, SnapshotId, SnapshotRootDisk,
    SnapshotScope, SnapshotState, UpperIntegrity,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Preserve the released importer's mapping from descriptor digest to portable identity.
pub fn snapshot_id(digest: &str) -> SnapshotManifestResult<SnapshotId> {
    SnapshotId::new(format!("snap_{}", &digest_hex(digest)?[..32]))
}

/// Preserve the released importer's mapping from descriptor digest to its single layer.
pub fn layer_id(digest: &str) -> SnapshotManifestResult<DiskLayerId> {
    DiskLayerId::new(format!("layer_{}", &digest_hex(digest)?[32..]))
}

/// Project a validated cloud wire descriptor without changing its source identity.
///
/// Callers retain the provider's reference and source digest separately. The returned
/// value must never be serialized back to an endpoint expecting the legacy wire shape.
pub fn project_cloud_descriptor(
    source: &cloud_manifest::Manifest,
    source_digest: &str,
) -> SnapshotManifestResult<Manifest> {
    source.validate()?;
    if source.digest()? != source_digest {
        return invalid("cloud descriptor does not match its reported digest");
    }
    let cloud_manifest::SnapshotState::File(file) = &source.state else {
        return invalid("cloud descriptor projection requires supported disk state");
    };
    let layer_id = layer_id(source_digest)?;
    let format = match file.format {
        cloud_manifest::SnapshotFormat::Raw => SnapshotFormat::Raw,
        cloud_manifest::SnapshotFormat::Qcow2 => SnapshotFormat::Qcow2,
    };
    let integrity = file
        .upper
        .integrity
        .as_ref()
        .map(|integrity| match integrity {
            cloud_manifest::UpperIntegrity::Sha256 { digest } => UpperIntegrity::Sha256 {
                digest: digest.clone(),
            },
            cloud_manifest::UpperIntegrity::SparseSha256V1 { digest } => {
                UpperIntegrity::SparseSha256V1 {
                    digest: digest.clone(),
                }
            }
            cloud_manifest::UpperIntegrity::FileMerkleBlake3V1 {
                root,
                logical_size,
                leaf_size,
            } => UpperIntegrity::FileMerkleBlake3V1 {
                root: root.clone(),
                logical_size: *logical_size,
                leaf_size: *leaf_size,
            },
        });
    let projected = Manifest {
        schema: SCHEMA.into(),
        snapshot_id: snapshot_id(source_digest)?,
        scope: SnapshotScope::Disk,
        state: SnapshotState::File(FileSnapshotState {
            disk_format: format,
            filesystem: file.fstype.clone(),
            virtual_size: file.upper.size_bytes,
            head: layer_id.clone(),
            layers: vec![DiskLayer {
                layer_id,
                format,
                virtual_size: file.upper.size_bytes,
                backing: None,
                payload: LayerPayload {
                    file_kind: LayerFileKind::Regular,
                    integrity,
                },
            }],
        }),
        capture: SnapshotCapture {
            created_at: source.created_at.clone(),
            source_lineage: source.source_sandbox.clone(),
            source_checkpoint: None,
            consistency: SnapshotConsistency::CrashConsistent,
        },
        image: ImageRef {
            reference: source.image.reference.clone(),
            manifest_digest: source.image.manifest_digest.clone(),
        },
        root_disk: SnapshotRootDisk::Managed,
        parent: source.parent.as_deref().map(snapshot_id).transpose()?,
        requires: source.requires.clone(),
        extensions: source.extensions.clone(),
    };
    projected.validate()?;
    Ok(projected)
}

fn digest_hex(digest: &str) -> SnapshotManifestResult<&str> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return invalid("legacy descriptor digest is not sha256");
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return invalid("legacy descriptor digest is not lowercase sha256");
    }
    Ok(hex)
}

fn invalid<T>(message: &str) -> SnapshotManifestResult<T> {
    Err(SnapshotManifestError::ManifestParse(message.into()))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn released_identity_mapping_uses_the_same_digest_halves() {
        let digest = format!("sha256:{}{}", "a".repeat(32), "b".repeat(32));
        assert_eq!(
            snapshot_id(&digest).unwrap().as_str(),
            format!("snap_{}", "a".repeat(32))
        );
        assert_eq!(
            layer_id(&digest).unwrap().as_str(),
            format!("layer_{}", "b".repeat(32))
        );
        for invalid in ["", "sha256:short", "sha512:abcd"] {
            assert!(snapshot_id(invalid).is_err());
            assert!(layer_id(invalid).is_err());
        }
    }
}
