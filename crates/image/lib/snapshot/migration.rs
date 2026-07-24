//! Pure adjacent-release snapshot descriptor translation.
//!
//! This module deliberately does not expose the v0.6.6 manifest as a reader.
//! Callers can only translate exact legacy bytes into the final descriptor or
//! reverse a representable final file descriptor for adjacent downgrade.

use std::collections::BTreeMap;
use std::path::{Component, Path};

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};

use crate::error::{ImageError, ImageResult};

use super::{
    FileSnapshotState, ImageRef, Manifest, SCHEMA_VERSION, SNAPSHOT_ARTIFACT_KIND,
    SPARSE_SHA256_V1, SnapshotFormat, SnapshotScope, SnapshotState, UpperIntegrity, UpperLayer,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Exact released descriptor filename accepted by the adjacent migrator.
pub const V066_DESCRIPTOR_FILENAME: &str = "manifest.json";

/// Inert downgrade backup retained beside migrated artifacts.
pub const V066_BACKUP_FILENAME: &str = ".manifest.json.legacy";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Payload identities computed through the migration's pinned file handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V066PayloadIdentity {
    /// Apparent payload size.
    pub size_bytes: u64,
    /// Mandatory final sparse semantic integrity.
    pub sparse_integrity: UpperIntegrity,
    /// Ordinary SHA-256 over logical bytes, used only to verify a legacy
    /// descriptor that recorded that older optional algorithm.
    pub sha256: String,
}

/// Bounded planning metadata exposed to the host migrator without exposing the
/// legacy manifest model as a general snapshot reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V066SourceInfo {
    /// Canonical legacy identity.
    pub source_digest: String,
    /// Legacy parent identity.
    pub parent_digest: Option<String>,
    /// Confined payload filename.
    pub upper_file: String,
    /// Recorded apparent payload size.
    pub size_bytes: u64,
}

/// Deterministic forward translation result.
#[derive(Debug, Clone)]
pub struct V066ForwardTranslation {
    /// Canonical exact-shape legacy bytes retained for downgrade.
    pub source_bytes: Vec<u8>,
    /// Identity of the legacy descriptor.
    pub source_digest: String,
    /// Legacy parent identity before graph rewriting.
    pub source_parent_digest: Option<String>,
    /// Final normalized descriptor.
    pub target: Manifest,
    /// Final snapshot identity.
    pub target_digest: String,
}

/// Deterministic reverse translation result for native final file state.
#[derive(Debug, Clone)]
pub struct V066ReverseTranslation {
    /// Canonical v0.6.6 descriptor bytes.
    pub target_bytes: Vec<u8>,
    /// Canonical v0.6.6 descriptor identity.
    pub target_digest: String,
}

/// Exact private model released by v0.6.6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct V066SnapshotManifest {
    schema: u32,
    format: SnapshotFormat,
    fstype: String,
    image: ImageRef,
    #[serde(deserialize_with = "deserialize_required_option")]
    parent: Option<String>,
    created_at: String,
    labels: BTreeMap<String, String>,
    upper: V066UpperLayer,
    #[serde(deserialize_with = "deserialize_required_option")]
    source_sandbox: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct V066UpperLayer {
    file: String,
    size_bytes: u64,
    #[serde(deserialize_with = "deserialize_required_option")]
    integrity: Option<UpperIntegrity>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Translate exact v0.6.6 descriptor bytes into final schema-1 file state.
///
/// `target_parent_digest` must already contain the parent-first graph mapping.
pub fn translate_v066_forward(
    source: &[u8],
    payload: &V066PayloadIdentity,
    target_parent_digest: Option<String>,
) -> ImageResult<V066ForwardTranslation> {
    let legacy = parse_v066(source)?;
    validate_v066_payload_binding(&legacy, payload)?;

    let source_bytes = serde_json::to_vec(&legacy).map_err(legacy_serialize_error)?;
    let source_digest = sha256_digest(&source_bytes);
    let source_parent_digest = legacy.parent.clone();
    let target = Manifest {
        schema: SCHEMA_VERSION,
        artifact: SNAPSHOT_ARTIFACT_KIND.into(),
        scope: SnapshotScope::Disk,
        created_at: legacy.created_at,
        parent: target_parent_digest,
        image: legacy.image,
        source_sandbox: legacy.source_sandbox,
        state: SnapshotState::File(FileSnapshotState {
            format: legacy.format,
            fstype: legacy.fstype,
            upper: UpperLayer {
                file: legacy.upper.file,
                size_bytes: payload.size_bytes,
                integrity: payload.sparse_integrity.clone(),
            },
        }),
        labels: legacy.labels,
        extensions: BTreeMap::new(),
        requires: Vec::new(),
    };
    let target_bytes = target.to_canonical_bytes()?;
    let target_digest = sha256_digest(&target_bytes);

    Ok(V066ForwardTranslation {
        source_bytes,
        source_digest,
        source_parent_digest,
        target,
        target_digest,
    })
}

/// Inspect only the fields required to plan safe host migration.
pub fn inspect_v066_source(source: &[u8]) -> ImageResult<V066SourceInfo> {
    let manifest = parse_v066(source)?;
    let canonical = serde_json::to_vec(&manifest).map_err(legacy_serialize_error)?;
    Ok(V066SourceInfo {
        source_digest: sha256_digest(&canonical),
        parent_digest: manifest.parent,
        upper_file: manifest.upper.file,
        size_bytes: manifest.upper.size_bytes,
    })
}

/// Reverse a representable native final descriptor into exact v0.6.6 shape.
pub fn translate_v066_reverse(
    source: &Manifest,
    target_parent_digest: Option<String>,
) -> ImageResult<V066ReverseTranslation> {
    source.validate()?;
    if source.scope != SnapshotScope::Disk {
        return legacy_error("snapshot_downgrade_unrepresentable: scope is not disk");
    }
    if !source.requires.is_empty() || !source.extensions.is_empty() {
        return legacy_error(
            "snapshot_downgrade_unrepresentable: extensions are not representable in v0.6.6",
        );
    }
    let SnapshotState::File(file) = &source.state else {
        return legacy_error(
            "snapshot_downgrade_unrepresentable: checkpoint state is not supported by v0.6.6",
        );
    };
    if file.format != SnapshotFormat::Raw || file.fstype != "ext4" {
        return legacy_error(
            "snapshot_downgrade_unrepresentable: only raw ext4 file state is supported",
        );
    }
    if file.upper.integrity.algorithm != SPARSE_SHA256_V1 {
        return legacy_error(
            "snapshot_downgrade_unrepresentable: payload integrity is not supported by v0.6.6",
        );
    }

    let legacy = V066SnapshotManifest {
        schema: 1,
        format: file.format,
        fstype: file.fstype.clone(),
        image: source.image.clone(),
        parent: target_parent_digest,
        created_at: source.created_at.clone(),
        labels: source.labels.clone(),
        upper: V066UpperLayer {
            file: file.upper.file.clone(),
            size_bytes: file.upper.size_bytes,
            integrity: Some(file.upper.integrity.clone()),
        },
        source_sandbox: source.source_sandbox.clone(),
    };
    validate_v066(&legacy)?;
    let target_bytes = serde_json::to_vec(&legacy).map_err(legacy_serialize_error)?;
    let target_digest = sha256_digest(&target_bytes);
    Ok(V066ReverseTranslation {
        target_bytes,
        target_digest,
    })
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn parse_v066(source: &[u8]) -> ImageResult<V066SnapshotManifest> {
    let manifest: V066SnapshotManifest = serde_json::from_slice(source).map_err(|error| {
        ImageError::ManifestParse(format!(
            "legacy_descriptor_malformed: v0.6.6 snapshot manifest parse failed: {error}"
        ))
    })?;
    validate_v066(&manifest)?;
    Ok(manifest)
}

fn validate_v066(manifest: &V066SnapshotManifest) -> ImageResult<()> {
    if manifest.schema != 1 {
        return legacy_error("unsupported_legacy_schema: expected schema 1");
    }
    if manifest.format != SnapshotFormat::Raw || manifest.fstype != "ext4" {
        return legacy_error("unsupported_legacy_layout: expected raw ext4 payload");
    }
    if manifest.image.reference.is_empty() {
        return legacy_error("legacy_descriptor_malformed: empty image.ref");
    }
    validate_digest(&manifest.image.manifest_digest, "image.manifest_digest")?;
    if let Some(parent) = manifest.parent.as_deref() {
        validate_digest(parent, "parent")?;
    }
    validate_filename(&manifest.upper.file)?;
    if let Some(integrity) = &manifest.upper.integrity {
        if !matches!(integrity.algorithm.as_str(), "sha256" | SPARSE_SHA256_V1) {
            return legacy_error("legacy_integrity_unsupported");
        }
        validate_digest(&integrity.digest, "upper.integrity.digest")?;
    }
    // The final descriptor parser performs full RFC3339 normalization. Parse
    // through a temporary translation so malformed legacy timestamps fail
    // before any filesystem publication.
    chrono::DateTime::parse_from_rfc3339(&manifest.created_at).map_err(|error| {
        ImageError::ManifestParse(format!(
            "legacy_descriptor_malformed: created_at is not RFC3339: {error}"
        ))
    })?;
    Ok(())
}

fn validate_v066_payload_binding(
    manifest: &V066SnapshotManifest,
    payload: &V066PayloadIdentity,
) -> ImageResult<()> {
    if manifest.upper.size_bytes != payload.size_bytes {
        return legacy_error(format!(
            "legacy_payload_size_mismatch: descriptor={}, file={}",
            manifest.upper.size_bytes, payload.size_bytes
        ));
    }
    if payload.sparse_integrity.algorithm != SPARSE_SHA256_V1 {
        return legacy_error("legacy_integrity_unsupported: planned sparse identity is invalid");
    }
    if let Some(recorded) = &manifest.upper.integrity {
        let computed = match recorded.algorithm.as_str() {
            "sha256" => &payload.sha256,
            SPARSE_SHA256_V1 => &payload.sparse_integrity.digest,
            _ => return legacy_error("legacy_integrity_unsupported"),
        };
        if recorded.digest != *computed {
            return legacy_error("legacy payload integrity mismatch");
        }
    }
    Ok(())
}

fn validate_digest(value: &str, field: &str) -> ImageResult<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return legacy_error(format!(
            "legacy_descriptor_malformed: {field} is not sha256"
        ));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return legacy_error(format!(
            "legacy_descriptor_malformed: {field} is not lowercase sha256"
        ));
    }
    Ok(())
}

fn validate_filename(value: &str) -> ImageResult<()> {
    let mut components = Path::new(value).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return legacy_error("legacy_descriptor_malformed: upper.file is not confined");
    }
    if matches!(
        value,
        V066_DESCRIPTOR_FILENAME
            | V066_BACKUP_FILENAME
            | super::DESCRIPTOR_FILENAME
            | ".snapshot-migration.lock"
    ) {
        return legacy_error("legacy_descriptor_malformed: upper.file uses a reserved name");
    }
    Ok(())
}

fn sha256_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn legacy_error<T>(message: impl Into<String>) -> ImageResult<T> {
    Err(ImageError::ManifestParse(message.into()))
}

fn legacy_serialize_error(error: serde_json::Error) -> ImageError {
    ImageError::ManifestParse(format!(
        "v0.6.6 snapshot manifest serialize failed: {error}"
    ))
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY: &[u8] = br#"{"schema":1,"format":"raw","fstype":"ext4","image":{"ref":"docker.io/library/alpine:3.20","manifest_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"parent":null,"created_at":"2026-07-01T10:00:00Z","labels":{},"upper":{"file":"upper.ext4","size_bytes":5,"integrity":null},"source_sandbox":"box"}"#;

    fn payload() -> V066PayloadIdentity {
        V066PayloadIdentity {
            size_bytes: 5,
            sparse_integrity: UpperIntegrity {
                algorithm: SPARSE_SHA256_V1.into(),
                digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .into(),
            },
            sha256: "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
                .into(),
        }
    }

    #[test]
    fn forward_translation_is_deterministic_and_binds_integrity() {
        let translated = translate_v066_forward(LEGACY, &payload(), None).unwrap();
        let file = translated.target.state.as_file().unwrap();
        assert_eq!(file.upper.integrity, payload().sparse_integrity);
        assert_eq!(translated.source_bytes, LEGACY);
        assert_eq!(
            translated.target_digest,
            translated.target.digest().unwrap()
        );
    }

    #[test]
    fn native_final_file_state_reverse_translates() {
        let translated = translate_v066_forward(LEGACY, &payload(), None).unwrap();
        let reversed = translate_v066_reverse(&translated.target, None).unwrap();
        let parsed = parse_v066(&reversed.target_bytes).unwrap();
        assert_eq!(parsed.upper.integrity, Some(payload().sparse_integrity));
    }

    #[test]
    fn legacy_shape_is_not_the_final_reader() {
        assert!(Manifest::from_bytes(LEGACY).is_err());
    }
}
