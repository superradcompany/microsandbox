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
    FileSnapshotState, ImageRef, Manifest, SCHEMA_VERSION, SNAPSHOT_ARTIFACT_KIND, SnapshotFormat,
    SnapshotScope, SnapshotState, UpperIntegrity, UpperLayer,
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

/// Payload metadata read through the migration's pinned file handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V066PayloadIdentity {
    /// Apparent payload size.
    pub size_bytes: u64,
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
    /// Canonical v0.6.6 bytes used to compute the legacy identity.
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

/// Translate a v0.6.6 descriptor into final schema-1 file state.
///
/// The returned `source_bytes` are the canonical legacy encoding; callers that
/// need byte-exact downgrade recovery must retain the original input separately.
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
                // Preserve released metadata exactly. Migration is a
                // descriptor operation, not an implicit payload verification.
                integrity: legacy.upper.integrity,
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
///
/// `target_integrity` must preserve a released integrity value exactly, or
/// contain the sparse-SHA projection computed by the host coordinator for a
/// current BLAKE3 descriptor.
pub fn translate_v066_reverse(
    source: &Manifest,
    target_parent_digest: Option<String>,
    target_integrity: Option<UpperIntegrity>,
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
    match (&file.upper.integrity, &target_integrity) {
        (
            Some(UpperIntegrity::FileMerkleBlake3V1 { .. }),
            Some(UpperIntegrity::SparseSha256V1 { .. }),
        ) => {}
        (source, target) if source == target => {}
        _ => {
            return legacy_error(
                "snapshot_downgrade_unrepresentable: invalid v0.6.6 integrity projection",
            );
        }
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
            // The host downgrade coordinator supplies a legacy-compatible
            // projection. New integrity algorithms may require reading the
            // payload during the explicit downgrade operation.
            integrity: target_integrity,
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
        if matches!(integrity, UpperIntegrity::FileMerkleBlake3V1 { .. }) {
            return legacy_error("legacy_integrity_unsupported");
        }
        validate_digest(integrity.value(), "upper.integrity.digest")?;
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
    const LEGACY_RECORDED: &[u8] = br#"{"schema":1,"format":"raw","fstype":"ext4","image":{"ref":"docker.io/library/alpine:3.20","manifest_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"parent":null,"created_at":"2026-07-01T10:00:00Z","labels":{},"upper":{"file":"upper.ext4","size_bytes":5,"integrity":{"algorithm":"msb-sparse-sha256-v1","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},"source_sandbox":"box"}"#;

    fn payload() -> V066PayloadIdentity {
        V066PayloadIdentity { size_bytes: 5 }
    }

    #[test]
    fn forward_translation_is_deterministic_and_binds_integrity() {
        let translated = translate_v066_forward(LEGACY, &payload(), None).unwrap();
        let file = translated.target.state.as_file().unwrap();
        assert_eq!(file.upper.integrity, None);
        assert_eq!(translated.source_bytes, LEGACY);
        assert_eq!(
            translated.target_digest,
            translated.target.digest().unwrap()
        );
    }

    #[test]
    fn forward_translation_reports_canonical_legacy_bytes() {
        let mut formatted = b"\n  ".to_vec();
        formatted.extend_from_slice(LEGACY);
        formatted.push(b'\n');

        let translated = translate_v066_forward(&formatted, &payload(), None).unwrap();

        assert_eq!(translated.source_bytes, LEGACY);
        assert_ne!(translated.source_bytes, formatted);
    }

    #[test]
    fn forward_translation_preserves_recorded_integrity_without_recomputing_it() {
        let translated = translate_v066_forward(LEGACY_RECORDED, &payload(), None).unwrap();
        assert_eq!(
            translated.target.state.as_file().unwrap().upper.integrity,
            Some(UpperIntegrity::SparseSha256V1 {
                digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .into()
            })
        );
    }

    #[test]
    fn native_final_file_state_reverse_translates() {
        let translated = translate_v066_forward(LEGACY, &payload(), None).unwrap();
        let integrity = translated
            .target
            .state
            .as_file()
            .unwrap()
            .upper
            .integrity
            .clone();
        let reversed = translate_v066_reverse(&translated.target, None, integrity).unwrap();
        let parsed = parse_v066(&reversed.target_bytes).unwrap();
        assert_eq!(parsed.upper.integrity, None);
    }

    #[test]
    fn reverse_translation_rejects_current_integrity_without_legacy_projection() {
        let mut translated = translate_v066_forward(LEGACY, &payload(), None).unwrap();
        let current = UpperIntegrity::FileMerkleBlake3V1 {
            root: format!("blake3:{}", "b".repeat(64)),
            logical_size: 5,
            leaf_size: crate::snapshot::FILE_MERKLE_BLAKE3_LEAF_SIZE,
        };
        let SnapshotState::File(file) = &mut translated.target.state else {
            panic!("fixture must contain file state");
        };
        file.upper.integrity = Some(current.clone());

        assert!(
            translate_v066_reverse(&translated.target, None, Some(current)).is_err(),
            "v0.6.6 must never receive a current-only integrity algorithm"
        );
        assert!(
            translate_v066_reverse(&translated.target, None, None).is_err(),
            "downgrade must not silently discard recorded integrity"
        );

        let legacy = Some(UpperIntegrity::SparseSha256V1 {
            digest: format!("sha256:{}", "c".repeat(64)),
        });
        let reversed = translate_v066_reverse(&translated.target, None, legacy.clone()).unwrap();
        assert_eq!(
            parse_v066(&reversed.target_bytes).unwrap().upper.integrity,
            legacy
        );
    }

    #[test]
    fn legacy_shape_is_not_the_final_reader() {
        assert!(Manifest::from_bytes(LEGACY).is_err());
    }
}
