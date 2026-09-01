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
    DEFAULT_UPPER_FILE, DiskLayer, DiskLayerId, FileSnapshotState, ImageRef, LayerFileKind,
    LayerPayload, Manifest, SCHEMA, SnapshotCapture, SnapshotConsistency, SnapshotFormat,
    SnapshotId, SnapshotScope, SnapshotState, UpperIntegrity,
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
    /// Mutable local labels to persist outside the final descriptor.
    pub labels: BTreeMap<String, String>,
}

/// Deterministic reverse translation result for native final file state.
#[derive(Debug, Clone)]
pub struct V066ReverseTranslation {
    /// Canonical v0.6.6 descriptor bytes.
    pub target_bytes: Vec<u8>,
    /// Canonical v0.6.6 descriptor identity.
    pub target_digest: String,
}

/// Translation result for the released flat `snapshot.json` family.
#[derive(Debug, Clone)]
pub struct ReleasedFlatTranslation {
    /// Released descriptor digest.
    pub source_digest: String,
    /// Parent descriptor digest in the released identity namespace.
    pub source_parent_digest: Option<String>,
    /// Released payload filename.
    pub upper_file: String,
    /// Released payload size.
    pub size_bytes: u64,
    /// Final in-memory descriptor projection.
    pub target: Manifest,
    /// Mutable local labels to persist outside the final descriptor.
    pub labels: BTreeMap<String, String>,
}

/// Reverse translation of one representable final file descriptor into the
/// flat `snapshot.json` shape read by v0.6.7-v0.6.16.
#[derive(Debug, Clone)]
pub struct ReleasedFlatReverseTranslation {
    /// Canonical released descriptor bytes.
    pub target_bytes: Vec<u8>,
    /// SHA-256 identity used by the released index and parent graph.
    pub target_digest: String,
    /// Current artifact-relative layer path that must also be exposed as `upper.ext4`.
    pub source_layer: String,
}

/// Exact private model released by v0.6.6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct V066SnapshotManifest {
    schema: u32,
    format: SnapshotFormat,
    fstype: String,
    image: ReleasedImageRef,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleasedFlatManifest {
    schema: u32,
    artifact: String,
    scope: ReleasedSnapshotScope,
    created_at: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    parent: Option<String>,
    image: ReleasedImageRef,
    #[serde(deserialize_with = "deserialize_required_option")]
    source_sandbox: Option<String>,
    state: ReleasedSnapshotState,
    labels: BTreeMap<String, String>,
    extensions: BTreeMap<String, serde_json::Value>,
    requires: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ReleasedSnapshotScope {
    Disk,
    Resumable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleasedImageRef {
    #[serde(rename = "ref")]
    reference: String,
    manifest_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum ReleasedSnapshotState {
    File(ReleasedFileState),
    Checkpoint(ReleasedCheckpointState),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleasedFileState {
    format: SnapshotFormat,
    fstype: String,
    upper: V066UpperLayer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleasedCheckpointState {
    checkpoint_id: String,
    manifest: String,
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
    let labels = legacy.labels.clone();
    let snapshot_id = legacy_snapshot_id(&source_digest)?;
    let layer_id = legacy_layer_id(&source_digest)?;
    let parent = target_parent_digest
        .as_deref()
        .map(legacy_or_final_snapshot_id)
        .transpose()?;
    let target = Manifest {
        schema: SCHEMA.into(),
        snapshot_id,
        scope: SnapshotScope::Disk,
        state: SnapshotState::File(FileSnapshotState {
            disk_format: legacy.format,
            filesystem: legacy.fstype,
            virtual_size: payload.size_bytes,
            head: layer_id.clone(),
            layers: vec![DiskLayer {
                layer_id,
                format: legacy.format,
                virtual_size: payload.size_bytes,
                backing: None,
                payload: LayerPayload {
                    file_kind: LayerFileKind::Regular,
                    // Preserve released metadata without executing its verifier.
                    integrity: legacy.upper.integrity,
                },
            }],
        }),
        capture: SnapshotCapture {
            created_at: legacy.created_at,
            source_lineage: legacy.source_sandbox,
            source_checkpoint: None,
            consistency: SnapshotConsistency::CrashConsistent,
        },
        image: ImageRef {
            reference: legacy.image.reference,
            manifest_digest: legacy.image.manifest_digest,
        },
        parent,
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
        labels,
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
    labels: BTreeMap<String, String>,
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
    if file.layers.len() != 1
        || file.disk_format != SnapshotFormat::Raw
        || file.filesystem != "ext4"
    {
        return legacy_error(
            "snapshot_downgrade_unrepresentable: only raw ext4 file state is supported",
        );
    }
    let layer = file.head_layer()?;
    match (&layer.payload.integrity, &target_integrity) {
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
        format: file.disk_format,
        fstype: file.filesystem.clone(),
        image: ReleasedImageRef {
            reference: source.image.reference.clone(),
            manifest_digest: source.image.manifest_digest.clone(),
        },
        parent: target_parent_digest,
        created_at: source.capture.created_at.clone(),
        labels,
        upper: V066UpperLayer {
            file: super::DEFAULT_UPPER_FILE.into(),
            size_bytes: layer.virtual_size,
            // The host downgrade coordinator supplies a legacy-compatible
            // projection. New integrity algorithms may require reading the
            // payload during the explicit downgrade operation.
            integrity: target_integrity,
        },
        source_sandbox: source.capture.source_lineage.clone(),
    };
    validate_v066(&legacy)?;
    let target_bytes = serde_json::to_vec(&legacy).map_err(legacy_serialize_error)?;
    let target_digest = sha256_digest(&target_bytes);
    Ok(V066ReverseTranslation {
        target_bytes,
        target_digest,
    })
}

/// Translate the exact flat `snapshot.json` representation released from
/// v0.6.7 through v0.6.16 into the final closure model.
pub fn translate_released_flat_forward(source: &[u8]) -> ImageResult<ReleasedFlatTranslation> {
    let legacy: ReleasedFlatManifest = serde_json::from_slice(source).map_err(|error| {
        ImageError::ManifestParse(format!(
            "released_flat_descriptor_malformed: snapshot.json parse failed: {error}"
        ))
    })?;
    if legacy.schema != 1 || legacy.artifact != "snapshot" {
        return legacy_error("unsupported released flat snapshot schema");
    }
    if !legacy.requires.is_empty() || !legacy.extensions.is_empty() {
        return legacy_error("released flat snapshot requires unsupported extensions");
    }
    let source_digest = sha256_digest(source);
    let source_parent_digest = legacy.parent.clone();
    let labels = legacy.labels.clone();
    let snapshot_id = legacy_snapshot_id(&source_digest)?;
    let parent = legacy
        .parent
        .as_deref()
        .map(legacy_or_final_snapshot_id)
        .transpose()?;
    let (state, upper_file, size_bytes) = match legacy.state {
        ReleasedSnapshotState::File(file) => {
            validate_filename(&file.upper.file)?;
            let layer_id = legacy_layer_id(&source_digest)?;
            let size = file.upper.size_bytes;
            (
                SnapshotState::File(FileSnapshotState {
                    disk_format: file.format,
                    filesystem: file.fstype,
                    virtual_size: size,
                    head: layer_id.clone(),
                    layers: vec![DiskLayer {
                        layer_id,
                        format: file.format,
                        virtual_size: size,
                        backing: None,
                        payload: LayerPayload {
                            file_kind: LayerFileKind::Regular,
                            integrity: file.upper.integrity,
                        },
                    }],
                }),
                file.upper.file,
                size,
            )
        }
        ReleasedSnapshotState::Checkpoint(checkpoint) => (
            SnapshotState::Checkpoint(super::CheckpointSnapshotState {
                checkpoint_id: checkpoint.checkpoint_id,
                checkpoint_root: checkpoint.manifest,
                restore_intents: vec!["resume".into()],
                requirements_summary: BTreeMap::new(),
            }),
            String::new(),
            0,
        ),
    };
    let target = Manifest {
        schema: SCHEMA.into(),
        snapshot_id,
        scope: match legacy.scope {
            ReleasedSnapshotScope::Disk => SnapshotScope::Disk,
            ReleasedSnapshotScope::Resumable => SnapshotScope::Full,
        },
        state,
        capture: SnapshotCapture {
            created_at: legacy.created_at,
            source_lineage: legacy.source_sandbox,
            source_checkpoint: None,
            consistency: SnapshotConsistency::CrashConsistent,
        },
        image: ImageRef {
            reference: legacy.image.reference,
            manifest_digest: legacy.image.manifest_digest,
        },
        parent,
        requires: Vec::new(),
        extensions: BTreeMap::new(),
    };
    target.validate()?;
    Ok(ReleasedFlatTranslation {
        source_digest,
        source_parent_digest,
        upper_file,
        size_bytes,
        target,
        labels,
    })
}

/// Translate a final single-raw-layer file snapshot into the descriptor read
/// by released v0.6.7-v0.6.16 binaries.
pub fn translate_released_flat_reverse(
    source: &Manifest,
    target_parent_digest: Option<String>,
    labels: BTreeMap<String, String>,
) -> ImageResult<ReleasedFlatReverseTranslation> {
    source.validate()?;
    if source.scope != SnapshotScope::Disk {
        return legacy_error(
            "checkpoint snapshots are not representable by the released flat schema",
        );
    }
    let SnapshotState::File(file) = &source.state else {
        return legacy_error(
            "checkpoint snapshots are not representable by the released flat schema",
        );
    };
    if file.layers.len() != 1
        || file.disk_format != SnapshotFormat::Raw
        || file.filesystem != "ext4"
    {
        return legacy_error(
            "released flat downgrade requires exactly one raw ext4 layer without a backing file",
        );
    }
    let layer = file.head_layer()?;
    if layer.backing.is_some()
        || layer.format != SnapshotFormat::Raw
        || layer.virtual_size != file.virtual_size
    {
        return legacy_error("released flat downgrade cannot represent the file-state closure");
    }

    if !source.extensions.is_empty() || !source.requires.is_empty() {
        return legacy_error(
            "final descriptor extensions are not representable by the released flat schema",
        );
    }

    let released = ReleasedFlatManifest {
        schema: 1,
        artifact: "snapshot".into(),
        scope: ReleasedSnapshotScope::Disk,
        created_at: source.capture.created_at.clone(),
        parent: target_parent_digest,
        image: ReleasedImageRef {
            reference: source.image.reference.clone(),
            manifest_digest: source.image.manifest_digest.clone(),
        },
        source_sandbox: source.capture.source_lineage.clone(),
        state: ReleasedSnapshotState::File(ReleasedFileState {
            format: SnapshotFormat::Raw,
            fstype: "ext4".into(),
            upper: V066UpperLayer {
                file: DEFAULT_UPPER_FILE.into(),
                size_bytes: layer.virtual_size,
                integrity: layer.payload.integrity.clone(),
            },
        }),
        labels,
        extensions: BTreeMap::new(),
        requires: Vec::new(),
    };
    let target_bytes = serde_json::to_vec(&released).map_err(legacy_serialize_error)?;
    let target_digest = sha256_digest(&target_bytes);
    Ok(ReleasedFlatReverseTranslation {
        target_bytes,
        target_digest,
        source_layer: file.layer_path(layer).to_string_lossy().into_owned(),
    })
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn legacy_snapshot_id(digest: &str) -> ImageResult<SnapshotId> {
    let hex = digest.strip_prefix("sha256:").ok_or_else(|| {
        ImageError::ManifestParse("legacy descriptor digest is not sha256".into())
    })?;
    SnapshotId::new(format!("snap_{}", &hex[..32]))
}

fn legacy_layer_id(digest: &str) -> ImageResult<DiskLayerId> {
    let hex = digest.strip_prefix("sha256:").ok_or_else(|| {
        ImageError::ManifestParse("legacy descriptor digest is not sha256".into())
    })?;
    DiskLayerId::new(format!("layer_{}", &hex[32..64]))
}

fn legacy_or_final_snapshot_id(value: &str) -> ImageResult<SnapshotId> {
    if value.starts_with("snap_") {
        SnapshotId::new(value)
    } else {
        legacy_snapshot_id(value)
    }
}

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
        assert_eq!(file.layers[0].payload.integrity, None);
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
            translated.target.state.as_file().unwrap().layers[0]
                .payload
                .integrity,
            Some(UpperIntegrity::SparseSha256V1 {
                digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .into()
            })
        );
    }

    #[test]
    fn native_final_file_state_reverse_translates() {
        let translated = translate_v066_forward(LEGACY, &payload(), None).unwrap();
        let integrity = translated.target.state.as_file().unwrap().layers[0]
            .payload
            .integrity
            .clone();
        let reversed = translate_v066_reverse(
            &translated.target,
            None,
            integrity,
            translated.labels.clone(),
        )
        .unwrap();
        let parsed = parse_v066(&reversed.target_bytes).unwrap();
        assert_eq!(parsed.upper.integrity, None);
    }

    #[test]
    fn native_single_raw_layer_round_trips_through_released_flat_shape() {
        let translated = translate_v066_forward(LEGACY, &payload(), None).unwrap();
        let reversed =
            translate_released_flat_reverse(&translated.target, None, translated.labels.clone())
                .unwrap();
        let round_trip = translate_released_flat_forward(&reversed.target_bytes).unwrap();

        assert_eq!(round_trip.source_digest, reversed.target_digest);
        assert_eq!(round_trip.upper_file, DEFAULT_UPPER_FILE);
        let round_trip_file = round_trip.target.state.as_file().unwrap();
        let translated_file = translated.target.state.as_file().unwrap();
        assert_eq!(round_trip_file.disk_format, translated_file.disk_format);
        assert_eq!(round_trip_file.filesystem, translated_file.filesystem);
        assert_eq!(round_trip_file.virtual_size, translated_file.virtual_size);
        assert_eq!(
            round_trip_file.layers[0].payload,
            translated_file.layers[0].payload
        );
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
        file.layers[0].payload.integrity = Some(current.clone());

        assert!(
            translate_v066_reverse(&translated.target, None, Some(current), BTreeMap::new(),)
                .is_err(),
            "v0.6.6 must never receive a current-only integrity algorithm"
        );
        assert!(
            translate_v066_reverse(&translated.target, None, None, BTreeMap::new()).is_err(),
            "downgrade must not silently discard recorded integrity"
        );

        let legacy = Some(UpperIntegrity::SparseSha256V1 {
            digest: format!("sha256:{}", "c".repeat(64)),
        });
        let reversed =
            translate_v066_reverse(&translated.target, None, legacy.clone(), BTreeMap::new())
                .unwrap();
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
