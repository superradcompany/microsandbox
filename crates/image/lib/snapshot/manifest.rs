//! Snapshot descriptor schema and canonical (de)serialization.
//!
//! The descriptor (`snapshot.json`) is the source of truth for a snapshot
//! artifact. Its SHA-256 digest over the normalized canonical byte form is the
//! snapshot's identity. Canonical form has no insignificant whitespace, keeps
//! struct fields in declaration order, recursively sorts map keys, and never
//! elides required fields.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::path::{Component, Path};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};

use crate::error::{ImageError, ImageResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Current snapshot descriptor schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// Canonical filename for the descriptor inside an artifact directory.
pub const DESCRIPTOR_FILENAME: &str = "snapshot.json";

/// Expected artifact kind for snapshot descriptors.
pub const SNAPSHOT_ARTIFACT_KIND: &str = "snapshot";

/// Default filename for a raw file-state upper layer.
pub const DEFAULT_UPPER_FILE: &str = "upper.ext4";

/// Semantic sparse-file digest for raw upper files.
pub const SPARSE_SHA256_V1: &str = "msb-sparse-sha256-v1";

/// Largest integer that all public JSON consumers can represent exactly.
pub const MAX_JSON_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Extension keys understood by this runtime.
pub const SUPPORTED_REQUIRES: &[&str] = &[];

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// On-disk format of a file-state upper layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotFormat {
    /// Raw disk image.
    Raw,
    /// Qcow2 image. Restore remains capability-gated until its full chain
    /// contract is implemented.
    Qcow2,
}

/// Snapshot payload scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotScope {
    /// Disk-only state.
    Disk,
    /// Disk, memory, and device state that can resume execution.
    Resumable,
}

/// Reference to the pinned OCI image used by the snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRef {
    /// Human-readable image reference.
    #[serde(rename = "ref")]
    pub reference: String,
    /// Pinned OCI manifest digest.
    pub manifest_digest: String,
}

/// Captured file-state upper-layer metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpperLayer {
    /// One normal filename relative to the artifact directory.
    pub file: String,
    /// Apparent file size, including sparse holes.
    pub size_bytes: u64,
    /// Mandatory semantic payload integrity.
    pub integrity: UpperIntegrity,
}

/// Content integrity descriptor for a file-state upper layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpperIntegrity {
    /// Digest algorithm name.
    pub algorithm: String,
    /// Algorithm output in qualified digest form.
    pub digest: String,
}

/// Concrete file-backed snapshot state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSnapshotState {
    /// On-disk payload format.
    pub format: SnapshotFormat,
    /// Filesystem type inside the payload.
    pub fstype: String,
    /// File-backed upper-layer binding.
    pub upper: UpperLayer,
}

/// Immutable checkpoint-manifest-backed snapshot state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointSnapshotState {
    /// Stable identifier for the captured cut.
    pub checkpoint_id: String,
    /// SHA-256 identity of the disk or composite checkpoint manifest.
    pub manifest: String,
}

/// Closed snapshot state family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SnapshotState {
    /// Concrete file-backed disk state.
    File(FileSnapshotState),
    /// Manifest-backed disk or resumable state.
    Checkpoint(CheckpointSnapshotState),
}

/// Final schema-1 snapshot descriptor.
///
/// Field order is identity-bearing. Do not reorder these fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Schema version. Exactly [`SCHEMA_VERSION`].
    pub schema: u32,
    /// Artifact kind. Exactly [`SNAPSHOT_ARTIFACT_KIND`].
    pub artifact: String,
    /// Snapshot payload scope.
    pub scope: SnapshotScope,
    /// Normalized RFC 3339 creation timestamp.
    pub created_at: String,
    /// Exact snapshot identity of the logical lineage parent.
    #[serde(deserialize_with = "deserialize_required_option")]
    pub parent: Option<String>,
    /// Pinned base image.
    pub image: ImageRef,
    /// Informational source-sandbox name.
    #[serde(deserialize_with = "deserialize_required_option")]
    pub source_sandbox: Option<String>,
    /// Closed file/checkpoint state variant.
    pub state: SnapshotState,
    /// User-supplied labels, sorted by key in canonical form.
    pub labels: BTreeMap<String, String>,
    /// Namespaced additive extension values.
    pub extensions: BTreeMap<String, serde_json::Value>,
    /// Sorted unique must-understand extension keys.
    pub requires: Vec<String>,
}

/// Descriptive alias for callers that prefer descriptor terminology.
pub type SnapshotDescriptor = Manifest;

/// JSON visitor used only to reject duplicate object keys at every nesting
/// level before ordinary typed decoding occurs.
struct DuplicateCheckedJson;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SnapshotState {
    /// Return the stable state discriminant used by index and SDK projections.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::File(_) => "file",
            Self::Checkpoint(_) => "checkpoint",
        }
    }

    /// Return file state when this descriptor is file-backed.
    pub const fn as_file(&self) -> Option<&FileSnapshotState> {
        match self {
            Self::File(state) => Some(state),
            Self::Checkpoint(_) => None,
        }
    }

    /// Return checkpoint state when this descriptor is manifest-backed.
    pub const fn as_checkpoint(&self) -> Option<&CheckpointSnapshotState> {
        match self {
            Self::File(_) => None,
            Self::Checkpoint(state) => Some(state),
        }
    }
}

impl Manifest {
    /// Validate descriptor invariants.
    pub fn validate(&self) -> ImageResult<()> {
        if self.schema != SCHEMA_VERSION {
            return descriptor_error(format!(
                "unsupported schema version {} (expected {})",
                self.schema, SCHEMA_VERSION
            ));
        }
        if self.artifact != SNAPSHOT_ARTIFACT_KIND {
            return descriptor_error(format!(
                "unsupported artifact kind {} (expected {})",
                self.artifact, SNAPSHOT_ARTIFACT_KIND
            ));
        }
        if self.image.reference.is_empty() {
            return descriptor_error("empty image.ref");
        }
        validate_sha256_digest(&self.image.manifest_digest, "image.manifest_digest")?;
        if let Some(parent) = self.parent.as_deref() {
            validate_sha256_digest(parent, "parent")?;
        }
        normalize_timestamp(&self.created_at)?;

        match &self.state {
            SnapshotState::File(file) => {
                if self.scope != SnapshotScope::Disk {
                    return descriptor_error("state.kind=file requires scope=disk");
                }
                if file.fstype.is_empty() {
                    return descriptor_error("empty state.fstype");
                }
                validate_artifact_filename(&file.upper.file, "state.upper.file")?;
                if file.upper.size_bytes > MAX_JSON_SAFE_INTEGER {
                    return descriptor_error(format!(
                        "state.upper.size_bytes exceeds JSON safe-integer limit: {}",
                        file.upper.size_bytes
                    ));
                }
                if file.upper.integrity.algorithm != SPARSE_SHA256_V1 {
                    return descriptor_error(format!(
                        "unsupported state.upper.integrity.algorithm: {}",
                        file.upper.integrity.algorithm
                    ));
                }
                validate_sha256_digest(
                    &file.upper.integrity.digest,
                    "state.upper.integrity.digest",
                )?;
            }
            SnapshotState::Checkpoint(checkpoint) => {
                if checkpoint.checkpoint_id.is_empty() {
                    return descriptor_error("empty state.checkpoint_id");
                }
                validate_sha256_digest(&checkpoint.manifest, "state.manifest")?;
            }
        }

        let mut previous: Option<&str> = None;
        for key in &self.requires {
            if key.is_empty() {
                return descriptor_error("empty requires entry");
            }
            if !self.extensions.contains_key(key) {
                return descriptor_error(format!(
                    "requires names '{key}' but extensions has no such key"
                ));
            }
            if previous.is_some_and(|value| value >= key.as_str()) {
                return descriptor_error(format!(
                    "requires must be sorted and unique (at '{key}')"
                ));
            }
            previous = Some(key);
        }

        Ok(())
    }

    /// Return unknown must-understand extension keys.
    pub fn unsupported_requires(&self) -> Vec<&str> {
        self.requires
            .iter()
            .map(String::as_str)
            .filter(|key| !SUPPORTED_REQUIRES.contains(key))
            .collect()
    }

    /// Serialize the normalized semantic value to canonical identity bytes.
    pub fn to_canonical_bytes(&self) -> ImageResult<Vec<u8>> {
        let normalized = self.normalized()?;
        serde_json::to_vec(&normalized).map_err(|error| {
            ImageError::ManifestParse(format!("snapshot descriptor: serialize failed: {error}"))
        })
    }

    /// Parse, normalize, and validate one strict schema-1 descriptor.
    pub fn from_bytes(bytes: &[u8]) -> ImageResult<Self> {
        reject_duplicate_json_keys(bytes)?;
        let parsed: Self = serde_json::from_slice(bytes).map_err(|error| {
            ImageError::ManifestParse(format!("snapshot descriptor: parse failed: {error}"))
        })?;
        parsed.normalized()
    }

    /// Compute the snapshot identity over normalized canonical bytes.
    pub fn digest(&self) -> ImageResult<String> {
        let mut hasher = Sha256::new();
        hasher.update(self.to_canonical_bytes()?);
        Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
    }

    fn normalized(&self) -> ImageResult<Self> {
        let mut normalized = self.clone();
        normalized.created_at = normalize_timestamp(&normalized.created_at)?;
        for value in normalized.extensions.values_mut() {
            normalize_json_value(value);
        }
        normalized.validate()?;
        Ok(normalized)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<'de> Deserialize<'de> for DuplicateCheckedJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateCheckedJsonVisitor)
    }
}

struct DuplicateCheckedJsonVisitor;

impl<'de> Visitor<'de> for DuplicateCheckedJsonVisitor {
    type Value = DuplicateCheckedJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedJson)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedJson)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedJson)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedJson)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(DuplicateCheckedJson)
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedJson)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedJson)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedJson)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<DuplicateCheckedJson>()?.is_some() {}
        Ok(DuplicateCheckedJson)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(A::Error::custom(format!("duplicate object key '{key}'")));
            }
            map.next_value::<DuplicateCheckedJson>()?;
        }
        Ok(DuplicateCheckedJson)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn descriptor_error<T>(message: impl Into<String>) -> ImageResult<T> {
    Err(ImageError::ManifestParse(format!(
        "snapshot descriptor: {}",
        message.into()
    )))
}

fn validate_sha256_digest(value: &str, field: &str) -> ImageResult<()> {
    let Some(encoded) = value.strip_prefix("sha256:") else {
        return descriptor_error(format!("{field} must use sha256: {value}"));
    };
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return descriptor_error(format!(
            "{field} must contain 64 lowercase hexadecimal digits: {value}"
        ));
    }
    Ok(())
}

fn validate_artifact_filename(value: &str, field: &str) -> ImageResult<()> {
    let mut components = Path::new(value).components();
    let Some(Component::Normal(name)) = components.next() else {
        return descriptor_error(format!(
            "{field} must be one relative normal filename: {value}"
        ));
    };
    if name.is_empty() || components.next().is_some() {
        return descriptor_error(format!(
            "{field} must be one relative normal filename: {value}"
        ));
    }
    Ok(())
}

fn normalize_timestamp(value: &str) -> ImageResult<String> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|error| {
            ImageError::ManifestParse(format!(
                "snapshot descriptor: created_at is not RFC 3339: {error}"
            ))
        })?
        .with_timezone(&Utc);
    let mut normalized = parsed.to_rfc3339_opts(SecondsFormat::Nanos, true);
    if let Some(dot) = normalized.find('.') {
        let z = normalized.len() - 1;
        let trimmed = normalized[dot + 1..z].trim_end_matches('0');
        normalized = if trimmed.is_empty() {
            format!("{}Z", &normalized[..dot])
        } else {
            format!("{}.{}Z", &normalized[..dot], trimmed)
        };
    }
    Ok(normalized)
}

fn normalize_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                normalize_json_value(value);
            }
        }
        serde_json::Value::Object(object) => {
            let old = std::mem::take(object);
            let mut sorted = BTreeMap::new();
            for (key, mut value) in old {
                normalize_json_value(&mut value);
                sorted.insert(key, value);
            }
            object.extend(sorted);
        }
        _ => {}
    }
}

fn reject_duplicate_json_keys(bytes: &[u8]) -> ImageResult<()> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    DuplicateCheckedJson::deserialize(&mut deserializer).map_err(|error| {
        ImageError::ManifestParse(format!("snapshot descriptor: parse failed: {error}"))
    })?;
    deserializer.end().map_err(|error| {
        ImageError::ManifestParse(format!("snapshot descriptor: parse failed: {error}"))
    })
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

    fn sample_manifest() -> Manifest {
        Manifest {
            schema: SCHEMA_VERSION,
            artifact: SNAPSHOT_ARTIFACT_KIND.into(),
            scope: SnapshotScope::Disk,
            created_at: "2026-05-01T12:00:00Z".into(),
            parent: None,
            image: ImageRef {
                reference: "docker.io/library/python:3.12".into(),
                manifest_digest:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .into(),
            },
            source_sandbox: Some("build-1".into()),
            state: SnapshotState::File(FileSnapshotState {
                format: SnapshotFormat::Raw,
                fstype: "ext4".into(),
                upper: UpperLayer {
                    file: DEFAULT_UPPER_FILE.into(),
                    size_bytes: 4_294_967_296,
                    integrity: UpperIntegrity {
                        algorithm: SPARSE_SHA256_V1.into(),
                        digest:
                            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                                .into(),
                    },
                },
            }),
            labels: BTreeMap::from([
                ("owner".into(), "alice".into()),
                ("stage".into(), "post-pip-install".into()),
            ]),
            extensions: BTreeMap::new(),
            requires: Vec::new(),
        }
    }

    #[test]
    fn final_file_descriptor_matches_golden_bytes_and_digest() {
        let manifest = sample_manifest();
        let expected = r#"{"schema":1,"artifact":"snapshot","scope":"disk","created_at":"2026-05-01T12:00:00Z","parent":null,"image":{"ref":"docker.io/library/python:3.12","manifest_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"source_sandbox":"build-1","state":{"kind":"file","format":"raw","fstype":"ext4","upper":{"file":"upper.ext4","size_bytes":4294967296,"integrity":{"algorithm":"msb-sparse-sha256-v1","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}},"labels":{"owner":"alice","stage":"post-pip-install"},"extensions":{},"requires":[]}"#;
        assert_eq!(manifest.to_canonical_bytes().unwrap(), expected.as_bytes());
        assert_eq!(
            manifest.digest().unwrap(),
            "sha256:5b9ca7611f40ec61fea70c1b1ac9881ed63a16091922682028222cdaef997572"
        );
    }

    #[test]
    fn semantic_normalization_preserves_identity() {
        let canonical = sample_manifest();
        let reordered = br#"{
          "requires": [], "extensions": {}, "labels": {"stage":"post-pip-install","owner":"alice"},
          "state": {"upper":{"integrity":{"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","algorithm":"msb-sparse-sha256-v1"},"size_bytes":4294967296,"file":"upper.ext4"},"fstype":"ext4","format":"raw","kind":"file"},
          "source_sandbox":"build-1", "image":{"manifest_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ref":"docker.io/library/python:3.12"},
          "parent":null,"created_at":"2026-05-01T13:00:00+01:00","scope":"disk","artifact":"snapshot","schema":1
        }"#;
        let parsed = Manifest::from_bytes(reordered).unwrap();
        assert_eq!(parsed.digest().unwrap(), canonical.digest().unwrap());
        assert_eq!(parsed.created_at, "2026-05-01T12:00:00Z");
    }

    #[test]
    fn checkpoint_variant_round_trips() {
        let mut manifest = sample_manifest();
        manifest.scope = SnapshotScope::Resumable;
        manifest.state = SnapshotState::Checkpoint(CheckpointSnapshotState {
            checkpoint_id: "ckpt_example".into(),
            manifest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                .into(),
        });
        let bytes = manifest.to_canonical_bytes().unwrap();
        assert!(std::str::from_utf8(&bytes).unwrap().contains(
            r#""state":{"kind":"checkpoint","checkpoint_id":"ckpt_example","manifest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}"#
        ));
        assert_eq!(Manifest::from_bytes(&bytes).unwrap(), manifest);
    }

    #[test]
    fn rejects_file_state_without_integrity() {
        let bytes = sample_manifest().to_canonical_bytes().unwrap();
        let value = String::from_utf8(bytes)
            .unwrap()
            .replace(
                r#","integrity":{"algorithm":"msb-sparse-sha256-v1","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#,
                "",
            );
        let error = Manifest::from_bytes(value.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("integrity"));
    }

    #[test]
    fn rejects_file_state_for_resumable_scope() {
        let mut manifest = sample_manifest();
        manifest.scope = SnapshotScope::Resumable;
        let error = manifest.to_canonical_bytes().unwrap_err();
        assert!(error.to_string().contains("requires scope=disk"));
    }

    #[test]
    fn rejects_duplicate_keys_at_any_depth() {
        let bytes = sample_manifest().to_canonical_bytes().unwrap();
        let value = String::from_utf8(bytes).unwrap().replace(
            r#""extensions":{}"#,
            r#""extensions":{"msb.example/1":{"x":1,"x":2}}"#,
        );
        let error = Manifest::from_bytes(value.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("duplicate object key 'x'"));
    }

    #[test]
    fn recursively_sorts_extension_object_keys() {
        let mut manifest = sample_manifest();
        manifest.extensions.insert(
            "msb.example/1".into(),
            serde_json::json!({"z": {"b": 2, "a": 1}, "a": 0}),
        );
        let text = String::from_utf8(manifest.to_canonical_bytes().unwrap()).unwrap();
        assert!(text.contains(r#""msb.example/1":{"a":0,"z":{"a":1,"b":2}}"#));
    }

    #[test]
    fn rejects_unsafe_upper_filename_and_unsafe_integer() {
        let mut manifest = sample_manifest();
        let file = manifest.state.as_file().unwrap().clone();
        manifest.state = SnapshotState::File(FileSnapshotState {
            upper: UpperLayer {
                file: "../upper.ext4".into(),
                ..file.upper
            },
            ..file
        });
        assert!(manifest.to_canonical_bytes().is_err());

        let mut manifest = sample_manifest();
        let file = manifest.state.as_file().unwrap().clone();
        manifest.state = SnapshotState::File(FileSnapshotState {
            upper: UpperLayer {
                size_bytes: MAX_JSON_SAFE_INTEGER + 1,
                ..file.upper
            },
            ..file
        });
        assert!(manifest.to_canonical_bytes().is_err());
    }

    #[test]
    fn unknown_required_extension_parses_but_blocks_use() {
        let mut manifest = sample_manifest();
        manifest
            .extensions
            .insert("msb.future/1".into(), serde_json::json!({}));
        manifest.requires.push("msb.future/1".into());
        let parsed = Manifest::from_bytes(&manifest.to_canonical_bytes().unwrap()).unwrap();
        assert_eq!(parsed.unsupported_requires(), vec!["msb.future/1"]);
    }
}
