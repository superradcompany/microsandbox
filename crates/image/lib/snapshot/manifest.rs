//! Snapshot descriptor schema and canonical (de)serialization.
//!
//! The descriptor (`snapshot.json`) is the source of truth for a snapshot
//! artifact. Its SHA-256 digest over the canonical byte form is the
//! snapshot's identity. Canonical form means: no insignificant whitespace,
//! struct fields in declaration order, map keys sorted, no fields elided.

use std::collections::BTreeMap;
use std::path::{Component, Path};

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};

use crate::error::{ImageError, ImageResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Current snapshot descriptor schema version. Readers reject unknown
/// schemas with a clear error.
pub const SCHEMA_VERSION: u32 = 1;

/// Canonical filename for the descriptor inside an artifact directory.
pub const DESCRIPTOR_FILENAME: &str = "snapshot.json";

/// Expected artifact kind for snapshot descriptors.
pub const SNAPSHOT_ARTIFACT_KIND: &str = "snapshot";

/// Default filename for the upper-layer file when format is `raw`.
pub const DEFAULT_UPPER_FILE: &str = "upper.ext4";

/// Sparse representation-aware digest for raw upper files.
pub const SPARSE_SHA256_V1: &str = "msb-sparse-sha256-v1";

/// Extension keys this runtime understands (see [`Manifest::requires`]).
/// Empty today; resumable-era capabilities register here as they land.
pub const SUPPORTED_REQUIRES: &[&str] = &[];

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// On-disk format of the captured upper layer.
///
/// Today only `Raw` is produced. The field exists so qcow2 chains
/// (future) drop in without a schema migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotFormat {
    /// Raw ext4 image, sparse on disk.
    Raw,
    /// qcow2 with optional backing chain (future).
    Qcow2,
}

/// Snapshot payload scope.
///
/// Parsing accepts every known scope so older runtimes can still list and
/// inspect artifacts they cannot restore; restore paths enforce support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotScope {
    /// Disk-only snapshot. Captures the writable filesystem state.
    Disk,
    /// Resumable snapshot. Reserved for future memory/device-state capture.
    Resumable,
}

/// Reference to the OCI image the snapshot was taken from.
///
/// The boot path uses `manifest_digest` to look up cached layers and
/// the VMDK descriptor; if not cached, it re-pulls `reference` and
/// verifies the resulting digest matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRef {
    /// Human-readable image reference (e.g. `docker.io/library/python:3.12`).
    #[serde(rename = "ref")]
    pub reference: String,
    /// Digest of the OCI manifest, in `sha256:hex` form.
    pub manifest_digest: String,
}

/// Captured upper-layer file metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpperLayer {
    /// Filename inside the artifact directory.
    pub file: String,
    /// Apparent size in bytes (the ext4 virtual size; sparse on disk).
    pub size_bytes: u64,
    /// Optional content integrity descriptor.
    ///
    /// Local hot paths are allowed to leave this as `None`; explicit verify
    /// and save/load boundaries use it when present.
    #[serde(deserialize_with = "deserialize_required_option")]
    pub integrity: Option<UpperIntegrity>,
}

/// Content integrity descriptor for the captured upper layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpperIntegrity {
    /// Digest algorithm name.
    pub algorithm: String,
    /// Algorithm output, in `sha256:hex` form for current algorithms.
    pub digest: String,
}

/// Snapshot artifact descriptor.
///
/// Field order matters: it determines the byte layout of the canonical
/// form, and therefore the descriptor digest. Do not reorder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Schema version of this descriptor. Readers reject unknown values.
    pub schema: u32,
    /// Artifact kind. Always `"snapshot"` for snapshot descriptors.
    pub artifact: String,
    /// Payload scope. Only disk snapshots are created and restored today.
    pub scope: SnapshotScope,
    /// On-disk format of the upper layer.
    pub format: SnapshotFormat,
    /// Filesystem type inside the upper (e.g. `ext4`).
    pub fstype: String,
    /// Image the snapshot was taken from.
    pub image: ImageRef,
    /// Descriptor digest of the parent snapshot, or `null` for a root.
    /// Always `null` today; populated once chained snapshots land.
    #[serde(deserialize_with = "deserialize_required_option")]
    pub parent: Option<String>,
    /// RFC 3339 timestamp when the snapshot was created.
    pub created_at: String,
    /// User-supplied labels. Sorted by key in canonical form.
    pub labels: BTreeMap<String, String>,
    /// The captured upper layer.
    pub upper: UpperLayer,
    /// Best-effort name of the source sandbox (informational).
    #[serde(deserialize_with = "deserialize_required_option")]
    pub source_sandbox: Option<String>,
    /// Namespaced additive data. Readers must tolerate keys they do not
    /// recognize and may ignore them; load-bearing keys are named in
    /// `requires`. This is how schema 1 evolves without breaking parsers.
    pub extensions: BTreeMap<String, serde_json::Value>,
    /// Extension keys a reader must understand to restore or start from
    /// this snapshot. Readers that do not recognize a listed key must
    /// refuse restore with a clear error but may still list and inspect
    /// the artifact. Sorted and unique in canonical form.
    pub requires: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Manifest {
    /// Validate basic invariants of a descriptor.
    ///
    /// Called automatically by `from_bytes`; exposed for callers that
    /// construct descriptors programmatically. Scope is deliberately not
    /// restricted here — validation answers "is this a well-formed snapshot
    /// descriptor", while create/restore paths answer "can this runtime
    /// handle it".
    pub fn validate(&self) -> ImageResult<()> {
        if self.schema != SCHEMA_VERSION {
            return Err(ImageError::ManifestParse(format!(
                "snapshot descriptor: unsupported schema version {} (expected {})",
                self.schema, SCHEMA_VERSION
            )));
        }
        if self.artifact != SNAPSHOT_ARTIFACT_KIND {
            return Err(ImageError::ManifestParse(format!(
                "snapshot descriptor: unsupported artifact kind {} (expected {})",
                self.artifact, SNAPSHOT_ARTIFACT_KIND
            )));
        }
        if self.fstype.is_empty() {
            return Err(ImageError::ManifestParse(
                "snapshot descriptor: empty fstype".into(),
            ));
        }
        if self.image.reference.is_empty() {
            return Err(ImageError::ManifestParse(
                "snapshot descriptor: empty image.ref".into(),
            ));
        }
        validate_digest_form(&self.image.manifest_digest, "image.manifest_digest")?;
        if let Some(ref parent) = self.parent {
            validate_digest_form(parent, "parent")?;
        }
        if self.upper.file.is_empty() {
            return Err(ImageError::ManifestParse(
                "snapshot descriptor: empty upper.file".into(),
            ));
        }
        validate_artifact_filename(&self.upper.file, "upper.file")?;
        if let Some(ref integrity) = self.upper.integrity {
            if integrity.algorithm.is_empty() {
                return Err(ImageError::ManifestParse(
                    "snapshot descriptor: empty upper.integrity.algorithm".into(),
                ));
            }
            validate_digest_form(&integrity.digest, "upper.integrity.digest")?;
        }
        let mut prev: Option<&str> = None;
        for key in &self.requires {
            if key.is_empty() {
                return Err(ImageError::ManifestParse(
                    "snapshot descriptor: empty requires entry".into(),
                ));
            }
            if !self.extensions.contains_key(key) {
                return Err(ImageError::ManifestParse(format!(
                    "snapshot descriptor: requires names '{key}' but extensions has no such key"
                )));
            }
            if prev.is_some_and(|p| p >= key.as_str()) {
                return Err(ImageError::ManifestParse(format!(
                    "snapshot descriptor: requires must be sorted and unique (at '{key}')"
                )));
            }
            prev = Some(key);
        }
        Ok(())
    }

    /// Extension keys named in `requires` that this runtime does not
    /// understand. Non-empty means the artifact can be listed and
    /// inspected but must not be restored or booted from.
    pub fn unsupported_requires(&self) -> Vec<&str> {
        self.requires
            .iter()
            .map(String::as_str)
            .filter(|k| !SUPPORTED_REQUIRES.contains(k))
            .collect()
    }

    /// Serialize to the canonical byte form used for digest computation.
    ///
    /// Properties:
    /// - struct fields in declaration order,
    /// - map keys sorted lexicographically (via `BTreeMap`),
    /// - no whitespace beyond what `serde_json` produces in compact mode,
    /// - all fields present (no `skip_serializing_if`).
    pub fn to_canonical_bytes(&self) -> ImageResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| {
            ImageError::ManifestParse(format!("snapshot descriptor: serialize failed: {e}"))
        })
    }

    /// Parse a descriptor from canonical byte form.
    ///
    /// Validates the schema version and required fields. Unknown fields
    /// are rejected so schema mistakes are surfaced immediately.
    pub fn from_bytes(bytes: &[u8]) -> ImageResult<Self> {
        let m: Manifest = serde_json::from_slice(bytes).map_err(|e| {
            ImageError::ManifestParse(format!("snapshot descriptor: parse failed: {e}"))
        })?;
        m.validate()?;
        Ok(m)
    }

    /// Compute this descriptor's content digest (`sha256:hex`).
    ///
    /// Hashes the canonical byte form. Stable across processes,
    /// platforms, and serde_json versions as long as the field set and
    /// declaration order remain unchanged.
    pub fn digest(&self) -> ImageResult<String> {
        let bytes = self.to_canonical_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn validate_digest_form(s: &str, field: &str) -> ImageResult<()> {
    let (algo, hex) = s.split_once(':').ok_or_else(|| {
        ImageError::ManifestParse(format!(
            "snapshot descriptor: {field} is not a digest (missing ':'): {s}"
        ))
    })?;
    if algo.is_empty() || hex.is_empty() {
        return Err(ImageError::ManifestParse(format!(
            "snapshot descriptor: {field} has empty component: {s}"
        )));
    }
    Ok(())
}

fn validate_artifact_filename(s: &str, field: &str) -> ImageResult<()> {
    let mut components = Path::new(s).components();
    let Some(Component::Normal(_)) = components.next() else {
        return Err(ImageError::ManifestParse(format!(
            "snapshot descriptor: {field} must be a relative artifact filename: {s}"
        )));
    };
    if components.next().is_some() {
        return Err(ImageError::ManifestParse(format!(
            "snapshot descriptor: {field} must be a single artifact filename: {s}"
        )));
    }
    Ok(())
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
        let mut labels = BTreeMap::new();
        labels.insert("stage".into(), "post-pip-install".into());
        labels.insert("owner".into(), "alice".into());
        Manifest {
            schema: SCHEMA_VERSION,
            artifact: SNAPSHOT_ARTIFACT_KIND.into(),
            scope: SnapshotScope::Disk,
            format: SnapshotFormat::Raw,
            fstype: "ext4".into(),
            image: ImageRef {
                reference: "docker.io/library/python:3.12".into(),
                manifest_digest:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            },
            parent: None,
            created_at: "2026-05-01T12:00:00Z".into(),
            labels,
            upper: UpperLayer {
                file: DEFAULT_UPPER_FILE.into(),
                size_bytes: 4_294_967_296,
                integrity: Some(UpperIntegrity {
                    algorithm: SPARSE_SHA256_V1.into(),
                    digest:
                        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            .into(),
                }),
            },
            source_sandbox: Some("build-1".into()),
            extensions: BTreeMap::new(),
            requires: Vec::new(),
        }
    }

    #[test]
    fn round_trip_canonical() {
        let m = sample_manifest();
        let bytes = m.to_canonical_bytes().unwrap();
        let parsed = Manifest::from_bytes(&bytes).unwrap();
        assert_eq!(m, parsed);
    }

    #[test]
    fn digest_is_deterministic() {
        let m = sample_manifest();
        let d1 = m.digest().unwrap();
        let d2 = m.digest().unwrap();
        assert_eq!(d1, d2);
        assert!(d1.starts_with("sha256:"));
        assert_eq!(d1.len(), "sha256:".len() + 64);
    }

    #[test]
    fn digest_changes_on_field_change() {
        let m1 = sample_manifest();
        let mut m2 = m1.clone();
        m2.created_at = "2026-05-01T12:00:01Z".into();
        assert_ne!(m1.digest().unwrap(), m2.digest().unwrap());
    }

    #[test]
    fn labels_canonical_order_independent_of_insert_order() {
        let mut m1 = sample_manifest();
        m1.labels.clear();
        m1.labels.insert("a".into(), "1".into());
        m1.labels.insert("b".into(), "2".into());

        let mut m2 = sample_manifest();
        m2.labels.clear();
        m2.labels.insert("b".into(), "2".into());
        m2.labels.insert("a".into(), "1".into());

        assert_eq!(m1.digest().unwrap(), m2.digest().unwrap());
    }

    #[test]
    fn rejects_unknown_schema() {
        let mut m = sample_manifest();
        m.schema = 999;
        let bytes = serde_json::to_vec(&m).unwrap();
        let err = Manifest::from_bytes(&bytes).unwrap_err();
        assert!(format!("{err}").contains("unsupported schema"));
    }

    #[test]
    fn rejects_unknown_artifact_kind() {
        let mut m = sample_manifest();
        m.artifact = "checkpoint".into();
        let bytes = serde_json::to_vec(&m).unwrap();
        let err = Manifest::from_bytes(&bytes).unwrap_err();
        assert!(format!("{err}").contains("unsupported artifact kind"));
    }

    #[test]
    fn rejects_descriptor_missing_artifact_and_scope() {
        let bytes = br#"{"schema":1,"format":"raw","fstype":"ext4","image":{"ref":"docker.io/library/python:3.12","manifest_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"parent":null,"created_at":"2026-05-01T12:00:00Z","labels":{},"upper":{"file":"upper.ext4","size_bytes":4294967296,"integrity":null},"source_sandbox":null}"#;
        let err = Manifest::from_bytes(bytes).unwrap_err();
        assert!(format!("{err}").contains("missing field"));
    }

    #[test]
    fn parses_resumable_scope() {
        let mut m = sample_manifest();
        m.scope = SnapshotScope::Resumable;
        let bytes = m.to_canonical_bytes().unwrap();
        let parsed = Manifest::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.scope, SnapshotScope::Resumable);
    }

    #[test]
    fn rejects_invalid_digest_form() {
        let mut m = sample_manifest();
        m.image.manifest_digest = "not-a-digest".into();
        let bytes = serde_json::to_vec(&m).unwrap();
        let err = Manifest::from_bytes(&bytes).unwrap_err();
        assert!(format!("{err}").contains("manifest_digest"));
    }

    #[test]
    fn parent_serializes_as_null_when_none() {
        let m = sample_manifest();
        let bytes = m.to_canonical_bytes().unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("\"parent\":null"));
    }

    #[test]
    fn empty_labels_still_present() {
        let mut m = sample_manifest();
        m.labels.clear();
        let bytes = m.to_canonical_bytes().unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("\"labels\":{}"));
    }

    #[test]
    fn format_serializes_lowercase() {
        let m = sample_manifest();
        let bytes = m.to_canonical_bytes().unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("\"format\":\"raw\""));
    }

    #[test]
    fn integrity_can_be_absent() {
        let mut m = sample_manifest();
        m.upper.integrity = None;
        let bytes = m.to_canonical_bytes().unwrap();
        let parsed = Manifest::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.upper.integrity, None);
        assert!(
            std::str::from_utf8(&bytes)
                .unwrap()
                .contains("\"integrity\":null")
        );
    }

    #[test]
    fn rejects_missing_integrity_field() {
        let bytes = br#"{"schema":1,"artifact":"snapshot","scope":"disk","format":"raw","fstype":"ext4","image":{"ref":"docker.io/library/python:3.12","manifest_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"parent":null,"created_at":"2026-05-01T12:00:00Z","labels":{},"upper":{"file":"upper.ext4","size_bytes":4294967296},"source_sandbox":null}"#;
        let err = Manifest::from_bytes(bytes).unwrap_err();
        assert!(format!("{err}").contains("integrity"));
    }

    #[test]
    fn rejects_legacy_upper_sha256_field() {
        let bytes = br#"{"schema":1,"artifact":"snapshot","scope":"disk","format":"raw","fstype":"ext4","image":{"ref":"docker.io/library/python:3.12","manifest_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"parent":null,"created_at":"2026-05-01T12:00:00Z","labels":{},"upper":{"file":"upper.ext4","size_bytes":4294967296,"sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"source_sandbox":null}"#;
        let err = Manifest::from_bytes(bytes).unwrap_err();
        assert!(format!("{err}").contains("sha256"));
    }

    #[test]
    fn field_order_is_stable() {
        let m = sample_manifest();
        let bytes = m.to_canonical_bytes().unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        let schema_pos = s.find("\"schema\"").unwrap();
        let artifact_pos = s.find("\"artifact\"").unwrap();
        let scope_pos = s.find("\"scope\"").unwrap();
        let format_pos = s.find("\"format\"").unwrap();
        let upper_pos = s.find("\"upper\"").unwrap();
        let source_pos = s.find("\"source_sandbox\"").unwrap();
        let extensions_pos = s.find("\"extensions\"").unwrap();
        let requires_pos = s.find("\"requires\"").unwrap();
        assert!(schema_pos < artifact_pos);
        assert!(artifact_pos < scope_pos);
        assert!(scope_pos < format_pos);
        assert!(format_pos < upper_pos);
        assert!(upper_pos < source_pos);
        assert!(source_pos < extensions_pos);
        assert!(extensions_pos < requires_pos);
    }

    #[test]
    fn extensions_round_trip_and_may_be_ignored() {
        let mut m = sample_manifest();
        m.extensions
            .insert("msb.example/1".into(), serde_json::json!({ "answer": 42 }));
        let bytes = m.to_canonical_bytes().unwrap();
        let parsed = Manifest::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.extensions["msb.example/1"]["answer"], 42);
        assert!(parsed.unsupported_requires().is_empty());
    }

    #[test]
    fn unknown_required_extension_blocks_restore_but_parses() {
        let mut m = sample_manifest();
        m.extensions
            .insert("msb.future/1".into(), serde_json::json!({}));
        m.requires.push("msb.future/1".into());
        let bytes = m.to_canonical_bytes().unwrap();
        let parsed = Manifest::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.unsupported_requires(), vec!["msb.future/1"]);
    }

    #[test]
    fn rejects_require_without_extension() {
        let mut m = sample_manifest();
        m.requires.push("msb.future/1".into());
        let bytes = serde_json::to_vec(&m).unwrap();
        let err = Manifest::from_bytes(&bytes).unwrap_err();
        assert!(format!("{err}").contains("no such key"));
    }

    #[test]
    fn rejects_unsorted_or_duplicate_requires() {
        let mut m = sample_manifest();
        m.extensions.insert("msb.a/1".into(), serde_json::json!({}));
        m.extensions.insert("msb.b/1".into(), serde_json::json!({}));
        m.requires = vec!["msb.b/1".into(), "msb.a/1".into()];
        let bytes = serde_json::to_vec(&m).unwrap();
        let err = Manifest::from_bytes(&bytes).unwrap_err();
        assert!(format!("{err}").contains("sorted and unique"));

        m.requires = vec!["msb.a/1".into(), "msb.a/1".into()];
        let bytes = serde_json::to_vec(&m).unwrap();
        let err = Manifest::from_bytes(&bytes).unwrap_err();
        assert!(format!("{err}").contains("sorted and unique"));
    }

    #[test]
    fn descriptor_without_extensions_and_requires_is_rejected() {
        let m = sample_manifest();
        let mut v: serde_json::Value = serde_json::to_value(&m).unwrap();
        let obj = v.as_object_mut().unwrap();
        obj.remove("extensions");
        obj.remove("requires");
        let bytes = serde_json::to_vec(&v).unwrap();
        let err = Manifest::from_bytes(&bytes).unwrap_err();
        assert!(format!("{err}").contains("missing field"));
    }
}
