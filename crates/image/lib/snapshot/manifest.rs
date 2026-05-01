//! Snapshot manifest schema and canonical (de)serialization.
//!
//! The manifest is the source of truth for a snapshot artifact. Its
//! SHA-256 digest over the canonical byte form is the snapshot's
//! identity. Canonical form means: no insignificant whitespace, struct
//! fields in declaration order, map keys sorted, no fields elided.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::error::{ImageError, ImageResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Current snapshot manifest schema version. Readers reject unknown
/// schemas with a clear error.
pub const SCHEMA_VERSION: u32 = 1;

/// Canonical filename for the manifest inside an artifact directory.
pub const MANIFEST_FILENAME: &str = "manifest.json";

/// Default filename for the upper-layer file when format is `raw`.
pub const DEFAULT_UPPER_FILE: &str = "upper.ext4";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// On-disk format of the captured upper layer.
///
/// v1 only ever produces `Raw`. The field exists so qcow2 chains
/// (future) drop in without a schema migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotFormat {
    /// Raw ext4 image, sparse on disk.
    Raw,
    /// qcow2 with optional backing chain (future).
    Qcow2,
}

/// Reference to the OCI image the snapshot was taken from.
///
/// The boot path uses `manifest_digest` to look up cached layers and
/// the VMDK descriptor; if not cached, it re-pulls `reference` and
/// verifies the resulting digest matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageRef {
    /// Human-readable image reference (e.g. `docker.io/library/python:3.12`).
    #[serde(rename = "ref")]
    pub reference: String,
    /// Digest of the OCI manifest, in `sha256:hex` form.
    pub manifest_digest: String,
}

/// Captured upper-layer file metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpperLayer {
    /// Filename inside the artifact directory.
    pub file: String,
    /// Apparent size in bytes (the ext4 virtual size; sparse on disk).
    pub size_bytes: u64,
    /// `sha256:hex` digest over the file's bytes (holes hashed as zeros).
    pub sha256: String,
}

/// Snapshot artifact manifest.
///
/// Field order matters: it determines the byte layout of the canonical
/// form, and therefore the manifest digest. Do not reorder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Schema version of this manifest. Readers reject unknown values.
    pub schema: u32,
    /// On-disk format of the upper layer.
    pub format: SnapshotFormat,
    /// Filesystem type inside the upper (e.g. `ext4`).
    pub fstype: String,
    /// Image the snapshot was taken from.
    pub image: ImageRef,
    /// Manifest digest of the parent snapshot, or `null` for a root.
    /// v1 always writes `null`.
    pub parent: Option<String>,
    /// RFC 3339 timestamp when the snapshot was created.
    pub created_at: String,
    /// User-supplied labels. Sorted by key in canonical form.
    pub labels: BTreeMap<String, String>,
    /// The captured upper layer.
    pub upper: UpperLayer,
    /// Best-effort name of the source sandbox (informational).
    pub source_sandbox: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Manifest {
    /// Validate basic invariants of a manifest.
    ///
    /// Called automatically by `from_bytes`; exposed for callers that
    /// construct manifests programmatically.
    pub fn validate(&self) -> ImageResult<()> {
        if self.schema != SCHEMA_VERSION {
            return Err(ImageError::ManifestParse(format!(
                "snapshot manifest: unsupported schema version {} (expected {})",
                self.schema, SCHEMA_VERSION
            )));
        }
        if self.fstype.is_empty() {
            return Err(ImageError::ManifestParse(
                "snapshot manifest: empty fstype".into(),
            ));
        }
        if self.image.reference.is_empty() {
            return Err(ImageError::ManifestParse(
                "snapshot manifest: empty image.ref".into(),
            ));
        }
        validate_digest_form(&self.image.manifest_digest, "image.manifest_digest")?;
        if let Some(ref parent) = self.parent {
            validate_digest_form(parent, "parent")?;
        }
        if self.upper.file.is_empty() {
            return Err(ImageError::ManifestParse(
                "snapshot manifest: empty upper.file".into(),
            ));
        }
        validate_digest_form(&self.upper.sha256, "upper.sha256")?;
        Ok(())
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
            ImageError::ManifestParse(format!("snapshot manifest: serialize failed: {e}"))
        })
    }

    /// Parse a manifest from canonical (or compatible) byte form.
    ///
    /// Validates the schema version and required fields. The input is
    /// not required to be byte-identical to the canonical form — only
    /// the parsed manifest's *re-serialized* form is digested.
    pub fn from_bytes(bytes: &[u8]) -> ImageResult<Self> {
        let m: Manifest = serde_json::from_slice(bytes).map_err(|e| {
            ImageError::ManifestParse(format!("snapshot manifest: parse failed: {e}"))
        })?;
        m.validate()?;
        Ok(m)
    }

    /// Compute this manifest's content digest (`sha256:hex`).
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
            "snapshot manifest: {field} is not a digest (missing ':'): {s}"
        ))
    })?;
    if algo.is_empty() || hex.is_empty() {
        return Err(ImageError::ManifestParse(format!(
            "snapshot manifest: {field} has empty component: {s}"
        )));
    }
    Ok(())
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
                sha256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .into(),
            },
            source_sandbox: Some("build-1".into()),
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
    fn field_order_is_stable() {
        let m = sample_manifest();
        let bytes = m.to_canonical_bytes().unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        let schema_pos = s.find("\"schema\"").unwrap();
        let format_pos = s.find("\"format\"").unwrap();
        let upper_pos = s.find("\"upper\"").unwrap();
        let source_pos = s.find("\"source_sandbox\"").unwrap();
        assert!(schema_pos < format_pos);
        assert!(format_pos < upper_pos);
        assert!(upper_pos < source_pos);
    }
}
