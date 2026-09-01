//! Final snapshot descriptor schema and canonical serialization.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};

use crate::error::{ImageError, ImageResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Current snapshot descriptor schema identifier.
pub const SCHEMA: &str = "microsandbox.snapshot/1";
/// Numeric source-compatibility alias for the released schema.
pub const SCHEMA_VERSION: u32 = 1;
/// Canonical descriptor filename.
pub const DESCRIPTOR_FILENAME: &str = "snapshot.json";
/// Source-compatibility alias for the released artifact discriminator.
pub const SNAPSHOT_ARTIFACT_KIND: &str = "snapshot";
/// Released flat-payload filename.
pub const DEFAULT_UPPER_FILE: &str = "upper.ext4";
/// Directory containing physical file layers.
pub const LAYERS_DIRECTORY: &str = "layers";
/// Released sparse SHA-256 algorithm.
pub const SPARSE_SHA256_V1: &str = "msb-sparse-sha256-v1";
/// Current file Merkle algorithm.
pub const FILE_MERKLE_BLAKE3_V1: &str = "msb-file-merkle-blake3-v1";
/// Fixed leaf size of the current file Merkle algorithm.
pub const FILE_MERKLE_BLAKE3_LEAF_SIZE: u32 = 64 * 1024;
/// Largest exact integer shared by public JSON consumers.
pub const MAX_JSON_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
/// Maximum accepted descriptor size.
pub const MAX_DESCRIPTOR_BYTES: usize = 1024 * 1024;
/// Maximum physical depth of one file-state closure.
pub const MAX_FILE_LAYERS: usize = 256;
/// Must-understand extensions implemented by this runtime.
pub const SUPPORTED_REQUIRES: &[&str] = &[];

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Stable opaque snapshot identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SnapshotId(String);

/// Stable opaque physical-layer identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DiskLayerId(String);

/// Physical disk format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotFormat {
    /// Raw disk image.
    Raw,
    /// Qcow2 disk image.
    Qcow2,
}

/// Snapshot state family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotScope {
    /// File-backed disk state.
    #[serde(rename = "file")]
    Disk,
    /// Composite checkpoint state.
    #[serde(rename = "checkpoint")]
    Full,
}

/// Consistency guarantee of a capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotConsistency {
    /// Equivalent to storage observed after abrupt power loss.
    CrashConsistent,
    /// Captured after filesystem quiescence.
    FilesystemConsistent,
    /// Coherently resumable execution state.
    ApplicationConsistent,
}

/// Pinned OCI image reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRef {
    /// Human-readable image reference.
    pub reference: String,
    /// OCI manifest digest.
    pub manifest_digest: String,
}

/// Immutable capture provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotCapture {
    /// Normalized RFC 3339 capture time.
    pub created_at: String,
    /// Stable source lineage when known.
    #[serde(deserialize_with = "deserialize_required_option")]
    pub source_lineage: Option<String>,
    /// Source checkpoint ID when applicable.
    #[serde(deserialize_with = "deserialize_required_option")]
    pub source_checkpoint: Option<String>,
    /// Capture consistency.
    pub consistency: SnapshotConsistency,
}

/// Optional persistent layer integrity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "algorithm", deny_unknown_fields)]
pub enum UpperIntegrity {
    /// Ordinary SHA-256 retained only for released compatibility.
    #[serde(rename = "sha256")]
    Sha256 {
        /// Qualified digest.
        digest: String,
    },
    /// Released logical-byte sparse SHA-256.
    #[serde(rename = "msb-sparse-sha256-v1")]
    SparseSha256V1 {
        /// Qualified digest.
        digest: String,
    },
    /// Current sparse-aware fixed-leaf BLAKE3 Merkle root.
    #[serde(rename = "msb-file-merkle-blake3-v1")]
    FileMerkleBlake3V1 {
        /// Qualified root.
        root: String,
        /// Bound logical payload size.
        logical_size: u64,
        /// Fixed leaf size.
        leaf_size: u32,
    },
}

/// Allowed physical payload kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LayerFileKind {
    /// Ordinary regular file.
    Regular,
}

/// Physical payload metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayerPayload {
    /// Required member kind.
    pub file_kind: LayerFileKind,
    /// Optional persistent integrity.
    #[serde(deserialize_with = "deserialize_required_option")]
    pub integrity: Option<UpperIntegrity>,
}

/// One member of an ordered complete file-layer closure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskLayer {
    /// Opaque member identity.
    pub layer_id: DiskLayerId,
    /// Physical format.
    pub format: SnapshotFormat,
    /// Guest-visible virtual length.
    pub virtual_size: u64,
    /// Immediate predecessor, if any.
    #[serde(deserialize_with = "deserialize_required_option")]
    pub backing: Option<DiskLayerId>,
    /// Physical payload metadata.
    pub payload: LayerPayload,
}

/// Compatibility alias for callers that imported the released name.
pub type UpperLayer = DiskLayer;

/// Concrete file-backed snapshot state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSnapshotState {
    /// Format of the head layer.
    pub disk_format: SnapshotFormat,
    /// Filesystem inside the virtual disk.
    pub filesystem: String,
    /// Guest-visible size of the head layer.
    pub virtual_size: u64,
    /// Opaque identity of the head layer.
    pub head: DiskLayerId,
    /// Complete physical closure, oldest first.
    pub layers: Vec<DiskLayer>,
}

/// Composite-checkpoint-backed state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointSnapshotState {
    /// Stable checkpoint identifier.
    pub checkpoint_id: String,
    /// Composite checkpoint integrity root.
    pub checkpoint_root: String,
    /// Allowed restore intents.
    pub restore_intents: Vec<String>,
    /// Bounded early-admission summary.
    pub requirements_summary: BTreeMap<String, serde_json::Value>,
}

/// Closed snapshot-state variants.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SnapshotState {
    /// Concrete file-backed state.
    File(FileSnapshotState),
    /// Composite checkpoint state.
    Checkpoint(CheckpointSnapshotState),
}

/// Final schema-1 descriptor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Schema identifier. Exactly [`SCHEMA`].
    pub schema: String,
    /// Stable artifact identity.
    pub snapshot_id: SnapshotId,
    /// State family.
    pub scope: SnapshotScope,
    /// Closed state value.
    pub state: SnapshotState,
    /// Capture provenance.
    pub capture: SnapshotCapture,
    /// Pinned base image.
    pub image: ImageRef,
    /// Logical parent by snapshot ID.
    #[serde(deserialize_with = "deserialize_required_option")]
    pub parent: Option<SnapshotId>,
    /// Sorted unique must-understand extension keys.
    pub requires: Vec<String>,
    /// Namespaced additive extensions.
    pub extensions: BTreeMap<String, serde_json::Value>,
}

/// Descriptive alias for descriptor terminology.
pub type SnapshotDescriptor = Manifest;

/// Duplicate-key rejecting JSON visitor.
struct DuplicateCheckedJson;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SnapshotId {
    /// Construct a validated snapshot ID.
    pub fn new(value: impl Into<String>) -> ImageResult<Self> {
        let value = value.into();
        validate_opaque_id(&value, "snap_", "snapshot_id")?;
        Ok(Self(value))
    }

    /// Return the encoded ID.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SnapshotId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl DiskLayerId {
    /// Construct a validated layer ID.
    pub fn new(value: impl Into<String>) -> ImageResult<Self> {
        let value = value.into();
        validate_opaque_id(&value, "layer_", "layer_id")?;
        Ok(Self(value))
    }

    /// Return the encoded ID.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DiskLayerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl SnapshotState {
    /// Return the index discriminant.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::File(_) => "file",
            Self::Checkpoint(_) => "checkpoint",
        }
    }

    /// Return file state when present.
    pub const fn as_file(&self) -> Option<&FileSnapshotState> {
        match self {
            Self::File(state) => Some(state),
            Self::Checkpoint(_) => None,
        }
    }

    /// Return checkpoint state when present.
    pub const fn as_checkpoint(&self) -> Option<&CheckpointSnapshotState> {
        match self {
            Self::File(_) => None,
            Self::Checkpoint(state) => Some(state),
        }
    }
}

impl FileSnapshotState {
    /// Return the validated head layer.
    pub fn head_layer(&self) -> ImageResult<&DiskLayer> {
        self.layers
            .last()
            .filter(|layer| layer.layer_id == self.head)
            .ok_or_else(|| descriptor_error_value("state.head does not name the final layer"))
    }

    /// Return a layer's canonical artifact-relative path.
    pub fn layer_path(&self, layer: &DiskLayer) -> PathBuf {
        layer_path(&layer.layer_id, layer.format)
    }

    /// Return a representation-sensitive state root when every layer records integrity.
    pub fn state_root(&self) -> ImageResult<Option<String>> {
        if self
            .layers
            .iter()
            .any(|layer| layer.payload.integrity.is_none())
        {
            return Ok(None);
        }
        let mut input = b"microsandbox.file-state-root/1\0".to_vec();
        input.extend_from_slice(self.filesystem.as_bytes());
        input.push(0);
        input.extend_from_slice(&self.virtual_size.to_le_bytes());
        for layer in &self.layers {
            input.extend_from_slice(match layer.format {
                SnapshotFormat::Raw => b"raw\0",
                SnapshotFormat::Qcow2 => b"qcow2\0",
            });
            input.extend_from_slice(&layer.virtual_size.to_le_bytes());
            let integrity = layer.payload.integrity.as_ref().expect("checked above");
            input.extend_from_slice(integrity.algorithm().as_bytes());
            input.push(0);
            input.extend_from_slice(integrity.value().as_bytes());
            input.push(0);
        }
        let mut hasher = Sha256::new();
        hasher.update(input);
        Ok(Some(format!("sha256:{}", hex::encode(hasher.finalize()))))
    }
}

impl UpperIntegrity {
    /// Return the serialized algorithm name.
    pub const fn algorithm(&self) -> &'static str {
        match self {
            Self::Sha256 { .. } => "sha256",
            Self::SparseSha256V1 { .. } => SPARSE_SHA256_V1,
            Self::FileMerkleBlake3V1 { .. } => FILE_MERKLE_BLAKE3_V1,
        }
    }

    /// Return the qualified digest or root.
    pub fn value(&self) -> &str {
        match self {
            Self::Sha256 { digest } | Self::SparseSha256V1 { digest } => digest,
            Self::FileMerkleBlake3V1 { root, .. } => root,
        }
    }
}

impl Manifest {
    /// Validate all closed descriptor invariants.
    pub fn validate(&self) -> ImageResult<()> {
        if self.schema != SCHEMA {
            return descriptor_error(format!(
                "unsupported schema {} (expected {SCHEMA})",
                self.schema
            ));
        }
        validate_opaque_id(self.snapshot_id.as_str(), "snap_", "snapshot_id")?;
        if self.image.reference.is_empty() {
            return descriptor_error("empty image.reference");
        }
        validate_digest(
            &self.image.manifest_digest,
            "sha256:",
            "image.manifest_digest",
        )?;
        if let Some(parent) = &self.parent {
            validate_opaque_id(parent.as_str(), "snap_", "parent")?;
            if parent == &self.snapshot_id {
                return descriptor_error("snapshot cannot be its own parent");
            }
        }
        normalize_timestamp(&self.capture.created_at)?;
        match &self.state {
            SnapshotState::File(file) => {
                if self.scope != SnapshotScope::Disk {
                    return descriptor_error("state.kind=file requires scope=file");
                }
                validate_file_state(file)?;
            }
            SnapshotState::Checkpoint(checkpoint) => {
                if self.scope != SnapshotScope::Full {
                    return descriptor_error("state.kind=checkpoint requires scope=checkpoint");
                }
                if checkpoint.checkpoint_id.is_empty() {
                    return descriptor_error("empty state.checkpoint_id");
                }
                validate_digest(
                    &checkpoint.checkpoint_root,
                    "sha256:",
                    "state.checkpoint_root",
                )?;
            }
        }
        let mut previous = None;
        for key in &self.requires {
            if key.is_empty() || !self.extensions.contains_key(key) {
                return descriptor_error(format!("invalid required extension '{key}'"));
            }
            if previous.is_some_and(|value: &str| value >= key.as_str()) {
                return descriptor_error("requires must be sorted and unique");
            }
            previous = Some(key.as_str());
        }
        for value in self.extensions.values() {
            validate_json_value(value, 0)?;
        }
        Ok(())
    }

    /// Return unknown must-understand extensions.
    pub fn unsupported_requires(&self) -> Vec<&str> {
        self.requires
            .iter()
            .map(String::as_str)
            .filter(|key| !SUPPORTED_REQUIRES.contains(key))
            .collect()
    }

    /// Serialize normalized semantics using the schema's bounded RFC 8785 subset.
    pub fn to_canonical_bytes(&self) -> ImageResult<Vec<u8>> {
        let normalized = self.normalized()?;
        let value = serde_json::to_value(normalized)
            .map_err(|error| descriptor_error_value(format!("serialize failed: {error}")))?;
        let mut output = Vec::new();
        write_canonical_json(&value, &mut output)?;
        Ok(output)
    }

    /// Parse one strict final descriptor.
    pub fn from_bytes(bytes: &[u8]) -> ImageResult<Self> {
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return descriptor_error(format!("descriptor exceeds {MAX_DESCRIPTOR_BYTES} bytes"));
        }
        reject_duplicate_json_keys(bytes)?;
        let parsed: Self = serde_json::from_slice(bytes)
            .map_err(|error| descriptor_error_value(format!("parse failed: {error}")))?;
        parsed.normalized()
    }

    /// Compute the descriptor digest, distinct from [`SnapshotId`].
    pub fn digest(&self) -> ImageResult<String> {
        let mut hasher = Sha256::new();
        hasher.update(self.to_canonical_bytes()?);
        Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
    }

    fn normalized(&self) -> ImageResult<Self> {
        let mut normalized = self.clone();
        normalized.capture.created_at = normalize_timestamp(&normalized.capture.created_at)?;
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
        formatter.write_str("JSON without duplicate object keys")
    }
    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedJson)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedJson)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedJson)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(DuplicateCheckedJson)
    }
    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(DuplicateCheckedJson)
    }
    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
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
// Functions
//--------------------------------------------------------------------------------------------------

/// Return the canonical artifact-relative path for a layer.
pub fn layer_path(layer_id: &DiskLayerId, format: SnapshotFormat) -> PathBuf {
    let extension = match format {
        SnapshotFormat::Raw => "raw",
        SnapshotFormat::Qcow2 => "qcow2",
    };
    Path::new(LAYERS_DIRECTORY).join(format!("{layer_id}.{extension}"))
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn descriptor_error<T>(message: impl Into<String>) -> ImageResult<T> {
    Err(descriptor_error_value(message))
}
fn descriptor_error_value(message: impl Into<String>) -> ImageError {
    ImageError::ManifestParse(format!("snapshot descriptor: {}", message.into()))
}

fn validate_opaque_id(value: &str, prefix: &str, field: &str) -> ImageResult<()> {
    let Some(encoded) = value.strip_prefix(prefix) else {
        return descriptor_error(format!("{field} must start with {prefix}: {value}"));
    };
    if encoded.len() != 32
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return descriptor_error(format!(
            "{field} must contain 32 lowercase hexadecimal digits after {prefix}: {value}"
        ));
    }
    Ok(())
}

fn validate_file_state(file: &FileSnapshotState) -> ImageResult<()> {
    if file.filesystem.is_empty() {
        return descriptor_error("empty state.filesystem");
    }
    if file.virtual_size > MAX_JSON_SAFE_INTEGER {
        return descriptor_error("state.virtual_size exceeds the JSON safe-integer limit");
    }
    if file.layers.is_empty() || file.layers.len() > MAX_FILE_LAYERS {
        return descriptor_error(format!(
            "state.layers must contain 1..={MAX_FILE_LAYERS} entries"
        ));
    }
    let mut ids = HashSet::with_capacity(file.layers.len());
    for (index, layer) in file.layers.iter().enumerate() {
        validate_opaque_id(layer.layer_id.as_str(), "layer_", "state.layers[].layer_id")?;
        if !ids.insert(layer.layer_id.as_str()) {
            return descriptor_error(format!("duplicate layer id {}", layer.layer_id));
        }
        if layer.virtual_size > MAX_JSON_SAFE_INTEGER {
            return descriptor_error("layer virtual_size exceeds the JSON safe-integer limit");
        }
        match (index, layer.format, layer.backing.as_ref()) {
            (0, _, None) => {}
            (0, _, Some(_)) => {
                return descriptor_error("oldest layer must not name a backing layer");
            }
            (_, SnapshotFormat::Raw, _) => {
                return descriptor_error("raw successor layers are not allowed");
            }
            (_, SnapshotFormat::Qcow2, Some(backing))
                if backing == &file.layers[index - 1].layer_id => {}
            (_, SnapshotFormat::Qcow2, Some(_)) => {
                return descriptor_error("qcow2 successor must name its immediate predecessor");
            }
            (_, SnapshotFormat::Qcow2, None) => {
                return descriptor_error("qcow2 successor is missing its backing layer");
            }
        }
        if let Some(integrity) = &layer.payload.integrity {
            validate_integrity(integrity, layer.virtual_size)?;
        }
    }
    let head = file.head_layer()?;
    if head.format != file.disk_format || head.virtual_size != file.virtual_size {
        return descriptor_error("head format/size does not match file state");
    }
    Ok(())
}

fn validate_integrity(integrity: &UpperIntegrity, virtual_size: u64) -> ImageResult<()> {
    match integrity {
        UpperIntegrity::Sha256 { digest } | UpperIntegrity::SparseSha256V1 { digest } => {
            validate_digest(digest, "sha256:", "layer integrity digest")
        }
        UpperIntegrity::FileMerkleBlake3V1 {
            root,
            logical_size,
            leaf_size,
        } => {
            validate_digest(root, "blake3:", "layer integrity root")?;
            if *logical_size != virtual_size {
                return descriptor_error(
                    "layer integrity logical_size does not match virtual_size",
                );
            }
            if *leaf_size != FILE_MERKLE_BLAKE3_LEAF_SIZE {
                return descriptor_error(format!(
                    "layer integrity leaf_size must be {FILE_MERKLE_BLAKE3_LEAF_SIZE}"
                ));
            }
            Ok(())
        }
    }
}

fn validate_digest(value: &str, prefix: &str, field: &str) -> ImageResult<()> {
    let Some(encoded) = value.strip_prefix(prefix) else {
        return descriptor_error(format!("{field} must use {prefix}: {value}"));
    };
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return descriptor_error(format!("invalid {field}: {value}"));
    }
    Ok(())
}

fn normalize_timestamp(value: &str) -> ImageResult<String> {
    let parsed = DateTime::parse_from_rfc3339(value).map_err(|error| {
        descriptor_error_value(format!("capture.created_at is not RFC 3339: {error}"))
    })?;
    Ok(parsed
        .with_timezone(&Utc)
        .to_rfc3339_opts(SecondsFormat::Nanos, true))
}

pub(crate) fn reject_duplicate_json_keys(bytes: &[u8]) -> ImageResult<()> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    DuplicateCheckedJson::deserialize(&mut deserializer)
        .map_err(|error| descriptor_error_value(format!("parse failed: {error}")))?;
    deserializer
        .end()
        .map_err(|error| descriptor_error_value(format!("parse failed: {error}")))
}

fn validate_json_value(value: &serde_json::Value, depth: usize) -> ImageResult<()> {
    if depth > 64 {
        return descriptor_error("extension nesting exceeds 64 levels");
    }
    match value {
        serde_json::Value::Number(number) => {
            let valid = number
                .as_i64()
                .map(|n| n.unsigned_abs() <= MAX_JSON_SAFE_INTEGER)
                .or_else(|| number.as_u64().map(|n| n <= MAX_JSON_SAFE_INTEGER))
                .unwrap_or(false);
            if !valid {
                return descriptor_error("extension numbers must be JSON-safe integers");
            }
        }
        serde_json::Value::Array(items) => {
            if items.len() > 4096 {
                return descriptor_error("extension array exceeds 4096 entries");
            }
            for item in items {
                validate_json_value(item, depth + 1)?;
            }
        }
        serde_json::Value::Object(map) => {
            if map.len() > 4096 {
                return descriptor_error("extension object exceeds 4096 entries");
            }
            for item in map.values() {
                validate_json_value(item, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn write_canonical_json(
    value: &serde_json::Value,
    output: &mut Vec<u8>,
) -> ImageResult<()> {
    match value {
        serde_json::Value::Null => output.extend_from_slice(b"null"),
        serde_json::Value::Bool(true) => output.extend_from_slice(b"true"),
        serde_json::Value::Bool(false) => output.extend_from_slice(b"false"),
        serde_json::Value::Number(number) => {
            output.extend_from_slice(number.to_string().as_bytes())
        }
        serde_json::Value::String(string) => serde_json::to_writer(output, string)
            .map_err(|e| descriptor_error_value(format!("canonical string: {e}")))?,
        serde_json::Value::Array(items) => {
            output.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(item, output)?;
            }
            output.push(b']');
        }
        serde_json::Value::Object(map) => {
            output.push(b'{');
            let mut entries: Vec<_> = map.iter().collect();
            // RFC 8785 orders object names by their UTF-16 code units, not
            // Rust's UTF-8 byte/string ordering. The distinction matters for
            // non-BMP extension keys and therefore for descriptor identity.
            entries
                .sort_unstable_by(|left, right| left.0.encode_utf16().cmp(right.0.encode_utf16()));
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)
                    .map_err(|e| descriptor_error_value(format!("canonical key: {e}")))?;
                output.push(b':');
                write_canonical_json(item, output)?;
            }
            output.push(b'}');
        }
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

    fn descriptor() -> Manifest {
        let layer_id = DiskLayerId::new("layer_0123456789abcdef0123456789abcdef").unwrap();
        Manifest {
            schema: SCHEMA.into(),
            snapshot_id: SnapshotId::new("snap_0123456789abcdef0123456789abcdef").unwrap(),
            scope: SnapshotScope::Disk,
            state: SnapshotState::File(FileSnapshotState {
                disk_format: SnapshotFormat::Raw,
                filesystem: "ext4".into(),
                virtual_size: 4,
                head: layer_id.clone(),
                layers: vec![DiskLayer {
                    layer_id,
                    format: SnapshotFormat::Raw,
                    virtual_size: 4,
                    backing: None,
                    payload: LayerPayload {
                        file_kind: LayerFileKind::Regular,
                        integrity: None,
                    },
                }],
            }),
            capture: SnapshotCapture {
                created_at: "2026-08-29T00:00:00Z".into(),
                source_lineage: Some("sandbox-a".into()),
                source_checkpoint: None,
                consistency: SnapshotConsistency::CrashConsistent,
            },
            image: ImageRef {
                reference: "docker.io/library/alpine:latest".into(),
                manifest_digest: format!("sha256:{}", "a".repeat(64)),
            },
            parent: None,
            requires: Vec::new(),
            extensions: BTreeMap::new(),
        }
    }

    #[test]
    fn canonical_descriptor_round_trips() {
        let descriptor = descriptor();
        let bytes = descriptor.to_canonical_bytes().unwrap();
        assert_eq!(
            Manifest::from_bytes(&bytes)
                .unwrap()
                .to_canonical_bytes()
                .unwrap(),
            bytes
        );
        assert!(
            std::str::from_utf8(&bytes)
                .unwrap()
                .starts_with("{\"capture\":")
        );
    }

    #[test]
    fn descriptor_digest_is_not_snapshot_id() {
        let descriptor = descriptor();
        assert_ne!(
            descriptor.digest().unwrap(),
            descriptor.snapshot_id.as_str()
        );
    }

    #[test]
    fn rejects_nonlinear_closure() {
        let mut descriptor = descriptor();
        let SnapshotState::File(file) = &mut descriptor.state else {
            unreachable!()
        };
        file.layers.push(DiskLayer {
            layer_id: DiskLayerId::new("layer_11111111111111111111111111111111").unwrap(),
            format: SnapshotFormat::Qcow2,
            virtual_size: 4,
            backing: None,
            payload: LayerPayload {
                file_kind: LayerFileKind::Regular,
                integrity: None,
            },
        });
        file.head = file.layers[1].layer_id.clone();
        file.disk_format = SnapshotFormat::Qcow2;
        assert!(descriptor.validate().is_err());
    }
}
