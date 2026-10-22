//! Bounded decoding and redacted diagnostics shared by portable config sections.

use serde::{Serialize, de::DeserializeOwned};

use crate::error::{SnapshotManifestError, SnapshotManifestResult};
use crate::snapshot::MAX_JSON_SAFE_INTEGER;
use crate::snapshot::manifest::reject_duplicate_json_keys;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum encoded portable configuration, within the existing 1 MiB descriptor limit.
pub const MAX_SAVED_CONFIG_BYTES: usize = 512 * 1024;
/// Maximum entries in each saved map or argument list.
pub const MAX_SAVED_CONFIG_ENTRIES: usize = 256;
/// Maximum UTF-8 bytes in one normalized inline script.
pub const MAX_SAVED_SCRIPT_BYTES: usize = 64 * 1024;
/// Maximum combined inline script bytes in one configuration.
pub const MAX_SAVED_SCRIPTS_BYTES: usize = 256 * 1024;

/// Maximum UTF-8 bytes in one runtime argument or environment value, including bound inputs.
pub const MAX_TEXT_BYTES: usize = 64 * 1024;
pub(super) const MAX_NAME_BYTES: usize = 256;
pub(super) const MAX_GUEST_PATH_BYTES: usize = 4096;
const MAX_BINDING_ID_BYTES: usize = 128;
const MAX_CONFIG_DEPTH: usize = 24;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn decode<T: DeserializeOwned>(bytes: &[u8], field: &str) -> SnapshotManifestResult<T> {
    if bytes.len() > MAX_SAVED_CONFIG_BYTES {
        return invalid("SCFG_LIMIT", field, "encoded configuration is too large");
    }
    // The shared duplicate visitor may include attacker-controlled keys in its
    // error. Do not forward that text through this sensitive document boundary.
    reject_duplicate_json_keys(bytes)
        .map_err(|_| error("SCFG_JSON", field, "invalid JSON or duplicate object key"))?;
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| error("SCFG_JSON", field, "invalid JSON"))?;
    validate_tree(&value, 0, field)?;
    serde_json::from_value(value).map_err(|_| {
        error(
            "SCFG_SCHEMA",
            field,
            "unknown field, invalid type or invalid value state",
        )
    })
}

pub(super) fn encoded_size<T: Serialize>(value: &T, field: &str) -> SnapshotManifestResult<()> {
    let json = serde_json::to_value(value)
        .map_err(|_| error("SCFG_SCHEMA", field, "cannot encode configuration"))?;
    validate_tree(&json, 0, field)?;
    let encoded = serde_json::to_vec(&json)
        .map_err(|_| error("SCFG_SCHEMA", field, "cannot encode configuration"))?;
    if encoded.len() > MAX_SAVED_CONFIG_BYTES {
        return invalid("SCFG_LIMIT", field, "encoded configuration is too large");
    }
    Ok(())
}

pub(super) fn error(code: &str, field: &str, detail: &str) -> SnapshotManifestError {
    SnapshotManifestError::ManifestParse(format!("{code}: {field}: {detail}"))
}

pub(super) fn invalid<T>(code: &str, field: &str, detail: &str) -> SnapshotManifestResult<T> {
    Err(error(code, field, detail))
}

pub(super) fn count(length: usize, field: &str) -> SnapshotManifestResult<()> {
    if length > MAX_SAVED_CONFIG_ENTRIES {
        return invalid("SCFG_LIMIT", field, "too many entries");
    }
    Ok(())
}

pub(super) fn binding(id: &str, field: &str) -> SnapshotManifestResult<()> {
    if id.is_empty()
        || id.len() > MAX_BINDING_ID_BYTES
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return invalid("SCFG_BINDING", field, "invalid logical binding identifier");
    }
    Ok(())
}

fn validate_tree(
    value: &serde_json::Value,
    depth: usize,
    field: &str,
) -> SnapshotManifestResult<()> {
    if depth > MAX_CONFIG_DEPTH {
        return invalid("SCFG_LIMIT", field, "configuration nesting is too deep");
    }
    match value {
        serde_json::Value::Number(number) => {
            let exact = number.as_u64().is_some_and(|n| n <= MAX_JSON_SAFE_INTEGER)
                || number
                    .as_i64()
                    .is_some_and(|n| n.unsigned_abs() <= MAX_JSON_SAFE_INTEGER);
            if !exact {
                return invalid(
                    "SCFG_VALUE",
                    field,
                    "numbers must be exact JSON-safe integers",
                );
            }
        }
        serde_json::Value::Array(values) => {
            count(values.len(), field)?;
            for value in values {
                validate_tree(value, depth + 1, field)?;
            }
        }
        serde_json::Value::Object(values) => {
            count(values.len(), field)?;
            for value in values.values() {
                validate_tree(value, depth + 1, field)?;
            }
        }
        _ => {}
    }
    Ok(())
}
