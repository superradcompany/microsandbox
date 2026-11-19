//! Observed guest metadata for registered scripts, separate from reusable command defaults.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};

use super::validation::{count, invalid};
use super::{SavedOrigin, SavedRuntimeConfig, SavedScript, SavedValue};
use crate::SnapshotManifestResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Guest-visible ownership and ordinary permission bits; never host ownership or file identity.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedScriptMetadata {
    /// Numeric guest owner.
    pub uid: u32,
    /// Numeric guest group.
    pub gid: u32,
    /// Ordinary permission bits, without privileged bits or file type.
    pub mode: u16,
}

/// Complete registered-script metadata observed at a full capture boundary.
/// This does not certify unregistered files or captured filesystem handle closure.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedScriptBacking {
    /// Metadata of the mounted guest runtime directory.
    pub runtime_directory: SavedScriptMetadata,
    /// Metadata of its scripts directory.
    pub scripts_directory: SavedScriptMetadata,
    /// Exactly the registered script inventory, without duplicate bodies or body hashes.
    pub files: BTreeMap<String, SavedScriptMetadata>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SavedScriptBacking {
    /// Validate against the sanitized runtime inventory, before destination overrides apply.
    pub fn validate(&self, runtime: &SavedRuntimeConfig) -> SnapshotManifestResult<()> {
        count(self.files.len(), "active.script_backing")?;
        let Some(SavedValue::Value {
            value: scripts,
            origin: SavedOrigin::Observed,
        }) = &runtime.scripts
        else {
            return invalid(
                "SCFG_IDENTITY",
                "active.script_backing",
                "observed script inventory is unavailable",
            );
        };
        if !self.files.keys().eq(scripts.keys()) {
            return invalid(
                "SCFG_IDENTITY",
                "active.script_backing",
                "registered inventory differs",
            );
        }
        for metadata in [self.runtime_directory, self.scripts_directory]
            .into_iter()
            .chain(self.files.values().copied())
        {
            if metadata.mode > 0o777 {
                return invalid(
                    "SCFG_VALUE",
                    "active.script_backing",
                    "unsupported permission bits",
                );
            }
        }
        for (name, metadata) in &self.files {
            match &scripts[name] {
                SavedScript::Inline { mode, .. } if *mode == metadata.mode => {}
                // A bound body deliberately has no retained digest. Its captured identity
                // remains unresolved; metadata equality alone never permits full resume.
                SavedScript::Binding { .. } => {}
                _ => {
                    return invalid(
                        "SCFG_IDENTITY",
                        "active.script_backing",
                        "script metadata disagrees with backing",
                    );
                }
            }
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for SavedScriptBacking {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SavedScriptBacking")
            .field("count", &self.files.len())
            .finish_non_exhaustive()
    }
}
