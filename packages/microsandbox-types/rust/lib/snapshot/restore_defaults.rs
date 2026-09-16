//! Portable execution defaults, distinct from credentials of captured processes.

use serde::{Deserialize, Serialize};

use super::Manifest;
use crate::error::{SnapshotManifestError, SnapshotManifestResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Must-understand key for the sandbox defaults retained by a snapshot.
pub const RESTORE_DEFAULTS_EXTENSION: &str = "microsandbox.restore-defaults";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Defaults for commands started after restore; never changes captured process credentials.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreDefaults {
    /// Effective sandbox-level user, not a one-command exec override.
    pub user: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Manifest {
    /// Record execution defaults without embedding source host bindings or credentials.
    pub fn set_restore_defaults(
        &mut self,
        defaults: RestoreDefaults,
    ) -> SnapshotManifestResult<()> {
        validate_defaults(&defaults)?;
        // Absence preserves the released descriptor's image-default semantics, including
        // downgrade eligibility. Only an actual override needs a required extension.
        if defaults.user.is_none() {
            self.extensions.remove(RESTORE_DEFAULTS_EXTENSION);
            self.requires
                .retain(|key| key != RESTORE_DEFAULTS_EXTENSION);
            return Ok(());
        }
        self.extensions.insert(
            RESTORE_DEFAULTS_EXTENSION.into(),
            serde_json::to_value(defaults)
                .map_err(|error| SnapshotManifestError::ManifestParse(error.to_string()))?,
        );
        // An older reader must refuse rather than silently execute as a different user.
        self.requires.push(RESTORE_DEFAULTS_EXTENSION.into());
        self.requires.sort();
        self.requires.dedup();
        Ok(())
    }

    /// Read bounded, typed defaults; released snapshots without the extension use image defaults.
    pub fn restore_defaults(&self) -> SnapshotManifestResult<RestoreDefaults> {
        let Some(value) = self.extensions.get(RESTORE_DEFAULTS_EXTENSION) else {
            return Ok(RestoreDefaults::default());
        };
        let defaults: RestoreDefaults = serde_json::from_value(value.clone()).map_err(|error| {
            SnapshotManifestError::ManifestParse(format!("invalid restore defaults: {error}"))
        })?;
        validate_defaults(&defaults)?;
        Ok(defaults)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn validate_defaults(defaults: &RestoreDefaults) -> SnapshotManifestResult<()> {
    if defaults
        .user
        .as_ref()
        .is_some_and(|user| user.is_empty() || user.len() > 4096 || user.contains('\0'))
    {
        return Err(SnapshotManifestError::ManifestParse(
            "invalid snapshot default exec user".into(),
        ));
    }
    Ok(())
}
