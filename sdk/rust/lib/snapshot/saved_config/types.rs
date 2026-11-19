//! Typed runtime selection controls; none are accepted as authorization from an archive.

use std::{collections::BTreeSet, fmt};

use microsandbox_types::snapshot::saved_config::{RuntimeBindingRequirements, SavedRuntimeConfig};
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Source of optional snapshot defaults. Required captured state is independent of this choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotConfigMode {
    /// Reuse eligible recorded defaults below explicit destination inputs.
    Saved,
    /// Discard optional defaults while retaining required captured execution state.
    Fresh,
}

/// Operation facts, supplied by the trusted source/operation resolver rather than the artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeSelectionContext {
    /// Whether optional saved defaults participate in destination resolution.
    pub config_mode: SnapshotConfigMode,
    /// Whether this operation resumes captured processes rather than booting the disk.
    pub full_resume: bool,
    /// Whether the current operation requests a new initial workload.
    pub starts_command: bool,
}

/// Structural optional-default clears; map keys containing dots stay one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeDefaultClear {
    /// Discard the saved guest working directory.
    Workdir,
    /// Discard the saved shell selection.
    Shell,
    /// Discard the complete saved entrypoint vector.
    Entrypoint,
    /// Discard the complete saved command vector.
    Cmd,
    /// Discard all optional saved environment entries.
    Env,
    /// Discard one exact saved environment key, without splitting dots.
    EnvKey(String),
    /// Discard optional registered scripts; unavailable for full resume.
    Scripts,
    /// Discard one exact registered script name; unavailable for full resume.
    ScriptKey(String),
    /// Discard the saved init selection and its arguments/environment.
    Init,
    /// Discard the saved guest hostname selection.
    Hostname,
    /// Discard the saved default identity for new processes.
    User,
    /// Discard optional saved clock policy; captured full-resume policy is retained.
    GuestClock,
}

/// Selected lower-priority runtime defaults, not an executable or authorized launch config.
/// Explicit destination values remain in their original sparse patch, never copied into
/// portable metadata here. All binding and full-state checks must finish before activation.
#[derive(Clone)]
pub struct RuntimeDefaultSelection {
    /// Saved defaults that survive mode, clears and explicit destination overrides.
    pub defaults: SavedRuntimeConfig,
    /// Whether a changed entrypoint needs a lower-priority empty CMD to block image fallback.
    pub reset_inherited_cmd: bool,
    /// Explicit full-resume script registrations requiring separate captured-backing proof.
    pub scripts_requiring_identity_check: BTreeSet<String>,
    /// Even replacing the script map with an empty map must pass captured-backing admission.
    pub script_replacement_requires_identity_check: bool,
    /// Derived remaining source binding consumers. These are not yet activation timing.
    pub binding_requirements: RuntimeBindingRequirements,
    /// Retained unknown fields; absence and a known builtin/default are not unknown values.
    pub unknown_fields: BTreeSet<&'static str>,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for RuntimeDefaultSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeDefaultSelection")
            .field("reset_inherited_cmd", &self.reset_inherited_cmd)
            .field(
                "script_checks",
                &self.scripts_requiring_identity_check.len(),
            )
            .field(
                "script_map_replacement",
                &self.script_replacement_requires_identity_check,
            )
            .field("binding_count", &self.binding_requirements.len())
            .field("unknown_fields", &self.unknown_fields)
            .finish_non_exhaustive()
    }
}
