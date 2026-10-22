//! Versioned portable document and cross-section consistency checks.
//!
//! This is an internal schema under construction. It does not enable the required
//! extension; captured resource identity, capture evidence and activation remain separate gates.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::snapshot::{GUEST_CLOCK_EXTENSION, Manifest, RESTORE_DEFAULTS_EXTENSION};
use crate::{GuestClockPolicy, SnapshotManifestError, SnapshotManifestResult};

use super::inventory::{merge_binding_uses, validate_inventory_uses};
use super::validation::{MAX_NAME_BYTES, MAX_SAVED_SCRIPTS_BYTES, decode, encoded_size, invalid};
use super::value::deserialize_present;
use super::{
    SavedBindingKind, SavedBindingUses, SavedExecutionConfig, SavedNetworkConfig,
    SavedResourcesConfig, SavedRuntimeConfig, SavedScript, SavedScriptBacking, SavedStorageConfig,
    SavedValue, collect_binding_uses,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Version belongs inside the record, never in the extension key.
pub const SAVED_CONFIG_SCHEMA_VERSION: u32 = 1;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One bounded document associated with the immutable checkpoint's descriptor digest.
/// No generic JSON field can carry raw source config, credentials or host lookup instructions.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedSandboxConfig {
    /// Unsupported versions fail before a consumer uses any settings.
    pub schema_version: u32,
    /// Known active values and explicit unknowns, never desired-next-start fallback.
    pub active: SavedActiveConfig,
    /// Value shapes only. Purpose and activation demand are derived from the references.
    pub bindings: BTreeMap<String, SavedBindingKind>,
    /// Safe source evidence, not executable defaults or destination allocation authority.
    pub provenance: SavedCaptureProvenance,
    /// Sanitized desired-next-start settings, never automatic restore defaults.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub pending: Option<SavedActiveConfig>,
}

/// Portable policy sections; authoritative captured-resource checks remain activation gates.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedActiveConfig {
    /// Guest allocation and huge-page policy; checkpoint geometry remains authoritative.
    #[serde(default)]
    pub resources: SavedResourcesConfig,
    /// Configured command/init/script defaults, without a foreground invocation.
    #[serde(default)]
    pub runtime: SavedRuntimeConfig,
    /// Observed registered-file metadata for full capture; not reusable policy or handle admission.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub script_backing: Option<SavedValue<SavedScriptBacking>>,
    /// Ordered gateway policy and logical destination network resources.
    #[serde(default)]
    pub network: SavedNetworkConfig,
    /// User labels, new-process security/limits and fresh lifetime durations.
    #[serde(default)]
    pub execution: SavedExecutionConfig,
    /// Guest mount and IPC requirements; source paths and sockets are never defaults.
    #[serde(default)]
    pub storage: SavedStorageConfig,
}

/// A deliberately small safe provenance record; no arbitrary config or source paths.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedCaptureProvenance {
    /// Producer version used for diagnostics, not permission to skip validation.
    pub producer_version: String,
    /// Optional source name; it never selects a destination or source database row.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub source_name: Option<String>,
    /// Capture's coherent runtime/config generation, or an explicit unavailable observation.
    /// Merely recording a generation is not proof: the capture path must pin/check it.
    pub active_generation: SavedValue<String>,
    /// Original construction geometry, separate from active confirmed allocation.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub construction_resources: Option<SavedResourcesConfig>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SavedSandboxConfig {
    /// Decode and validate the whole bounded document before importing or resolving it.
    pub fn from_bytes(bytes: &[u8]) -> SnapshotManifestResult<Self> {
        let config: Self = decode(bytes, "sandbox-config")?;
        config.validate()?;
        Ok(config)
    }

    /// Validate typed capture output too; callers cannot bypass bounds via direct construction.
    pub fn validate(&self) -> SnapshotManifestResult<()> {
        encoded_size(self, "sandbox-config")?;
        if self.schema_version != SAVED_CONFIG_SCHEMA_VERSION {
            return invalid(
                "SCFG_SCHEMA",
                "schema_version",
                "unsupported saved configuration version",
            );
        }
        self.active.validate()?;
        self.active.runtime.validate_active_role()?;
        self.active.storage.validate_active()?;
        self.active.resources.validate_active_observations()?;
        self.provenance.validate()?;
        let mut uses = collect_binding_uses(&self.active.runtime, &self.active.network)?;
        merge_binding_uses(&mut uses, self.active.storage.binding_uses()?)?;
        let mut script_bytes = self.active.inline_script_bytes();
        if let Some(pending) = &self.pending {
            if pending.script_backing.is_some() {
                return invalid(
                    "SCFG_IDENTITY",
                    "pending.script_backing",
                    "pending intent cannot contain observed backing",
                );
            }
            // Pending input receives the same exclusion/validation contract, but it
            // contributes no activation demand. Do not hand this union to a launcher.
            pending.validate().map_err(pending_error)?;
            merge_binding_uses(
                &mut uses,
                pending.storage.binding_uses().map_err(pending_error)?,
            )?;
            script_bytes += pending.inline_script_bytes();
            merge_binding_uses(
                &mut uses,
                collect_binding_uses(&pending.runtime, &pending.network).map_err(pending_error)?,
            )?;
        }
        if script_bytes > MAX_SAVED_SCRIPTS_BYTES {
            return invalid(
                "SCFG_LIMIT",
                "sandbox-config",
                "combined active and pending script payload is too large",
            );
        }
        validate_inventory_uses(&uses, &self.bindings)
    }

    /// Potential active consumers only; pending requirements cannot become restore defaults.
    /// Resolve saved/fresh mode and destination overrides before activation demand is decided.
    pub fn active_binding_uses(&self) -> SnapshotManifestResult<SavedBindingUses> {
        self.validate()?;
        let mut uses = collect_binding_uses(&self.active.runtime, &self.active.network)?;
        merge_binding_uses(&mut uses, self.active.storage.binding_uses()?)?;
        Ok(uses)
    }

    /// Check duplicated legacy projections without mutating their released encodings.
    /// This method is not registered with the manifest reader until the feature is complete.
    pub fn validate_legacy_projections(&self, manifest: &Manifest) -> SnapshotManifestResult<()> {
        self.validate()?;
        self.active.storage.validate_owned_projection(manifest)?;
        if manifest.extensions.contains_key(RESTORE_DEFAULTS_EXTENSION)
            && let Some(saved) = &self.active.runtime.user
        {
            let legacy = manifest
                .restore_defaults()
                .map_err(|_| projection_error("active.runtime.user"))?;
            let agrees = match saved {
                SavedValue::Value { value, .. } => legacy.user.as_ref() == Some(value),
                SavedValue::Default {} => legacy.user.is_none(),
                SavedValue::Unknown { .. } => false,
            };
            if !agrees {
                return Err(projection_error("active.runtime.user"));
            }
        }
        if let Some(saved) = &self.active.runtime.guest_clock {
            // Unlike an unknown optional projection, an absent legacy clock
            // extension explicitly means Sync. Saved policy must agree with it.
            let legacy = manifest
                .guest_clock()
                .map_err(|_| projection_error("active.runtime.guest_clock"))?;
            let agrees = match saved {
                SavedValue::Value { value, .. } => *value == legacy,
                SavedValue::Default {} => legacy == GuestClockPolicy::Sync,
                // An unrecorded source remains unknown until destination selection.
                // Only an explicit legacy record contradicts that unknown projection.
                SavedValue::Unknown { .. } => {
                    !manifest.extensions.contains_key(GUEST_CLOCK_EXTENSION)
                }
            };
            if !agrees {
                return Err(projection_error("active.runtime.guest_clock"));
            }
        }
        Ok(())
    }
}

impl SavedActiveConfig {
    /// Validate each typed section before binding cross-checks or destination resolution.
    pub fn validate(&self) -> SnapshotManifestResult<()> {
        self.resources.validate()?;
        self.runtime.validate()?;
        match &self.script_backing {
            None | Some(SavedValue::Unknown { .. }) => {}
            Some(SavedValue::Value {
                value,
                origin: super::SavedOrigin::Observed,
            }) => value.validate(&self.runtime)?,
            _ => {
                return invalid(
                    "SCFG_IDENTITY",
                    "active.script_backing",
                    "script metadata must be observed",
                );
            }
        }
        self.network.validate()?;
        self.execution.validate()?;
        self.storage.validate()
    }

    fn inline_script_bytes(&self) -> usize {
        self.runtime
            .scripts
            .as_ref()
            .and_then(SavedValue::value)
            .map_or(0, |scripts| {
                scripts
                    .values()
                    .map(|script| match script {
                        SavedScript::Inline { content, .. }
                        | SavedScript::Declaration { content } => content.len(),
                        SavedScript::Binding { .. } => 0,
                    })
                    .sum()
            })
    }
}

impl SavedCaptureProvenance {
    fn validate(&self) -> SnapshotManifestResult<()> {
        for (field, value) in [
            ("provenance.producer_version", Some(&self.producer_version)),
            ("provenance.source_name", self.source_name.as_ref()),
            (
                "provenance.active_generation",
                self.active_generation.value(),
            ),
        ] {
            if let Some(value) = value
                && (value.is_empty()
                    || value.len() > MAX_NAME_BYTES
                    || value.chars().any(char::is_control))
            {
                return invalid("SCFG_VALUE", field, "invalid provenance identifier");
            }
        }
        // A generation can be observed or unknown. A default isn't evidence of
        // a stable capture, and a requested generation cannot become observed fact.
        if matches!(
            &self.active_generation,
            SavedValue::Default {}
                | SavedValue::Value {
                    origin: super::SavedOrigin::Configured
                        | super::SavedOrigin::Image
                        | super::SavedOrigin::Platform,
                    ..
                }
        ) {
            return invalid(
                "SCFG_VALUE",
                "provenance.active_generation",
                "generation must be observed or explicitly unknown",
            );
        }
        if let Some(resources) = &self.construction_resources {
            resources.validate().map_err(|_| {
                super::validation::error(
                    "SCFG_VALUE",
                    "provenance.construction_resources",
                    "invalid construction geometry",
                )
            })?;
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn projection_error(field: &str) -> SnapshotManifestError {
    super::validation::error(
        "SCFG_IDENTITY",
        field,
        "saved configuration disagrees with legacy projection",
    )
}

fn pending_error(error: SnapshotManifestError) -> SnapshotManifestError {
    // Only errors produced by the already redacted typed validators reach here.
    // Preserve their actionable field/code while identifying the non-active section.
    match error {
        SnapshotManifestError::ManifestParse(message) => {
            SnapshotManifestError::ManifestParse(message.replacen("active.", "pending.", 1))
        }
    }
}
