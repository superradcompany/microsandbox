//! Compose destination metadata, new-process limits and fresh timer durations only.

use std::{collections::BTreeMap, fmt};

use microsandbox_types::snapshot::saved_config::{SavedExecutionConfig, SavedU64, SavedValue};
use microsandbox_types::{Rlimit, SandboxPolicy, SandboxSpec, SandboxSpecPatch};

use super::{
    DestinationGuestSecurity, ExecutionDefaultClear, ExecutionDefaultSelection,
    ExecutionRestoreMode, SnapshotConfigMode, select_execution_defaults,
};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Native defaults only; applying these fields does not change any captured guest process.
pub struct ExecutionConfigurationPlan {
    labels: BTreeMap<String, String>,
    rlimits: Vec<Rlimit>,
    durations: SandboxPolicy,
    selection: ExecutionDefaultSelection,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExecutionConfigurationPlan {
    /// Retain source unknowns and the admitted guest-security decision without mutation.
    pub fn selection(&self) -> &ExecutionDefaultSelection {
        &self.selection
    }

    /// Apply only user labels, process defaults, guest-security selection and duration policy.
    /// Preserve destination identity labels and ephemeral ownership. The caller must enforce
    /// full-state rules and start new timers rather than copying source elapsed counters.
    pub fn apply_to(&self, target: &mut SandboxSpec) -> MicrosandboxResult<()> {
        if !self.selection.unknown_fields.is_empty() {
            return Err(error(
                "SCFG_UNKNOWN",
                "execution defaults need explicit resolution",
            ));
        }
        target
            .labels
            .retain(|key, _| crate::sandbox::reserved_label_prefix(key).is_some());
        target.labels.extend(self.labels.clone());
        target.rlimits.clone_from(&self.rlimits);
        target.security_profile = self.selection.security_profile;
        target.lifecycle.max_duration_secs = self.durations.max_duration_secs;
        target.lifecycle.idle_timeout_secs = self.durations.idle_timeout_secs;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for ExecutionConfigurationPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutionConfigurationPlan")
            .field("selection", &self.selection)
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Compose the selected execution overlay below sparse destination inputs. Source labels
/// are user metadata, never authority to copy/replace a sandbox identity. No unrelated spec
/// fields, source ownership, elapsed clocks or foreground invocation are consumed here.
pub fn prepare_execution_configuration(
    saved: &SavedExecutionConfig,
    lower: &SandboxSpec,
    explicit: &SandboxSpecPatch,
    clears: &[ExecutionDefaultClear],
    mode: SnapshotConfigMode,
    restore_mode: ExecutionRestoreMode,
    security: DestinationGuestSecurity,
) -> MicrosandboxResult<ExecutionConfigurationPlan> {
    let selection =
        select_execution_defaults(saved, explicit, clears, mode, restore_mode, security)?;
    // Validate the original source before fresh/clear/override can hide a forged identity.
    if let Some(labels) = saved.labels.as_ref().and_then(SavedValue::value) {
        validate_labels(labels)?;
    }
    if let Some(labels) = explicit.get_labels() {
        validate_labels(labels)?;
    }
    let mut labels: BTreeMap<_, _> = lower
        .labels
        .iter()
        .filter(|(key, _)| crate::sandbox::reserved_label_prefix(key).is_none())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let mut rlimits = lower.rlimits.clone();
    let mut durations = SandboxPolicy {
        ephemeral: false,
        max_duration_secs: lower.lifecycle.max_duration_secs,
        idle_timeout_secs: lower.lifecycle.idle_timeout_secs,
    };
    for clear in clears {
        match clear {
            ExecutionDefaultClear::Labels => labels.clear(),
            ExecutionDefaultClear::LabelKey(key) => {
                labels.remove(key);
            }
            ExecutionDefaultClear::Rlimits => rlimits.clear(),
            ExecutionDefaultClear::Lifetime => {
                durations.max_duration_secs = None;
                durations.idle_timeout_secs = None;
            }
            ExecutionDefaultClear::MaxDuration => durations.max_duration_secs = None,
            ExecutionDefaultClear::IdleTimeout => durations.idle_timeout_secs = None,
            ExecutionDefaultClear::Security => {} // The selector already admitted destination policy.
        }
    }
    match &selection.labels {
        Some(SavedValue::Value { value, .. }) => labels.clone_from(value),
        Some(SavedValue::Default {} | SavedValue::Unknown { .. }) => labels.clear(),
        None => {}
    }
    match &selection.rlimits {
        Some(SavedValue::Value { value, .. }) => {
            rlimits = value.iter().cloned().map(Into::into).collect()
        }
        Some(SavedValue::Default {} | SavedValue::Unknown { .. }) => rlimits.clear(),
        None => {}
    }
    duration(
        &selection.lifetime.max_duration_secs,
        &mut durations.max_duration_secs,
    );
    duration(
        &selection.lifetime.idle_timeout_secs,
        &mut durations.idle_timeout_secs,
    );
    if explicit.replaces_labels() {
        labels.clear();
    }
    if let Some(overrides) = explicit.get_labels() {
        labels.extend(overrides.clone());
    }
    if let Some(overrides) = &explicit.rlimits {
        rlimits.clone_from(overrides);
    }
    if let Some(value) = explicit.lifecycle.max_duration_secs {
        durations.max_duration_secs = Some(value);
    }
    if let Some(value) = explicit.lifecycle.idle_timeout_secs {
        durations.idle_timeout_secs = Some(value);
    }
    validate_labels(&labels)?;
    // Match existing native validation rather than imposing portable capture size limits
    // on explicit destination input. Preserve order and exact u64 unlimited sentinels.
    if rlimits.iter().any(|limit| limit.soft > limit.hard) {
        return Err(error(
            "SCFG_VALUE",
            "process soft limit exceeds its hard limit",
        ));
    }
    Ok(ExecutionConfigurationPlan {
        labels,
        rlimits,
        durations,
        selection,
    })
}

fn duration(saved: &Option<SavedValue<Option<SavedU64>>>, target: &mut Option<u64>) {
    match saved {
        Some(SavedValue::Value { value, .. }) => *target = value.map(SavedU64::get),
        Some(SavedValue::Default {} | SavedValue::Unknown { .. }) => *target = None,
        None => {}
    }
}

fn validate_labels(labels: &BTreeMap<String, String>) -> MicrosandboxResult<()> {
    crate::sandbox::validate_labels(labels)
        .map_err(|_| error("SCFG_IDENTITY", "labels must use valid user keys"))
}

fn error(code: &str, message: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!("{code}: execution: {message}"))
}
