//! Select process defaults and enforce guest-security admission without starting a guest.

use std::collections::{BTreeMap, BTreeSet};

use microsandbox_types::snapshot::saved_config::{
    SavedExecutionConfig, SavedLifetimePolicy, SavedRlimit, SavedU64, SavedValue,
};
use microsandbox_types::{SandboxSpecPatch, SecurityProfile};

use crate::{MicrosandboxError, MicrosandboxResult};

use super::SnapshotConfigMode;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Destination-owned policy, never read from portable artifact permission claims.
#[derive(Debug, Clone, Copy)]
pub struct DestinationGuestSecurity {
    /// Ordinary destination profile. Saved defaults cannot implicitly weaken it.
    pub baseline: SecurityProfile,
    /// Mandatory minimum, including constraints no caller option can override.
    pub minimum: SecurityProfile,
}

/// Verified captured guest policy is separate from optional saved defaults.
#[derive(Debug, Clone, Copy)]
pub enum ExecutionRestoreMode {
    /// A new guest boot may select its security profile.
    Disk,
    /// The caller obtained this policy from authoritative captured execution evidence.
    Full { captured_security: SecurityProfile },
}

/// Optional execution defaults that can be discarded before explicit inputs apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionDefaultClear {
    /// Clear all optional user labels.
    Labels,
    /// Clear one exact label key; dots have no special meaning.
    LabelKey(String),
    /// Select the destination security default; prohibited during full resume.
    Security,
    /// Clear the complete default resource-limit list for new processes.
    Rlimits,
    /// Clear both optional lifetime duration defaults.
    Lifetime,
    /// Clear only the maximum-duration default.
    MaxDuration,
    /// Clear only the idle-timeout default.
    IdleTimeout,
}

/// Per-field lifetime overlays distinguish omission, unknown and known unlimited.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LifetimeDefaultSelection {
    /// A concrete None means unlimited; an outer None means no saved fallback.
    pub max_duration_secs: Option<SavedValue<Option<SavedU64>>>,
    /// A concrete None disables idle detection; zero is a separate concrete value.
    pub idle_timeout_secs: Option<SavedValue<Option<SavedU64>>>,
}

/// Defaults for new commands/timers, plus a policy-admitted guest security choice.
/// Captured processes and elapsed counters are never modified by this pure result.
#[derive(Debug)]
pub struct ExecutionDefaultSelection {
    /// Remaining saved labels, excluding keys supplied by the destination.
    pub labels: Option<SavedValue<BTreeMap<String, String>>>,
    /// Optional saved resource-limit list; explicit lists replace it in full.
    pub rlimits: Option<SavedValue<Vec<SavedRlimit>>>,
    /// New destination timer defaults, never source elapsed time or ownership.
    pub lifetime: LifetimeDefaultSelection,
    /// Selected boot profile or the unchanged authoritative captured guest profile.
    pub security_profile: SecurityProfile,
    /// Optional settings whose source value is not known.
    pub unknown_fields: BTreeSet<&'static str>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Select execution defaults using explicit destination intent and mandatory policy.
///
/// Explicit values stay in the original patch. Resource limits affect future execs,
/// and lifetime durations start new host timers. System labels must still be regenerated
/// by destination identity assembly. This function does not start any timer or process.
pub fn select_execution_defaults(
    saved: &SavedExecutionConfig,
    explicit: &SandboxSpecPatch,
    clears: &[ExecutionDefaultClear],
    config_mode: SnapshotConfigMode,
    restore_mode: ExecutionRestoreMode,
    security: DestinationGuestSecurity,
) -> MicrosandboxResult<ExecutionDefaultSelection> {
    saved
        .validate()
        .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))?;
    // A new portable execution field must receive a selection rule here.
    let SavedExecutionConfig {
        labels: source_labels,
        rlimits: source_rlimits,
        lifecycle,
        security_profile: _,
    } = saved;
    if clears.len() > microsandbox_types::snapshot::saved_config::MAX_SAVED_CONFIG_ENTRIES {
        return invalid("SCFG_LIMIT", "execution", "too many clear selectors");
    }
    for clear in clears {
        if let ExecutionDefaultClear::LabelKey(key) = clear
            && !saved
                .labels
                .as_ref()
                .and_then(SavedValue::value)
                .is_some_and(|labels| labels.contains_key(key))
        {
            return invalid(
                "SCFG_CLEAR",
                "execution.labels",
                "selected key is not recorded; clear the whole optional field instead",
            );
        }
    }
    let security_profile =
        select_security(saved, explicit, clears, config_mode, restore_mode, security)?;
    let (mut labels, mut rlimits, mut lifetime) = match config_mode {
        SnapshotConfigMode::Saved => (
            source_labels.clone(),
            source_rlimits.clone(),
            split_lifetime(lifecycle.as_ref()),
        ),
        SnapshotConfigMode::Fresh => (None, None, LifetimeDefaultSelection::default()),
    };
    for clear in clears {
        match clear {
            ExecutionDefaultClear::Labels => labels = None,
            ExecutionDefaultClear::LabelKey(key) => {
                if let Some(SavedValue::Value { value, .. }) = &mut labels {
                    value.remove(key);
                }
            }
            ExecutionDefaultClear::Rlimits => rlimits = None,
            ExecutionDefaultClear::Lifetime => lifetime = LifetimeDefaultSelection::default(),
            ExecutionDefaultClear::MaxDuration => lifetime.max_duration_secs = None,
            ExecutionDefaultClear::IdleTimeout => lifetime.idle_timeout_secs = None,
            ExecutionDefaultClear::Security => {} // Handled before any optional mutation above.
        }
    }
    if explicit.replaces_labels() {
        labels = None;
    } else if let Some(overrides) = explicit.get_labels()
        && let Some(SavedValue::Value { value, .. }) = &mut labels
    {
        for key in overrides.keys() {
            value.remove(key);
        }
    }
    if explicit.rlimits.is_some() {
        rlimits = None;
    }
    if explicit.lifecycle.max_duration_secs.is_some() {
        lifetime.max_duration_secs = None;
    }
    if explicit.lifecycle.idle_timeout_secs.is_some() {
        lifetime.idle_timeout_secs = None;
    }

    let unknown_fields = [
        (
            "execution.labels",
            matches!(labels, Some(SavedValue::Unknown { .. })),
        ),
        (
            "execution.rlimits",
            matches!(rlimits, Some(SavedValue::Unknown { .. })),
        ),
        (
            "execution.lifecycle.max_duration_secs",
            matches!(lifetime.max_duration_secs, Some(SavedValue::Unknown { .. })),
        ),
        (
            "execution.lifecycle.idle_timeout_secs",
            matches!(lifetime.idle_timeout_secs, Some(SavedValue::Unknown { .. })),
        ),
    ]
    .into_iter()
    .filter_map(|(path, unknown)| unknown.then_some(path))
    .collect();
    Ok(ExecutionDefaultSelection {
        labels,
        rlimits,
        lifetime,
        security_profile,
        unknown_fields,
    })
}

fn select_security(
    saved: &SavedExecutionConfig,
    explicit: &SandboxSpecPatch,
    clears: &[ExecutionDefaultClear],
    config_mode: SnapshotConfigMode,
    restore_mode: ExecutionRestoreMode,
    destination: DestinationGuestSecurity,
) -> MicrosandboxResult<SecurityProfile> {
    let clear = clears.contains(&ExecutionDefaultClear::Security);
    let profile = match restore_mode {
        ExecutionRestoreMode::Full { captured_security } => {
            if clear || explicit.security_profile.is_some() {
                return invalid(
                    "SCFG_FULL_STATE",
                    "execution.security_profile",
                    "security overrides and clears require disk boot",
                );
            }
            // Fresh mode cannot waive disagreement between metadata and captured
            // execution. Unknown/omitted metadata never replaces verified evidence.
            if recorded_security(saved.security_profile.as_ref())
                .is_some_and(|recorded| recorded != captured_security)
            {
                return invalid(
                    "SCFG_INTEGRITY",
                    "execution.security_profile",
                    "saved policy disagrees with captured execution",
                );
            }
            captured_security
        }
        ExecutionRestoreMode::Disk => match explicit.security_profile {
            Some(profile) => profile,
            None if config_mode == SnapshotConfigMode::Fresh || clear => destination.baseline,
            None => match saved.security_profile.as_ref() {
                Some(SavedValue::Unknown { .. }) => {
                    return invalid(
                        "SCFG_UNKNOWN",
                        "execution.security_profile",
                        "recorded guest policy is unknown; select an explicit disk-boot policy or discard this optional default",
                    );
                }
                recorded => recorded_security(recorded).unwrap_or(destination.baseline),
            },
        },
    };
    if weaker(profile, destination.minimum) {
        return invalid(
            "SCFG_POLICY",
            "execution.security_profile",
            "guest policy does not satisfy mandatory destination security",
        );
    }
    if weaker(profile, destination.baseline) && explicit.security_profile.is_none() {
        return invalid(
            "SCFG_APPROVAL",
            "execution.security_profile",
            "saved or captured guest policy cannot implicitly weaken destination security",
        );
    }
    Ok(profile)
}

fn weaker(profile: SecurityProfile, baseline: SecurityProfile) -> bool {
    // Keep this exhaustive: a future profile needs an explicit ordering/admission
    // decision, rather than inheriting permission from numeric enum ordering.
    match (profile, baseline) {
        (SecurityProfile::Default, SecurityProfile::Restricted) => true,
        (SecurityProfile::Default, SecurityProfile::Default)
        | (SecurityProfile::Restricted, SecurityProfile::Default)
        | (SecurityProfile::Restricted, SecurityProfile::Restricted) => false,
    }
}

fn recorded_security(saved: Option<&SavedValue<SecurityProfile>>) -> Option<SecurityProfile> {
    match saved {
        Some(SavedValue::Value { value, .. }) => Some(*value),
        // Schema 1's builtin guest profile is the named Default profile. Do not
        // reinterpret saved metadata if Rust's Default implementation later changes.
        Some(SavedValue::Default {}) => Some(SecurityProfile::Default),
        Some(SavedValue::Unknown { .. }) | None => None,
    }
}

fn split_lifetime(saved: Option<&SavedValue<SavedLifetimePolicy>>) -> LifetimeDefaultSelection {
    match saved {
        None => LifetimeDefaultSelection::default(),
        Some(SavedValue::Default {}) => LifetimeDefaultSelection {
            max_duration_secs: Some(SavedValue::Default {}),
            idle_timeout_secs: Some(SavedValue::Default {}),
        },
        Some(SavedValue::Unknown { reason }) => LifetimeDefaultSelection {
            max_duration_secs: Some(SavedValue::Unknown { reason: *reason }),
            idle_timeout_secs: Some(SavedValue::Unknown { reason: *reason }),
        },
        Some(SavedValue::Value { value, origin }) => {
            let SavedLifetimePolicy {
                max_duration_secs,
                idle_timeout_secs,
            } = value;
            LifetimeDefaultSelection {
                max_duration_secs: Some(SavedValue::Value {
                    value: *max_duration_secs,
                    origin: *origin,
                }),
                idle_timeout_secs: Some(SavedValue::Value {
                    value: *idle_timeout_secs,
                    origin: *origin,
                }),
            }
        }
    }
}

fn invalid<T>(code: &str, path: &str, reason: &str) -> MicrosandboxResult<T> {
    Err(MicrosandboxError::InvalidConfig(format!(
        "{code}: {path}: {reason}"
    )))
}
