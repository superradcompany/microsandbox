//! Project allocation evidence and execution defaults from the same guarded raw source.

use std::collections::BTreeSet;

use microsandbox_types::SandboxResources;
use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_ENTRIES, SavedExecutionConfig, SavedLifetimePolicy, SavedOrigin,
    SavedResourcesConfig, SavedRlimit, SavedUnknownReason, SavedValue,
};

use super::RuntimeCaptureSource;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Independently confirmed capacity from the same capture cut as the retained source.
/// Requested configuration, successful resize dispatch and construction geometry are not
/// sufficient evidence. Missing, unsupported or converging observations must retain their explicit unknown reason.
#[derive(Clone)]
pub struct ResourceCaptureObservation {
    /// Confirmed effective CPU count, independently of the desired target.
    pub cpus: SavedValue<u8>,
    /// Confirmed effective memory allocation in MiB, not a usage sample or requested target.
    pub memory_mib: SavedValue<u32>,
}

/// Capture-only exclusions for ordinary user labels. These are caller instructions,
/// never imported metadata or permission to weaken a destination security profile.
#[derive(Default)]
pub struct ExecutionCaptureControls {
    /// Omit all optional label defaults without constructing their portable values.
    pub omit_labels: bool,
    /// Exact user-label keys to omit. Keys are not paths and cannot select system labels.
    pub omit_label_keys: BTreeSet<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeCaptureSource<'_> {
    /// Project capacity only from supplied observations. Retained targets are deliberately
    /// ignored; static ceilings and THP require recorded presence, not serde defaults.
    /// This does not prove observation freshness or full-state geometry compatibility.
    pub fn project_resources(
        &self,
        observation: ResourceCaptureObservation,
    ) -> MicrosandboxResult<SavedResourcesConfig> {
        let SandboxResources {
            cpus: _,
            memory_mib: _,
            max_cpus,
            max_memory_mib,
            cpu_placement: _,
            placement_profile: _,
            thp,
        } = &self.config.spec.resources;
        let result = SavedResourcesConfig {
            cpus: Some(observed(observation.cpus, "resources.cpus")?),
            memory_mib: Some(observed(observation.memory_mib, "resources.memory_mib")?),
            max_cpus: Some(recorded(
                self.recorded.pointer("/resources/max_cpus").is_some(),
                *max_cpus,
            )),
            max_memory_mib: Some(recorded(
                self.recorded.pointer("/resources/max_memory_mib").is_some(),
                *max_memory_mib,
            )),
            thp: Some(recorded(
                self.recorded.pointer("/resources/thp").is_some()
                    || (self
                        .recorded
                        .get("resources")
                        .is_some_and(serde_json::Value::is_object)
                        && self
                            .config
                            .field_presence
                            .as_ref()
                            .is_some_and(|presence| presence.knows_thp(&self.config.spec))),
                *thp,
            )),
        };
        result
            .validate()
            .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))?;
        Ok(result)
    }

    /// Record desired next-start capacities, never confirmed guest allocation. Missing raw
    /// fields remain unknown even when decoding supplied a historical default.
    pub fn project_pending_resources(&self) -> MicrosandboxResult<SavedResourcesConfig> {
        let mut resources = self.project_resources(ResourceCaptureObservation::default())?;
        resources.cpus = Some(recorded(
            self.recorded.pointer("/resources/cpus").is_some(),
            self.config.spec.resources.cpus,
        ));
        resources.memory_mib = Some(recorded(
            self.recorded.pointer("/resources/memory_mib").is_some(),
            self.config.spec.resources.memory_mib,
        ));
        resources
            .validate()
            .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))?;
        Ok(resources)
    }

    /// Project reusable process policy without source ephemeral ownership, elapsed timers,
    /// system identity labels or per-invocation limits. Raw configuration is never portable output.
    /// Caller exclusions run before label cloning/validation; retained labels remain bounded.
    pub fn project_execution(
        &self,
        controls: &ExecutionCaptureControls,
    ) -> MicrosandboxResult<SavedExecutionConfig> {
        if controls.omit_label_keys.len() > MAX_SAVED_CONFIG_ENTRIES {
            return Err(invalid("SCFG_LIMIT", "too many label exclusions"));
        }
        if controls.omit_labels && !controls.omit_label_keys.is_empty() {
            return Err(invalid("SCFG_VALUE", "overlapping label exclusions"));
        }
        for key in &controls.omit_label_keys {
            if self.recorded.get("labels").is_none()
                || crate::sandbox::reserved_label_prefix(key).is_some()
                || !self.config.spec.labels.contains_key(key)
            {
                return Err(invalid(
                    "SCFG_VALUE",
                    "label exclusion did not match source",
                ));
            }
        }
        let labels = if controls.omit_labels {
            None
        } else if self.recorded.get("labels").is_none() {
            Some(unknown())
        } else {
            Some(configured(
                self.config
                    .spec
                    .labels
                    .iter()
                    .filter(|(key, _)| {
                        crate::sandbox::reserved_label_prefix(key).is_none()
                            && !controls.omit_label_keys.contains(*key)
                    })
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            ))
        };
        let rlimits = if self.recorded.get("rlimits").is_some() {
            Some(configured(
                self.config
                    .spec
                    .rlimits
                    .iter()
                    .map(SavedRlimit::from)
                    .collect(),
            ))
        } else {
            Some(unknown())
        };
        // An omitted duration in a historical object is not evidence of unlimited time.
        // Both durations must be recorded, even when their concrete value is null.
        let lifecycle = if ["max_duration_secs", "idle_timeout_secs"]
            .iter()
            .all(|field| {
                self.recorded
                    .get("lifecycle")
                    .and_then(|value| value.get(field))
                    .is_some()
            }) {
            Some(configured(SavedLifetimePolicy::from_source(
                &self.config.spec.lifecycle,
            )))
        } else {
            Some(unknown())
        };
        let result = SavedExecutionConfig {
            labels,
            security_profile: Some(recorded(
                self.recorded.get("security_profile").is_some(),
                self.config.spec.security_profile,
            )),
            rlimits,
            lifecycle,
        };
        result
            .validate()
            .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))?;
        Ok(result)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for ResourceCaptureObservation {
    fn default() -> Self {
        Self {
            cpus: SavedValue::Unknown {
                reason: SavedUnknownReason::NotObserved,
            },
            memory_mib: SavedValue::Unknown {
                reason: SavedUnknownReason::NotObserved,
            },
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn configured<T>(value: T) -> SavedValue<T> {
    SavedValue::Value {
        value,
        origin: SavedOrigin::Configured,
    }
}

fn unknown<T>() -> SavedValue<T> {
    SavedValue::Unknown {
        reason: SavedUnknownReason::NotRecorded,
    }
}

fn recorded<T>(present: bool, value: T) -> SavedValue<T> {
    if present {
        configured(value)
    } else {
        unknown()
    }
}

fn observed<T>(value: SavedValue<T>, field: &str) -> MicrosandboxResult<SavedValue<T>> {
    match value {
        SavedValue::Value {
            origin: SavedOrigin::Observed,
            ..
        }
        | SavedValue::Unknown { .. } => Ok(value),
        _ => Err(MicrosandboxError::InvalidConfig(format!(
            "SCFG_VALUE: {field}: active capacity requires observation, not a configured default"
        ))),
    }
}

fn invalid(code: &str, detail: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!("{code}: execution.labels: {detail}"))
}
