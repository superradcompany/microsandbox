//! Recorded guest allocation, distinct from host placement and authoritative checkpoint geometry.

use serde::{Deserialize, Serialize};

use crate::{SnapshotManifestResult, TransparentHugePagePolicy};

use super::validation::{decode, encoded_size, invalid};
use super::value::deserialize_present;
use super::{SavedOrigin, SavedValue};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Active observed allocations or explicitly unavailable observations, not pending resize targets.
/// Full restore must additionally compare its authoritative checkpoint execution geometry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedResourcesConfig {
    /// Confirmed guest CPU count; unknown is not replaced with a requested target.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub cpus: Option<SavedValue<u8>>,
    /// Confirmed guest memory allocation in MiB.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub memory_mib: Option<SavedValue<u32>>,
    /// Configured maximum CPU count, separate from effective allocation.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub max_cpus: Option<SavedValue<u8>>,
    /// Configured maximum guest memory in MiB.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub max_memory_mib: Option<SavedValue<u32>>,
    /// Guest huge-page policy; full resume cannot change captured policy.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub thp: Option<SavedValue<TransparentHugePagePolicy>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SavedResourcesConfig {
    /// Decode portable resource settings without consulting source or destination hosts.
    pub fn from_bytes(bytes: &[u8]) -> SnapshotManifestResult<Self> {
        let config: Self = decode(bytes, "active.resources")?;
        config.validate()?;
        Ok(config)
    }

    /// Active capacity must be observed, not merely requested by creation or resize.
    /// Pending and construction records use ordinary validation instead.
    pub(super) fn validate_active_observations(&self) -> SnapshotManifestResult<()> {
        for (field, origin) in [
            (
                "active.resources.cpus",
                self.cpus.as_ref().and_then(recorded_origin),
            ),
            (
                "active.resources.memory_mib",
                self.memory_mib.as_ref().and_then(recorded_origin),
            ),
        ] {
            if origin.is_some_and(|origin| origin != SavedOrigin::Observed) {
                return invalid(
                    "SCFG_VALUE",
                    field,
                    "active allocation requires an observed value, not a requested target",
                );
            }
        }
        Ok(())
    }

    /// Reject impossible concrete allocations while keeping unavailable observations distinct.
    pub fn validate(&self) -> SnapshotManifestResult<()> {
        encoded_size(self, "active.resources")?;
        allocation(
            self.cpus
                .as_ref()
                .and_then(SavedValue::value)
                .copied()
                .map(u64::from),
            self.max_cpus
                .as_ref()
                .and_then(SavedValue::value)
                .copied()
                .map(u64::from),
            "active.resources.cpus",
            "active.resources.max_cpus",
        )?;
        allocation(
            self.memory_mib
                .as_ref()
                .and_then(SavedValue::value)
                .copied()
                .map(u64::from),
            self.max_memory_mib
                .as_ref()
                .and_then(SavedValue::value)
                .copied()
                .map(u64::from),
            "active.resources.memory_mib",
            "active.resources.max_memory_mib",
        )
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn allocation(
    current: Option<u64>,
    maximum: Option<u64>,
    current_field: &str,
    maximum_field: &str,
) -> SnapshotManifestResult<()> {
    if current == Some(0) {
        return invalid("SCFG_VALUE", current_field, "allocation must be positive");
    }
    if maximum == Some(0) {
        return invalid("SCFG_VALUE", maximum_field, "maximum must be positive");
    }
    // Missing/default/unknown maxima are not invented from the active value. The
    // destination resolver must select and validate defaults after applying overrides.
    if let (Some(current), Some(maximum)) = (current, maximum)
        && current > maximum
    {
        return invalid(
            "SCFG_VALUE",
            current_field,
            "allocation exceeds recorded maximum",
        );
    }
    Ok(())
}

fn recorded_origin<T>(saved: &SavedValue<T>) -> Option<SavedOrigin> {
    match saved {
        SavedValue::Value { origin, .. } => Some(*origin),
        SavedValue::Default {} | SavedValue::Unknown { .. } => None,
    }
}
