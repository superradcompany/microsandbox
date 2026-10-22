//! Portable new-command defaults and fresh lifetime policy, excluding invocation and ownership.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Rlimit, RlimitResource, SandboxPolicy, SecurityProfile, SnapshotManifestResult};

use super::SavedValue;
use super::validation::{MAX_NAME_BYTES, MAX_TEXT_BYTES, count, decode, encoded_size, invalid};
use super::value::deserialize_present;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Sandbox defaults; saved security policy is data, never destination consent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedExecutionConfig {
    /// User labels only; system/artifact labels are regenerated separately.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub labels: Option<SavedValue<BTreeMap<String, String>>>,
    /// Guest security profile, subject to mandatory destination constraints.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub security_profile: Option<SavedValue<SecurityProfile>>,
    /// Sandbox-wide defaults for newly launched processes, not ancestor invocation limits.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub rlimits: Option<SavedValue<Vec<SavedRlimit>>>,
    /// Duration policy only; elapsed counters and ephemeral ownership are never inherited.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub lifecycle: Option<SavedValue<SavedLifetimePolicy>>,
}

/// Exact unsigned 64-bit quantity encoded as canonical decimal text.
///
/// Resource limits use the entire u64 range, including the existing unlimited
/// sentinel. JSON numbers above 2^53-1 cannot survive descriptor canonicalization
/// reliably. A private field prevents unvalidated decimal spellings in typed callers.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SavedU64(u64);

/// Strict counterpart of the existing resource-limit type, with lossless quantities.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedRlimit {
    /// Existing resource vocabulary; this schema introduces no new guest resources.
    pub resource: RlimitResource,
    /// Soft limit, including zero and the existing unlimited sentinel.
    pub soft: SavedU64,
    /// Ceiling, which must be at least the soft value.
    pub hard: SavedU64,
}

/// A fresh destination timer policy, with no captured elapsed time or removal consent.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedLifetimePolicy {
    /// Absence means unlimited lifetime; a concrete zero remains zero.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub max_duration_secs: Option<SavedU64>,
    /// Absence disables idle detection; a concrete zero remains zero.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub idle_timeout_secs: Option<SavedU64>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SavedU64 {
    /// Retain the full existing SDK range without floating-point conversion.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Recover the exact value for a validated destination configuration.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl SavedLifetimePolicy {
    /// Explicit projection: ephemeral ownership is an operation choice, never a default.
    pub fn from_source(source: &SandboxPolicy) -> Self {
        let SandboxPolicy {
            ephemeral: _,
            max_duration_secs,
            idle_timeout_secs,
        } = source;
        Self {
            max_duration_secs: max_duration_secs.map(SavedU64::new),
            idle_timeout_secs: idle_timeout_secs.map(SavedU64::new),
        }
    }
}

impl SavedExecutionConfig {
    /// Decode the same strict record used for typed capture validation.
    pub fn from_bytes(bytes: &[u8]) -> SnapshotManifestResult<Self> {
        let config: Self = decode(bytes, "active.execution")?;
        config.validate()?;
        Ok(config)
    }

    /// Validate identities and ranges without applying saved permissions or timers.
    pub fn validate(&self) -> SnapshotManifestResult<()> {
        encoded_size(self, "active.execution")?;
        if let Some(labels) = self.labels.as_ref().and_then(SavedValue::value) {
            count(labels.len(), "active.execution.labels")?;
            for (key, value) in labels {
                if key.is_empty()
                    || key.len() > MAX_NAME_BYTES
                    || key.contains('\0')
                    || value.len() > MAX_TEXT_BYTES
                    || value.contains('\0')
                {
                    return invalid(
                        "SCFG_VALUE",
                        "active.execution.labels",
                        "invalid label key or value",
                    );
                }
            }
        }
        if let Some(limits) = self.rlimits.as_ref().and_then(SavedValue::value) {
            count(limits.len(), "active.execution.rlimits")?;
            // There are only sixteen resource kinds. Avoid converting them to a
            // string (which could accidentally establish a competing name grammar).
            for (index, limit) in limits.iter().enumerate() {
                if limits[..index]
                    .iter()
                    .any(|other| other.resource == limit.resource)
                {
                    return invalid(
                        "SCFG_IDENTITY",
                        "active.execution.rlimits",
                        "duplicate resource limit",
                    );
                }
                if limit.soft > limit.hard {
                    return invalid(
                        "SCFG_VALUE",
                        "active.execution.rlimits",
                        "soft limit exceeds hard limit",
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

impl From<&Rlimit> for SavedRlimit {
    fn from(value: &Rlimit) -> Self {
        let Rlimit {
            resource,
            soft,
            hard,
        } = value;
        Self {
            resource: *resource,
            soft: SavedU64::new(*soft),
            hard: SavedU64::new(*hard),
        }
    }
}

impl From<SavedRlimit> for Rlimit {
    fn from(value: SavedRlimit) -> Self {
        Self {
            resource: value.resource,
            soft: value.soft.get(),
            hard: value.hard.get(),
        }
    }
}

impl Serialize for SavedU64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for SavedU64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // String's standard type error can include an unexpected scalar, so callers
        // must retain the outer decoder's redacted error boundary for untrusted JSON.
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || value.len() > 20
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(serde::de::Error::custom(
                "expected canonical unsigned decimal string",
            ));
        }
        value
            .parse::<u64>()
            .map(Self)
            .map_err(|_| serde::de::Error::custom("unsigned quantity out of range"))
    }
}

impl fmt::Debug for SavedU64 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SavedU64(..)")
    }
}
