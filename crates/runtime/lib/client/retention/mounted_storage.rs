//! Private observations of filesystem backends admitted by the running VM.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Backend kind observed at construction, never inferred by reopening a host pathname.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountedFilesystemKind {
    /// A single-file backend.
    File,
    /// A directory backend.
    Directory,
}

/// Actual backend settings, with no host source path, volume name or credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountedFilesystem {
    /// Admitted backend kind.
    pub kind: MountedFilesystemKind,
    /// Effective quota; null means observed unlimited, not missing evidence.
    #[serde(deserialize_with = "required_quota")]
    pub quota_bytes: Option<u64>,
}

/// Per-guest-path observations. Missing entries are unknown, never proof of absence.
/// No Debug implementation: even guest paths should not leak through diagnostics.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MountedStorageEvidence(pub(crate) BTreeMap<String, MountedBacking>);

// Keep the released filesystem representation unchanged. The optional block representation
// is sent only when the reader advertised support before dispatch.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub(crate) enum MountedBacking {
    Filesystem(MountedFilesystem),
    Block {
        capacity_bytes: std::num::NonZeroU64,
    },
}

impl From<MountedFilesystem> for MountedBacking {
    fn from(value: MountedFilesystem) -> Self {
        Self::Filesystem(value)
    }
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MountedStorageEvidence {
    /// Read only explicitly observed backing; unavailable mappings remain unknown.
    pub fn get(&self, guest_path: &str) -> Option<MountedFilesystem> {
        match self.0.get(guest_path)? {
            MountedBacking::Filesystem(fs) => Some(*fs),
            MountedBacking::Block { .. } => None,
        }
    }

    /// Guest-visible virtual capacity. Sparse allocation and directory write quotas have
    /// different meanings and must never fill this field.
    pub fn block_capacity_bytes(&self, guest_path: &str) -> Option<u64> {
        match self.0.get(guest_path)? {
            MountedBacking::Block { capacity_bytes } => Some(capacity_bytes.get()),
            MountedBacking::Filesystem(_) => None,
        }
    }

    /// Used by the recipient to reject unsolicited evidence.
    pub fn has_block_capacity(&self) -> bool {
        self.0
            .values()
            .any(|value| matches!(value, MountedBacking::Block { .. }))
    }

    #[cfg(feature = "runner")]
    pub(crate) fn record_block(&mut self, path: &str, capacity: u64) {
        if self.0.len() < microsandbox_types::snapshot::saved_config::MAX_SAVED_CONFIG_ENTRIES
            && let Some(capacity_bytes) = std::num::NonZeroU64::new(capacity)
        {
            self.0
                .entry(path.to_owned())
                .or_insert(MountedBacking::Block { capacity_bytes });
        }
    }

    pub(crate) fn validate(&self) -> std::io::Result<()> {
        if self.0.len() > microsandbox_types::snapshot::saved_config::MAX_SAVED_CONFIG_ENTRIES
            || self
                .0
                .keys()
                .any(|path| path.len() > 4096 || !path.starts_with('/') || path.contains('\0'))
        {
            return Err(super::invalid("invalid mounted storage evidence"));
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

// Option normally accepts a missing JSON member as None. Here only an explicit
// null certifies unlimited backing; omission must never manufacture observation.
fn required_quota<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    Option::<u64>::deserialize(deserializer)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_quota_is_not_observed_unlimited() {
        assert!(serde_json::from_str::<MountedFilesystem>(r#"{"kind":"directory"}"#).is_err());
        for quota in [None, Some(0), Some(32 * 1024 * 1024)] {
            let observed = MountedFilesystem {
                kind: MountedFilesystemKind::Directory,
                quota_bytes: quota,
            };
            let encoded = serde_json::to_string(&observed).unwrap();
            assert_eq!(
                serde_json::from_str::<MountedFilesystem>(&encoded).unwrap(),
                observed
            );
        }
    }
}
