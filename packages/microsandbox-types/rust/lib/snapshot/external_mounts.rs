//! Guest paths of external mounts that a disk snapshot does not carry.

use serde::{Deserialize, Serialize};

use super::Manifest;
use crate::error::{SnapshotManifestError, SnapshotManifestResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Optional (not must-understand) key listing guest paths whose host-side backing is not captured.
pub const EXTERNAL_MOUNTS_EXTENSION: &str = "microsandbox.external-mounts";

/// Must-understand key carrying the captured bind-mount hide-path policy.
///
/// Kept separate from [`EXTERNAL_MOUNTS_EXTENSION`] so an older reader refuses a
/// hide_path-bearing snapshot rather than silently restoring a destination that drops
/// the policy, while a hide_path-free snapshot stays byte-identical and advisory.
pub const BIND_MOUNT_DENY_EXTENSION: &str = "microsandbox.bind-mount-hide_path";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExternalMountsExtension {
    guest_paths: Vec<String>,
}

/// Captured bind-mount hide-path policy carried under its own must-understand key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BindMountHidePathExtension {
    policies: Vec<ExternalMountPolicy>,
}

/// A captured bind-mount host-side hide-path policy, keyed by guest path.
///
/// Only bind mounts carry a hide-path list today; the policy is recorded under a
/// must-understand extension so an older reader refuses a hide_path-bearing snapshot
/// instead of silently restoring a destination that drops the policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalMountPolicy {
    /// Guest mount path the policy applies to.
    pub guest_path: String,
    /// Captured gitignore-style hide-path patterns.
    pub hide_path: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Manifest {
    /// Record the guest paths of source mounts this snapshot does not carry. Never host paths.
    ///
    /// The extension is advisory for older readers, so it is never added to `requires`.
    pub fn set_external_mounts(
        &mut self,
        mut guest_paths: Vec<String>,
    ) -> SnapshotManifestResult<()> {
        guest_paths.sort();
        guest_paths.dedup();

        if guest_paths.is_empty() {
            self.extensions.remove(EXTERNAL_MOUNTS_EXTENSION);
            return Ok(());
        }

        let value = serde_json::to_value(ExternalMountsExtension { guest_paths })
            .map_err(|error| SnapshotManifestError::ManifestParse(error.to_string()))?;
        self.extensions
            .insert(EXTERNAL_MOUNTS_EXTENSION.into(), value);

        Ok(())
    }

    /// Record the captured hide-path policy for each host-backed bind mount.
    ///
    /// Written under the must-understand [`BIND_MOUNT_DENY_EXTENSION`] and added
    /// to `requires`, so an older reader refuses a hide_path-bearing snapshot rather
    /// than restoring a destination that drops the policy. A mount with an empty
    /// hide-path list contributes no entry and a hide_path-less snapshot keeps its released
    /// bytes.
    pub fn set_external_mount_policies(
        &mut self,
        mut policies: Vec<ExternalMountPolicy>,
    ) -> SnapshotManifestResult<()> {
        policies.retain(|policy| !policy.hide_path.is_empty());
        policies.sort_by(|left, right| left.guest_path.cmp(&right.guest_path));

        self.requires.retain(|key| key != BIND_MOUNT_DENY_EXTENSION);

        if policies.is_empty() {
            self.extensions.remove(BIND_MOUNT_DENY_EXTENSION);
            return Ok(());
        }

        let value = serde_json::to_value(BindMountHidePathExtension { policies })
            .map_err(|error| SnapshotManifestError::ManifestParse(error.to_string()))?;
        self.extensions
            .insert(BIND_MOUNT_DENY_EXTENSION.into(), value);
        self.requires.push(BIND_MOUNT_DENY_EXTENSION.into());
        self.requires.sort();
        self.requires.dedup();

        Ok(())
    }

    /// Read the recorded hide-path policy; snapshots without the policy record `None`.
    ///
    /// `None` means the snapshot predates hide_path-policy capture (or carried no
    /// hide-path list); callers must treat it as unknown, never as an empty list.
    pub fn external_mount_policies(
        &self,
    ) -> SnapshotManifestResult<Option<Vec<ExternalMountPolicy>>> {
        let Some(value) = self.extensions.get(BIND_MOUNT_DENY_EXTENSION) else {
            return Ok(None);
        };

        let extension: BindMountHidePathExtension =
            serde_json::from_value(value.clone()).map_err(|error| {
                SnapshotManifestError::ManifestParse(format!(
                    "invalid bind mount hide_path: {error}"
                ))
            })?;

        Ok(Some(extension.policies))
    }

    /// Read the recorded guest paths; snapshots without the extension record none.
    pub fn external_mounts(&self) -> SnapshotManifestResult<Vec<String>> {
        let Some(value) = self.extensions.get(EXTERNAL_MOUNTS_EXTENSION) else {
            return Ok(Vec::new());
        };

        let extension: ExternalMountsExtension =
            serde_json::from_value(value.clone()).map_err(|error| {
                SnapshotManifestError::ManifestParse(format!("invalid external mounts: {error}"))
            })?;

        Ok(extension.guest_paths)
    }
}
