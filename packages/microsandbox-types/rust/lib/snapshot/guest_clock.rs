//! Guest wall-clock policy retained by a snapshot.

use serde::{Deserialize, Serialize};

use super::Manifest;
use crate::GuestClockPolicy;
use crate::error::{SnapshotManifestError, SnapshotManifestResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Must-understand key for a non-default guest clock policy retained by a snapshot.
pub const GUEST_CLOCK_EXTENSION: &str = "microsandbox.guest-clock";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestClockExtension {
    policy: GuestClockPolicy,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Manifest {
    /// Record the source sandbox's guest clock policy.
    pub fn set_guest_clock(&mut self, policy: GuestClockPolicy) -> SnapshotManifestResult<()> {
        // Absence keeps the released meaning (host sync) and downgrade eligibility.
        if policy.is_sync() {
            self.extensions.remove(GUEST_CLOCK_EXTENSION);
            self.requires.retain(|key| key != GUEST_CLOCK_EXTENSION);
            return Ok(());
        }

        self.extensions.insert(
            GUEST_CLOCK_EXTENSION.into(),
            serde_json::to_value(GuestClockExtension { policy })
                .map_err(|error| SnapshotManifestError::ManifestParse(error.to_string()))?,
        );

        // An older reader must refuse rather than silently step a restored guest to host time.
        self.requires.push(GUEST_CLOCK_EXTENSION.into());
        self.requires.sort();
        self.requires.dedup();

        Ok(())
    }

    /// Read the recorded guest clock policy; snapshots without the extension use host sync.
    pub fn guest_clock(&self) -> SnapshotManifestResult<GuestClockPolicy> {
        let Some(value) = self.extensions.get(GUEST_CLOCK_EXTENSION) else {
            return Ok(GuestClockPolicy::Sync);
        };

        let extension: GuestClockExtension =
            serde_json::from_value(value.clone()).map_err(|error| {
                SnapshotManifestError::ManifestParse(format!("invalid guest clock policy: {error}"))
            })?;

        Ok(extension.policy)
    }
}
