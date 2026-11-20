//! Byte accounting for one local snapshot import, including its dependencies.

use std::path::Path;

use microsandbox_types::SnapshotManifest;

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Default)]
pub(super) struct ImportBudget {
    maximum_bytes: Option<u64>,
    remaining_bytes: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ImportBudget {
    pub(super) fn new(maximum_bytes: Option<u64>) -> MicrosandboxResult<Self> {
        if maximum_bytes == Some(0) {
            return Err(MicrosandboxError::InvalidConfig(
                "snapshot maximum disk size must be positive".into(),
            ));
        }

        Ok(Self {
            maximum_bytes,
            remaining_bytes: maximum_bytes.unwrap_or_default(),
        })
    }

    pub(super) fn unlimited() -> Self {
        Self::default()
    }

    pub(super) fn is_limited(&self) -> bool {
        self.maximum_bytes.is_some()
    }

    pub(super) fn charge_entry(
        &mut self,
        bytes: u64,
        metadata_limit: Option<u64>,
    ) -> MicrosandboxResult<()> {
        if self.maximum_bytes.is_some() && metadata_limit.is_some_and(|limit| bytes > limit) {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "snapshot import metadata exceeds its size limit".into(),
            ));
        }

        self.charge(bytes)
    }

    pub(super) fn charge(&mut self, bytes: u64) -> MicrosandboxResult<()> {
        if self.maximum_bytes.is_none() {
            return Ok(());
        }

        self.remaining_bytes = self.remaining_bytes.checked_sub(bytes).ok_or_else(|| {
            MicrosandboxError::InvalidConfig(
                "snapshot import exceeds its maximum disk size (expanded file bytes)".into(),
            )
        })?;
        Ok(())
    }

    pub(super) async fn charge_file(&mut self, path: &Path) -> MicrosandboxResult<()> {
        if !self.is_limited() {
            return Ok(());
        }

        self.charge(tokio::fs::metadata(path).await?.len())
    }

    pub(super) fn validate_manifest(&self, manifest: &SnapshotManifest) -> MicrosandboxResult<()> {
        if let Some(maximum) = self.maximum_bytes
            && let Some(file) = manifest.state.as_file()
            && file.virtual_size > maximum
        {
            return Err(MicrosandboxError::InvalidConfig(
                "snapshot import exceeds its maximum disk size".into(),
            ));
        }

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_budget_preserves_unbounded_imports() {
        let mut budget = ImportBudget::unlimited();
        budget.charge(u64::MAX).unwrap();
        budget.charge_entry(u64::MAX, Some(1)).unwrap();
    }
}
