//! Explicit archive expansion limits and caller-owned import policy.

use std::path::Path;

use microsandbox_types::SnapshotManifest;
use tokio_tar::Header;

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Limits enforced before writing each archive member.
///
/// These bound extracted logical bytes, including sparse holes, rather than
/// compressed upload size or total temporary workspace usage. The caller must
/// reserve space for any additional copies made during import and publication.
#[derive(Clone, Copy, Debug)]
pub struct ImportLimits {
    /// Maximum sum of the logical sizes of all archive members.
    pub expanded_bytes: u64,
    /// Maximum size of an individual descriptor, labels file, or inventory.
    pub metadata_bytes: u64,
    /// Maximum number of archive members, including directories.
    pub entries: usize,
    /// Maximum length of an archive path in bytes.
    pub path_bytes: usize,
}

/// Caller-owned restrictions checked before extraction and publication.
///
/// Cloud callers can restrict supported formats independently of byte limits.
/// Checks must be read-only; descriptors have not been published or authorized
/// for host filesystem access when they reach this policy.
pub trait ImportPolicy: Send + Sync {
    /// Check a member path and logical size before any of its data is written.
    fn validate_entry(&self, path: &Path, logical_bytes: u64) -> MicrosandboxResult<()>;

    /// Check the number of snapshots and whether the archive includes all dependencies.
    fn validate_archive(&self, snapshots: usize, complete: bool) -> MicrosandboxResult<()>;

    /// Check a descriptor before resolving dependencies or placing payloads.
    fn validate_manifest(&self, manifest: &SnapshotManifest) -> MicrosandboxResult<()>;
}

pub(crate) struct ImportBudget<'a> {
    limits: ImportLimits,
    remaining: u64,
    entries: usize,
    policy: &'a dyn ImportPolicy,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ImportLimits {
    /// Reject empty limits before opening or creating import files.
    pub fn validate(&self) -> MicrosandboxResult<()> {
        if self.expanded_bytes == 0
            || self.metadata_bytes == 0
            || self.entries == 0
            || self.path_bytes == 0
        {
            return Err(invalid("snapshot import limits must be positive"));
        }

        Ok(())
    }
}

impl<'a> ImportBudget<'a> {
    pub(crate) fn new(
        limits: ImportLimits,
        policy: &'a dyn ImportPolicy,
    ) -> MicrosandboxResult<Self> {
        limits.validate()?;

        Ok(Self {
            limits,
            remaining: limits.expanded_bytes,
            entries: 0,
            policy,
        })
    }

    pub(crate) fn charge(&mut self, path: &Path, header: &Header) -> MicrosandboxResult<()> {
        if self.entries == self.limits.entries {
            return Err(invalid("snapshot import exceeds its archive entry limit"));
        }
        self.entries += 1;

        if path.as_os_str().len() > self.limits.path_bytes {
            return Err(invalid("snapshot import exceeds its archive path limit"));
        }

        // GNU sparse members can encode a tiny payload with a huge logical size.
        let logical_bytes = header.size()?;
        self.policy.validate_entry(path, logical_bytes)?;

        let metadata = path.file_name().is_some_and(|name| {
            matches!(
                name.to_str(),
                Some("archive.json" | "snapshot.json" | "manifest.json" | "metadata.json")
            )
        });
        if metadata && logical_bytes > self.limits.metadata_bytes {
            return Err(invalid("snapshot import exceeds its metadata size limit"));
        }

        self.remaining = self
            .remaining
            .checked_sub(logical_bytes)
            .ok_or_else(|| invalid("snapshot import exceeds its expanded byte limit"))?;

        Ok(())
    }

    pub(crate) fn validate_archive(
        &self,
        snapshots: usize,
        complete: bool,
    ) -> MicrosandboxResult<()> {
        self.policy.validate_archive(snapshots, complete)
    }

    pub(crate) fn validate_manifest(&self, manifest: &SnapshotManifest) -> MicrosandboxResult<()> {
        self.policy.validate_manifest(manifest)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn invalid(message: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(message.into())
}
