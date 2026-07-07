//! Offline growth of a sandbox's writable overlay upper image.
//!
//! The persisted `upper_size_mib` is only the desired size; the real state is the `upper.ext4` file attached as the overlay upper device. Callers rely on the success ordering
//! this module enables: the new desired size is persisted (or booted against) only after the file itself has grown.

use std::path::{Path, PathBuf};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const BYTES_PER_MIB: u64 = 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Failure modes for an offline `upper.ext4` grow.
pub(crate) enum UpperGrowError {
    /// The image cannot grow to the requested size in place; recreating the
    /// sandbox is required to go larger.
    OverCapacity {
        /// Largest size in bytes the existing image can grow to in place.
        max_size_bytes: u64,
    },

    /// Any other resize failure.
    Other(String),
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Grow the `upper.ext4` at `path` to `target_mib`, off the async runtime.
///
/// A file that is already at or beyond the target is left untouched (shrink is never attempted here), so the call is idempotent across repeated starts.
pub(crate) async fn grow_upper_to_mib(path: PathBuf, target_mib: u32) -> MicrosandboxResult<()> {
    let metadata = tokio::fs::metadata(&path).await.map_err(|e| {
        MicrosandboxError::Custom(format!("cannot grow upper.ext4 at {}: {e}", path.display()))
    })?;
    let target_bytes = u64::from(target_mib) * BYTES_PER_MIB;
    if metadata.len() >= target_bytes {
        return Ok(());
    }

    tokio::task::spawn_blocking(move || grow_upper_ext4(&path, target_bytes))
        .await
        .map_err(|e| MicrosandboxError::Runtime(format!("upper grow task failed: {e}")))?
        .map_err(|err| match err {
            UpperGrowError::OverCapacity { max_size_bytes } => {
                MicrosandboxError::Custom(format!(
                    "cannot grow oci upper size to {target_mib} MiB: the existing upper.ext4 can grow to at most {} MiB; recreate the sandbox for a larger upper",
                    max_size_bytes / BYTES_PER_MIB
                ))
            }
            UpperGrowError::Other(message) => {
                MicrosandboxError::Custom(format!("failed to grow upper.ext4: {message}"))
            }
        })
}

/// Grow the ext4 image at `path` to `new_size_bytes` in place.
fn grow_upper_ext4(path: &Path, new_size_bytes: u64) -> Result<(), UpperGrowError> {
    microsandbox_image::ext4::grow_image(path, new_size_bytes)
        .map(|_outcome| ())
        .map_err(map_ext4_error)
}

/// Map the resizer's error surface into this module's vocabulary. Only the
/// GDT-capacity error is actionable for callers (it carries the max growable
/// size and means recreate-to-go-larger); everything else is opaque.
fn map_ext4_error(err: microsandbox_image::ext4::Ext4Error) -> UpperGrowError {
    match err {
        microsandbox_image::ext4::Ext4Error::ExceedsGdtCapacity { max_size_bytes, .. } => {
            UpperGrowError::OverCapacity { max_size_bytes }
        }
        other => UpperGrowError::Other(other.to_string()),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn grow_skips_files_already_at_or_beyond_target() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("upper.ext4");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(2 * BYTES_PER_MIB).unwrap();

        grow_upper_to_mib(path.clone(), 2).await.unwrap();
        grow_upper_to_mib(path, 1).await.unwrap();
    }

    #[tokio::test]
    async fn grow_errors_when_upper_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.ext4");

        let err = grow_upper_to_mib(path, 8).await.unwrap_err();
        assert!(err.to_string().contains("cannot grow upper.ext4"));
    }
}
