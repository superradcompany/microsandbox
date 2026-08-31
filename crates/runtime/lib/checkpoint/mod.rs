//! Runtime-owned composite checkpoint production.

mod coordinator;
mod disk;
mod restore;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub(crate) use coordinator::{CheckpointCoordinator, CheckpointResult};
pub(crate) use disk::recover_managed_upper;
pub(crate) use restore::PreparedCheckpointRestore;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Atomically replace one runtime-owned file after its temporary contents have been synced.
pub(crate) fn replace_file(
    temporary: &std::path::Path,
    target: &std::path::Path,
) -> std::io::Result<()> {
    #[cfg(not(windows))]
    {
        std::fs::rename(temporary, target)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;

        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };

        let temporary = temporary
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let target = target
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let moved = unsafe {
            MoveFileExW(
                temporary.as_ptr(),
                target.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if moved == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
