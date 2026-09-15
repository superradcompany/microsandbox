//! Runtime-owned composite checkpoint production.

#[cfg(feature = "runner")]
mod additional_disk;
#[cfg(feature = "runner")]
mod capture_pipeline;
mod compaction;
#[cfg(feature = "runner")]
mod coordinator;
mod disk;
mod external_mounts;
mod local;
#[cfg(feature = "runner")]
mod local_disk;
mod local_memory;
#[cfg(target_os = "linux")]
mod local_memory_budget;
mod memory_cache;
mod network;
mod object_pipeline;
mod owned_disk;
#[cfg(feature = "runner")]
mod restore;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use compaction::compact_stopped_disks;
#[cfg(feature = "runner")]
pub(crate) use coordinator::{CheckpointCoordinator, CheckpointResult, UserPause};
#[cfg(feature = "runner")]
pub(crate) use disk::recover_runtime_owned_root;
pub use disk::{
    DiskCompactionResult, RuntimeOwnedRootChain, RuntimeOwnedRootLayer, compact_stopped_root,
    grow_stopped_root, load_runtime_owned_root_chain, recover_stopped_root_growth,
};
pub use external_mounts::ExternalMountAuthorization;
pub use local::LocalBranchState;
pub use local_memory::{LocalMemory, LocalMemoryPin, LocalMemoryReservation};
pub use memory_cache::{CachedMemory, CachedMemoryRegion, MemoryCache};
pub use network::captured_gateway_mac;
pub use owned_disk::{
    capture_stopped_owned_disk, load_runtime_owned_disk_chain, seed_runtime_owned_disk_chain,
};
#[cfg(feature = "runner")]
pub(crate) use restore::{ExternalMountReport, PreparedCheckpointRestore, RestoredAgentState};

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
