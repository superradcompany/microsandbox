//! Read-only OCI root setup without writing to the host's container filesystem.

use std::fs;

use microsandbox_protocol::bootstrap::READ_ONLY_ROOTFS_TAG;
use nix::mount::{MsFlags, mount as mount_fs};

use crate::{AgentdError, AgentdResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const LOWER: &str = "/.msb/readonly-root/lower";
const BOOT: &str = "/.msb/readonly-root/boot";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Prepare an overlay for boot-time files and mountpoints, never host root writes.
pub(crate) fn mount() -> AgentdResult<()> {
    for path in [LOWER, BOOT] {
        fs::create_dir_all(path).map_err(|error| {
            AgentdError::Init(format!("create read-only root mountpoint {path}: {error}"))
        })?;
    }
    mount_fs(
        Some(READ_ONLY_ROOTFS_TAG),
        LOWER,
        Some("virtiofs"),
        MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .map_err(|error| AgentdError::Init(format!("mount read-only virtiofs root: {error}")))?;
    mount_fs(
        Some("tmpfs"),
        BOOT,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("size=64m,mode=700"),
    )
    .map_err(|error| AgentdError::Init(format!("mount read-only root boot storage: {error}")))?;
    for path in [format!("{BOOT}/upper"), format!("{BOOT}/work")] {
        fs::create_dir(&path).map_err(|error| {
            AgentdError::Init(format!("create boot overlay directory {path}: {error}"))
        })?;
    }
    let options = format!("lowerdir={LOWER},upperdir={BOOT}/upper,workdir={BOOT}/work");
    mount_fs(
        Some("overlay"),
        "/newroot",
        Some("overlay"),
        MsFlags::empty(),
        Some(options.as_str()),
    )
    .map_err(|error| AgentdError::Init(format!("mount read-only root boot overlay: {error}")))
}

/// Seal only the root mount after initialization; explicit volumes stay writable.
pub(crate) fn seal() -> AgentdResult<()> {
    mount_fs(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .map_err(|error| AgentdError::Init(format!("seal OCI root filesystem read-only: {error}")))
}
