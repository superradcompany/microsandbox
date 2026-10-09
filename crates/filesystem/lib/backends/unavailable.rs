//! A retained virtiofs transport whose external backing is unavailable.

use std::{io, sync::Mutex};

use crate::{DynFileSystem, PassthroughFs, SingleFileFs};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Error-serving backend used only by explicit relaxed external-mount restore.
#[derive(Default)]
pub struct UnavailableFs {
    limits: msb_krun::DeviceStateLimits,
    state: Mutex<Option<Vec<u8>>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl UnavailableFs {
    /// Configure the state budget for a retained, unavailable mount.
    pub fn with_state_limit(mut self, bytes: usize) -> Self {
        self.limits = self.limits.with_fs_state_limit(bytes);
        self
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl DynFileSystem for UnavailableFs {
    fn validate_state(&self, state: &[u8]) -> io::Result<()> {
        if state.starts_with(b"MSBSFILE") {
            SingleFileFs::validate_external_state_with_limit(state, self.limits.fs_state_limit())
        } else {
            PassthroughFs::validate_external_state_with_limit(state, self.limits.fs_state_limit())
        }
    }

    fn restore_state(&self, state: &[u8]) -> io::Result<()> {
        self.validate_state(state)?;
        *self.state.lock().unwrap() = Some(state.to_vec());
        Ok(())
    }

    fn capture_state(&self) -> io::Result<Vec<u8>> {
        Err(io::Error::other(
            "unavailable external mount cannot establish a new writeback boundary",
        ))
    }

    fn request_error(&self, _inode: u64) -> Option<i32> {
        // FUSE protocol errno values are Linux values on every host.
        Some(5)
    }

    fn notify_reply(&self) -> io::Result<()> {
        // Notifications have no response, including on an error-serving transport.
        Ok(())
    }
}
