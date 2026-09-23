//! A retained virtiofs transport whose external backing is unavailable.

use std::{io, sync::Mutex};

use crate::{DynFileSystem, PassthroughFs, SingleFileFs};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Error-serving backend used only by explicit relaxed external-mount restore.
#[derive(Default)]
pub struct UnavailableFs {
    state: Mutex<Option<Vec<u8>>>,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl DynFileSystem for UnavailableFs {
    fn validate_state(&self, state: &[u8]) -> io::Result<()> {
        if state.starts_with(b"MSBSFILE") {
            SingleFileFs::validate_external_state(state)
        } else {
            PassthroughFs::validate_external_state(state)
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
