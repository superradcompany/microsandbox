// Copyright 2026 The Microsandbox Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A cloneable live limit for one or more buffered-writeback controllers.
///
/// The maximum is fixed when the handle is created. Callers may lower the active target while a
/// VM is running and later raise it back up to that maximum. Controllers observe changes before
/// admitting each new backing-file mutation.
#[derive(Clone, Debug)]
pub struct WritebackLimit {
    maximum_bytes: u64,
    target_bytes: Arc<AtomicU64>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl WritebackLimit {
    /// Creates a live limit whose initial target is also its immutable maximum.
    pub fn new(maximum_bytes: u64) -> Self {
        Self {
            maximum_bytes,
            target_bytes: Arc::new(AtomicU64::new(maximum_bytes)),
        }
    }

    /// Returns the immutable maximum configured for this handle.
    pub fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }

    /// Returns the currently requested pressure target.
    pub fn target_bytes(&self) -> u64 {
        self.target_bytes.load(Ordering::Acquire)
    }

    /// Changes the live pressure target without rebuilding or pausing the VM.
    ///
    /// A target must be non-zero and cannot exceed the immutable maximum. Linux controllers round
    /// a sub-page target up to one host page so every disk can continue to make forward progress.
    pub fn set_target_bytes(&self, target_bytes: u64) -> io::Result<()> {
        if target_bytes == 0 || target_bytes > self.maximum_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "writeback target must be between 1 and {} bytes",
                    self.maximum_bytes
                ),
            ));
        }
        self.target_bytes.store(target_bytes, Ordering::Release);
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::WritebackLimit;

    #[test]
    fn target_is_shared_but_cannot_escape_the_maximum() {
        let limit = WritebackLimit::new(1024);
        let observer = limit.clone();

        limit.set_target_bytes(512).unwrap();
        assert_eq!(observer.target_bytes(), 512);
        assert!(limit.set_target_bytes(0).is_err());
        assert!(limit.set_target_bytes(1025).is_err());
        assert_eq!(observer.target_bytes(), 512);
    }
}
