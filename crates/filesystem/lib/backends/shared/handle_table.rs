//! Handle table for open file descriptors.

use std::{fs::File, sync::RwLock};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Data associated with an open file handle.
pub(crate) struct HandleData {
    /// The real host file descriptor.
    ///
    /// Wrapped in `RwLock` because `preadv64`/`pwritev64` only need a shared
    /// lock (they take an explicit offset), while `lseek`, `fsync`, and
    /// `ftruncate` need exclusive access.
    pub file: RwLock<File>,
}
