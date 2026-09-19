//! Logical disk I/O shared by raw-file and explicitly resolved qcow2 offline growth.

use std::fs::File;
use std::io::{self, Read, Seek, Write};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Offline filesystem storage. Callers must exclude all other writers.
pub(crate) trait Ext4Storage: Read + Write + Seek {
    fn length(&self) -> io::Result<u64>;
    fn grow(&mut self, size: u64) -> io::Result<()>;
    fn sync_all(&self) -> io::Result<()>;
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Ext4Storage for File {
    fn length(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }

    fn grow(&mut self, size: u64) -> io::Result<()> {
        super::formatter::mark_sparse(self).map_err(io::Error::other)?;
        self.set_len(size)
    }

    fn sync_all(&self) -> io::Result<()> {
        File::sync_all(self)
    }
}

impl<T: Ext4Storage + ?Sized> Ext4Storage for &mut T {
    fn length(&self) -> io::Result<u64> {
        (**self).length()
    }
    fn grow(&mut self, size: u64) -> io::Result<()> {
        (**self).grow(size)
    }
    fn sync_all(&self) -> io::Result<()> {
        (**self).sync_all()
    }
}
