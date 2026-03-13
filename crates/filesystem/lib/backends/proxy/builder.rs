//! ProxyFs builder.

use std::{
    collections::HashMap,
    io,
    sync::{Mutex, RwLock},
};

use super::{AccessMode, ProxyFs};
use crate::DynFileSystem;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Builder for constructing a [`ProxyFs`].
#[allow(clippy::type_complexity)]
pub struct ProxyFsBuilder {
    inner: Box<dyn DynFileSystem>,
    on_access: Option<Box<dyn Fn(&str, AccessMode) -> Result<(), io::Error> + Send + Sync>>,
    on_read: Option<Box<dyn Fn(&str, &[u8]) -> Vec<u8> + Send + Sync>>,
    on_write: Option<Box<dyn Fn(&str, &[u8]) -> Vec<u8> + Send + Sync>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ProxyFsBuilder {
    pub(crate) fn new(inner: Box<dyn DynFileSystem>) -> Self {
        ProxyFsBuilder {
            inner,
            on_access: None,
            on_read: None,
            on_write: None,
        }
    }

    /// Set the access control hook.
    ///
    /// Called before `open`, `create`, and `opendir`. Receives the file path
    /// (relative to mount root) and the access mode. Return `Ok(())` to allow,
    /// `Err(e)` to deny with that error.
    pub fn on_access(
        mut self,
        hook: impl Fn(&str, AccessMode) -> Result<(), io::Error> + Send + Sync + 'static,
    ) -> Self {
        self.on_access = Some(Box::new(hook));
        self
    }

    /// Set the read interception hook.
    ///
    /// Called after data is read from the inner backend, before returning to
    /// the guest. Receives the path and raw data, returns (possibly transformed)
    /// data. When set, the zero-copy read path is broken — data flows through memory.
    pub fn on_read(
        mut self,
        hook: impl Fn(&str, &[u8]) -> Vec<u8> + Send + Sync + 'static,
    ) -> Self {
        self.on_read = Some(Box::new(hook));
        self
    }

    /// Set the write interception hook.
    ///
    /// Called after receiving data from the guest, before passing to the inner
    /// backend. Receives the path and raw data, returns (possibly transformed)
    /// data. When set, the zero-copy write path is broken — data flows through memory.
    pub fn on_write(
        mut self,
        hook: impl Fn(&str, &[u8]) -> Vec<u8> + Send + Sync + 'static,
    ) -> Self {
        self.on_write = Some(Box::new(hook));
        self
    }

    /// Build the `ProxyFs`.
    pub fn build(self) -> io::Result<ProxyFs> {
        // Only create staging file if read or write hooks need buffering.
        let staging_file = if self.on_read.is_some() || self.on_write.is_some() {
            Some(Mutex::new(create_staging_file()?))
        } else {
            None
        };

        // Pre-seed root inode path.
        let mut paths = HashMap::new();
        paths.insert(1u64, String::new());

        Ok(ProxyFs {
            inner: self.inner,
            on_access: self.on_access,
            on_read: self.on_read,
            on_write: self.on_write,
            paths: RwLock::new(paths),
            handle_paths: RwLock::new(HashMap::new()),
            staging_file,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Create a staging file for buffered hook interception.
fn create_staging_file() -> io::Result<std::fs::File> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::FromRawFd;

        let name = std::ffi::CString::new("proxyfs-staging").unwrap();
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // Pre-allocate a 128KB buffer for typical FUSE read/write chunks.
        let buf = vec![0u8; 128 * 1024];
        let written = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if written < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    #[cfg(target_os = "macos")]
    {
        tempfile::tempfile()
    }
}
