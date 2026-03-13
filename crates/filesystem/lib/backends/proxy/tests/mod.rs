//! Tests for the proxy filesystem backend.
//!
//! Tests cover ProxyFs-specific behavior: transparent delegation to inner
//! backend, access control hooks, read/write interception hooks, roundtrip
//! data integrity, path tracking, and concurrent access safety.

mod test_access_hook;
mod test_concurrency;
mod test_delegation;
mod test_path_tracking;
mod test_read_hook;
mod test_roundtrip;
mod test_write_hook;

use std::{
    ffi::CString,
    fs::File,
    io,
    os::fd::AsRawFd,
    sync::{Arc, Mutex},
};

use super::*;
use crate::{
    Context, DynFileSystem, Entry, Extensions, FsOptions, GetxattrReply, ListxattrReply,
    OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter, backends::memfs::MemFs,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Linux errno constants for assertion matching.
///
/// The ProxyFs always returns Linux errno values regardless of host OS
/// (macOS BSD errnos are translated via `platform::linux_error()`).
const LINUX_EPERM: i32 = 1;
const LINUX_ENOENT: i32 = 2;
const LINUX_EBADF: i32 = 9;
const LINUX_EACCES: i32 = 13;
const LINUX_EEXIST: i32 = 17;
const LINUX_EINVAL: i32 = 22;
const LINUX_ENODATA: i32 = 61;

/// Root inode number (FUSE convention).
const ROOT_INODE: u64 = 1;

/// Init binary inode number (ROOT_ID + 1).
const INIT_INODE: u64 = 2;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Test harness providing a fully initialized ProxyFs over MemFs.
///
/// Multiple constructors support different hook configurations: no hooks,
/// logging hooks, deny hooks, and transform hooks.
struct ProxyFsTestSandbox {
    fs: ProxyFs,
    access_log: Arc<Mutex<Vec<(String, AccessMode)>>>,
    read_log: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
    write_log: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
}

/// Mock [`ZeroCopyWriter`] that captures data read from a [`File`].
struct MockZeroCopyWriter {
    buf: Vec<u8>,
}

/// Mock [`ZeroCopyReader`] that provides data to be written into a [`File`].
struct MockZeroCopyReader {
    data: Vec<u8>,
    pos: usize,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ProxyFsTestSandbox {
    /// No hooks — pure delegation over MemFs.
    fn new() -> Self {
        let memfs = MemFs::builder().build().unwrap();
        let fs = ProxyFs::builder(Box::new(memfs)).build().unwrap();
        fs.init(FsOptions::empty()).unwrap();
        Self {
            fs,
            access_log: Arc::new(Mutex::new(Vec::new())),
            read_log: Arc::new(Mutex::new(Vec::new())),
            write_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// With logging access hook (records all access calls, allows all).
    fn with_access_log() -> Self {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log_clone = log.clone();
        let memfs = MemFs::builder().build().unwrap();
        let fs = ProxyFs::builder(Box::new(memfs))
            .on_access(move |path, mode| {
                log_clone.lock().unwrap().push((path.to_string(), mode));
                Ok(())
            })
            .build()
            .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        Self {
            fs,
            access_log: log,
            read_log: Arc::new(Mutex::new(Vec::new())),
            write_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// With deny-all access hook.
    fn with_deny_all() -> Self {
        let memfs = MemFs::builder().build().unwrap();
        let fs = ProxyFs::builder(Box::new(memfs))
            .on_access(|_path, _mode| Err(io::Error::from_raw_os_error(LINUX_EACCES)))
            .build()
            .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        Self {
            fs,
            access_log: Arc::new(Mutex::new(Vec::new())),
            read_log: Arc::new(Mutex::new(Vec::new())),
            write_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// With selective access hook (deny matching pattern).
    fn with_access_deny(pattern: &str) -> Self {
        let pat = pattern.to_string();
        let memfs = MemFs::builder().build().unwrap();
        let fs = ProxyFs::builder(Box::new(memfs))
            .on_access(move |path, _mode| {
                if path.starts_with(&pat) {
                    Err(io::Error::from_raw_os_error(LINUX_EACCES))
                } else {
                    Ok(())
                }
            })
            .build()
            .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        Self {
            fs,
            access_log: Arc::new(Mutex::new(Vec::new())),
            read_log: Arc::new(Mutex::new(Vec::new())),
            write_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// With identity read hook (records, returns unchanged).
    fn with_read_log() -> Self {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log_clone = log.clone();
        let memfs = MemFs::builder().build().unwrap();
        let fs = ProxyFs::builder(Box::new(memfs))
            .on_read(move |path, data| {
                log_clone
                    .lock()
                    .unwrap()
                    .push((path.to_string(), data.to_vec()));
                data.to_vec()
            })
            .build()
            .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        Self {
            fs,
            access_log: Arc::new(Mutex::new(Vec::new())),
            read_log: log,
            write_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// With transform read hook.
    fn with_read_transform(f: impl Fn(&str, &[u8]) -> Vec<u8> + Send + Sync + 'static) -> Self {
        let memfs = MemFs::builder().build().unwrap();
        let fs = ProxyFs::builder(Box::new(memfs))
            .on_read(f)
            .build()
            .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        Self {
            fs,
            access_log: Arc::new(Mutex::new(Vec::new())),
            read_log: Arc::new(Mutex::new(Vec::new())),
            write_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// With identity write hook (records, returns unchanged).
    fn with_write_log() -> Self {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log_clone = log.clone();
        let memfs = MemFs::builder().build().unwrap();
        let fs = ProxyFs::builder(Box::new(memfs))
            .on_write(move |path, data| {
                log_clone
                    .lock()
                    .unwrap()
                    .push((path.to_string(), data.to_vec()));
                data.to_vec()
            })
            .build()
            .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        Self {
            fs,
            access_log: Arc::new(Mutex::new(Vec::new())),
            read_log: Arc::new(Mutex::new(Vec::new())),
            write_log: log,
        }
    }

    /// With transform write hook.
    fn with_write_transform(f: impl Fn(&str, &[u8]) -> Vec<u8> + Send + Sync + 'static) -> Self {
        let memfs = MemFs::builder().build().unwrap();
        let fs = ProxyFs::builder(Box::new(memfs))
            .on_write(f)
            .build()
            .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        Self {
            fs,
            access_log: Arc::new(Mutex::new(Vec::new())),
            read_log: Arc::new(Mutex::new(Vec::new())),
            write_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// With both read and write transform hooks.
    fn with_read_write_transforms(
        on_read: impl Fn(&str, &[u8]) -> Vec<u8> + Send + Sync + 'static,
        on_write: impl Fn(&str, &[u8]) -> Vec<u8> + Send + Sync + 'static,
    ) -> Self {
        let memfs = MemFs::builder().build().unwrap();
        let fs = ProxyFs::builder(Box::new(memfs))
            .on_read(on_read)
            .on_write(on_write)
            .build()
            .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        Self {
            fs,
            access_log: Arc::new(Mutex::new(Vec::new())),
            read_log: Arc::new(Mutex::new(Vec::new())),
            write_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get a default Context (uid=1000, gid=1000).
    fn ctx() -> Context {
        Context {
            uid: 1000,
            gid: 1000,
            pid: 1,
        }
    }

    /// Make a CString from a &str (panics on embedded nul).
    fn cstr(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    /// Lookup a name in a parent directory.
    fn lookup(&self, parent: u64, name: &str) -> io::Result<Entry> {
        self.fs.lookup(Self::ctx(), parent, &Self::cstr(name))
    }

    /// Lookup a name in the root directory.
    fn lookup_root(&self, name: &str) -> io::Result<Entry> {
        self.lookup(ROOT_INODE, name)
    }

    /// Create a file via the FUSE create() operation. Returns (Entry, handle).
    fn fuse_create(&self, parent: u64, name: &str, mode: u32) -> io::Result<(Entry, Option<u64>)> {
        let (entry, handle, _opts) = self.fs.create(
            Self::ctx(),
            parent,
            &Self::cstr(name),
            mode,
            false,
            libc::O_RDWR as u32,
            0,
            Extensions::default(),
        )?;
        Ok((entry, handle))
    }

    /// Create a file in root via FUSE create() with mode 0o644.
    fn fuse_create_root(&self, name: &str) -> io::Result<(Entry, Option<u64>)> {
        self.fuse_create(ROOT_INODE, name, 0o644)
    }

    /// Create a directory via FUSE mkdir().
    fn fuse_mkdir(&self, parent: u64, name: &str, mode: u32) -> io::Result<Entry> {
        self.fs.mkdir(
            Self::ctx(),
            parent,
            &Self::cstr(name),
            mode,
            0,
            Extensions::default(),
        )
    }

    /// Create a directory in root via FUSE mkdir() with mode 0o755.
    fn fuse_mkdir_root(&self, name: &str) -> io::Result<Entry> {
        self.fuse_mkdir(ROOT_INODE, name, 0o755)
    }

    /// Open a file by inode. Returns (handle, OpenOptions).
    fn fuse_open(&self, ino: u64, flags: u32) -> io::Result<(Option<u64>, OpenOptions)> {
        self.fs.open(Self::ctx(), ino, false, flags)
    }

    /// Open a directory by inode. Returns (handle, OpenOptions).
    fn fuse_opendir(&self, ino: u64) -> io::Result<(Option<u64>, OpenOptions)> {
        self.fs.opendir(Self::ctx(), ino, 0)
    }

    /// Read data from a file handle via MockZeroCopyWriter.
    fn fuse_read(&self, ino: u64, handle: u64, size: u32, offset: u64) -> io::Result<Vec<u8>> {
        let mut writer = MockZeroCopyWriter::new();
        let n = self
            .fs
            .read(Self::ctx(), ino, handle, &mut writer, size, offset, None, 0)?;
        let mut data = writer.into_data();
        data.truncate(n);
        Ok(data)
    }

    /// Write data to a file handle via MockZeroCopyReader.
    fn fuse_write(&self, ino: u64, handle: u64, data: &[u8], offset: u64) -> io::Result<usize> {
        let mut reader = MockZeroCopyReader::new(data.to_vec());
        self.fs.write(
            Self::ctx(),
            ino,
            handle,
            &mut reader,
            data.len() as u32,
            offset,
            None,
            false,
            false,
            0,
        )
    }

    /// Collect all entry names from readdir on the given inode.
    fn readdir_names(&self, ino: u64) -> io::Result<Vec<String>> {
        let (handle, _) = self.fuse_opendir(ino)?;
        let handle = handle.unwrap();
        let entries = self.fs.readdir(Self::ctx(), ino, handle, 65536, 0)?;
        let names: Vec<String> = entries
            .iter()
            .map(|e| String::from_utf8_lossy(&e.name).to_string())
            .collect();
        self.fs.releasedir(Self::ctx(), ino, 0, handle)?;
        Ok(names)
    }

    /// Create a file and write content. Returns the inode.
    fn create_file_with_content(&self, parent: u64, name: &str, data: &[u8]) -> io::Result<u64> {
        let (entry, handle) = self.fuse_create(parent, name, 0o644)?;
        let handle = handle.unwrap();
        self.fuse_write(entry.inode, handle, data, 0)?;
        self.fs
            .release(Self::ctx(), entry.inode, 0, handle, false, false, None)?;
        Ok(entry.inode)
    }

    /// Assert that an io::Result is an error with the expected Linux errno.
    fn assert_errno<T>(result: io::Result<T>, expected_errno: i32) {
        match result {
            Ok(_) => panic!("expected errno {expected_errno}, got Ok"),
            Err(err) => assert_eq!(
                err.raw_os_error(),
                Some(expected_errno),
                "expected errno {expected_errno}, got {:?}",
                err
            ),
        }
    }
}

impl MockZeroCopyWriter {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn into_data(self) -> Vec<u8> {
        self.buf
    }
}

impl MockZeroCopyReader {
    fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0 }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl ZeroCopyWriter for MockZeroCopyWriter {
    fn write_from(&mut self, f: &File, count: usize, off: u64) -> io::Result<usize> {
        let mut tmp = vec![0u8; count];
        let n = unsafe {
            libc::pread(
                f.as_raw_fd(),
                tmp.as_mut_ptr() as *mut libc::c_void,
                count,
                off as i64,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(n)
    }
}

impl ZeroCopyReader for MockZeroCopyReader {
    fn read_to(&mut self, f: &File, count: usize, off: u64) -> io::Result<usize> {
        let remaining = &self.data[self.pos..];
        let to_write = std::cmp::min(count, remaining.len());
        if to_write == 0 {
            return Ok(0);
        }
        let n = unsafe {
            libc::pwrite(
                f.as_raw_fd(),
                remaining.as_ptr() as *const libc::c_void,
                to_write,
                off as i64,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        self.pos += n;
        Ok(n)
    }
}
