mod test_bootstrap;
mod test_concurrency;
mod test_config;
mod test_corrupt_xattr;
mod test_create_ops;
mod test_dir_ops;
mod test_file_ops;
mod test_flag_translation;
mod test_init_binary;
mod test_kill_priv;
mod test_lookup_inode;
mod test_metadata;
mod test_name_validation;
mod test_open_after_unlink;
mod test_remove_ops;
mod test_special_ops;
mod test_vol_lookup;
mod test_xattr_ops;

use std::{ffi::CString, fs::File, io, os::fd::AsRawFd, path::PathBuf};

use tempfile::TempDir;

use super::*;
use crate::{
    Context, DynFileSystem, Entry, Extensions, FsOptions, GetxattrReply, ListxattrReply,
    OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Linux errno constants for assertion matching.
///
/// The PassthroughFs always returns Linux errno values regardless of host OS
/// (macOS BSD errnos are translated via `platform::linux_error()`).
const LINUX_EPERM: i32 = 1;
const LINUX_ENOENT: i32 = 2;
#[allow(dead_code)]
const LINUX_EIO: i32 = 5;
const LINUX_EBADF: i32 = 9;
const LINUX_EACCES: i32 = 13;
const LINUX_EEXIST: i32 = 17;
const LINUX_EINVAL: i32 = 22;
const LINUX_ELOOP: i32 = 40;
const LINUX_ENOSYS: i32 = 38;
const LINUX_ENOTEMPTY: i32 = 39;
const LINUX_ENODATA: i32 = 61;
#[cfg(target_os = "macos")]
const LINUX_EOVERFLOW: i32 = 75;
#[cfg(target_os = "macos")]
const LINUX_EOPNOTSUPP: i32 = 95;

/// Linux open flags (FUSE always passes Linux values, even on macOS).
const LINUX_O_RDWR: u32 = 2;
const LINUX_O_TRUNC: u32 = 0x200;

/// Root inode number (FUSE convention).
const ROOT_INODE: u64 = 1;

/// Init binary inode number (ROOT_ID + 1).
const INIT_INODE: u64 = 2;

/// Init binary handle number (reserved handle 0).
const INIT_HANDLE: u64 = 0;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Test harness providing a fully initialized PassthroughFs over a temp directory.
///
/// Field order matters: `fs` is dropped before `_tmp` (Rust drops fields in
/// declaration order), ensuring the filesystem is torn down before the
/// temporary directory is removed.
struct TestSandbox {
    fs: PassthroughFs,
    _tmp: TempDir,
    root: PathBuf,
}

/// Mock [`ZeroCopyWriter`] that captures data read from a [`File`].
///
/// Used in tests to read file data via the FUSE `read` operation.
/// Implements `write_from` using `libc::pread` to match real FUSE transport
/// semantics (offset-based, no fd seek position mutation).
struct MockZeroCopyWriter {
    buf: Vec<u8>,
}

/// Mock [`ZeroCopyReader`] that provides data to be written into a [`File`].
///
/// Used in tests to write data via the FUSE `write` operation.
/// Implements `read_to` using `libc::pwrite` to match real FUSE transport
/// semantics.
struct MockZeroCopyReader {
    data: Vec<u8>,
    pos: usize,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TestSandbox {
    /// Create a new sandbox with default config (xattr=true, strict=true).
    fn new() -> Self {
        Self::with_config(|cfg| cfg)
    }

    /// Create a new sandbox with a custom config modifier.
    fn with_config(f: impl FnOnce(PassthroughConfig) -> PassthroughConfig) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = f(PassthroughConfig {
            root_dir: tmp.path().to_path_buf(),
            ..Default::default()
        });
        let fs = PassthroughFs::new(cfg).unwrap();
        fs.init(FsOptions::empty()).unwrap();
        let root = tmp.path().to_path_buf();
        Self {
            fs,
            _tmp: tmp,
            root,
        }
    }

    /// Get a default Context (uid=0, gid=0 — root user).
    fn ctx(&self) -> Context {
        Context {
            uid: 0,
            gid: 0,
            pid: 1,
        }
    }

    /// Get a Context with specific uid/gid.
    fn ctx_as(&self, uid: u32, gid: u32) -> Context {
        Context { uid, gid, pid: 1 }
    }

    /// Create a file on the host filesystem (bypassing FUSE).
    fn host_create_file(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.root.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, contents).unwrap();
        path
    }

    /// Create a directory on the host filesystem (bypassing FUSE).
    fn host_create_dir(&self, name: &str) -> PathBuf {
        let path = self.root.join(name);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    /// Make a CString from a &str (panics on embedded nul).
    fn cstr(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    /// Lookup a name in a parent directory.
    fn lookup(&self, parent: u64, name: &str) -> io::Result<Entry> {
        self.fs.lookup(self.ctx(), parent, &Self::cstr(name))
    }

    /// Lookup a name in the root directory.
    fn lookup_root(&self, name: &str) -> io::Result<Entry> {
        self.lookup(ROOT_INODE, name)
    }

    /// Create a file via the FUSE create() operation. Returns (Entry, handle).
    fn fuse_create(&self, parent: u64, name: &str, mode: u32) -> io::Result<(Entry, u64)> {
        self.fuse_create_flags(parent, name, mode, false, libc::O_RDWR as u32)
    }

    /// Create a file via the FUSE create() operation with explicit kill_priv and flags.
    fn fuse_create_flags(
        &self,
        parent: u64,
        name: &str,
        mode: u32,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Entry, u64)> {
        let (entry, handle, _opts) = self.fs.create(
            self.ctx(),
            parent,
            &Self::cstr(name),
            mode,
            kill_priv,
            flags,
            0,
            Extensions::default(),
        )?;
        Ok((entry, handle.unwrap()))
    }

    /// Create a file in root via FUSE create() with mode 0o644.
    fn fuse_create_root(&self, name: &str) -> io::Result<(Entry, u64)> {
        self.fuse_create(ROOT_INODE, name, 0o644)
    }

    /// Create a directory via FUSE mkdir().
    fn fuse_mkdir(&self, parent: u64, name: &str, mode: u32) -> io::Result<Entry> {
        self.fs.mkdir(
            self.ctx(),
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

    /// Open a file by inode. Returns handle.
    fn fuse_open(&self, inode: u64, flags: u32) -> io::Result<u64> {
        self.fuse_open_kill_priv(inode, false, flags)
    }

    /// Open a file by inode with explicit kill_priv. Returns handle.
    fn fuse_open_kill_priv(&self, inode: u64, kill_priv: bool, flags: u32) -> io::Result<u64> {
        let (handle, _opts) = self.fs.open(self.ctx(), inode, kill_priv, flags)?;
        Ok(handle.unwrap())
    }

    /// Open a directory by inode. Returns handle.
    fn fuse_opendir(&self, inode: u64) -> io::Result<u64> {
        let (handle, _opts) = self.fs.opendir(self.ctx(), inode, 0)?;
        Ok(handle.unwrap())
    }

    /// Write data to a file handle via MockZeroCopyReader.
    fn fuse_write(&self, inode: u64, handle: u64, data: &[u8], offset: u64) -> io::Result<usize> {
        self.fuse_write_kill_priv(inode, handle, data, offset, false)
    }

    /// Write data to a file handle with explicit kill_priv.
    fn fuse_write_kill_priv(
        &self,
        inode: u64,
        handle: u64,
        data: &[u8],
        offset: u64,
        kill_priv: bool,
    ) -> io::Result<usize> {
        let mut reader = MockZeroCopyReader::new(data.to_vec());
        self.fs.write(
            self.ctx(),
            inode,
            handle,
            &mut reader,
            data.len() as u32,
            offset,
            None,
            false,
            kill_priv,
            0,
        )
    }

    /// Read data from a file handle via MockZeroCopyWriter.
    fn fuse_read(&self, inode: u64, handle: u64, size: u32, offset: u64) -> io::Result<Vec<u8>> {
        let mut writer = MockZeroCopyWriter::new();
        let n = self.fs.read(
            self.ctx(),
            inode,
            handle,
            &mut writer,
            size,
            offset,
            None,
            0,
        )?;
        let mut data = writer.into_data();
        data.truncate(n);
        Ok(data)
    }

    /// Get the permission mode bits (lower 12 bits) for an inode.
    fn get_mode(&self, inode: u64) -> u32 {
        let (st, _) = self.fs.getattr(self.ctx(), inode, None).unwrap();
        st.st_mode as u32 & 0o7777
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

impl MockZeroCopyReader {
    fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0 }
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
