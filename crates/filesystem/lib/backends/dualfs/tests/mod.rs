//! Tests for the DualFs two-backend compositional filesystem.
//!
//! Tests cover DualFs-specific behavior: policy routing, merged lookup,
//! materialization, whiteout masking, opaque directories, hook pipeline,
//! and concurrency safety.

mod test_bootstrap;
mod test_concurrency;
mod test_create_ops;
mod test_dir_ops;
mod test_file_ops;
mod test_hooks;
mod test_init_binary;
mod test_integration;
mod test_lookup;
mod test_materialize;
mod test_metadata;
mod test_policies;
mod test_remove_ops;
mod test_rename;
mod test_special_ops;
mod test_whiteouts;
mod test_xattr;

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use super::*;
use crate::backends::memfs::MemFs;
use crate::{
    Context, DynFileSystem, Entry, Extensions, FsOptions, GetxattrReply, ListxattrReply,
    SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Linux errno constants for assertion matching.
///
/// DualFs always returns Linux errno values regardless of host OS
/// (macOS BSD errnos are translated via `platform::linux_error()`).
#[allow(dead_code)]
const LINUX_EPERM: i32 = 1;
#[allow(dead_code)]
const LINUX_ENOENT: i32 = 2;
#[allow(dead_code)]
const LINUX_EBADF: i32 = 9;
#[allow(dead_code)]
const LINUX_EACCES: i32 = 13;
#[allow(dead_code)]
const LINUX_EEXIST: i32 = 17;
#[allow(dead_code)]
const LINUX_EXDEV: i32 = 18;
#[allow(dead_code)]
const LINUX_EISDIR: i32 = 21;
#[allow(dead_code)]
const LINUX_EINVAL: i32 = 22;
#[allow(dead_code)]
const LINUX_ENOTEMPTY: i32 = 39;
#[allow(dead_code)]
const LINUX_ENODATA: i32 = 61;

/// Root inode number (FUSE convention).
const ROOT_INODE: u64 = 1;

/// Init binary inode number (ROOT_ID + 1).
const INIT_INODE: u64 = 2;

/// Linux rename flags.
const RENAME_NOREPLACE: u32 = 1;
const RENAME_EXCHANGE: u32 = 2;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Test harness providing a fully initialized DualFs over two MemFs backends.
struct DualFsTestSandbox {
    fs: DualFs,
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

impl DualFsTestSandbox {
    /// Create a new sandbox with default config (two empty MemFs backends, default policy).
    fn new() -> Self {
        let backend_a = MemFs::builder().build().unwrap();
        let backend_b = MemFs::builder().build().unwrap();
        let fs = DualFs::builder()
            .backend_a(backend_a)
            .backend_b(backend_b)
            .build()
            .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        Self { fs }
    }

    /// Create a sandbox with pre-populated backend_b.
    ///
    /// The closure receives a reference to the backend_b MemFs for population
    /// before it is moved into the DualFs builder.
    fn with_backend_b(setup_b: impl FnOnce(&MemFs)) -> Self {
        let backend_a = MemFs::builder().build().unwrap();
        let backend_b = MemFs::builder().build().unwrap();
        backend_b.init(FsOptions::empty()).unwrap();
        setup_b(&backend_b);
        let fs = DualFs::builder()
            .backend_a(backend_a)
            .backend_b(backend_b)
            .build()
            .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        Self { fs }
    }

    /// Create a sandbox with a custom dispatch policy.
    fn with_policy(p: impl policy::DualDispatchPolicy + 'static) -> Self {
        let backend_a = MemFs::builder().build().unwrap();
        let backend_b = MemFs::builder().build().unwrap();
        let fs = DualFs::builder()
            .backend_a(backend_a)
            .backend_b(backend_b)
            .policy(p)
            .build()
            .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        Self { fs }
    }

    /// Create a sandbox with a custom policy and pre-populated backend_b.
    fn with_policy_and_backend_b(
        p: impl policy::DualDispatchPolicy + 'static,
        setup_b: impl FnOnce(&MemFs),
    ) -> Self {
        let backend_a = MemFs::builder().build().unwrap();
        let backend_b = MemFs::builder().build().unwrap();
        backend_b.init(FsOptions::empty()).unwrap();
        setup_b(&backend_b);
        let fs = DualFs::builder()
            .backend_a(backend_a)
            .backend_b(backend_b)
            .policy(p)
            .build()
            .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        Self { fs }
    }

    /// Create a sandbox with lifecycle hooks.
    fn with_hooks(hooks_list: Vec<Arc<dyn hooks::DualDispatchHook>>) -> Self {
        let backend_a = MemFs::builder().build().unwrap();
        let backend_b = MemFs::builder().build().unwrap();
        let mut builder = DualFs::builder()
            .backend_a(backend_a)
            .backend_b(backend_b);
        for h in hooks_list {
            builder = builder.hook(h);
        }
        let fs = builder.build().unwrap();
        fs.init(FsOptions::empty()).unwrap();
        Self { fs }
    }

    /// Get a default Context (uid=0, gid=0 — root user).
    fn ctx() -> Context {
        Context {
            uid: 0,
            gid: 0,
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
    fn fuse_create(&self, parent: u64, name: &str, mode: u32) -> io::Result<(Entry, u64)> {
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
        Ok((entry, handle.unwrap()))
    }

    /// Create a file in root via FUSE create() with mode 0o644.
    fn fuse_create_root(&self, name: &str) -> io::Result<(Entry, u64)> {
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

    /// Open a file by inode. Returns handle.
    fn fuse_open(&self, inode: u64, flags: u32) -> io::Result<u64> {
        let (handle, _opts) = self.fs.open(Self::ctx(), inode, false, flags)?;
        Ok(handle.unwrap())
    }

    /// Open a directory by inode. Returns handle.
    fn fuse_opendir(&self, inode: u64) -> io::Result<u64> {
        let (handle, _opts) = self.fs.opendir(Self::ctx(), inode, 0)?;
        Ok(handle.unwrap())
    }

    /// Write data to a file handle via MockZeroCopyReader.
    fn fuse_write(&self, inode: u64, handle: u64, data: &[u8], offset: u64) -> io::Result<usize> {
        let mut reader = MockZeroCopyReader::new(data.to_vec());
        self.fs.write(
            Self::ctx(),
            inode,
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

    /// Read data from a file handle via MockZeroCopyWriter.
    fn fuse_read(&self, inode: u64, handle: u64, size: u32, offset: u64) -> io::Result<Vec<u8>> {
        let mut writer = MockZeroCopyWriter::new();
        let n = self.fs.read(
            Self::ctx(),
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

    /// Collect all entry names from readdir on the given inode.
    fn readdir_names(&self, inode: u64) -> io::Result<Vec<String>> {
        let handle = self.fuse_opendir(inode)?;
        let entries = self.fs.readdir(Self::ctx(), inode, handle, 65536, 0)?;
        let names: Vec<String> = entries
            .iter()
            .map(|e| String::from_utf8_lossy(e.name).to_string())
            .collect();
        self.fs.releasedir(Self::ctx(), inode, 0, handle)?;
        Ok(names)
    }

    /// Create a file in the given parent with content, then release the handle.
    fn create_file_with_content(
        &self,
        parent: u64,
        name: &str,
        data: &[u8],
    ) -> io::Result<u64> {
        let (entry, handle) = self.fuse_create(parent, name, 0o644)?;
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

/// Create a file on a MemFs backend directly via DynFileSystem methods.
fn memfs_create_file(fs: &MemFs, parent: u64, name: &str, content: &[u8]) {
    let ctx = Context {
        uid: 0,
        gid: 0,
        pid: 1,
    };
    let cname = CString::new(name).unwrap();
    let (entry, handle, _) = fs
        .create(
            ctx,
            parent,
            &cname,
            0o644,
            false,
            libc::O_RDWR as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    let handle = handle.unwrap();
    let mut reader = MockZeroCopyReader::new(content.to_vec());
    fs.write(
        ctx,
        entry.inode,
        handle,
        &mut reader,
        content.len() as u32,
        0,
        None,
        false,
        false,
        0,
    )
    .unwrap();
    fs.release(ctx, entry.inode, 0, handle, false, false, None)
        .unwrap();
}

/// Create a directory on a MemFs backend directly via DynFileSystem methods.
fn memfs_mkdir(fs: &MemFs, parent: u64, name: &str) -> u64 {
    let ctx = Context {
        uid: 0,
        gid: 0,
        pid: 1,
    };
    let cname = CString::new(name).unwrap();
    let entry = fs
        .mkdir(ctx, parent, &cname, 0o755, 0, Extensions::default())
        .unwrap();
    entry.inode
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
