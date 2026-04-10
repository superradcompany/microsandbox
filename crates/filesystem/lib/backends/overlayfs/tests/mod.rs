//! Tests for the overlay filesystem backend.
//!
//! Tests cover overlay-specific behavior: layer merging, whiteout masking,
//! opaque directories, copy-up on write, directory rename with redirects,
//! and multi-layer readdir deduplication.

mod test_bootstrap;
mod test_create_ops;
mod test_file_ops;
mod test_index;
mod test_lookup;
mod test_metadata;
mod test_multi_layer;
mod test_read_only;
mod test_readdir;
mod test_remove_ops;
mod test_rename;
mod test_special_ops;
mod test_xattr;

use std::{
    ffi::CString,
    fs::File,
    io,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

use tempfile::TempDir;

use super::*;
use crate::{
    Context, DynFileSystem, Entry, Extensions, FsOptions, GetxattrReply, ListxattrReply,
    SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Linux errno constants for assertion matching.
///
/// The OverlayFs always returns Linux errno values regardless of host OS
/// (macOS BSD errnos are translated via `platform::linux_error()`).
const LINUX_ENOENT: i32 = 2;
const LINUX_EBADF: i32 = 9;
const LINUX_EACCES: i32 = 13;
const LINUX_EEXIST: i32 = 17;
const LINUX_EINVAL: i32 = 22;
const LINUX_ELOOP: i32 = 40;
const LINUX_ENOTEMPTY: i32 = 39;
const LINUX_EROFS: i32 = 30;
const LINUX_ENODATA: i32 = 61;

/// Root inode number (FUSE convention).
const ROOT_INODE: u64 = 1;

/// Init binary inode number (ROOT_ID + 1).
const INIT_INODE: u64 = 2;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Test harness providing a fully initialized OverlayFs over temp directories.
///
/// Field order matters: `fs` is dropped before `_tmp` (Rust drops fields in
/// declaration order), ensuring the filesystem is torn down before the
/// temporary directories are removed.
struct OverlayTestSandbox {
    fs: OverlayFs,
    _tmp: TempDir,
    upper_root: PathBuf,
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
// Functions
//--------------------------------------------------------------------------------------------------

fn root_ctx() -> Context {
    Context {
        uid: 0,
        gid: 0,
        pid: 1,
    }
}

fn make_cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn fs_lookup(fs: &OverlayFs, parent: u64, name: &str) -> io::Result<Entry> {
    fs.lookup(root_ctx(), parent, &make_cstr(name))
}

fn fs_lookup_root(fs: &OverlayFs, name: &str) -> io::Result<Entry> {
    fs_lookup(fs, ROOT_INODE, name)
}

fn fs_fuse_open(fs: &OverlayFs, inode: u64, flags: u32) -> io::Result<u64> {
    let (handle, _opts) = fs.open(root_ctx(), inode, false, flags)?;
    Ok(handle.unwrap())
}

fn fs_fuse_opendir(fs: &OverlayFs, inode: u64) -> io::Result<u64> {
    let (handle, _opts) = fs.opendir(root_ctx(), inode, 0)?;
    Ok(handle.unwrap())
}

fn fs_fuse_read(
    fs: &OverlayFs,
    inode: u64,
    handle: u64,
    size: u32,
    offset: u64,
) -> io::Result<Vec<u8>> {
    let mut writer = MockZeroCopyWriter::new();
    let n = fs.read(
        root_ctx(),
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

fn fs_readdir_names(fs: &OverlayFs, inode: u64) -> io::Result<Vec<Vec<u8>>> {
    let handle = fs_fuse_opendir(fs, inode)?;
    let entries = fs.readdir(root_ctx(), inode, handle, 65536, 0)?;
    let names = entries.iter().map(|e| e.name.to_vec()).collect();
    fs.releasedir(root_ctx(), inode, 0, handle)?;
    Ok(names)
}

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

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl OverlayTestSandbox {
    /// Create a new sandbox with 1 empty lower layer and empty upper.
    fn new() -> Self {
        Self::with_lower(|_| {})
    }

    /// Create a sandbox with 1 lower layer. `f` populates the lower dir before mount.
    fn with_lower(f: impl FnOnce(&Path)) -> Self {
        Self::with_layers(1, |lowers, _upper| {
            f(&lowers[0]);
        })
    }

    /// Create a sandbox with N lower layers. `f` populates layers before mount.
    fn with_layers(n: usize, f: impl FnOnce(&[PathBuf], &Path)) -> Self {
        let tmp = tempfile::tempdir().unwrap();

        let mut lower_roots = Vec::with_capacity(n);
        for i in 0..n {
            let lower = tmp.path().join(format!("lower_{i}"));
            std::fs::create_dir(&lower).unwrap();
            lower_roots.push(lower);
        }

        let upper = tmp.path().join("upper");
        std::fs::create_dir(&upper).unwrap();

        let staging = tmp.path().join("staging");
        std::fs::create_dir(&staging).unwrap();

        // Let caller populate layers before mount.
        f(&lower_roots, &upper);

        let mut builder = OverlayFs::builder();
        for lower in &lower_roots {
            builder = builder.layer(lower);
        }
        let fs = builder.writable(&upper).staging(&staging).build().unwrap();

        fs.init(FsOptions::empty()).unwrap();

        let upper_root = upper;
        Self {
            fs,
            _tmp: tmp,
            upper_root,
        }
    }

    /// Get a default Context (uid=0, gid=0 — root user).
    fn ctx(&self) -> Context {
        root_ctx()
    }

    /// Get a Context with specific uid/gid.
    fn ctx_as(&self, uid: u32, gid: u32) -> Context {
        Context { uid, gid, pid: 1 }
    }

    /// Make a CString from a &str (panics on embedded nul).
    fn cstr(s: &str) -> CString {
        make_cstr(s)
    }

    /// Lookup a name in a parent directory.
    fn lookup(&self, parent: u64, name: &str) -> io::Result<Entry> {
        fs_lookup(&self.fs, parent, name)
    }

    /// Lookup a name in the root directory.
    fn lookup_root(&self, name: &str) -> io::Result<Entry> {
        fs_lookup_root(&self.fs, name)
    }

    /// Create a file via the FUSE create() operation. Returns (Entry, handle).
    fn fuse_create(&self, parent: u64, name: &str, mode: u32) -> io::Result<(Entry, u64)> {
        let (entry, handle, _opts) = self.fs.create(
            self.ctx(),
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
        fs_fuse_open(&self.fs, inode, flags)
    }

    /// Open a directory by inode. Returns handle.
    fn fuse_opendir(&self, inode: u64) -> io::Result<u64> {
        fs_fuse_opendir(&self.fs, inode)
    }

    /// Write data to a file handle via MockZeroCopyReader.
    fn fuse_write(&self, inode: u64, handle: u64, data: &[u8], offset: u64) -> io::Result<usize> {
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
            false,
            0,
        )
    }

    /// Read data from a file handle via MockZeroCopyWriter.
    fn fuse_read(&self, inode: u64, handle: u64, size: u32, offset: u64) -> io::Result<Vec<u8>> {
        fs_fuse_read(&self.fs, inode, handle, size, offset)
    }

    /// Collect all entry names from readdir on the given inode.
    fn readdir_names(&self, inode: u64) -> io::Result<Vec<Vec<u8>>> {
        fs_readdir_names(&self.fs, inode)
    }

    /// Check if a whiteout marker exists on the upper layer.
    fn upper_has_whiteout(&self, name: &str) -> bool {
        let wh_name = format!(".wh.{name}");
        self.upper_root.join(&wh_name).exists()
    }

    /// Check if a file exists on the upper layer.
    fn upper_has_file(&self, name: &str) -> bool {
        self.upper_root.join(name).exists()
    }

    /// Assert that an io::Result is an error with the expected Linux errno.
    fn assert_errno<T>(result: io::Result<T>, expected_errno: i32) {
        assert_errno(result, expected_errno)
    }
}

/// Test harness providing a read-only OverlayFs (no upper layer).
struct ReadOnlyOverlayTestSandbox {
    fs: OverlayFs,
    _tmp: TempDir,
}

impl ReadOnlyOverlayTestSandbox {
    /// Create a read-only sandbox with 1 lower layer. `f` populates before mount.
    fn with_lower(f: impl FnOnce(&Path)) -> Self {
        Self::with_layers(1, |lowers| {
            f(&lowers[0]);
        })
    }

    /// Create a read-only sandbox with N lower layers.
    fn with_layers(n: usize, f: impl FnOnce(&[PathBuf])) -> Self {
        let tmp = tempfile::tempdir().unwrap();

        let mut lower_roots = Vec::with_capacity(n);
        for i in 0..n {
            let lower = tmp.path().join(format!("lower_{i}"));
            std::fs::create_dir(&lower).unwrap();
            lower_roots.push(lower);
        }

        f(&lower_roots);

        let mut builder = OverlayFs::builder();
        for lower in &lower_roots {
            builder = builder.layer(lower);
        }
        let fs = builder.read_only().build().unwrap();

        fs.init(FsOptions::empty()).unwrap();

        Self { fs, _tmp: tmp }
    }

    fn ctx(&self) -> Context {
        root_ctx()
    }

    fn cstr(s: &str) -> CString {
        make_cstr(s)
    }

    fn lookup(&self, parent: u64, name: &str) -> io::Result<Entry> {
        fs_lookup(&self.fs, parent, name)
    }

    fn lookup_root(&self, name: &str) -> io::Result<Entry> {
        fs_lookup_root(&self.fs, name)
    }

    fn fuse_open(&self, inode: u64, flags: u32) -> io::Result<u64> {
        fs_fuse_open(&self.fs, inode, flags)
    }

    fn fuse_read(&self, inode: u64, handle: u64, size: u32, offset: u64) -> io::Result<Vec<u8>> {
        fs_fuse_read(&self.fs, inode, handle, size, offset)
    }

    fn readdir_names(&self, inode: u64) -> io::Result<Vec<Vec<u8>>> {
        fs_readdir_names(&self.fs, inode)
    }

    fn assert_errno<T>(result: io::Result<T>, expected_errno: i32) {
        assert_errno(result, expected_errno)
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
