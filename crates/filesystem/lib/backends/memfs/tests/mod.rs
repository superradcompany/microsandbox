mod test_bootstrap;
mod test_capacity;
mod test_concurrency;
mod test_create_ops;
mod test_dir_ops;
mod test_file_ops;
mod test_init_binary;
mod test_lookup;
mod test_metadata;
mod test_refcount;
mod test_remove_ops;
mod test_rename;
mod test_special_ops;
mod test_xattr;

use std::{ffi::CString, fs::File, io, os::fd::AsRawFd};

use super::*;
use crate::{
    Context, DynFileSystem, Entry, Extensions, FsOptions, GetxattrReply, ListxattrReply,
    OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter, stat64,
};

const LINUX_EPERM: i32 = 1;
const LINUX_ENOENT: i32 = 2;
const LINUX_EBADF: i32 = 9;
const LINUX_EACCES: i32 = 13;
const LINUX_EEXIST: i32 = 17;
const LINUX_EISDIR: i32 = 21;
const LINUX_EINVAL: i32 = 22;
const LINUX_ENOSPC: i32 = 28;
const LINUX_ENOTEMPTY: i32 = 39;
const LINUX_ENODATA: i32 = 61;

const ROOT_INODE: u64 = 1;
const INIT_INODE: u64 = 2;

struct MemFsTestSandbox {
    fs: MemFs,
}

struct MockZeroCopyWriter {
    buf: Vec<u8>,
}

struct MockZeroCopyReader {
    data: Vec<u8>,
    pos: usize,
}

impl MemFsTestSandbox {
    fn new() -> Self {
        let fs = MemFs::builder().build().unwrap();
        fs.init(FsOptions::empty()).unwrap();
        Self { fs }
    }

    fn with_capacity(bytes: u64) -> Self {
        let fs = MemFs::builder().capacity(bytes).build().unwrap();
        fs.init(FsOptions::empty()).unwrap();
        Self { fs }
    }

    fn with_max_inodes(max: u64) -> Self {
        let fs = MemFs::builder().max_inodes(max).build().unwrap();
        fs.init(FsOptions::empty()).unwrap();
        Self { fs }
    }

    fn ctx() -> Context {
        Context {
            uid: 1000,
            gid: 1000,
            pid: 1,
        }
    }

    fn ctx_as(uid: u32, gid: u32) -> Context {
        Context { uid, gid, pid: 1 }
    }

    fn cstr(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    fn lookup(&self, parent: u64, name: &str) -> io::Result<Entry> {
        self.fs.lookup(Self::ctx(), parent, &Self::cstr(name))
    }

    fn lookup_root(&self, name: &str) -> io::Result<Entry> {
        self.lookup(ROOT_INODE, name)
    }

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

    fn fuse_create_root(&self, name: &str) -> io::Result<(Entry, Option<u64>)> {
        self.fuse_create(ROOT_INODE, name, 0o644)
    }

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

    fn fuse_mkdir_root(&self, name: &str) -> io::Result<Entry> {
        self.fuse_mkdir(ROOT_INODE, name, 0o755)
    }

    fn fuse_open(&self, ino: u64, flags: u32) -> io::Result<(Option<u64>, OpenOptions)> {
        self.fs.open(Self::ctx(), ino, false, flags)
    }

    fn fuse_opendir(&self, ino: u64) -> io::Result<(Option<u64>, OpenOptions)> {
        self.fs.opendir(Self::ctx(), ino, 0)
    }

    fn fuse_read(&self, ino: u64, handle: u64, size: u32, offset: u64) -> io::Result<Vec<u8>> {
        let mut writer = MockZeroCopyWriter::new();
        let n = self
            .fs
            .read(Self::ctx(), ino, handle, &mut writer, size, offset, None, 0)?;
        let mut data = writer.into_data();
        data.truncate(n);
        Ok(data)
    }

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

    fn readdir_names(&self, ino: u64) -> io::Result<Vec<String>> {
        let (handle, _) = self.fuse_opendir(ino)?;
        let handle = handle.unwrap();
        let entries = self.fs.readdir(Self::ctx(), ino, handle, 65536, 0)?;
        let names: Vec<String> = entries
            .iter()
            .map(|e| String::from_utf8_lossy(e.name).to_string())
            .collect();
        self.fs.releasedir(Self::ctx(), ino, 0, handle)?;
        Ok(names)
    }

    fn create_file_with_content(&self, parent: u64, name: &str, data: &[u8]) -> io::Result<u64> {
        let (entry, handle) = self.fuse_create(parent, name, 0o644)?;
        let handle = handle.unwrap();
        self.fuse_write(entry.inode, handle, data, 0)?;
        self.fs
            .release(Self::ctx(), entry.inode, 0, handle, false, false, None)?;
        Ok(entry.inode)
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
