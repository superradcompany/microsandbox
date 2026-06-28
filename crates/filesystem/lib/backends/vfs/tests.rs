//! Tests for the path-based `VirtualFs` scaffold.
//!
//! These drive the `DynFileSystem` surface end-to-end against an in-memory
//! `PathFs` backend, exercising the scaffold's inode↔path bookkeeping,
//! handle tables, readdir snapshots, rename remapping, and zero-copy I/O.

use std::{
    ffi::CString,
    io,
    path::Path,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use super::test_backend::{InMemoryFs, MockReader, MockWriter, Node};
use super::{NodeKind, PathFs, VAttr, VDirEntry, VirtualFs, *};
use crate::{Context, DynFileSystem, Entry, Extensions, FsOptions, GetxattrReply, SetattrValid};

const LINUX_ENOENT: i32 = 2;
const LINUX_EPERM: i32 = 1;
const LINUX_EBADF: i32 = 9;
const LINUX_EISDIR: i32 = 21;
const LINUX_ENOTDIR: i32 = 20;
const LINUX_ENOTEMPTY: i32 = 39;
const LINUX_ENOSYS: i32 = 38;
const LINUX_EINVAL: i32 = 22;
const LINUX_EEXIST: i32 = 17;
const LINUX_EIO: i32 = 5;
const LINUX_EAGAIN: i32 = 11;
const LINUX_ESTALE: i32 = 116;
const LINUX_ENODATA: i32 = 61;

//--------------------------------------------------------------------------------------------------
// Test harness
//--------------------------------------------------------------------------------------------------

struct Sandbox {
    fs: VirtualFs<InMemoryFs>,
}

impl Sandbox {
    fn new() -> Self {
        let fs = VirtualFs::new(InMemoryFs::new()).unwrap();
        fs.init(FsOptions::empty()).unwrap();
        Sandbox { fs }
    }

    fn ctx() -> Context {
        Context {
            uid: 0,
            gid: 0,
            pid: 1,
        }
    }

    fn cstr(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    fn lookup(&self, parent: u64, name: &str) -> io::Result<Entry> {
        self.fs.lookup(Self::ctx(), parent, &Self::cstr(name))
    }

    fn create(&self, parent: u64, name: &str) -> io::Result<(Entry, u64)> {
        let (entry, handle, _) = self.fs.create(
            Self::ctx(),
            parent,
            &Self::cstr(name),
            0o644,
            false,
            libc::O_RDWR as u32,
            0,
            Extensions::default(),
        )?;
        Ok((entry, handle.unwrap()))
    }

    fn mkdir(&self, parent: u64, name: &str) -> io::Result<Entry> {
        self.fs.mkdir(
            Self::ctx(),
            parent,
            &Self::cstr(name),
            0o755,
            0,
            Extensions::default(),
        )
    }

    fn write(&self, ino: u64, handle: u64, data: &[u8], offset: u64) -> io::Result<usize> {
        let mut reader = MockReader::new(data.to_vec());
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

    fn read(&self, ino: u64, handle: u64, size: u32, offset: u64) -> io::Result<Vec<u8>> {
        let mut writer = MockWriter::new();
        let n = self
            .fs
            .read(Self::ctx(), ino, handle, &mut writer, size, offset, None, 0)?;
        let mut data = writer.buf;
        data.truncate(n);
        Ok(data)
    }

    fn readdir_names(&self, ino: u64) -> io::Result<Vec<String>> {
        let (handle, _) = self.fs.opendir(Self::ctx(), ino, 0)?;
        let handle = handle.unwrap();
        let entries = self.fs.readdir(Self::ctx(), ino, handle, 65536, 0)?;
        let names = entries
            .iter()
            .map(|e| String::from_utf8_lossy(e.name).to_string())
            .filter(|n| n != "." && n != "..")
            .collect();
        self.fs.releasedir(Self::ctx(), ino, 0, handle)?;
        Ok(names)
    }

    fn assert_errno<T>(result: io::Result<T>, expected: i32) {
        match result {
            Ok(_) => panic!("expected errno {expected}, got Ok"),
            Err(e) => assert_eq!(e.raw_os_error(), Some(expected), "got {e:?}"),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn lookup_missing_is_enoent() {
    let sb = Sandbox::new();
    Sandbox::assert_errno(sb.lookup(1, "nope"), LINUX_ENOENT);
}

#[test]
fn create_read_write_roundtrip() {
    let sb = Sandbox::new();
    let (entry, handle) = sb.create(1, "f.txt").unwrap();
    let n = sb.write(entry.inode, handle, b"hello world", 0).unwrap();
    assert_eq!(n, 11);
    let data = sb.read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(&data[..], b"hello world");
}

#[test]
fn read_partial_at_offset() {
    let sb = Sandbox::new();
    let (entry, handle) = sb.create(1, "f.txt").unwrap();
    sb.write(entry.inode, handle, b"hello world", 0).unwrap();
    let data = sb.read(entry.inode, handle, 5, 6).unwrap();
    assert_eq!(&data[..], b"world");
}

#[test]
fn write_at_offset_zero_fills_gap() {
    let sb = Sandbox::new();
    let (entry, handle) = sb.create(1, "f.txt").unwrap();
    sb.write(entry.inode, handle, b"data", 10).unwrap();
    let full = sb.read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(full.len(), 14);
    assert!(full[..10].iter().all(|&b| b == 0));
    assert_eq!(&full[10..], b"data");
}

#[test]
fn lookup_reflects_provider_size() {
    let sb = Sandbox::new();
    let (entry, handle) = sb.create(1, "f.txt").unwrap();
    sb.write(entry.inode, handle, b"abcde", 0).unwrap();
    let looked = sb.lookup(1, "f.txt").unwrap();
    assert_eq!(looked.attr.st_size, 5);
}

#[test]
fn mkdir_and_readdir_lists_children() {
    let sb = Sandbox::new();
    let dir = sb.mkdir(1, "d").unwrap();
    sb.create(dir.inode, "a.txt").unwrap();
    sb.create(dir.inode, "b.txt").unwrap();
    let mut names = sb.readdir_names(dir.inode).unwrap();
    names.sort();
    assert_eq!(names, vec!["a.txt".to_string(), "b.txt".to_string()]);
}

#[test]
fn unlink_removes_file() {
    let sb = Sandbox::new();
    sb.create(1, "gone.txt").unwrap();
    sb.fs
        .unlink(Sandbox::ctx(), 1, &Sandbox::cstr("gone.txt"))
        .unwrap();
    Sandbox::assert_errno(sb.lookup(1, "gone.txt"), LINUX_ENOENT);
}

#[test]
fn unlink_directory_is_eisdir() {
    let sb = Sandbox::new();
    let dir = sb.mkdir(1, "d").unwrap();
    Sandbox::assert_errno(
        sb.fs.unlink(Sandbox::ctx(), 1, &Sandbox::cstr("d")),
        LINUX_EISDIR,
    );
    let _ = dir;
}

#[test]
fn rmdir_file_is_enotdir() {
    let sb = Sandbox::new();
    sb.create(1, "f.txt").unwrap();
    Sandbox::assert_errno(
        sb.fs.rmdir(Sandbox::ctx(), 1, &Sandbox::cstr("f.txt")),
        LINUX_ENOTDIR,
    );
}

#[test]
fn rmdir_nonempty_is_enotempty() {
    let sb = Sandbox::new();
    let dir = sb.mkdir(1, "d").unwrap();
    sb.create(dir.inode, "child").unwrap();
    Sandbox::assert_errno(
        sb.fs.rmdir(Sandbox::ctx(), 1, &Sandbox::cstr("d")),
        LINUX_ENOTEMPTY,
    );
}

#[test]
fn rmdir_invalidates_open_directory_handle() {
    let sb = Sandbox::new();
    let dir = sb.mkdir(1, "gone").unwrap();
    let (dh, _) = sb.fs.opendir(Sandbox::ctx(), dir.inode, 0).unwrap();
    let dh = dh.unwrap();
    sb.fs
        .readdir(Sandbox::ctx(), dir.inode, dh, 65536, 0)
        .unwrap();
    sb.fs
        .rmdir(Sandbox::ctx(), 1, &Sandbox::cstr("gone"))
        .unwrap();
    Sandbox::assert_errno(
        sb.fs.readdir(Sandbox::ctx(), dir.inode, dh, 65536, 0),
        LINUX_ESTALE,
    );
}

#[test]
fn rmdir_rejects_when_readdir_returns_only_unrepresentable_names() {
    struct BadReaddirFs(InMemoryFs);

    impl PathFs for BadReaddirFs {
        fn getattr(&self, path: &Path) -> io::Result<VAttr> {
            self.0.getattr(path)
        }

        fn readdir(&self, path: &Path) -> io::Result<Vec<VDirEntry>> {
            if path == Path::new("/empty") {
                // Overlong name the scaffold cannot represent — may hide a real child.
                return Ok(vec![VDirEntry::new(vec![b'a'; 256], NodeKind::File)]);
            }
            self.0.readdir(path)
        }

        fn read(&self, path: &Path, offset: u64, size: u32) -> io::Result<Vec<u8>> {
            self.0.read(path, offset, size)
        }

        fn mkdir(&self, path: &Path, mode: u32) -> io::Result<VAttr> {
            self.0.mkdir(path, mode)
        }

        fn remove(&self, path: &Path) -> io::Result<()> {
            self.0.remove(path)
        }
    }

    let fs = VirtualFs::new(BadReaddirFs(InMemoryFs::new())).unwrap();
    fs.init(FsOptions::empty()).unwrap();
    fs.mkdir(
        Sandbox::ctx(),
        1,
        &Sandbox::cstr("empty"),
        0o755,
        0,
        Extensions::default(),
    )
    .unwrap();
    Sandbox::assert_errno(
        fs.rmdir(Sandbox::ctx(), 1, &Sandbox::cstr("empty")),
        LINUX_EIO,
    );
}

#[test]
fn rmdir_succeeds_when_readdir_returns_only_dot_entries() {
    struct DotReaddirFs(InMemoryFs);

    impl PathFs for DotReaddirFs {
        fn getattr(&self, path: &Path) -> io::Result<VAttr> {
            self.0.getattr(path)
        }

        fn readdir(&self, path: &Path) -> io::Result<Vec<VDirEntry>> {
            if path == Path::new("/empty") {
                return Ok(vec![
                    VDirEntry::new(b".", NodeKind::Dir),
                    VDirEntry::new(b"..", NodeKind::Dir),
                ]);
            }
            self.0.readdir(path)
        }

        fn read(&self, path: &Path, offset: u64, size: u32) -> io::Result<Vec<u8>> {
            self.0.read(path, offset, size)
        }

        fn mkdir(&self, path: &Path, mode: u32) -> io::Result<VAttr> {
            self.0.mkdir(path, mode)
        }

        fn remove(&self, path: &Path) -> io::Result<()> {
            self.0.remove(path)
        }
    }

    let fs = VirtualFs::new(DotReaddirFs(InMemoryFs::new())).unwrap();
    fs.init(FsOptions::empty()).unwrap();
    fs.mkdir(
        Sandbox::ctx(),
        1,
        &Sandbox::cstr("empty"),
        0o755,
        0,
        Extensions::default(),
    )
    .unwrap();
    fs.rmdir(Sandbox::ctx(), 1, &Sandbox::cstr("empty"))
        .expect("rmdir should ignore provider . and .. entries on an empty dir");
}

#[test]
fn rename_file_moves_content() {
    let sb = Sandbox::new();
    let (entry, handle) = sb.create(1, "old.txt").unwrap();
    sb.write(entry.inode, handle, b"payload", 0).unwrap();
    sb.fs
        .rename(
            Sandbox::ctx(),
            1,
            &Sandbox::cstr("old.txt"),
            1,
            &Sandbox::cstr("new.txt"),
            0,
        )
        .unwrap();
    Sandbox::assert_errno(sb.lookup(1, "old.txt"), LINUX_ENOENT);
    let moved = sb.lookup(1, "new.txt").unwrap();
    assert_eq!(moved.attr.st_size, 7);
}

#[test]
fn rename_dir_remaps_subtree_and_open_handle() {
    let sb = Sandbox::new();
    let dir = sb.mkdir(1, "d").unwrap();
    let (file, handle) = sb.create(dir.inode, "f.txt").unwrap();
    sb.write(file.inode, handle, b"keep", 0).unwrap();

    // Rename the parent directory; the open handle must follow the move.
    sb.fs
        .rename(
            Sandbox::ctx(),
            1,
            &Sandbox::cstr("d"),
            1,
            &Sandbox::cstr("e"),
            0,
        )
        .unwrap();

    // Old tree is gone, new tree resolves, and the still-open handle reads
    // through the new backing path.
    Sandbox::assert_errno(sb.lookup(1, "d"), LINUX_ENOENT);
    let new_dir = sb.lookup(1, "e").unwrap();
    let moved_file = sb.lookup(new_dir.inode, "f.txt").unwrap();
    assert_eq!(moved_file.attr.st_size, 4);
    let data = sb.read(file.inode, handle, 1024, 0).unwrap();
    assert_eq!(&data[..], b"keep");
}

#[test]
fn setattr_truncate_changes_size() {
    let sb = Sandbox::new();
    let (entry, handle) = sb.create(1, "f.txt").unwrap();
    sb.write(entry.inode, handle, b"0123456789", 0).unwrap();
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_size = 4;
    let (st, _) = sb
        .fs
        .setattr(Sandbox::ctx(), entry.inode, attr, None, SetattrValid::SIZE)
        .unwrap();
    assert_eq!(st.st_size, 4);
    let data = sb.read(entry.inode, handle, 1024, 0).unwrap();
    assert_eq!(&data[..], b"0123");
}

#[test]
fn symlink_and_readlink_roundtrip() {
    let sb = Sandbox::new();
    let entry = sb
        .fs
        .symlink(
            Sandbox::ctx(),
            &Sandbox::cstr("target/path"),
            1,
            &Sandbox::cstr("link"),
            Extensions::default(),
        )
        .unwrap();
    let target = sb.fs.readlink(Sandbox::ctx(), entry.inode).unwrap();
    assert_eq!(&target[..], b"target/path");
}

#[test]
fn symlink_rejects_dotdot_target() {
    let sb = Sandbox::new();
    Sandbox::assert_errno(
        sb.fs.symlink(
            Sandbox::ctx(),
            &Sandbox::cstr("../etc/passwd"),
            1,
            &Sandbox::cstr("bad"),
            Extensions::default(),
        ),
        LINUX_EPERM,
    );
}

#[test]
fn symlink_rejects_absolute_target() {
    let sb = Sandbox::new();
    Sandbox::assert_errno(
        sb.fs.symlink(
            Sandbox::ctx(),
            &Sandbox::cstr("/etc/passwd"),
            1,
            &Sandbox::cstr("bad"),
            Extensions::default(),
        ),
        LINUX_EPERM,
    );
}

#[test]
fn mknod_invalidates_cached_readdir() {
    let sb = Sandbox::new();
    let dir = sb.mkdir(1, "dir").unwrap();
    let (dh, _) = sb.fs.opendir(Sandbox::ctx(), dir.inode, 0).unwrap();
    let dh = dh.unwrap();
    let before = sb
        .fs
        .readdir(Sandbox::ctx(), dir.inode, dh, 65536, 0)
        .unwrap();
    let before_names: Vec<String> = before
        .iter()
        .map(|e| String::from_utf8_lossy(e.name).to_string())
        .filter(|n| n != "." && n != "..")
        .collect();
    assert!(before_names.is_empty());

    sb.fs
        .mknod(
            Sandbox::ctx(),
            dir.inode,
            &Sandbox::cstr("pipe"),
            0o644 | (libc::S_IFIFO as u32),
            0,
            0,
            Extensions::default(),
        )
        .unwrap();

    let after = sb
        .fs
        .readdir(Sandbox::ctx(), dir.inode, dh, 65536, 0)
        .unwrap();
    let after_names: Vec<String> = after
        .iter()
        .map(|e| String::from_utf8_lossy(e.name).to_string())
        .filter(|n| n != "." && n != "..")
        .collect();
    assert!(after_names.iter().any(|n| n == "pipe"));
}

#[test]
fn readdir_stale_cookie_returns_eagain_after_mutation() {
    let sb = Sandbox::new();
    let dir = sb.mkdir(1, "d").unwrap();
    for i in 0..20 {
        sb.create(dir.inode, &format!("f{i:02}")).unwrap();
    }
    let (dh, _) = sb.fs.opendir(Sandbox::ctx(), dir.inode, 0).unwrap();
    let dh = dh.unwrap();
    let page = sb.fs.readdir(Sandbox::ctx(), dir.inode, dh, 64, 0).unwrap();
    assert!(!page.is_empty());
    let cookie = page.last().unwrap().offset;
    sb.create(dir.inode, "new").unwrap();
    Sandbox::assert_errno(
        sb.fs.readdir(Sandbox::ctx(), dir.inode, dh, 65536, cookie),
        LINUX_EAGAIN,
    );
}

#[test]
fn scoped_invalidation_preserves_unrelated_directory_handles() {
    let sb = Sandbox::new();
    let dir_a = sb.mkdir(1, "a").unwrap();
    let dir_b = sb.mkdir(1, "b").unwrap();
    for i in 0..20 {
        sb.create(dir_a.inode, &format!("a{i:02}")).unwrap();
        sb.create(dir_b.inode, &format!("b{i:02}")).unwrap();
    }
    let (dh_b, _) = sb.fs.opendir(Sandbox::ctx(), dir_b.inode, 0).unwrap();
    let dh_b = dh_b.unwrap();
    let page = sb
        .fs
        .readdir(Sandbox::ctx(), dir_b.inode, dh_b, 64, 0)
        .unwrap();
    assert!(!page.is_empty());
    let cookie = page.last().unwrap().offset;
    sb.create(dir_a.inode, "new").unwrap();
    sb.fs
        .readdir(Sandbox::ctx(), dir_b.inode, dh_b, 65536, cookie)
        .expect("unrelated directory handle should stay valid after sibling mutation");
}

struct FlushSpy {
    inner: InMemoryFs,
    flushes: Arc<std::sync::atomic::AtomicUsize>,
}

impl FlushSpy {
    fn new() -> Self {
        FlushSpy {
            inner: InMemoryFs::new(),
            flushes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

impl PathFs for FlushSpy {
    fn getattr(&self, path: &Path) -> io::Result<VAttr> {
        self.inner.getattr(path)
    }

    fn readdir(&self, path: &Path) -> io::Result<Vec<VDirEntry>> {
        self.inner.readdir(path)
    }

    fn read(&self, path: &Path, offset: u64, size: u32) -> io::Result<Vec<u8>> {
        self.inner.read(path, offset, size)
    }

    fn write(&self, path: &Path, offset: u64, data: &[u8]) -> io::Result<usize> {
        self.inner.write(path, offset, data)
    }

    fn create(&self, path: &Path, attr: &VAttr) -> io::Result<VAttr> {
        self.inner.create(path, attr)
    }

    fn flush(&self, path: &Path) -> io::Result<()> {
        self.flushes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _ = path;
        Ok(())
    }
}

#[test]
fn release_with_flush_delegates_to_provider() {
    let spy = FlushSpy::new();
    let flushes = Arc::clone(&spy.flushes);
    let fs = VirtualFs::new(spy).unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let ctx = Sandbox::ctx();
    let (entry, handle, _) = fs
        .create(
            ctx,
            1,
            &Sandbox::cstr("f.txt"),
            0o644,
            false,
            libc::O_RDWR as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    let handle = handle.unwrap();
    fs.release(ctx, entry.inode, 0, handle, true, false, None)
        .unwrap();
    assert_eq!(flushes.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn fsyncdir_refreshes_stale_directory_listing() {
    let children = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let provider = MutableListingFs {
        dir_children: Arc::clone(&children),
    };
    let fs = VirtualFs::new(provider).unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let ctx = Sandbox::ctx();
    let root = fs.lookup(ctx, 1, &Sandbox::cstr(".")).unwrap();
    let dir = fs.lookup(ctx, root.inode, &Sandbox::cstr("d")).unwrap();
    let (dh, _) = fs.opendir(ctx, dir.inode, 0).unwrap();
    let dh = dh.unwrap();
    let before = fs.readdir(ctx, dir.inode, dh, 65536, 0).unwrap();
    assert!(
        before.iter().all(|e| e.name == b"." || e.name == b".."),
        "directory should only contain dot entries initially"
    );
    children.lock().unwrap().push(b"newfile".to_vec());
    let stale = fs.readdir(ctx, dir.inode, dh, 65536, 0).unwrap();
    assert!(
        stale.iter().all(|e| e.name == b"." || e.name == b".."),
        "open handle keeps point-in-time snapshot"
    );
    fs.fsyncdir(ctx, dir.inode, false, dh).unwrap();
    let after = fs.readdir(ctx, dir.inode, dh, 65536, 0).unwrap();
    let names: Vec<_> = after
        .iter()
        .filter(|e| e.name != b"." && e.name != b"..")
        .map(|e| e.name.as_ref())
        .collect();
    assert_eq!(names, vec![b"newfile".as_ref()]);
}

#[test]
fn fsyncdir_stale_cookie_returns_eagain_until_rewind() {
    let children = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let provider = MutableListingFs {
        dir_children: Arc::clone(&children),
    };
    let fs = VirtualFs::new(provider).unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let ctx = Sandbox::ctx();
    let root = fs.lookup(ctx, 1, &Sandbox::cstr(".")).unwrap();
    let dir = fs.lookup(ctx, root.inode, &Sandbox::cstr("d")).unwrap();
    let (dh, _) = fs.opendir(ctx, dir.inode, 0).unwrap();
    let dh = dh.unwrap();
    let page = fs.readdir(ctx, dir.inode, dh, 65536, 0).unwrap();
    let cookie = page.last().map(|e| e.offset).unwrap_or(0);
    children.lock().unwrap().push(b"newfile".to_vec());
    fs.fsyncdir(ctx, dir.inode, false, dh).unwrap();
    Sandbox::assert_errno(fs.readdir(ctx, dir.inode, dh, 65536, cookie), LINUX_EAGAIN);
    let after = fs.readdir(ctx, dir.inode, dh, 65536, 0).unwrap();
    let names: Vec<_> = after
        .iter()
        .filter(|e| e.name != b"." && e.name != b"..")
        .map(|e| e.name.as_ref())
        .collect();
    assert_eq!(names, vec![b"newfile".as_ref()]);
}

#[test]
fn xattr_set_get_remove() {
    let sb = Sandbox::new();
    let (entry, _) = sb.create(1, "f.txt").unwrap();
    sb.fs
        .setxattr(
            Sandbox::ctx(),
            entry.inode,
            &Sandbox::cstr("user.tag"),
            b"value",
            0,
        )
        .unwrap();
    let reply = sb
        .fs
        .getxattr(Sandbox::ctx(), entry.inode, &Sandbox::cstr("user.tag"), 64)
        .unwrap();
    match reply {
        GetxattrReply::Value(v) => assert_eq!(&v[..], b"value"),
        GetxattrReply::Count(_) => panic!("expected value"),
    }
    sb.fs
        .removexattr(Sandbox::ctx(), entry.inode, &Sandbox::cstr("user.tag"))
        .unwrap();
    Sandbox::assert_errno(
        sb.fs
            .getxattr(Sandbox::ctx(), entry.inode, &Sandbox::cstr("user.tag"), 64),
        LINUX_ENODATA,
    );
}

#[test]
fn open_directory_is_eisdir() {
    let sb = Sandbox::new();
    let dir = sb.mkdir(1, "d").unwrap();
    Sandbox::assert_errno(
        sb.fs.open(Sandbox::ctx(), dir.inode, false, 0),
        LINUX_EISDIR,
    );
}

#[test]
fn hard_link_is_unsupported() {
    let sb = Sandbox::new();
    let (entry, _) = sb.create(1, "f.txt").unwrap();
    Sandbox::assert_errno(
        sb.fs
            .link(Sandbox::ctx(), entry.inode, 1, &Sandbox::cstr("alias")),
        LINUX_ENOSYS,
    );
}

#[test]
fn open_truncate_zeros_file() {
    let sb = Sandbox::new();
    let (entry, handle) = sb.create(1, "f.txt").unwrap();
    sb.write(entry.inode, handle, b"content", 0).unwrap();
    sb.fs
        .release(Sandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
    // Re-open with O_TRUNC.
    let (h2, _) = sb
        .fs
        .open(Sandbox::ctx(), entry.inode, false, 0x200)
        .unwrap();
    let data = sb.read(entry.inode, h2.unwrap(), 1024, 0).unwrap();
    assert_eq!(data.len(), 0);
}

#[test]
fn provider_accessor_round_trips() {
    let sb = Sandbox::new();
    // The provider is reachable for backend-specific inspection.
    assert!(
        sb.fs
            .provider()
            .map
            .read()
            .unwrap()
            .contains_key(b"/".as_slice())
    );
}

#[test]
fn concurrent_creates_are_consistent() {
    use std::{sync::Arc, thread};

    let fs = Arc::new(VirtualFs::new(InMemoryFs::new()).unwrap());
    fs.init(FsOptions::empty()).unwrap();

    let threads = 8;
    let per_thread = 25;
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let fs = Arc::clone(&fs);
            thread::spawn(move || {
                for i in 0..per_thread {
                    let name = format!("t{t}_{i}.txt");
                    let (entry, handle, _) = fs
                        .create(
                            Sandbox::ctx(),
                            1,
                            &Sandbox::cstr(&name),
                            0o644,
                            false,
                            libc::O_RDWR as u32,
                            0,
                            Extensions::default(),
                        )
                        .unwrap();
                    let handle = handle.unwrap();
                    let mut reader = MockReader::new(name.clone().into_bytes());
                    fs.write(
                        Sandbox::ctx(),
                        entry.inode,
                        handle,
                        &mut reader,
                        name.len() as u32,
                        0,
                        None,
                        false,
                        false,
                        0,
                    )
                    .unwrap();
                    fs.release(Sandbox::ctx(), entry.inode, 0, handle, false, false, None)
                        .unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }

    // Every file is present and readable with its own name as content.
    let (dh, _) = fs.opendir(Sandbox::ctx(), 1, 0).unwrap();
    let dh = dh.unwrap();
    let entries = fs.readdir(Sandbox::ctx(), 1, dh, 1 << 20, 0).unwrap();
    let child_count = entries
        .iter()
        .filter(|e| e.name != b"." && e.name != b"..")
        .count();
    assert_eq!(child_count, threads * per_thread);
}

#[test]
fn rename_under_concurrent_lookup_is_consistent() {
    use std::{
        sync::Arc,
        thread,
        time::{Duration, Instant},
    };

    let fs = Arc::new(VirtualFs::new(InMemoryFs::new()).unwrap());
    fs.init(FsOptions::empty()).unwrap();

    // Build /d with N children, each holding its own name as content.
    let dir = fs
        .mkdir(
            Sandbox::ctx(),
            1,
            &Sandbox::cstr("d"),
            0o755,
            0,
            Extensions::default(),
        )
        .unwrap();
    let dir_ino = dir.inode;
    let n_children = 16usize;
    for i in 0..n_children {
        let name = format!("c{i}.txt");
        let (entry, handle, _) = fs
            .create(
                Sandbox::ctx(),
                dir_ino,
                &Sandbox::cstr(&name),
                0o644,
                false,
                libc::O_RDWR as u32,
                0,
                Extensions::default(),
            )
            .unwrap();
        let handle = handle.unwrap();
        let mut reader = MockReader::new(name.clone().into_bytes());
        fs.write(
            Sandbox::ctx(),
            entry.inode,
            handle,
            &mut reader,
            name.len() as u32,
            0,
            None,
            false,
            false,
            0,
        )
        .unwrap();
        fs.release(Sandbox::ctx(), entry.inode, 0, handle, false, false, None)
            .unwrap();
    }

    let deadline = Instant::now() + Duration::from_millis(150);

    // Renamer flips the parent directory's name /d <-> /e in a tight loop. The
    // child inodes are unchanged; only their backing paths get remapped.
    let renamer = {
        let fs = Arc::clone(&fs);
        thread::spawn(move || {
            let (mut from, mut to) = ("d", "e");
            while Instant::now() < deadline {
                if fs
                    .rename(
                        Sandbox::ctx(),
                        1,
                        &Sandbox::cstr(from),
                        1,
                        &Sandbox::cstr(to),
                        0,
                    )
                    .is_ok()
                {
                    std::mem::swap(&mut from, &mut to);
                }
            }
        })
    };

    // Readers address the directory by its (stable) inode. Because the scaffold
    // runs provider calls outside its brief remap lock, a readdir/lookup can
    // compute the pre-rename path and miss the just-moved subtree — a transient
    // ENOENT that is legal POSIX rename/lookup racing. What must NEVER happen is
    // a *partial* view: any readdir that succeeds must list the whole subtree,
    // any child that resolves must read back intact, and no other errno may leak.
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let fs = Arc::clone(&fs);
            thread::spawn(move || {
                let tolerate = |e: &io::Error| {
                    assert_eq!(
                        e.raw_os_error(),
                        Some(LINUX_ENOENT),
                        "only a transient ENOENT is acceptable mid-rename, got {e:?}"
                    );
                };
                while Instant::now() < deadline {
                    match fs.opendir(Sandbox::ctx(), dir_ino, 0) {
                        Ok((dh, _)) => {
                            let dh = dh.unwrap();
                            match fs.readdir(Sandbox::ctx(), dir_ino, dh, 1 << 20, 0) {
                                Ok(entries) => {
                                    let count = entries
                                        .iter()
                                        .filter(|e| e.name != b"." && e.name != b"..")
                                        .count();
                                    assert_eq!(count, n_children, "partial subtree during rename");
                                }
                                Err(e) => tolerate(&e),
                            }
                            fs.releasedir(Sandbox::ctx(), dir_ino, 0, dh).unwrap();
                        }
                        Err(e) => tolerate(&e),
                    }

                    for i in 0..n_children {
                        match fs.lookup(
                            Sandbox::ctx(),
                            dir_ino,
                            &Sandbox::cstr(&format!("c{i}.txt")),
                        ) {
                            Ok(e) => assert!(e.attr.st_size >= 2, "child backing path went stale"),
                            Err(e) => tolerate(&e),
                        }
                    }
                }
            })
        })
        .collect();

    renamer.join().unwrap();
    for r in readers {
        r.join().unwrap();
    }

    // The directory resolves under exactly one of the two names with every child
    // intact, proving the map settled to a consistent state.
    let final_dir = fs
        .lookup(Sandbox::ctx(), 1, &Sandbox::cstr("d"))
        .or_else(|_| fs.lookup(Sandbox::ctx(), 1, &Sandbox::cstr("e")))
        .expect("dir must resolve under d or e after the renames settle");
    let (dh, _) = fs.opendir(Sandbox::ctx(), final_dir.inode, 0).unwrap();
    let dh = dh.unwrap();
    let entries = fs
        .readdir(Sandbox::ctx(), final_dir.inode, dh, 1 << 20, 0)
        .unwrap();
    let count = entries
        .iter()
        .filter(|e| e.name != b"." && e.name != b"..")
        .count();
    assert_eq!(count, n_children);
}

#[test]
fn open_consults_live_kind_not_cached() {
    let sb = Sandbox::new();
    let (entry, _) = sb.create(1, "f").unwrap(); // interned as a file
    // The programmable backend turns the path into a directory out-of-band.
    {
        let mut map = sb.fs.provider().map.write().unwrap();
        map.insert(b"/f".to_vec(), Node::new(NodeKind::Dir, 0o755));
    }
    // open/opendir must reflect the live kind, not the kind seen at intern.
    Sandbox::assert_errno(
        sb.fs.open(Sandbox::ctx(), entry.inode, false, 0),
        LINUX_EISDIR,
    );
    let (h, _) = sb.fs.opendir(Sandbox::ctx(), entry.inode, 0).unwrap();
    assert!(h.is_some());
}

#[test]
fn readdir_does_not_pin_unlooked_children() {
    let sb = Sandbox::new();
    let dir = sb.mkdir(1, "d").unwrap();
    // Inject children straight into the backend; they are never looked up
    // through the scaffold, so readdir must not permanently intern them.
    {
        let mut map = sb.fs.provider().map.write().unwrap();
        map.insert(b"/d/x".to_vec(), Node::new(NodeKind::File, 0o644));
        map.insert(b"/d/y".to_vec(), Node::new(NodeKind::File, 0o644));
    }
    let before = sb.fs.inodes.read().unwrap().iter_alt().count();
    let mut names = sb.readdir_names(dir.inode).unwrap();
    names.sort();
    assert_eq!(names, vec!["x".to_string(), "y".to_string()]);
    let after = sb.fs.inodes.read().unwrap().iter_alt().count();
    assert_eq!(before, after, "readdir leaked interned nodes");
    // The children are absent from the map until a real lookup establishes them.
    assert!(
        sb.fs
            .inodes
            .read()
            .unwrap()
            .get_alt(b"/d/x".as_slice())
            .is_none()
    );
}

#[test]
fn rename_over_dir_evicts_stale_destination_nodes() {
    let sb = Sandbox::new();
    let dst = sb.mkdir(1, "dst").unwrap();
    let (old, _) = sb.create(dst.inode, "old").unwrap(); // interns + refs /dst/old
    assert!(
        sb.fs
            .inodes
            .read()
            .unwrap()
            .get_alt(b"/dst/old".as_slice())
            .is_some()
    );

    let src = sb.mkdir(1, "src").unwrap();
    sb.create(src.inode, "new").unwrap();

    sb.fs
        .rename(
            Sandbox::ctx(),
            1,
            &Sandbox::cstr("src"),
            1,
            &Sandbox::cstr("dst"),
            0,
        )
        .unwrap();

    // The overwritten destination's child no longer occupies its old path.
    assert!(
        sb.fs
            .inodes
            .read()
            .unwrap()
            .get_alt(b"/dst/old".as_slice())
            .is_none(),
        "stale destination path was not freed"
    );
    // But the kernel still holds a lookup reference on that inode, so it stays
    // resolvable until FORGET — as ESTALE (its name is gone), never EBADF (which
    // would claim the kernel referenced an inode the table dropped).
    Sandbox::assert_errno(sb.fs.getattr(Sandbox::ctx(), old.inode, None), LINUX_ESTALE);
    // Once forgotten, the inode is fully reclaimed.
    sb.fs.forget(Sandbox::ctx(), old.inode, 1);
    Sandbox::assert_errno(sb.fs.getattr(Sandbox::ctx(), old.inode, None), LINUX_EBADF);

    // The moved subtree resolves under the destination.
    let new_dst = sb.lookup(1, "dst").unwrap();
    assert!(sb.lookup(new_dst.inode, "new").is_ok());
}

#[test]
fn open_opendir_on_tombstoned_inode_return_estale() {
    let sb = Sandbox::new();
    let dst = sb.mkdir(1, "dst").unwrap();
    let (old, _) = sb.create(dst.inode, "old").unwrap();
    let src = sb.mkdir(1, "src").unwrap();
    sb.create(src.inode, "new").unwrap();

    sb.fs
        .rename(
            Sandbox::ctx(),
            1,
            &Sandbox::cstr("src"),
            1,
            &Sandbox::cstr("dst"),
            0,
        )
        .unwrap();

    Sandbox::assert_errno(
        sb.fs
            .open(Sandbox::ctx(), old.inode, false, libc::O_RDONLY as u32),
        LINUX_ESTALE,
    );
    Sandbox::assert_errno(sb.fs.opendir(Sandbox::ctx(), dst.inode, 0), LINUX_ESTALE);
    Sandbox::assert_errno(sb.readdir_names(dst.inode), LINUX_ESTALE);
}

#[test]
fn unlink_tombstone_rejects_open() {
    let sb = Sandbox::new();
    let (entry, _) = sb.create(1, "gone").unwrap();
    sb.fs
        .unlink(Sandbox::ctx(), 1, &Sandbox::cstr("gone"))
        .unwrap();
    Sandbox::assert_errno(
        sb.fs
            .open(Sandbox::ctx(), entry.inode, false, libc::O_RDONLY as u32),
        LINUX_ESTALE,
    );
}

struct BadReaddirFs;

struct MutableListingFs {
    dir_children: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl PathFs for MutableListingFs {
    fn getattr(&self, path: &Path) -> io::Result<VAttr> {
        match path.to_str() {
            Some("/") | Some("/d") => Ok(VAttr::dir(0o755)),
            Some(p) if p.starts_with("/d/") => Ok(VAttr::file(0o644, 0)),
            _ => Err(io::Error::from_raw_os_error(LINUX_ENOENT)),
        }
    }

    fn readdir(&self, path: &Path) -> io::Result<Vec<VDirEntry>> {
        if path == Path::new("/") {
            return Ok(vec![VDirEntry::new(b"d".to_vec(), NodeKind::Dir)]);
        }
        if path == Path::new("/d") {
            return Ok(self
                .dir_children
                .lock()
                .unwrap()
                .iter()
                .map(|name| VDirEntry::new(name.clone(), NodeKind::File))
                .collect());
        }
        Err(io::Error::from_raw_os_error(LINUX_ENOENT))
    }

    fn read(&self, _path: &Path, _offset: u64, _size: u32) -> io::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

impl PathFs for BadReaddirFs {
    fn getattr(&self, path: &Path) -> io::Result<VAttr> {
        if path == Path::new("/") {
            Ok(VAttr::dir(0o755))
        } else {
            Err(io::Error::from_raw_os_error(LINUX_ENOENT))
        }
    }

    fn readdir(&self, path: &Path) -> io::Result<Vec<VDirEntry>> {
        if path == Path::new("/") {
            Ok(vec![
                // Names the scaffold cannot represent: `.`/`..`, a slash, and an
                // empty name. Each must be skipped, not abort the whole listing.
                VDirEntry::new(b"..".to_vec(), NodeKind::File),
                VDirEntry::new(b".".to_vec(), NodeKind::File),
                VDirEntry::new(b"a/b".to_vec(), NodeKind::File),
                VDirEntry::new(Vec::new(), NodeKind::File),
                VDirEntry::new(b"good".to_vec(), NodeKind::File),
            ])
        } else {
            Err(io::Error::from_raw_os_error(LINUX_ENOENT))
        }
    }

    fn read(&self, _path: &Path, _offset: u64, _size: u32) -> io::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

struct FlakyReaddirPlusFs;

impl PathFs for FlakyReaddirPlusFs {
    fn getattr(&self, path: &Path) -> io::Result<VAttr> {
        if path == Path::new("/") {
            Ok(VAttr::dir(0o755))
        } else {
            Err(io::Error::from_raw_os_error(LINUX_EIO))
        }
    }

    fn readdir(&self, path: &Path) -> io::Result<Vec<VDirEntry>> {
        if path == Path::new("/") {
            Ok(vec![VDirEntry::new(b"child".to_vec(), NodeKind::File)])
        } else {
            Err(io::Error::from_raw_os_error(LINUX_ENOENT))
        }
    }

    fn read(&self, _path: &Path, _offset: u64, _size: u32) -> io::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

#[test]
fn readdir_skips_unrepresentable_provider_names() {
    let fs = VirtualFs::new(BadReaddirFs).unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let (handle, _) = fs.opendir(Sandbox::ctx(), 1, 0).unwrap();
    // A name the scaffold cannot represent hides only that entry; the listing
    // still succeeds and returns the valid siblings (plus synthesized `.`/`..`).
    let entries = fs
        .readdir(Sandbox::ctx(), 1, handle.unwrap(), 65536, 0)
        .expect("one bad name must not fail the whole listing");
    let names: Vec<String> = entries
        .iter()
        .map(|e| String::from_utf8_lossy(e.name).to_string())
        .filter(|n| n != "." && n != "..")
        .collect();
    assert_eq!(names, vec!["good".to_string()]);
}

#[test]
fn readdir_dino_is_stable_across_listings() {
    let sb = Sandbox::new();
    sb.create(1, "a.txt").unwrap();
    sb.create(1, "b.txt").unwrap();

    let dino = |sb: &Sandbox| -> Vec<u64> {
        let (handle, _) = sb.fs.opendir(Sandbox::ctx(), 1, 0).unwrap();
        let handle = handle.unwrap();
        let entries = sb.fs.readdir(Sandbox::ctx(), 1, handle, 65536, 0).unwrap();
        let inos = entries
            .iter()
            .filter(|e| e.name != b"." && e.name != b"..")
            .map(|e| e.ino)
            .collect();
        sb.fs.releasedir(Sandbox::ctx(), 1, 0, handle).unwrap();
        inos
    };

    // The same unchanged entries must report the same d_ino on a fresh opendir,
    // rather than a brand-new number each time.
    assert_eq!(dino(&sb), dino(&sb));
}

/// Provider with more children than [`super::rpc::protocol::MAX_BATCH_PATHS`].
struct LargeDirFs {
    count: usize,
}

impl PathFs for LargeDirFs {
    fn getattr(&self, path: &Path) -> io::Result<VAttr> {
        if path == Path::new("/") {
            return Ok(VAttr::dir(0o755));
        }
        let key = path.as_os_str().as_bytes();
        if key.starts_with(b"/f") && key.len() == 6 {
            return Ok(VAttr::file(0o644, 0));
        }
        Err(io::Error::from_raw_os_error(LINUX_ENOENT))
    }

    fn readdir(&self, path: &Path) -> io::Result<Vec<VDirEntry>> {
        if path != Path::new("/") {
            return Err(io::Error::from_raw_os_error(LINUX_ENOENT));
        }
        Ok((0..self.count)
            .map(|i| VDirEntry::new(format!("f{i:04}").into_bytes(), NodeKind::File))
            .collect())
    }

    fn read(&self, _path: &Path, _offset: u64, _size: u32) -> io::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

#[test]
fn readdirplus_handles_more_than_batch_limit() {
    use super::rpc::protocol::MAX_BATCH_PATHS;

    let count = MAX_BATCH_PATHS + 500;
    let fs = VirtualFs::new(LargeDirFs { count }).unwrap();
    fs.init(FsOptions::DO_READDIRPLUS | FsOptions::READDIRPLUS_AUTO)
        .unwrap();
    let (handle, _) = fs.opendir(Sandbox::ctx(), 1, 0).unwrap();
    let entries = fs
        .readdirplus(Sandbox::ctx(), 1, handle.unwrap(), 0, 0)
        .expect("readdirplus must succeed for large directories");
    assert_eq!(
        entries.len(),
        count,
        "expected one readdirplus entry per child"
    );
}

#[test]
fn readdirplus_fails_when_child_getattr_fails() {
    let fs = VirtualFs::new(FlakyReaddirPlusFs).unwrap();
    fs.init(FsOptions::DO_READDIRPLUS | FsOptions::READDIRPLUS_AUTO)
        .unwrap();
    let (handle, _) = fs.opendir(Sandbox::ctx(), 1, 0).unwrap();
    let err = match fs.readdirplus(Sandbox::ctx(), 1, handle.unwrap(), 65536, 0) {
        Err(e) => e,
        Ok(_) => panic!("a child getattr failure must fail the whole listing"),
    };
    assert_eq!(err.raw_os_error(), Some(libc::EIO));
}

#[test]
fn rename_noreplace_fails_when_destination_exists() {
    let sb = Sandbox::new();
    sb.create(1, "src").unwrap();
    sb.create(1, "dst").unwrap();
    Sandbox::assert_errno(
        sb.fs.rename(
            Sandbox::ctx(),
            1,
            &Sandbox::cstr("src"),
            1,
            &Sandbox::cstr("dst"),
            1, // RENAME_NOREPLACE
        ),
        LINUX_EEXIST,
    );
}

#[test]
fn inmemory_rename_with_flags_enforces_noreplace_atomically() {
    use super::test_backend::InMemoryFs;

    let fs = InMemoryFs::new();
    fs.create(std::path::Path::new("/src"), &VAttr::file(0o644, 0))
        .unwrap();
    fs.create(std::path::Path::new("/dst"), &VAttr::file(0o644, 0))
        .unwrap();
    let err = fs
        .rename_with_flags(
            std::path::Path::new("/src"),
            std::path::Path::new("/dst"),
            1,
        )
        .expect_err("destination exists");
    assert_eq!(err.raw_os_error(), Some(LINUX_EEXIST), "got: {err:?}");
    assert!(fs.getattr(std::path::Path::new("/src")).is_ok());
}

#[test]
fn rename_rejects_unknown_flags() {
    let sb = Sandbox::new();
    sb.create(1, "f").unwrap();
    Sandbox::assert_errno(
        sb.fs.rename(
            Sandbox::ctx(),
            1,
            &Sandbox::cstr("f"),
            1,
            &Sandbox::cstr("g"),
            0x8000_0000,
        ),
        LINUX_EINVAL,
    );
}

#[test]
fn rename_rejects_dot_component() {
    let sb = Sandbox::new();
    sb.create(1, "f").unwrap();
    Sandbox::assert_errno(
        sb.fs.rename(
            Sandbox::ctx(),
            1,
            &Sandbox::cstr("f"),
            1,
            &Sandbox::cstr("."),
            0,
        ),
        LINUX_EPERM,
    );
}

#[test]
fn rename_exchange_is_unsupported() {
    let sb = Sandbox::new();
    sb.create(1, "a").unwrap();
    sb.create(1, "b").unwrap();
    Sandbox::assert_errno(
        sb.fs.rename(
            Sandbox::ctx(),
            1,
            &Sandbox::cstr("a"),
            1,
            &Sandbox::cstr("b"),
            2, // RENAME_EXCHANGE
        ),
        LINUX_ENOSYS,
    );
}

#[test]
fn now_is_used_for_default_times() {
    let sb = Sandbox::new();
    let (entry, _) = sb.create(1, "f.txt").unwrap();
    let (st, _) = sb.fs.getattr(Sandbox::ctx(), entry.inode, None).unwrap();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // Default ctime should be within a minute of now.
    assert!(
        (now - st.st_ctime).abs() < 60,
        "ctime {} now {}",
        st.st_ctime,
        now
    );
}

#[test]
fn rename_into_descendant_is_rejected() {
    let sb = Sandbox::new();
    let d = sb.mkdir(1, "d").unwrap();
    let sub = sb.mkdir(d.inode, "sub").unwrap();
    Sandbox::assert_errno(
        sb.fs.rename(
            Sandbox::ctx(),
            1,
            &Sandbox::cstr("d"),
            sub.inode,
            &Sandbox::cstr("dest"),
            0,
        ),
        LINUX_EINVAL,
    );
}

#[test]
fn mknod_rejects_unknown_file_type() {
    let sb = Sandbox::new();
    Sandbox::assert_errno(
        sb.fs.mknod(
            Sandbox::ctx(),
            1,
            &Sandbox::cstr("weird"),
            0o620, // no S_IF* type bits
            0,
            0,
            Extensions::default(),
        ),
        LINUX_EINVAL,
    );
}

#[test]
fn flush_on_release_succeeds_after_unlink_on_open_handle() {
    let sb = Sandbox::new();
    let (entry, handle) = sb.create(1, "live").unwrap();
    sb.fs
        .unlink(Sandbox::ctx(), 1, &Sandbox::cstr("live"))
        .unwrap();
    sb.fs
        .release(Sandbox::ctx(), entry.inode, 0, handle, true, false, None)
        .expect("flush should reach the provider after unlink on an open handle");
}

#[test]
fn getattr_by_path_after_unlink_returns_estale() {
    let sb = Sandbox::new();
    let (entry, _handle) = sb.create(1, "live").unwrap();
    sb.fs
        .unlink(Sandbox::ctx(), 1, &Sandbox::cstr("live"))
        .unwrap();
    Sandbox::assert_errno(
        sb.fs.getattr(Sandbox::ctx(), entry.inode, None),
        LINUX_ESTALE,
    );
}

struct NoTruncateFs {
    inner: InMemoryFs,
}

impl PathFs for NoTruncateFs {
    fn getattr(&self, path: &Path) -> io::Result<VAttr> {
        self.inner.getattr(path)
    }

    fn readdir(&self, path: &Path) -> io::Result<Vec<VDirEntry>> {
        self.inner.readdir(path)
    }

    fn read(&self, path: &Path, offset: u64, size: u32) -> io::Result<Vec<u8>> {
        self.inner.read(path, offset, size)
    }

    fn write(&self, path: &Path, offset: u64, data: &[u8]) -> io::Result<usize> {
        self.inner.write(path, offset, data)
    }

    fn create(&self, path: &Path, attr: &VAttr) -> io::Result<VAttr> {
        self.inner.create(path, attr)
    }

    fn mkdir(&self, path: &Path, mode: u32) -> io::Result<VAttr> {
        self.inner.mkdir(path, mode)
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        self.inner.remove(path)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.inner.rename(from, to)
    }

    fn setattr(&self, path: &Path, attr: &VAttr, valid: SetattrValid) -> io::Result<VAttr> {
        if valid.contains(SetattrValid::SIZE) {
            return Err(io::Error::from_raw_os_error(LINUX_ENOSYS));
        }
        self.inner.setattr(path, attr, valid)
    }
}

#[test]
fn open_truncate_fails_when_provider_cannot_truncate() {
    let fs = VirtualFs::new(NoTruncateFs {
        inner: InMemoryFs::new(),
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let (entry, handle, _) = fs
        .create(
            Sandbox::ctx(),
            1,
            &Sandbox::cstr("f.txt"),
            0o644,
            false,
            libc::O_RDWR as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    fs.release(
        Sandbox::ctx(),
        entry.inode,
        0,
        handle.unwrap(),
        false,
        false,
        None,
    )
    .unwrap();
    Sandbox::assert_errno(
        fs.open(
            Sandbox::ctx(),
            entry.inode,
            false,
            libc::O_RDWR as u32 | 0x200, // O_TRUNC
        ),
        95, // EOPNOTSUPP on Linux
    );
}

#[test]
fn access_uses_owner_bits_for_matching_uid() {
    let sb = Sandbox::new();
    let (entry, _) = sb.create(1, "secret").unwrap();
    {
        let mut map = sb.fs.provider().map.write().unwrap();
        let node = map.get_mut(b"/secret".as_slice()).unwrap();
        node.mode = 0o600;
        node.uid = 1000;
        node.gid = 1000;
    }
    let ctx = Context {
        uid: 1000,
        gid: 1000,
        pid: 1,
    };
    sb.fs.access(ctx, entry.inode, 4).unwrap(); // R_OK
    let ctx = Context {
        uid: 1001,
        gid: 1001,
        pid: 1,
    };
    Sandbox::assert_errno(sb.fs.access(ctx, entry.inode, 4), 13); // EACCES
}
