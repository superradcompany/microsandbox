//! Isolated host-file filesystem backend.
//!
//! `SingleFileFs` presents a synthetic directory containing exactly one host
//! file. The selected file uses the platform passthrough implementation for
//! data and metadata operations, while this facade prevents the guest from
//! discovering or mutating any sibling names in the host directory.

use std::{
    ffi::{CStr, CString},
    io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use super::passthroughfs::{PassthroughConfig, PassthroughFs};
use crate::{
    Context, DirEntry, DynFileSystem, Entry, FsOptions, GetxattrReply, ListxattrReply, OpenOptions,
    SetattrValid, ZeroCopyReader, ZeroCopyWriter, stat64, statvfs64,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const ROOT_INODE: u64 = 1;
const ROOT_HANDLE: u64 = 0;

const DT_DIR: u32 = 4;
const DT_REG: u32 = 8;

const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFMT: u32 = 0o170000;

const LINUX_ENOENT: i32 = 2;
const LINUX_EBADF: i32 = 9;
const LINUX_EACCES: i32 = 13;
const LINUX_ENOTDIR: i32 = 20;
const LINUX_EISDIR: i32 = 21;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A virtio-fs backend exposing one host file beneath a synthetic root.
pub struct SingleFileFs {
    inner: PassthroughFs,
    inner_name: CString,
    guest_name: &'static [u8],
    file_inode: AtomicU64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SingleFileFs {
    /// Create an isolated view of `source` under `guest_name`.
    ///
    /// The source is canonicalized once so the passthrough backend is anchored
    /// to a real parent directory. The guest-facing namespace is synthetic and
    /// never exposes that parent or any of its other entries.
    pub fn new(
        source: PathBuf,
        guest_name: String,
        mut cfg: PassthroughConfig,
    ) -> io::Result<Self> {
        let source = std::fs::canonicalize(source)?;
        let metadata = std::fs::metadata(&source)?;
        if !metadata.is_file() {
            return Err(linux_error(LINUX_EISDIR));
        }

        let parent = source
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file has no parent"))?;
        let inner_name = source
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file has no name"))?
            .to_str()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "host filename is not valid UTF-8",
                )
            })?
            .to_string();

        if guest_name.is_empty()
            || guest_name == "."
            || guest_name == ".."
            || guest_name.contains('/')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "single-file guest name must be a normal path component",
            ));
        }

        cfg.root_dir = parent.to_path_buf();
        cfg.no_symlink_root = true;
        cfg.inject_init = false;
        cfg.quota_bytes = None;

        let inner_name = CString::new(inner_name).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "host filename contains NUL")
        })?;
        let inner = PassthroughFs::new_with_stat_probe(cfg, Some(&inner_name))?;
        let guest_name = CString::new(guest_name)
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "guest filename contains NUL")
            })?
            .into_bytes()
            .into_boxed_slice();

        Ok(Self {
            inner,
            inner_name,
            // The backend lives for the VM lifetime. A stable name lets both
            // vector and streaming readdir callbacks borrow it safely.
            guest_name: Box::leak(guest_name),
            file_inode: AtomicU64::new(0),
        })
    }

    fn lookup_file(&self, ctx: Context) -> io::Result<Entry> {
        let entry = self.inner.lookup(ctx, ROOT_INODE, &self.inner_name)?;
        if u32::from(entry.attr.st_mode) & S_IFMT != S_IFREG {
            return Err(linux_error(LINUX_ENOENT));
        }
        self.file_inode.store(entry.inode, Ordering::Release);
        Ok(entry)
    }

    fn require_file_inode(&self, inode: u64) -> io::Result<()> {
        if inode != 0 && self.file_inode.load(Ordering::Acquire) == inode {
            Ok(())
        } else {
            Err(linux_error(LINUX_ENOENT))
        }
    }

    fn root_entries(&self) -> Vec<DirEntry<'static>> {
        let file_inode = self.file_inode.load(Ordering::Acquire);
        vec![
            DirEntry {
                ino: ROOT_INODE,
                offset: 1,
                type_: DT_DIR,
                name: b".",
            },
            DirEntry {
                ino: ROOT_INODE,
                offset: 2,
                type_: DT_DIR,
                name: b"..",
            },
            DirEntry {
                ino: file_inode,
                offset: 3,
                type_: DT_REG,
                name: self.guest_name,
            },
        ]
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl DynFileSystem for SingleFileFs {
    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        self.inner.init(capable)
    }

    fn destroy(&self) {
        self.inner.destroy();
    }

    fn lookup(&self, ctx: Context, parent: u64, name: &CStr) -> io::Result<Entry> {
        if parent != ROOT_INODE {
            return Err(linux_error(LINUX_ENOTDIR));
        }
        if name.to_bytes() != self.guest_name {
            return Err(linux_error(LINUX_ENOENT));
        }
        self.lookup_file(ctx)
    }

    fn forget(&self, ctx: Context, inode: u64, count: u64) {
        if self.require_file_inode(inode).is_ok() {
            self.inner.forget(ctx, inode, count);
        }
    }

    fn getattr(
        &self,
        ctx: Context,
        inode: u64,
        handle: Option<u64>,
    ) -> io::Result<(stat64, Duration)> {
        if inode == ROOT_INODE {
            return Ok((root_stat(), Duration::from_secs(5)));
        }
        self.require_file_inode(inode)?;
        self.inner.getattr(ctx, inode, handle)
    }

    fn setattr(
        &self,
        ctx: Context,
        inode: u64,
        attr: stat64,
        handle: Option<u64>,
        valid: SetattrValid,
    ) -> io::Result<(stat64, Duration)> {
        self.require_file_inode(inode)?;
        self.inner.setattr(ctx, inode, attr, handle, valid)
    }

    fn open(
        &self,
        ctx: Context,
        inode: u64,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        if inode == ROOT_INODE {
            return Err(linux_error(LINUX_EISDIR));
        }
        self.require_file_inode(inode)?;
        self.inner.open(ctx, inode, kill_priv, flags)
    }

    fn read(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        writer: &mut dyn ZeroCopyWriter,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> io::Result<usize> {
        self.require_file_inode(inode)?;
        self.inner
            .read(ctx, inode, handle, writer, size, offset, lock_owner, flags)
    }

    fn write(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        reader: &mut dyn ZeroCopyReader,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        delayed_write: bool,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<usize> {
        self.require_file_inode(inode)?;
        self.inner.write(
            ctx,
            inode,
            handle,
            reader,
            size,
            offset,
            lock_owner,
            delayed_write,
            kill_priv,
            flags,
        )
    }

    fn flush(&self, ctx: Context, inode: u64, handle: u64, lock_owner: u64) -> io::Result<()> {
        self.require_file_inode(inode)?;
        self.inner.flush(ctx, inode, handle, lock_owner)
    }

    fn fsync(&self, ctx: Context, inode: u64, datasync: bool, handle: u64) -> io::Result<()> {
        self.require_file_inode(inode)?;
        self.inner.fsync(ctx, inode, datasync, handle)
    }

    fn fallocate(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        self.require_file_inode(inode)?;
        self.inner
            .fallocate(ctx, inode, handle, mode, offset, length)
    }

    fn release(
        &self,
        ctx: Context,
        inode: u64,
        flags: u32,
        handle: u64,
        flush: bool,
        flock_release: bool,
        lock_owner: Option<u64>,
    ) -> io::Result<()> {
        self.require_file_inode(inode)?;
        self.inner
            .release(ctx, inode, flags, handle, flush, flock_release, lock_owner)
    }

    fn statfs(&self, ctx: Context, _inode: u64) -> io::Result<statvfs64> {
        self.inner.statfs(ctx, ROOT_INODE)
    }

    fn setxattr(
        &self,
        ctx: Context,
        inode: u64,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        self.require_file_inode(inode)?;
        self.inner.setxattr(ctx, inode, name, value, flags)
    }

    fn getxattr(
        &self,
        ctx: Context,
        inode: u64,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        self.require_file_inode(inode)?;
        self.inner.getxattr(ctx, inode, name, size)
    }

    fn listxattr(&self, ctx: Context, inode: u64, size: u32) -> io::Result<ListxattrReply> {
        self.require_file_inode(inode)?;
        self.inner.listxattr(ctx, inode, size)
    }

    fn removexattr(&self, ctx: Context, inode: u64, name: &CStr) -> io::Result<()> {
        self.require_file_inode(inode)?;
        self.inner.removexattr(ctx, inode, name)
    }

    fn opendir(
        &self,
        _ctx: Context,
        inode: u64,
        _flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        if inode == ROOT_INODE {
            Ok((Some(ROOT_HANDLE), OpenOptions::empty()))
        } else {
            Err(linux_error(LINUX_ENOTDIR))
        }
    }

    fn readdir(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        _size: u32,
        offset: u64,
    ) -> io::Result<Vec<DirEntry<'static>>> {
        if inode != ROOT_INODE || handle != ROOT_HANDLE {
            return Err(linux_error(LINUX_EBADF));
        }
        if self.file_inode.load(Ordering::Acquire) == 0 {
            self.lookup_file(ctx)?;
        }
        Ok(self
            .root_entries()
            .into_iter()
            .skip(offset as usize)
            .collect())
    }

    fn readdirplus(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        _size: u32,
        offset: u64,
    ) -> io::Result<Vec<(DirEntry<'static>, Entry)>> {
        if inode != ROOT_INODE || handle != ROOT_HANDLE {
            return Err(linux_error(LINUX_EBADF));
        }
        let file_entry = self.lookup_file(ctx)?;
        let mut dir_entries = self.root_entries().into_iter();
        let entries = vec![
            (dir_entries.next().unwrap(), root_entry()),
            (dir_entries.next().unwrap(), root_entry()),
            (dir_entries.next().unwrap(), file_entry),
        ];
        Ok(entries.into_iter().skip(offset as usize).collect())
    }

    fn fsyncdir(&self, _ctx: Context, inode: u64, _datasync: bool, handle: u64) -> io::Result<()> {
        if inode == ROOT_INODE && handle == ROOT_HANDLE {
            Ok(())
        } else {
            Err(linux_error(LINUX_EBADF))
        }
    }

    fn releasedir(&self, _ctx: Context, inode: u64, _flags: u32, handle: u64) -> io::Result<()> {
        if inode == ROOT_INODE && handle == ROOT_HANDLE {
            Ok(())
        } else {
            Err(linux_error(LINUX_EBADF))
        }
    }

    fn access(&self, ctx: Context, inode: u64, mask: u32) -> io::Result<()> {
        if inode == ROOT_INODE {
            return if mask & 0o2 == 0 {
                Ok(())
            } else {
                Err(linux_error(LINUX_EACCES))
            };
        }
        self.require_file_inode(inode)?;
        self.inner.access(ctx, inode, mask)
    }

    fn lseek(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        self.require_file_inode(inode)?;
        self.inner.lseek(ctx, inode, handle, offset, whence)
    }

    fn copyfilerange(
        &self,
        ctx: Context,
        inode_in: u64,
        handle_in: u64,
        offset_in: u64,
        inode_out: u64,
        handle_out: u64,
        offset_out: u64,
        len: u64,
        flags: u64,
    ) -> io::Result<usize> {
        self.require_file_inode(inode_in)?;
        self.require_file_inode(inode_out)?;
        self.inner.copyfilerange(
            ctx, inode_in, handle_in, offset_in, inode_out, handle_out, offset_out, len, flags,
        )
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn root_entry() -> Entry {
    Entry {
        inode: ROOT_INODE,
        generation: 0,
        attr: root_stat(),
        attr_flags: 0,
        attr_timeout: Duration::from_secs(5),
        entry_timeout: Duration::from_secs(5),
    }
}

fn root_stat() -> stat64 {
    let mut stat: stat64 = unsafe { std::mem::zeroed() };
    stat.st_ino = ROOT_INODE;
    stat.st_mode = (S_IFDIR | 0o555) as _;
    stat.st_nlink = 2;
    stat.st_uid = 0;
    stat.st_gid = 0;
    stat.st_blksize = 4096;
    stat
}

fn linux_error(errno: i32) -> io::Error {
    io::Error::from_raw_os_error(errno)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom};
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;

    const LINUX_EROFS: i32 = 30;
    const LINUX_O_WRONLY: u32 = 1;

    struct CaptureWriter {
        bytes: Vec<u8>,
    }

    impl ZeroCopyWriter for CaptureWriter {
        fn write_from(
            &mut self,
            file: &std::fs::File,
            count: usize,
            offset: u64,
        ) -> io::Result<usize> {
            let mut file = file.try_clone()?;
            file.seek(SeekFrom::Start(offset))?;
            file.take(count as u64).read_to_end(&mut self.bytes)
        }
    }

    fn context() -> Context {
        Context {
            uid: 0,
            gid: 0,
            pid: 1,
        }
    }

    #[test]
    fn exposes_only_the_selected_readonly_file_without_hardlinking() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("selected.txt");
        std::fs::write(&source, b"initial").unwrap();
        std::fs::write(temp.path().join("sibling.txt"), b"secret").unwrap();

        #[cfg(unix)]
        let links_before = std::fs::metadata(&source).unwrap().nlink();
        let fs = SingleFileFs::new(
            source.clone(),
            "config.txt".to_string(),
            PassthroughConfig {
                readonly: true,
                ..Default::default()
            },
        )
        .unwrap();

        // A source mutation after construction remains visible, proving the
        // backend did not stage a copy. Read-only permissions also exercise
        // the same access pattern as foreign-owned system files.
        std::fs::write(&source, b"updated").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o444)).unwrap();
        fs.init(FsOptions::empty()).unwrap();

        let entry = fs.lookup(context(), ROOT_INODE, c"config.txt").unwrap();
        #[cfg(unix)]
        assert_eq!(std::fs::metadata(&source).unwrap().nlink(), links_before);
        let sibling_error = match fs.lookup(context(), ROOT_INODE, c"sibling.txt") {
            Ok(_) => panic!("a sibling name must not be guest-visible"),
            Err(error) => error,
        };
        assert_eq!(sibling_error.raw_os_error(), Some(LINUX_ENOENT));

        let (handle, _) = fs.open(context(), entry.inode, false, 0).unwrap();
        let handle = handle.unwrap();
        let mut writer = CaptureWriter { bytes: Vec::new() };
        fs.read(context(), entry.inode, handle, &mut writer, 64, 0, None, 0)
            .unwrap();
        fs.release(context(), entry.inode, 0, handle, false, false, None)
            .unwrap();
        assert_eq!(writer.bytes, b"updated");

        let write_error = fs
            .open(context(), entry.inode, false, LINUX_O_WRONLY)
            .unwrap_err();
        assert_eq!(write_error.raw_os_error(), Some(LINUX_EROFS));

        let (directory_handle, _) = fs.opendir(context(), ROOT_INODE, 0).unwrap();
        let entries = fs
            .readdir(context(), ROOT_INODE, directory_handle.unwrap(), 4096, 0)
            .unwrap();
        let names = entries.iter().map(|entry| entry.name).collect::<Vec<_>>();
        assert_eq!(names, vec![b".".as_slice(), b"..", b"config.txt"]);
    }

    #[test]
    fn rejects_directories_and_non_component_guest_names() {
        let temp = tempfile::tempdir().unwrap();
        assert!(
            SingleFileFs::new(
                temp.path().to_path_buf(),
                "config.txt".to_string(),
                PassthroughConfig::default(),
            )
            .is_err()
        );

        let source = temp.path().join("selected.txt");
        std::fs::write(&source, b"data").unwrap();
        for name in ["", ".", "..", "nested/config.txt"] {
            assert!(
                SingleFileFs::new(
                    source.clone(),
                    name.to_string(),
                    PassthroughConfig::default(),
                )
                .is_err()
            );
        }
    }
}
