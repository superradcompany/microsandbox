use std::{
    collections::BTreeMap,
    ffi::CStr,
    fs::File,
    io::{self, Write},
    sync::Mutex,
    time::Duration,
};

use microsandbox_filesystem::agentd::AGENTD_BYTES;
use msb_krun::backends::fs::{
    Context, DirEntry, DynFileSystem, Entry, FsOptions, OpenOptions, ZeroCopyWriter, stat64,
    statvfs64,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const ROOT_INODE: u64 = 1;
const INIT_INODE: u64 = 2;
const INIT_HANDLE: u64 = 0;

const INIT_NAME: &[u8] = b"init.krun";

const DT_DIR: u32 = 4;
const DT_REG: u32 = 8;

const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;

const LINUX_EBADF: i32 = 9;
const LINUX_EACCES: i32 = 13;
const LINUX_EEXIST: i32 = 17;
const LINUX_ENOENT: i32 = 2;
const LINUX_ENOTDIR: i32 = 20;
const LINUX_EISDIR: i32 = 21;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(crate) struct AgentBootstrapFs {
    init_file: Mutex<File>,
    dirs: Mutex<DirState>,
}

#[derive(Default)]
struct DirState {
    next_inode: u64,
    nodes: BTreeMap<u64, DirNode>,
    children: BTreeMap<(u64, Vec<u8>), u64>,
}

struct DirNode {
    parent: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AgentBootstrapFs {
    pub(crate) fn new() -> io::Result<Self> {
        let mut init_file = tempfile::tempfile()?;
        init_file.write_all(AGENTD_BYTES)?;
        init_file.sync_data()?;

        Ok(Self {
            init_file: Mutex::new(init_file),
            dirs: Mutex::new(DirState::new()),
        })
    }
}

impl DirState {
    fn new() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(ROOT_INODE, DirNode { parent: ROOT_INODE });

        Self {
            next_inode: INIT_INODE + 1,
            nodes,
            children: BTreeMap::new(),
        }
    }

    fn lookup(&self, parent: u64, name: &[u8]) -> io::Result<u64> {
        if !self.nodes.contains_key(&parent) {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        self.children
            .get(&(parent, name.to_vec()))
            .copied()
            .ok_or_else(|| linux_error(LINUX_ENOENT))
    }

    fn mkdir(&mut self, parent: u64, name: &[u8]) -> io::Result<Entry> {
        if !self.nodes.contains_key(&parent) {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        if name.is_empty() || name == b"." || name == b".." {
            return Err(linux_error(LINUX_EACCES));
        }

        let key = (parent, name.to_vec());
        if self.children.contains_key(&key) {
            return Err(linux_error(LINUX_EEXIST));
        }

        let inode = self.next_inode;
        self.next_inode += 1;
        self.nodes.insert(inode, DirNode { parent });
        self.children.insert(key, inode);
        Ok(dir_entry(inode))
    }

    fn contains_dir(&self, inode: u64) -> bool {
        self.nodes.contains_key(&inode)
    }

    fn parent(&self, inode: u64) -> Option<u64> {
        self.nodes.get(&inode).map(|node| node.parent)
    }

    fn child_entries(&self, inode: u64) -> io::Result<Vec<(u64, Vec<u8>)>> {
        if !self.nodes.contains_key(&inode) {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        Ok(self
            .children
            .iter()
            .filter(|((parent, _), _)| *parent == inode)
            .map(|((_, name), child)| (*child, name.clone()))
            .collect())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl DynFileSystem for AgentBootstrapFs {
    fn init(&self, _capable: FsOptions) -> io::Result<FsOptions> {
        Ok(FsOptions::empty())
    }

    fn lookup(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<Entry> {
        if parent == ROOT_INODE && name.to_bytes() == INIT_NAME {
            return Ok(init_entry());
        }

        let dirs = self.dirs.lock().unwrap();
        let inode = dirs.lookup(parent, name.to_bytes())?;
        Ok(dir_entry(inode))
    }

    fn getattr(
        &self,
        _ctx: Context,
        inode: u64,
        _handle: Option<u64>,
    ) -> io::Result<(stat64, Duration)> {
        match inode {
            ROOT_INODE => Ok((dir_stat(ROOT_INODE), attr_timeout())),
            INIT_INODE => Ok((init_stat(), attr_timeout())),
            _ if self.dirs.lock().unwrap().contains_dir(inode) => {
                Ok((dir_stat(inode), attr_timeout()))
            }
            _ => Err(linux_error(LINUX_ENOENT)),
        }
    }

    fn mkdir(
        &self,
        _ctx: Context,
        parent: u64,
        name: &CStr,
        _mode: u32,
        _umask: u32,
        _extensions: msb_krun::backends::fs::Extensions,
    ) -> io::Result<Entry> {
        self.dirs.lock().unwrap().mkdir(parent, name.to_bytes())
    }

    fn open(
        &self,
        _ctx: Context,
        inode: u64,
        _kill_priv: bool,
        _flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        match inode {
            INIT_INODE => Ok((Some(INIT_HANDLE), OpenOptions::empty())),
            ROOT_INODE => Err(linux_error(LINUX_EISDIR)),
            _ => Err(linux_error(LINUX_ENOENT)),
        }
    }

    fn read(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        w: &mut dyn ZeroCopyWriter,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        if inode != INIT_INODE || handle != INIT_HANDLE {
            return Err(linux_error(LINUX_EBADF));
        }

        let data_len = AGENTD_BYTES.len() as u64;
        if offset >= data_len {
            return Ok(0);
        }

        let count = std::cmp::min(size as u64, data_len - offset) as usize;
        let init_file = self.init_file.lock().unwrap();
        w.write_from(&init_file, count, offset)
    }

    fn release(
        &self,
        _ctx: Context,
        inode: u64,
        _flags: u32,
        handle: u64,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        if inode == INIT_INODE && handle == INIT_HANDLE {
            Ok(())
        } else {
            Err(linux_error(LINUX_EBADF))
        }
    }

    fn flush(&self, _ctx: Context, inode: u64, handle: u64, _lock_owner: u64) -> io::Result<()> {
        if inode == INIT_INODE && handle == INIT_HANDLE {
            Ok(())
        } else {
            Err(linux_error(LINUX_EBADF))
        }
    }

    fn fsync(&self, _ctx: Context, inode: u64, _datasync: bool, handle: u64) -> io::Result<()> {
        if inode == INIT_INODE && handle == INIT_HANDLE {
            Ok(())
        } else {
            Err(linux_error(LINUX_EBADF))
        }
    }

    fn opendir(
        &self,
        _ctx: Context,
        inode: u64,
        _flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        if inode == INIT_INODE {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        if self.dirs.lock().unwrap().contains_dir(inode) {
            Ok((Some(inode), OpenOptions::empty()))
        } else {
            Err(linux_error(LINUX_ENOENT))
        }
    }

    fn readdir(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        _size: u32,
        offset: u64,
    ) -> io::Result<Vec<DirEntry<'static>>> {
        if inode != handle {
            return Err(linux_error(LINUX_EBADF));
        }

        Ok(self
            .dir_entries(inode)?
            .into_iter()
            .skip(offset as usize)
            .collect())
    }

    fn readdirplus(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        _size: u32,
        offset: u64,
    ) -> io::Result<Vec<(DirEntry<'static>, Entry)>> {
        if inode != handle {
            return Err(linux_error(LINUX_EBADF));
        }

        Ok(self
            .dir_entries(inode)?
            .into_iter()
            .map(|dir_entry| {
                let entry = if dir_entry.ino == INIT_INODE {
                    init_entry()
                } else {
                    dir_entry_for_ino(dir_entry.ino)
                };
                (dir_entry, entry)
            })
            .skip(offset as usize)
            .collect())
    }

    fn releasedir(&self, _ctx: Context, inode: u64, _flags: u32, handle: u64) -> io::Result<()> {
        if inode == handle && self.dirs.lock().unwrap().contains_dir(inode) {
            Ok(())
        } else {
            Err(linux_error(LINUX_EBADF))
        }
    }

    fn access(&self, _ctx: Context, inode: u64, _mask: u32) -> io::Result<()> {
        if inode == INIT_INODE || self.dirs.lock().unwrap().contains_dir(inode) {
            Ok(())
        } else {
            Err(linux_error(LINUX_ENOENT))
        }
    }

    fn write(
        &self,
        _ctx: Context,
        inode: u64,
        _handle: u64,
        _r: &mut dyn msb_krun::backends::fs::ZeroCopyReader,
        _size: u32,
        _offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        _kill_priv: bool,
        _flags: u32,
    ) -> io::Result<usize> {
        if inode == INIT_INODE {
            Err(linux_error(LINUX_EACCES))
        } else {
            Err(linux_error(LINUX_EBADF))
        }
    }

    fn statfs(&self, _ctx: Context, _inode: u64) -> io::Result<statvfs64> {
        #[cfg(windows)]
        let stat = statvfs64 {
            f_bsize: 4096,
            f_frsize: 4096,
            f_blocks: 1,
            f_bfree: 0,
            f_bavail: 0,
            f_files: 2,
            f_ffree: 0,
            f_namemax: 255,
        };

        #[cfg(not(windows))]
        let stat = statvfs64 {
            f_bsize: 4096,
            f_frsize: 4096,
            f_blocks: 1,
            f_bfree: 0,
            f_bavail: 0,
            f_files: 2,
            f_ffree: 0,
            f_namemax: 255,
            ..Default::default()
        };

        Ok(stat)
    }
}

impl AgentBootstrapFs {
    fn dir_entries(&self, inode: u64) -> io::Result<Vec<DirEntry<'static>>> {
        let dirs = self.dirs.lock().unwrap();
        let parent = dirs
            .parent(inode)
            .ok_or_else(|| linux_error(LINUX_ENOTDIR))?;
        let mut entries = vec![
            DirEntry {
                ino: inode,
                offset: 1,
                type_: DT_DIR,
                name: b".",
            },
            DirEntry {
                ino: parent,
                offset: 2,
                type_: DT_DIR,
                name: b"..",
            },
        ];

        if inode == ROOT_INODE {
            entries.push(DirEntry {
                ino: INIT_INODE,
                offset: entries.len() as u64 + 1,
                type_: DT_REG,
                name: INIT_NAME,
            });
        }

        for (child, name) in dirs.child_entries(inode)? {
            entries.push(DirEntry {
                ino: child,
                offset: entries.len() as u64 + 1,
                type_: DT_DIR,
                name: Box::leak(name.into_boxed_slice()),
            });
        }

        Ok(entries)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn dir_entry_for_ino(inode: u64) -> Entry {
    Entry {
        inode,
        generation: 0,
        attr: dir_stat(inode),
        attr_flags: 0,
        attr_timeout: attr_timeout(),
        entry_timeout: entry_timeout(),
    }
}

fn dir_entry(inode: u64) -> Entry {
    dir_entry_for_ino(inode)
}

fn init_entry() -> Entry {
    Entry {
        inode: INIT_INODE,
        generation: 0,
        attr: init_stat(),
        attr_flags: 0,
        attr_timeout: attr_timeout(),
        entry_timeout: entry_timeout(),
    }
}

fn dir_stat(inode: u64) -> stat64 {
    stat64 {
        st_ino: inode,
        st_mode: S_IFDIR | 0o755,
        st_nlink: 2,
        st_uid: 0,
        st_gid: 0,
        st_blksize: 4096,
        ..Default::default()
    }
}

fn init_stat() -> stat64 {
    stat64 {
        st_ino: INIT_INODE,
        st_size: AGENTD_BYTES.len() as i64,
        st_blocks: blocks_for_size(AGENTD_BYTES.len() as u64),
        st_mode: S_IFREG | 0o755,
        st_nlink: 1,
        st_uid: 0,
        st_gid: 0,
        st_blksize: 4096,
        ..Default::default()
    }
}

fn blocks_for_size(size: u64) -> i64 {
    size.div_ceil(512).try_into().unwrap_or(i64::MAX)
}

fn entry_timeout() -> Duration {
    Duration::from_secs(5)
}

fn attr_timeout() -> Duration {
    Duration::from_secs(5)
}

fn linux_error(errno: i32) -> io::Error {
    io::Error::from_raw_os_error(errno)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::os::windows::fs::FileExt;

    use super::*;

    struct VecWriter(Vec<u8>);

    impl ZeroCopyWriter for VecWriter {
        fn write_from(&mut self, file: &File, count: usize, offset: u64) -> io::Result<usize> {
            let mut buffer = vec![0; count];
            let read = file.seek_read(&mut buffer, offset)?;
            self.0.extend_from_slice(&buffer[..read]);
            Ok(read)
        }
    }

    fn context() -> Context {
        Context {
            uid: 0,
            gid: 0,
            pid: 0,
        }
    }

    #[test]
    fn reads_embedded_agentd_from_init_inode() {
        let fs = AgentBootstrapFs::new().unwrap();
        let name = c"init.krun";
        let entry = fs.lookup(context(), ROOT_INODE, name).unwrap();
        assert_eq!(entry.inode, INIT_INODE);
        assert_eq!(entry.attr.st_size, AGENTD_BYTES.len() as i64);

        let (handle, _) = fs.open(context(), INIT_INODE, false, 0).unwrap();
        let mut writer = VecWriter(Vec::new());
        let read = fs
            .read(
                context(),
                INIT_INODE,
                handle.unwrap(),
                &mut writer,
                4,
                0,
                None,
                0,
            )
            .unwrap();

        assert_eq!(read, 4);
        assert_eq!(writer.0, &AGENTD_BYTES[..4]);
    }
}
