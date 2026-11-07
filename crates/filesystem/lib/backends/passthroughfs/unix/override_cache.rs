//! Per-mount override cache. Bind mounts allow host writers; there is no enforced
//! single-writer contract here. Entries expire after five seconds (the default
//! guest attribute TTL), and a changed host ctime forces an earlier reread.
//! Guest SETXATTR/REMOVEXATTR reject the reserved override key; all internal
//! override writers invalidate through this cache. Namespace mutations clear it.
//! Errors are never cached. The cap also bounds mounts with long-lived inodes.

use std::{
    collections::{BTreeMap, HashMap},
    ffi::CStr,
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd, RawFd},
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};

use crate::{
    backends::shared::{
        platform,
        stat_override::{self, BindIdentityMapHandle, OverrideStat},
    },
    stat64,
};

// Deterministic syscall-boundary ordering for concurrent-writer regressions.
#[cfg(test)]
thread_local! {
    static AFTER_READ: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default();
    static BEFORE_INVALIDATE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default();
    static AFTER_WRITE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default();
}

const CAPACITY: usize = 16_384;
const TTL: Duration = Duration::from_secs(5);

type Identity = (u64, u64);

struct CachedOverride {
    value: Option<OverrideStat>,
    ctime: (i64, i64),
    read_at: Instant,
    used: u64,
}

#[derive(Default)]
pub(crate) struct OverrideCache {
    entries: Mutex<CacheEntries>,
}

#[derive(Default)]
struct CacheEntries {
    values: HashMap<Identity, CachedOverride>,
    recency: BTreeMap<u64, Identity>,
    clock: u64,
    generation: u64,
    in_flight: HashMap<Identity, Weak<Mutex<()>>>,
}

impl CacheEntries {
    fn clear(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.values.clear();
        self.recency.clear();
    }

    fn remove(&mut self, key: &Identity) {
        if let Some(old) = self.values.remove(key) {
            self.recency.remove(&old.used);
        }
    }

    fn touch(&mut self, key: Identity) {
        let entry = self.values.get_mut(&key).unwrap();
        self.recency.remove(&entry.used);
        self.clock += 1;
        entry.used = self.clock;
        self.recency.insert(entry.used, key);
    }
}

fn identity(st: &stat64) -> Identity {
    (platform::stat_dev(st), platform::stat_ino(st))
}

fn ctime(st: &stat64) -> (i64, i64) {
    (st.st_ctime, st.st_ctime_nsec)
}

impl OverrideCache {
    pub(crate) fn invalidate(&self, dev: u64, ino: u64) {
        let key = (dev, ino);
        #[cfg(test)]
        BEFORE_INVALIDATE.with(|hook| {
            if let Some(callback) = hook.borrow_mut().take() {
                callback();
            }
        });
        let guard = self.inode_guard(key);
        let _guard = guard.lock().unwrap();
        // Remove after all earlier readers finish, including readers that
        // started between FORGET's table mutation and this invalidation. Reads
        // crossing clear() still use its generation check before publishing.
        self.entries.lock().unwrap().remove(&key);
    }

    pub(crate) fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }

    fn inode_guard(&self, key: Identity) -> Arc<Mutex<()>> {
        let mut entries = self.entries.lock().unwrap();
        if let Some(guard) = entries.in_flight.get(&key).and_then(Weak::upgrade) {
            return guard;
        }
        // Bound idle guard bookkeeping without discarding a guard that still
        // has a reader, writer, or waiter. Never wait while holding the table.
        if entries.in_flight.len() >= CAPACITY {
            entries
                .in_flight
                .retain(|_, guard| guard.strong_count() > 0);
        }
        let guard = Arc::new(Mutex::new(()));
        entries.in_flight.insert(key, Arc::downgrade(&guard));
        guard
    }

    fn read(&self, fd: RawFd, st: &stat64, strict: bool) -> io::Result<Option<OverrideStat>> {
        let key = identity(st);
        let guard = self.inode_guard(key);
        let _guard = guard.lock().unwrap();
        let mut entries = self.entries.lock().unwrap();
        if let Some(entry) = entries.values.get(&key)
            && entry.ctime == ctime(st)
            && entry.read_at.elapsed() < TTL
        {
            let value = entry.value;
            entries.touch(key);
            return Ok(value);
        }
        entries.remove(&key);
        let generation = entries.generation;
        drop(entries);

        let value = stat_override::get_override(fd, true, strict)?;
        #[cfg(test)]
        AFTER_READ.with(|hook| {
            let callback = hook.borrow_mut().take();
            if let Some(callback) = callback {
                callback();
            }
        });
        let mut entries = self.entries.lock().unwrap();
        // clear() cannot wait for host I/O, but must invalidate reads already
        // in flight. Per-inode guards serialize reads with writes/invalidate.
        if generation == entries.generation {
            Self::insert(&mut entries, st, value);
        }
        Ok(value)
    }

    fn insert(entries: &mut CacheEntries, st: &stat64, value: Option<OverrideStat>) {
        let key = identity(st);
        entries.remove(&key);
        if entries.values.len() >= CAPACITY
            && let Some((_, oldest)) = entries.recency.pop_first()
        {
            entries.values.remove(&oldest);
        }
        entries.clock += 1;
        entries.recency.insert(entries.clock, key);
        entries.values.insert(
            identity(st),
            CachedOverride {
                value,
                ctime: ctime(st),
                read_at: Instant::now(),
                used: entries.clock,
            },
        );
    }

    pub(crate) fn patched_stat(
        &self,
        fd: RawFd,
        st: stat64,
        enabled: bool,
        strict: bool,
        map: Option<&BindIdentityMapHandle>,
    ) -> io::Result<stat64> {
        if !enabled {
            return stat_override::patched_stat(fd, st, false, strict, map);
        }
        #[cfg(target_os = "linux")]
        if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
            return stat_override::apply_override(st, None, map);
        }
        stat_override::apply_override(st, self.read(fd, &st, strict)?, map)
    }

    pub(crate) fn get_override(
        &self,
        fd: RawFd,
        enabled: bool,
        strict: bool,
    ) -> io::Result<Option<OverrideStat>> {
        if !enabled {
            return Ok(None);
        }
        self.read(fd, &platform::fstat(fd)?, strict)
    }

    pub(crate) fn set_override(
        &self,
        fd: RawFd,
        uid: u32,
        gid: u32,
        mode: u32,
        rdev: u32,
    ) -> io::Result<()> {
        let st = platform::fstat(fd)?;
        let key = identity(&st);
        let guard = self.inode_guard(key);
        let _guard = guard.lock().unwrap();
        self.entries.lock().unwrap().remove(&key);

        // Do not publish the supplied value under a later ctime: another mount
        // or host writer may have replaced the xattr before that stat. The next
        // read must obtain the actual backing value. Invalidate even on error.
        stat_override::set_override(fd, uid, gid, mode, rdev)?;
        #[cfg(test)]
        AFTER_WRITE.with(|hook| {
            let callback = hook.borrow_mut().take();
            if let Some(callback) = callback {
                callback();
            }
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn set_override_at(
        &self,
        dirfd: RawFd,
        name: &CStr,
        uid: u32,
        gid: u32,
        mode: u32,
        rdev: u32,
    ) -> io::Result<()> {
        let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        let mut fd = unsafe { libc::openat(dirfd, name.as_ptr(), flags) };
        if fd < 0 {
            fd = unsafe { libc::openat(dirfd, name.as_ptr(), flags | libc::O_DIRECTORY) };
        }
        if fd < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        self.set_override(file.as_raw_fd(), uid, gid, mode, rdev)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::super::{PassthroughConfig, PassthroughFs};
    use super::*;
    use crate::{Context, DynFileSystem, Extensions, FsOptions, SetattrValid};

    #[test]
    fn concurrent_backend_write_is_not_cached_as_our_value() {
        let root = tempfile::tempdir().unwrap();
        let backend = || {
            let fs = PassthroughFs::new(PassthroughConfig {
                root_dir: root.path().to_path_buf(),
                ..Default::default()
            })
            .unwrap();
            fs.init(FsOptions::empty()).unwrap();
            fs
        };
        let a = backend();
        let b = Arc::new(backend());
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 1,
        };
        let (entry, handle, _) = a
            .create(ctx, 1, c"data", 0o600, false, 2, 0, Extensions::default())
            .unwrap();
        let other = b.lookup(ctx, 1, c"data").unwrap();

        // B writes after A's setxattr, before A can read the resulting ctime.
        AFTER_WRITE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let mut attr: stat64 = unsafe { std::mem::zeroed() };
                attr.st_uid = 3000;
                attr.st_gid = 4000;
                b.setattr(
                    ctx,
                    other.inode,
                    attr,
                    None,
                    SetattrValid::UID | SetattrValid::GID,
                )
                .unwrap();
            }))
        });
        let handles = a.handles.read().unwrap();
        let file = handles[&handle.unwrap()].file.read().unwrap();
        a.override_cache
            .set_override(file.as_raw_fd(), 1000, 2000, platform::MODE_REG | 0o600, 0)
            .unwrap();
        drop(file);
        drop(handles);

        // A's partial chmod must preserve B's owner, including in the host xattr.
        let mut attr: stat64 = unsafe { std::mem::zeroed() };
        attr.st_mode = 0o640;
        a.setattr(ctx, entry.inode, attr, handle, SetattrValid::MODE)
            .unwrap();
        let file = File::open(root.path().join("data")).unwrap();
        let value = stat_override::get_override(file.as_raw_fd(), true, true)
            .unwrap()
            .unwrap();
        assert_eq!(
            (value.uid, value.gid, value.mode),
            (3000, 4000, platform::MODE_REG | 0o640)
        );
    }

    #[test]
    fn slow_inode_does_not_block_other_inodes_or_repopulate_after_clear() {
        let cache = OverrideCache::default();
        let slow = tempfile::tempfile().unwrap();
        let other = tempfile::tempfile().unwrap();
        let slow_st = platform::fstat(slow.as_raw_fd()).unwrap();
        let other_st = platform::fstat(other.as_raw_fd()).unwrap();
        cache.read(other.as_raw_fd(), &other_st, true).unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();

        std::thread::scope(|scope| {
            let cache = &cache;
            scope.spawn(move || {
                AFTER_READ.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        entered_tx.send(()).unwrap();
                        resume_rx.recv().unwrap();
                    }))
                });
                cache.read(slow.as_raw_fd(), &slow_st, true).unwrap();
            });
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            scope.spawn(move || {
                assert!(cache.read(-1, &other_st, true).unwrap().is_none());
                cache
                    .set_override(other.as_raw_fd(), 123, 456, platform::MODE_REG | 0o600, 0)
                    .unwrap();
                assert_eq!(
                    {
                        cache
                            .get_override(other.as_raw_fd(), true, true)
                            .unwrap()
                            .unwrap()
                            .uid
                    },
                    123
                );
                done_tx.send(()).unwrap();
            });

            let completed = done_rx.recv_timeout(Duration::from_secs(2));
            if completed.is_ok() {
                // A namespace clear must not be undone by the paused read.
                cache.clear();
            }
            resume_tx.send(()).unwrap();
            assert!(
                completed.is_ok(),
                "unrelated inode blocked behind a slow xattr read"
            );
        });
        assert!(
            cache.read(-1, &slow_st, true).is_err(),
            "in-flight read repopulated after clear"
        );
    }

    #[test]
    fn forget_during_xattr_does_not_block_unrelated_inode() {
        for batch in [true, false] {
            let root = tempfile::tempdir().unwrap();
            let fs = PassthroughFs::new(PassthroughConfig {
                root_dir: root.path().to_path_buf(),
                ..Default::default()
            })
            .unwrap();
            fs.init(FsOptions::empty()).unwrap();
            let ctx = Context {
                uid: 0,
                gid: 0,
                pid: 1,
            };
            let (slow, handle, _) = fs
                .create(ctx, 1, c"slow", 0o600, false, 2, 0, Extensions::default())
                .unwrap();
            let (other, _, _) = fs
                .create(ctx, 1, c"other", 0o600, false, 2, 0, Extensions::default())
                .unwrap();
            fs.override_cache.clear();
            let file = File::open(root.path().join("slow")).unwrap();
            let st = platform::fstat(file.as_raw_fd()).unwrap();
            let (entered_tx, entered_rx) = mpsc::channel();
            let (resume_tx, resume_rx) = mpsc::channel();
            let (forget_tx, forget_rx) = mpsc::channel();
            let (done_tx, done_rx) = mpsc::channel();

            std::thread::scope(|scope| {
                let fs = &fs;
                scope.spawn(move || {
                    AFTER_READ.with(|hook| {
                        *hook.borrow_mut() = Some(Box::new(move || {
                            entered_tx.send(()).unwrap();
                            resume_rx.recv().unwrap();
                        }));
                    });
                    fs.getattr(ctx, slow.inode, handle).unwrap();
                });
                entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                scope.spawn(move || {
                    BEFORE_INVALIDATE.with(|hook| {
                        *hook.borrow_mut() = Some(Box::new(move || {
                            forget_tx.send(()).unwrap();
                        }));
                    });
                    if batch {
                        fs.batch_forget(ctx, vec![(slow.inode, 1)]);
                    } else {
                        fs.forget(ctx, slow.inode, 1);
                    }
                });
                forget_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                scope.spawn(move || {
                    // Handleless GETATTR must consult the mount-wide inode table.
                    fs.getattr(ctx, other.inode, None).unwrap();
                    done_tx.send(()).unwrap();
                });
                let completed = done_rx.recv_timeout(Duration::from_secs(2));
                // Always unblock the worker, including when testing the broken code.
                resume_tx.send(()).unwrap();
                assert!(
                    completed.is_ok(),
                    "batch={batch}: FORGET blocked unrelated GETATTR"
                );
            });

            assert!(
                fs.override_cache.read(-1, &st, true).is_err(),
                "in-flight read repopulated the forgotten identity"
            );
        }
    }

    #[test]
    fn caches_absence_mutations_and_invalidates_without_hiding_errors() {
        let cache = OverrideCache::default();
        let file = tempfile::tempfile().unwrap();
        let fd = file.as_raw_fd();
        let st = platform::fstat(fd).unwrap();

        assert!(cache.read(fd, &st, true).unwrap().is_none());
        // An unusable fd proves a hit (including absence) performs no xattr I/O.
        assert!(cache.read(-1, &st, true).unwrap().is_none());
        cache.invalidate(platform::stat_dev(&st), platform::stat_ino(&st));
        assert!(cache.read(-1, &st, true).is_err());
        assert!(cache.read(fd, &st, true).unwrap().is_none());
        cache.clear();
        assert!(cache.read(-1, &st, true).is_err());

        cache
            .set_override(fd, 1000, 2000, platform::MODE_REG | 0o640, 0)
            .unwrap();
        let st = platform::fstat(fd).unwrap();
        let value = cache.read(fd, &st, true).unwrap().unwrap();
        assert_eq!(
            (value.uid, value.gid, value.mode),
            (1000, 2000, platform::MODE_REG | 0o640)
        );

        cache
            .set_override(fd, 3000, 4000, platform::MODE_REG | 0o600, 0)
            .unwrap();
        let st = platform::fstat(fd).unwrap();
        assert!(cache.read(-1, &st, true).is_err());
        assert_eq!({ cache.read(fd, &st, true).unwrap().unwrap().uid }, 3000);
        cache
            .entries
            .lock()
            .unwrap()
            .values
            .get_mut(&identity(&st))
            .unwrap()
            .read_at -= TTL;
        assert!(cache.read(-1, &st, true).is_err());
        assert_eq!({ cache.read(fd, &st, true).unwrap().unwrap().uid }, 3000);

        let mut changed = st;
        changed.st_ctime_nsec += 1;
        assert!(cache.read(-1, &changed, true).is_err());
        // Errors must not become cached absence or retain the previous value.
        assert!(cache.read(-1, &changed, true).is_err());
    }

    #[test]
    fn evicts_least_recently_used_without_extending_freshness() {
        let mut entries = CacheEntries::default();
        let mut st: stat64 = unsafe { std::mem::zeroed() };
        for ino in 0..CAPACITY {
            st.st_ino = ino as _;
            OverrideCache::insert(&mut entries, &st, None);
        }
        let key = (0, 0);
        let read_at = entries.values[&key].read_at;
        entries.touch(key);
        st.st_ino = CAPACITY as _;
        OverrideCache::insert(&mut entries, &st, None);

        assert_eq!(entries.values.len(), CAPACITY);
        assert_eq!(entries.recency.len(), CAPACITY);
        assert!(entries.values.contains_key(&key));
        assert!(!entries.values.contains_key(&(0, 1)));
        assert_eq!(entries.values[&key].read_at, read_at);
    }
}
