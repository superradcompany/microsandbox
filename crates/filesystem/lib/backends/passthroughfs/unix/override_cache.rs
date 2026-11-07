//! Per-mount override cache. Bind mounts allow host writers; there is no enforced
//! single-writer contract here. Entries expire after five seconds (the default
//! guest attribute TTL), and a changed host ctime forces an earlier reread.
//! Guest SETXATTR/REMOVEXATTR reject the reserved override key; all internal
//! override writers publish through this cache. Namespace mutations clear it.
//! Errors are never cached. The cap also bounds mounts with long-lived inodes.

use std::{
    collections::{BTreeMap, HashMap},
    ffi::CStr,
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd, RawFd},
    sync::Mutex,
    time::{Duration, Instant},
};

use crate::{
    backends::shared::{
        platform,
        stat_override::{self, BindIdentityMapHandle, OverrideStat},
    },
    stat64,
};

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
}

impl CacheEntries {
    fn clear(&mut self) {
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
        self.entries.lock().unwrap().remove(&(dev, ino));
    }

    pub(crate) fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }

    fn read(&self, fd: RawFd, st: &stat64, strict: bool) -> io::Result<Option<OverrideStat>> {
        let mut entries = self.entries.lock().unwrap();
        let key = identity(st);
        if let Some(entry) = entries.values.get(&key)
            && entry.ctime == ctime(st)
            && entry.read_at.elapsed() < TTL
        {
            let value = entry.value;
            entries.touch(key);
            return Ok(value);
        }
        entries.remove(&key);
        let value = stat_override::get_override(fd, true, strict)?;
        Self::insert(&mut entries, st, value);
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
        // Serialize publication with reads so an in-flight miss cannot publish
        // an old value after a successful mutation.
        let mut entries = self.entries.lock().unwrap();
        stat_override::set_override(fd, uid, gid, mode, rdev)?;
        match platform::fstat(fd) {
            Ok(st) => Self::insert(
                &mut entries,
                &st,
                Some(OverrideStat {
                    version: 1,
                    _pad: [0; 3],
                    uid,
                    gid,
                    mode,
                    rdev,
                }),
            ),
            Err(_) => entries.clear(),
        }
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
    use super::*;

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
        let value = cache.read(-1, &st, true).unwrap().unwrap();
        assert_eq!(
            (value.uid, value.gid, value.mode),
            (1000, 2000, platform::MODE_REG | 0o640)
        );

        cache
            .set_override(fd, 3000, 4000, platform::MODE_REG | 0o600, 0)
            .unwrap();
        let st = platform::fstat(fd).unwrap();
        assert_eq!({ cache.read(-1, &st, true).unwrap().unwrap().uid }, 3000);
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
