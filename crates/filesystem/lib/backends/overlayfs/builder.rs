//! Builder API for constructing an OverlayFs instance.
//!
//! ```ignore
//! OverlayFs::builder()
//!     .layer(lower0)
//!     .layer(lower1)
//!     .writable(upper)
//!     .work_dir(work)
//!     .build()?
//! ```

use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::RwLock;
use std::time::Duration;

use super::OverlayFs;
use super::types::{CachePolicy, Layer, NameTable, OverlayConfig};
use crate::backends::shared::{init_binary, platform, stat_override};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Builder for constructing an [`OverlayFs`] instance.
pub struct OverlayFsBuilder {
    lowers: Vec<PathBuf>,
    upper_dir: Option<PathBuf>,
    work_dir: Option<PathBuf>,
    strict: bool,
    entry_timeout: Duration,
    attr_timeout: Duration,
    cache_policy: CachePolicy,
    writeback: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl OverlayFsBuilder {
    /// Create a new builder with default settings.
    pub(crate) fn new() -> Self {
        Self {
            lowers: Vec::new(),
            upper_dir: None,
            work_dir: None,
            strict: true,
            entry_timeout: Duration::from_secs(5),
            attr_timeout: Duration::from_secs(5),
            cache_policy: CachePolicy::Auto,
            writeback: false,
        }
    }

    /// Add a lower layer (call repeatedly, bottom-to-top order).
    pub fn layer(mut self, path: impl Into<PathBuf>) -> Self {
        self.lowers.push(path.into());
        self
    }

    /// Add multiple lower layers at once (bottom-to-top order).
    pub fn layers(mut self, paths: impl IntoIterator<Item = impl Into<PathBuf>>) -> Self {
        self.lowers.extend(paths.into_iter().map(Into::into));
        self
    }

    /// Set the upper writable layer directory.
    pub fn writable(mut self, path: impl Into<PathBuf>) -> Self {
        self.upper_dir = Some(path.into());
        self
    }

    /// Set the private staging directory (must be on same filesystem as upper).
    pub fn work_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.work_dir = Some(path.into());
        self
    }

    /// Enable or disable strict mode.
    pub fn strict(mut self, enabled: bool) -> Self {
        self.strict = enabled;
        self
    }

    /// Set the FUSE entry cache timeout.
    pub fn entry_timeout(mut self, timeout: Duration) -> Self {
        self.entry_timeout = timeout;
        self
    }

    /// Set the FUSE attribute cache timeout.
    pub fn attr_timeout(mut self, timeout: Duration) -> Self {
        self.attr_timeout = timeout;
        self
    }

    /// Set the cache policy.
    pub fn cache_policy(mut self, policy: CachePolicy) -> Self {
        self.cache_policy = policy;
        self
    }

    /// Enable or disable writeback caching.
    pub fn writeback(mut self, enabled: bool) -> Self {
        self.writeback = enabled;
        self
    }

    /// Build the OverlayFs instance.
    pub fn build(self) -> io::Result<OverlayFs> {
        let upper_dir = self.upper_dir.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "upper directory not set")
        })?;
        let work_dir = self.work_dir.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "work directory not set")
        })?;

        if self.lowers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one lower layer is required",
            ));
        }

        // Probe platform capabilities once.
        #[cfg(target_os = "linux")]
        let has_openat2 = platform::probe_openat2();

        #[cfg(target_os = "linux")]
        let proc_self_fd_main = {
            let path = std::ffi::CString::new("/proc/self/fd").unwrap();
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            if fd < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
            unsafe { File::from_raw_fd(fd) }
        };

        // Open lower layers.
        let mut lowers = Vec::with_capacity(self.lowers.len());
        for (index, lower_path) in self.lowers.iter().enumerate() {
            let root_fd = open_dir(lower_path)?;

            #[cfg(target_os = "linux")]
            let layer_proc_fd = dup_fd(&proc_self_fd_main)?;

            lowers.push(Layer {
                root_fd,
                index,
                #[cfg(target_os = "linux")]
                proc_self_fd: layer_proc_fd,
                #[cfg(target_os = "linux")]
                has_openat2,
            });
        }

        // Open upper layer.
        let upper_index = self.lowers.len();
        let upper_root_fd = open_dir(&upper_dir)?;

        // Probe xattr support on upper if strict mode.
        if self.strict {
            use std::os::fd::AsRawFd;
            let supported = stat_override::probe_xattr_support(upper_root_fd.as_raw_fd())?;
            if !supported {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "xattr not supported on upper filesystem and strict mode is enabled",
                ));
            }
        }

        #[cfg(target_os = "linux")]
        let upper_proc_fd = dup_fd(&proc_self_fd_main)?;

        let upper = Layer {
            root_fd: upper_root_fd,
            index: upper_index,
            #[cfg(target_os = "linux")]
            proc_self_fd: upper_proc_fd,
            #[cfg(target_os = "linux")]
            has_openat2,
        };

        // Open work directory.
        let work_fd = open_dir(&work_dir)?;

        // Verify work_dir is on same filesystem as upper_dir.
        {
            use std::os::fd::AsRawFd;
            let upper_st = platform::fstat(upper.root_fd.as_raw_fd())?;
            let work_st = platform::fstat(work_fd.as_raw_fd())?;
            if upper_st.st_dev != work_st.st_dev {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "work_dir must be on the same filesystem as upper_dir",
                ));
            }
        }

        // Clean leftover temp files in work_dir.
        clean_work_dir(&work_fd)?;

        // Create init binary file.
        let init_file = init_binary::create_init_file()?;

        let cfg = OverlayConfig {
            entry_timeout: self.entry_timeout,
            attr_timeout: self.attr_timeout,
            cache_policy: self.cache_policy,
            writeback: self.writeback,
        };

        Ok(OverlayFs {
            lowers,
            upper,
            work_fd,
            nodes: RwLock::new(BTreeMap::new()),
            dentries: RwLock::new(BTreeMap::new()),
            upper_alt_keys: RwLock::new(BTreeMap::new()),
            lower_origin_keys: RwLock::new(BTreeMap::new()),
            origin_index: RwLock::new(BTreeMap::new()),
            next_inode: AtomicU64::new(3), // 1=root, 2=init
            file_handles: RwLock::new(BTreeMap::new()),
            dir_handles: RwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1), // 0=init handle
            writeback: AtomicBool::new(false),
            init_file,
            names: NameTable::new(),
            cfg,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open a directory path as an fd.
fn open_dir(path: &std::path::Path) -> io::Result<File> {
    let cpath = std::ffi::CString::new(
        path.to_str()
            .ok_or_else(platform::einval)?
            .as_bytes(),
    )
    .map_err(|_| platform::einval())?;

    let fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY,
        )
    };
    if fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Duplicate a file descriptor with CLOEXEC.
#[cfg(target_os = "linux")]
fn dup_fd(f: &File) -> io::Result<File> {
    use std::os::fd::AsRawFd;
    let fd = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Clean leftover temp files in work_dir from prior crashes.
fn clean_work_dir(work_fd: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let dup_fd = unsafe { libc::fcntl(work_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if dup_fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    let dirp = unsafe { libc::fdopendir(dup_fd) };
    if dirp.is_null() {
        unsafe { libc::close(dup_fd) };
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    loop {
        #[cfg(target_os = "linux")]
        unsafe {
            *libc::__errno_location() = 0;
        }
        #[cfg(target_os = "macos")]
        unsafe {
            *libc::__error() = 0;
        }

        let ent = unsafe { libc::readdir(dirp) };
        if ent.is_null() {
            // Check errno — readdir returns NULL on both end-of-directory and error.
            #[cfg(target_os = "linux")]
            let errno = unsafe { *libc::__errno_location() };
            #[cfg(target_os = "macos")]
            let errno = unsafe { *libc::__error() };
            if errno != 0 {
                unsafe { libc::closedir(dirp) };
                return Err(platform::linux_error(io::Error::from_raw_os_error(errno)));
            }
            break;
        }

        let d = unsafe { &*ent };
        let name = unsafe { std::ffi::CStr::from_ptr(d.d_name.as_ptr()) };
        let name_bytes = name.to_bytes();

        // Remove files starting with ".tmp." — our temp file prefix.
        if name_bytes.starts_with(b".tmp.") {
            let ret = unsafe { libc::unlinkat(work_fd.as_raw_fd(), name.as_ptr(), 0) };
            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ENOENT) {
                    unsafe { libc::closedir(dirp) };
                    return Err(platform::linux_error(err));
                }
            }
        }
    }

    unsafe { libc::closedir(dirp) };
    Ok(())
}
