//! Builder API for constructing an OverlayFs instance.
//!
//! ```ignore
//! // Read-write mode:
//! OverlayFs::builder()
//!     .layer(lower0)
//!     .layer(lower1)
//!     .writable(upper)
//!     .staging(staging)
//!     .build()?
//!
//! // Read-only mode:
//! OverlayFs::builder()
//!     .layer(lower0)
//!     .layer(lower1)
//!     .read_only()
//!     .build()?
//! ```

use std::{
    collections::BTreeMap,
    fs::File,
    io,
    os::fd::FromRawFd,
    path::PathBuf,
    sync::{
        RwLock,
        atomic::{AtomicBool, AtomicU64},
    },
    time::Duration,
};

use super::{
    OverlayFs,
    types::{CachePolicy, Layer, NameTable, OverlayConfig},
};
use crate::backends::shared::{init_binary, platform, stat_override};
use microsandbox_utils::index::MmapIndex;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Builder for constructing an [`OverlayFs`] instance.
pub struct OverlayFsBuilder {
    lowers: Vec<PathBuf>,
    lower_indexes: Vec<Option<PathBuf>>,
    upper_dir: Option<PathBuf>,
    staging_dir: Option<PathBuf>,
    read_only: bool,
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
            lower_indexes: Vec::new(),
            upper_dir: None,
            staging_dir: None,
            read_only: false,
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
        self.lower_indexes.push(None);
        self
    }

    /// Add a lower layer with a sidecar index for accelerated lookups.
    ///
    /// If the index file is missing or corrupt at `build()` time, the layer
    /// falls back to live syscalls (graceful degradation).
    pub fn layer_with_index(
        mut self,
        path: impl Into<PathBuf>,
        index_path: impl Into<PathBuf>,
    ) -> Self {
        self.lowers.push(path.into());
        self.lower_indexes.push(Some(index_path.into()));
        self
    }

    /// Add multiple lower layers at once (bottom-to-top order).
    pub fn layers(mut self, paths: impl IntoIterator<Item = impl Into<PathBuf>>) -> Self {
        let iter = paths.into_iter().map(Into::into);
        for path in iter {
            self.lowers.push(path);
            self.lower_indexes.push(None);
        }
        self
    }

    /// Set the upper writable layer directory.
    pub fn writable(mut self, path: impl Into<PathBuf>) -> Self {
        self.upper_dir = Some(path.into());
        self
    }

    /// Set the private staging directory (must be on same filesystem as upper).
    pub fn staging(mut self, path: impl Into<PathBuf>) -> Self {
        self.staging_dir = Some(path.into());
        self
    }

    /// Enable read-only mode (no writable upper layer).
    ///
    /// Mutually exclusive with `.writable()` and `.staging()`.
    /// All mutation operations will return EROFS.
    pub fn read_only(mut self) -> Self {
        self.read_only = true;
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

            // Try to open sidecar index (graceful fallback to None).
            let lower_index = self
                .lower_indexes
                .get(index)
                .and_then(|opt| opt.as_ref())
                .and_then(|p| MmapIndex::open(p));

            #[cfg(target_os = "linux")]
            let layer_proc_fd = dup_fd(&proc_self_fd_main)?;

            lowers.push(Layer {
                root_fd,
                index,
                lower_index,
                #[cfg(target_os = "linux")]
                proc_self_fd: layer_proc_fd,
                #[cfg(target_os = "linux")]
                has_openat2,
            });
        }

        if self.read_only {
            return self.build_read_only(
                lowers,
                #[cfg(target_os = "linux")]
                proc_self_fd_main,
            );
        }

        self.build_read_write(
            lowers,
            #[cfg(target_os = "linux")]
            proc_self_fd_main,
            #[cfg(target_os = "linux")]
            has_openat2,
        )
    }

    /// Build a read-only OverlayFs (no upper layer, no staging directory).
    fn build_read_only(
        self,
        lowers: Vec<Layer>,
        #[cfg(target_os = "linux")] proc_self_fd_main: File,
    ) -> io::Result<OverlayFs> {
        // Validate: writable/staging/writeback must not be set in read-only mode.
        if self.writeback {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "writeback must not be set in read-only mode",
            ));
        }
        if self.upper_dir.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "upper directory must not be set in read-only mode",
            ));
        }
        if self.staging_dir.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "staging directory must not be set in read-only mode",
            ));
        }

        let init_file = init_binary::create_init_file()?;

        let cfg = OverlayConfig {
            entry_timeout: self.entry_timeout,
            attr_timeout: self.attr_timeout,
            cache_policy: self.cache_policy,
            writeback: false, // Force-disable in read-only mode.
            strict: self.strict,
            read_only: true,
        };

        Ok(OverlayFs {
            lowers,
            upper: None,
            staging_fd: None,
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
            #[cfg(target_os = "linux")]
            proc_self_fd: proc_self_fd_main,
            cfg,
        })
    }

    /// Build a read-write OverlayFs with upper layer and staging directory.
    fn build_read_write(
        self,
        lowers: Vec<Layer>,
        #[cfg(target_os = "linux")] proc_self_fd_main: File,
        #[cfg(target_os = "linux")] has_openat2: bool,
    ) -> io::Result<OverlayFs> {
        let upper_dir = self.upper_dir.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "upper directory not set")
        })?;
        let staging_dir = self.staging_dir.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "staging directory not set")
        })?;

        // Open upper layer.
        let upper_index = lowers.len();
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
            lower_index: None,
            #[cfg(target_os = "linux")]
            proc_self_fd: upper_proc_fd,
            #[cfg(target_os = "linux")]
            has_openat2,
        };

        // Open staging directory.
        let staging_fd = open_dir(&staging_dir)?;

        // Verify staging_dir is on same filesystem as upper_dir.
        {
            use std::os::fd::AsRawFd;
            let upper_st = platform::fstat(upper.root_fd.as_raw_fd())?;
            let staging_st = platform::fstat(staging_fd.as_raw_fd())?;
            if upper_st.st_dev != staging_st.st_dev {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "staging_dir must be on the same filesystem as upper_dir",
                ));
            }
        }

        // Clean leftover temp files in staging_dir.
        clean_staging_dir(&staging_fd)?;

        let init_file = init_binary::create_init_file()?;

        let cfg = OverlayConfig {
            entry_timeout: self.entry_timeout,
            attr_timeout: self.attr_timeout,
            cache_policy: self.cache_policy,
            writeback: self.writeback,
            strict: self.strict,
            read_only: false,
        };

        Ok(OverlayFs {
            lowers,
            upper: Some(upper),
            staging_fd: Some(staging_fd),
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
            #[cfg(target_os = "linux")]
            proc_self_fd: proc_self_fd_main,
            cfg,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open a directory path as an fd.
fn open_dir(path: &std::path::Path) -> io::Result<File> {
    let cpath = std::ffi::CString::new(path.to_str().ok_or_else(platform::einval)?.as_bytes())
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

/// Clean leftover temp files in staging_dir from prior crashes.
fn clean_staging_dir(staging_fd: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let dup_fd = unsafe { libc::fcntl(staging_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
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
            let ret = unsafe { libc::unlinkat(staging_fd.as_raw_fd(), name.as_ptr(), 0) };
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
