//! Inode management: lookup, registration, forget, and fd operations.
//!
//! ## Lookup Strategy
//!
//! Overlay lookup searches upper then lowers (top-down), checking whiteouts and
//! opaque markers at each level. When an entry is found, it is resolved via
//! the RESOLVE step which handles deduplication (upper_alt_keys for upper entries,
//! lower_origin_keys for intra-layer hardlink unification).
//!
//! ## Fd Management
//!
//! On Linux, nodes in Lower/Upper state hold an O_PATH fd pinning the inode.
//! On macOS, nodes store (dev, ino) and open fds on demand via `/.vol/<dev>/<ino>`.

use std::{
    collections::HashSet,
    ffi::{CStr, CString},
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd, RawFd},
    sync::{Arc, Mutex, RwLock, atomic::Ordering},
};

use super::{
    OverlayFs, layer,
    origin::LowerOriginId,
    types::{Dentry, Layer, NameId, NodeState, OverlayNode, ROOT_INODE},
};
use crate::{
    Entry,
    backends::shared::{init_binary, inode_table::InodeAltKey, platform, stat_override},
    stat64,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Owned-or-borrowed fd for node operations.
pub(crate) struct NodeFd {
    fd: i32,
    owned: bool,
}

impl NodeFd {
    pub(crate) fn raw(&self) -> i32 {
        self.fd
    }

    /// Check if this fd is owned (will be closed on drop).
    pub(crate) fn is_owned(&self) -> bool {
        self.owned
    }

    /// Take ownership of the fd, preventing auto-close on drop.
    pub(crate) fn into_raw(mut self) -> i32 {
        self.owned = false;
        self.fd
    }
}

impl Drop for NodeFd {
    fn drop(&mut self) {
        if self.owned && self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

/// Linux guest open flag constants (same as passthrough's).
#[cfg(target_os = "macos")]
mod linux_flags {
    pub const O_APPEND: i32 = 0x400;
    pub const O_CREAT: i32 = 0x40;
    pub const O_TRUNC: i32 = 0x200;
    pub const O_EXCL: i32 = 0x80;
    pub const O_NOFOLLOW: i32 = 0x20000;
    pub const O_NONBLOCK: i32 = 0x800;
    pub const O_CLOEXEC: i32 = 0x80000;
    pub const O_DIRECTORY: i32 = 0x10000;
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Translate Linux guest open flags to host open flags.
#[cfg(target_os = "linux")]
pub(crate) fn translate_open_flags(flags: i32) -> i32 {
    flags
}

#[cfg(target_os = "macos")]
pub(crate) fn translate_open_flags(linux_flags_val: i32) -> i32 {
    let mut flags = linux_flags_val & 0b11;
    if linux_flags_val & linux_flags::O_APPEND != 0 {
        flags |= libc::O_APPEND;
    }
    if linux_flags_val & linux_flags::O_CREAT != 0 {
        flags |= libc::O_CREAT;
    }
    if linux_flags_val & linux_flags::O_TRUNC != 0 {
        flags |= libc::O_TRUNC;
    }
    if linux_flags_val & linux_flags::O_EXCL != 0 {
        flags |= libc::O_EXCL;
    }
    if linux_flags_val & linux_flags::O_NOFOLLOW != 0 {
        flags |= libc::O_NOFOLLOW;
    }
    if linux_flags_val & linux_flags::O_NONBLOCK != 0 {
        flags |= libc::O_NONBLOCK;
    }
    if linux_flags_val & linux_flags::O_CLOEXEC != 0 {
        flags |= libc::O_CLOEXEC;
    }
    if linux_flags_val & linux_flags::O_DIRECTORY != 0 {
        flags |= libc::O_DIRECTORY;
    }
    flags
}

/// Register the root inode (inode 1) and perform BFS upper hydration.
///
/// Called during `init()`. Scans the upper layer breadth-first to hydrate
/// all directories and metadata-bearing entries (those with overlay_origin
/// or overlay_redirect xattrs).
pub(crate) fn register_root_inode(fs: &OverlayFs) -> io::Result<()> {
    let upper_fd = if let Some(ref upper) = fs.upper {
        upper.root_fd.as_raw_fd()
    } else {
        fs.lowers.last().unwrap().root_fd.as_raw_fd()
    };
    let st = platform::fstat(upper_fd)?;

    // Create root node with Root state.
    let root_fd_dup = dup_fd_raw(upper_fd)?;
    let root_file = unsafe { File::from_raw_fd(root_fd_dup) };

    let root_name = fs.names.intern(b"");
    // Seed dir_record_cache for root: DirRecord 0 on the topmost indexed lower layer.
    let root_dir_record_cache = fs.lowers.iter().rev().find_map(|l| {
        l.lower_index.as_ref().and_then(|idx| {
            idx.find_dir(b"")
                .map(|(dir_idx, _)| (l.index, dir_idx as u32))
        })
    });

    let root_node = Arc::new(OverlayNode {
        inode: ROOT_INODE,
        kind: libc::S_IFDIR as u32,
        lookup_refs: std::sync::atomic::AtomicU64::new(2), // libfuse convention
        state: RwLock::new(NodeState::Root { root_fd: root_file }),
        opaque: std::sync::atomic::AtomicBool::new(false),
        copy_up_lock: Mutex::new(()),
        origin: None,
        redirect: RwLock::new(None),
        primary_parent: std::sync::atomic::AtomicU64::new(0),
        primary_name: RwLock::new(root_name),
        dir_record_cache: RwLock::new(root_dir_record_cache),
    });

    // Register root in tables.
    {
        let mut nodes = fs.nodes.write().unwrap();
        nodes.insert(ROOT_INODE, root_node.clone());
    }

    // Register upper alt key for root.
    if fs.upper.is_some() {
        #[cfg(target_os = "linux")]
        {
            let mut stx: libc::statx = unsafe { std::mem::zeroed() };
            let ret = unsafe {
                libc::statx(
                    upper_fd,
                    c"".as_ptr(),
                    libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW | libc::AT_STATX_SYNC_AS_STAT,
                    libc::STATX_BASIC_STATS | libc::STATX_MNT_ID,
                    &mut stx,
                )
            };
            if ret >= 0 {
                let alt_key = InodeAltKey::new(
                    stx.stx_ino,
                    stx.stx_dev_major as u64 * 256 + stx.stx_dev_minor as u64,
                    stx.stx_mnt_id,
                );
                let mut upper_alt = fs.upper_alt_keys.write().unwrap();
                upper_alt.insert(alt_key, ROOT_INODE);
            }
        }

        #[cfg(target_os = "macos")]
        {
            let alt_key = InodeAltKey::new(st.st_ino as u64, st.st_dev as u64);
            let mut upper_alt = fs.upper_alt_keys.write().unwrap();
            upper_alt.insert(alt_key, ROOT_INODE);
        }
    }

    // Check if root is opaque.
    if layer::check_opaque(upper_fd)? {
        root_node.opaque.store(true, Ordering::Release);
    }

    // BFS hydrate the upper layer to rebuild origin_index and redirect state.
    if fs.upper.is_some() {
        bfs_hydrate_upper(fs)?;
    }

    Ok(())
}

/// BFS scan of the upper layer to rebuild `origin_index` and attach redirect state.
///
/// Scans all directories breadth-first from root. For each entry:
/// - Directories are always hydrated (allocated a guest inode, registered).
/// - Non-directory entries with `overlay_origin` xattr are hydrated for
///   origin_index population.
/// - Directories with `overlay_redirect` xattr get RedirectState attached.
/// - Directories with `.wh..wh..opq` marker get opaque flag set.
///
/// Must complete before the first guest operation.
fn bfs_hydrate_upper(fs: &OverlayFs) -> io::Result<()> {
    use super::{origin, types::RedirectState};
    use std::collections::VecDeque;

    let upper_fd = fs.upper.as_ref().unwrap().root_fd.as_raw_fd();
    let root_dir_fd = dup_fd_raw(upper_fd)?;

    let mut queue: VecDeque<(RawFd, u64)> = VecDeque::new();
    queue.push_back((root_dir_fd, ROOT_INODE));

    while let Some((dir_fd, parent_ino)) = queue.pop_front() {
        let entries = match layer::read_dir_entries_raw(dir_fd) {
            Ok(e) => e,
            Err(_) => {
                unsafe { libc::close(dir_fd) };
                continue;
            }
        };

        let mut seen_opaque = false;

        for (name, _d_type) in &entries {
            // Track opaque marker.
            if name == b".wh..wh..opq" {
                seen_opaque = true;
                continue;
            }

            // Skip whiteout files.
            if name.starts_with(b".wh.") {
                continue;
            }

            let name_cstr = match CString::new(name.clone()) {
                Ok(c) => c,
                Err(_) => continue,
            };

            // Open the child entry.
            let child_fd = unsafe {
                libc::openat(
                    dir_fd,
                    name_cstr.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if child_fd < 0 {
                // Try O_PATH on Linux for entries that can't be opened O_RDONLY.
                #[cfg(target_os = "linux")]
                {
                    let child_fd = unsafe {
                        libc::openat(
                            dir_fd,
                            name_cstr.as_ptr(),
                            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if child_fd < 0 {
                        continue;
                    }
                    // Check for origin xattr on O_PATH fd.
                    if let Ok(Some(origin_id)) = origin::get_origin_xattr(child_fd) {
                        // Hydrate this entry for origin_index.
                        if let Ok(ino) = hydrate_upper_entry(fs, parent_ino, &name_cstr, child_fd) {
                            let mut idx = fs.origin_index.write().unwrap();
                            idx.insert(origin_id, ino);
                        }
                    }
                    unsafe { libc::close(child_fd) };
                }
                continue;
            }

            let st = match platform::fstat(child_fd) {
                Ok(s) => s,
                Err(_) => {
                    unsafe { libc::close(child_fd) };
                    continue;
                }
            };

            #[cfg(target_os = "linux")]
            let is_dir = st.st_mode & libc::S_IFMT == libc::S_IFDIR;
            #[cfg(target_os = "macos")]
            let is_dir = (st.st_mode as u32) & (libc::S_IFMT as u32) == libc::S_IFDIR as u32;

            // Read origin xattr.
            let has_origin = origin::get_origin_xattr(child_fd);

            // Only hydrate directories and entries with origin xattr.
            let origin_id = match has_origin {
                Ok(Some(id)) => Some(id),
                _ => None,
            };

            if !is_dir && origin_id.is_none() {
                // No metadata to recover — will be discovered lazily.
                unsafe { libc::close(child_fd) };
                continue;
            }

            // Hydrate this entry.
            let ino = match hydrate_upper_entry(fs, parent_ino, &name_cstr, child_fd) {
                Ok(ino) => ino,
                Err(_) => {
                    unsafe { libc::close(child_fd) };
                    continue;
                }
            };

            // Populate origin_index if applicable.
            if let Some(origin_id) = origin_id {
                let mut idx = fs.origin_index.write().unwrap();
                idx.insert(origin_id, ino);
            }

            if is_dir {
                // Read redirect xattr.
                if let Ok(Some(components)) = origin::get_redirect_xattr(child_fd) {
                    let nodes = fs.nodes.read().unwrap();
                    if let Some(node) = nodes.get(&ino) {
                        *node.redirect.write().unwrap() = Some(RedirectState {
                            lower_path: components,
                        });
                    }
                }

                // Check opaque.
                if layer::check_opaque(child_fd).unwrap_or(false) {
                    let nodes = fs.nodes.read().unwrap();
                    if let Some(node) = nodes.get(&ino) {
                        node.opaque.store(true, Ordering::Release);
                    }
                }

                // Enqueue for BFS (dup the fd since we need to keep scanning).
                let child_dir_fd = unsafe { libc::fcntl(child_fd, libc::F_DUPFD_CLOEXEC, 0) };
                if child_dir_fd >= 0 {
                    queue.push_back((child_dir_fd, ino));
                }
            }

            unsafe { libc::close(child_fd) };
        }

        // Set opaque on parent if .wh..wh..opq was found.
        if seen_opaque {
            let nodes = fs.nodes.read().unwrap();
            if let Some(node) = nodes.get(&parent_ino) {
                node.opaque.store(true, Ordering::Release);
            }
        }

        unsafe { libc::close(dir_fd) };
    }

    Ok(())
}

/// Hydrate an upper-layer entry discovered during BFS.
///
/// Allocates a guest inode, creates an OverlayNode with Upper state, and
/// registers it in nodes/dentries/upper_alt_keys. Returns the guest inode.
fn hydrate_upper_entry(fs: &OverlayFs, parent_ino: u64, name: &CStr, fd: RawFd) -> io::Result<u64> {
    let name_id = fs.names.intern(name.to_bytes());

    // Check if already registered via upper_alt_keys.
    #[cfg(target_os = "linux")]
    {
        let mut stx: libc::statx = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            libc::statx(
                fd,
                c"".as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW | libc::AT_STATX_SYNC_AS_STAT,
                libc::STATX_BASIC_STATS | libc::STATX_MNT_ID,
                &mut stx,
            )
        };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }

        let alt_key = InodeAltKey::new(
            stx.stx_ino,
            stx.stx_dev_major as u64 * 256 + stx.stx_dev_minor as u64,
            stx.stx_mnt_id,
        );

        // Check if already seen.
        {
            let upper_alt = fs.upper_alt_keys.read().unwrap();
            if let Some(&existing_ino) = upper_alt.get(&alt_key) {
                // Already registered — just add a dentry.
                let nodes = fs.nodes.read().unwrap();
                if let Some(node) = nodes.get(&existing_ino) {
                    node.lookup_refs.fetch_add(1, Ordering::Relaxed);
                }
                drop(nodes);
                let mut dentries = fs.dentries.write().unwrap();
                dentries.insert((parent_ino, name_id), Dentry { node: existing_ino });
                return Ok(existing_ino);
            }
        }

        // New entry — allocate inode.
        let inode = fs.next_inode.fetch_add(1, Ordering::Relaxed);

        // Open an O_PATH fd for the node state.
        let path_fd = unsafe {
            libc::openat(
                fd,
                c"".as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        // If O_PATH fails, try to dup the fd.
        let file = if path_fd >= 0 {
            unsafe { File::from_raw_fd(path_fd) }
        } else {
            let dup_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
            if dup_fd < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
            unsafe { File::from_raw_fd(dup_fd) }
        };

        let kind = stx.stx_mode as u32 & libc::S_IFMT as u32;

        let node = Arc::new(OverlayNode {
            inode,
            kind,
            lookup_refs: std::sync::atomic::AtomicU64::new(1),
            state: RwLock::new(NodeState::Upper {
                file,
                mnt_id: stx.stx_mnt_id,
            }),
            opaque: std::sync::atomic::AtomicBool::new(false),
            copy_up_lock: Mutex::new(()),
            origin: None,
            redirect: RwLock::new(None),
            primary_parent: std::sync::atomic::AtomicU64::new(parent_ino),
            primary_name: RwLock::new(name_id),
            dir_record_cache: RwLock::new(None),
        });

        // Register.
        fs.nodes.write().unwrap().insert(inode, node);
        fs.upper_alt_keys.write().unwrap().insert(alt_key, inode);
        fs.dentries
            .write()
            .unwrap()
            .insert((parent_ino, name_id), Dentry { node: inode });

        return Ok(inode);
    }

    #[cfg(target_os = "macos")]
    {
        let st = platform::fstat(fd)?;
        let alt_key = InodeAltKey::new(st.st_ino as u64, st.st_dev as u64);

        // Check if already seen.
        {
            let upper_alt = fs.upper_alt_keys.read().unwrap();
            if let Some(&existing_ino) = upper_alt.get(&alt_key) {
                let nodes = fs.nodes.read().unwrap();
                if let Some(node) = nodes.get(&existing_ino) {
                    node.lookup_refs.fetch_add(1, Ordering::Relaxed);
                }
                drop(nodes);
                let mut dentries = fs.dentries.write().unwrap();
                dentries.insert((parent_ino, name_id), Dentry { node: existing_ino });
                return Ok(existing_ino);
            }
        }

        let inode = fs.next_inode.fetch_add(1, Ordering::Relaxed);
        let kind = (st.st_mode as u32) & (libc::S_IFMT as u32);

        let node = Arc::new(OverlayNode {
            inode,
            kind,
            lookup_refs: std::sync::atomic::AtomicU64::new(1),
            state: RwLock::new(NodeState::Upper {
                ino: st.st_ino as u64,
                dev: st.st_dev as u64,
            }),
            opaque: std::sync::atomic::AtomicBool::new(false),
            copy_up_lock: Mutex::new(()),
            origin: None,
            redirect: RwLock::new(None),
            primary_parent: std::sync::atomic::AtomicU64::new(parent_ino),
            primary_name: RwLock::new(name_id),
            dir_record_cache: RwLock::new(None),
        });

        fs.nodes.write().unwrap().insert(inode, node);
        fs.upper_alt_keys.write().unwrap().insert(alt_key, inode);
        fs.dentries
            .write()
            .unwrap()
            .insert((parent_ino, name_id), Dentry { node: inode });

        Ok(inode)
    }
}

/// Look up a child name in a parent directory, searching across all layers.
///
/// Implements the full overlay lookup algorithm: upper first, then lowers
/// (top-down), with whiteout and opaque checks at each level.
pub(crate) fn do_lookup(fs: &OverlayFs, parent: u64, name: &CStr) -> io::Result<Entry> {
    // Handle init.krun in root.
    if parent == ROOT_INODE && name.to_bytes() == init_binary::INIT_FILENAME {
        return Ok(init_binary::init_entry(
            fs.cfg.entry_timeout,
            fs.cfg.attr_timeout,
        ));
    }

    crate::backends::shared::name_validation::validate_overlay_name(name)?;

    // Get parent node.
    let parent_node = {
        let nodes = fs.nodes.read().unwrap();
        nodes.get(&parent).cloned().ok_or_else(platform::enoent)?
    };

    // Try upper layer first.
    if fs.upper.is_some() {
        let upper_parent_fd = get_upper_dir_fd(fs, &parent_node);

        if let Some(ref upper_fd_node) = upper_parent_fd {
            let upper_fd = upper_fd_node.raw();

            // Check whiteout in upper.
            if layer::check_whiteout(upper_fd, name.to_bytes())? {
                return Err(platform::enoent());
            }

            // Check if entry exists in upper.
            #[cfg(target_os = "linux")]
            let upper_flags = libc::O_PATH | libc::O_NOFOLLOW;
            #[cfg(target_os = "macos")]
            let upper_flags = libc::O_RDONLY | libc::O_NOFOLLOW;

            match layer::open_child_beneath(
                upper_fd,
                name,
                upper_flags,
                #[cfg(target_os = "linux")]
                fs.upper.as_ref().unwrap().has_openat2,
                #[cfg(target_os = "macos")]
                false,
            ) {
                Ok(fd) => {
                    return resolve_upper(fs, parent, name, fd);
                }
                Err(e) if platform::is_enoent(&e) => {}
                Err(e) => return Err(e),
            }
        }
    }

    // If parent is opaque AND we already checked the upper, don't search lowers.
    // In read-only mode (no upper), the opaque dir's entries live on a lower layer,
    // so we must still search lowers — the per-layer opaque check inside the loop
    // handles stopping at the correct layer.
    if fs.upper.is_some() && parent_node.opaque.load(Ordering::Acquire) {
        return Err(platform::enoent());
    }

    // Search lower layers top-down.
    // Lazily computed — only needed for layers without an index.
    let mut parent_name_bytes: Option<Vec<Vec<u8>>> = None;

    for lower in fs.lowers.iter().rev() {
        // Index fast path: use sidecar index to avoid syscalls.
        if let Some(ref idx) = lower.lower_index {
            let dir_rec = match find_dir_record_for_parent(fs, idx, lower.index, &parent_node) {
                Some(rec) => rec,
                None => continue, // Parent dir not on this layer.
            };

            // Check whiteout via index.
            if idx.has_whiteout(dir_rec, name.to_bytes()) {
                return Err(platform::enoent());
            }

            // Check if entry exists in index.
            if let Some(entry_rec) = idx.find_entry(dir_rec, name.to_bytes()) {
                // Entry found in index — open the real fd and resolve.
                let name_bytes_lazy = parent_name_bytes.get_or_insert_with(|| {
                    get_parent_lower_path(fs, &parent_node).unwrap_or_default()
                });
                let lower_parent_fd = match open_lower_parent(lower, &parent_node, name_bytes_lazy)
                {
                    Some(fd) => fd,
                    None => continue,
                };

                match platform::fstatat_nofollow(lower_parent_fd.raw(), name) {
                    Ok(st) => {
                        let result = resolve_lower(fs, lower, parent, name, st);

                        // Cache dir_record_idx on the new child node if it's a directory.
                        if entry_rec.dir_record_idx
                            != microsandbox_utils::index::DIR_RECORD_IDX_NONE
                            && let Ok(ref entry) = result
                        {
                            let nodes = fs.nodes.read().unwrap();
                            if let Some(child_node) = nodes.get(&entry.inode) {
                                let mut cache = child_node.dir_record_cache.write().unwrap();
                                *cache = Some((lower.index, entry_rec.dir_record_idx));
                            }
                        }

                        return result;
                    }
                    Err(e) if platform::is_enoent(&e) => {}
                    Err(e) => return Err(e),
                }
            }

            // Entry not found in index — check opaque.
            if idx.is_opaque(dir_rec) {
                break;
            }
            continue;
        }

        // Syscall fallback path (no index).
        let name_bytes_lazy = parent_name_bytes
            .get_or_insert_with(|| get_parent_lower_path(fs, &parent_node).unwrap_or_default());
        let lower_parent_fd = match open_lower_parent(lower, &parent_node, name_bytes_lazy) {
            Some(fd) => fd,
            None => continue,
        };

        // Check whiteout in this lower.
        if layer::check_whiteout(lower_parent_fd.raw(), name.to_bytes())? {
            return Err(platform::enoent());
        }

        // Check if entry exists in this lower.
        match platform::fstatat_nofollow(lower_parent_fd.raw(), name) {
            Ok(st) => {
                return resolve_lower(fs, lower, parent, name, st);
            }
            Err(e) if platform::is_enoent(&e) => {}
            Err(e) => return Err(e),
        }

        // Check if this directory is opaque on this layer.
        if layer::check_opaque(lower_parent_fd.raw())? {
            break;
        }
    }

    Err(platform::enoent())
}

/// RESOLVE step for an upper layer entry.
fn resolve_upper(fs: &OverlayFs, parent: u64, name: &CStr, fd: RawFd) -> io::Result<Entry> {
    let _close_guard = scopeguard::guard(fd, |fd| unsafe {
        libc::close(fd);
    });

    // Get stat.
    let st = platform::fstat(fd)?;
    let patched = stat_override::patched_stat(fd, st)?;

    // Build alt key for upper dedup. On Linux, also capture mnt_id for node state.
    #[cfg(target_os = "linux")]
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    #[cfg(target_os = "linux")]
    let alt_key = {
        let ret = unsafe {
            libc::statx(
                fd,
                c"".as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW | libc::AT_STATX_SYNC_AS_STAT,
                libc::STATX_BASIC_STATS | libc::STATX_MNT_ID,
                &mut stx,
            )
        };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        InodeAltKey::new(
            stx.stx_ino,
            stx.stx_dev_major as u64 * 256 + stx.stx_dev_minor as u64,
            stx.stx_mnt_id,
        )
    };

    #[cfg(target_os = "macos")]
    let alt_key = InodeAltKey::new(st.st_ino as u64, st.st_dev as u64);

    let name_id = fs.names.intern(name.to_bytes());

    // Check if already registered (dedup via upper_alt_keys).
    {
        let upper_alt = fs.upper_alt_keys.read().unwrap();
        if let Some(&existing_ino) = upper_alt.get(&alt_key) {
            let nodes = fs.nodes.read().unwrap();
            if let Some(node) = nodes.get(&existing_ino) {
                node.lookup_refs.fetch_add(1, Ordering::Relaxed);

                // Register dentry for this (parent, name) → existing node.
                drop(nodes);
                let mut dentries = fs.dentries.write().unwrap();
                dentries.insert((parent, name_id), Dentry { node: existing_ino });

                return make_entry(
                    existing_ino,
                    patched,
                    fs.cfg.entry_timeout,
                    fs.cfg.attr_timeout,
                );
            }
        }
    }

    // New upper entry — allocate inode.
    let inode = fs.next_inode.fetch_add(1, Ordering::Relaxed);

    #[cfg(target_os = "linux")]
    let state = {
        // Take ownership of the fd (defuse the close guard).
        let owned_fd = scopeguard::ScopeGuard::into_inner(_close_guard);
        let file = unsafe { File::from_raw_fd(owned_fd) };
        // Reuse the stx from the alt_key call above — same fd, same data.
        NodeState::Upper {
            file,
            mnt_id: stx.stx_mnt_id,
        }
    };

    #[cfg(target_os = "macos")]
    let state = {
        // On macOS, we don't keep the fd — close it via the guard.
        // Store ino/dev for /.vol reopening.
        NodeState::Upper {
            ino: st.st_ino as u64,
            dev: st.st_dev as u64,
        }
    };

    #[cfg(target_os = "linux")]
    let kind = patched.st_mode & libc::S_IFMT;
    #[cfg(target_os = "macos")]
    let kind = (patched.st_mode as u32) & (libc::S_IFMT as u32);

    let node = Arc::new(OverlayNode {
        inode,
        kind,
        lookup_refs: std::sync::atomic::AtomicU64::new(1),
        state: RwLock::new(state),
        opaque: std::sync::atomic::AtomicBool::new(false),
        copy_up_lock: Mutex::new(()),
        origin: None,
        redirect: RwLock::new(None),
        primary_parent: std::sync::atomic::AtomicU64::new(parent),
        primary_name: RwLock::new(name_id),
        dir_record_cache: RwLock::new(None),
    });

    // Check opaque for directories.
    if kind == libc::S_IFDIR as u32 {
        // We need to check if this upper dir has .wh..wh..opq.
        // For upper entries, try opening the dir and checking.
        let parent_node = {
            let nodes = fs.nodes.read().unwrap();
            nodes.get(&parent).cloned().unwrap()
        };
        if let Some(upper_parent_fd_node) = get_upper_dir_fd(fs, &parent_node)
            && let Ok(child_dir_fd) = layer::open_subdir(upper_parent_fd_node.raw(), name)
        {
            if layer::check_opaque(child_dir_fd).unwrap_or(false) {
                node.opaque.store(true, Ordering::Release);
            }
            unsafe { libc::close(child_dir_fd) };
        }
    }

    // Register in tables.
    {
        let mut nodes = fs.nodes.write().unwrap();
        nodes.insert(inode, node);
    }
    {
        let mut upper_alt = fs.upper_alt_keys.write().unwrap();
        upper_alt.insert(alt_key, inode);
    }
    {
        let mut dentries = fs.dentries.write().unwrap();
        dentries.insert((parent, name_id), Dentry { node: inode });
    }

    make_entry(inode, patched, fs.cfg.entry_timeout, fs.cfg.attr_timeout)
}

/// RESOLVE step for a lower layer entry.
fn resolve_lower(
    fs: &OverlayFs,
    lower_layer: &Layer,
    parent: u64,
    name: &CStr,
    st: stat64,
) -> io::Result<Entry> {
    // Open fd to get xattr override. On Linux, keep the fd for reuse as the
    // O_PATH pinning fd (avoids a redundant second open_lower_child_fd call).
    //
    // On macOS, symlinks cannot be opened with O_NOFOLLOW (returns ELOOP) and
    // cannot carry user xattrs, so skip the fd-based override for symlinks.
    #[cfg(target_os = "macos")]
    let is_symlink = (st.st_mode as u32) & (libc::S_IFMT as u32) == (libc::S_IFLNK as u32);
    #[cfg(target_os = "linux")]
    let is_symlink = false; // Linux uses O_PATH which works on symlinks.

    let (lower_fd, patched) = if is_symlink {
        (-1, st)
    } else {
        let fd = open_lower_child_fd(lower_layer, parent, name, fs)?;
        let p = stat_override::patched_stat(fd, st)?;
        (fd, p)
    };
    let _close = scopeguard::guard(lower_fd, |fd| unsafe {
        if fd >= 0 {
            libc::close(fd);
        }
    });

    // Construct origin ID for hardlink unification.
    let origin_id = LowerOriginId::new(lower_layer.index, st.st_ino);
    let name_id = fs.names.intern(name.to_bytes());

    // Check if this origin was already copied up (cross-copy-up dedup).
    // If so, resolve to the existing upper node instead of creating a new Lower node.
    if !fs.cfg.read_only {
        let origin_idx = fs.origin_index.read().unwrap();
        if let Some(&existing_ino) = origin_idx.get(&origin_id) {
            let nodes = fs.nodes.read().unwrap();
            if let Some(node) = nodes.get(&existing_ino) {
                node.lookup_refs.fetch_add(1, Ordering::Relaxed);

                // Register new dentry for the existing upper node.
                drop(nodes);
                let mut dentries = fs.dentries.write().unwrap();
                dentries.insert((parent, name_id), Dentry { node: existing_ino });

                return make_entry(
                    existing_ino,
                    patched,
                    fs.cfg.entry_timeout,
                    fs.cfg.attr_timeout,
                );
            }
        }
    }

    // Check if this origin is already tracked (intra-layer hardlink unification).
    {
        let origin_keys = fs.lower_origin_keys.read().unwrap();
        if let Some(&existing_ino) = origin_keys.get(&origin_id) {
            let nodes = fs.nodes.read().unwrap();
            if let Some(node) = nodes.get(&existing_ino) {
                node.lookup_refs.fetch_add(1, Ordering::Relaxed);

                // Register new dentry for same node.
                drop(nodes);
                let mut dentries = fs.dentries.write().unwrap();
                dentries.insert((parent, name_id), Dentry { node: existing_ino });

                return make_entry(
                    existing_ino,
                    patched,
                    fs.cfg.entry_timeout,
                    fs.cfg.attr_timeout,
                );
            }
        }
    }

    // New lower entry — allocate inode.
    let inode = fs.next_inode.fetch_add(1, Ordering::Relaxed);

    #[cfg(target_os = "linux")]
    let state = {
        // Reuse the fd opened above — take ownership from the scopeguard.
        let fd = scopeguard::ScopeGuard::into_inner(_close);
        let file = unsafe { File::from_raw_fd(fd) };
        let mut stx: libc::statx = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            libc::statx(
                file.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW | libc::AT_STATX_SYNC_AS_STAT,
                libc::STATX_BASIC_STATS | libc::STATX_MNT_ID,
                &mut stx,
            )
        };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        NodeState::Lower {
            layer_idx: lower_layer.index,
            file,
            mnt_id: stx.stx_mnt_id,
        }
    };

    #[cfg(target_os = "macos")]
    let state = NodeState::Lower {
        layer_idx: lower_layer.index,
        ino: st.st_ino,
        dev: st.st_dev as u64,
    };

    #[cfg(target_os = "linux")]
    let kind = patched.st_mode & libc::S_IFMT;
    #[cfg(target_os = "macos")]
    let kind = (patched.st_mode as u32) & (libc::S_IFMT as u32);

    let node = Arc::new(OverlayNode {
        inode,
        kind,
        lookup_refs: std::sync::atomic::AtomicU64::new(1),
        state: RwLock::new(state),
        opaque: std::sync::atomic::AtomicBool::new(false),
        copy_up_lock: Mutex::new(()),
        origin: Some(origin_id),
        redirect: RwLock::new(None),
        primary_parent: std::sync::atomic::AtomicU64::new(parent),
        primary_name: RwLock::new(name_id),
        dir_record_cache: RwLock::new(None),
    });

    // Check opaque for lower directories.
    if kind == libc::S_IFDIR as u32
        && let Some(lower_dir_fd) = open_lower_dir(lower_layer, parent, name, fs)
    {
        if layer::check_opaque(lower_dir_fd).unwrap_or(false) {
            node.opaque.store(true, Ordering::Release);
        }
        unsafe { libc::close(lower_dir_fd) };
    }

    // Register in tables.
    {
        let mut nodes = fs.nodes.write().unwrap();
        nodes.insert(inode, node);
    }
    {
        let mut origin_keys = fs.lower_origin_keys.write().unwrap();
        origin_keys.insert(origin_id, inode);
    }
    {
        let mut dentries = fs.dentries.write().unwrap();
        dentries.insert((parent, name_id), Dentry { node: inode });
    }

    make_entry(inode, patched, fs.cfg.entry_timeout, fs.cfg.attr_timeout)
}

/// Decrement lookup refs for an inode, removing it when refs reach zero.
pub(crate) fn forget_one(fs: &OverlayFs, inode: u64, count: u64) {
    if inode == init_binary::INIT_INODE {
        return;
    }

    let removed = {
        let mut nodes = fs.nodes.write().unwrap();
        let mut dentries = fs.dentries.write().unwrap();
        forget_one_locked(&mut nodes, &mut dentries, inode, count)
    };

    // Clean up dedup maps after releasing nodes/dentries locks to avoid
    // lock ordering inversions (resolve_upper acquires upper_alt_keys → nodes).
    if let Some(origin) = removed {
        cleanup_dedup_maps(fs, inode, origin);
    }
}

/// Inner forget implementation for use under existing locks (batch_forget).
///
/// Returns `Some(origin)` if the inode was removed (for dedup map cleanup),
/// `None` if the inode was not removed.
pub(crate) fn forget_one_locked(
    nodes: &mut std::collections::BTreeMap<u64, Arc<OverlayNode>>,
    dentries: &mut std::collections::BTreeMap<(u64, NameId), Dentry>,
    inode: u64,
    count: u64,
) -> Option<Option<LowerOriginId>> {
    if inode == init_binary::INIT_INODE {
        return None;
    }

    let should_remove = if let Some(node) = nodes.get(&inode) {
        loop {
            let old = node.lookup_refs.load(Ordering::Relaxed);
            let new = old.saturating_sub(count);
            if node
                .lookup_refs
                .compare_exchange(old, new, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                break new == 0;
            }
        }
    } else {
        false
    };

    if should_remove {
        // Extract origin and primary dentry key before removing the node.
        let (origin, primary_parent, primary_name) = match nodes.get(&inode) {
            Some(n) => (
                n.origin,
                n.primary_parent.load(Ordering::Acquire),
                *n.primary_name.read().unwrap(),
            ),
            None => return None,
        };

        nodes.remove(&inode);

        // Remove primary dentry in O(1).
        dentries.remove(&(primary_parent, primary_name));

        // If this node had hardlink aliases, scan for any remaining dentries.
        if origin.is_some() {
            dentries.retain(|_, d| d.node != inode);
        }

        Some(origin)
    } else {
        None
    }
}

/// Clean up dedup maps after an inode is removed.
///
/// Must be called AFTER releasing nodes/dentries write locks to avoid
/// lock ordering deadlocks.
fn cleanup_dedup_maps(fs: &OverlayFs, inode: u64, origin: Option<LowerOriginId>) {
    // Always clean lower_origin_keys (populated for lower-layer hardlinks even in read-only mode).
    // Only clean upper_alt_keys and origin_index in writable mode.
    if !fs.cfg.read_only {
        fs.upper_alt_keys
            .write()
            .unwrap()
            .retain(|_, &mut v| v != inode);
    }

    if let Some(origin_id) = origin {
        fs.lower_origin_keys.write().unwrap().remove(&origin_id);
        if !fs.cfg.read_only {
            fs.origin_index.write().unwrap().remove(&origin_id);
        }
    }
}

/// Batch-clean dedup maps after multiple inodes are removed.
///
/// Called from batch_forget after releasing nodes/dentries locks.
pub(crate) fn cleanup_dedup_maps_batch(fs: &OverlayFs, removed: &[(u64, Option<LowerOriginId>)]) {
    // Always clean lower_origin_keys (populated for lower-layer hardlinks even in read-only mode).
    // Only clean upper_alt_keys and origin_index in writable mode.
    if !fs.cfg.read_only {
        let removed_set: HashSet<u64> = removed.iter().map(|(ino, _)| *ino).collect();

        fs.upper_alt_keys
            .write()
            .unwrap()
            .retain(|_, v| !removed_set.contains(v));

        let mut origin_idx = fs.origin_index.write().unwrap();
        for (_, origin) in removed {
            if let Some(origin_id) = origin {
                origin_idx.remove(origin_id);
            }
        }
    }

    let mut origin_keys = fs.lower_origin_keys.write().unwrap();
    for (_, origin) in removed {
        if let Some(origin_id) = origin {
            origin_keys.remove(origin_id);
        }
    }
}

/// Get the stat for an inode, applying xattr override.
pub(crate) fn stat_node(fs: &OverlayFs, inode: u64) -> io::Result<stat64> {
    if inode == init_binary::INIT_INODE {
        return Ok(init_binary::init_stat());
    }

    let node = {
        let nodes = fs.nodes.read().unwrap();
        nodes.get(&inode).cloned().ok_or_else(platform::enoent)?
    };

    let state = node.state.read().unwrap();
    match &*state {
        NodeState::Root { root_fd } => {
            let st = platform::fstat(root_fd.as_raw_fd())?;
            stat_override::patched_stat(root_fd.as_raw_fd(), st)
        }
        #[cfg(target_os = "linux")]
        NodeState::Lower { file, .. } | NodeState::Upper { file, .. } => {
            // On Linux, fstat works on O_PATH fds — no need to reopen.
            // The fd is borrowed from the File, so we must NOT close it.
            let fd = file.as_raw_fd();
            let st = platform::fstat(fd)?;
            stat_override::patched_stat(fd, st)
        }
        #[cfg(target_os = "macos")]
        NodeState::Lower { ino, dev, .. } | NodeState::Upper { ino, dev, .. } => {
            let path = vol_path(*dev, *ino);
            let fd = open_macos_vol(&path)?;
            let _close = scopeguard::guard(fd, |fd| unsafe {
                libc::close(fd);
            });
            let st = platform::fstat(fd)?;
            stat_override::patched_stat(fd, st)
        }
    }
}

/// Open a node's backing fd for I/O operations.
pub(crate) fn open_node_fd(fs: &OverlayFs, inode: u64, flags: i32) -> io::Result<RawFd> {
    let node = {
        let nodes = fs.nodes.read().unwrap();
        nodes.get(&inode).cloned().ok_or_else(platform::enoent)?
    };

    let state = node.state.read().unwrap();
    match &*state {
        NodeState::Root { root_fd } => {
            let fd = unsafe { libc::fcntl(root_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
            if fd < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
            Ok(fd)
        }
        #[cfg(target_os = "linux")]
        NodeState::Lower { file, .. } | NodeState::Upper { file, .. } => {
            reopen_fd_linux(&fs.proc_self_fd, file.as_raw_fd(), flags)
        }
        #[cfg(target_os = "macos")]
        NodeState::Lower { ino, dev, .. } | NodeState::Upper { ino, dev, .. } => {
            let path = vol_path(*dev, *ino);
            let fd =
                unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) };
            if fd >= 0 {
                return Ok(fd);
            }
            // Only fall back to O_SYMLINK for ELOOP (symlink with O_NOFOLLOW).
            // Other errors (EACCES, ENOENT, etc.) should propagate immediately.
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ELOOP) {
                return Err(platform::linux_error(err));
            }
            // O_SYMLINK opens the symlink itself (not its target) on macOS.
            let fd =
                unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC | libc::O_SYMLINK) };
            if fd < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
            Ok(fd)
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Build a FUSE Entry from an inode number and stat.
fn make_entry(
    inode: u64,
    st: stat64,
    entry_timeout: std::time::Duration,
    attr_timeout: std::time::Duration,
) -> io::Result<Entry> {
    Ok(Entry {
        inode,
        generation: 0,
        attr: st,
        attr_flags: 0,
        attr_timeout,
        entry_timeout,
    })
}

/// Get the upper layer fd for a parent node's directory.
///
/// Returns `Some(NodeFd)` if the parent has an upper representation, `None`
/// otherwise. The returned `NodeFd` is either borrowed (Root) or owned
/// (Upper), and is automatically closed on drop if owned.
#[allow(unused_variables)] // `fs` is used on Linux only (proc_self_fd reopen).
pub(crate) fn get_upper_dir_fd(fs: &OverlayFs, parent_node: &OverlayNode) -> Option<NodeFd> {
    let state = parent_node.state.read().unwrap();
    match &*state {
        NodeState::Root { root_fd } => Some(NodeFd {
            fd: root_fd.as_raw_fd(),
            owned: false,
        }),
        NodeState::Upper { .. } => {
            #[cfg(target_os = "linux")]
            if let NodeState::Upper { file, .. } = &*state {
                if let Ok(fd) = reopen_fd_linux(
                    &fs.proc_self_fd,
                    file.as_raw_fd(),
                    libc::O_RDONLY | libc::O_DIRECTORY,
                ) {
                    return Some(NodeFd { fd, owned: true });
                }
            }
            #[cfg(target_os = "macos")]
            if let NodeState::Upper { ino, dev, .. } = &*state {
                let path = vol_path(*dev, *ino);
                let fd = unsafe {
                    libc::open(
                        path.as_ptr(),
                        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                    )
                };
                if fd >= 0 {
                    return Some(NodeFd { fd, owned: true });
                }
            }
            None
        }
        _ => None,
    }
}

/// Get the lower path components for a parent node.
///
/// If the node has a redirect, returns the redirect's lower_path.
/// Otherwise, walks the primary_parent/primary_name chain to root,
/// checking each ancestor for a redirect as the base path.
///
/// Returns empty Vec for root nodes or nodes whose parent can be
/// opened directly via their fd (same-layer Lower).
pub(crate) fn get_parent_lower_path(
    fs: &OverlayFs,
    parent_node: &OverlayNode,
) -> io::Result<Vec<Vec<u8>>> {
    // Check redirect first.
    let redirect = parent_node.redirect.read().unwrap();
    if let Some(ref redir) = *redirect {
        return Ok(redir.lower_path.clone());
    }
    drop(redirect);

    // If this is a Root or Lower node, the path is implicit from the fd.
    // Only need to build path for Upper nodes (that were created from scratch
    // or copied up from a lower layer in a different position).
    let state = parent_node.state.read().unwrap();
    match &*state {
        NodeState::Root { .. } => return Ok(Vec::new()),
        NodeState::Lower { .. } => return Ok(Vec::new()),
        NodeState::Upper { .. } => {}
    }
    drop(state);

    // Walk the primary_parent/primary_name chain to root, collecting components.
    // Check each ancestor for a redirect along the way.
    walk_parent_chain(fs, parent_node)
}

/// Walk the dentry chain from a node to root, building path components.
///
/// At each step, checks if the ancestor has a redirect — if so, uses it
/// as the base path prefix. Returns components in root-to-leaf order.
fn walk_parent_chain(fs: &OverlayFs, node: &OverlayNode) -> io::Result<Vec<Vec<u8>>> {
    let mut components = Vec::new();

    // Collect this node's own name first.
    let name_bytes = {
        let name_id = node.primary_name.read().unwrap();
        fs.names.resolve(*name_id)
    };
    components.push(name_bytes);

    let mut current_ino = node.primary_parent.load(Ordering::Acquire);
    let mut visited = HashSet::new();

    while current_ino != ROOT_INODE {
        if !visited.insert(current_ino) {
            // Cycle detected in the parent chain.
            return Err(platform::eloop());
        }

        let cur_node = {
            let nodes = fs.nodes.read().unwrap();
            match nodes.get(&current_ino).cloned() {
                Some(n) => n,
                None => break,
            }
        };

        // Check if this ancestor has a redirect.
        let redirect = cur_node.redirect.read().unwrap();
        if let Some(ref redir) = *redirect {
            // Use the redirect's lower_path as the base prefix.
            let mut path = redir.lower_path.clone();
            components.reverse();
            path.extend(components);
            return Ok(path);
        }
        drop(redirect);

        // If ancestor is Root, we've reached the top.
        let state = cur_node.state.read().unwrap();
        if matches!(&*state, NodeState::Root { .. }) {
            break;
        }
        drop(state);

        let name_bytes = {
            let name_id = cur_node.primary_name.read().unwrap();
            fs.names.resolve(*name_id)
        };
        components.push(name_bytes);

        current_ino = cur_node.primary_parent.load(Ordering::Acquire);
    }

    // Reverse to get root-to-leaf order.
    components.reverse();
    Ok(components)
}

/// Try to open the parent directory in a lower layer.
///
/// For root parent, returns the layer's root fd.
/// For same-layer parents, reopens the fd.
/// For cross-layer or upper parents with path_components, walks the path.
pub(crate) fn open_lower_parent(
    layer: &Layer,
    parent_node: &OverlayNode,
    path_components: &[Vec<u8>],
) -> Option<NodeFd> {
    let state = parent_node.state.read().unwrap();

    match &*state {
        NodeState::Root { .. } => {
            // Parent is root — use the layer's root fd directly.
            Some(NodeFd {
                fd: layer.root_fd.as_raw_fd(),
                owned: false,
            })
        }
        NodeState::Lower { layer_idx, .. } if *layer_idx == layer.index => {
            // Parent is on this same lower layer.
            #[cfg(target_os = "linux")]
            if let NodeState::Lower { file, .. } = &*state {
                if let Ok(fd) = reopen_fd_linux(
                    &layer.proc_self_fd,
                    file.as_raw_fd(),
                    libc::O_RDONLY | libc::O_DIRECTORY,
                ) {
                    return Some(NodeFd { fd, owned: true });
                }
            }
            #[cfg(target_os = "macos")]
            if let NodeState::Lower { ino, dev, .. } = &*state {
                let path = vol_path(*dev, *ino);
                let fd = unsafe {
                    libc::open(
                        path.as_ptr(),
                        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                    )
                };
                if fd >= 0 {
                    return Some(NodeFd { fd, owned: true });
                }
            }
            None
        }
        _ => {
            // Parent is on a different lower layer, or is Upper/Init.
            // Try to open by walking path_components from the layer root.
            drop(state);
            if !path_components.is_empty() {
                open_lower_by_path(layer, path_components)
            } else {
                None
            }
        }
    }
}

/// Open a directory in a lower layer by walking path components from root.
///
/// Used when the parent is on a different layer or is Upper, so we can't
/// use the fd directly. Walks each component via openat from the layer root.
pub(crate) fn open_lower_by_path(layer: &Layer, components: &[Vec<u8>]) -> Option<NodeFd> {
    let mut fd = layer.root_fd.as_raw_fd();
    let mut owned = false;

    for component in components {
        let name = match CString::new(component.clone()) {
            Ok(n) => n,
            Err(_) => {
                if owned {
                    unsafe { libc::close(fd) };
                }
                return None;
            }
        };

        let child_fd = unsafe {
            libc::openat(
                fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
        };

        if owned {
            unsafe { libc::close(fd) };
        }

        if child_fd < 0 {
            return None;
        }

        fd = child_fd;
        owned = true;
    }

    Some(NodeFd { fd, owned })
}

/// Open a child entry fd in a lower layer for stat/xattr.
fn open_lower_child_fd(
    layer: &Layer,
    parent: u64,
    name: &CStr,
    fs: &OverlayFs,
) -> io::Result<RawFd> {
    let parent_node = {
        let nodes = fs.nodes.read().unwrap();
        nodes.get(&parent).cloned().ok_or_else(platform::enoent)?
    };

    let path_components = get_parent_lower_path(fs, &parent_node)?;
    let parent_fd_node =
        open_lower_parent(layer, &parent_node, &path_components).ok_or_else(platform::enoent)?;

    #[cfg(target_os = "linux")]
    return layer::open_child_beneath(
        parent_fd_node.raw(),
        name,
        libc::O_PATH | libc::O_NOFOLLOW,
        layer.has_openat2,
    );

    #[cfg(target_os = "macos")]
    {
        // On macOS, open the child for reading (no O_PATH).
        let fd = unsafe {
            libc::openat(
                parent_fd_node.raw(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd >= 0 {
            return Ok(fd);
        }
        // Try as directory.
        let fd = unsafe {
            libc::openat(
                parent_fd_node.raw(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
        };
        if fd >= 0 {
            return Ok(fd);
        }
        // Only fall back to O_SYMLINK for ELOOP (symlink with O_NOFOLLOW).
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ELOOP) {
            return Err(platform::linux_error(err));
        }
        // O_SYMLINK opens the symlink itself (not its target) on macOS.
        let fd = unsafe {
            libc::openat(
                parent_fd_node.raw(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_SYMLINK,
            )
        };
        if fd < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        Ok(fd)
    }
}

/// Try to open a lower child as a directory.
fn open_lower_dir(layer: &Layer, parent: u64, name: &CStr, fs: &OverlayFs) -> Option<RawFd> {
    let parent_node = {
        let nodes = fs.nodes.read().unwrap();
        nodes.get(&parent).cloned()?
    };

    let path_components = get_parent_lower_path(fs, &parent_node).ok()?;
    let parent_fd_node = open_lower_parent(layer, &parent_node, &path_components)?;

    let fd = unsafe {
        libc::openat(
            parent_fd_node.raw(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if fd >= 0 { Some(fd) } else { None }
}

/// Duplicate a raw fd with CLOEXEC.
pub(crate) fn dup_fd_raw(fd: RawFd) -> io::Result<RawFd> {
    let new_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if new_fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    Ok(new_fd)
}

/// Reopen an O_PATH fd for I/O via /proc/self/fd (Linux only).
#[cfg(target_os = "linux")]
pub(crate) fn reopen_fd_linux(
    proc_self_fd: &File,
    o_path_fd: RawFd,
    flags: i32,
) -> io::Result<RawFd> {
    let mut buf = [0u8; 20];
    let fd_str = format_fd_cstr(o_path_fd, &mut buf);
    let fd = unsafe {
        libc::openat(
            proc_self_fd.as_raw_fd(),
            fd_str.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    Ok(fd)
}

/// Format a file descriptor number as a C string (e.g. "42\0").
#[cfg(target_os = "linux")]
fn format_fd_cstr(fd: RawFd, buf: &mut [u8; 20]) -> &CStr {
    use std::io::Write;
    let mut cursor = std::io::Cursor::new(&mut buf[..]);
    write!(cursor, "{}", fd).unwrap();
    let pos = cursor.position() as usize;
    buf[pos] = 0;
    unsafe { CStr::from_bytes_with_nul_unchecked(&buf[..pos + 1]) }
}

/// Build a /.vol/<dev>/<ino> path for macOS.
#[cfg(target_os = "macos")]
pub(crate) fn vol_path(dev: u64, ino: u64) -> CString {
    CString::new(format!("/.vol/{dev}/{ino}"))
        .expect("formatted /.vol path never contains interior nul")
}

/// Open a /.vol path on macOS.
///
/// Tries O_RDONLY first, then O_DIRECTORY for directories. If ELOOP is returned
/// (symlink with O_NOFOLLOW), falls back to O_SYMLINK which opens the symlink
/// itself without following it.
#[cfg(target_os = "macos")]
fn open_macos_vol(path: &CStr) -> io::Result<RawFd> {
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd >= 0 {
        return Ok(fd);
    }
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if fd >= 0 {
        return Ok(fd);
    }
    // Only fall back to O_SYMLINK for ELOOP (symlink with O_NOFOLLOW).
    let err = io::Error::last_os_error();
    if err.raw_os_error() != Some(libc::ELOOP) {
        return Err(platform::linux_error(err));
    }
    // O_SYMLINK opens the symlink itself (not its target) on macOS.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_SYMLINK,
        )
    };
    if fd >= 0 {
        return Ok(fd);
    }
    Err(platform::linux_error(io::Error::last_os_error()))
}

//--------------------------------------------------------------------------------------------------
// Functions: Sidecar Index Helpers
//--------------------------------------------------------------------------------------------------

/// Build the overlay path for a node by walking the `primary_parent`/`primary_name`
/// chain to root, joining components with `/`.
///
/// Unlike `get_parent_lower_path`, this always walks the full chain (never
/// short-circuits for Lower nodes) because the index is keyed by path string,
/// not by fd.
///
/// Returns `b""` for root, `b"etc"`, `b"usr/bin"`, etc.
pub(crate) fn build_overlay_path(fs: &OverlayFs, node: &OverlayNode) -> io::Result<Vec<u8>> {
    // Root → empty path.
    {
        let state = node.state.read().unwrap();
        if matches!(&*state, NodeState::Root { .. }) {
            return Ok(Vec::new());
        }
    }

    // If this node has a redirect, use its lower path directly.
    {
        let redirect = node.redirect.read().unwrap();
        if let Some(ref redir) = *redirect {
            return Ok(redir.lower_path.join(&b"/"[..]));
        }
    }

    let components = walk_parent_chain(fs, node)?;
    Ok(components.join(&b"/"[..]))
}

/// Find the `DirRecord` for a parent node in a given layer's sidecar index.
///
/// Fast path: uses `dir_record_cache` if it matches this layer.
/// Slow path: builds the overlay path and binary-searches the directory table,
/// then caches the result.
pub(crate) fn find_dir_record_for_parent<'a>(
    fs: &OverlayFs,
    index: &'a microsandbox_utils::index::MmapIndex,
    layer_idx: usize,
    parent_node: &OverlayNode,
) -> Option<&'a microsandbox_utils::index::DirRecord> {
    // Fast path: check cache.
    {
        let cache = parent_node.dir_record_cache.read().unwrap();
        if let Some((cached_layer, cached_idx)) = *cache
            && cached_layer == layer_idx
        {
            let dirs = index.dir_records();
            return dirs.get(cached_idx as usize);
        }
    }

    // Slow path: build overlay path and binary search.
    let path = build_overlay_path(fs, parent_node).ok()?;
    let (dir_idx, dir_rec) = index.find_dir(&path)?;

    // Cache the result.
    {
        let mut cache = parent_node.dir_record_cache.write().unwrap();
        *cache = Some((layer_idx, dir_idx as u32));
    }

    Some(dir_rec)
}
