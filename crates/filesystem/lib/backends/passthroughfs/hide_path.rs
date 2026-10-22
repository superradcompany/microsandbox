//! Deny-list matcher for bind mounts.
//!
//! A `hide_path` list is a set of gitignore-style patterns that hide matching
//! paths from a bind mount, enforced host-side in the passthrough backend.
//! Component-only patterns (no `/`, e.g. `.env`, `*.log`) are matched against
//! the entry name anywhere in the tree (gitignore semantics). Path patterns
//! (containing `/`, e.g. `dir/secret`, `**/env.secret`) are matched against
//! the full path relative to the mount root.
//!
//! Cross-platform: the matcher lives at the passthrough level so both the
//! Unix and Windows passthrough backends can use it.
//!
//! Deny is enforced at name-taking entry points (lookup, create, mkdir,
//! unlink, rename, readdir, ...). Inode-scoped operations that reuse an already
//! resolved inode (`open` for write, `setattr`, `write`) are deliberately not
//! hide_path-checked: lookup returns `ENOENT` for a denied name, so the guest can
//! normally never obtain the inode of a hidden entry in the first place.
//!
//! That assumption breaks when a concurrent host writer changes an entry's
//! type after lookup vouched for it. The Windows backend caches an absolute
//! path per inode, so `opendir` and every operation that uses an inode as a
//! parent re-apply the directory-only rule to the live path (see
//! `PassthroughFs::child_path` and `opendir`); the Unix backends revalidate
//! inode identity on reopen instead.

use std::io;
use std::path::Path;
#[cfg(not(target_os = "windows"))]
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ignore::{Match, gitignore::Gitignore, gitignore::GitignoreBuilder};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Prefix of the probe file created in the mount root to detect a
/// case-insensitive filesystem, mirroring git's `core.ignorecase`
/// auto-detection (git creates a file and then `access`es a differently-cased
/// variant of its name).
///
/// The prefix must contain ASCII letters so a case-flipped sibling name can be
/// formed. A process-unique numeric suffix keeps concurrent builders from
/// colliding.
const CASE_PROBE_PREFIX: &str = "MsBCaSePrObE";

/// Lowercase of [`CASE_PROBE_PREFIX`], used to validate case-insensitivity by
/// resolving a differently-cased variant of the probe file. Must stay the
/// lowercase form of `CASE_PROBE_PREFIX`.
const CASE_VALIDATION_PREFIX: &str = "msbcaseprobe";

/// Monotonic counter used to make the case-sensitivity probe name unique within
/// the process, so concurrent builders on the same mount root do not collide.
static CASE_PROBE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Per-directory casefold state has not been probed yet.
pub(crate) const CASE_UNKNOWN: u8 = 0;
/// The directory matches case-sensitively.
pub(crate) const CASE_SENSITIVE: u8 = 1;
/// The directory folds case (`FS_CASEFOLD_FL` set).
pub(crate) const CASE_INSENSITIVE: u8 = 2;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Result of matching a name or path against one case variant of the list.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CaseMatch {
    /// A hide-path pattern matched last: the entry is hidden.
    Ignore,
    /// A negation (`!`) matched last: the entry is explicitly allowed.
    Allow,
    /// No pattern matched.
    Nothing,
}

/// A matcher for a bind-mount `hide_path` list of gitignore-style patterns.
///
/// Wraps [`ignore::gitignore::Gitignore`]. The matcher is never empty; an
/// empty hide-path list matches nothing.
///
/// Matching honors the case-sensitivity of the *directory being matched*. Two
/// compiled variants are built from the same patterns: a byte-exact one and a
/// case-insensitive one. The mount default comes from the root's filesystem
/// (Windows NTFS and default macOS APFS fold case; a Linux writable mount is
/// probed and a read-only one inferred from its type), while Linux
/// casefold-capable filesystems (ext4/btrfs) can fold per directory via
/// `FS_CASEFOLD_FL`, so the caller selects the variant per directory. This
/// mirrors git's `core.ignorecase` behavior for `.gitignore`.
#[derive(Debug)]
pub(crate) struct HidePathList {
    /// Byte-exact matcher, used when the matched directory does not fold case.
    matcher_sensitive: Gitignore,
    /// Case-insensitive matcher, used when the matched directory folds case.
    ///
    /// `None` when a non-ASCII pattern is present on a case-sensitive mount: the
    /// `ignore` crate folds ASCII-only, so such a pattern cannot be matched
    /// case-insensitively. A casefold directory then fails closed instead
    /// (`is_ignored_bytes` returns `true`) rather than falling back to an
    /// under-matching insensitive matcher.
    matcher_insensitive: Option<Gitignore>,
    /// Whether the mount root itself folds case (see the type docs).
    default_case_insensitive: bool,
    /// Whether any pattern needs the full mount-relative path (has an interior
    /// `/`, i.e. a separator that is not merely a trailing dir-only marker).
    ///
    /// When `false`, every pattern matches a single component name anywhere in
    /// the tree, so entries can be checked without reconstructing the parent
    /// path.
    needs_path_reconstruction: bool,
    /// Whether any pattern is directory-only (ends with `/`, e.g. `node_modules/`).
    ///
    /// Only dir-only patterns depend on the entry's type, so callers must learn
    /// `is_dir` when this is `true`.
    has_dir_only_patterns: bool,
    /// Whether the list has no patterns (matches nothing).
    empty: bool,
}

/// RAII guard for the case-sensitivity probe file.
///
/// Removes the probe on drop so an early `?` return (for example a failed
/// write) still cleans up, leaving no artifact in the user's host directory.
#[cfg(not(target_os = "windows"))]
struct ProbeFile {
    path: PathBuf,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HidePathList {
    /// Build a matcher from the given patterns.
    ///
    /// `root` is the mount root on the host. It is probed to detect whether its
    /// filesystem is case-insensitive; when it is, patterns are matched
    /// case-insensitively (see the type docs).
    ///
    /// Patterns are parsed with gitignore semantics. An invalid pattern is a
    /// hard error: every pattern must be accepted, otherwise the hide-path list
    /// would be weaker than the caller asked for. An empty list yields a
    /// matcher that denies nothing.
    ///
    /// `readonly` reports whether the mount is read-only. On read-only mounts
    /// the case-sensitivity probe write cannot run (it fails with `EROFS`), so
    /// case-sensitivity is instead inferred from the filesystem type; see
    /// [`mount_is_case_insensitive`].
    pub(crate) fn new(root: &Path, patterns: &[String], readonly: bool) -> io::Result<Self> {
        // Skip the host-side case-insensitivity probe for the common empty-list
        // case, so hide-path-less mounts avoid creating a probe file in the root.
        let case_insensitive = !patterns.is_empty() && mount_is_case_insensitive(root, readonly);
        Self::build(patterns, case_insensitive)
    }

    /// Build a matcher with an explicit mount-root case setting.
    ///
    /// Both the case-sensitive and case-insensitive variants are compiled here,
    /// before any matching, so a later per-directory casefold decision (Linux
    /// ext4/btrfs) only selects between already-initialized matchers. Case
    /// behavior must be configured *before* the globs are added: the `ignore`
    /// crate compiles each glob with the builder's current setting, and a later
    /// change only affects globs added afterward.
    fn build(patterns: &[String], default_case_insensitive: bool) -> io::Result<Self> {
        // A mount root that already folds case cannot match a non-ASCII pattern
        // case-insensitively (`ignore` folds ASCII-only), so reject it rather
        // than silently under-match.
        if default_case_insensitive {
            for pattern in patterns {
                if !pattern.is_ascii() {
                    return Err(non_ascii_case_error(pattern));
                }
            }
        }

        let mut needs_path_reconstruction = false;
        let mut has_dir_only_patterns = false;
        for pattern in patterns {
            // Fail closed on any pattern the shared validator rejects. An empty,
            // whitespace-only, wire-hazard, leading-`#`, or non-canonical pattern
            // all compile to an empty matcher, which would make the hide-path list
            // silently weaker than the caller asked for. The shared validator is
            // the single source of truth for that contract, so the runtime cannot
            // drift from the SDK/CLI.
            microsandbox_types::validate_hide_path_pattern(pattern).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid hide-path pattern {pattern:?}: {err}"),
                )
            })?;
            needs_path_reconstruction |= pattern.trim_end_matches('/').contains('/');
            has_dir_only_patterns |= pattern.ends_with('/');
        }

        let matcher_sensitive = Self::compile(patterns, false)?;
        // The insensitive variant is only built when every pattern folds
        // correctly (ASCII); otherwise a casefold directory fails closed.
        let matcher_insensitive = patterns
            .iter()
            .all(|pattern| pattern.is_ascii())
            .then(|| Self::compile(patterns, true))
            .transpose()?;

        Ok(Self {
            matcher_sensitive,
            matcher_insensitive,
            default_case_insensitive,
            needs_path_reconstruction,
            has_dir_only_patterns,
            empty: patterns.is_empty(),
        })
    }

    /// Compile every pattern into one [`Gitignore`] with the given case setting.
    fn compile(patterns: &[String], case_insensitive: bool) -> io::Result<Gitignore> {
        let mut builder = GitignoreBuilder::new(Path::new("/"));
        builder.case_insensitive(case_insensitive).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("failed to configure hide_path matcher: {err}"),
            )
        })?;
        for pattern in patterns {
            builder.add_line(None, pattern).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid hide-path pattern {pattern:?}: {err}"),
                )
            })?;
        }
        builder.build().map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("failed to build hide_path matcher: {err}"),
            )
        })
    }

    /// Whether any pattern needs the full mount-relative path (interior `/`).
    pub(crate) fn needs_path_reconstruction(&self) -> bool {
        self.needs_path_reconstruction
    }

    /// Whether the list has no patterns and therefore matches nothing.
    pub(crate) fn is_empty(&self) -> bool {
        self.empty
    }

    /// Whether any pattern is directory-only (trailing `/`).
    pub(crate) fn has_dir_only_patterns(&self) -> bool {
        self.has_dir_only_patterns
    }

    /// The mount-root case behavior, used when a directory's casefold state is
    /// unknown or the caller has no directory to probe.
    pub(crate) fn default_case_insensitive(&self) -> bool {
        self.default_case_insensitive
    }

    /// Whether the single entry `name` matches the hide-path list.
    ///
    /// Only meaningful when [`Self::needs_path_reconstruction`] is `false`; a
    /// path pattern cannot match a bare component name. `name` is a single
    /// component, matched at any depth (gitignore component semantics).
    ///
    /// `is_dir` reports whether the entry is a directory; only dir-only
    /// patterns (trailing `/`) depend on it.
    ///
    /// Caller contract: the caller must confirm [`Self::needs_path_reconstruction`]
    /// is `false` before calling this (the `debug_assert!` enforces it in debug
    /// builds). A path pattern (interior `/`) can only be matched against the
    /// full mount-relative path, so silently calling this with path patterns
    /// would let a matching path slip through — the hide-path check must fall back
    /// to [`Self::matches_path`] instead.
    ///
    /// The Windows backend matches without a directory to probe, so it uses this
    /// mount-default variant; the Unix backends select per directory via
    /// [`Self::matches_basename_with_case`], leaving this reachable on non-Windows
    /// only from tests.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn matches_basename(&self, name: &[u8], is_dir: bool) -> bool {
        self.matches_basename_with_case(name, is_dir, self.default_case_insensitive)
    }

    /// [`Self::matches_basename`] with an explicit case setting for the directory
    /// the entry lives in.
    ///
    /// Linux ext4/btrfs can enable case folding per directory, so callers that
    /// can observe the directory's `FS_CASEFOLD_FL` pass it here instead of the
    /// mount default.
    pub(crate) fn matches_basename_with_case(
        &self,
        name: &[u8],
        is_dir: bool,
        case_insensitive: bool,
    ) -> bool {
        debug_assert!(!self.needs_path_reconstruction);
        // `.` and `..` are structural entries; denying them would break path
        // walks and directory listings. Exempt them here so every caller gets
        // the guarantee without duplicating the guard.
        if is_structural_entry(name) {
            return false;
        }
        self.is_ignored_bytes(name, is_dir, case_insensitive)
    }

    /// Whether the full mount-relative path `rel` (relative to the mount root)
    /// matches the hide-path list.
    ///
    /// Used when [`Self::needs_path_reconstruction`] is `true`.
    ///
    /// `is_dir` reports whether the entry is a directory; see
    /// [`Self::matches_basename`].
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn matches_path(&self, rel: &[u8], is_dir: bool) -> bool {
        self.matches_path_with_case(rel, is_dir, self.default_case_insensitive)
    }

    /// [`Self::matches_path`] with an explicit case setting for the directory
    /// the entry lives in.
    ///
    /// When folding is forced by a casefold directory on an otherwise
    /// case-sensitive mount (`case_insensitive` is `true` while the mount default
    /// is case-sensitive), the whole path is folded. That is safe for hide-path rules
    /// (it can only hide more) but would broaden an `!` allow rule: folding a
    /// negation lets it rescue a differently-cased sibling the hide-path rule hides.
    /// An allow may therefore only rescue a folded match when it also wins
    /// without folding, so a per-directory fold can never re-expose a path. On a
    /// mount that folds case uniformly the whole-mount fold is correct and a
    /// negation folds as git's `core.ignorecase` does.
    pub(crate) fn matches_path_with_case(
        &self,
        rel: &[u8],
        is_dir: bool,
        case_insensitive: bool,
    ) -> bool {
        if is_structural_entry(rel) {
            return false;
        }
        if case_insensitive && !self.default_case_insensitive {
            return match self.case_match(rel, is_dir, true) {
                // Denied under folding: keep it hidden.
                CaseMatch::Ignore => true,
                // Nothing matched even when folded: not denied.
                CaseMatch::Nothing => false,
                // A negation won under folding. Trust it only when a negation
                // also wins byte-exactly, so folding a negation cannot rescue a
                // differently-cased sibling of a denied path.
                CaseMatch::Allow => {
                    !matches!(self.case_match(rel, is_dir, false), CaseMatch::Allow)
                }
            };
        }
        self.is_ignored_bytes(rel, is_dir, case_insensitive)
    }

    /// Whether a single entry `name` directly under the mount-relative directory
    /// `rel_parent` matches the hide-path list.
    ///
    /// `rel_parent` is the parent directory's path relative to the mount root,
    /// using `/` separators, or the empty string for the root itself. Equivalent
    /// to matching the joined relative path, so path patterns see the entry's
    /// true location while component-only patterns keep the basename fast path.
    ///
    /// Used by the Windows passthrough backend, whose path-backed inodes
    /// re-resolve an entry by path on inode-scoped operations.
    #[cfg(windows)]
    pub(crate) fn matches_relative(&self, rel_parent: &str, name: &str, is_dir: bool) -> bool {
        if !self.needs_path_reconstruction {
            return self.matches_basename(name.as_bytes(), is_dir);
        }
        let mut rel = String::with_capacity(rel_parent.len() + name.len() + 1);
        rel.push_str(rel_parent);
        if !rel.is_empty() {
            rel.push('/');
        }
        rel.push_str(name);
        self.matches_path(rel.as_bytes(), is_dir)
    }

    fn is_ignored_bytes(&self, bytes: &[u8], is_dir: bool, case_insensitive: bool) -> bool {
        matches!(
            self.case_match(bytes, is_dir, case_insensitive),
            CaseMatch::Ignore
        )
    }

    /// Match `bytes` (a component name or mount-relative path) against the list
    /// with the given case setting, distinguishing a negation win from no match.
    ///
    /// Fails closed: a casefold directory that cannot fold a non-ASCII pattern,
    /// or a name that cannot be decoded into a path, reports
    /// [`CaseMatch::Ignore`] so the entry is never exposed by a matcher that
    /// could not evaluate it.
    fn case_match(&self, bytes: &[u8], is_dir: bool, case_insensitive: bool) -> CaseMatch {
        let matcher = if case_insensitive {
            // A casefold directory on a case-sensitive mount cannot safely fold
            // a non-ASCII pattern (`matcher_insensitive` is `None`); hide_path it
            // rather than under-match.
            match &self.matcher_insensitive {
                Some(matcher) => matcher,
                None => return CaseMatch::Ignore,
            }
        } else {
            &self.matcher_sensitive
        };
        match name_as_path(bytes) {
            Some(path) => match matcher.matched(path, is_dir) {
                Match::Ignore(_) => CaseMatch::Ignore,
                Match::Whitelist(_) => CaseMatch::Allow,
                Match::None => CaseMatch::Nothing,
            },
            // A name that cannot be decoded into a path (non-Unix invalid
            // UTF-8) can never be matched; hide_path it rather than let it bypass the
            // hide-path list. Fail closed.
            None => CaseMatch::Ignore,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[cfg(not(target_os = "windows"))]
impl Drop for ProbeFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Whether the mount should match hide-path patterns case-insensitively.
///
/// On Windows this is always `true`. NTFS supports per-directory case
/// sensitivity that a mount-root probe cannot observe, so matching the whole
/// mount case-insensitively guarantees a differently-cased name can never
/// bypass a hide-path pattern; a case-sensitive NTFS directory may over-match
/// `.env` versus `.ENV`, which is the safe direction.
#[cfg(target_os = "windows")]
fn mount_is_case_insensitive(_root: &Path, _readonly: bool) -> bool {
    true
}

/// Detect whether the filesystem holding `root` respectively the folder 'root'
/// is case-insensitive.
///
/// Almost all Linux/Unix filesystems: sensitive.
/// APFS / HFS+: insensitive by default, can be formatted case-sensitive.
/// FAT: insensitive.
/// NTFS: insensitive by default, can be configured per directory.
///
/// This detects the *mount root's* case behavior. Linux ext4/btrfs can enable
/// case folding on individual directories regardless of the root, so the Unix
/// backend additionally probes `FS_CASEFOLD_FL` per directory (see
/// [`dir_is_casefold`]) and selects the matcher's case-insensitive variant for a
/// folding directory.
///
/// On writable mounts this uses git's `core.ignorecase` probe: create a probe
/// file with a known mixed-case name, then check whether a case variant of
/// that name resolves to the same file. If it does, the filesystem folds case
/// and hide-path patterns must be matched case-insensitively. The probe requires a
/// write, so on read-only mounts (`readonly` set) it cannot run; there,
/// case-sensitivity is instead inferred from the filesystem type ([`ro_fs_is_case_sensitive`]).
///
/// A failed probe defaults to `true` (case-insensitive) rather than `false`:
/// over-matching only hides a few differently-cased names that almost never
/// coexist, whereas under-matching on a case-insensitive host would let a
/// pattern like `.env` be bypassed by requesting `.ENV`.
#[cfg(not(target_os = "windows"))]
fn mount_is_case_insensitive(root: &Path, readonly: bool) -> bool {
    if readonly {
        return !ro_fs_is_case_sensitive(root);
    }

    let seq = CASE_PROBE_SEQ.fetch_add(1, Ordering::Relaxed);
    let probe_name = format!("{CASE_PROBE_PREFIX}-{}-{seq}", std::process::id());
    let validation_name = format!("{}-{}-{seq}", CASE_VALIDATION_PREFIX, std::process::id());
    let probe_path = root.join(&probe_name);
    let validation = root.join(&validation_name);

    let result = (|| -> std::io::Result<bool> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe_path)?;
        // Create the cleanup guard only after `create_new` succeeded. If the
        // probe name already exists (a leftover from an interrupted process
        // whose PID was reused), `open` fails and dropping a guard built before
        // it would delete that pre-existing host file.
        let _guard = ProbeFile {
            path: probe_path.clone(),
        };
        std::io::Write::write_all(&mut file, b"probe")?;
        // If the case-flipped name resolves, the same file was found by a
        // differently-cased name, so the filesystem is case-insensitive.
        let insensitive = std::fs::symlink_metadata(&validation).is_ok();
        Ok(insensitive)
    })();

    // The `ProbeFile` guard removes the probe on drop, so an early `?` return
    // above cannot leave an artifact behind. A failed probe defaults to
    // case-insensitive (over-match), never error.
    result.unwrap_or(true)
}

/// Whether a read-only mount root sits on a filesystem known to be
/// case-sensitive.
///
/// On read-only mounts the case-sensitivity probe cannot create its marker
/// file, so case-sensitivity is inferred instead. Only positive proof of
/// case-sensitivity permits byte-exact matching; unknown or ambiguous
/// filesystem types report `false` (assume case-insensitive) so a hide-path list
/// over-matches rather than letting a case-variant name bypass a pattern.
#[cfg(target_os = "linux")]
fn ro_fs_is_case_sensitive(root: &Path) -> bool {
    use std::os::fd::AsRawFd;

    let Ok(dir) = std::fs::File::open(root) else {
        return false;
    };
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(dir.as_raw_fd(), &mut st) } != 0 {
        return false;
    }
    // Known case-sensitive filesystem magic numbers (ext2/3/4, xfs, btrfs,
    // tmpfs, reiserfs, jfs, bcachefs, nilfs2, ocfs2). Everything else
    // (vfat/exfat/ntfs, remote/fuseblk/cifs/nfs, f2fs, overlayfs, unknown,
    // future types) is treated as case-insensitive, because those filesystems'
    // case behavior is server-, configuration-, or per-directory-dependent and
    // cannot be positively established without a write probe. Over-matching is
    // the safe direction.
    matches!(
        st.f_type as u32,
        0x0000_EF53 // ext2/3/4
            | 0x5846_5342 // xfs
            | 0x9123_683E // btrfs
            | 0x0102_1994 // tmpfs
            | 0x5265_4973 // reiserfs
            | 0x3153_464A // jfs
            | 0xCA45_1A4E // bcachefs
            | 0x0000_3434 // nilfs2
            | 0x7461_636F // ocfs2
    )
}

/// Non-Linux hosts do not expose case-sensitivity via `statfs` (macOS APFS is
/// case-insensitive by default and its mode is not queryable here; Windows NTFS
/// is case-insensitive), so a read-only mount is assumed case-insensitive.
#[cfg(not(target_os = "linux"))]
fn ro_fs_is_case_sensitive(_root: &Path) -> bool {
    false
}

/// Join entry-name components into a relative `PathBuf`.
///
/// Used by the Unix backend to reconstruct a mount-relative path from the inode
/// anchor chain; the Windows backend matches on `str` paths instead.
#[cfg(unix)]
pub(crate) fn join_path(components: &[Vec<u8>]) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;

    let mut path = PathBuf::new();
    for component in components {
        path.push(std::ffi::OsStr::from_bytes(component));
    }
    path
}

/// Whether the raw entry bytes are the structural `.` or `..` directory entry.
fn is_structural_entry(name: &[u8]) -> bool {
    name == b"." || name == b".."
}

/// Error for a non-ASCII pattern that must be matched case-insensitively.
///
/// `ignore` folds ASCII-only, so a non-ASCII pattern would silently fail to
/// hide a differently-cased name. Rejecting it is the only honest option.
fn non_ascii_case_error(pattern: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "hide-path pattern {pattern:?} contains non-ASCII characters, which cannot be \
             matched case-insensitively on this filesystem; use an ASCII pattern or a \
             case-sensitive mount"
        ),
    )
}

/// Read the `FS_CASEFOLD_FL` flag from an open directory descriptor.
///
/// Case folding is a per-directory property on casefold-capable filesystems
/// (ext4/btrfs), so the hide_path matcher consults the directory itself instead of
/// trusting the mount-level filesystem type. Returns `None` when the flags
/// cannot be read (for example a filesystem that does not implement
/// `FS_IOC_GETFLAGS`), so callers fall back to the mount-level case behavior.
#[cfg(target_os = "linux")]
pub(crate) fn dir_is_casefold(fd: std::os::fd::RawFd) -> Option<bool> {
    // `FS_IOC_GETFLAGS` = `_IOR('f', 1, long)`; `FS_CASEFOLD_FL` is a kernel
    // inode flag shared by ext4 and btrfs.
    const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
    const FS_CASEFOLD_FL: libc::c_long = 0x4000_0000;

    let mut flags: libc::c_long = 0;
    let ret = unsafe { libc::ioctl(fd, FS_IOC_GETFLAGS, &mut flags as *mut libc::c_long) };
    if ret == 0 {
        Some(flags & FS_CASEFOLD_FL != 0)
    } else {
        None
    }
}

/// Build a `Path` from raw entry-name bytes.
///
/// On Unix the bytes are used verbatim (arbitrary non-UTF8 names are legal);
/// elsewhere they are decoded as UTF-8. Returns `None` when a non-Unix name is
/// not valid UTF-8, so the caller can fail closed instead of matching a lossy
/// empty path. The bytes must not contain a trailing NUL.
fn name_as_path(bytes: &[u8]) -> Option<&Path> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Some(Path::new(std::ffi::OsStr::from_bytes(bytes)))
    }
    #[cfg(not(unix))]
    {
        std::str::from_utf8(bytes).ok().map(|s| Path::new(s))
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hide_path(patterns: &[&str]) -> HidePathList {
        let owned: Vec<String> = patterns.iter().map(|s| s.to_string()).collect();
        let root = tempfile::tempdir().unwrap();
        HidePathList::new(root.path(), &owned, false).unwrap()
    }

    #[test]
    fn mount_is_case_insensitive_cleans_up_fs() {
        // neither for unix nor for windows we can assert the check deterministically.
        // Therefore, we only assert the probe leaves no residue.
        let root = tempfile::tempdir().unwrap();
        let _ = mount_is_case_insensitive(root.path(), false);
        let empty = std::fs::read_dir(root.path()).unwrap().count();
        assert_eq!(empty, 0);
    }

    #[test]
    fn case_probe_leaves_no_artifact_on_write_failure() {
        // A probe write that cannot complete must not leave a file behind in the
        // user's host directory. `root` is a regular file here, so creating the
        // probe beneath it fails with ENOTDIR.
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap();

        let _ = mount_is_case_insensitive(&blocker, false);

        let names: Vec<std::ffi::OsString> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("blocker")]);
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn probe_file_guard_removes_file_on_drop() {
        // The RAII guard must remove the probe file on every exit path,
        // including an early `?` return from the write/probe sequence.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("probe");
        std::fs::write(&path, b"x").unwrap();

        {
            let _guard = ProbeFile { path: path.clone() };
            assert!(path.exists());
        }

        assert!(!path.exists(), "ProbeFile must remove its file on drop");
    }

    #[test]
    fn readonly_mount_detects_case_sensitivity_without_probe() {
        // A read-only mount infers case-sensitivity from the filesystem type
        // (via `statfs`) and must never create the probe file.
        let root = tempfile::tempdir().unwrap();

        let list = HidePathList::new(root.path(), &[".env".to_string()], true).unwrap();
        let residue = std::fs::read_dir(root.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("MsBCaSePrObE"))
            .count();
        assert_eq!(
            residue, 0,
            "a read-only mount must not probe the filesystem"
        );

        // The hide-path list's effective case-sensitivity must match the detection:
        // on a case-sensitive host `.ENV` stays visible, on a case-insensitive
        // host it is hidden by the `.env` pattern.
        let case_sensitive = ro_fs_is_case_sensitive(root.path());
        assert_eq!(list.matches_basename(b".ENV", false), !case_sensitive);
    }

    #[test]
    fn case_validation_prefix_matches_probe_prefix() {
        // The probe creates `CASE_PROBE_PREFIX...` and validates by resolving
        // `CASE_VALIDATION_PREFIX...`; if the two ever drift, the case probe
        // silently mis-detects and a differently-cased name could bypass a
        // hide-path pattern. `CASE_VALIDATION_PREFIX` is a literal for const-ness,
        // so pin the relationship here.
        assert_eq!(
            CASE_VALIDATION_PREFIX,
            CASE_PROBE_PREFIX.to_ascii_lowercase()
        );
    }

    #[test]
    fn case_insensitive_matcher_folds_names() {
        // Regression: case-insensitivity must be applied when the globs are
        // added, so a pattern hides a differently-cased sibling. `build` takes
        // the setting explicitly so this holds on a case-sensitive test host.
        let patterns = vec![".env".to_string(), "node_modules/".to_string()];
        let sensitive = HidePathList::build(&patterns, false).unwrap();
        let insensitive = HidePathList::build(&patterns, true).unwrap();

        assert!(!sensitive.matches_basename(b".ENV", false));
        assert!(insensitive.matches_basename(b".ENV", false));
        assert!(insensitive.matches_basename(b".Env", false));

        assert!(!sensitive.matches_basename(b"NODE_MODULES", true));
        assert!(insensitive.matches_basename(b"NODE_MODULES", true));

        let path_patterns = vec!["sub/.env".to_string()];
        let insensitive = HidePathList::build(&path_patterns, true).unwrap();
        assert!(insensitive.matches_path(b"sub/.ENV", false));
    }

    #[test]
    fn per_directory_casefold_selects_insensitive_matcher() {
        // A mount whose root is case-sensitive can still contain a casefold
        // directory (Linux ext4/btrfs `FS_CASEFOLD_FL`). The caller selects the
        // compiled variant per directory, so the same `HidePathList` hides `.ENV`
        // only inside the folding directory.
        let list = HidePathList::build(&[".env".to_string()], false).unwrap();

        // Mount-default (case-sensitive) directory: byte-exact.
        assert!(!list.matches_basename_with_case(b".ENV", false, false));
        assert!(list.matches_basename_with_case(b".env", false, false));

        // Casefold directory: the insensitive variant folds.
        assert!(list.matches_basename_with_case(b".ENV", false, true));
        assert!(list.matches_basename_with_case(b".env", false, true));

        // Path matching selects the same way.
        let path_list = HidePathList::build(&["sub/.env".to_string()], false).unwrap();
        assert!(!path_list.matches_path_with_case(b"sub/.ENV", false, false));
        assert!(path_list.matches_path_with_case(b"sub/.ENV", false, true));
    }

    #[test]
    fn casefold_directory_with_non_ascii_pattern_fails_closed() {
        // `ignore` folds ASCII-only, so a non-ASCII pattern cannot be matched
        // case-insensitively. On a case-sensitive mount such a pattern is valid,
        // but a casefold directory must hide_path rather than fall back to an
        // under-matching insensitive matcher.
        let list = HidePathList::build(&["café".to_string()], false).unwrap();

        // Byte-exact matching on the sensitive default still works...
        assert!(list.matches_basename(b"caf\xc3\xa9", false));
        assert!(!list.matches_basename(b"other", false));

        // ...but inside a casefold directory every name fails closed.
        assert!(list.matches_basename_with_case(b"other", false, true));
    }

    #[test]
    fn non_ascii_pattern_on_case_insensitive_mount_is_rejected_or_folds() {
        // A case-insensitive mount folds with `ignore`'s ASCII-only fold, so a
        // non-ASCII pattern can never match a differently-cased name. The build
        // must therefore either reject it or truly fold it; silently accepting
        // and then under-matching is the bug this pins.
        let owned = vec!["café".to_string()];
        match HidePathList::build(&owned, true) {
            Ok(list) => assert!(
                list.matches_basename("CAFE\u{301}".as_bytes(), false),
                "a case-insensitive build must fold café to CAFÉ or reject it"
            ),
            Err(_) => {}
        }

        // On a case-sensitive mount the pattern is byte-exact and stays valid.
        assert!(HidePathList::build(&owned, false).is_ok());
    }

    #[test]
    fn ascii_folding_still_works() {
        let sensitive = HidePathList::build(&[".ENV".to_string()], false).unwrap();
        assert!(!sensitive.matches_basename(b".env", false));

        let insensitive = HidePathList::build(&[".ENV".to_string()], true).unwrap();
        assert!(insensitive.matches_basename(b".env", false));
        assert!(insensitive.matches_basename(b".Env", false));
    }

    #[test]
    fn matcher_never_matches_dot_or_dotdot() {
        // `.` and `..` are structural directory entries: denying them breaks
        // path walks and directory listings. The matcher exempts them even for a
        // catch-all pattern, so a backend need not duplicate the guard.
        let list = hide_path(&["*"]);
        assert!(!list.matches_basename(b".", true));
        assert!(!list.matches_basename(b"..", true));
        assert!(!list.matches_path(b".", true));
        assert!(!list.matches_path(b"..", true));
        // A non-structural dot-prefixed name is still matched.
        assert!(list.matches_basename(b".env", false));

        let path_list = hide_path(&["**/secret"]);
        assert!(!path_list.matches_path(b".", true));
        assert!(!path_list.matches_path(b"..", true));
    }

    #[test]
    fn empty_list_denies_nothing() {
        let list = hide_path(&[]);
        assert!(!list.matches_basename(b"anything", false));
        assert!(!list.matches_path(b"dir/anything", false));
    }

    #[test]
    fn basename_pattern_matches_anywhere() {
        let list = hide_path(&[".env", "*.log"]);
        assert!(!list.needs_path_reconstruction());
        assert!(!list.has_dir_only_patterns());
        assert!(list.matches_basename(b".env", false));
        assert!(list.matches_basename(b"debug.log", false));
        assert!(!list.matches_basename(b"env", false));
        assert!(!list.matches_basename(b"keep.log.txt", false));
        assert!(list.matches_path(b"dir/.env", false));
        assert!(list.matches_path(b"dir/debug.log", false));
    }

    #[test]
    fn path_pattern_matches_full_path() {
        let list = hide_path(&["dir/secret", "**/env.secret"]);
        assert!(list.needs_path_reconstruction());
        assert!(!list.has_dir_only_patterns());
        assert!(list.matches_path(b"dir/secret", false));
        assert!(list.matches_path(b"a/b/c/env.secret", false));
        assert!(!list.matches_path(b"dir/other", false));
        assert!(!list.matches_path(b"secret", false));
    }

    #[test]
    fn path_pattern_does_not_match_bare_component() {
        let list = hide_path(&["dir/secret"]);
        assert!(!list.matches_path(b"secret", false));
    }

    #[test]
    fn path_pattern_is_anchored_at_mount_root() {
        // A pattern containing a `/` is anchored at the mount root in gitignore
        // semantics: `dir/secret` matches only the root-level `dir/secret`, and a
        // leading `/` pins the name to the root, so `/foo` does not match a
        // component boundary such as `foobar` nor a nested `a/foo`.
        let list = hide_path(&["dir/secret"]);
        assert!(list.matches_path(b"dir/secret", false));
        assert!(!list.matches_path(b"x/dir/secret", false));
        assert!(!list.matches_path(b"dir/secret/extra", false));

        let rooted = hide_path(&["/foo"]);
        assert!(rooted.matches_path(b"foo", false));
        assert!(!rooted.matches_path(b"foobar", false));
        assert!(!rooted.matches_path(b"a/foo", false));
    }

    #[test]
    fn empty_path_matches_nothing() {
        // An empty relative path is never a real entry and does not match a
        // concrete pattern. (A catch-all `*` denies it, the fail-closed
        // direction, but production never passes an empty path.)
        let list = hide_path(&["dir/secret", ".env", "node_modules/"]);
        assert!(!list.matches_path(b"", false));
        assert!(!list.matches_path(b"", true));
    }

    #[test]
    fn bracket_pattern_matches() {
        let list = hide_path(&["[a-z]"]);
        assert!(list.matches_basename(b"a", false));
        assert!(list.matches_basename(b"z", false));
        assert!(!list.matches_basename(b"0", false));
    }

    #[test]
    fn hash_leading_pattern_is_rejected_not_silently_dropped() {
        // gitignore would treat `#secret` as a comment and enforce nothing; the
        // matcher must reject it so the hide-path list is never weaker than asked.
        let hash = vec!["#secret".to_string()];
        assert!(HidePathList::build(&hash, false).is_err());

        // An escaped literal '#' is still a valid pattern.
        let escaped = vec!["\\#secret".to_string()];
        assert!(HidePathList::build(&escaped, false).is_ok());
    }

    #[test]
    fn rejects_non_canonical_patterns() {
        // A pattern the matcher cannot enforce must fail construction rather
        // than compile to an empty matcher that silently denies nothing.
        for bad in [
            "./secret",
            "//secret",
            "a//b",
            "!",
            ".",
            "..",
            "foo//",
            "a/./b",
            "a/../b",
            "../secret",
            "./a",
        ] {
            let owned = vec![(*bad).to_string()];
            assert!(
                HidePathList::build(&owned, false).is_err(),
                "expected {bad:?} to be rejected"
            );
        }

        for ok in [
            ".env",
            "sub/.env",
            "**/env.secret",
            "node_modules/",
            "\\#x",
            "!keep.txt",
            "..foo",
            "...",
            "a/..foo/b",
        ] {
            let owned = vec![(*ok).to_string()];
            assert!(
                HidePathList::build(&owned, false).is_ok(),
                "expected {ok:?} to be accepted"
            );
        }
    }

    #[test]
    fn rejects_empty_and_whitespace_only_patterns() {
        // An empty or whitespace-only pattern is accepted by gitignore and
        // compiles to an empty matcher, so the hide-path list would silently enforce
        // nothing. `HidePathList::build` must refuse it instead.
        for bad in ["", " ", "\t", "  .env  "] {
            let owned = vec![bad.to_string()];
            assert!(
                HidePathList::build(&owned, false).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn invalid_pattern_is_rejected() {
        let owned: Vec<String> = ["[a-z".to_string(), "{".to_string()].to_vec();
        let root = tempfile::tempdir().unwrap();
        let result = HidePathList::new(root.path(), &owned, false);
        assert!(
            result.is_err(),
            "an invalid pattern must fail the hide_path-list build"
        );
    }

    #[test]
    fn bracket_pattern_with_unclosed_class_is_literal() {
        let list = hide_path(&["[a-z"]);
        assert!(!list.matches_basename(b"a", false));
    }

    #[test]
    fn dir_only_path_pattern_matches_directory_but_not_file() {
        let list = hide_path(&["node_modules/"]);
        assert!(!list.needs_path_reconstruction());
        assert!(list.has_dir_only_patterns());
        assert!(list.matches_basename(b"node_modules", true));
        assert!(!list.matches_basename(b"node_modules", false));
        assert!(list.matches_path(b"node_modules", true));
        assert!(!list.matches_path(b"node_modules", false));
        assert!(!list.matches_path(b"node_modules.js", false));
    }

    #[test]
    fn dir_only_nested_path_pattern_matches_directory_but_not_file() {
        let list = hide_path(&["sub/node_modules/"]);
        assert!(list.needs_path_reconstruction());
        assert!(list.has_dir_only_patterns());
        assert!(list.matches_path(b"sub/node_modules", true));
        assert!(!list.matches_path(b"sub/node_modules", false));
        assert!(!list.matches_path(b"sub/node_modules.js", false));
    }

    #[test]
    fn interior_slash_pattern_needs_path_reconstruction() {
        let list = hide_path(&["sub/.env"]);
        assert!(list.needs_path_reconstruction());
        assert!(!list.has_dir_only_patterns());
    }

    #[test]
    fn trailing_slash_dir_only_uses_basename_fast_path() {
        let list = hide_path(&["node_modules/"]);
        assert!(!list.needs_path_reconstruction());
        assert!(list.has_dir_only_patterns());
        assert!(list.matches_basename(b"node_modules", true));
        assert!(!list.matches_basename(b"node_modules", false));
        assert!(!list.matches_basename(b"node_modules.js", false));
    }

    #[test]
    fn mixed_component_and_path_patterns_set_both_flags() {
        let list = hide_path(&["node_modules/", "sub/.env"]);
        assert!(list.needs_path_reconstruction());
        assert!(list.has_dir_only_patterns());
    }

    #[test]
    fn negation_enables_allowlist_mode() {
        let list = hide_path(&["*", "!keep.txt"]);
        assert!(list.matches_basename(b"other.txt", false));
        assert!(!list.matches_basename(b"keep.txt", false));
        assert!(list.matches_basename(b".env", false));
    }

    #[test]
    fn ancestor_fold_does_not_broaden_a_negation() {
        // `fold` folds case on an otherwise case-sensitive mount, but `Data` does
        // not, so `secret` and `SECRET` are distinct files. The hide_path must hide
        // `secret` even though the allow rule targets `SECRET`; folding the
        // negation must not rescue the differently-cased sibling.
        let patterns = vec![
            "fold/Data/secret".to_string(),
            "!fold/Data/SECRET".to_string(),
        ];
        let list = HidePathList::build(&patterns, false).unwrap();

        assert!(list.matches_path_with_case(b"fold/DATA/secret", false, true));
        // The allow rule itself only resolves by folding, so the conservative
        // rule also hides its own spelling rather than risk exposing a sibling.
        assert!(list.matches_path_with_case(b"fold/DATA/SECRET", false, true));
    }

    #[test]
    fn ancestor_fold_keeps_an_exactly_matching_allowlist() {
        // An allow rule that wins byte-exactly stays effective under a
        // per-directory fold; only negations that need folding are distrusted.
        let patterns = vec!["sub/*".to_string(), "!sub/keep.txt".to_string()];
        let list = HidePathList::build(&patterns, false).unwrap();

        assert!(!list.matches_path_with_case(b"sub/keep.txt", false, true));
        assert!(list.matches_path_with_case(b"sub/other.txt", false, true));
    }

    #[test]
    fn uniform_case_insensitive_mount_folds_a_negation() {
        // On a mount that folds case uniformly, `secret` and `SECRET` are the same
        // entry, so the differently-cased allow rule must still apply.
        let list =
            HidePathList::build(&["secret".to_string(), "!SECRET".to_string()], true).unwrap();
        assert!(!list.matches_path_with_case(b"secret", false, true));
    }
}
