//! Deny-list matcher for bind mounts.
//!
//! A `deny` list is a set of gitignore-style patterns that hide matching
//! paths from a bind mount, enforced host-side in the passthrough backend.
//! Component-only patterns (no `/`, e.g. `.env`, `*.log`) are matched against
//! the entry name anywhere in the tree (gitignore semantics). Path patterns
//! (containing `/`, e.g. `dir/secret`, `**/env.secret`) are matched against
//! the full path relative to the mount root.
//!
//! Cross-platform: the matcher lives at the passthrough level so both the
//! Unix and Windows passthrough backends can use it.
//!
//! Deny is enforced only at name-taking entry points (lookup, create, mkdir,
//! unlink, rename, readdir, ...). Inode-scoped operations that reuse an already
//! resolved inode (`open` for write, `setattr`, `write`) are deliberately not
//! deny-checked: lookup returns `ENOENT` for a denied name, so the guest can
//! never obtain the inode of a hidden entry in the first place.

use std::io;
use std::path::{Path, PathBuf};
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
/// Probe file prefix lowercased, used to validate case-insensitivity.
fn case_validation_prefix() -> String {
    CASE_PROBE_PREFIX.to_ascii_lowercase()
}

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A matcher for a bind-mount `deny` list of gitignore-style patterns.
///
/// Wraps [`ignore::gitignore::Gitignore`]. The matcher is never empty; an
/// empty deny list matches nothing.
///
/// Matching honors the case-sensitivity of the mount root's filesystem. When
/// the root sits on a case-insensitive filesystem (Windows NTFS, default
/// macOS APFS, etc.), patterns and candidate names are folded so a pattern like
/// `.env` also hides `.ENV` and `.Env`; otherwise matching is byte-exact. This
/// mirrors git's `core.ignorecase` behavior for `.gitignore`.
#[derive(Debug)]
pub(crate) struct DenyList {
    matcher: Gitignore,
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
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DenyList {
    /// Build a matcher from the given patterns.
    ///
    /// `root` is the mount root on the host. It is probed to detect whether its
    /// filesystem is case-insensitive; when it is, patterns are matched
    /// case-insensitively (see the type docs).
    ///
    /// Patterns are parsed with gitignore semantics. An invalid pattern is a
    /// hard error: every pattern must be accepted, otherwise the deny list
    /// would be weaker than the caller asked for. An empty list yields a
    /// matcher that denies nothing.
    ///
    /// `readonly` reports whether the mount is read-only. On read-only mounts
    /// the case-sensitivity probe write cannot run (it fails with `EROFS`), so
    /// case-sensitivity is instead inferred from the filesystem type; see
    /// [`mount_is_case_insensitive`].
    pub(crate) fn new(root: &Path, patterns: &[String], readonly: bool) -> io::Result<Self> {
        let mut builder = GitignoreBuilder::new(Path::new("/"));
        let mut needs_path_reconstruction = false;
        let mut has_dir_only_patterns = false;
        for pattern in patterns {
            needs_path_reconstruction |= pattern.trim_end_matches('/').contains('/');
            has_dir_only_patterns |= pattern.ends_with('/');
            builder.add_line(None, pattern).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid deny pattern {pattern:?}: {err}"),
                )
            })?;
        }
        // Skip the host-side case-insensitivity probe for the common empty-list
        // case, so deny-less mounts avoid creating a probe file in the root.
        if !patterns.is_empty() {
            let _ = builder.case_insensitive(mount_is_case_insensitive(root, readonly));
        }
        let matcher = builder.build().map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("failed to build deny matcher: {err}"),
            )
        })?;
        Ok(Self {
            matcher,
            needs_path_reconstruction,
            has_dir_only_patterns,
        })
    }

    /// Whether any pattern needs the full mount-relative path (interior `/`).
    pub(crate) fn needs_path_reconstruction(&self) -> bool {
        self.needs_path_reconstruction
    }

    /// Whether any pattern is directory-only (trailing `/`).
    pub(crate) fn has_dir_only_patterns(&self) -> bool {
        self.has_dir_only_patterns
    }

    /// Whether the single entry `name` matches the deny list.
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
    /// would let a matching path slip through — the deny check must fall back
    /// to [`Self::matches_path`] instead.
    pub(crate) fn matches_basename(&self, name: &[u8], is_dir: bool) -> bool {
        debug_assert!(!self.needs_path_reconstruction);
        self.is_ignored(name_as_path(name), is_dir)
    }

    /// Whether the full mount-relative path `rel` (relative to the mount root)
    /// matches the deny list.
    ///
    /// Used when [`Self::needs_path_reconstruction`] is `true`.
    ///
    /// `is_dir` reports whether the entry is a directory; see
    /// [`Self::matches_basename`].
    pub(crate) fn matches_path(&self, rel: &[u8], is_dir: bool) -> bool {
        self.is_ignored(name_as_path(rel), is_dir)
    }

    fn is_ignored(&self, path: &Path, is_dir: bool) -> bool {
        matches!(self.matcher.matched(path, is_dir), Match::Ignore(_))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Monotonic counter used to make the case-sensitivity probe name unique within
/// the process, so concurrent builders on the same mount root do not collide.
static CASE_PROBE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Detect whether the filesystem holding `root` respectively the folder 'root'
/// is case-insensitive.
///
/// Almost all Linux/Unix filesystems: sensitive.
/// APFS / HFS+: insensitive by default, can be formatted case-sensitive.
/// FAT: insensitive.
/// NTFS: insensitive by default, can be configured per directory.
///
/// We don't detect case sensitivity per directory, but per mount.
///
/// On writable mounts this uses git's `core.ignorecase` probe: create a probe
/// file with a known mixed-case name, then check whether a case variant of
/// that name resolves to the same file. If it does, the filesystem folds case
/// and deny patterns must be matched case-insensitively. The probe requires a
/// write, so on read-only mounts (`readonly` set) it cannot run; there,
/// case-sensitivity is instead inferred from the filesystem type ([`ro_fs_is_case_sensitive`]).
///
/// A failed probe defaults to `true` (case-insensitive) rather than `false`:
/// over-matching only hides a few differently-cased names that almost never
/// coexist, whereas under-matching on a case-insensitive host would let a
/// pattern like `.env` be bypassed by requesting `.ENV`.
fn mount_is_case_insensitive(root: &Path, readonly: bool) -> bool {
    if readonly {
        return !ro_fs_is_case_sensitive(root);
    }

    let seq = CASE_PROBE_SEQ.fetch_add(1, Ordering::Relaxed);
    let probe_name = format!("{CASE_PROBE_PREFIX}-{}-{seq}", std::process::id());
    let validation_name = format!("{}-{}-{seq}", case_validation_prefix(), std::process::id());
    let probe = root.join(&probe_name);
    let validation = root.join(&validation_name);

    let result = (|| -> std::io::Result<bool> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)?;
        std::io::Write::write_all(&mut file, b"probe")?;
        // If the case-flipped name resolves, the same file was found by a
        // differently-cased name, so the filesystem is case-insensitive.
        let insensitive = std::fs::symlink_metadata(&validation).is_ok();
        std::fs::remove_file(&probe)?;
        Ok(insensitive)
    })();

    result.unwrap_or(true)
}

/// Whether a read-only mount root sits on a filesystem known to be
/// case-sensitive.
///
/// On read-only mounts the case-sensitivity probe cannot create its marker
/// file, so case-sensitivity is inferred instead. Only positive proof of
/// case-sensitivity permits byte-exact matching; unknown or ambiguous
/// filesystem types report `false` (assume case-insensitive) so a deny list
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
    // tmpfs, reiserfs, jfs, f2fs, bcachefs, nilfs2, ocfs2). Everything else
    // (overlayfs, vfat/exfat/ntfs, remote/fuseblk/cifs/nfs, unknown, future
    // types) is treated as case-insensitive.
    matches!(
        st.f_type as u32,
        0x0000_EF53 // ext2/3/4
            | 0x5846_5342 // xfs
            | 0x9123_683E // btrfs
            | 0x0102_1994 // tmpfs
            | 0x5265_4973 // reiserfs
            | 0x3153_464A // jfs
            | 0xF2F5_2010 // f2fs
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
/// Used to reconstruct a mount-relative path from the inode anchor chain.
pub(crate) fn join_path(components: &[Vec<u8>]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let mut path = PathBuf::new();
        for component in components {
            path.push(std::ffi::OsStr::from_bytes(component));
        }
        path
    }
    #[cfg(not(unix))]
    {
        let mut path = PathBuf::new();
        for component in components {
            path.push(String::from_utf8_lossy(component).into_owned());
        }
        path
    }
}

/// Build a `Path` from raw entry-name bytes.
///
/// On Unix the bytes are used verbatim (arbitrary non-UTF8 names are legal);
/// elsewhere they are treated lossily. The bytes must not contain a trailing
/// NUL.
fn name_as_path(bytes: &[u8]) -> &Path {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Path::new(std::ffi::OsStr::from_bytes(bytes))
    }
    #[cfg(not(unix))]
    {
        Path::new(std::str::from_utf8(bytes).unwrap_or(""))
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn deny(patterns: &[&str]) -> DenyList {
        let owned: Vec<String> = patterns.iter().map(|s| s.to_string()).collect();
        let root = tempfile::tempdir().unwrap();
        DenyList::new(root.path(), &owned, false).unwrap()
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
    fn readonly_mount_detects_case_sensitivity_without_probe() {
        // A read-only mount infers case-sensitivity from the filesystem type
        // (via `statfs`) and must never create the probe file.
        let root = tempfile::tempdir().unwrap();

        let list = DenyList::new(root.path(), &[".env".to_string()], true).unwrap();
        let residue = std::fs::read_dir(root.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("MsBCaSePrObE"))
            .count();
        assert_eq!(
            residue, 0,
            "a read-only mount must not probe the filesystem"
        );

        // The deny list's effective case-sensitivity must match the detection:
        // on a case-sensitive host `.ENV` stays visible, on a case-insensitive
        // host it is hidden by the `.env` pattern.
        let case_sensitive = ro_fs_is_case_sensitive(root.path());
        assert_eq!(list.matches_basename(b".ENV", false), !case_sensitive);
    }

    #[test]
    fn empty_list_denies_nothing() {
        let list = deny(&[]);
        assert!(!list.matches_basename(b"anything", false));
        assert!(!list.matches_path(b"dir/anything", false));
    }

    #[test]
    fn basename_pattern_matches_anywhere() {
        let list = deny(&[".env", "*.log"]);
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
        let list = deny(&["dir/secret", "**/env.secret"]);
        assert!(list.needs_path_reconstruction());
        assert!(!list.has_dir_only_patterns());
        assert!(list.matches_path(b"dir/secret", false));
        assert!(list.matches_path(b"a/b/c/env.secret", false));
        assert!(!list.matches_path(b"dir/other", false));
        assert!(!list.matches_path(b"secret", false));
    }

    #[test]
    fn path_pattern_does_not_match_bare_component() {
        let list = deny(&["dir/secret"]);
        assert!(!list.matches_path(b"secret", false));
    }

    #[test]
    fn bracket_pattern_matches() {
        let list = deny(&["[a-z]"]);
        assert!(list.matches_basename(b"a", false));
        assert!(list.matches_basename(b"z", false));
        assert!(!list.matches_basename(b"0", false));
    }

    #[test]
    fn invalid_pattern_is_rejected() {
        let owned: Vec<String> = ["[a-z".to_string(), "{".to_string()].to_vec();
        let root = tempfile::tempdir().unwrap();
        let result = DenyList::new(root.path(), &owned, false);
        assert!(
            result.is_err(),
            "an invalid pattern must fail the deny-list build"
        );
    }

    #[test]
    fn bracket_pattern_with_unclosed_class_is_literal() {
        let list = deny(&["[a-z"]);
        assert!(!list.matches_basename(b"a", false));
    }

    #[test]
    fn dir_only_path_pattern_matches_directory_but_not_file() {
        let list = deny(&["node_modules/"]);
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
        let list = deny(&["sub/node_modules/"]);
        assert!(list.needs_path_reconstruction());
        assert!(list.has_dir_only_patterns());
        assert!(list.matches_path(b"sub/node_modules", true));
        assert!(!list.matches_path(b"sub/node_modules", false));
        assert!(!list.matches_path(b"sub/node_modules.js", false));
    }

    #[test]
    fn interior_slash_pattern_needs_path_reconstruction() {
        let list = deny(&["sub/.env"]);
        assert!(list.needs_path_reconstruction());
        assert!(!list.has_dir_only_patterns());
    }

    #[test]
    fn trailing_slash_dir_only_uses_basename_fast_path() {
        let list = deny(&["node_modules/"]);
        assert!(!list.needs_path_reconstruction());
        assert!(list.has_dir_only_patterns());
        assert!(list.matches_basename(b"node_modules", true));
        assert!(!list.matches_basename(b"node_modules", false));
        assert!(!list.matches_basename(b"node_modules.js", false));
    }

    #[test]
    fn mixed_component_and_path_patterns_set_both_flags() {
        let list = deny(&["node_modules/", "sub/.env"]);
        assert!(list.needs_path_reconstruction());
        assert!(list.has_dir_only_patterns());
    }

    #[test]
    fn negation_enables_allowlist_mode() {
        let list = deny(&["*", "!keep.txt"]);
        assert!(list.matches_basename(b"other.txt", false));
        assert!(!list.matches_basename(b"keep.txt", false));
        assert!(list.matches_basename(b".env", false));
    }
}
