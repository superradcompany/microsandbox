//! Capability-scoped access to a named volume's host directory.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::Dir;

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A pinned root plus its names, used only to translate existing in-root absolute symlinks.
/// All filesystem access uses `dir`, never the translated ambient host path.
pub struct RootedVolumeFs {
    /// The pinned directory; callers must use only relative capability operations.
    pub dir: Dir,
    root_name: PathBuf,
    root_link: Option<(Dir, OsString)>,
}

/// Retain the selected root's identity while releasing its delete-blocking capability.
#[cfg(windows)]
struct WindowsRootRemoval {
    parent: std::fs::File,
    name: OsString,
    // This handle shares deletion and is only used for identity checks, never access.
    identity: Dir,
}

/// Pin the nearest existing ancestor before recreating a missing volume root.
struct MissingRoot {
    parent: Dir,
    names: Vec<OsString>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RootedVolumeFs {
    /// Follow a relocated root once, then keep the selected directory pinned.
    pub fn open(root: &Path) -> MicrosandboxResult<Self> {
        let dir = Dir::open_ambient_dir(root, ambient_authority())?;
        let root_name = root.canonicalize()?;
        // Canonicalization and opening are separate operations. Verify that the
        // name still identifies our capability before using it to translate links.
        if !same_directory(
            &dir,
            &Dir::open_ambient_dir(&root_name, ambient_authority())?,
        )? {
            return Err(path_escape());
        }
        let root_link = if std::fs::symlink_metadata(root)?.file_type().is_symlink() {
            let parent = root.parent().ok_or_else(path_escape)?;
            let name = root.file_name().ok_or_else(path_escape)?.to_owned();
            Some((Dir::open_ambient_dir(parent, ambient_authority())?, name))
        } else {
            None
        };
        Ok(Self {
            dir,
            root_name,
            root_link,
        })
    }

    /// Recreate missing root directories for Go's MkdirAll contract.
    pub fn open_or_create(root: &Path) -> MicrosandboxResult<Self> {
        match Self::open(root) {
            Ok(opened) => return Ok(opened),
            Err(MicrosandboxError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let created = MissingRoot::prepare(root)?.create()?;
        let opened = Self::open(root)?;
        // A concurrent replacement of the ambient name cannot select a different
        // root after capability-relative creation has selected its directory.
        if !same_directory(&created, &opened.dir)? {
            return Err(path_escape());
        }
        Ok(opened)
    }

    /// Resolve the parent but preserve the final directory entry itself.
    /// Inspection, unlink and rename must also work for dangling symlinks.
    pub fn resolve_entry(&self, path: &str) -> MicrosandboxResult<PathBuf> {
        let path = Path::new(path.trim_start_matches('/'));
        match path.components().next_back() {
            Some(Component::Normal(name)) => {
                let parent = path.parent().unwrap_or_else(|| Path::new(""));
                Ok(self
                    .resolve(parent.to_str().ok_or_else(path_escape)?)?
                    .join(name))
            }
            _ => self.resolve(path.to_str().ok_or_else(path_escape)?),
        }
    }

    /// Delete the selected root and its contents, for Go's RemoveAll contract.
    pub fn remove_root(self) -> MicrosandboxResult<()> {
        self.remove_root_with_mode(true)
    }

    /// Delete only an empty root, retaining Go's nonrecursive Remove contract.
    pub fn remove_empty_root(self) -> MicrosandboxResult<()> {
        self.remove_root_with_mode(false)
    }

    fn remove_root_with_mode(mut self, recursive: bool) -> MicrosandboxResult<()> {
        // os.RemoveAll on a symlinked root unlinks the root link, leaving the
        // relocated directory intact. Never recurse through this ambient name.
        if let Some((parent, name)) = self.root_link.take() {
            #[cfg(unix)]
            parent.remove_file(name)?;
            #[cfg(windows)]
            {
                let entry = crate::sandbox::windows_open_relative_for_removal(
                    &parent.into_std_file(),
                    &name,
                )?;
                use std::os::windows::fs::MetadataExt;
                if entry.metadata()?.file_attributes() & 0x400 == 0 {
                    return Err(path_escape());
                }
                crate::sandbox::windows_remove_open_entry(entry)?;
            }
            return Ok(());
        }
        #[cfg(not(windows))]
        if recursive {
            self.dir.remove_open_dir_all()?;
        } else {
            // Let the OS check emptiness atomically; never enumerate then recurse.
            self.dir.remove_open_dir()?;
        }
        #[cfg(windows)]
        WindowsRootRemoval::prepare(self)?.remove(recursive)?;
        Ok(())
    }

    /// Translate alternate absolute spellings only after verifying the real root.
    fn relative_target(&self, target: &Path) -> MicrosandboxResult<PathBuf> {
        let mut ancestor = target.to_owned();
        let mut suffix = Vec::new();
        let canonical = loop {
            match ancestor.canonicalize() {
                Ok(path) => break path,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let component = ancestor.components().next_back().ok_or_else(path_escape)?;
                    match component {
                        Component::Normal(name) => suffix.push(name.to_owned()),
                        Component::ParentDir => suffix.push(OsString::from("..")),
                        _ => return Err(path_escape()),
                    }
                    ancestor.pop();
                }
                Err(error) => return Err(error.into()),
            }
        };
        let named_root = Dir::open_ambient_dir(&self.root_name, ambient_authority())?;
        if !same_directory(&self.dir, &named_root)? {
            return Err(path_escape());
        }
        let mut relative = canonical
            .strip_prefix(&self.root_name)
            .map_err(|_| path_escape())?
            .to_owned();
        for part in suffix.into_iter().rev() {
            relative.push(part);
        }
        // The result is used only through `dir`: a later alias/name replacement
        // cannot turn this verified in-root destination into ambient access.
        Ok(relative)
    }

    /// Resolve link semantics without using the result as an ambient pathname.
    ///
    /// Existing APIs follow final symlinks and allow `..` within the volume. Resolve
    /// those components in order, including dangling links and missing suffixes. The
    /// final capability operation resolves again under the pinned root, so swapping
    /// a component after this walk cannot redirect the operation outside the volume.
    pub fn resolve(&self, path: &str) -> MicrosandboxResult<PathBuf> {
        // Public volume paths use a leading slash to denote this volume's root.
        let mut pending = components(Path::new(path.trim_start_matches('/')))?;
        let mut resolved = PathBuf::new();
        let mut followed = 0;
        while let Some(component) = pending.pop_front() {
            if component == ".." {
                if !resolved.pop() {
                    return Err(path_escape());
                }
                continue;
            }
            let candidate = resolved.join(&component);
            match self.dir.symlink_metadata(&candidate) {
                Ok(metadata) if metadata.is_symlink() => {
                    followed += 1;
                    if followed > 40 {
                        return Err(MicrosandboxError::SandboxFsOps(
                            "too many symlinks within volume root".into(),
                        ));
                    }
                    let target = self.dir.read_link_contents(&candidate)?;
                    let target = if target.is_absolute() {
                        resolved.clear();
                        self.relative_target(&target)?
                    } else {
                        target
                    };
                    let mut link_components = components(&target)?;
                    link_components.append(&mut pending);
                    pending = link_components;
                }
                Ok(metadata) => {
                    if !pending.is_empty() && !metadata.is_dir() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::NotADirectory,
                            "volume path component is not a directory",
                        )
                        .into());
                    }
                    resolved.push(component);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    // Do not erase `missing/..`: reads must still report the missing
                    // directory, while writes can create parents with normal OS semantics.
                    // The capability operation validates any links that appear afterward.
                    let mut depth = resolved.components().count() + 1;
                    resolved.push(component);
                    for remainder in pending {
                        if remainder == ".." {
                            depth = depth.checked_sub(1).ok_or_else(path_escape)?;
                        } else {
                            depth += 1;
                        }
                        resolved.push(remainder);
                    }
                    return Ok(resolved);
                }
                Err(error) => return Err(error.into()),
            }
        }
        if resolved.as_os_str().is_empty() {
            resolved.push(".");
        }
        Ok(resolved)
    }

    /// Remove a directory tree without reopening an ambient path on Windows.
    pub fn remove_dir_all(&self, path: &Path) -> std::io::Result<()> {
        #[cfg(windows)]
        {
            let name = path.file_name().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "remove_dir cannot target the volume root",
                )
            })?;
            let parent_path = path.parent().unwrap_or_else(|| Path::new("."));
            let parent = if parent_path.as_os_str().is_empty() {
                self.dir.try_clone()?
            } else {
                self.dir.open_dir(parent_path)?
            }
            .into_std_file();
            let entry = crate::sandbox::windows_open_relative_for_removal(&parent, name)?;
            if !entry.metadata()?.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotADirectory,
                    "recursive directory removal requires a directory",
                ));
            }
            crate::sandbox::windows_remove_open_entry(entry)?;
        }
        #[cfg(not(windows))]
        self.dir.remove_dir_all(path)?;
        Ok(())
    }

    /// Create parents through the pinned directory capability.
    pub fn ensure_parent(&self, path: &Path) -> MicrosandboxResult<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            self.dir.create_dir_all(parent)?;
        }
        Ok(())
    }
}

#[cfg(windows)]
impl WindowsRootRemoval {
    fn prepare(root: RootedVolumeFs) -> MicrosandboxResult<Self> {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        let parent = root.root_name.parent().ok_or_else(path_escape)?;
        let name = root
            .root_name
            .file_name()
            .ok_or_else(path_escape)?
            .to_owned();
        let parent = Dir::open_ambient_dir(parent, ambient_authority())?.into_std_file();
        // cap-std roots deny FILE_SHARE_DELETE, so a DELETE handle cannot coexist
        // with them. First pin the same object's identity without requesting DELETE.
        // Keeping this handle alive also prevents file-ID reuse during the handoff.
        let identity = Dir::from_std_file(
            std::fs::OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&root.root_name)?,
        );
        if !same_directory(&root.dir, &identity)? {
            return Err(path_escape());
        }
        drop(root);
        Ok(Self {
            parent,
            name,
            identity,
        })
    }

    fn remove(self, recursive: bool) -> MicrosandboxResult<()> {
        // After releasing the capability, the name can change. Open without
        // following a replacement link and verify identity before any deletion.
        let entry = crate::sandbox::windows_open_relative_for_removal(&self.parent, &self.name)?;
        let selected = Dir::from_std_file(entry.try_clone()?);
        if !same_directory(&self.identity, &selected)? {
            return Err(path_escape());
        }
        drop(selected);
        drop(self.identity);
        if recursive {
            crate::sandbox::windows_remove_open_entry(entry)?;
        } else {
            // FileDispositionInfo rejects a nonempty directory without deleting
            // any descendants, using the same identity-checked deletion handle.
            crate::sandbox::windows_mark_delete(&entry)?;
        }
        Ok(())
    }
}

impl MissingRoot {
    fn prepare(root: &Path) -> MicrosandboxResult<Self> {
        let mut ancestor = root;
        let mut names = Vec::new();
        loop {
            match Dir::open_ambient_dir(ancestor, ambient_authority()) {
                Ok(parent) => return Ok(Self { parent, names }),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    names.push(ancestor.file_name().ok_or_else(path_escape)?.to_owned());
                    ancestor = ancestor.parent().ok_or_else(path_escape)?;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn create(self) -> MicrosandboxResult<Dir> {
        let mut parent = self.parent;
        for name in self.names.into_iter().rev() {
            let mut options = cap_std::fs::DirBuilder::new();
            options.recursive(false);
            #[cfg(unix)]
            {
                use cap_std::fs::DirBuilderExt;
                options.mode(0o755);
            }
            match parent.create_dir_with(&name, &options) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            // Each newly appearing component must be a real directory. Following
            // a concurrent symlink here could create descendants outside our root.
            parent = Dir::from_std_file(cap_primitives::fs::open_dir_nofollow(
                &parent.into_std_file(),
                Path::new(&name),
            )?);
        }
        Ok(parent)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn same_directory(left: &Dir, right: &Dir) -> std::io::Result<bool> {
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;
        let left = left.dir_metadata()?;
        let right = right.dir_metadata()?;
        Ok(left.dev() == right.dev() && left.ino() == right.ino())
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let identify = |dir: &Dir| -> std::io::Result<(u32, u32, u32)> {
            let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
            // Both handles remain owned for the duration of this identity check.
            if unsafe { GetFileInformationByHandle(dir.as_raw_handle(), info.as_mut_ptr()) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let info = unsafe { info.assume_init() };
            Ok((
                info.dwVolumeSerialNumber,
                info.nFileIndexHigh,
                info.nFileIndexLow,
            ))
        };
        Ok(identify(left)? == identify(right)?)
    }
}

fn components(path: &Path) -> MicrosandboxResult<VecDeque<OsString>> {
    path.components()
        .filter_map(|component| match component {
            Component::CurDir => None,
            Component::Normal(name) => Some(Ok(name.to_owned())),
            Component::ParentDir => Some(Ok(OsString::from(".."))),
            // Reject drive-relative names, UNC paths, and rooted Windows backslash paths.
            Component::Prefix(_) | Component::RootDir => Some(Err(path_escape())),
        })
        .collect()
}

fn path_escape() -> MicrosandboxError {
    MicrosandboxError::SandboxFsOps("path traversal outside volume root".into())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn missing_root_creation_stays_with_its_pinned_parent() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("parent");
        let moved = temp.path().join("moved");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let missing = MissingRoot::prepare(&parent.join("nested/volume")).unwrap();
        std::fs::rename(&parent, &moved).unwrap();
        std::os::unix::fs::symlink(&outside, &parent).unwrap();

        let selected = missing.create().unwrap();
        selected.write("marker", b"inside").unwrap();
        assert_eq!(
            std::fs::read(moved.join("nested/volume/marker")).unwrap(),
            b"inside"
        );
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    }

    #[test]
    fn missing_root_creation_rejects_a_new_symlink_component() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("missing/volume");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let missing = MissingRoot::prepare(&root).unwrap();
        std::os::unix::fs::symlink(&outside, temp.path().join("missing")).unwrap();

        assert!(missing.create().is_err());
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    }

    #[test]
    fn mutations_stay_confined_after_a_resolved_component_is_swapped() {
        let temp = tempfile::tempdir().unwrap();
        let volume = temp.path().join("volume");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(volume.join("nested")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"outside").unwrap();
        std::fs::write(volume.join("source"), b"inside").unwrap();
        let root = RootedVolumeFs::open(&volume).unwrap();
        let destination = root.resolve("nested/sentinel").unwrap();
        let directory = root.resolve("nested").unwrap();

        // Deterministically swap the directory in the old check/use window.
        std::fs::remove_dir(volume.join("nested")).unwrap();
        symlink(&outside, volume.join("nested")).unwrap();

        assert!(root.dir.read(&destination).is_err());
        assert!(root.dir.write(&destination, b"overwrite").is_err());
        assert!(root.dir.create(&destination).is_err());
        assert!(root.dir.create_dir_all(directory.join("new")).is_err());
        assert!(root.dir.read_dir(&directory).is_err());
        assert!(root.dir.metadata(&destination).is_err());
        assert!(root.dir.try_exists(&destination).is_err());
        assert!(root.dir.remove_file(&destination).is_err());
        assert!(root.dir.copy("source", &root.dir, &destination).is_err());
        assert!(root.dir.rename("source", &root.dir, &destination).is_err());
        // Recursive deletion may remove the symlink itself, but cannot enter its target.
        let _ = root.remove_dir_all(&directory);
        assert_eq!(std::fs::read(outside.join("sentinel")).unwrap(), b"outside");
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 1);
    }

    #[test]
    fn root_cleanup_cannot_delete_a_replacement_tree() {
        let temp = tempfile::tempdir().unwrap();
        let volume = temp.path().join("volume");
        let moved = temp.path().join("moved");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&volume).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(volume.join("file"), b"inside").unwrap();
        std::fs::write(outside.join("sentinel"), b"outside").unwrap();
        let root = RootedVolumeFs::open(&volume).unwrap();
        std::fs::rename(&volume, &moved).unwrap();
        symlink(&outside, &volume).unwrap();
        root.remove_root().unwrap();
        assert!(!moved.exists());
        assert_eq!(std::fs::read(outside.join("sentinel")).unwrap(), b"outside");
    }

    #[test]
    fn alternate_absolute_link_cannot_redirect_access_after_resolution() {
        let temp = tempfile::tempdir().unwrap();
        let volume = temp.path().join("volume");
        let alias = temp.path().join("alias");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&volume).unwrap();
        std::fs::create_dir(&outside).unwrap();
        symlink(&volume, &alias).unwrap();
        symlink(alias.join("file"), volume.join("link")).unwrap();
        std::fs::write(volume.join("file"), b"inside").unwrap();
        std::fs::write(outside.join("file"), b"outside").unwrap();
        let root = RootedVolumeFs::open(&volume).unwrap();
        let destination = root.resolve("link").unwrap();
        std::fs::remove_file(&alias).unwrap();
        symlink(&outside, &alias).unwrap();
        root.dir.write(destination, b"updated").unwrap();
        assert_eq!(std::fs::read(volume.join("file")).unwrap(), b"updated");
        assert_eq!(std::fs::read(outside.join("file")).unwrap(), b"outside");
        assert!(root.resolve("link").is_err());
    }

    #[test]
    fn opened_root_remains_the_same_directory_after_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let volume = temp.path().join("volume");
        let moved = temp.path().join("moved");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&volume).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(volume.join("sentinel"), b"inside").unwrap();
        std::fs::write(outside.join("sentinel"), b"outside").unwrap();
        let root = RootedVolumeFs::open(&volume).unwrap();
        std::fs::rename(&volume, &moved).unwrap();
        symlink(&outside, &volume).unwrap();

        assert_eq!(
            root.dir.read(root.resolve("sentinel").unwrap()).unwrap(),
            b"inside"
        );
        assert_eq!(
            RootedVolumeFs::open(&volume)
                .unwrap()
                .dir
                .read("sentinel")
                .unwrap(),
            b"outside"
        );
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn missing_root_creation_rejects_a_new_junction_component() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("missing/volume");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let missing = MissingRoot::prepare(&root).unwrap();
        junction(&temp.path().join("missing"), &outside);

        assert!(missing.create().is_err());
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    }

    #[test]
    fn recursive_removal_does_not_follow_descendant_junctions() {
        let temp = tempfile::tempdir().unwrap();
        let volume = temp.path().join("volume");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(volume.join("remove/nested")).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(volume.join("remove/nested/file"), b"inside").unwrap();
        std::fs::write(outside.join("sentinel"), b"outside").unwrap();
        junction(&volume.join("remove/link"), &outside);
        let root = RootedVolumeFs::open(&volume).unwrap();

        root.remove_dir_all(&root.resolve("remove").unwrap())
            .unwrap();

        assert!(!volume.join("remove").exists());
        assert_eq!(std::fs::read(outside.join("sentinel")).unwrap(), b"outside");
    }

    #[test]
    fn junction_swap_after_resolution_cannot_redirect_a_write() {
        let temp = tempfile::tempdir().unwrap();
        let volume = temp.path().join("volume");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(volume.join("nested")).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"outside").unwrap();
        let root = RootedVolumeFs::open(&volume).unwrap();
        let path = root.resolve("nested/sentinel").unwrap();
        std::fs::remove_dir(volume.join("nested")).unwrap();
        junction(&volume.join("nested"), &outside);

        assert!(root.dir.write(path, b"changed").is_err());
        assert_eq!(std::fs::read(outside.join("sentinel")).unwrap(), b"outside");
    }

    #[test]
    fn junction_root_and_alternate_spelling_are_supported() {
        let temp = tempfile::tempdir().unwrap();
        let actual = temp.path().join("actual");
        std::fs::create_dir(&actual).unwrap();
        std::fs::write(actual.join("file"), b"inside").unwrap();
        let volume = temp.path().join("volume");
        let shortcut = temp.path().join("shortcut");
        junction(&volume, &actual);
        junction(&shortcut, &actual);
        junction(&actual.join("internal-link"), &shortcut);
        let root = RootedVolumeFs::open(&volume).unwrap();
        assert_eq!(
            root.dir
                .read(root.resolve("internal-link/file").unwrap())
                .unwrap(),
            b"inside"
        );
        assert_eq!(
            root.dir.read(root.resolve("file").unwrap()).unwrap(),
            b"inside"
        );
        assert_eq!(
            root.relative_target(&shortcut.join("file")).unwrap(),
            Path::new("file")
        );
        root.remove_root().unwrap();
        assert!(!volume.exists());
        assert_eq!(std::fs::read(actual.join("file")).unwrap(), b"inside");
    }

    #[test]
    fn root_cleanup_removes_directory_without_following_junctions() {
        let temp = tempfile::tempdir().unwrap();
        let volume = temp.path().join("volume");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(volume.join("nested")).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"outside").unwrap();
        junction(&volume.join("nested").join("link"), &outside);
        let root = RootedVolumeFs::open(&volume).unwrap();
        root.remove_root().unwrap();
        assert!(!volume.exists());
        assert_eq!(std::fs::read(outside.join("sentinel")).unwrap(), b"outside");
    }

    #[test]
    fn root_cleanup_rejects_replacement_during_handle_handoff() {
        for replace_with_junction in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let volume = temp.path().join("volume");
            let moved = temp.path().join("moved");
            let outside = temp.path().join("outside");
            std::fs::create_dir(&volume).unwrap();
            std::fs::create_dir(&outside).unwrap();
            std::fs::write(volume.join("original"), b"original").unwrap();
            std::fs::write(outside.join("sentinel"), b"outside").unwrap();
            let removal =
                WindowsRootRemoval::prepare(RootedVolumeFs::open(&volume).unwrap()).unwrap();

            // Exercise the exact interval where deletion sharing allows replacement.
            std::fs::rename(&volume, &moved).unwrap();
            if replace_with_junction {
                junction(&volume, &outside);
            } else {
                std::fs::create_dir(&volume).unwrap();
                std::fs::write(volume.join("replacement"), b"replacement").unwrap();
            }
            assert!(removal.remove(true).is_err());
            assert_eq!(std::fs::read(moved.join("original")).unwrap(), b"original");
            assert_eq!(std::fs::read(outside.join("sentinel")).unwrap(), b"outside");
            if !replace_with_junction {
                assert_eq!(
                    std::fs::read(volume.join("replacement")).unwrap(),
                    b"replacement"
                );
            }
        }
    }

    fn junction(link: &Path, target: &Path) {
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link.as_os_str().to_string_lossy().replace('/', "\\"))
            .arg(target.as_os_str().to_string_lossy().replace('/', "\\"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
