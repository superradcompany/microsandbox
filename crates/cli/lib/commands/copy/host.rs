//! Race-resistant host filesystem operations for sandbox copy-out.

use std::ffi::{CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use tokio::io::AsyncWriteExt;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Private mode used while a copied directory is still being populated.
const WORKING_DIRECTORY_MODE: libc::mode_t = 0o700;

/// Private mode used while a copied file is still being populated.
const WORKING_FILE_MODE: libc::mode_t = 0o600;

/// Number of unique temporary names to try before reporting contention.
const MAX_TEMP_NAME_ATTEMPTS: usize = 128;

/// Counter mixed into temporary names to avoid collisions within this process.
static NEXT_TEMP_NAME: AtomicU64 = AtomicU64::new(0);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A destination directory pinned before any guest-derived path is materialized.
pub(super) struct CopyRoot {
    directory: File,
}

/// A file written under a temporary name and atomically installed on commit.
pub(super) struct PendingFile {
    file: tokio::fs::File,
    parent: File,
    temporary_name: CString,
    destination_name: CString,
    committed: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CopyRoot {
    /// Open the operator-selected destination directory and pin its inode.
    ///
    /// The operator path may itself use trusted host symlinks. Guest-derived
    /// paths are handled only after this directory has been opened, and every
    /// component below it is subsequently resolved with `O_NOFOLLOW`.
    pub(super) fn open(path: &Path) -> anyhow::Result<Self> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open(path)
            .with_context(|| format!("open copy destination root {}", path.display()))?;
        Ok(Self { directory })
    }

    /// Construct a copy root from an already pinned directory.
    pub(super) fn from_directory(directory: File) -> Self {
        Self { directory }
    }

    /// Create or open a directory without following any guest-controlled component.
    pub(super) fn ensure_directory(&self, path: &Path) -> anyhow::Result<File> {
        let mut current = duplicate_fd(&self.directory).context("duplicate copy root handle")?;

        for component in normal_components(path)? {
            let name = cstring_component(component)?;
            match open_directory_at(current.as_raw_fd(), &name) {
                Ok(next) => current = next,
                Err(open_error) => {
                    if is_symlink_at(current.as_raw_fd(), &name)? {
                        // This removes only the named entry beneath the pinned
                        // parent. A concurrent replacement can make the copy
                        // fail, but it cannot redirect the unlink elsewhere.
                        unlink_at(current.as_raw_fd(), &name)?;
                    } else if open_error.kind() != io::ErrorKind::NotFound {
                        return Err(open_error).with_context(|| {
                            format!("open destination directory {}", path.display())
                        });
                    }

                    mkdir_at(current.as_raw_fd(), &name)?;
                    current = open_directory_at(current.as_raw_fd(), &name).with_context(|| {
                        format!("open newly created directory {}", path.display())
                    })?;
                }
            }
        }

        Ok(current)
    }

    /// Open an existing directory without following any guest-controlled component.
    fn open_directory(&self, path: &Path) -> anyhow::Result<File> {
        let mut current = duplicate_fd(&self.directory).context("duplicate copy root handle")?;
        for component in normal_components(path)? {
            let name = cstring_component(component)?;
            current = open_directory_at(current.as_raw_fd(), &name)
                .with_context(|| format!("open destination directory {}", path.display()))?;
        }
        Ok(current)
    }

    /// Create a temporary regular file beside `path` for atomic installation.
    pub(super) fn create_file(&self, path: &Path) -> anyhow::Result<PendingFile> {
        let parent_path = path.parent().unwrap_or_else(|| Path::new(""));
        let parent = self.open_directory(parent_path)?;
        let destination_name = final_component(path)?;

        for _ in 0..MAX_TEMP_NAME_ATTEMPTS {
            let temporary_name = temporary_name()?;
            match create_file_at(parent.as_raw_fd(), &temporary_name) {
                Ok(file) => {
                    return Ok(PendingFile {
                        file: tokio::fs::File::from_std(file),
                        parent,
                        temporary_name,
                        destination_name,
                        committed: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("create temporary file for {}", path.display()));
                }
            }
        }

        anyhow::bail!(
            "could not allocate a temporary name while copying {}",
            path.display()
        )
    }

    /// Atomically replace `path` with a symlink beneath the pinned root.
    pub(super) fn replace_symlink(&self, path: &Path, target: &Path) -> anyhow::Result<()> {
        let parent_path = path.parent().unwrap_or_else(|| Path::new(""));
        let parent = self.open_directory(parent_path)?;
        let destination_name = final_component(path)?;
        let target = CString::new(target.as_os_str().as_bytes())
            .with_context(|| format!("symlink target for {} contains NUL", path.display()))?;

        for _ in 0..MAX_TEMP_NAME_ATTEMPTS {
            let temporary_name = temporary_name()?;
            match symlink_at(&target, parent.as_raw_fd(), &temporary_name) {
                Ok(()) => {
                    let rename_result = rename_at(
                        parent.as_raw_fd(),
                        &temporary_name,
                        parent.as_raw_fd(),
                        &destination_name,
                    );
                    if rename_result.is_err() {
                        let _ = unlink_at(parent.as_raw_fd(), &temporary_name);
                    }
                    return rename_result
                        .with_context(|| format!("install symlink at {}", path.display()));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("create symlink at {}", path.display()));
                }
            }
        }

        anyhow::bail!(
            "could not allocate a temporary name while copying symlink {}",
            path.display()
        )
    }
}

impl PendingFile {
    /// Return the temporary file receiving guest content.
    pub(super) fn file_mut(&mut self) -> &mut tokio::fs::File {
        &mut self.file
    }

    /// Set the final mode and atomically replace the destination entry.
    pub(super) async fn commit(mut self, mode: u32) -> anyhow::Result<()> {
        self.file.flush().await.context("flush copied file")?;
        set_fd_mode(self.file.as_raw_fd(), mode).context("set copied file mode")?;
        rename_at(
            self.parent.as_raw_fd(),
            &self.temporary_name,
            self.parent.as_raw_fd(),
            &self.destination_name,
        )
        .context("install copied file")?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for PendingFile {
    fn drop(&mut self) {
        if !self.committed {
            let _ = unlink_at(self.parent.as_raw_fd(), &self.temporary_name);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Apply guest permission bits to an already opened destination inode.
pub(super) fn set_directory_mode(directory: &File, mode: u32) -> anyhow::Result<()> {
    set_fd_mode(directory.as_raw_fd(), mode).context("set copied directory mode")
}

/// Return the normal components of a path that is relative to the copy root.
fn normal_components(path: &Path) -> anyhow::Result<Vec<&OsStr>> {
    path.components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => anyhow::bail!(
                "destination path {} is not relative to the copy root",
                path.display()
            ),
        })
        .collect()
}

/// Return the final normal component of a root-relative path.
fn final_component(path: &Path) -> anyhow::Result<CString> {
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("destination path {} has no file name", path.display()))?;
    cstring_component(name)
}

/// Convert a single filesystem name to a C string.
fn cstring_component(name: &OsStr) -> anyhow::Result<CString> {
    if name.as_bytes().contains(&b'/') {
        anyhow::bail!("destination component contains a path separator");
    }
    CString::new(name.as_bytes()).context("destination component contains NUL")
}

/// Duplicate a directory handle without re-resolving its pathname.
fn duplicate_fd(file: &File) -> io::Result<File> {
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Open one directory component without following a symlink.
fn open_directory_at(parent: RawFd, name: &CString) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Create one directory component beneath an opened parent.
fn mkdir_at(parent: RawFd, name: &CString) -> io::Result<()> {
    let result = unsafe { libc::mkdirat(parent, name.as_ptr(), WORKING_DIRECTORY_MODE) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(error);
        }
    }
    Ok(())
}

/// Return whether an entry is currently a symlink without following it.
fn is_symlink_at(parent: RawFd, name: &CString) -> io::Result<bool> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let result =
        unsafe { libc::fstatat(parent, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(false);
        }
        return Err(error);
    }
    Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFLNK)
}

/// Remove one non-directory entry beneath an opened parent.
fn unlink_at(parent: RawFd, name: &CString) -> io::Result<()> {
    let result = unsafe { libc::unlinkat(parent, name.as_ptr(), 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Create a private temporary file beneath an opened parent.
fn create_file_at(parent: RawFd, name: &CString) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            libc::c_uint::from(WORKING_FILE_MODE),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Create a symlink beneath an opened parent.
fn symlink_at(target: &CString, parent: RawFd, name: &CString) -> io::Result<()> {
    let result = unsafe { libc::symlinkat(target.as_ptr(), parent, name.as_ptr()) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Atomically replace one entry beneath an opened parent.
fn rename_at(
    old_parent: RawFd,
    old_name: &CString,
    new_parent: RawFd,
    new_name: &CString,
) -> io::Result<()> {
    let result =
        unsafe { libc::renameat(old_parent, old_name.as_ptr(), new_parent, new_name.as_ptr()) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Apply only Unix permission bits to an opened inode.
fn set_fd_mode(fd: RawFd, mode: u32) -> io::Result<()> {
    let result = unsafe { libc::fchmod(fd, (mode & 0o7777) as libc::mode_t) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Generate a process-local temporary name used only beneath a pinned parent.
fn temporary_name() -> anyhow::Result<CString> {
    let sequence = NEXT_TEMP_NAME.fetch_add(1, Ordering::Relaxed);
    CString::new(format!(".msb-copy-{}-{sequence}", std::process::id()))
        .context("temporary copy name contains NUL")
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test]
    async fn copied_file_replaces_symlink_without_following_it() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("root");
        let victim_path = temp.path().join("victim");
        std::fs::create_dir(&root_path).unwrap();
        std::fs::write(&victim_path, b"original").unwrap();
        symlink(&victim_path, root_path.join("payload")).unwrap();

        let root = CopyRoot::open(&root_path).unwrap();
        let mut pending = root.create_file(Path::new("payload")).unwrap();
        pending.file_mut().write_all(b"guest data").await.unwrap();
        pending.commit(0o644).await.unwrap();

        assert_eq!(std::fs::read(&victim_path).unwrap(), b"original");
        assert_eq!(
            std::fs::read(root_path.join("payload")).unwrap(),
            b"guest data"
        );
        assert!(
            !std::fs::symlink_metadata(root_path.join("payload"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn guest_directory_replaces_symlink_without_following_it() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("root");
        let outside_path = temp.path().join("outside");
        std::fs::create_dir(&root_path).unwrap();
        std::fs::create_dir(&outside_path).unwrap();
        symlink(&outside_path, root_path.join("directory")).unwrap();

        let root = CopyRoot::open(&root_path).unwrap();
        root.ensure_directory(Path::new("directory")).unwrap();

        assert!(root_path.join("directory").is_dir());
        assert!(
            !std::fs::symlink_metadata(root_path.join("directory"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}
