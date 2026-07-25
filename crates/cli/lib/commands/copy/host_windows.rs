//! Reparse-safe host filesystem operations for Windows sandbox copy-out.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::path::{Component, Path};

use anyhow::Context;
use tokio::io::AsyncWriteExt;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
};
use windows_sys::Win32::Foundation::{
    HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_BASIC_INFO, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
    FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FileAttributeTagInfo, FileBasicInfo,
    FileDispositionInfo, GetFileInformationByHandleEx, SYNCHRONIZE, SetFileInformationByHandle,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum retries when a destination entry changes during safe replacement.
const MAX_COMPONENT_ATTEMPTS: usize = 128;

/// Share mode used so handles do not unnecessarily block normal filesystem activity.
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

/// Access needed on a pinned directory that will receive copied children.
const DIRECTORY_ACCESS: u32 = FILE_LIST_DIRECTORY
    | FILE_ADD_FILE
    | FILE_ADD_SUBDIRECTORY
    | FILE_TRAVERSE
    | FILE_READ_ATTRIBUTES
    | FILE_WRITE_ATTRIBUTES
    | SYNCHRONIZE;

/// Access needed on a copied regular file.
const FILE_ACCESS: u32 =
    FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE;

/// Access used to inspect an entry without following its reparse point.
const INSPECT_ACCESS: u32 = FILE_READ_ATTRIBUTES | SYNCHRONIZE;

/// Access used to remove a reparse point after verifying the opened handle.
const DELETE_ACCESS: u32 = DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE;

/// Options common to synchronous, reparse-safe relative opens.
const SAFE_OPEN_OPTIONS: u32 = FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A destination directory pinned before any guest-derived path is materialized.
pub(super) struct CopyRoot {
    directory: File,
}

/// A regular file opened without traversing any reparse point.
pub(super) struct PendingFile {
    file: tokio::fs::File,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CopyRoot {
    /// Open and pin the operator-selected destination directory.
    ///
    /// Normal Win32 path resolution is intentional here so trusted paths may
    /// contain junctions or symlinks. Every sandbox-derived component below
    /// this handle is opened relative to it with reparse processing disabled.
    pub(super) fn open(path: &Path) -> anyhow::Result<Self> {
        let directory = OpenOptions::new()
            .access_mode(FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
            .share_mode(SHARE_ALL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .with_context(|| format!("open copy destination root {}", path.display()))?;
        Ok(Self { directory })
    }

    /// Construct a copy root from an already pinned directory.
    pub(super) fn from_directory(directory: File) -> Self {
        Self { directory }
    }

    /// Create or open a directory without processing any reparse component.
    pub(super) fn ensure_directory(&self, path: &Path) -> anyhow::Result<File> {
        let mut current = self
            .directory
            .try_clone()
            .context("duplicate copy root handle")?;

        for component in normal_components(path)? {
            current = open_or_create_directory(&current, component)
                .with_context(|| format!("open destination directory {}", path.display()))?;
        }

        Ok(current)
    }

    /// Open an existing directory without processing any reparse component.
    fn open_directory(&self, path: &Path) -> anyhow::Result<File> {
        let mut current = self
            .directory
            .try_clone()
            .context("duplicate copy root handle")?;

        for component in normal_components(path)? {
            current = open_existing_directory(&current, component)
                .with_context(|| format!("open destination directory {}", path.display()))?;
        }

        Ok(current)
    }

    /// Open or create a regular file without following a reparse point.
    pub(super) fn create_file(&self, path: &Path) -> anyhow::Result<PendingFile> {
        let parent_path = path.parent().unwrap_or_else(|| Path::new(""));
        let parent = self.open_directory(parent_path)?;
        let name = final_component(path)?;
        let file = open_or_create_file(&parent, name)
            .with_context(|| format!("create copied file {}", path.display()))?;

        Ok(PendingFile {
            file: tokio::fs::File::from_std(file),
        })
    }
}

impl PendingFile {
    /// Return the file receiving guest content.
    pub(super) fn file_mut(&mut self) -> &mut tokio::fs::File {
        &mut self.file
    }

    /// Flush copied content and apply the Windows readonly equivalent of the guest mode.
    pub(super) async fn commit(mut self, mode: u32) -> anyhow::Result<()> {
        self.file.flush().await.context("flush copied file")?;
        let file = self.file.into_std().await;
        set_readonly_mode(&file, mode).context("set copied file mode")
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Apply the Windows readonly equivalent of guest permission bits to a pinned directory.
pub(super) fn set_directory_mode(directory: &File, mode: u32) -> anyhow::Result<()> {
    set_readonly_mode(directory, mode).context("set copied directory mode")
}

/// Return the normal components of a path relative to the pinned copy root.
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
fn final_component(path: &Path) -> anyhow::Result<&OsStr> {
    path.file_name()
        .ok_or_else(|| anyhow::anyhow!("destination path {} has no file name", path.display()))
}

/// Open or create one directory component, replacing only verified reparse points.
fn open_or_create_directory(parent: &File, name: &OsStr) -> io::Result<File> {
    for _ in 0..MAX_COMPONENT_ATTEMPTS {
        match open_relative(
            parent,
            name,
            DIRECTORY_ACCESS,
            FILE_OPEN,
            FILE_ATTRIBUTE_DIRECTORY,
            SAFE_OPEN_OPTIONS | FILE_DIRECTORY_FILE,
        ) {
            Ok(directory) if is_reparse_point(&directory)? => {
                drop(directory);
                remove_reparse_point(parent, name)?;
            }
            Ok(directory) => return Ok(directory),
            Err(open_error) if open_error.kind() == io::ErrorKind::NotFound => {
                match open_relative(
                    parent,
                    name,
                    DIRECTORY_ACCESS,
                    FILE_CREATE,
                    FILE_ATTRIBUTE_DIRECTORY,
                    SAFE_OPEN_OPTIONS | FILE_DIRECTORY_FILE,
                ) {
                    Ok(directory) => return Ok(directory),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error),
                }
            }
            Err(open_error) => {
                if remove_if_reparse_point(parent, name)? {
                    continue;
                }
                return Err(open_error);
            }
        }
    }

    Err(io::Error::other(
        "destination directory changed too often during safe creation",
    ))
}

/// Open one existing directory component and reject every reparse point.
fn open_existing_directory(parent: &File, name: &OsStr) -> io::Result<File> {
    let directory = open_relative(
        parent,
        name,
        DIRECTORY_ACCESS,
        FILE_OPEN,
        FILE_ATTRIBUTE_DIRECTORY,
        SAFE_OPEN_OPTIONS | FILE_DIRECTORY_FILE,
    )?;
    if is_reparse_point(&directory)? {
        return Err(io::Error::other(
            "refusing to traverse a destination reparse point",
        ));
    }
    Ok(directory)
}

/// Open or create one regular file, replacing only verified reparse points.
fn open_or_create_file(parent: &File, name: &OsStr) -> io::Result<File> {
    for _ in 0..MAX_COMPONENT_ATTEMPTS {
        match open_relative(
            parent,
            name,
            FILE_ACCESS,
            FILE_OPEN,
            FILE_ATTRIBUTE_NORMAL,
            SAFE_OPEN_OPTIONS | FILE_NON_DIRECTORY_FILE,
        ) {
            Ok(file) if is_reparse_point(&file)? => {
                drop(file);
                remove_reparse_point(parent, name)?;
            }
            Ok(file) => {
                file.set_len(0)?;
                return Ok(file);
            }
            Err(open_error) if open_error.kind() == io::ErrorKind::NotFound => {
                match open_relative(
                    parent,
                    name,
                    FILE_ACCESS,
                    FILE_CREATE,
                    FILE_ATTRIBUTE_NORMAL,
                    SAFE_OPEN_OPTIONS | FILE_NON_DIRECTORY_FILE,
                ) {
                    Ok(file) => return Ok(file),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error),
                }
            }
            Err(open_error) => {
                if remove_if_reparse_point(parent, name)? {
                    continue;
                }
                return Err(open_error);
            }
        }
    }

    Err(io::Error::other(
        "destination file changed too often during safe creation",
    ))
}

/// Probe an entry without following it and remove it only if it is still a reparse point.
fn remove_if_reparse_point(parent: &File, name: &OsStr) -> io::Result<bool> {
    let entry = match open_relative(
        parent,
        name,
        INSPECT_ACCESS,
        FILE_OPEN,
        FILE_ATTRIBUTE_NORMAL,
        SAFE_OPEN_OPTIONS,
    ) {
        Ok(entry) => entry,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(error),
    };

    if !is_reparse_point(&entry)? {
        return Ok(false);
    }
    drop(entry);
    remove_reparse_point(parent, name)?;
    Ok(true)
}

/// Delete a named entry after reopening and verifying the exact reparse point handle.
fn remove_reparse_point(parent: &File, name: &OsStr) -> io::Result<()> {
    let entry = open_relative(
        parent,
        name,
        DELETE_ACCESS,
        FILE_OPEN,
        FILE_ATTRIBUTE_NORMAL,
        SAFE_OPEN_OPTIONS,
    )?;
    if !is_reparse_point(&entry)? {
        return Err(io::Error::other(
            "destination entry changed while replacing a reparse point",
        ));
    }

    clear_readonly_attribute(&entry)?;
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    let result = unsafe {
        SetFileInformationByHandle(
            entry.as_raw_handle() as HANDLE,
            FileDispositionInfo,
            std::ptr::from_ref(&disposition).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    drop(entry);
    Ok(())
}

/// Return whether an opened entry is any kind of Windows reparse point.
fn is_reparse_point(file: &File) -> io::Result<bool> {
    let mut information = FILE_ATTRIBUTE_TAG_INFO::default();
    let result = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileAttributeTagInfo,
            std::ptr::from_mut(&mut information).cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
}

/// Clear a readonly attribute before deleting a verified reparse point.
fn clear_readonly_attribute(file: &File) -> io::Result<()> {
    let mut information = basic_information(file)?;
    if information.FileAttributes & FILE_ATTRIBUTE_READONLY != 0 {
        information.FileAttributes &= !FILE_ATTRIBUTE_READONLY;
        if information.FileAttributes == 0 {
            information.FileAttributes = FILE_ATTRIBUTE_NORMAL;
        }
        set_basic_information(file, &information)?;
    }
    Ok(())
}

/// Apply guest write permission as the closest Windows readonly equivalent.
fn set_readonly_mode(file: &File, mode: u32) -> io::Result<()> {
    let mut information = basic_information(file)?;
    if mode & 0o222 == 0 {
        information.FileAttributes |= FILE_ATTRIBUTE_READONLY;
    } else {
        information.FileAttributes &= !FILE_ATTRIBUTE_READONLY;
        if information.FileAttributes == 0 {
            information.FileAttributes = FILE_ATTRIBUTE_NORMAL;
        }
    }
    set_basic_information(file, &information)
}

/// Read basic attributes from an already verified file handle.
fn basic_information(file: &File) -> io::Result<FILE_BASIC_INFO> {
    let mut information = FILE_BASIC_INFO::default();
    let result = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileBasicInfo,
            std::ptr::from_mut(&mut information).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(information)
}

/// Write basic attributes through an already verified file handle.
fn set_basic_information(file: &File, information: &FILE_BASIC_INFO) -> io::Result<()> {
    let result = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as HANDLE,
            FileBasicInfo,
            std::ptr::from_ref(information).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Open or create one name relative to a pinned directory handle.
fn open_relative(
    parent: &File,
    name: &OsStr,
    desired_access: u32,
    disposition: u32,
    attributes: u32,
    options: u32,
) -> io::Result<File> {
    let mut wide_name: Vec<u16> = name.encode_wide().collect();
    if wide_name.is_empty() || wide_name.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination component is empty or contains NUL",
        ));
    }
    let byte_length = wide_name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "component is too long"))?;
    let unicode_name = UNICODE_STRING {
        Length: byte_length,
        MaximumLength: byte_length,
        Buffer: wide_name.as_mut_ptr(),
    };
    let object_attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle() as HANDLE,
        ObjectName: std::ptr::from_ref(&unicode_name),
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut handle = INVALID_HANDLE_VALUE;
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            desired_access,
            &object_attributes,
            &mut io_status,
            std::ptr::null(),
            attributes,
            SHARE_ALL,
            disposition,
            options,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        let win32_error = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(win32_error as i32));
    }
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(io::Error::other(
            "NtCreateFile succeeded without returning a handle",
        ));
    }

    Ok(unsafe { File::from_raw_handle(handle as RawHandle) })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::os::windows::fs::{symlink_dir, symlink_file};

    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test]
    async fn copied_file_replaces_symlink_without_following_it() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("root");
        let victim_path = temp.path().join("victim");
        std::fs::create_dir(&root_path).unwrap();
        std::fs::write(&victim_path, b"original").unwrap();
        if symlink_file(&victim_path, root_path.join("payload")).is_err() {
            // Symlink creation requires Developer Mode or elevated privileges
            // on older Windows installations.
            return;
        }

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
    fn intermediate_directory_replaces_symlink_without_traversing_it() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("root");
        let outside_path = temp.path().join("outside");
        std::fs::create_dir(&root_path).unwrap();
        std::fs::create_dir(&outside_path).unwrap();
        if symlink_dir(&outside_path, root_path.join("directory")).is_err() {
            return;
        }

        let root = CopyRoot::open(&root_path).unwrap();
        root.ensure_directory(Path::new("directory/child")).unwrap();

        assert!(root_path.join("directory/child").is_dir());
        assert!(!outside_path.join("child").exists());
    }
}
