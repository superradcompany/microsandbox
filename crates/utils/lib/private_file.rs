//! Owner-private file permissions for newly created storage and non-mutating inspection.
//!
//! These helpers operate on one caller-owned object, not its ancestors. Callers must first
//! establish namespace authority and exclude symlinks/reparse points and concurrent replacement.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io;
use std::path::Path;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Create a new owner-private file without following an existing path.
///
/// Unix creation starts at `0600` before the name is visible, then restores owner access if the
/// inherited umask is more restrictive. Windows inherits the parent directory's ACL; callers
/// should use this only beneath a storage parent whose publication policy they already checked.
pub fn create_new(path: &Path) -> io::Result<File> {
    create_new_with_access(path, false, false)
}

/// Create a new owner-private file opened for reading and writing.
///
/// See [`create_new`] for the parent-directory and platform guarantees.
pub fn create_new_read_write(path: &Path) -> io::Result<File> {
    create_new_with_access(path, true, false)
}

/// Create a new owner-private file opened for appending.
pub fn create_new_append(path: &Path) -> io::Result<File> {
    create_new_with_access(path, false, true)
}

/// Create missing directories with owner-only access, leaving existing directories unchanged.
///
/// Callers remain responsible for verifying the authority and intended sharing policy of
/// existing ancestors. On Unix, every directory created by the recursive operation starts at
/// `0700`, so a permissive process umask cannot expose new host-managed storage.
pub fn create_private_dir_all(path: &Path) -> io::Result<()> {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => return Ok(()),
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "private storage path is not a directory",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let components = path.components().collect::<Vec<_>>();
    let mut current = std::path::PathBuf::new();
    for component in components {
        current.push(component.as_os_str());
        match std::fs::metadata(&current) {
            Ok(metadata) if metadata.is_dir() => continue,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "private storage path component is not a directory",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match create_private_directory(&current) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        if !std::fs::metadata(&current)?.is_dir() {
                            return Err(io::Error::other(
                                "private storage path changed during directory creation",
                            ));
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Create one new owner-private directory, failing if its name already exists.
pub fn create_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)?;
    }
    #[cfg(not(unix))]
    DirBuilder::new().create(path)?;
    let directory = open_directory(path)?;
    // Apply ACL and mode restrictions through the opened directory, not by resolving the path
    // again. macOS inherits extended ACLs when creating children even when their mode is 0700.
    if let Err(error) = harden(&directory, true) {
        drop(directory);
        let _ = std::fs::remove_dir(path);
        return Err(error);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = directory.metadata()?;
        let current = std::fs::symlink_metadata(path)?;
        if !current.is_dir() || opened.dev() != current.dev() || opened.ino() != current.ino() {
            return Err(io::Error::other(
                "private storage directory changed during creation",
            ));
        }
    }
    Ok(())
}

/// Tighten an existing directory after its namespace has been authorized by the caller.
pub fn harden_existing_directory(path: &Path) -> io::Result<()> {
    let directory = open_directory(path)?;
    harden(&directory, true)
}

/// Tighten an existing single-link regular file after its namespace has been authorized.
#[cfg(unix)]
pub fn harden_existing_file(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(io::Error::other(
            "private storage must be a single-link regular file",
        ));
    }
    harden(&file, false)
}

fn open_directory(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options
            .access_mode(0x0006_0080)
            .share_mode(0x7)
            .custom_flags(0x0220_0000);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() {
        return Err(io::Error::other("private storage entry is not a directory"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(io::Error::other(
                "private storage cannot use reparse points",
            ));
        }
    }
    Ok(file)
}

fn create_new_with_access(path: &Path, read: bool, append: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .read(read)
        .append(append)
        .create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    if let Err(error) = harden(&file, false) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(error);
    }
    Ok(file)
}

/// Remove inherited grants from a newly created object and grant only its owner access.
/// The caller must not use this to adopt an untrusted existing object's contents.
pub fn harden(file: &File, directory: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if file.metadata()?.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::other(
                "private storage is owned by another account",
            ));
        }
        file.set_permissions(std::fs::Permissions::from_mode(if directory {
            0o700
        } else {
            0o600
        }))?;
        // Restrict the mode first. On Linux this narrows a POSIX ACL's mask before removal,
        // which also lets repair handle owner-only read-only files without a write-open.
        #[cfg(target_os = "linux")]
        linux_acl::clear(file, directory)?;
        #[cfg(target_os = "macos")]
        macos::clear(file)?;
    }
    #[cfg(windows)]
    windows::harden(file, directory)?;
    verify(file)
}

#[cfg(target_os = "linux")]
mod linux_acl {
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;

    pub(super) fn clear(file: &File, directory: bool) -> io::Result<()> {
        let attributes: &[&[u8]] = if directory {
            &[b"system.posix_acl_access\0", b"system.posix_acl_default\0"]
        } else {
            &[b"system.posix_acl_access\0"]
        };

        for attribute in attributes {
            let result = unsafe { libc::fremovexattr(file.as_raw_fd(), attribute.as_ptr().cast()) };
            if result == 0 {
                continue;
            }

            let error = io::Error::last_os_error();
            if error.raw_os_error().is_some_and(|code| {
                code == libc::ENODATA || code == libc::ENOTSUP || code == libc::EOPNOTSUPP
            }) {
                continue;
            }
            return Err(error);
        }

        Ok(())
    }
}

/// Verify one object's ownership and access policy without changing permissions or contents.
pub fn verify(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::other("storage is not private to its owner"));
        }
        #[cfg(target_os = "macos")]
        macos::verify(file)?;
    }
    #[cfg(windows)]
    windows::verify_policy(file, windows::Policy::Private)?;
    Ok(())
}

/// Verify a Windows namespace ancestor without rejecting harmless read/traverse grants.
/// Unlike `verify`, this checks path substitution rather than confidentiality of its contents.
/// Every selected child must already exist and be checked separately: creating an unrelated
/// sibling file or directory does not authorize replacing that existing protected child.
#[cfg(windows)]
pub fn verify_ancestor(file: &File) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
        return Err(io::Error::other(
            "namespace ancestor must be an existing directory",
        ));
    }
    windows::verify_policy(file, windows::Policy::Ancestor)
}

/// Verify a Windows directory before publishing new host-managed children beneath it.
/// Unlike an existing ancestor, its inherited grants must not authorize another account
/// to modify the new files, even when the grant does not apply to the directory itself.
#[cfg(windows)]
pub fn verify_publication_parent(file: &File) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
        return Err(io::Error::other(
            "publication parent must be a real directory",
        ));
    }
    windows::verify_policy(file, windows::Policy::Publication)
}

/// Readable shared cache artifacts may grant read access, while their owner and all
/// mutation rights have to remain under trusted host control.
#[cfg(windows)]
pub fn verify_read_source(file: &File) -> io::Result<()> {
    windows::verify_policy(file, windows::Policy::ReadSource)
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{c_int, c_void};
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;

    const ACL_TYPE_EXTENDED: c_int = 0x100;
    unsafe extern "C" {
        fn acl_init(count: c_int) -> *mut c_void;
        fn acl_get_fd_np(fd: c_int, kind: c_int) -> *mut c_void;
        fn acl_set_fd_np(fd: c_int, acl: *mut c_void, kind: c_int) -> c_int;
        fn acl_get_entry(acl: *mut c_void, index: c_int, entry: *mut *mut c_void) -> c_int;
        fn acl_free(acl: *mut c_void) -> c_int;
    }
    pub(super) fn clear(file: &File) -> io::Result<()> {
        let acl = unsafe { acl_init(0) };
        if acl.is_null() {
            return Err(io::Error::last_os_error());
        }
        let result = unsafe { acl_set_fd_np(file.as_raw_fd(), acl, ACL_TYPE_EXTENDED) };
        let error = io::Error::last_os_error();
        unsafe { acl_free(acl) };
        if result != 0 {
            return Err(error);
        }
        Ok(())
    }
    pub(super) fn verify(file: &File) -> io::Result<()> {
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::ENOENT) {
                Ok(())
            } else {
                Err(error)
            };
        }
        let mut entry = std::ptr::null_mut();
        let result = unsafe { acl_get_entry(acl, 0, &mut entry) };
        let error = io::Error::last_os_error();
        unsafe { acl_free(acl) };
        if result != 0 && error.raw_os_error() == Some(libc::EINVAL) {
            Ok(())
        } else if result == 0 {
            Err(io::Error::other("private storage has an extended ACL"))
        } else {
            Err(error)
        }
    }

    #[cfg(test)]
    mod tests {
        use std::fs::{self, File};
        use std::path::Path;
        use std::process::Command;

        use super::*;

        #[test]
        fn hardening_removes_extended_acls_from_files_and_directories() {
            let temporary = tempfile::tempdir().unwrap();
            let file_path = temporary.path().join("private-file");
            let directory_path = temporary.path().join("private-directory");
            fs::write(&file_path, b"private").unwrap();
            fs::create_dir(&directory_path).unwrap();
            let file = File::open(&file_path).unwrap();
            let directory = File::open(&directory_path).unwrap();

            set_extended_acl(&file_path);
            set_extended_acl(&directory_path);
            assert!(verify(&file).is_err());
            assert!(verify(&directory).is_err());

            crate::private_file::harden(&file, false).unwrap();
            crate::private_file::harden(&directory, true).unwrap();

            verify(&file).unwrap();
            verify(&directory).unwrap();
        }

        fn set_extended_acl(path: &Path) {
            let result = Command::new("/bin/chmod")
                .arg("+a")
                .arg("everyone allow read")
                .arg(path)
                .status()
                .unwrap();
            assert!(result.success(), "cannot set test ACL");
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::fs::File;
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{
        CloseHandle, GENERIC_ALL, GENERIC_WRITE, HANDLE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, AddAccessAllowedAceEx,
        CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetLengthSid,
        GetSidIdentifierAuthority, GetSidSubAuthority, GetSidSubAuthorityCount,
        GetTokenInformation, InitializeAcl, IsValidSid, IsWellKnownSid, OBJECT_INHERIT_ACE,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSID, TOKEN_QUERY,
        TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid, WinCreatorOwnerRightsSid,
        WinCreatorOwnerSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ALL_ACCESS, FILE_DELETE_CHILD,
        FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, GetFinalPathNameByHandleW,
        GetVolumeInformationByHandleW, VOLUME_NAME_GUID, WRITE_DAC, WRITE_OWNER,
    };
    use windows_sys::Win32::System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum Policy {
        Private,
        Ancestor,
        Publication,
        ReadSource,
    }

    struct Token {
        handle: HANDLE,
        _buffer: Vec<usize>,
        sid: PSID,
    }
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.handle) };
        }
    }
    struct Descriptor(*mut core::ffi::c_void);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0) };
        }
    }

    impl Token {
        fn current() -> io::Result<Self> {
            let mut handle = null_mut();
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut token = Self {
                handle,
                _buffer: Vec::new(),
                sid: null_mut(),
            };
            let mut length = 0;
            unsafe { GetTokenInformation(handle, TokenUser, null_mut(), 0, &mut length) };
            if length == 0 || length > 65536 {
                return Err(io::Error::other("invalid account token size"));
            }
            token._buffer = vec![0; (length as usize).div_ceil(std::mem::size_of::<usize>())];
            if unsafe {
                GetTokenInformation(
                    handle,
                    TokenUser,
                    token._buffer.as_mut_ptr().cast(),
                    length,
                    &mut length,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            token.sid = unsafe { (*(token._buffer.as_ptr() as *const TOKEN_USER)).User.Sid };
            if unsafe { IsValidSid(token.sid) } == 0 {
                return Err(io::Error::other("invalid account SID"));
            }
            Ok(token)
        }
    }

    fn security(file: &File) -> io::Result<(Descriptor, PSID, *mut ACL)> {
        let mut descriptor = null_mut();
        let mut owner = null_mut();
        let mut acl = null_mut();
        let error = unsafe {
            GetSecurityInfo(
                file.as_raw_handle() as _,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut acl,
                null_mut(),
                &mut descriptor,
            )
        };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        Ok((Descriptor(descriptor), owner, acl))
    }
    fn trusted(sid: PSID, account: PSID) -> bool {
        !sid.is_null()
            && unsafe { IsValidSid(sid) } != 0
            && (unsafe { EqualSid(sid, account) } != 0
                || unsafe { IsWellKnownSid(sid, WinLocalSystemSid) } != 0
                || unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) } != 0)
    }
    fn trusted_installer(sid: PSID) -> bool {
        // Windows Resource Protection uses this exact service SID to own normal system
        // ancestors such as C:\. Other service SIDs do not inherit that trust.
        const PARTS: [u32; 6] = [
            80, 956008885, 3418522649, 1831038044, 1853292631, 2271478464,
        ];
        !sid.is_null()
            && unsafe { IsValidSid(sid) } != 0
            && unsafe { (*GetSidIdentifierAuthority(sid)).Value } == [0, 0, 0, 0, 0, 5]
            && unsafe { *GetSidSubAuthorityCount(sid) } == PARTS.len() as u8
            && PARTS.iter().enumerate().all(
                |(index, expected)| unsafe { *GetSidSubAuthority(sid, index as u32) } == *expected,
            )
    }
    // A drive letter may name a substituted directory or a share. Only use volume-root
    // semantics when the opened handle resolves to a local NTFS volume GUID root.
    fn is_ntfs_volume_root(file: &File) -> bool {
        let handle = file.as_raw_handle() as HANDLE;
        const ROOT_LEN: usize = r"\\?\Volume{00000000-0000-0000-0000-000000000000}\".len();
        let mut path = [0u16; ROOT_LEN + 1];
        let length = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                path.as_mut_ptr(),
                path.len() as u32,
                VOLUME_NAME_GUID,
            )
        };
        if length as usize != ROOT_LEN || path[ROOT_LEN - 1] != u16::from(b'\\') {
            return false;
        }
        let mut name = [0u16; 16];
        let success = unsafe {
            GetVolumeInformationByHandleW(
                handle,
                null_mut(),
                0,
                null_mut(),
                null_mut(),
                null_mut(),
                name.as_mut_ptr(),
                name.len() as u32,
            )
        };
        success != 0 && name[..5].iter().copied().eq("NTFS\0".encode_utf16())
    }

    impl Policy {
        fn rejects_grant(self, file: &File, mask: u32) -> bool {
            let namespace =
                FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;
            let object = DELETE | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES;
            match self {
                Self::Private => mask != 0,
                Self::Ancestor => {
                    // Modify includes DELETE on this object, not DELETE_CHILD. The NTFS
                    // root has no parent entry to rename and contains the selected child.
                    // Each existing child is checked for inherited rights in its own turn.
                    mask & namespace != 0 || (mask & object != 0 && !is_ntfs_volume_root(file))
                }
                Self::Publication => {
                    mask & (namespace | object | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY) != 0
                }
                Self::ReadSource => mask & (namespace | object | FILE_WRITE_DATA) != 0,
            }
        }
    }

    pub(super) fn verify_policy(file: &File, policy: Policy) -> io::Result<()> {
        let private = policy == Policy::Private;
        let publication = policy == Policy::Publication;
        let token = Token::current()?;
        let (_descriptor, owner, acl) = security(file)?;
        if !(trusted(owner, token.sid) || (!private && trusted_installer(owner))) || acl.is_null() {
            return Err(io::Error::other(
                "private storage has an untrusted owner or unrestricted DACL",
            ));
        }
        for index in 0..unsafe { (*acl).AceCount } {
            let mut ace = null_mut();
            if unsafe { GetAce(acl, u32::from(index), &mut ace) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let kind = unsafe { (*(ace as *const ACE_HEADER)).AceType };
            if u32::from(kind) == ACCESS_DENIED_ACE_TYPE {
                continue;
            }
            if u32::from(kind) != ACCESS_ALLOWED_ACE_TYPE {
                return Err(io::Error::other(
                    "private storage has an unsupported access-control entry",
                ));
            }
            let entry = ace as *const ACCESS_ALLOWED_ACE;
            let sid = unsafe { std::ptr::addr_of!((*entry).SidStart) as PSID };
            let mask = unsafe { (*entry).Mask };
            let flags = unsafe { (*ace.cast::<ACE_HEADER>()).AceFlags };
            let inherited_only = flags & 0x08 != 0;
            // A creator-only inherited grant resolves to us on our new children. It does
            // not grant another account access to this parent or to our output objects.
            let safe_creator = publication
                && inherited_only
                && flags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8 != 0
                && unsafe { IsWellKnownSid(sid, WinCreatorOwnerSid) } != 0;
            if (private || publication || !inherited_only)
                && !(trusted(sid, token.sid)
                    || safe_creator
                    // OWNER RIGHTS denotes this object's already validated owner. It is
                    // not the inheritable CREATOR OWNER placeholder or an arbitrary group.
                    || unsafe { IsWellKnownSid(sid, WinCreatorOwnerRightsSid) } != 0
                    || (!private
                        && trusted_installer(owner)
                        && unsafe { EqualSid(sid, owner) } != 0))
                && policy.rejects_grant(file, mask)
            {
                return Err(io::Error::other(
                    "private storage grants access to another account",
                ));
            }
        }
        Ok(())
    }
    pub(super) fn harden(file: &File, directory: bool) -> io::Result<()> {
        let token = Token::current()?;
        let (_descriptor, owner, _) = security(file)?;
        if !trusted(owner, token.sid) {
            return Err(io::Error::other(
                "cannot adopt storage owned by another account",
            ));
        }
        let bytes = std::mem::size_of::<ACL>() + std::mem::size_of::<ACCESS_ALLOWED_ACE>()
            - std::mem::size_of::<u32>()
            + unsafe { GetLengthSid(token.sid) } as usize;
        let mut buffer = vec![0usize; bytes.div_ceil(std::mem::size_of::<usize>())];
        let acl = buffer.as_mut_ptr() as *mut ACL;
        if unsafe { InitializeAcl(acl, bytes as u32, ACL_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let flags = if directory {
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        } else {
            0
        };
        if unsafe { AddAccessAllowedAceEx(acl, ACL_REVISION, flags, FILE_ALL_ACCESS, token.sid) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        let error = unsafe {
            SetSecurityInfo(
                file.as_raw_handle() as _,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                acl,
                null(),
            )
        };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        Ok(())
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::windows::fs::OpenOptionsExt;
        use std::path::Path;

        #[test]
        fn modify_grant_on_ntfs_volume_root_is_limited_to_existing_ancestry() {
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
                READ_CONTROL,
            };
            let open_dir = |path: &Path| {
                File::options()
                    .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(path)
                    .unwrap()
            };
            let system = std::fs::canonicalize(std::env::var_os("SystemRoot").unwrap()).unwrap();
            let root = open_dir(system.ancestors().last().unwrap());
            let windows = open_dir(&system);

            // The mask displayed by icacls as (M), including SYNCHRONIZE. Evaluate
            // it using read-only handles; the real system drive's ACL is never edited.
            let modify = 0x0013_01bf;
            assert!(!Policy::Ancestor.rejects_grant(&root, modify));
            assert!(Policy::Ancestor.rejects_grant(&windows, modify));
            assert!(Policy::Publication.rejects_grant(&root, modify));
            for right in [FILE_DELETE_CHILD, WRITE_DAC, WRITE_OWNER] {
                assert!(Policy::Ancestor.rejects_grant(&root, modify | right));
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, windows))]
mod windows_tests {
    use std::fs::{File, OpenOptions};
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::Path;
    use std::process::Command;

    fn directory(path: &Path) -> File {
        OpenOptions::new()
            .access_mode(0x0006_0080)
            .share_mode(7)
            .custom_flags(0x0220_0000)
            .open(path)
            .unwrap()
    }

    #[test]
    fn normal_windows_home_ancestors_are_accepted_without_permission_changes() {
        let temporary = tempfile::tempdir().unwrap();
        for ancestor in temporary.path().ancestors() {
            // Do not ask for WRITE_DAC on system ancestors merely to inspect them.
            let file = OpenOptions::new()
                .access_mode(0x0002_0080)
                .share_mode(7)
                .custom_flags(0x0220_0000)
                .open(ancestor)
                .unwrap();
            super::verify_ancestor(&file).unwrap();
        }
    }

    #[test]
    fn owner_rights_grants_are_limited_to_the_validated_object_owner() {
        let temporary = tempfile::tempdir().unwrap();
        let parent = directory(temporary.path());
        super::harden(&parent, true).unwrap();
        assert!(
            Command::new("icacls.exe")
                .arg(temporary.path())
                .arg("/grant:r")
                .arg("*S-1-3-4:(OI)(CI)(F)")
                .output()
                .unwrap()
                .status
                .success()
        );
        super::verify(&parent).unwrap();
        super::verify_ancestor(&parent).unwrap();
        let path = temporary.path().join("catalog.db");
        std::fs::write(&path, b"private catalog").unwrap();
        let catalog = directory(&path);
        // An existing catalog can inherit OWNER RIGHTS from its private database
        // directory. Diagnosis must accept this without rewriting the valid ACL.
        super::verify(&catalog).unwrap();
        assert!(
            Command::new("icacls.exe")
                .arg(&path)
                .arg("/grant:r")
                .arg("*S-1-1-0:(R)")
                .output()
                .unwrap()
                .status
                .success()
        );
        assert!(super::verify(&catalog).is_err());
    }

    #[test]
    fn ancestor_create_only_grant_cannot_relax_private_storage_or_replacement_checks() {
        let temporary = tempfile::tempdir().unwrap();
        let file = directory(temporary.path());
        super::harden(&file, true).unwrap();
        let grant = |rights: &str| {
            assert!(
                Command::new("icacls.exe")
                    .arg(temporary.path())
                    .arg("/grant:r")
                    .arg(format!("*S-1-1-0:({rights})"))
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
        };
        for rights in ["WD", "AD", "WD,AD"] {
            grant(rights);
            super::verify_ancestor(&file).unwrap();
            assert!(super::verify_publication_parent(&file).is_err());
            assert!(super::verify(&file).is_err());
        }
        for rights in ["DC", "DE", "WDAC", "WO", "W", "M"] {
            grant(rights);
            assert!(super::verify_ancestor(&file).is_err(), "allowed {rights}");
        }
        let path = temporary.path().join("file.raw");
        std::fs::write(&path, b"private bytes").unwrap();
        let plain = directory(&path);
        super::harden(&plain, false).unwrap();
        assert!(
            Command::new("icacls.exe")
                .arg(&path)
                .arg("/grant:r")
                .arg("*S-1-1-0:(AD)")
                .output()
                .unwrap()
                .status
                .success()
        );
        assert!(super::verify_ancestor(&plain).is_err());
        assert!(super::verify(&plain).is_err());
        assert!(
            Command::new("icacls.exe")
                .arg(&path)
                .arg("/grant:r")
                .arg("*S-1-5-11:(WD)")
                .output()
                .unwrap()
                .status
                .success()
        );
        // The same bit that creates a sibling directory entry writes data on a file.
        assert!(super::verify_read_source(&plain).is_err());
    }

    #[test]
    fn publication_parent_checks_inherited_mutation_without_tightening_ancestors() {
        let temporary = tempfile::tempdir().unwrap();
        let parent = directory(temporary.path());
        let grant = |sid: &str, rights: &str| {
            super::harden(&parent, true).unwrap();
            assert!(
                Command::new("icacls.exe")
                    .arg(temporary.path())
                    .arg("/grant:r")
                    .arg(format!("*{sid}:{rights}"))
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
        };
        for rights in ["(RX)", "(OI)(CI)(IO)(R)"] {
            grant("S-1-1-0", rights);
            super::verify_publication_parent(&parent).unwrap();
        }
        for rights in [
            "(OI)(IO)(WD)",
            "(OI)(IO)(AD)",
            "(CI)(IO)(DC)",
            "(AD)",
            "(DC)",
            "(WDAC)",
        ] {
            grant("S-1-1-0", rights);
            let before = Command::new("icacls.exe")
                .arg(temporary.path())
                .output()
                .unwrap();
            assert!(
                super::verify_publication_parent(&parent).is_err(),
                "allowed {rights}"
            );
            let after = Command::new("icacls.exe")
                .arg(temporary.path())
                .output()
                .unwrap();
            assert_eq!(before.stdout, after.stdout, "rewrote {rights}");
            if rights.contains("(IO)") || rights == "(AD)" {
                super::verify_ancestor(&parent).unwrap();
            }
        }
        // CREATOR OWNER resolves to the account creating each child; it is safe only
        // as an inherited placeholder, after other grants cannot create/replace children.
        grant("S-1-3-0", "(OI)(CI)(IO)(F)");
        super::verify_publication_parent(&parent).unwrap();
        let path = temporary.path().join("new-private-file");
        std::fs::write(&path, b"private bytes").unwrap();
        super::verify(&directory(&path)).unwrap();
        assert!(super::verify_publication_parent(&directory(&path)).is_err());
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    #[cfg(target_os = "linux")]
    use std::fs::{self, File};

    #[test]
    fn created_files_have_owner_only_mode() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("private");
        let file = super::create_new(&path).unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        super::verify(&file).unwrap();
    }

    #[test]
    fn private_directory_stays_owner_only_under_zero_umask() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("private-directory");
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "private_file::unix_tests::private_directory_creation_child",
                "--nocapture",
            ])
            .env("MSB_PRIVATE_DIRECTORY_CHILD", &path)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn private_directory_creation_child() {
        let Some(path) = std::env::var_os("MSB_PRIVATE_DIRECTORY_CHILD") else {
            return;
        };
        unsafe { libc::umask(0) };
        super::create_private_directory(std::path::Path::new(&path)).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn hardening_removes_posix_access_and_default_acls() {
        use std::ffi::CString;
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;
        use std::path::Path;

        let temporary = tempfile::tempdir().unwrap();
        let file_path = temporary.path().join("private-file");
        let directory_path = temporary.path().join("private-directory");
        fs::write(&file_path, b"private").unwrap();
        fs::create_dir(&directory_path).unwrap();
        let file = File::open(&file_path).unwrap();
        let directory = File::open(&directory_path).unwrap();
        let acl = extended_acl();

        if !set_acl(&file_path, b"system.posix_acl_access\0", &acl)
            || !set_acl(&directory_path, b"system.posix_acl_access\0", &acl)
            || !set_acl(&directory_path, b"system.posix_acl_default\0", &acl)
        {
            return;
        }

        super::harden(&file, false).unwrap();
        super::harden(&directory, true).unwrap();

        assert_acl_absent(&file, b"system.posix_acl_access\0");
        assert_acl_absent(&directory, b"system.posix_acl_access\0");
        assert_acl_absent(&directory, b"system.posix_acl_default\0");

        fn set_acl(path: &Path, name: &[u8], acl: &[u8]) -> bool {
            let path = CString::new(path.as_os_str().as_bytes()).unwrap();
            let result = unsafe {
                libc::setxattr(
                    path.as_ptr(),
                    name.as_ptr().cast(),
                    acl.as_ptr().cast(),
                    acl.len(),
                    0,
                )
            };
            if result == 0 {
                return true;
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error().is_some_and(|code| {
                code == libc::ENOTSUP || code == libc::EOPNOTSUPP || code == libc::EPERM
            }) {
                return false;
            }
            panic!("cannot set test POSIX ACL: {error}");
        }

        fn assert_acl_absent(file: &File, name: &[u8]) {
            let size = unsafe {
                libc::fgetxattr(
                    file.as_raw_fd(),
                    name.as_ptr().cast(),
                    std::ptr::null_mut(),
                    0,
                )
            };
            assert_eq!(size, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ENODATA)
            );
        }

        fn extended_acl() -> Vec<u8> {
            let mut acl = 2u32.to_le_bytes().to_vec();
            for (tag, permission, id) in [
                (0x01u16, 0x07u16, u32::MAX),
                (0x02, 0x04, 1001),
                (0x04, 0x00, u32::MAX),
                (0x10, 0x04, u32::MAX),
                (0x20, 0x00, u32::MAX),
            ] {
                acl.extend_from_slice(&tag.to_le_bytes());
                acl.extend_from_slice(&permission.to_le_bytes());
                acl.extend_from_slice(&id.to_le_bytes());
            }
            acl
        }
    }
}
