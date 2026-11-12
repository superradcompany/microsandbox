//! Owner-private file permissions for newly created storage and non-mutating inspection.
//!
//! These helpers operate on one caller-owned object, not its ancestors. Callers must first
//! establish namespace authority and exclude symlinks/reparse points and concurrent replacement.

use std::fs::File;
use std::io;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

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
        #[cfg(target_os = "macos")]
        macos::clear(file)?;
        file.set_permissions(std::fs::Permissions::from_mode(if directory {
            0o700
        } else {
            0o600
        }))?;
    }
    #[cfg(windows)]
    windows::harden(file, directory)?;
    verify(file)
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
    windows::verify(file)?;
    Ok(())
}

/// Verify a Windows namespace ancestor without rejecting harmless read/traverse grants.
/// Unlike `verify`, this checks path substitution rather than confidentiality of its contents.
/// Every selected child must already exist and be checked separately: creating an unrelated
/// sibling directory does not authorize replacing that existing protected child.
#[cfg(windows)]
pub fn verify_ancestor(file: &File) -> io::Result<()> {
    if !file.metadata()?.is_dir() {
        return Err(io::Error::other(
            "namespace ancestor must be an existing directory",
        ));
    }
    windows::verify_policy(file, false, false)
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
    windows::verify_policy(file, false, true)
}

/// Readable shared cache artifacts may grant read access, while their owner and all
/// mutation rights have to remain under trusted host control.
#[cfg(windows)]
pub fn verify_read_source(file: &File) -> io::Result<()> {
    windows::verify_policy(file, false, false)
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
}

#[cfg(windows)]
mod windows {
    use std::fs::File;
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
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
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

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
    pub(super) fn verify(file: &File) -> io::Result<()> {
        verify_policy(file, true, false)
    }

    pub(super) fn verify_policy(file: &File, private: bool, publication: bool) -> io::Result<()> {
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
            // Existing ancestors may grant ADD_SUBDIRECTORY (the normal drive-root ACL):
            // that only creates unrelated sibling directories. Keep rejecting ADD_FILE,
            // DELETE_CHILD, DELETE, metadata/ACL ownership writes and generic write/all.
            // The selected child and current catalog still undergo their stricter checks.
            let dangerous = if private {
                u32::MAX
            } else if publication {
                // ADD_SUBDIRECTORY on the parent is unsafe here, and the same bit is
                // APPEND_DATA when inherited by a subsequently published regular file.
                0x500d_0156
            } else {
                0x500d_0152
            };
            let flags = unsafe { (*ace.cast::<ACE_HEADER>()).AceFlags };
            let inherited_only = flags & 0x08 != 0;
            // A creator-only inherited grant resolves to us on our new children. It does
            // not grant another account access to this parent or to our output objects.
            let safe_creator = publication
                && inherited_only
                && flags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8 != 0
                && unsafe { IsWellKnownSid(sid, WinCreatorOwnerSid) } != 0;
            if unsafe { (*entry).Mask } & dangerous != 0
                && (private || publication || !inherited_only)
                && !(trusted(sid, token.sid)
                    || safe_creator
                    // OWNER RIGHTS denotes this object's already validated owner. It is
                    // not the inheritable CREATOR OWNER placeholder or an arbitrary group.
                    || unsafe { IsWellKnownSid(sid, WinCreatorOwnerRightsSid) } != 0
                    || (!private
                        && trusted_installer(owner)
                        && unsafe { EqualSid(sid, owner) } != 0))
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
        grant("AD");
        super::verify_ancestor(&file).unwrap();
        assert!(super::verify(&file).is_err());
        for rights in ["DC", "WD", "WDAC", "WO", "W"] {
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
