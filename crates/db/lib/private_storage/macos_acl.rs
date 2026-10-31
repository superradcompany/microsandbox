//! macOS ACLs can grant access independently of chmod. Keep this Darwin ABI local.

use std::ffi::{CString, c_char, c_int, c_void};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const ACL_TYPE_EXTENDED: c_int = 0x100;
const ACL_EXTENDED_ALLOW: c_int = 1;
const ACL_EXTENDED_DENY: c_int = 2;
// sys/acl.h: write data, append, delete, delete child, write attributes/xattrs/security, chown.
const MUTATING_PERMISSIONS: u64 =
    (1 << 2) | (1 << 5) | (1 << 4) | (1 << 6) | (1 << 8) | (1 << 10) | (1 << 12) | (1 << 13);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct Acl(*mut c_void);

unsafe extern "C" {
    fn acl_get_fd_np(fd: c_int, kind: c_int) -> *mut c_void;
    fn acl_get_link_np(path: *const c_char, kind: c_int) -> *mut c_void;
    fn acl_set_fd_np(fd: c_int, acl: *mut c_void, kind: c_int) -> c_int;
    fn acl_set_link_np(path: *const c_char, kind: c_int, acl: *mut c_void) -> c_int;
    fn acl_init(count: c_int) -> *mut c_void;
    fn acl_free(acl: *mut c_void) -> c_int;
    fn acl_get_entry(acl: *mut c_void, index: c_int, entry: *mut *mut c_void) -> c_int;
    fn acl_get_qualifier(entry: *mut c_void) -> *mut c_void;
    fn mbr_uid_to_uuid(uid: libc::uid_t, uuid: *mut u8) -> c_int;
    fn acl_get_tag_type(entry: *mut c_void, tag: *mut c_int) -> c_int;
    fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> c_int;
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Acl {
    fn checked(pointer: *mut c_void) -> io::Result<Self> {
        if pointer.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(pointer))
        }
    }

    fn read(pointer: *mut c_void) -> io::Result<Self> {
        // Darwin reports ENOENT when the inode exists but has no extended ACL.
        // Callers validate the inode separately; other ACL failures must fail closed.
        if pointer.is_null() && io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Self::checked(unsafe { acl_init(0) })
        } else {
            Self::checked(pointer)
        }
    }

    fn entries(&self) -> io::Result<Vec<*mut c_void>> {
        let mut entries = Vec::new();
        for index in 0.. {
            let mut entry = std::ptr::null_mut();
            if unsafe { acl_get_entry(self.0, index, &mut entry) } != 0 {
                let error = io::Error::last_os_error();
                // Darwin returns EINVAL for an index beyond the last entry, including empty ACLs.
                if error.raw_os_error() == Some(libc::EINVAL) {
                    break;
                }
                return Err(error);
            }
            entries.push(entry);
        }
        Ok(entries)
    }

    fn grants_untrusted_access(&self) -> io::Result<bool> {
        for entry in self.entries()? {
            let mut tag = 0;
            checked(unsafe { acl_get_tag_type(entry, &mut tag) })?;
            match tag {
                ACL_EXTENDED_DENY => {}
                ACL_EXTENDED_ALLOW if grants_only_trusted_user(entry)? => {}
                // Include inherit-only grants: they can expose subsequently created files
                // even though they do not grant access to the directory itself.
                ACL_EXTENDED_ALLOW => return Ok(true),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "catalog ACL contains an unrecognized entry type",
                    ));
                }
            }
        }
        Ok(false)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for Acl {
    fn drop(&mut self) {
        unsafe {
            acl_free(self.0);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn clear_directory(directory: &File) -> io::Result<()> {
    let fd = directory.as_raw_fd();
    let acl = Acl::read(unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) })?;
    // Denials and explicit owner/root grants do not expand the trust boundary. Leave
    // them intact so already-private read-only or immutable storage needs no mutation.
    if !acl.grants_untrusted_access()? {
        return Ok(());
    }
    let empty = Acl::checked(unsafe { acl_init(0) })?;
    checked(unsafe { acl_set_fd_np(fd, empty.0, ACL_TYPE_EXTENDED) })?;
    let verified = Acl::read(unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) })?;
    require_empty(&verified)
}

pub(super) fn clear_file(path: &Path) -> io::Result<()> {
    let path = c_path(path)?;
    let acl = Acl::read(unsafe { acl_get_link_np(path.as_ptr(), ACL_TYPE_EXTENDED) })?;
    if !acl.grants_untrusted_access()? {
        return Ok(());
    }
    let empty = Acl::checked(unsafe { acl_init(0) })?;
    checked(unsafe { acl_set_link_np(path.as_ptr(), ACL_TYPE_EXTENDED, empty.0) })?;
    let verified = Acl::read(unsafe { acl_get_link_np(path.as_ptr(), ACL_TYPE_EXTENDED) })?;
    require_empty(&verified)
}

pub(super) fn verify_ancestor(path: &Path) -> io::Result<bool> {
    let name = c_path(path)?;
    let acl = Acl::read(unsafe { acl_get_link_np(name.as_ptr(), ACL_TYPE_EXTENDED) })?;
    let mut no_grants = true;
    for entry in acl.entries()? {
        let mut tag = 0;
        let mut mask = 0;
        checked(unsafe { acl_get_tag_type(entry, &mut tag) })?;
        checked(unsafe { acl_get_permset_mask_np(entry, &mut mask) })?;
        // Explicit owner/root grants do not expand this threat boundary. Group and
        // unknown-identity grants remain conservative; never infer group membership.
        if tag != ACL_EXTENDED_ALLOW || grants_only_trusted_user(entry)? {
            continue;
        }
        no_grants = false;
        // Do not rewrite shared ancestor ACLs. Read/search grants and common deny-delete
        // home-directory entries are harmless; mutation grants need an operator decision.
        if tag == ACL_EXTENDED_ALLOW && mask & MUTATING_PERMISSIONS != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "catalog ancestor {} has a mutation-granting ACL; use a storage root protected from other accounts",
                    path.display()
                ),
            ));
        }
    }
    Ok(no_grants)
}

fn grants_only_trusted_user(entry: *mut c_void) -> io::Result<bool> {
    // Darwin returns an allocated 16-byte UUID for the qualifier; copy it before freeing.
    let qualifier = unsafe { acl_get_qualifier(entry) };
    if qualifier.is_null() {
        return Err(io::Error::last_os_error());
    }
    let uuid = unsafe { std::ptr::read(qualifier.cast::<[u8; 16]>()) };
    unsafe { acl_free(qualifier) };
    for uid in [unsafe { libc::geteuid() }, 0] {
        let mut trusted = [0; 16];
        let result = unsafe { mbr_uid_to_uuid(uid, trusted.as_mut_ptr()) };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        if uuid == trusted {
            return Ok(true);
        }
    }
    Ok(false)
}

fn require_empty(acl: &Acl) -> io::Result<()> {
    if acl.entries()?.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "catalog ACL remains accessible to other accounts",
        ))
    }
}

fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "catalog path contains NUL"))
}

fn checked(result: c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
