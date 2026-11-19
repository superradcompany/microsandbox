//! Capability-gated NTFS transactions. Optional APIs are resolved at runtime so an
//! unsupported host can still use unrelated sandbox and snapshot operations.

use std::ffi::c_void;
use std::fs;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, FreeLibrary, HANDLE, HMODULE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    GetVolumeInformationW, GetVolumePathNameW, LPPROGRESS_ROUTINE,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::core::GUID;

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const FILE_SUPPORTS_TRANSACTIONS: u32 = 0x0020_0000;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

type Create = unsafe extern "system" fn(
    *mut SECURITY_ATTRIBUTES,
    *mut GUID,
    u32,
    u32,
    u32,
    u32,
    *const u16,
) -> HANDLE;
type Finish = unsafe extern "system" fn(HANDLE) -> i32;
type Move = unsafe extern "system" fn(
    *const u16,
    *const u16,
    LPPROGRESS_ROUTINE,
    *const c_void,
    u32,
    HANDLE,
) -> i32;
type Delete = unsafe extern "system" fn(*const u16, HANDLE) -> i32;

struct Library(HMODULE);

struct Api {
    create: Create,
    commit: Finish,
    rollback: Finish,
    move_file: Move,
    delete_file: Delete,
    _ktm: Library,
    _kernel: Library,
}

pub(super) struct Transaction {
    api: Api,
    handle: HANDLE,
    committed: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Library {
    fn open(name: &str) -> io::Result<Self> {
        let name: Vec<u16> = name.encode_utf16().chain([0]).collect();
        // SAFETY: terminated name is valid throughout the call. Only the system directory
        // is searched; a snapshot directory must never supply a transaction implementation.
        let handle =
            unsafe { LoadLibraryExW(name.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(handle))
    }
}

impl Api {
    fn load() -> io::Result<Self> {
        let ktm = Library::open("KtmW32.dll")?;
        let kernel = Library::open("kernel32.dll")?;
        // Each symbol has the documented Windows ABI. The owning libraries outlive
        // every use of these function pointers, including transaction destruction.
        macro_rules! symbol {
            ($library:expr, $name:literal, $ty:ty) => {{
                // SAFETY: static NUL-terminated symbol and live module handle.
                let pointer = unsafe { GetProcAddress($library.0, concat!($name, "\0").as_ptr()) }
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::Unsupported,
                            concat!("missing Windows API ", $name),
                        )
                    })?;
                // SAFETY: the named export has exactly the explicitly specified ABI.
                unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(pointer) }
            }};
        }
        Ok(Self {
            create: symbol!(ktm, "CreateTransaction", Create),
            commit: symbol!(ktm, "CommitTransaction", Finish),
            rollback: symbol!(ktm, "RollbackTransaction", Finish),
            move_file: symbol!(kernel, "MoveFileTransactedW", Move),
            delete_file: symbol!(kernel, "DeleteFileTransactedW", Delete),
            _ktm: ktm,
            _kernel: kernel,
        })
    }
}

impl Transaction {
    pub(super) fn new() -> io::Result<Self> {
        let api = Api::load()?;
        // SAFETY: optional parameters are null; this call returns an owned kernel handle.
        let handle = unsafe { (api.create)(null_mut(), null_mut(), 0, 0, 0, 0, null()) };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            api,
            handle,
            committed: false,
        })
    }

    pub(super) fn rename(&self, from: &Path, to: &Path, replace: bool) -> io::Result<()> {
        let from = wide(from)?;
        let to = wide(to)?;
        // No COPY_ALLOWED flag: publication must never turn into a payload copy or
        // cross-volume operation outside the atomic transaction.
        // SAFETY: paths and transaction remain valid for this synchronous call.
        let result = unsafe {
            (self.api.move_file)(
                from.as_ptr(),
                to.as_ptr(),
                None,
                null(),
                u32::from(replace),
                self.handle,
            )
        };
        checked(result)
    }

    pub(super) fn remove_file(&self, path: &Path) -> io::Result<()> {
        let path = wide(path)?;
        // SAFETY: terminated path and live transaction handle.
        checked(unsafe { (self.api.delete_file)(path.as_ptr(), self.handle) })
    }

    pub(super) fn commit(&mut self) -> io::Result<()> {
        // SAFETY: the handle belongs to this live transaction. Commit is synchronous.
        checked(unsafe { (self.api.commit)(self.handle) })?;
        self.committed = true;
        Ok(())
    }

    fn rollback(&self) -> io::Result<()> {
        // SAFETY: the handle remains valid until Drop closes it.
        checked(unsafe { (self.api.rollback)(self.handle) })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for Library {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns exactly one loader reference.
        unsafe {
            FreeLibrary(self.0);
        }
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.rollback();
        }
        // SAFETY: this wrapper owns the handle; APIs remain loaded until after Drop.
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Check the actual destination volume before unpacking or reserving a catalog/group.
/// A disposable rename also detects a disabled/unavailable resource manager even when
/// NTFS advertises transactions. Failure leaves the target group untouched.
pub(super) fn check(root: &Path) -> MicrosandboxResult<()> {
    check_inner(root).map_err(|error| MicrosandboxError::InvalidConfig(format!(
        "atomic snapshot import is unavailable at {}: Windows requires an NTFS volume with working TxF support ({error}); choose a supported local NTFS destination; no group changes were made",
        root.display()
    )))
}

fn check_inner(root: &Path) -> io::Result<()> {
    let absolute = std::path::absolute(root)?;
    let mut existing = absolute.as_path();
    while !existing.try_exists()? {
        existing = existing.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "destination has no existing parent",
            )
        })?;
    }
    let existing = fs::canonicalize(existing)?;
    let path = wide(&existing)?;
    let mut volume = vec![0u16; 32768];
    let mut filesystem = [0u16; 32];
    let mut flags = 0;
    // SAFETY: output buffers have the supplied capacities; other outputs are optional.
    checked(unsafe {
        GetVolumePathNameW(path.as_ptr(), volume.as_mut_ptr(), volume.len() as u32)
    })?;
    checked(unsafe {
        GetVolumeInformationW(
            volume.as_ptr(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut flags,
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    })?;
    let end = filesystem
        .iter()
        .position(|c| *c == 0)
        .unwrap_or(filesystem.len());
    if !String::from_utf16_lossy(&filesystem[..end]).eq_ignore_ascii_case("NTFS")
        || flags & FILE_SUPPORTS_TRANSACTIONS == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "volume does not support NTFS transactions",
        ));
    }
    let probe = tempfile::Builder::new()
        .prefix(".msb-txf-probe-")
        .tempdir_in(&existing)?;
    fs::write(probe.path().join("before"), b"")?;
    // Drop transaction before the temporary directory, including on any error.
    let transaction = Transaction::new()?;
    transaction.rename(
        &probe.path().join("before"),
        &probe.path().join("after"),
        false,
    )?;
    transaction.rollback()?;
    drop(transaction);
    Ok(())
}

fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let path: Vec<u16> = path.as_os_str().encode_wide().collect();
    if path.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains NUL",
        ));
    }
    Ok(path.into_iter().chain([0]).collect())
}

fn checked(result: i32) -> io::Result<()> {
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
