//! Windows host prerequisite checks for local sandbox execution.

use std::ffi::c_void;
use std::fmt;

use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// The Windows optional feature that exposes the WHP VMM API.
pub const HYPERVISOR_PLATFORM_FEATURE: &str = "HypervisorPlatform";

/// Elevated PowerShell command that enables the WHP optional feature.
pub const ENABLE_HYPERVISOR_PLATFORM_COMMAND: &str =
    "Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -All -NoRestart";

const WINHV_PLATFORM_DLL: &str = "WinHvPlatform.dll";
const WHV_GET_CAPABILITY: &[u8] = b"WHvGetCapability\0";
const WHV_CAPABILITY_CODE_HYPERVISOR_PRESENT: i32 = 0;
const WHV_CAPABILITY_BUFFER_LEN: usize = 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

type WhvGetCapabilityFn =
    unsafe extern "system" fn(i32, *mut c_void, u32, *mut u32) -> windows_sys::core::HRESULT;

/// A Windows host setup problem that prevents local WHP-backed sandboxes from starting.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum WindowsHostSetupError {
    /// `WinHvPlatform.dll` could not be loaded.
    HypervisorPlatformLibraryUnavailable {
        /// The Windows loader error returned while opening `WinHvPlatform.dll`.
        reason: String,
    },

    /// The `WHvGetCapability` entry point was not found in `WinHvPlatform.dll`.
    HypervisorPlatformEntryPointMissing {
        /// The Windows loader error returned while resolving `WHvGetCapability`.
        reason: String,
    },

    /// WHP reported that no hypervisor is available to the current boot session.
    HypervisorNotPresent,

    /// WHP returned an error while querying host capabilities.
    CapabilityQueryFailed {
        /// HRESULT returned by `WHvGetCapability`.
        hresult: i32,
    },

    /// WHP returned an unexpectedly short capability payload.
    CapabilityPayloadInvalid {
        /// Number of bytes returned by `WHvGetCapability`.
        bytes_returned: u32,
    },
}

struct WhpLibrary {
    module: HMODULE,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl WindowsHostSetupError {
    /// Short user-facing title for CLI rendering.
    pub fn title(&self) -> &'static str {
        "Windows Hypervisor Platform is not available"
    }

    /// One-line cause suitable for a styled CLI error block.
    pub fn cause(&self) -> String {
        match self {
            Self::HypervisorPlatformLibraryUnavailable { reason } => {
                format!("{WINHV_PLATFORM_DLL} could not be loaded: {reason}")
            }
            Self::HypervisorPlatformEntryPointMissing { reason } => {
                format!("WHvGetCapability was not found in {WINHV_PLATFORM_DLL}: {reason}")
            }
            Self::HypervisorNotPresent => {
                "WHP is installed but the hypervisor is not active for this Windows boot session"
                    .to_string()
            }
            Self::CapabilityQueryFailed { hresult } => {
                format!(
                    "WHvGetCapability failed with HRESULT 0x{:08x}",
                    *hresult as u32
                )
            }
            Self::CapabilityPayloadInvalid { bytes_returned } => {
                format!("WHvGetCapability returned only {bytes_returned} bytes")
            }
        }
    }

    /// Actionable setup hints for CLI and SDK consumers.
    pub fn hints(&self) -> Vec<&'static str> {
        vec![
            "Run PowerShell as Administrator:",
            ENABLE_HYPERVISOR_PLATFORM_COMMAND,
            "Reboot if Windows asks, then run the sandbox again.",
            "HypervisorPlatform is the WHP API that libkrun uses; it is not the full Hyper-V management role.",
            "VirtualMachinePlatform for WSL2/Docker is separate, so it can be enabled while HypervisorPlatform is still off.",
        ]
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Helpers
//--------------------------------------------------------------------------------------------------

impl WhpLibrary {
    fn load() -> Result<Self, WindowsHostSetupError> {
        let dll_name = wide_null(WINHV_PLATFORM_DLL);
        let module = unsafe { LoadLibraryW(dll_name.as_ptr()) };
        if module.is_null() {
            return Err(
                WindowsHostSetupError::HypervisorPlatformLibraryUnavailable {
                    reason: last_os_error_string(),
                },
            );
        }

        Ok(Self { module })
    }

    fn get_capability_proc(&self) -> Result<WhvGetCapabilityFn, WindowsHostSetupError> {
        let proc = unsafe { GetProcAddress(self.module, WHV_GET_CAPABILITY.as_ptr()) };
        let Some(proc) = proc else {
            return Err(WindowsHostSetupError::HypervisorPlatformEntryPointMissing {
                reason: last_os_error_string(),
            });
        };

        // The function comes from the DLL by name, so reinterpret the generic
        // FARPROC thunk as the precise WHvGetCapability ABI we call below.
        Ok(unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, WhvGetCapabilityFn>(proc)
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Display for WindowsHostSetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.title(), self.cause())?;
        for hint in self.hints() {
            write!(f, "\n  {hint}")?;
        }
        Ok(())
    }
}

impl std::error::Error for WindowsHostSetupError {}

impl Drop for WhpLibrary {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.module);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Verify that the current Windows boot session can run WHP-backed sandboxes.
pub fn verify_windows_host_prerequisites() -> Result<(), WindowsHostSetupError> {
    let library = WhpLibrary::load()?;
    let whv_get_capability = library.get_capability_proc()?;
    let mut capability = [0_u8; WHV_CAPABILITY_BUFFER_LEN];
    let mut bytes_returned = 0_u32;

    // WHV_CAPABILITY is a C union. For HypervisorPresent, the first 4 bytes are
    // a BOOL. A generously sized byte buffer avoids a static winhvplatform.lib
    // import while still giving WHP the same storage shape the C API expects.
    let hresult = unsafe {
        whv_get_capability(
            WHV_CAPABILITY_CODE_HYPERVISOR_PRESENT,
            capability.as_mut_ptr().cast(),
            capability.len() as u32,
            &mut bytes_returned,
        )
    };
    if hresult < 0 {
        return Err(WindowsHostSetupError::CapabilityQueryFailed { hresult });
    }
    if bytes_returned < std::mem::size_of::<i32>() as u32 {
        return Err(WindowsHostSetupError::CapabilityPayloadInvalid { bytes_returned });
    }

    if !hypervisor_present_from_capability(&capability) {
        return Err(WindowsHostSetupError::HypervisorNotPresent);
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn hypervisor_present_from_capability(capability: &[u8]) -> bool {
    let bytes: [u8; 4] = capability[..4]
        .try_into()
        .expect("capability buffer must contain the WHP BOOL field");
    i32::from_ne_bytes(bytes) != 0
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last_os_error_string() -> String {
    std::io::Error::last_os_error().to_string()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_host_setup_error_mentions_enable_command() {
        let error = WindowsHostSetupError::HypervisorNotPresent;
        let rendered = error.to_string();

        assert!(rendered.contains(HYPERVISOR_PLATFORM_FEATURE));
        assert!(rendered.contains(ENABLE_HYPERVISOR_PLATFORM_COMMAND));
        assert!(rendered.contains("VirtualMachinePlatform"));
    }

    #[test]
    fn capability_hresult_uses_windows_hex_shape() {
        let error = WindowsHostSetupError::CapabilityQueryFailed {
            hresult: 0x8007_0006_u32 as i32,
        };

        assert!(error.cause().contains("0x80070006"));
    }

    #[test]
    fn hypervisor_present_reads_first_bool_field() {
        let mut capability = [0_u8; WHV_CAPABILITY_BUFFER_LEN];
        assert!(!hypervisor_present_from_capability(&capability));

        capability[..4].copy_from_slice(&1_i32.to_ne_bytes());
        assert!(hypervisor_present_from_capability(&capability));
    }

    #[test]
    #[ignore = "requires a Windows boot session with WHP available"]
    fn verify_windows_host_prerequisites_smoke() {
        verify_windows_host_prerequisites().expect("WHP should be available on this host");
    }
}
