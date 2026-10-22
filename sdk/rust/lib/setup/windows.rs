//! Windows host prerequisite checks for local sandbox execution.

use std::ffi::c_void;
use std::fmt;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

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

/// Reads the `HypervisorPlatform` install state from `Win32_OptionalFeature`
/// (documented and readable without elevation) and whether Component Based
/// Servicing has a restart pending. Prints `<InstallState>;<True|False>`.
const SERVICING_PROBE_SCRIPT: &str = concat!(
    "$ErrorActionPreference = 'Stop'; ",
    "$feature = Get-CimInstance -ClassName Win32_OptionalFeature -Filter 'Name=''HypervisorPlatform'''; ",
    r"$pending = Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'; ",
    "'{0};{1}' -f $feature.InstallState, $pending",
);
const SERVICING_PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const SERVICING_PROBE_POLL_INTERVAL: Duration = Duration::from_millis(50);

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

    /// WHP reported that no hypervisor is available to the current boot session,
    /// and the `HypervisorPlatform` feature state could not be determined.
    HypervisorNotPresent,

    /// WHP reported that no hypervisor is available because the
    /// `HypervisorPlatform` feature is not enabled.
    HypervisorPlatformNotEnabled,

    /// `HypervisorPlatform` is enabled, but Windows has a restart pending, so the
    /// hypervisor is not active for the current boot session yet.
    HypervisorRestartPending,

    /// `HypervisorPlatform` is enabled and no restart is pending, but the
    /// hypervisor did not start for the current boot session.
    HypervisorNotLaunched,

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

/// Install state of the `HypervisorPlatform` optional feature.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum FeatureState {
    Enabled,
    NotEnabled,
    Unknown,
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
            Self::HypervisorPlatformNotEnabled => {
                format!("the {HYPERVISOR_PLATFORM_FEATURE} Windows feature is not enabled")
            }
            Self::HypervisorRestartPending => {
                format!(
                    "{HYPERVISOR_PLATFORM_FEATURE} is enabled, but Windows has a restart pending"
                )
            }
            Self::HypervisorNotLaunched => {
                format!(
                    "{HYPERVISOR_PLATFORM_FEATURE} is enabled, but the hypervisor did not start for this Windows boot session"
                )
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
        let enable_hints = [
            "Run PowerShell as Administrator:",
            ENABLE_HYPERVISOR_PLATFORM_COMMAND,
            "Reboot if Windows asks, then run the sandbox again.",
            "HypervisorPlatform is the WHP API that libkrun uses; it is not the full Hyper-V management role.",
            "VirtualMachinePlatform for WSL2/Docker is separate, so it can be enabled while HypervisorPlatform is still off.",
        ];
        let launch_causes = [
            "1. Hardware virtualization is turned off in the firmware (BIOS/UEFI) settings; turn it on.",
            "2. The hypervisor is disabled at boot: if `bcdedit /enum {current}` shows `hypervisorlaunchtype Off`, run `bcdedit /set hypervisorlaunchtype auto` as Administrator, then reboot.",
            "3. This Windows is itself a virtual machine without nested virtualization; enable nested virtualization on its host.",
        ];

        match self {
            Self::HypervisorRestartPending => {
                vec!["Restart Windows to finish applying the change, then run the sandbox again."]
            }
            Self::HypervisorNotLaunched => {
                let mut hints = vec!["Likely causes, in order:"];
                hints.extend(launch_causes);
                hints
            }
            // The feature state could not be read, so cover both the
            // not-enabled and the enabled-but-not-starting cases.
            Self::HypervisorNotPresent => {
                let mut hints = enable_hints.to_vec();
                hints.push(
                    "If HypervisorPlatform is already enabled and Windows has restarted since, the hypervisor is not starting. Likely causes, in order:",
                );
                hints.extend(launch_causes);
                hints
            }
            Self::HypervisorPlatformNotEnabled
            | Self::HypervisorPlatformLibraryUnavailable { .. }
            | Self::HypervisorPlatformEntryPointMissing { .. }
            | Self::CapabilityQueryFailed { .. }
            | Self::CapabilityPayloadInvalid { .. } => enable_hints.to_vec(),
        }
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
        // WinHvPlatform.dll ships even when the feature is disabled, so the
        // capability query alone cannot tell "not enabled" from "not starting".
        let (feature, restart_pending) = probe_hypervisor_platform_servicing()
            .map(|output| parse_servicing_probe(&output))
            .unwrap_or((FeatureState::Unknown, false));
        return Err(hypervisor_inactive_error(feature, restart_pending));
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Doctor
//--------------------------------------------------------------------------------------------------

/// Diagnose Windows host virtualization prerequisites for `msb doctor`.
pub(super) fn host_section() -> (super::host::Section, Vec<super::host::Problem>) {
    use super::host::{Check, Problem, Section};

    let arch = std::env::consts::ARCH;
    let mut checks = vec![Check::info("Platform", &format!("Windows {arch}"))];
    let mut problems = Vec::new();

    match verify_windows_host_prerequisites() {
        Ok(()) => checks.push(Check::pass("Hypervisor", "Windows Hypervisor Platform")),
        Err(err) => {
            checks.push(Check::fail("Hypervisor", "unavailable"));
            let mut hints = vec![err.cause()];
            hints.extend(err.hints().iter().map(|hint| (*hint).to_string()));
            problems.push(Problem::new(err.title(), hints));
        }
    }

    (
        Section {
            title: "Host".to_string(),
            checks,
        },
        problems,
    )
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Pick the setup error for a boot session where WHP reports no hypervisor, so
/// the advice never asks to enable a feature that is already enabled.
fn hypervisor_inactive_error(
    feature: FeatureState,
    restart_pending: bool,
) -> WindowsHostSetupError {
    match feature {
        FeatureState::Enabled if restart_pending => WindowsHostSetupError::HypervisorRestartPending,
        FeatureState::Enabled => WindowsHostSetupError::HypervisorNotLaunched,
        FeatureState::NotEnabled => WindowsHostSetupError::HypervisorPlatformNotEnabled,
        FeatureState::Unknown => WindowsHostSetupError::HypervisorNotPresent,
    }
}

/// Run the servicing probe. Returns `None` when PowerShell or WMI is
/// unavailable, fails, or does not answer in time.
fn probe_hypervisor_platform_servicing() -> Option<String> {
    let mut child = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            SERVICING_PROBE_SCRIPT,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .ok()?;

    let deadline = Instant::now() + SERVICING_PROBE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(SERVICING_PROBE_POLL_INTERVAL);
            }
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }

    let output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Parse `<InstallState>;<True|False>` from the servicing probe.
///
/// `Win32_OptionalFeature.InstallState` is 1 (Enabled), 2 (Disabled),
/// 3 (Absent), or 4 (Unknown).
fn parse_servicing_probe(output: &str) -> (FeatureState, bool) {
    let Some((install_state, restart_pending)) = output.trim().split_once(';') else {
        return (FeatureState::Unknown, false);
    };

    let feature = match install_state.trim() {
        "1" => FeatureState::Enabled,
        "2" | "3" => FeatureState::NotEnabled,
        _ => FeatureState::Unknown,
    };
    let restart_pending = restart_pending.trim().eq_ignore_ascii_case("true");

    (feature, restart_pending)
}

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
    fn disabled_feature_gets_enable_advice() {
        let error = hypervisor_inactive_error(FeatureState::NotEnabled, false);
        let rendered = error.to_string();

        assert_eq!(error, WindowsHostSetupError::HypervisorPlatformNotEnabled);
        assert!(rendered.contains(ENABLE_HYPERVISOR_PLATFORM_COMMAND));
        assert!(!rendered.contains("hypervisorlaunchtype"));
    }

    #[test]
    fn enabled_feature_with_pending_restart_gets_restart_advice() {
        let error = hypervisor_inactive_error(FeatureState::Enabled, true);
        let rendered = error.to_string();

        assert_eq!(error, WindowsHostSetupError::HypervisorRestartPending);
        assert!(rendered.contains("Restart Windows"));
        assert!(!rendered.contains(ENABLE_HYPERVISOR_PLATFORM_COMMAND));
    }

    #[test]
    fn enabled_feature_without_pending_restart_lists_launch_causes() {
        let error = hypervisor_inactive_error(FeatureState::Enabled, false);
        let rendered = error.to_string();

        assert_eq!(error, WindowsHostSetupError::HypervisorNotLaunched);
        assert!(!rendered.contains(ENABLE_HYPERVISOR_PLATFORM_COMMAND));

        let firmware = rendered.find("firmware").expect("firmware cause");
        let launch_type = rendered
            .find("bcdedit /set hypervisorlaunchtype auto")
            .expect("hypervisorlaunchtype cause");
        let nested = rendered
            .find("nested virtualization")
            .expect("nested virtualization cause");
        assert!(firmware < launch_type && launch_type < nested);
    }

    #[test]
    fn unknown_feature_state_covers_both_paths() {
        let error = hypervisor_inactive_error(FeatureState::Unknown, true);
        let rendered = error.to_string();

        assert_eq!(error, WindowsHostSetupError::HypervisorNotPresent);
        assert!(rendered.contains(ENABLE_HYPERVISOR_PLATFORM_COMMAND));
        assert!(rendered.contains("hypervisorlaunchtype"));
        assert!(rendered.contains("nested virtualization"));
    }

    #[test]
    fn servicing_probe_output_parses() {
        assert_eq!(
            parse_servicing_probe("1;False\r\n"),
            (FeatureState::Enabled, false)
        );
        assert_eq!(
            parse_servicing_probe("1;True"),
            (FeatureState::Enabled, true)
        );
        assert_eq!(
            parse_servicing_probe("2;False"),
            (FeatureState::NotEnabled, false)
        );
        assert_eq!(
            parse_servicing_probe("3;True"),
            (FeatureState::NotEnabled, true)
        );
        assert_eq!(
            parse_servicing_probe(";False"),
            (FeatureState::Unknown, false)
        );
        assert_eq!(parse_servicing_probe(""), (FeatureState::Unknown, false));
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
