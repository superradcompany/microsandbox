//! Identity-checked termination of leaked sandbox runtime processes.
//!
//! On Windows a sandbox VM process can outlive its database row: the guest powers off, the exit observer marks the run terminated, but the host process never finishes exiting and
//! keeps serving the name-derived agent pipes. The helpers here terminate such a process only after proving the PID still names the recorded runtime — a recycled PID must never
//! be killed. Identity holds when the process was created no later than the run row's `started_at` (the runtime inserts that row moments after it starts, while a recycled PID can
//! only be created after the original process died) and, when the image path is queryable, the executable is the `msb` binary.

#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, FILETIME, GetLastError, HANDLE, STILL_ACTIVE,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Allowed clock/timer slack when comparing a process creation time against the run row's `started_at`.
pub(crate) const IDENTITY_CREATION_SLACK_MICROS: i64 = 5_000_000;

/// How long callers should wait for a terminated process to disappear before treating the reap as failed.
pub(crate) const REAP_EXIT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Offset between the Windows FILETIME epoch (1601-01-01) and the Unix epoch, in microseconds.
const FILETIME_UNIX_EPOCH_OFFSET_MICROS: i64 = 11_644_473_600_000_000;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Result of an identity-checked termination attempt.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReapOutcome {
    /// The PID no longer names a live process.
    AlreadyDead,

    /// The process was validated as the recorded runtime and termination was requested.
    Terminated,

    /// A live process holds the PID but is not the recorded runtime (recycled PID); it was left alone.
    IdentityMismatch,

    /// The process could not be opened or queried, so identity is unprovable; it was left alone.
    /// Windows recycles PIDs aggressively, so this is usually a recycled PID landing on a
    /// protected or other-user process rather than a leaked runtime (our own runtime children run
    /// as the same user and stay queryable).
    Unverifiable,
}

/// Process handle that closes on drop so every early return releases it.
#[cfg(windows)]
struct OwnedProcessHandle(HANDLE);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Whether a live process created at `creation_unix_micros` can be the runtime process that
/// recorded `run_started_unix_micros`.
///
/// The runtime writes its run row right after the process starts, so the true process is always
/// created at-or-before `started_at` (within timer granularity). A recycled PID is created only
/// after the original process died, i.e. strictly after `started_at`.
pub(crate) fn creation_may_belong_to_run(
    creation_unix_micros: i64,
    run_started_unix_micros: i64,
) -> bool {
    creation_unix_micros <= run_started_unix_micros + IDENTITY_CREATION_SLACK_MICROS
}

/// Convert FILETIME ticks (100ns units since 1601-01-01) to Unix microseconds.
pub(crate) fn filetime_ticks_to_unix_micros(ticks: u64) -> i64 {
    (ticks / 10) as i64 - FILETIME_UNIX_EPOCH_OFFSET_MICROS
}

/// Whether an executable path names the `msb` binary (`msb` or `msb.exe`, any directory, any case).
///
/// String-based on purpose: `Path` parsing of `C:\...` differs across host platforms, and this
/// must stay unit-testable everywhere.
pub(crate) fn image_basename_is_msb(image_path: &str) -> bool {
    let basename = image_path.rsplit(['/', '\\']).next().unwrap_or(image_path);
    let stem = match basename.len().checked_sub(4) {
        Some(idx)
            if basename.is_char_boundary(idx) && basename[idx..].eq_ignore_ascii_case(".exe") =>
        {
            &basename[..idx]
        }
        _ => basename,
    };
    stem.eq_ignore_ascii_case("msb")
}

/// Terminate the process at `pid` if and only if it is still the runtime recorded at
/// `run_started_unix_micros`.
///
/// Opens one handle with query+terminate rights so the identity check and the `TerminateProcess`
/// call target the same process object — there is no PID-reuse window between check and kill.
/// Returns `Err` only when `TerminateProcess` itself fails on a *verified* runtime process;
/// termination is asynchronous on Windows either way, so callers must poll liveness (bounded by
/// [`REAP_EXIT_WAIT`]) before relying on the process being gone.
#[cfg(windows)]
pub(crate) fn terminate_runtime_process_checked(
    pid: u32,
    run_started_unix_micros: i64,
) -> std::io::Result<ReapOutcome> {
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
            0,
            pid,
        )
    };
    if handle.is_null() {
        let err = unsafe { GetLastError() };
        // No such process — nothing left to reap. Anything else (typically
        // access denied) means we cannot prove what the PID is now.
        if err == ERROR_INVALID_PARAMETER {
            return Ok(ReapOutcome::AlreadyDead);
        }
        return Ok(ReapOutcome::Unverifiable);
    }
    let handle = OwnedProcessHandle(handle);

    let mut exit_code = 0u32;
    if unsafe { GetExitCodeProcess(handle.0, &mut exit_code) } == 0 {
        return Ok(ReapOutcome::Unverifiable);
    }
    if exit_code != STILL_ACTIVE as u32 {
        return Ok(ReapOutcome::AlreadyDead);
    }

    let Some(creation_unix_micros) = process_creation_unix_micros(handle.0) else {
        return Ok(ReapOutcome::Unverifiable);
    };
    if !creation_may_belong_to_run(creation_unix_micros, run_started_unix_micros) {
        return Ok(ReapOutcome::IdentityMismatch);
    }
    // Belt and braces on top of the creation-time check. Unqueryable image
    // paths fall through to the time check alone rather than blocking a reap.
    if let Some(image) = process_image_path(handle.0)
        && !image_basename_is_msb(&image)
    {
        return Ok(ReapOutcome::IdentityMismatch);
    }

    if unsafe { TerminateProcess(handle.0, 1) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(ReapOutcome::Terminated)
}

#[cfg(windows)]
fn process_creation_unix_micros(handle: HANDLE) -> Option<i64> {
    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = creation;
    let mut kernel = creation;
    let mut user = creation;
    if unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        return None;
    }

    let ticks = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    Some(filetime_ticks_to_unix_micros(ticks))
}

#[cfg(windows)]
fn process_image_path(handle: HANDLE) -> Option<String> {
    let mut buf = vec![0u16; 4096];
    let mut len = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len) };
    (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[cfg(windows)]
impl Drop for OwnedProcessHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creation_before_run_start_matches() {
        assert!(creation_may_belong_to_run(1_000_000, 2_000_000));
        assert!(creation_may_belong_to_run(2_000_000, 2_000_000));
    }

    #[test]
    fn creation_within_slack_after_run_start_matches() {
        assert!(creation_may_belong_to_run(
            2_000_000 + IDENTITY_CREATION_SLACK_MICROS,
            2_000_000
        ));
    }

    #[test]
    fn creation_after_slack_is_a_recycled_pid() {
        assert!(!creation_may_belong_to_run(
            2_000_001 + IDENTITY_CREATION_SLACK_MICROS,
            2_000_000
        ));
    }

    #[test]
    fn filetime_epoch_offset_maps_to_unix_epoch() {
        // 1601-01-01 → Unix epoch is exactly 11644473600 seconds of 100ns ticks.
        assert_eq!(filetime_ticks_to_unix_micros(116_444_736_000_000_000), 0);
        assert_eq!(
            filetime_ticks_to_unix_micros(116_444_736_000_000_000 + 10_000_000),
            1_000_000
        );
    }

    #[test]
    fn msb_image_names_match() {
        assert!(image_basename_is_msb(r"C:\Program Files\msb\msb.exe"));
        assert!(image_basename_is_msb(r"C:\Users\dev\MSB.EXE"));
        assert!(image_basename_is_msb("/usr/local/bin/msb"));
        assert!(image_basename_is_msb("msb"));
    }

    #[test]
    fn non_msb_image_names_do_not_match() {
        assert!(!image_basename_is_msb(r"C:\Windows\System32\svchost.exe"));
        assert!(!image_basename_is_msb(r"C:\tools\msb-agent.exe"));
        assert!(!image_basename_is_msb("/usr/bin/cargo"));
        assert!(!image_basename_is_msb(""));
    }
}
