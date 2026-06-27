//! Process-state helpers shared by host-side lifecycle code.

#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, GetLastError, STILL_ACTIVE,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Return whether `pid` names a live, runnable process.
///
/// This intentionally treats zombies as not alive. `kill(pid, 0)` reports
/// success for zombies because the PID still exists, but a zombie sandbox
/// runtime has already exited and can only be reaped by its parent.
pub fn pid_is_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }

    pid_is_alive_platform(pid)
}

#[cfg(unix)]
fn pid_is_alive_platform(pid: i32) -> bool {
    if !pid_exists(pid) {
        return false;
    }

    !pid_is_zombie(pid).unwrap_or(false)
}

#[cfg(windows)]
fn pid_is_alive_platform(pid: i32) -> bool {
    let Ok(pid) = u32::try_from(pid) else {
        return false;
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        // Protected processes can deny query access while still proving that
        // the PID is live enough for cleanup to leave it alone.
        let error = unsafe { GetLastError() };
        return error == ERROR_ACCESS_DENIED;
    }

    let mut exit_code = 0;
    let ok = unsafe { GetExitCodeProcess(handle, &mut exit_code) };
    unsafe { CloseHandle(handle) };

    ok != 0 && exit_code == STILL_ACTIVE as u32
}

#[cfg(not(any(unix, windows)))]
fn pid_is_alive_platform(_pid: i32) -> bool {
    false
}

/// Return whether `pid` exists, regardless of whether it can still run.
#[cfg(unix)]
pub fn pid_exists(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }

    let result = unsafe { libc::kill(pid, 0) };
    if result == 0 {
        return true;
    }

    matches!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(code) if code == libc::EPERM
    )
}

/// Return whether `pid` exists, regardless of whether it can still run.
#[cfg(windows)]
pub fn pid_exists(pid: i32) -> bool {
    let Ok(pid) = u32::try_from(pid) else {
        return false;
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        let error = unsafe { GetLastError() };
        return error == ERROR_ACCESS_DENIED;
    }

    unsafe { CloseHandle(handle) };
    true
}

/// Return whether `pid` exists, regardless of whether it can still run.
#[cfg(not(any(unix, windows)))]
pub fn pid_exists(_pid: i32) -> bool {
    false
}

/// Return whether `pid` is currently a zombie process.
///
/// Returns `None` when the platform cannot report process state or when the
/// process disappears between the existence check and the state probe.
pub fn pid_is_zombie(pid: i32) -> Option<bool> {
    if pid <= 0 {
        return Some(false);
    }

    pid_is_zombie_platform(pid)
}

#[cfg(target_os = "linux")]
fn pid_is_zombie_platform(pid: i32) -> Option<bool> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close_paren = stat.rfind(')')?;
    let state = stat
        .get(close_paren + 1..)?
        .bytes()
        .find(|byte| !byte.is_ascii_whitespace())?;
    Some(state == b'Z')
}

#[cfg(target_os = "macos")]
fn pid_is_zombie_platform(pid: i32) -> Option<bool> {
    // `proc_pidinfo(PROC_PIDTBSDINFO)` returns no record for zombies on
    // Darwin, but the kern.proc.pid sysctl still exposes `extern_proc.p_stat`.
    // On 64-bit Darwin the offset is stable:
    // p_un(16) + p_vmspace(8) + p_sigacts(8) + p_flag(4) = 36.
    const KINFO_PROC_P_STAT_OFFSET: usize = 36;

    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
    let mut len: libc::size_t = 0;
    let size_result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if size_result != 0 || len <= KINFO_PROC_P_STAT_OFFSET {
        return None;
    }

    let mut buf = vec![0u8; len];
    let read_result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if read_result != 0 || len <= KINFO_PROC_P_STAT_OFFSET {
        return None;
    }

    Some(buf[KINFO_PROC_P_STAT_OFFSET] == libc::SZOMB as u8)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn pid_is_zombie_platform(_pid: i32) -> Option<bool> {
    None
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, unix))]
mod tests {
    use std::process::Command;
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn pid_liveness_treats_zombies_as_dead() {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("spawn short-lived child");
        let pid = child.id() as i32;
        let deadline = Instant::now() + Duration::from_secs(5);

        while Instant::now() < deadline {
            if pid_is_zombie(pid) == Some(true) {
                assert!(
                    !pid_is_alive(pid),
                    "zombie process should not count as alive"
                );
                let _ = child.wait();
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        let status = child.try_wait().expect("poll child");
        let _ = child.wait();
        panic!("child did not become observable as a zombie; last status: {status:?}");
    }
}
