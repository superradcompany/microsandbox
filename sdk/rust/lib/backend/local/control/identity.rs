//! OS identity without any new runtime handshake field or persisted schema.

use std::fs::File;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};

#[cfg(not(any(target_os = "macos", windows)))]
use microsandbox_control_client::ErrorKind;
use microsandbox_control_client::{ClientError, ControlClientError, ControlClientResult};
#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{FILETIME, WAIT_TIMEOUT},
    Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
    System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        WaitForSingleObject,
    },
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ProcessStart(pub u64, pub u64);

/// One process instance: its PID plus the kernel birth token a recycled PID cannot reproduce.
pub(crate) struct ProcessIdentity {
    pub pid: i32,
    pub start: ProcessStart,
    #[cfg(target_os = "linux")]
    handle: Option<File>,
    #[cfg(windows)]
    handle: OwnedHandle,
}

pub(super) struct DatabaseIdentity {
    path: PathBuf,
    id: (u64, u64, u64),
    // Keep the original object alive so an unlinked inode/file ID cannot be
    // recycled and mistaken for this backend's database.
    _file: File,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ProcessIdentity {
    pub fn capture(pid: i32) -> ControlClientResult<Self> {
        if pid <= 0 {
            return Err(ControlClientError::RuntimeChanged);
        }
        #[cfg(target_os = "linux")]
        {
            let start = linux_start(pid)?;
            // Older supported kernels may lack pidfd_open. They still have
            // /proc birth tokens; where available, retain a kernel process handle.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            let handle = if fd >= 0 {
                Some(unsafe { File::from_raw_fd(fd as i32) })
            } else {
                let error = std::io::Error::last_os_error();
                if !matches!(error.raw_os_error(), Some(libc::ENOSYS | libc::EINVAL)) {
                    return Err(process_lookup_error(error));
                }
                None
            };
            let identity = Self { pid, start, handle };
            identity.verify()?;
            Ok(identity)
        }
        #[cfg(target_os = "macos")]
        {
            Ok(Self {
                pid,
                start: macos_start(pid)?,
            })
        }
        #[cfg(windows)]
        {
            let raw = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    0,
                    pid as u32,
                )
            };
            if raw.is_null() {
                return Err(ClientError::from(std::io::Error::last_os_error()).into());
            }
            let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
            let start = windows_start(&handle)?;
            Ok(Self { pid, start, handle })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            Err(ClientError::new(ErrorKind::UnsupportedOperation).into())
        }
    }

    pub fn verify(&self) -> ControlClientResult<()> {
        #[cfg(target_os = "linux")]
        let current = {
            if let Some(handle) = &self.handle {
                let mut poll = libc::pollfd {
                    fd: handle.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let result = unsafe { libc::poll(&mut poll, 1, 0) };
                if result < 0 {
                    return Err(ClientError::from(std::io::Error::last_os_error()).into());
                }
                if result != 0 {
                    return Err(ControlClientError::RuntimeChanged);
                }
            }
            linux_start(self.pid)?
        };
        #[cfg(target_os = "macos")]
        let current = macos_start(self.pid)?;
        #[cfg(windows)]
        let current = windows_start(&self.handle)?;
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        let current = return Err(ClientError::new(ErrorKind::UnsupportedOperation).into());
        if current != self.start {
            return Err(ControlClientError::RuntimeChanged);
        }
        Ok(())
    }

    pub fn verify_peer(&self, pid: i32) -> ControlClientResult<()> {
        if pid != self.pid {
            return Err(ControlClientError::RuntimeChanged);
        }
        self.verify()
    }

    /// Whether signals reach this process instance through a kernel process handle, so a PID
    /// that changes hands after the identity check can never receive them.
    #[cfg(target_os = "linux")]
    pub fn signals_through_handle(&self) -> bool {
        self.handle.is_some()
    }

    /// Whether this process instance has exited. A recycled PID is an exit, never a survivor.
    #[cfg(unix)]
    pub fn has_exited(&self) -> std::io::Result<bool> {
        match self.verify() {
            Ok(()) => Ok(false),
            Err(ControlClientError::RuntimeChanged) => Ok(true),
            Err(error) => Err(std::io::Error::other(error.to_string())),
        }
    }

    /// Wall-clock creation time in Unix microseconds, comparable with a run row's `started_at`.
    #[cfg(unix)]
    pub fn created_unix_micros(&self) -> std::io::Result<i64> {
        #[cfg(target_os = "linux")]
        {
            // starttime counts clock ticks since boot on the boot-time clock. Anchor it to the
            // wall clock now; the anchor moves if the wall clock is stepped after the process
            // started, so callers keep generous slack around this value.
            let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
            if ticks_per_second <= 0 {
                return Err(std::io::Error::last_os_error());
            }
            let realtime = clock_unix_micros(libc::CLOCK_REALTIME)?;
            let boottime = clock_unix_micros(libc::CLOCK_BOOTTIME)?;
            let since_boot =
                (i128::from(self.start.0) * 1_000_000 / i128::from(ticks_per_second)) as i64;
            Ok(realtime - boottime + since_boot)
        }
        #[cfg(target_os = "macos")]
        {
            // libproc reports the absolute birth timeval; no boot anchor is involved.
            Ok((self.start.0 as i64)
                .saturating_mul(1_000_000)
                .saturating_add(self.start.1 as i64))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }
    }

    /// Deliver `signal` to this process instance.
    ///
    /// Linux signals through the pidfd captured with the identity, so there is no window
    /// between the identity check and delivery. Without a pidfd (Darwin) the birth token is
    /// re-verified immediately before `kill(2)`; the residual window is the gap between those
    /// two syscalls. A process that already exited is not an error.
    #[cfg(unix)]
    pub fn signal(&self, signal: libc::c_int) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(handle) = &self.handle {
            let result = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    handle.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0u32,
                )
            };
            return signal_result(result == 0);
        }
        match self.verify() {
            Ok(()) => {}
            Err(ControlClientError::RuntimeChanged) => return Ok(()),
            Err(error) => return Err(std::io::Error::other(error.to_string())),
        }
        signal_result(unsafe { libc::kill(self.pid, signal) } == 0)
    }
}

impl DatabaseIdentity {
    pub fn capture(path: impl AsRef<Path>) -> ControlClientResult<Self> {
        let file = File::open(path.as_ref()).map_err(ClientError::from)?;
        let id = file_id(&file)?;
        Ok(Self {
            path: path.as_ref().to_owned(),
            id,
            _file: file,
        })
    }

    pub fn verify(&self) -> ControlClientResult<()> {
        let current = File::open(&self.path).map_err(|_| ControlClientError::RuntimeChanged)?;
        if file_id(&current)? != self.id {
            return Err(ControlClientError::RuntimeChanged);
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn linux_start(pid: i32) -> ControlClientResult<ProcessStart> {
    let stat =
        std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(process_lookup_error)?;
    let fields = stat
        .rsplit_once(')')
        .ok_or_else(invalid)?
        .1
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    // Fields after comm begin with state (field 3); starttime is field 22.
    if fields
        .first()
        .is_some_and(|state| matches!(*state, "Z" | "X" | "x"))
    {
        return Err(ControlClientError::RuntimeChanged);
    }
    let ticks = fields
        .get(19)
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_| invalid())?;
    Ok(ProcessStart(ticks, 0))
}

#[cfg(target_os = "macos")]
fn macos_start(pid: i32) -> ControlClientResult<ProcessStart> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    // libproc's typed record supplies both birth components; no guessed struct
    // offsets, wall-clock slack, or kill(pid, 0) equivalence is used for reuse.
    let read = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if read != size {
        return Err(process_lookup_error(std::io::Error::last_os_error()));
    }
    let info = unsafe { info.assume_init() };
    if info.pbi_pid != pid as u32 || info.pbi_status == libc::SZOMB {
        return Err(ControlClientError::RuntimeChanged);
    }
    Ok(ProcessStart(info.pbi_start_tvsec, info.pbi_start_tvusec))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn process_lookup_error(error: std::io::Error) -> ControlClientError {
    // An exited process may disappear before libproc, /proc, or pidfd_open
    // inspects it. That breaks identity continuity; permission and other OS
    // failures remain transport errors rather than being mistaken for exit.
    if matches!(error.raw_os_error(), Some(libc::ESRCH | libc::ENOENT)) {
        ControlClientError::RuntimeChanged
    } else {
        ClientError::from(error).into()
    }
}

#[cfg(windows)]
fn windows_start(handle: &OwnedHandle) -> ControlClientResult<ProcessStart> {
    if unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) } != WAIT_TIMEOUT {
        return Err(ControlClientError::RuntimeChanged);
    }
    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = creation;
    let mut kernel = creation;
    let mut user = creation;
    if unsafe {
        GetProcessTimes(
            handle.as_raw_handle(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(ClientError::from(std::io::Error::last_os_error()).into());
    }
    Ok(ProcessStart(
        (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime),
        0,
    ))
}

fn file_id(file: &File) -> ControlClientResult<(u64, u64, u64)> {
    #[cfg(unix)]
    {
        let metadata = file.metadata().map_err(ClientError::from)?;
        Ok((metadata.dev(), metadata.ino(), 0))
    }
    #[cfg(windows)]
    {
        let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0 {
            return Err(ClientError::from(std::io::Error::last_os_error()).into());
        }
        let info = unsafe { info.assume_init() };
        Ok((
            u64::from(info.dwVolumeSerialNumber),
            u64::from(info.nFileIndexHigh),
            u64::from(info.nFileIndexLow),
        ))
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(ClientError::new(ErrorKind::UnsupportedOperation).into())
    }
}

#[cfg(target_os = "linux")]
fn invalid() -> ControlClientError {
    ClientError::new(ErrorKind::InvalidData).into()
}

#[cfg(target_os = "linux")]
fn clock_unix_micros(clock: libc::clockid_t) -> std::io::Result<i64> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(clock, &mut now) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // `time_t` and `c_long` widths differ across Linux targets; widen both before scaling.
    Ok((i128::from(now.tv_sec) * 1_000_000 + i128::from(now.tv_nsec) / 1_000) as i64)
}

#[cfg(unix)]
fn signal_result(delivered: bool) -> std::io::Result<()> {
    if delivered {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    // The process finished between the identity check and delivery: nothing left to signal.
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(error)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Command, Stdio};

    use super::{ControlClientError, ProcessIdentity};

    //--------------------------------------------------------------------------------------------------
    // Types
    //--------------------------------------------------------------------------------------------------

    struct ProcessFixture(Child);

    //--------------------------------------------------------------------------------------------------
    // Methods
    //--------------------------------------------------------------------------------------------------

    impl ProcessFixture {
        fn start() -> Self {
            let mut child = Self(
                Command::new("/bin/sh")
                    .args([
                        "-c",
                        "printf 'msb ) control' > /proc/self/comm; printf 'ready\\n'; read -r line",
                    ])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
            let mut ready = String::new();
            BufReader::new(child.0.stdout.take().unwrap())
                .read_line(&mut ready)
                .unwrap();
            assert_eq!(ready, "ready\n");
            child
        }
    }

    //--------------------------------------------------------------------------------------------------
    // Trait Implementations
    //--------------------------------------------------------------------------------------------------

    impl Drop for ProcessFixture {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    //--------------------------------------------------------------------------------------------------
    // Tests
    //--------------------------------------------------------------------------------------------------

    #[test]
    fn linux_process_identity_handles_parentheses_and_detects_exit() {
        let mut child = ProcessFixture::start();
        let pid = child.0.id() as i32;
        // Linux comm is parenthesized but may itself contain ')' and spaces.
        // Exercise the actual kernel record, not a synthetic parser fixture.
        assert_eq!(
            std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap(),
            "msb ) control\n"
        );
        let identity = ProcessIdentity::capture(pid).unwrap();
        identity.verify_peer(pid).unwrap();
        assert!(matches!(
            identity.verify_peer(std::process::id() as i32),
            Err(ControlClientError::RuntimeChanged)
        ));
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(identity.verify().is_err());
    }

    #[test]
    fn linux_zombie_is_not_a_reusable_runtime_identity() {
        let mut child = ProcessFixture::start();
        let pid = child.0.id() as i32;
        let identity = ProcessIdentity::capture(pid).unwrap();
        child.0.kill().unwrap();
        // WNOWAIT observes exit without reaping. The PID and /proc record still
        // exist, which must not make this terminated runtime appear reusable.
        let mut status = std::mem::MaybeUninit::<libc::siginfo_t>::uninit();
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    status.as_mut_ptr(),
                    libc::WEXITED | libc::WNOWAIT,
                )
            },
            0
        );
        assert!(matches!(
            identity.verify(),
            Err(ControlClientError::RuntimeChanged)
        ));
        assert!(matches!(
            ProcessIdentity::capture(pid),
            Err(ControlClientError::RuntimeChanged)
        ));
    }
}
