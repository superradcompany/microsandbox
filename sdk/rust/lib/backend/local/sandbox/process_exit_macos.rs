//! Observe Darwin runtime teardown without reaping a child or following a recycled PID.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Public Darwin proc-info flavor from <sys/proc_info.h>.
const PROC_PIDFDVNODEINFO: i32 = 1;
/// Public Darwin process flag: the process is working on exiting.
const P_WEXIT: i32 = 0x00002000;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A kqueue registration refers to a process instance, not future users of its PID.
pub(super) struct RuntimeExit {
    queue: Option<OwnedFd>,
    pid: i32,
    identity: ProcessState,
}

#[derive(Clone, Copy)]
struct ProcessState {
    birth: (i64, i32),
    status: u8,
    flags: i32,
}

// libc exposes vnode_info, but not these two public proc-info wrapper layouts.
#[repr(C)]
struct ProcFileInfo {
    open_flags: u32,
    status: u32,
    offset: i64,
    kind: i32,
    guard_flags: u32,
}

#[repr(C)]
struct VnodeFdInfo {
    file: ProcFileInfo,
    vnode: libc::vnode_info,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeExit {
    /// Select under the sandbox transition guard, before requesting shutdown.
    pub(super) fn capture(pid: Option<i32>, lifecycle: &Path) -> io::Result<Option<Self>> {
        let Some(pid) = pid.filter(|pid| *pid > 0) else {
            return Ok(None);
        };
        let Some(identity) = process_state(pid)? else {
            return Ok(None);
        };
        if identity.status == libc::SZOMB as u8 {
            return Ok(None);
        }
        let queue = register_exit(pid)?;
        let observer = Self {
            queue,
            pid,
            identity,
        };
        // The PID may have disappeared/recycled between the identity read and registration.
        // Never wait for a new occupant, even if it later opens the same lifecycle file.
        let Some(current) = process_state(pid)? else {
            return Ok(None);
        };
        if current.birth != identity.birth || current.status == libc::SZOMB as u8 {
            return Ok(None);
        }
        let matches = lifecycle_matches(pid, lifecycle)?;
        let Some(current) = process_state(pid)? else {
            return Ok(None);
        };
        if current.birth != identity.birth || current.status == libc::SZOMB as u8 {
            return Ok(None);
        }
        if matches {
            return Ok(Some(observer));
        }
        // proc_refdrain / descriptor closure can make libproc return ESRCH or EBADF
        // before file teardown completes. An exiting PID is not an already-exited PID.
        // In this narrow race observe its birth-identified teardown; never wait for an
        // unrelated *live* process merely because a catalog row contains its PID.
        if current.flags & P_WEXIT != 0 {
            // Without the still-open descriptor, registration may have missed the exit
            // edge. Use the birth-identified late-exit path instead of awaiting that edge.
            return Ok(Some(Self {
                queue: None,
                ..observer
            }));
        }
        Ok(None)
    }

    pub(super) fn has_exited(&self) -> io::Result<bool> {
        if let Some(queue) = &self.queue {
            let mut event = libc::pollfd {
                fd: queue.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut event, 1, 0) } < 0 {
                let error = io::Error::last_os_error();
                return if error.kind() == io::ErrorKind::Interrupted {
                    Ok(false)
                } else {
                    Err(error)
                };
            }
            if event.revents & (libc::POLLNVAL | libc::POLLERR) != 0 {
                return Err(io::Error::other("invalid runtime exit kqueue"));
            }
            // Only NOTE_EXIT is registered. Darwin issues it after closing the process's
            // file table. Leave it queued so repeated observations remain true.
            // The lifecycle descriptor was verified open after registration, so NOTE_EXIT
            // cannot have preceded it. No process-table scans are needed on this path.
            return Ok(event.revents & libc::POLLIN != 0);
        }
        // Registration can race proc_refdrain and return ESRCH before NOTE_EXIT. A late
        // registration can also miss the edge. kern.proc.pid still sees exiting processes
        // and zombies; libproc and kill(pid, 0) alone cannot prove completed teardown.
        Ok(process_state(self.pid)?.is_none_or(|state| {
            state.birth != self.identity.birth || state.status == libc::SZOMB as u8
        }))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn register_exit(pid: i32) -> io::Result<Option<OwnedFd>> {
    let raw = unsafe { libc::kqueue() };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let queue = unsafe { OwnedFd::from_raw_fd(raw) };
    // kqueues are not inherited across fork; also explicitly exclude exec inheritance.
    if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let change = libc::kevent64_s {
        ident: pid as u64,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ENABLE,
        fflags: libc::NOTE_EXIT,
        data: 0,
        udata: 0,
        ext: [0; 2],
    };
    loop {
        let result = unsafe {
            libc::kevent64(
                raw,
                &change,
                1,
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null(),
            )
        };
        if result >= 0 {
            return Ok(Some(queue));
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::ESRCH) => return Ok(None),
            _ => return Err(error),
        }
    }
}

fn lifecycle_matches(pid: i32, lifecycle: &Path) -> io::Result<bool> {
    let mut info = std::mem::MaybeUninit::<VnodeFdInfo>::zeroed();
    let size = std::mem::size_of::<VnodeFdInfo>();
    let result = unsafe {
        libc::proc_pidfdinfo(
            pid,
            microsandbox_runtime::vm::LIFECYCLE_LOCK_FD,
            PROC_PIDFDVNODEINFO,
            info.as_mut_ptr().cast(),
            size as i32,
        )
    };
    if result <= 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ESRCH | libc::EBADF | libc::ENOENT) => Ok(false),
            _ => Err(error),
        };
    }
    if result as usize != size {
        return Err(io::Error::other(
            "incomplete runtime lifecycle descriptor information",
        ));
    }
    let info = unsafe { info.assume_init() };
    let expected = std::fs::metadata(lifecycle)?;
    Ok((
        u64::from(info.vnode.vi_stat.vst_dev),
        info.vnode.vi_stat.vst_ino,
    ) == (expected.dev(), expected.ino()))
}

fn process_state(pid: i32) -> io::Result<Option<ProcessState>> {
    // The 64-bit Darwin kern.proc.pid ABI starts with extern_proc: timeval at 0,
    // two pointers at 16/24, flags at 32, status at 36, PID at 40. Read byte fields
    // rather than transmuting an incompletely represented kernel structure.
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
    let mut size = 0;
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            4,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if size == 0 {
        return Ok(None);
    }
    let mut bytes = vec![0_u8; size];
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            4,
            bytes.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if size == 0 {
        return Ok(None);
    }
    if size < 44 || size > bytes.len() {
        return Err(io::Error::other("incomplete Darwin process identity"));
    }
    if i32::from_ne_bytes(bytes[40..44].try_into().unwrap()) != pid {
        return Err(io::Error::other(
            "Darwin process identity does not match requested PID",
        ));
    }
    Ok(Some(ProcessState {
        birth: (
            i64::from_ne_bytes(bytes[0..8].try_into().unwrap()),
            i32::from_ne_bytes(bytes[8..12].try_into().unwrap()),
        ),
        flags: i32::from_ne_bytes(bytes[32..36].try_into().unwrap()),
        status: bytes[36],
    }))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::{BufRead, Read, Write};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use super::*;

    fn lock_disk(path: &Path) -> io::Result<std::fs::File> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        if !microsandbox_utils::process_lock::try_lock_exclusive(&file)? {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(file)
    }

    #[test]
    fn exit_barrier_child() {
        if std::env::var_os("MSB_DARWIN_EXIT_CHILD").is_none() {
            return;
        }
        let mut byte = [0];
        println!("ready");
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_exact(&mut byte).unwrap();
        unsafe { libc::close(microsandbox_runtime::vm::LIFECYCLE_LOCK_FD) };
        println!("lifecycle-released");
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_exact(&mut byte).unwrap();
        unsafe { libc::close(100) };
        println!("disk-released");
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_exact(&mut byte).unwrap();
        std::process::exit(0);
    }

    fn spawn_owner(lifecycle_fd: i32, disk_fd: i32) -> Child {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "backend::local::sandbox::process_exit::tests::exit_barrier_child",
                "--nocapture",
            ])
            .env("MSB_DARWIN_EXIT_CHILD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        unsafe {
            command.pre_exec(move || {
                // Duplicate above fixed destinations before replacing anything in the child.
                let lifecycle_copy = libc::fcntl(lifecycle_fd, libc::F_DUPFD_CLOEXEC, 200);
                let disk_copy = libc::fcntl(disk_fd, libc::F_DUPFD_CLOEXEC, 200);
                if lifecycle_copy < 0
                    || disk_copy < 0
                    || libc::dup2(lifecycle_copy, microsandbox_runtime::vm::LIFECYCLE_LOCK_FD) < 0
                    || libc::dup2(disk_copy, 100) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.spawn().unwrap()
    }

    fn wait_line(output: &mut impl BufRead, expected: &str) {
        loop {
            let mut line = String::new();
            assert_ne!(output.read_line(&mut line).unwrap(), 0);
            if line.trim() == expected {
                return;
            }
        }
    }

    fn wait_exit(barrier: &RuntimeExit) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !barrier.has_exited().unwrap() {
            assert!(Instant::now() < deadline, "runtime exit was not observed");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            barrier.has_exited().unwrap(),
            "exit observation must be repeatable"
        );
    }

    fn wait_for_lock<T>(name: &str, mut acquire: impl FnMut() -> io::Result<T>) -> T {
        // An unrelated parallel test may fork while this parent owns the lock.
        // CLOEXEC releases that child's copy at exec, not when our owner closes it.
        // Wait for actual availability; a leaked reference still hits the deadline.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match acquire() {
                Ok(lock) => return lock,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "{name} lock was not released");
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("failed to acquire {name} lock: {error}"),
            }
        }
    }

    #[test]
    fn exit_barrier_waits_past_lifecycle_release_without_following_next_disk_owner() {
        let home = tempfile::tempdir().unwrap();
        let lifecycle =
            microsandbox_runtime::ipc::acquire_lifecycle_guard(home.path(), "exit").unwrap();
        let disk = tempfile::NamedTempFile::new().unwrap();
        let lock = lock_disk(disk.path()).unwrap();
        let mut child = scopeguard::guard(
            spawn_owner(lifecycle.as_raw_fd(), lock.as_raw_fd()),
            |mut child| {
                let _ = child.kill();
                let _ = child.wait();
            },
        );
        let mut output = io::BufReader::new(child.stdout.take().unwrap());
        wait_line(&mut output, "ready");
        let barrier = RuntimeExit::capture(
            Some(child.id() as i32),
            &microsandbox_runtime::ipc::lifecycle_lock_path(home.path(), "exit"),
        )
        .unwrap()
        .unwrap();
        assert!(barrier.queue.is_some());
        assert_ne!(
            unsafe { libc::fcntl(barrier.queue.as_ref().unwrap().as_raw_fd(), libc::F_GETFD) }
                & libc::FD_CLOEXEC,
            0
        );
        drop(lifecycle);
        drop(lock);
        child.stdin.as_mut().unwrap().write_all(b"l").unwrap();
        wait_line(&mut output, "lifecycle-released");
        drop(wait_for_lock("lifecycle", || {
            microsandbox_runtime::ipc::try_acquire_lifecycle_guard(home.path(), "exit")
                .and_then(|guard| guard.ok_or_else(|| io::ErrorKind::WouldBlock.into()))
        }));
        assert!(lock_disk(disk.path()).is_err());
        assert!(!barrier.has_exited().unwrap());
        child.stdin.as_mut().unwrap().write_all(b"d").unwrap();
        wait_line(&mut output, "disk-released");
        let _next_owner = wait_for_lock("disk", || lock_disk(disk.path()));
        assert!(!barrier.has_exited().unwrap());
        child.stdin.as_mut().unwrap().write_all(b"x").unwrap();
        wait_exit(&barrier);
        assert!(
            child.wait().unwrap().success(),
            "observer must not reap Child"
        );
        assert!(
            lock_disk(disk.path()).is_err(),
            "next owner must remain locked"
        );
    }

    #[test]
    fn killed_runtime_releases_disk_before_exit_completion() {
        let home = tempfile::tempdir().unwrap();
        let lifecycle =
            microsandbox_runtime::ipc::acquire_lifecycle_guard(home.path(), "kill").unwrap();
        let disk = tempfile::NamedTempFile::new().unwrap();
        let lock = lock_disk(disk.path()).unwrap();
        let mut child = scopeguard::guard(
            spawn_owner(lifecycle.as_raw_fd(), lock.as_raw_fd()),
            |mut child| {
                let _ = child.kill();
                let _ = child.wait();
            },
        );
        let mut output = io::BufReader::new(child.stdout.take().unwrap());
        wait_line(&mut output, "ready");
        let barrier = RuntimeExit::capture(
            Some(child.id() as i32),
            &microsandbox_runtime::ipc::lifecycle_lock_path(home.path(), "kill"),
        )
        .unwrap()
        .unwrap();
        // Exercise the late-registration fallback as well as the normal kqueue path.
        let late = RuntimeExit {
            queue: None,
            pid: barrier.pid,
            identity: barrier.identity,
        };
        assert!(!late.has_exited().unwrap());
        drop(lifecycle);
        drop(lock);
        child.kill().unwrap();
        wait_exit(&barrier);
        wait_exit(&late);
        let _reused = wait_for_lock("disk", || lock_disk(disk.path()));
        assert!(!child.wait().unwrap().success());
    }

    #[test]
    fn stale_pid_and_missing_process_are_not_followed() {
        let home = tempfile::tempdir().unwrap();
        let _owner =
            microsandbox_runtime::ipc::acquire_lifecycle_guard(home.path(), "stale").unwrap();
        let path = microsandbox_runtime::ipc::lifecycle_lock_path(home.path(), "stale");
        assert!(
            RuntimeExit::capture(Some(std::process::id() as i32), &path)
                .unwrap()
                .is_none()
        );
        assert!(RuntimeExit::capture(None, &path).unwrap().is_none());
        assert!(RuntimeExit::capture(Some(-1), &path).unwrap().is_none());
        let mut child = Command::new("/usr/bin/true").spawn().unwrap();
        child.wait().unwrap();
        assert!(
            RuntimeExit::capture(Some(child.id() as i32), &path)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn process_identity_layout_matches_libproc_and_recycled_identity_completes() {
        let pid = std::process::id() as i32;
        let state = process_state(pid).unwrap().unwrap();
        let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
        let size = std::mem::size_of::<libc::proc_bsdinfo>();
        assert_eq!(
            unsafe {
                libc::proc_pidinfo(
                    pid,
                    libc::PROC_PIDTBSDINFO,
                    0,
                    info.as_mut_ptr().cast(),
                    size as i32,
                )
            },
            size as i32
        );
        let info = unsafe { info.assume_init() };
        assert_eq!(
            state.birth,
            (info.pbi_start_tvsec as i64, info.pbi_start_tvusec as i32)
        );
        assert_eq!(state.status as u32, info.pbi_status);
        let mut identity = state;
        identity.birth.0 -= 1;
        let stale = RuntimeExit {
            queue: None,
            pid,
            identity,
        };
        assert!(stale.has_exited().unwrap());
        // Frozen public proc-info wrapper ABI, independently checked against the SDK headers.
        assert_eq!(std::mem::size_of::<ProcFileInfo>(), 24);
        assert_eq!(std::mem::size_of::<VnodeFdInfo>(), 176);
    }
}
