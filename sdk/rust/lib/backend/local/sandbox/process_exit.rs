//! Linux process-wide exit barrier, without reaping or following a recycled PID.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Pins the departing runtime, not a shared disk which another sandbox may acquire next.
pub(super) struct RuntimeExit(OwnedFd);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeExit {
    /// The caller holds the sandbox transition guard across selection and dispatch.
    pub(super) fn capture(pid: Option<i32>, lifecycle: &Path) -> std::io::Result<Option<Self>> {
        let Some(pid) = pid.filter(|pid| *pid > 0) else {
            return Ok(None);
        };
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        // pidfd_open sets CLOEXEC. Neither this handle nor disk descriptors are retained
        // after the stop future finishes, and observing exit never steals Child's wait status.
        let process = Self(unsafe { OwnedFd::from_raw_fd(fd as i32) });
        let inherited = format!(
            "/proc/{pid}/fd/{}",
            microsandbox_runtime::vm::LIFECYCLE_LOCK_FD
        );
        let actual = match std::fs::metadata(inherited) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let expected = std::fs::metadata(lifecycle)?;
        // A stale catalog PID can point to an unrelated process. Require the runtime's
        // inherited lifecycle file, not just a live PID or a terminal database row.
        if (actual.dev(), actual.ino()) != (expected.dev(), expected.ino()) {
            return Ok(None);
        }
        Ok(Some(process))
    }

    pub(super) fn has_exited(&self) -> std::io::Result<bool> {
        let mut poll = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 0) } < 0 {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::Interrupted {
                Ok(false)
            } else {
                Err(error)
            };
        }
        if poll.revents & libc::POLLNVAL != 0 {
            return Err(std::io::Error::other("invalid runtime exit handle"));
        }
        // A process pidfd becomes readable only once the entire thread group has exited;
        // the leader becoming a zombie is insufficient while workers release shared files.
        Ok(poll.revents & (libc::POLLIN | libc::POLLHUP) != 0)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::{BufRead, Read, Write};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    use super::*;

    fn lock_disk(path: &Path) -> std::io::Result<std::fs::File> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        if !microsandbox_utils::process_lock::try_lock_exclusive(&file)? {
            return Err(std::io::ErrorKind::WouldBlock.into());
        }
        Ok(file)
    }

    extern "C" fn exit_leader_only(_: libc::c_int) {
        // Test subprocess only: leave its test worker alive with the shared file table.
        unsafe { libc::syscall(libc::SYS_exit, 0) };
    }

    #[test]
    fn exit_barrier_child() {
        if std::env::var_os("MSB_EXIT_BARRIER_CHILD").is_none() {
            return;
        }
        let mut byte = [0];
        println!("ready");
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_exact(&mut byte).unwrap();
        unsafe {
            libc::signal(
                libc::SIGUSR2,
                exit_leader_only as *const () as libc::sighandler_t,
            );
            libc::syscall(
                libc::SYS_tgkill,
                libc::getpid(),
                libc::getpid(),
                libc::SIGUSR2,
            );
        }
        // Release lifecycle ownership while deliberately retaining the disk and process.
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

    #[test]
    fn exit_barrier_ignores_next_disk_owner_and_does_not_reap() {
        let home = tempfile::tempdir().unwrap();
        let lifecycle =
            microsandbox_runtime::ipc::acquire_lifecycle_guard(home.path(), "exit").unwrap();
        let disk = tempfile::NamedTempFile::new().unwrap();
        let lock = lock_disk(disk.path()).unwrap();
        let lifecycle_fd = lifecycle.as_raw_fd();
        let disk_fd = lock.as_raw_fd();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "backend::local::sandbox::process_exit::tests::exit_barrier_child",
                "--nocapture",
            ])
            .env("MSB_EXIT_BARRIER_CHILD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        unsafe {
            command.pre_exec(move || {
                // Spare copies avoid colliding with source descriptors in busy test processes.
                let lifecycle_copy = libc::fcntl(lifecycle_fd, libc::F_DUPFD_CLOEXEC, 200);
                if lifecycle_copy < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let disk_copy = libc::fcntl(disk_fd, libc::F_DUPFD_CLOEXEC, 200);
                if disk_copy < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::dup2(lifecycle_copy, microsandbox_runtime::vm::LIFECYCLE_LOCK_FD) < 0
                    || libc::dup2(disk_copy, 100) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = scopeguard::guard(command.spawn().unwrap(), |mut child| {
            // A failed assertion must not leave a helper holding inherited disk locks.
            let _ = child.kill();
            let _ = child.wait();
        });
        let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut wait_line = |expected: &str| {
            loop {
                let mut line = String::new();
                assert_ne!(output.read_line(&mut line).unwrap(), 0);
                if line.trim() == expected {
                    break;
                }
            }
        };
        wait_line("ready");
        let barrier = RuntimeExit::capture(
            Some(child.id() as i32),
            &microsandbox_runtime::ipc::lifecycle_lock_path(home.path(), "exit"),
        )
        .unwrap()
        .unwrap();
        drop(lock);
        drop(lifecycle);
        child.stdin.as_mut().unwrap().write_all(b"l").unwrap();
        wait_line("lifecycle-released");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while microsandbox_utils::process::pid_is_alive(child.id() as i32) {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(!barrier.has_exited().unwrap());
        let ownership =
            microsandbox_runtime::ipc::try_acquire_lifecycle_guard(home.path(), "exit").unwrap();
        assert!(ownership.is_some());
        assert!(lock_disk(disk.path()).is_err());
        child.stdin.as_mut().unwrap().write_all(b"d").unwrap();
        wait_line("disk-released");
        let next_owner = lock_disk(disk.path()).unwrap();
        assert!(!barrier.has_exited().unwrap());
        child.stdin.take().unwrap().write_all(b"x").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !barrier.has_exited().unwrap() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(
            child.wait().unwrap().success(),
            "exit observation must not reap Child"
        );
        // Completion is independent of this new owner's continuing exclusive attachment.
        assert!(lock_disk(disk.path()).is_err());
        drop(next_owner);
    }

    #[test]
    fn stale_pid_without_matching_lifecycle_is_not_followed() {
        let home = tempfile::tempdir().unwrap();
        let _owner =
            microsandbox_runtime::ipc::acquire_lifecycle_guard(home.path(), "stale").unwrap();
        assert!(
            RuntimeExit::capture(
                Some(std::process::id() as i32),
                &microsandbox_runtime::ipc::lifecycle_lock_path(home.path(), "stale")
            )
            .unwrap()
            .is_none()
        );
        assert!(RuntimeExit::capture(None, home.path()).unwrap().is_none());
    }
}
