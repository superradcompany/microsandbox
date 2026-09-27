//! Identity-checked view of the process a run row records.
//!
//! A run row keeps the runtime's PID, but the row can outlive the process (SIGKILL, host
//! crash, container kill) and the kernel can hand that PID to an unrelated process. Every
//! local-backend path that signals a recorded PID goes through [`RecordedRuntime`], which
//! requires proof that the PID still names the runtime that wrote the row.
//!
//! A PID held by a live process gets one of three verdicts, each erring toward leaving the
//! process alone:
//!
//! - `Live`: positive proof. The process may be signalled.
//! - `Unverified`: the process might be the runtime, but nothing proves it. It still counts
//!   as live, so no resources are released behind it, and it is never signalled; callers
//!   return an error instead.
//! - `Recycled`: positive proof that the PID now belongs to someone else. It counts as dead
//!   and is never signalled.
//!
//! A wrong `Live` signals a stranger; a wrong `Recycled` lets replacement remove a live VM's
//! storage. Both therefore need evidence that survives the ways a recorded PID can mislead:
//!
//! | lifecycle descriptor (fd 99)                 | creation vs `started_at` | executable | verdict                  |
//! |----------------------------------------------|--------------------------|------------|--------------------------|
//! | this launcher's lock file (same dev/ino)     | any                      | any        | `Live(LifecycleLock)`    |
//! | a lock with this sandbox's name, other inode | any                      | any        | `Unverified`             |
//! | another sandbox's lifecycle lock             | created too late         | any        | `Recycled`               |
//! | another sandbox's lifecycle lock             | missing or in time       | any        | `Unverified`             |
//! | missing, or not a lifecycle lock             | created in time          | msb        | `Live(LegacyRuntime)`    |
//! | missing, not a lifecycle lock, or unreadable | created too late         | other      | `Recycled`               |
//! | missing, not a lifecycle lock, or unreadable | anything else            | any        | `Unverified`             |
//!
//! Only the inode identifies this launcher's lock. The file name is `<sha256(name)>.lock`,
//! which does not depend on the run directory, so the same name on another inode may be this
//! runtime seen from another mount namespace or a runtime of the same sandbox name under a
//! different microsandbox home; neither can be told apart here.
//!
//! Creation time is weak evidence. On Linux it is anchored to the current wall clock, so a
//! clock step in either direction moves it, and it cannot tell the runtime from a process that
//! reused its PID within the timer slack. It is therefore only ever combined with the
//! executable: an `msb` process created in time with no lifecycle descriptor is taken for a
//! runtime older than the inherited descriptor (before v0.6.9), and a process created too late
//! that is positively not `msb` is taken for a stranger. An unreadable executable, or a
//! too-late creation time on an `msb` process (a wall-clock step, or another sandbox's legacy
//! runtime), proves nothing either way. Neither does a descriptor that could not be inspected:
//! it may hold another runtime's lifecycle lock, so it never admits a legacy runtime. A
//! lifecycle lock with a *different* name on a process created too late is a recycled PID the
//! executable check cannot catch, because the new occupant is itself an `msb` runtime.
//!
//! On Linux the identity is pinned with a pidfd before any evidence is read and re-verified
//! afterwards, and signals go through that pidfd, so a PID that changes hands during the check
//! is never signalled. A Linux process without a pidfd is `Unverified`. Darwin has no process
//! handle; there the kernel birth token is re-verified immediately before `kill(2)`, leaving
//! only the gap between those two syscalls.

use std::path::Path;

use chrono::NaiveDateTime;

#[cfg(unix)]
use super::super::control::identity::ProcessIdentity;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// What a run row's recorded PID names right now.
#[cfg_attr(windows, allow(dead_code))]
pub(super) enum RecordedRuntime {
    /// No live process holds the PID (missing, or a zombie).
    Dead,

    /// A live process holds the PID but is provably not the recorded runtime.
    Recycled,

    /// A live process holds the PID, but nothing proves it is the recorded runtime. It is
    /// treated as live and never signalled.
    Unverified {
        /// The recorded PID.
        pid: i32,
    },

    /// A live process proven to be the recorded runtime.
    Live(RuntimeProcess),
}

/// How a live process was tied to its run row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(windows, allow(dead_code))]
pub(super) enum Proof {
    /// The process holds this sandbox's lifecycle lock on the runtime's inherited descriptor.
    LifecycleLock,

    /// No lifecycle descriptor, but the process runs `msb` and was created no later than the
    /// row's `started_at`, within timer slack: a runtime older than the inherited descriptor.
    LegacyRuntime,

    /// Windows keeps its bare-PID rule here; `crate::sandbox::reap` owns identity-checked
    /// termination of leaked runtimes there.
    #[cfg(windows)]
    Unchecked,
}

/// Signals the lifecycle paths deliver to a verified runtime process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RuntimeSignal {
    /// Request graceful termination (SIGTERM).
    Terminate,

    /// Force termination (SIGKILL).
    Kill,

    /// Trigger the legacy drain path (SIGUSR1).
    #[cfg(unix)]
    Drain,
}

/// A live process proven to be the runtime its run row recorded, with a handle that follows
/// the process instance rather than its PID wherever the platform offers one.
pub(super) struct RuntimeProcess {
    pid: i32,
    proof: Proof,
    #[cfg(unix)]
    identity: ProcessIdentity,
}

/// What the process's inherited lifecycle descriptor points at.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LockEvidence {
    /// This launcher's lifecycle lock file, by device and inode.
    Matches,

    /// A lifecycle lock with this sandbox's file name on another inode: this runtime seen from
    /// another mount namespace, or a runtime of the same name under another microsandbox home.
    SameName,

    /// A lifecycle lock that belongs to a different sandbox name.
    OtherSandbox,

    /// No descriptor, or one that is not a lifecycle lock at all.
    Absent,

    /// The descriptor could not be inspected. It may still hold another runtime's lock, so it
    /// never admits a legacy runtime.
    Unreadable,
}

/// How the process's creation time relates to the row's `started_at`.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TimeEvidence {
    /// No `started_at`, or the creation time could not be read.
    Unknown,

    /// Created no later than `started_at` plus slack: consistent with being the runtime.
    Plausible,

    /// Created after `started_at` plus slack: inconsistent with being the runtime.
    TooLate,
}

/// Whether the process runs the `msb` binary.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExeEvidence {
    Msb,
    Other,
    Unknown,
}

/// The outcome of the decision table for a live, pinned process.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Proven(Proof),
    Unverified,
    Recycled,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RecordedRuntime {
    /// Decide what `pid` names for the run row that recorded it.
    ///
    /// `started_at` is the row's own timestamp; `lifecycle` the sandbox's lifecycle lock file
    /// as this launcher would create it. See the module documentation for the decision table.
    /// Observation failures yield [`RecordedRuntime::Unverified`], never
    /// [`RecordedRuntime::Recycled`], and never fail the call.
    pub(super) fn inspect(
        pid: Option<i32>,
        started_at: Option<NaiveDateTime>,
        lifecycle: &Path,
    ) -> Self {
        let Some(pid) = pid.filter(|pid| *pid > 0) else {
            return Self::Dead;
        };
        #[cfg(unix)]
        {
            Self::inspect_unix(pid, started_at, lifecycle)
        }
        #[cfg(windows)]
        {
            let _ = (started_at, lifecycle);
            if super::LocalBackend::pid_is_alive(pid) {
                Self::Live(RuntimeProcess {
                    pid,
                    proof: Proof::Unchecked,
                })
            } else {
                Self::Dead
            }
        }
    }

    #[cfg(unix)]
    fn inspect_unix(pid: i32, started_at: Option<NaiveDateTime>, lifecycle: &Path) -> Self {
        use microsandbox_control_client::ControlClientError;

        let identity = match ProcessIdentity::capture(pid) {
            Ok(identity) => identity,
            Err(error) => {
                // Gone or a zombie is dead. A live process whose kernel record this user cannot
                // read (hidden procfs, another user's process) is unprovable, not dead.
                if !super::LocalBackend::pid_is_alive(pid) {
                    return Self::Dead;
                }
                if !matches!(error, ControlClientError::RuntimeChanged) {
                    tracing::debug!(
                        pid,
                        error = %error,
                        "recorded runtime PID is live but its identity is unreadable"
                    );
                }
                return Self::Unverified { pid };
            }
        };

        // Linux signals only through the pidfd pinned here, so a PID that changes hands after
        // the check can never receive a signal. Without one (a kernel before 5.3), there is no
        // race-free delivery, matching stop and kill's existing pidfd requirement.
        #[cfg(target_os = "linux")]
        if !identity.signals_through_handle() {
            tracing::debug!(pid, "no pidfd for the recorded runtime process");
            return Self::Unverified { pid };
        }

        let lock = lock_evidence(pid, lifecycle);
        let time = match started_at {
            None => TimeEvidence::Unknown,
            Some(started_at) => match identity.created_unix_micros() {
                Ok(created) => {
                    if crate::runtime::reap::creation_may_belong_to_run(
                        created,
                        started_at.and_utc().timestamp_micros(),
                    ) {
                        TimeEvidence::Plausible
                    } else {
                        TimeEvidence::TooLate
                    }
                }
                Err(error) => {
                    tracing::debug!(
                        pid,
                        error = %error,
                        "cannot read the recorded runtime's creation time"
                    );
                    TimeEvidence::Unknown
                }
            },
        };
        // The executable only matters when no lifecycle descriptor settles the question.
        let exe = if time != TimeEvidence::Unknown
            && matches!(lock, LockEvidence::Absent | LockEvidence::Unreadable)
        {
            exe_evidence(pid)
        } else {
            ExeEvidence::Unknown
        };

        // The reads above are attributed to the pinned instance only while it is still alive;
        // a process that exited meanwhile may have handed its PID to a new occupant, and one
        // that can no longer be observed cannot vouch for them either.
        match identity.has_exited() {
            Ok(false) => {}
            Ok(true) => return Self::Dead,
            Err(error) => {
                tracing::debug!(pid, error = %error, "cannot re-verify the recorded runtime process");
                return Self::Unverified { pid };
            }
        }
        match verdict(lock, time, exe) {
            Verdict::Proven(proof) => Self::Live(RuntimeProcess {
                pid,
                proof,
                identity,
            }),
            Verdict::Unverified => Self::Unverified { pid },
            Verdict::Recycled => Self::Recycled,
        }
    }

    /// Whether the row may still have its runtime behind it: proven, or not ruled out.
    pub(super) fn is_live(&self) -> bool {
        matches!(self, Self::Live(_) | Self::Unverified { .. })
    }

    /// The process a lifecycle path may signal: `None` when the PID is dead or recycled.
    ///
    /// An unprovable identity fails with `refuse(pid)`. Signalling it could hit an unrelated
    /// process, and treating it as gone could release resources a live runtime still uses.
    pub(super) fn signallable(
        self,
        refuse: impl FnOnce(i32) -> MicrosandboxError,
    ) -> MicrosandboxResult<Option<RuntimeProcess>> {
        match self {
            Self::Live(process) => Ok(Some(process)),
            Self::Dead | Self::Recycled => Ok(None),
            Self::Unverified { pid } => Err(refuse(pid)),
        }
    }
}

impl RuntimeProcess {
    pub(super) fn pid(&self) -> i32 {
        self.pid
    }

    pub(super) fn proof(&self) -> Proof {
        self.proof
    }

    /// Deliver `signal` to this process instance; a process that already exited is not an error.
    pub(super) fn signal(&self, signal: RuntimeSignal) -> MicrosandboxResult<()> {
        tracing::debug!(
            pid = self.pid(),
            proof = ?self.proof(),
            ?signal,
            "signalling the recorded runtime process"
        );
        #[cfg(unix)]
        {
            let signal = match signal {
                RuntimeSignal::Terminate => libc::SIGTERM,
                RuntimeSignal::Kill => libc::SIGKILL,
                RuntimeSignal::Drain => libc::SIGUSR1,
            };
            self.identity.signal(signal)?;
            Ok(())
        }
        #[cfg(windows)]
        {
            // Windows has no graceful signal; both requests terminate the process.
            match signal {
                RuntimeSignal::Terminate | RuntimeSignal::Kill => {
                    super::LocalBackend::terminate_pid(self.pid)
                }
            }
        }
    }

    /// Whether this process instance has exited, without consuming its wait status.
    ///
    /// Only a confirmed exit counts. An instance that can no longer be observed is still
    /// running as far as callers know, so they never release its resources or write a
    /// terminal row behind it.
    pub(super) fn has_exited(&self) -> bool {
        #[cfg(unix)]
        {
            confirmed_exit(self.pid, self.identity.has_exited())
        }
        #[cfg(windows)]
        {
            super::LocalBackend::pid_has_exited(self.pid)
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Whether an exit observation confirms the instance exited; an observation error does not.
#[cfg(unix)]
fn confirmed_exit(pid: i32, observed: std::io::Result<bool>) -> bool {
    match observed {
        Ok(exited) => exited,
        Err(error) => {
            tracing::debug!(
                pid,
                error = %error,
                "cannot observe the recorded runtime process; treating it as still running"
            );
            false
        }
    }
}

/// The decision table from the module documentation.
#[cfg(unix)]
fn verdict(lock: LockEvidence, time: TimeEvidence, exe: ExeEvidence) -> Verdict {
    match (lock, time, exe) {
        (LockEvidence::Matches, _, _) => Verdict::Proven(Proof::LifecycleLock),
        (LockEvidence::SameName, _, _) => Verdict::Unverified,
        (LockEvidence::OtherSandbox, TimeEvidence::TooLate, _) => Verdict::Recycled,
        (LockEvidence::OtherSandbox, TimeEvidence::Unknown | TimeEvidence::Plausible, _) => {
            Verdict::Unverified
        }
        (LockEvidence::Absent, TimeEvidence::Plausible, ExeEvidence::Msb) => {
            Verdict::Proven(Proof::LegacyRuntime)
        }
        (
            LockEvidence::Absent | LockEvidence::Unreadable,
            TimeEvidence::TooLate,
            ExeEvidence::Other,
        ) => Verdict::Recycled,
        (LockEvidence::Absent | LockEvidence::Unreadable, _, _) => Verdict::Unverified,
    }
}

/// Compare the process's inherited lifecycle descriptor with this launcher's `lifecycle` path.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn lock_evidence(pid: i32, lifecycle: &Path) -> LockEvidence {
    lock_evidence_from(
        pid,
        lifecycle,
        super::process_exit::lifecycle_matches(pid, lifecycle),
        || super::process_exit::lifecycle_link(pid),
    )
}

/// Combine the inode comparison with the descriptor's link, read only when the inode does not
/// already prove the lock. A failed link read is [`LockEvidence::Unreadable`], never absent.
#[cfg(unix)]
fn lock_evidence_from(
    pid: i32,
    lifecycle: &Path,
    matches: std::io::Result<bool>,
    link: impl FnOnce() -> std::io::Result<Option<std::path::PathBuf>>,
) -> LockEvidence {
    match matches {
        Ok(true) => return LockEvidence::Matches,
        Ok(false) => {}
        Err(error) => {
            tracing::debug!(
                pid,
                lifecycle = %lifecycle.display(),
                error = %error,
                "cannot compare the recorded runtime's lifecycle descriptor by inode"
            );
        }
    }
    match link() {
        Ok(Some(link)) => classify_lock_link(&link, lifecycle),
        Ok(None) => LockEvidence::Absent,
        Err(error) => {
            tracing::debug!(
                pid,
                error = %error,
                "cannot read the recorded runtime's lifecycle descriptor path"
            );
            LockEvidence::Unreadable
        }
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn lock_evidence(_pid: i32, _lifecycle: &Path) -> LockEvidence {
    LockEvidence::Unreadable
}

/// Classify the path a lifecycle descriptor points at, as the holder's namespace renders it,
/// once the inode comparison has failed to match.
///
/// The `<sha256(name)>.lock` file name does not depend on the run directory, so a matching
/// name proves nothing about which launcher's lock it is. A different lifecycle lock name
/// under `locks/` can only belong to another sandbox's runtime.
#[cfg(unix)]
fn classify_lock_link(link: &Path, lifecycle: &Path) -> LockEvidence {
    let Some(name) = lock_file_name(link) else {
        return LockEvidence::Absent;
    };
    if lifecycle
        .file_name()
        .is_some_and(|expected| expected == name)
    {
        return LockEvidence::SameName;
    }
    let in_locks_dir = link
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|dir| dir == "locks");
    if in_locks_dir && is_lifecycle_lock_name(name) {
        LockEvidence::OtherSandbox
    } else {
        LockEvidence::Absent
    }
}

/// File name of a descriptor link, without the ` (deleted)` marker procfs appends to an unlinked target.
#[cfg(unix)]
fn lock_file_name(link: &Path) -> Option<&str> {
    let name = link.file_name()?.to_str()?;
    Some(name.strip_suffix(" (deleted)").unwrap_or(name))
}

/// Whether `name` has the shape [`microsandbox_runtime::ipc::lifecycle_lock_path`] produces.
#[cfg(unix)]
fn is_lifecycle_lock_name(name: &str) -> bool {
    let Some(hash) = name.strip_suffix(".lock") else {
        return false;
    };
    hash.len() == microsandbox_runtime::ipc::LEGACY_SOCKET_HASH_BYTES * 2
        && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Whether the process runs the `msb` binary, from its executable path and its command name.
///
/// Either name suffices: the executable link resolves symlinks and survives an upgrade that
/// replaced the binary (procfs marks it ` (deleted)`), while the command name keeps the name
/// the runtime was launched under.
#[cfg(target_os = "linux")]
fn exe_evidence(pid: i32) -> ExeEvidence {
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|path| lock_file_name(&path).map(str::to_owned));
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|comm| comm.trim().to_owned());
    exe_evidence_from_names([exe, comm])
}

/// Whether the process runs the `msb` binary, from libproc's executable path and command name.
#[cfg(target_os = "macos")]
fn exe_evidence(pid: i32) -> ExeEvidence {
    let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let length = unsafe {
        libc::proc_pidpath(
            pid,
            buffer.as_mut_ptr().cast(),
            libc::PROC_PIDPATHINFO_MAXSIZE as u32,
        )
    };
    let exe = usize::try_from(length)
        .ok()
        .filter(|length| *length > 0)
        .and_then(|length| {
            Path::new(std::str::from_utf8(&buffer[..length]).ok()?)
                .file_name()?
                .to_str()
                .map(str::to_owned)
        });
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    let read = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    let comm = (read == size).then(|| {
        let info = unsafe { info.assume_init() };
        let bytes: Vec<u8> = info
            .pbi_comm
            .iter()
            .take_while(|byte| **byte != 0)
            .map(|byte| *byte as u8)
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    });
    exe_evidence_from_names([exe, comm])
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn exe_evidence(_pid: i32) -> ExeEvidence {
    ExeEvidence::Unknown
}

#[cfg(unix)]
fn exe_evidence_from_names(names: [Option<String>; 2]) -> ExeEvidence {
    let mut seen = false;
    for name in names.into_iter().flatten() {
        seen = true;
        if crate::runtime::reap::image_basename_is_msb(&name) {
            return ExeEvidence::Msb;
        }
    }
    if seen {
        ExeEvidence::Other
    } else {
        ExeEvidence::Unknown
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// Test processes the identity check recognises as the `msb` binary.
#[cfg(all(test, unix))]
pub(super) mod test_support {
    use std::path::Path;
    use std::process::{Child, Command};

    /// Spawn `sleep secs` from a copy of the binary named `msb`, as a runtime stand-in.
    ///
    /// The returned directory holds the copy and must outlive the child. A multicall `sleep`
    /// dispatches on `argv[0]`, so that stays `sleep`; the kernel still names the process after
    /// the executed file.
    pub(in crate::backend::local::sandbox) fn spawn_msb_sleep(
        secs: u32,
    ) -> (Child, tempfile::TempDir) {
        use std::os::unix::process::CommandExt;

        let bin = tempfile::tempdir().unwrap();
        let msb = bin.path().join("msb");
        let sleep = ["/bin/sleep", "/usr/bin/sleep"]
            .into_iter()
            .find(|path| Path::new(path).exists())
            .expect("a sleep binary");
        std::fs::copy(sleep, &msb).unwrap();
        // macOS kills a copied platform binary on launch; an ad-hoc signature lets it run.
        #[cfg(target_os = "macos")]
        assert!(
            Command::new("/usr/bin/codesign")
                .args(["--force", "--sign", "-"])
                .arg(&msb)
                .output()
                .unwrap()
                .status
                .success()
        );
        let child = Command::new(&msb)
            .arg0("sleep")
            .arg(secs.to_string())
            .spawn()
            .unwrap();
        (child, bin)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::path::PathBuf;
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};

    use chrono::{TimeDelta, Utc};

    use super::*;

    //----------------------------------------------------------------------------------------------
    // Types
    //----------------------------------------------------------------------------------------------

    /// A long-lived child: an unrelated process, or a stand-in for a runtime.
    struct Bystander(
        Child,
        /// Keeps an `msb` copy on disk for as long as the child runs.
        #[allow(dead_code)]
        Option<tempfile::TempDir>,
    );

    //----------------------------------------------------------------------------------------------
    // Methods
    //----------------------------------------------------------------------------------------------

    impl Bystander {
        /// An unrelated process: positively not `msb`.
        fn spawn() -> Self {
            Self(Command::new("sleep").arg("30").spawn().unwrap(), None)
        }

        /// A process the identity check sees as the `msb` binary.
        fn spawn_msb() -> Self {
            let (child, bin) = super::test_support::spawn_msb_sleep(30);
            Self(child, Some(bin))
        }

        /// Spawn with `lock_fd` inherited on the runtime's lifecycle descriptor number.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        fn spawn_holding(lock_fd: i32) -> Self {
            use std::os::unix::process::CommandExt;

            let mut command = Command::new("sleep");
            command.arg("30");
            unsafe {
                command.pre_exec(move || {
                    // A spare copy avoids a no-op dup2 should the source already sit at the
                    // target number; dup2 then clears CLOEXEC so the child keeps the inherited
                    // lock descriptor exactly as a spawned runtime does.
                    let spare = libc::fcntl(lock_fd, libc::F_DUPFD_CLOEXEC, 200);
                    if spare < 0
                        || libc::dup2(spare, microsandbox_runtime::vm::LIFECYCLE_LOCK_FD) < 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            Self(command.spawn().unwrap(), None)
        }

        fn pid(&self) -> i32 {
            self.0.id() as i32
        }

        fn is_alive(&mut self) -> bool {
            self.0.try_wait().unwrap().is_none()
        }
    }

    //----------------------------------------------------------------------------------------------
    // Trait Implementations
    //----------------------------------------------------------------------------------------------

    impl Drop for Bystander {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    //----------------------------------------------------------------------------------------------
    // Functions
    //----------------------------------------------------------------------------------------------

    fn now() -> NaiveDateTime {
        Utc::now().naive_utc()
    }

    fn an_hour_ago() -> NaiveDateTime {
        (Utc::now() - TimeDelta::hours(1)).naive_utc()
    }

    fn wait_until(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !condition() {
            assert!(Instant::now() < deadline, "condition not met within 5s");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn lock_path(dir: &str, name: &str) -> PathBuf {
        PathBuf::from(dir)
            .join("locks")
            .join(format!("{name}.lock"))
    }

    /// A lifecycle lock path no process holds and no file backs.
    fn unheld_lock() -> PathBuf {
        lock_path("/nonexistent/run", &"c".repeat(32))
    }

    //----------------------------------------------------------------------------------------------
    // Tests
    //----------------------------------------------------------------------------------------------

    #[test]
    fn decision_table() {
        use ExeEvidence as E;
        use LockEvidence as L;
        use TimeEvidence as T;

        for time in [T::Unknown, T::Plausible, T::TooLate] {
            for exe in [E::Msb, E::Other, E::Unknown] {
                assert_eq!(
                    verdict(L::Matches, time, exe),
                    Verdict::Proven(Proof::LifecycleLock)
                );
                // The lock name alone never identifies this launcher's lock.
                assert_eq!(verdict(L::SameName, time, exe), Verdict::Unverified);
                assert_eq!(verdict(L::Absent, T::Unknown, exe), Verdict::Unverified);
                assert_eq!(verdict(L::Unreadable, T::Unknown, exe), Verdict::Unverified);
                // A descriptor that could not be inspected may hold another runtime's lock.
                assert_eq!(
                    verdict(L::Unreadable, T::Plausible, exe),
                    Verdict::Unverified
                );
            }
        }
        for exe in [E::Msb, E::Other, E::Unknown] {
            assert_eq!(verdict(L::OtherSandbox, T::TooLate, exe), Verdict::Recycled);
            assert_eq!(
                verdict(L::OtherSandbox, T::Unknown, exe),
                Verdict::Unverified
            );
            assert_eq!(
                verdict(L::OtherSandbox, T::Plausible, exe),
                Verdict::Unverified
            );
        }
        // Creation time only counts together with the executable, and only a positively
        // absent descriptor admits a legacy runtime.
        assert_eq!(
            verdict(L::Absent, T::Plausible, E::Msb),
            Verdict::Proven(Proof::LegacyRuntime)
        );
        for lock in [L::Absent, L::Unreadable] {
            assert_eq!(verdict(lock, T::Plausible, E::Other), Verdict::Unverified);
            assert_eq!(verdict(lock, T::Plausible, E::Unknown), Verdict::Unverified);
            assert_eq!(verdict(lock, T::TooLate, E::Msb), Verdict::Unverified);
            assert_eq!(verdict(lock, T::TooLate, E::Other), Verdict::Recycled);
            assert_eq!(verdict(lock, T::TooLate, E::Unknown), Verdict::Unverified);
        }
    }

    #[test]
    fn lock_link_classification() {
        let hash_a = "a".repeat(32);
        let hash_b = "b".repeat(32);
        let expected = lock_path("/opt/microsandbox/run", &hash_a);

        // Same name in another run directory: another mount namespace or another home.
        assert_eq!(
            classify_lock_link(&lock_path("/other/run", &hash_a), &expected),
            LockEvidence::SameName
        );
        // An unlinked lock file of the same name is no longer this launcher's lock either.
        assert_eq!(
            classify_lock_link(
                &PathBuf::from(format!(
                    "/opt/microsandbox/run/locks/{hash_a}.lock (deleted)"
                )),
                &expected
            ),
            LockEvidence::SameName
        );
        // Another sandbox's lifecycle lock: this PID now runs a different VM.
        assert_eq!(
            classify_lock_link(&lock_path("/opt/microsandbox/run", &hash_b), &expected),
            LockEvidence::OtherSandbox
        );
        // Sibling lock kinds and arbitrary files on fd 99 are no evidence either way.
        assert_eq!(
            classify_lock_link(
                &PathBuf::from(format!(
                    "/opt/microsandbox/run/locks/{hash_b}.snapshot-lineage.lock"
                )),
                &expected
            ),
            LockEvidence::Absent
        );
        assert_eq!(
            classify_lock_link(&PathBuf::from("/tmp/x.lock"), &expected),
            LockEvidence::Absent
        );
        assert_eq!(
            classify_lock_link(&PathBuf::from("/dev/null"), &expected),
            LockEvidence::Absent
        );
    }

    #[test]
    fn descriptor_probe_errors_are_unreadable_not_absent() {
        use std::io::{Error, ErrorKind};

        let expected = lock_path("/opt/microsandbox/run", &"a".repeat(32));
        let denied = || Error::from(ErrorKind::PermissionDenied);
        // Denied inspection (for example, no ptrace access to /proc/<pid>/fd) proves nothing.
        assert_eq!(
            lock_evidence_from(1, &expected, Err(denied()), || Err(denied())),
            LockEvidence::Unreadable
        );
        assert_eq!(
            lock_evidence_from(1, &expected, Ok(false), || Err(denied())),
            LockEvidence::Unreadable
        );
        // Only a descriptor that is positively not open is absent.
        assert_eq!(
            lock_evidence_from(1, &expected, Ok(false), || Ok(None)),
            LockEvidence::Absent
        );
        // A failed inode comparison still falls through to the readable link.
        assert_eq!(
            lock_evidence_from(1, &expected, Err(denied()), || Ok(Some(lock_path(
                "/opt/microsandbox/run",
                &"b".repeat(32)
            )))),
            LockEvidence::OtherSandbox
        );
        // An inode match needs no link at all.
        assert_eq!(
            lock_evidence_from(1, &expected, Ok(true), || -> std::io::Result<_> {
                panic!("the link is not read once the inode proves the lock")
            }),
            LockEvidence::Matches
        );
        // So an uninspectable descriptor never admits a legacy runtime.
        assert_eq!(
            verdict(
                LockEvidence::Unreadable,
                TimeEvidence::Plausible,
                ExeEvidence::Msb
            ),
            Verdict::Unverified
        );
    }

    #[test]
    fn unobservable_exit_is_not_an_exit() {
        use std::io::{Error, ErrorKind};

        assert!(confirmed_exit(1, Ok(true)));
        assert!(!confirmed_exit(1, Ok(false)));
        // An observation failure must not let kill write Stopped or replace remove storage.
        assert!(!confirmed_exit(
            1,
            Err(Error::from(ErrorKind::PermissionDenied))
        ));
    }

    #[test]
    fn executable_names_identify_msb() {
        assert_eq!(
            exe_evidence_from_names([Some("/usr/local/bin/msb".into()), Some("msb".into())]),
            ExeEvidence::Msb
        );
        // Upgraded binary: procfs marks the unlinked executable, the command name still tells.
        assert_eq!(
            exe_evidence_from_names([Some("msb (deleted)".into()), None]),
            ExeEvidence::Other
        );
        assert_eq!(
            exe_evidence_from_names([
                Some(
                    lock_file_name(Path::new("/opt/bin/msb (deleted)"))
                        .unwrap()
                        .into()
                ),
                None
            ]),
            ExeEvidence::Msb
        );
        assert_eq!(
            exe_evidence_from_names([Some("/usr/bin/sleep".into()), Some("sleep".into())]),
            ExeEvidence::Other
        );
        assert_eq!(exe_evidence_from_names([None, None]), ExeEvidence::Unknown);
    }

    #[test]
    fn missing_and_dead_pids_are_dead() {
        assert!(matches!(
            RecordedRuntime::inspect(None, Some(now()), &unheld_lock()),
            RecordedRuntime::Dead
        ));
        assert!(matches!(
            RecordedRuntime::inspect(Some(-1), Some(now()), &unheld_lock()),
            RecordedRuntime::Dead
        ));
        let mut child = Command::new("sh").arg("-c").arg("exit 0").spawn().unwrap();
        let pid = child.id() as i32;
        // The zombie still owns its PID; the runtime it stood for has nonetheless exited.
        wait_until(|| !super::super::LocalBackend::pid_is_alive(pid));
        assert!(matches!(
            RecordedRuntime::inspect(Some(pid), Some(an_hour_ago()), &unheld_lock()),
            RecordedRuntime::Dead
        ));
        child.wait().unwrap();
        assert!(matches!(
            RecordedRuntime::inspect(Some(pid), None, &unheld_lock()),
            RecordedRuntime::Dead
        ));
    }

    #[test]
    fn stranger_created_after_the_run_started_is_recycled_and_spared() {
        let mut bystander = Bystander::spawn();
        // `sleep` is positively not msb, so a too-late creation time condemns it.
        assert_eq!(exe_evidence(bystander.pid()), ExeEvidence::Other);
        let verdict =
            RecordedRuntime::inspect(Some(bystander.pid()), Some(an_hour_ago()), &unheld_lock());
        assert!(matches!(verdict, RecordedRuntime::Recycled));
        assert!(!verdict.is_live());
        assert!(bystander.is_alive());
    }

    #[test]
    fn stranger_created_in_time_is_unverified_and_spared() {
        // A PID reused within the timer slack, or a backward wall-clock step, makes a
        // stranger look older than the row. Only `msb` may be proven by creation time.
        let mut bystander = Bystander::spawn();
        let verdict = RecordedRuntime::inspect(Some(bystander.pid()), Some(now()), &unheld_lock());
        assert!(matches!(verdict, RecordedRuntime::Unverified { .. }));
        assert!(bystander.is_alive());
    }

    #[test]
    fn legacy_runtime_created_before_the_run_started_is_live_and_signalled() {
        let mut runtime = Bystander::spawn_msb();
        let RecordedRuntime::Live(process) =
            RecordedRuntime::inspect(Some(runtime.pid()), Some(now()), &unheld_lock())
        else {
            panic!("an msb process older than its run row, without a descriptor, is the runtime");
        };
        assert_eq!(process.proof(), Proof::LegacyRuntime);
        assert_eq!(process.pid(), runtime.pid());
        assert!(!process.has_exited());

        process.signal(RuntimeSignal::Kill).unwrap();
        wait_until(|| process.has_exited());
        assert!(!runtime.0.wait().unwrap().success());
        // Delivery after exit reports nothing to do rather than following the PID.
        process.signal(RuntimeSignal::Kill).unwrap();
    }

    #[test]
    fn missing_started_at_is_unverified_live_and_unsignallable() {
        let mut runtime = Bystander::spawn_msb();
        let verdict = RecordedRuntime::inspect(Some(runtime.pid()), None, &unheld_lock());
        // Live for liveness, but no `RuntimeProcess` exists to signal.
        assert!(verdict.is_live());
        assert!(matches!(verdict, RecordedRuntime::Unverified { pid } if pid == runtime.pid()));
        assert!(runtime.is_alive());
    }

    #[test]
    fn stale_started_at_on_an_msb_process_is_unverified() {
        // A too-late creation time never condemns msb: a wall-clock step or another
        // sandbox's legacy runtime looks exactly like this.
        let mut runtime = Bystander::spawn_msb();
        assert_eq!(exe_evidence(runtime.pid()), ExeEvidence::Msb);
        let verdict =
            RecordedRuntime::inspect(Some(runtime.pid()), Some(an_hour_ago()), &unheld_lock());
        assert!(matches!(verdict, RecordedRuntime::Unverified { .. }));
        assert!(runtime.is_alive());
    }

    #[test]
    fn started_at_within_slack_after_creation_is_still_live() {
        let runtime = Bystander::spawn_msb();
        let slack = TimeDelta::microseconds(crate::runtime::reap::IDENTITY_CREATION_SLACK_MICROS);
        // The reaper's slack tolerates timer rounding and small clock drift between the
        // process birth and its row, so a birth shortly after `started_at` is still accepted
        // for a legacy-shaped runtime. This is the accepted tolerance, not an ordering the
        // runtime produces.
        let started_at = (Utc::now() - slack + TimeDelta::seconds(1)).naive_utc();
        assert!(matches!(
            RecordedRuntime::inspect(Some(runtime.pid()), Some(started_at), &unheld_lock()),
            RecordedRuntime::Live(_)
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn lifecycle_lock_holder_is_the_runtime_regardless_of_started_at() {
        let home = tempfile::tempdir().unwrap();
        let guard =
            microsandbox_runtime::ipc::acquire_lifecycle_guard(home.path(), "identity").unwrap();
        let lifecycle = microsandbox_runtime::ipc::lifecycle_lock_path(home.path(), "identity");
        let mut runtime = Bystander::spawn_holding(guard.as_raw_fd());

        // Same inode: the strongest proof, immune to a stale `started_at`.
        let RecordedRuntime::Live(process) =
            RecordedRuntime::inspect(Some(runtime.pid()), Some(an_hour_ago()), &lifecycle)
        else {
            panic!("the lock holder is the runtime even with a stale started_at");
        };
        assert_eq!(process.proof(), Proof::LifecycleLock);

        // Another run directory, whether another mount namespace or another microsandbox
        // home: the lock name is the same sandbox name's, which proves nothing, whether or
        // not that lock file exists here and whatever the creation time says.
        let other_home = tempfile::tempdir().unwrap();
        let foreign = microsandbox_runtime::ipc::lifecycle_lock_path(other_home.path(), "identity");
        assert!(!foreign.exists());
        for started_at in [an_hour_ago(), now()] {
            assert!(matches!(
                RecordedRuntime::inspect(Some(runtime.pid()), Some(started_at), &foreign),
                RecordedRuntime::Unverified { .. }
            ));
        }
        let _other_guard =
            microsandbox_runtime::ipc::acquire_lifecycle_guard(other_home.path(), "identity")
                .unwrap();
        assert!(matches!(
            RecordedRuntime::inspect(Some(runtime.pid()), Some(now()), &foreign),
            RecordedRuntime::Unverified { .. }
        ));

        // A descriptor on a different sandbox's lifecycle lock, on a process created after the
        // row, is a different VM on this PID. With a creation time in step with the row the
        // two signals contradict each other, and the process stays unverified.
        let other_sandbox = microsandbox_runtime::ipc::lifecycle_lock_path(home.path(), "other");
        assert!(matches!(
            RecordedRuntime::inspect(Some(runtime.pid()), Some(an_hour_ago()), &other_sandbox),
            RecordedRuntime::Recycled
        ));
        assert!(matches!(
            RecordedRuntime::inspect(Some(runtime.pid()), Some(now()), &other_sandbox),
            RecordedRuntime::Unverified { .. }
        ));
        assert!(runtime.is_alive());

        process.signal(RuntimeSignal::Terminate).unwrap();
        wait_until(|| process.has_exited());
        assert!(!runtime.0.wait().unwrap().success());
        drop(guard);
    }
}
