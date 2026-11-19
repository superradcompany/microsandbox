//! Ownership checks for the exact process recorded by a sandbox run.
//!
//! Executable names and wall-clock timestamps never authorize a signal or deletion.
//! Unverified processes remain live for resource admission and cannot be signaled.

use std::path::Path;
use std::time::Duration;

#[cfg(unix)]
use super::super::control::identity::ProcessIdentity;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::process_record::{LoadedProcessRecord, ProcessRecord, boot_identity};
use super::{LocalContext, run_entity};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(super) enum RecordedRuntime {
    Dead,
    #[cfg(unix)]
    Recycled,
    #[cfg(unix)]
    Unverified {
        pid: i32,
    },
    Live(RuntimeProcess),
}

pub(super) enum RuntimeSignal {
    Terminate,
    Kill,
    #[cfg(unix)]
    Drain,
}

pub(super) struct RuntimeProcess {
    pid: i32,
    #[cfg(unix)]
    identity: ProcessIdentity,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalContext {
    /// Check the recorded process against the sandbox's lifecycle ownership.
    /// Every signal drawn from a recorded PID goes through here,
    /// so a recycled or unprovable PID is never signalled.
    pub(super) async fn recorded_runtime(
        db: &microsandbox_db::DbReadConnection,
        run: Option<&run_entity::Model>,
        lifecycle: &Path,
    ) -> MicrosandboxResult<RecordedRuntime> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(run) = run {
            match ProcessRecord::load(db, run).await? {
                LoadedProcessRecord::Known(record) => {
                    return RecordedRuntime::from_record(&record, run.pid.unwrap());
                }
                LoadedProcessRecord::Unsupported => {
                    // Do not fall back to a PID/lifecycle heuristic for future evidence.
                    return Ok(RecordedRuntime::Unverified {
                        pid: run.pid.unwrap_or_default(),
                    });
                }
                LoadedProcessRecord::Missing { pid } => {
                    return Ok(RecordedRuntime::inspect(pid, lifecycle));
                }
            }
        }
        let _ = db;
        Ok(RecordedRuntime::inspect(
            run.and_then(|run| run.pid),
            lifecycle,
        ))
    }

    /// Poll a signalled runtime process until it exits or `timeout` elapses.
    pub(super) async fn wait_for_runtime_exit(process: &RuntimeProcess, timeout: Duration) {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(50);
        while !process.has_exited() && start.elapsed() < timeout {
            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Whether no process currently owns `name`'s lifecycle lock in this run directory.
    ///
    /// The probe acquires and immediately releases the lock, so it must only run while the
    /// caller holds the name's transition guard.
    pub(super) fn lifecycle_is_unowned(run_dir: &Path, name: &str) -> MicrosandboxResult<bool> {
        Ok(microsandbox_runtime::ipc::try_acquire_lifecycle_guard(run_dir, name)?.is_some())
    }
}

impl RecordedRuntime {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) fn from_record(record: &ProcessRecord, pid: i32) -> MicrosandboxResult<Self> {
        if record.boot != boot_identity()? {
            return Ok(Self::Recycled);
        }
        if let Ok(identity) = ProcessIdentity::capture(pid) {
            if [identity.start.0, identity.start.1] != record.birth {
                return Ok(Self::Recycled);
            }
            #[cfg(target_os = "linux")]
            if !identity.signals_through_handle() {
                return Ok(Self::Unverified { pid });
            }
            return Ok(match identity.has_exited() {
                Ok(true) => Self::Dead,
                Ok(false) => Self::Live(RuntimeProcess { pid, identity }),
                Err(_) => Self::Unverified { pid },
            });
        }
        // Recorded evidence remains authoritative. A failed capture cannot fall
        // back to a second process identified only by a lifecycle descriptor.
        Ok(
            if matches!(super::process_exit::pid_has_exited(pid), Ok(true)) {
                Self::Dead
            } else {
                Self::Unverified { pid }
            },
        )
    }

    pub(super) fn inspect(pid: Option<i32>, lifecycle: &Path) -> Self {
        let Some(pid) = pid.filter(|pid| *pid > 0) else {
            return Self::Dead;
        };
        #[cfg(unix)]
        {
            let identity = match ProcessIdentity::capture(pid) {
                Ok(identity) => identity,
                Err(_) => {
                    // Failed live-identity capture can also mean a zombie leader.
                    // Only whole-process completion authorizes resource admission.
                    return if matches!(super::process_exit::pid_has_exited(pid), Ok(true)) {
                        Self::Dead
                    } else {
                        Self::Unverified { pid }
                    };
                }
            };
            #[cfg(target_os = "linux")]
            if !identity.signals_through_handle() {
                return Self::Unverified { pid };
            }
            let proven = matches!(
                super::process_exit::lifecycle_matches(pid, lifecycle),
                Ok(true)
            );
            match identity.has_exited() {
                Ok(true) => Self::Dead,
                Ok(false) if proven => Self::Live(RuntimeProcess { pid, identity }),
                _ => Self::Unverified { pid },
            }
        }
        #[cfg(windows)]
        {
            let _ = lifecycle;
            if LocalContext::pid_is_alive(pid) {
                Self::Live(RuntimeProcess { pid })
            } else {
                Self::Dead
            }
        }
    }

    pub(super) fn is_live(&self) -> bool {
        #[cfg(unix)]
        {
            matches!(self, Self::Live(_) | Self::Unverified { .. })
        }
        #[cfg(not(unix))]
        {
            matches!(self, Self::Live(_))
        }
    }

    /// Keep admission conservative without claiming an unverified PID is a live runtime.
    pub(super) fn blocking_reason(&self) -> Option<&'static str> {
        match self {
            Self::Live(_) => Some("recorded runtime process is still alive"),
            #[cfg(unix)]
            Self::Unverified { .. } => {
                Some("recorded runtime process ownership cannot be verified")
            }
            _ => None,
        }
    }

    pub(super) fn signallable(
        self,
        _refuse: impl FnOnce(i32) -> MicrosandboxError,
    ) -> MicrosandboxResult<Option<RuntimeProcess>> {
        match self {
            Self::Live(process) => Ok(Some(process)),
            Self::Dead => Ok(None),
            #[cfg(unix)]
            Self::Recycled => Ok(None),
            #[cfg(unix)]
            Self::Unverified { pid } => Err(_refuse(pid)),
        }
    }
}

impl RuntimeProcess {
    pub(super) fn signal(&self, signal: RuntimeSignal) -> MicrosandboxResult<()> {
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
            let _ = signal;
            LocalContext::terminate_pid(self.pid)
        }
    }

    pub(super) fn has_exited(&self) -> bool {
        #[cfg(unix)]
        {
            match self.identity.has_exited() {
                Ok(exited) => exited,
                Err(error) => {
                    tracing::debug!(pid = self.pid, %error, "runtime exit is unconfirmed");
                    false
                }
            }
        }
        #[cfg(windows)]
        {
            LocalContext::pid_has_exited(self.pid)
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, unix))]
#[path = "runtime_identity_tests.rs"]
pub(super) mod test_support;
