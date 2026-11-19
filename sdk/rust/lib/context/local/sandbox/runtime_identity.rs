//! Ownership checks for the exact process recorded by a sandbox run.
//!
//! Executable names and wall-clock timestamps never authorize a signal or deletion.
//! Unverified processes remain live for resource admission and cannot be signaled.

use std::path::Path;
use std::time::Duration;

use chrono::NaiveDateTime;

#[cfg(unix)]
use super::super::control::identity::ProcessIdentity;
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
        if let Some(run) = run
            && let Some(record) = super::process_record::ProcessRecord::load(db, run).await?
        {
            let pid = run.pid.unwrap(); // load validated a non-null matching PID.
            if record.boot != super::process_record::boot_identity()? {
                return Ok(RecordedRuntime::Recycled);
            }
            if let Ok(identity) = ProcessIdentity::capture(pid) {
                if [identity.start.0, identity.start.1] != record.birth {
                    return Ok(RecordedRuntime::Recycled);
                }
                #[cfg(target_os = "linux")]
                if !identity.signals_through_handle() {
                    return Ok(RecordedRuntime::Unverified { pid });
                }
                return Ok(match identity.has_exited() {
                    Ok(true) => RecordedRuntime::Dead,
                    Ok(false) => RecordedRuntime::Live(RuntimeProcess { pid, identity }),
                    Err(_) => RecordedRuntime::Unverified { pid },
                });
            }
            // Once recorded, this identity stays authoritative. A failed capture
            // cannot fall back to a second, differently identified lifecycle owner.
            return Ok(
                if matches!(super::process_exit::pid_has_exited(pid), Ok(true)) {
                    RecordedRuntime::Dead
                } else {
                    RecordedRuntime::Unverified { pid }
                },
            );
        }
        let _ = db;
        Ok(RecordedRuntime::inspect(
            run.and_then(|run| run.pid),
            run.and_then(|run| run.started_at),
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
    pub(super) fn inspect(
        pid: Option<i32>,
        _started_at: Option<NaiveDateTime>,
        lifecycle: &Path,
    ) -> Self {
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
