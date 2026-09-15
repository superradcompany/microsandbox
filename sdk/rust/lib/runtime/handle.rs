//! Handle to a running sandbox process.
//!
//! [`ProcessHandle`] holds the PID of the sandbox process and provides
//! methods for lifecycle management (signals, wait).

use std::fs::File;
#[cfg(unix)]
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::ExitStatus;

#[cfg(unix)]
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use tokio::process::Child;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(windows)]
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE};

use microsandbox_metrics::MetricsRegistry;

use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Handle to a running sandbox process.
pub struct ProcessHandle {
    /// PID of the sandbox process.
    pid: u32,

    #[cfg(windows)]
    pub(crate) ownership: Option<(super::ownership::RuntimeProcess, bool)>,

    /// Name of the sandbox this process manages.
    sandbox_name: String,

    /// The sandbox child process handle.
    child: Child,

    /// Retained only until preparation completes. No background reader survives creation.
    pub(crate) startup_reader: Option<Box<dyn tokio::io::AsyncBufRead + Send + Unpin>>,

    /// When true, the Drop impl will NOT send SIGTERM.
    detached: bool,

    /// Writer side of the attached-parent watchdog pipe. Keeping this open
    /// lets the child detect when the owner process disappears.
    #[cfg(unix)]
    parent_watchdog: Option<OwnedFd>,

    /// Windows job object that owns the sandbox process tree.
    #[cfg(windows)]
    job: Option<WindowsJob>,

    /// Best-effort cleanup token for a metrics slot that may still be in
    /// `Reserved` if the runtime exits before activation.
    metrics_reservation: Option<MetricsReservationCleanup>,

    /// Startup-owned Windows locks, cleared after duplication into the exact runtime process.
    /// Unix transfers these at spawn. Established handles must not retain parent lock copies.
    _disk_locks: Vec<File>,
}

/// Cancellation owner for a process whose startup has not completed.
///
/// Dropping a Tokio child alone does not terminate it. Keep the process and its locks together
/// until either startup hands them off or cancellation has killed and reaped the child.
pub(crate) struct StartupProcess {
    handle: Option<ProcessHandle>,
}

/// Token used to release a metrics reservation that never reached Active.
#[derive(Clone)]
pub(crate) struct MetricsReservationCleanup {
    shm_name: String,
    slot: u32,
    generation: u64,
    registry: Option<MetricsRegistry>,
}

/// Windows job object used to scope sandbox process cleanup.
#[cfg(windows)]
pub(crate) struct WindowsJob {
    handle: HANDLE,
}

#[cfg(windows)]
unsafe impl Send for WindowsJob {}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl StartupProcess {
    pub(crate) fn new(handle: ProcessHandle) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    pub(crate) fn handle_mut(&mut self) -> &mut ProcessHandle {
        self.handle
            .as_mut()
            .expect("startup owner already consumed")
    }

    pub(crate) fn child_mut(&mut self) -> &mut Child {
        &mut self.handle_mut().child
    }

    /// Transfer ownership without detaching the established process.
    pub(crate) fn into_handle(mut self) -> ProcessHandle {
        self.handle.take().expect("startup owner already consumed")
    }
}

impl ProcessHandle {
    /// Transfer sidecar ownership while startup cancellation still owns and can reap the child.
    #[cfg(windows)]
    pub(crate) async fn handoff_disk_locks(&mut self) -> MicrosandboxResult<()> {
        use std::os::windows::io::AsRawHandle;
        use tokio::io::AsyncWriteExt;
        use windows_sys::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle};
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        if self._disk_locks.is_empty() {
            return Ok(());
        }
        let process = self
            .child
            .raw_handle()
            .ok_or_else(|| std::io::Error::other("runtime exited before disk ownership handoff"))?;
        let mut handles = Vec::with_capacity(self._disk_locks.len());
        for lock in &self._disk_locks {
            let mut duplicate = std::ptr::null_mut();
            // No inheritable handles are created in either process. Other concurrent spawns
            // cannot steal these locks. Partial failure leaves duplicates owned by the child;
            // the startup guard must terminate/reap it before storage cleanup.
            if unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    lock.as_raw_handle(),
                    process,
                    &mut duplicate,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            handles.push(duplicate as usize);
        }
        let bytes = serde_json::to_vec(&handles)?;
        if bytes.len() > microsandbox_runtime::disk_lock_handoff::MAX_MESSAGE_BYTES {
            return Err(std::io::Error::other("disk lock handoff exceeds startup limit").into());
        }
        let mut stdin = self
            .child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("missing disk ownership startup pipe"))?;
        stdin.write_all(&bytes).await?;
        stdin.shutdown().await?;
        drop(stdin); // EOF commits the complete message; the child cannot boot before it.
        // The duplicates already hold the same file objects, even if the child has not yet
        // read its message. Closing our copies never opens an ownership gap.
        self._disk_locks.clear();
        Ok(())
    }

    /// Wait without a preparation deadline. The caller owns cancellation and process cleanup.
    pub(crate) async fn wait_for_preparation(
        &mut self,
        observer: &Option<tokio::sync::mpsc::WeakSender<crate::CreationProgress>>,
    ) -> MicrosandboxResult<()> {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt};
        let Some(mut reader) = self.startup_reader.take() else {
            // Older runtimes only report a PID. Preserve their bounded readiness path.
            return Ok(());
        };
        loop {
            let mut line = String::new();
            let mut frame = (&mut reader).take(4096);
            let length = tokio::select! {
                result = frame.read_line(&mut line) => result?,
                status = self.child.wait() => {
                    return Err(crate::MicrosandboxError::Runtime(format!(
                        "sandbox exited during preparation: {}", status?
                    )));
                }
            };
            if length == 0 || !line.ends_with('\n') {
                return Err(crate::MicrosandboxError::Runtime(
                    "sandbox startup channel ended before activation or sent an oversized frame"
                        .into(),
                ));
            }
            let event: crate::StartupProgress = serde_json::from_str(&line).map_err(|error| {
                crate::MicrosandboxError::Runtime(format!("invalid startup progress: {error}"))
            })?;
            let activating = event.phase == crate::StartupPhase::Activating;
            crate::progress::report(observer, crate::CreationProgress::Startup(event));
            if activating {
                return Ok(());
            }
        }
    }

    /// Create a new handle.
    pub(crate) fn new(
        pid: u32,
        sandbox_name: String,
        child: Child,
        disk_locks: Vec<File>,
        #[cfg(unix)] parent_watchdog: Option<OwnedFd>,
        #[cfg(windows)] job: Option<WindowsJob>,
        metrics_reservation: Option<MetricsReservationCleanup>,
    ) -> Self {
        // A successful Unix spawn has already inherited these locked open-file descriptions.
        // Close our copies, rather than issuing LOCK_UN (which would unlock the child's copy
        // too). The runtime alone must determine when its disks become available again.
        #[cfg(unix)]
        let disk_locks = {
            drop(disk_locks);
            Vec::new()
        };
        Self {
            pid,
            #[cfg(windows)]
            ownership: None,
            sandbox_name,
            child,
            startup_reader: None,
            detached: false,
            _disk_locks: disk_locks,
            #[cfg(unix)]
            parent_watchdog,
            #[cfg(windows)]
            job,
            metrics_reservation,
        }
    }

    /// Get the sandbox process PID.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Get the sandbox name. Names are limited to 128 UTF-8 bytes.
    pub fn sandbox_name(&self) -> &str {
        &self.sandbox_name
    }

    /// Send SIGKILL to the sandbox process for immediate termination.
    pub fn kill(&self) -> MicrosandboxResult<()> {
        #[cfg(unix)]
        {
            tracing::debug!(pid = self.pid, sandbox = %self.sandbox_name, "sending SIGKILL");
            signal::kill(Pid::from_raw(self.pid as i32), Signal::SIGKILL)?;
            Ok(())
        }

        #[cfg(windows)]
        {
            if let Some(job) = &self.job {
                tracing::debug!(pid = self.pid, sandbox = %self.sandbox_name, "terminating job");
                job.terminate(1)?;
            } else {
                tracing::debug!(pid = self.pid, sandbox = %self.sandbox_name, "terminating process");
                terminate_process(self.pid)?;
            }
            Ok(())
        }
    }

    /// Send SIGUSR1 to the sandbox process to trigger a graceful drain.
    ///
    /// The libkrun signal handler catches SIGUSR1, writes to the exit event
    /// fd, exit observers run, and the process terminates.
    pub fn drain(&self) -> MicrosandboxResult<()> {
        #[cfg(unix)]
        {
            tracing::debug!(pid = self.pid, sandbox = %self.sandbox_name, "sending SIGUSR1 (drain)");
            signal::kill(Pid::from_raw(self.pid as i32), Signal::SIGUSR1)?;
            Ok(())
        }

        #[cfg(windows)]
        {
            Err(crate::MicrosandboxError::Runtime(
                "graceful drain is not supported on Windows yet".into(),
            ))
        }
    }

    /// Wait for the sandbox process to exit.
    pub async fn wait(&mut self) -> MicrosandboxResult<ExitStatus> {
        tracing::debug!(pid = self.pid, sandbox = %self.sandbox_name, "waiting for exit");
        let status = self.child.wait().await?;
        self._disk_locks.clear();
        tracing::debug!(pid = self.pid, ?status, "process exited");
        self.cleanup_metrics_reservation();
        Ok(status)
    }

    /// Check if the process has exited without blocking.
    pub fn try_wait(&mut self) -> MicrosandboxResult<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        if status.is_some() {
            // Also release startup-owned copies on failed handoff. Cleanup may retain this
            // ProcessHandle while deleting the sandbox directory containing the sidecars.
            self._disk_locks.clear();
        }
        Ok(status)
    }

    /// Reap a creator-owned process after startup has failed.
    ///
    /// This is rollback of an unpublished child, not the public graceful-stop API. The child
    /// handle pins process identity; never rediscover a process by sandbox name during cleanup.
    pub(crate) async fn terminate_failed_startup(&mut self) -> MicrosandboxResult<ExitStatus> {
        if let Some(status) = self.try_wait()? {
            self.cleanup_metrics_reservation();
            return Ok(status);
        }
        #[cfg(unix)]
        {
            // Give installed exit observers a chance to reconcile state, but don't let a
            // signal queued before the VMM event loop leave construction alive indefinitely.
            let _ = signal::kill(Pid::from_raw(self.pid as i32), Signal::SIGTERM);
            if let Ok(result) =
                tokio::time::timeout(std::time::Duration::from_secs(1), self.wait()).await
            {
                return result;
            }
        }
        self.child.start_kill()?;
        tokio::time::timeout(std::time::Duration::from_secs(5), self.wait())
            .await
            .map_err(|_| {
                crate::MicrosandboxError::Runtime(format!(
                    "startup cleanup pending: runtime process {} for {:?} has not exited",
                    self.pid, self.sandbox_name,
                ))
            })?
    }

    /// Disarm the SIGTERM safety net so the sandbox keeps running after
    /// this handle is dropped. Used by detached sandbox flows.
    pub fn disarm(&mut self) {
        self.detached = true;

        #[cfg(unix)]
        {
            if let Some(parent_watchdog) = &self.parent_watchdog
                && let Err(err) = send_parent_watchdog_detach(parent_watchdog)
            {
                tracing::debug!(
                    error = %err,
                    sandbox = %self.sandbox_name,
                    "failed to send parent-watch detach"
                );
            }
        }
    }

    fn cleanup_metrics_reservation(&mut self) {
        let Some(metrics_reservation) = self.metrics_reservation.take() else {
            return;
        };
        metrics_reservation.release_reserved(&self.sandbox_name);
    }
}

impl MetricsReservationCleanup {
    /// Create a cleanup token for a reserved metrics slot.
    pub(crate) fn new(
        shm_name: String,
        slot: u32,
        generation: u64,
        registry: Option<MetricsRegistry>,
    ) -> Self {
        Self {
            shm_name,
            slot,
            generation,
            registry,
        }
    }

    fn release_reserved(&self, sandbox_name: &str) {
        let opened;
        let registry = if let Some(registry) = &self.registry {
            registry
        } else {
            opened = match MetricsRegistry::open(&self.shm_name) {
                Ok(registry) => registry,
                Err(err) => {
                    tracing::debug!(
                        error = %err,
                        sandbox = %sandbox_name,
                        "metrics reservation cleanup: failed to open registry"
                    );
                    return;
                }
            };
            &opened
        };
        if let Err(err) = registry.release_reserved(self.slot, self.generation) {
            tracing::debug!(
                error = %err,
                sandbox = %sandbox_name,
                slot = self.slot,
                "metrics reservation cleanup: failed to release reserved slot"
            );
        }
    }
}

#[cfg(windows)]
impl WindowsJob {
    /// Create an unnamed job object that terminates its process tree when the
    /// final job handle closes.
    pub(crate) fn new_kill_on_close() -> std::io::Result<Self> {
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        let mut limits = unsafe { std::mem::zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        let result = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if result == 0 {
            let err = std::io::Error::last_os_error();
            let _ = unsafe { CloseHandle(handle) };
            return Err(err);
        }

        Ok(Self { handle })
    }

    /// Assign a process to this job.
    pub(crate) fn assign_pid(&self, pid: u32) -> std::io::Result<()> {
        let process = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid) };
        if process.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        let result = unsafe { AssignProcessToJobObject(self.handle, process) };
        let result_err = (result == 0).then(std::io::Error::last_os_error);
        let close_result = unsafe { CloseHandle(process) };
        if let Some(err) = result_err {
            return Err(err);
        }
        if close_result == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Terminate every process currently assigned to this job.
    fn terminate(&self, exit_code: u32) -> std::io::Result<()> {
        let result = unsafe { TerminateJobObject(self.handle, exit_code) };
        if result == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for StartupProcess {
    fn drop(&mut self) {
        let Some(mut handle) = self.handle.take() else {
            return;
        };
        if matches!(handle.try_wait(), Ok(Some(_))) {
            handle.cleanup_metrics_reservation();
            return;
        }

        // Cancellation has no caller left to await graceful rollback. Request termination
        // synchronously, before scheduling the reaper: a runtime shutdown must not leave an
        // unpublished VM running merely because the cleanup task never got polled.
        if let Err(error) = handle.child.start_kill() {
            tracing::error!(pid = handle.pid, %error, "failed to terminate cancelled startup");
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                // Retain disk locks and the Windows job until exit, not just until kill is sent.
                // There is deliberately no cleanup deadline that would release these early.
                if let Err(error) = handle.wait().await {
                    tracing::error!(pid = handle.pid, %error, "failed to reap cancelled startup");
                }
            });
        }
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if self.detached {
            return;
        }

        self.cleanup_metrics_reservation();

        // Attached sandboxes are coupled to the owner through the parent
        // watchdog pipe. Dropping the last writer is enough to trigger guest
        // shutdown and lets the runtime distinguish owner-exit cleanup from a
        // normal explicit stop. Keep SIGTERM only for legacy/non-watchdog
        // cases.
        #[cfg(unix)]
        {
            if self.parent_watchdog.is_some() {
                tracing::debug!(
                    sandbox = %self.sandbox_name,
                    "drop: closing parent watchdog writer for attached sandbox cleanup"
                );
                return;
            }
        }

        if let Ok(None) = self.child.try_wait()
            && let Some(pid) = self.child.id()
        {
            #[cfg(unix)]
            {
                tracing::debug!(pid, sandbox = %self.sandbox_name, "drop: sending SIGTERM safety net");
                let _ = signal::kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
            }

            #[cfg(windows)]
            {
                if let Some(job) = &self.job {
                    tracing::debug!(pid, sandbox = %self.sandbox_name, "drop: terminating job");
                    let _ = job.terminate(1);
                } else {
                    tracing::debug!(pid, sandbox = %self.sandbox_name, "drop: terminating child process");
                    let _ = self.child.start_kill();
                }
            }
        }
    }
}

#[cfg(windows)]
impl Drop for WindowsJob {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.handle) };
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(unix)]
fn send_parent_watchdog_detach(fd: &OwnedFd) -> std::io::Result<()> {
    let byte = [microsandbox_runtime::vm::PARENT_WATCH_DETACH];

    loop {
        let written = unsafe {
            libc::write(
                fd.as_raw_fd(),
                byte.as_ptr().cast::<libc::c_void>(),
                byte.len(),
            )
        };
        if written == byte.len() as isize {
            return Ok(());
        }
        if written < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "failed to write parent-watch detach byte",
        ));
    }
}

#[cfg(windows)]
fn terminate_process(pid: u32) -> std::io::Result<()> {
    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error());
    }

    let result = unsafe { windows_sys::Win32::System::Threading::TerminateProcess(handle, 1) };
    let result_err = (result == 0).then(std::io::Error::last_os_error);
    let close_result = unsafe { CloseHandle(handle) };
    if let Some(err) = result_err {
        return Err(err);
    }
    if close_result == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, unix))]
mod startup_tests {
    use std::process::Stdio;

    use tokio::io::{AsyncBufReadExt, BufReader};

    use super::*;

    async fn blocked_startup(ignore_term: bool) -> (ProcessHandle, tokio::process::ChildStdin) {
        let script = if ignore_term {
            "trap '' TERM; printf 'ready\\n'; read value"
        } else {
            "printf 'ready\\n'; read value"
        };
        let mut child = tokio::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        // Wait until the signal disposition is installed, without spawning grandchildren.
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .await
            .unwrap();
        assert_eq!(ready, "ready\n");
        // Tokio's Child::wait closes a child-owned stdin to avoid deadlock. Retain the writer
        // externally so EOF cannot accidentally make our signal-resistant fixture exit.
        let stdin = child.stdin.take().unwrap();
        let handle = ProcessHandle::new(
            child.id().unwrap(),
            "startup-cleanup-test".into(),
            child,
            Vec::new(),
            None,
            None,
        );
        (handle, stdin)
    }

    #[tokio::test]
    async fn failed_startup_is_terminated_and_reaped() {
        let (mut handle, _stdin) = blocked_startup(false).await;
        let status = handle.terminate_failed_startup().await.unwrap();
        assert!(!status.success());
        assert!(handle.try_wait().unwrap().is_some());
        assert!(handle.child.id().is_none());
    }

    #[tokio::test]
    async fn failed_startup_escalates_when_sigterm_is_ignored() {
        let (mut handle, _stdin) = blocked_startup(true).await;
        let status = handle.terminate_failed_startup().await.unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert!(handle.try_wait().unwrap().is_some());
        // Repeated cleanup observes the same exited child instead of signaling a stale PID.
        assert_eq!(handle.terminate_failed_startup().await.unwrap(), status);
    }

    #[tokio::test]
    async fn cancelled_startup_kills_and_reaps_a_signal_resistant_child() {
        let (handle, _stdin) = blocked_startup(true).await;
        let pid = handle.pid();
        let (ready, waiting) = tokio::sync::oneshot::channel();
        let launch = tokio::spawn(async move {
            let _owner = StartupProcess::new(handle);
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        waiting.await.unwrap();
        launch.abort();
        assert!(launch.await.unwrap_err().is_cancelled());

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            // A zombie still answers kill(pid, 0). ESRCH therefore checks reaping, not merely
            // delivery of SIGKILL. The fixture has no grandchildren or unrelated processes.
            while signal::kill(Pid::from_raw(pid as i32), None) != Err(nix::errno::Errno::ESRCH) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cancelled startup child was not reaped");
        assert_eq!(
            nix::sys::wait::waitpid(
                Pid::from_raw(pid as i32),
                Some(nix::sys::wait::WaitPidFlag::WNOHANG),
            ),
            Err(nix::errno::Errno::ECHILD),
        );
    }

    #[tokio::test]
    async fn startup_owner_handoff_preserves_the_live_child() {
        let (handle, _stdin) = blocked_startup(false).await;
        let mut handle = StartupProcess::new(handle).into_handle();
        tokio::task::yield_now().await;
        assert!(handle.try_wait().unwrap().is_none());
        handle.terminate_failed_startup().await.unwrap();
    }

    #[tokio::test]
    async fn preparation_is_unbounded_and_activation_is_explicit() {
        use tokio::io::AsyncWriteExt;
        let (mut handle, _stdin) = blocked_startup(false).await;
        let (reader, mut writer) = tokio::io::duplex(4096);
        handle.startup_reader = Some(Box::new(BufReader::new(reader)));
        let started = std::time::Instant::now();
        let write = tokio::spawn(async move {
            writer.write_all(b"{\"phase\":\"waiting_for_memory_backing\",\"completed_bytes\":0,\"total_bytes\":null}\n").await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            writer
                .write_all(
                    b"{\"phase\":\"activating\",\"completed_bytes\":0,\"total_bytes\":null}\n",
                )
                .await
                .unwrap();
        });
        let (events, sender) = crate::progress::channel();
        drop(events); // No observer: the internal activation event must still be consumed.
        handle
            .wait_for_preparation(&Some(sender.downgrade()))
            .await
            .unwrap();
        assert!(started.elapsed() >= std::time::Duration::from_millis(100));
        assert!(handle.startup_reader.is_none());
        write.await.unwrap();
        handle.terminate_failed_startup().await.unwrap();
    }

    #[tokio::test]
    async fn preparation_eof_is_not_readiness() {
        let (mut handle, _stdin) = blocked_startup(false).await;
        handle.startup_reader = Some(Box::new(BufReader::new(&b""[..])));
        let error = handle.wait_for_preparation(&None).await.unwrap_err();
        assert!(error.to_string().contains("before activation"));
        handle.terminate_failed_startup().await.unwrap();
    }

    #[tokio::test]
    async fn completed_ram_progress_does_not_start_activation() {
        use tokio::io::AsyncWriteExt;

        let (mut handle, _stdin) = blocked_startup(false).await;
        let (reader, mut writer) = tokio::io::duplex(4096);
        handle.startup_reader = Some(Box::new(BufReader::new(reader)));
        writer.write_all(b"{\"phase\":\"preparing_snapshot\",\"completed_bytes\":4096,\"total_bytes\":4096}\n").await.unwrap();

        // RAM can be complete while CPU/device reconstruction is still in progress.
        // Only the explicit construction-boundary event starts activation deadlines.
        {
            let waiting = handle.wait_for_preparation(&None);
            tokio::pin!(waiting);
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(30), &mut waiting)
                    .await
                    .is_err()
            );
            writer
                .write_all(
                    b"{\"phase\":\"activating\",\"completed_bytes\":0,\"total_bytes\":null}\n",
                )
                .await
                .unwrap();
            waiting.await.unwrap();
        }
        handle.terminate_failed_startup().await.unwrap();
    }

    #[tokio::test]
    async fn legacy_pid_only_runtime_does_not_wait_for_events() {
        let (mut handle, _stdin) = blocked_startup(false).await;
        handle.wait_for_preparation(&None).await.unwrap();
        handle.terminate_failed_startup().await.unwrap();
    }

    #[tokio::test]
    async fn preparation_rejects_oversized_frame() {
        let (mut handle, _stdin) = blocked_startup(false).await;
        handle.startup_reader = Some(Box::new(BufReader::new(std::io::Cursor::new(vec![
            b'x';
            4097
        ]))));
        assert!(
            handle
                .wait_for_preparation(&None)
                .await
                .unwrap_err()
                .to_string()
                .contains("oversized")
        );
        handle.terminate_failed_startup().await.unwrap();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::Read;
    use std::os::fd::FromRawFd;

    use super::*;

    #[test]
    fn test_send_parent_watchdog_detach_writes_detach_byte() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        send_parent_watchdog_detach(&write_fd).unwrap();

        let mut reader = std::fs::File::from(read_fd);
        let mut byte = [0_u8; 1];
        reader.read_exact(&mut byte).unwrap();
        assert_eq!(byte[0], microsandbox_runtime::vm::PARENT_WATCH_DETACH);
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::os::windows::fs::OpenOptionsExt;
    use std::process::Stdio;
    use std::time::Duration;

    use super::*;

    fn open_lock(path: &std::path::Path) -> File {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .open(path)
            .unwrap()
    }

    fn available(path: &std::path::Path) -> bool {
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(path)
            .is_ok()
    }

    fn child(directory: &std::path::Path, locks: Vec<File>) -> ProcessHandle {
        let child = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "runtime::handle::windows_tests::disk_lock_child",
                "--nocapture",
            ])
            .env("MSB_TEST_DISK_HANDOFF", directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        ProcessHandle::new(
            child.id().unwrap(),
            "disk-handoff-test".into(),
            child,
            locks,
            None,
            None,
        )
    }

    async fn ready(directory: &std::path::Path) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !directory.join("ready").exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("child did not adopt disk locks");
    }

    #[test]
    fn disk_lock_child() {
        let Some(directory) = std::env::var_os("MSB_TEST_DISK_HANDOFF") else {
            return;
        };
        let directory = std::path::PathBuf::from(directory);
        // SAFETY: the fixture parent transfers new handles exclusively to this child.
        let _locks =
            unsafe { microsandbox_runtime::disk_lock_handoff::receive(std::io::stdin().lock()) }
                .unwrap();
        std::fs::write(directory.join("ready"), b"ready").unwrap();
        while !directory.join("exit").exists() {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[tokio::test]
    async fn transferred_locks_follow_child_not_retained_sdk_handle() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("disk.lock");
        let mut process = child(directory.path(), vec![open_lock(&path)]);
        process.handoff_disk_locks().await.unwrap();
        assert!(process._disk_locks.is_empty());
        ready(directory.path()).await;
        assert!(!available(&path));
        // An unrelated process must not inherit the transferred, non-inheritable lock.
        let mut unrelated = tokio::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 30"])
            .spawn()
            .unwrap();
        std::fs::write(directory.path().join("exit"), b"exit").unwrap();
        process.wait().await.unwrap();
        assert!(available(&path));
        assert!(unrelated.try_wait().unwrap().is_none());
        unrelated.kill().await.unwrap();
        // Cleanup must work while the original ProcessHandle is still retained.
        std::fs::remove_file(&path).unwrap();
    }

    #[tokio::test]
    async fn detached_handle_drop_does_not_release_live_child_locks() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("disk.lock");
        let mut process = child(directory.path(), vec![open_lock(&path)]);
        process.handoff_disk_locks().await.unwrap();
        ready(directory.path()).await;
        process.disarm();
        drop(process);
        assert!(!available(&path));
        std::fs::write(directory.path().join("exit"), b"exit").unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while !available(&path) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn failed_handoff_releases_parent_and_child_copies_before_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("disk.lock");
        let mut process = child(directory.path(), vec![open_lock(&path)]);
        // DuplicateHandle succeeds, but sending cannot: exercise partial handoff cleanup.
        drop(process.child.stdin.take());
        assert!(process.handoff_disk_locks().await.is_err());
        process.terminate_failed_startup().await.unwrap();
        assert!(available(&path));
        std::fs::remove_file(&path).unwrap();
    }

    #[tokio::test]
    async fn cancellation_after_transfer_releases_child_locks() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("disk.lock");
        let mut process = child(directory.path(), vec![open_lock(&path)]);
        process.handoff_disk_locks().await.unwrap();
        ready(directory.path()).await;
        drop(StartupProcess::new(process));
        tokio::time::timeout(Duration::from_secs(10), async {
            while !available(&path) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
}
