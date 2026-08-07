//! Process lifecycle management for the agent daemon.
//!
//! Initializing [`ProcessManager`] transfers process-wide child-status ownership
//! to its dedicated thread: it drains `waitpid(-1, WNOHANG)` and therefore also
//! consumes statuses for untracked children. Code that needs an exit status must
//! acquire [`ProcessManager::spawn_guard`] before creating the process and finish
//! with [`ProcessSpawnGuard::track`]. It must not independently wait on the same
//! child PID during normal operation. Terminal teardown is the deliberate
//! exception: it may reap any remaining child directly when the manager itself
//! can no longer be assumed healthy.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, mpsc};
use std::task::{Context, Poll};
use std::thread;

use tokio::signal::unix::{Signal, SignalKind};
use tokio::sync::{oneshot, watch};

use crate::error::{AgentdError, AgentdResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

static PROCESS_MANAGER: OnceLock<Arc<ProcessManager>> = OnceLock::new();

/// Maximum number of children reaped while holding the process-state lock.
///
/// Releasing the lock between batches prevents a fork-heavy workload from
/// starving exec spawning and signalling indefinitely.
const REAP_BATCH_SIZE: usize = 64;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Coordinates process spawning, exit observation, and process-wide child reaping.
#[derive(Debug)]
pub struct ProcessManager {
    state: Mutex<ProcessManagerState>,
    startup_error: OnceLock<String>,
    failure_tx: watch::Sender<Option<String>>,
}

#[derive(Debug)]
struct ProcessManagerState {
    processes: HashMap<i32, TrackedProcess>,
    next_generation: u64,
    terminal_error: Option<String>,
}

#[derive(Debug)]
struct TrackedProcess {
    generation: u64,
    exit_tx: Option<oneshot::Sender<i32>>,
}

/// Keeps process reaping paused until a newly spawned PID is tracked.
pub struct ProcessSpawnGuard<'a> {
    state: MutexGuard<'a, ProcessManagerState>,
}

/// Stable identity for one registration of an operating-system PID.
///
/// PIDs can be reused after a child is reaped. The generation prevents an old
/// exec session from signalling a newer process that received the same PID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    pid: i32,
    generation: u64,
}

/// Observes the eventual exit code of a tracked process.
///
/// Processes terminated by a signal resolve to `-1`. If the reaper thread
/// unexpectedly drops the notification, the failure is logged and also resolves
/// to `-1` to preserve the exec-session wire protocol.
pub struct ProcessExitWatcher {
    identity: ProcessIdentity,
    receiver: oneshot::Receiver<i32>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ProcessManager {
    /// Returns the process-wide manager, starting its `SIGCHLD` thread on first use.
    ///
    /// The first call blocks synchronously until the dedicated thread has built
    /// its runtime and installed the `SIGCHLD` listener.
    ///
    /// # Errors
    ///
    /// Returns an error if the thread, runtime, or signal listener cannot start,
    /// or if the process manager has terminated unexpectedly.
    pub fn get() -> AgentdResult<Arc<Self>> {
        if let Some(manager) = PROCESS_MANAGER.get() {
            return manager.result();
        }

        let candidate = Arc::new(Self::new());
        let manager = PROCESS_MANAGER.get_or_init(move || {
            candidate.launch_thread();
            candidate
        });
        manager.result()
    }

    fn new() -> Self {
        let (failure_tx, _) = watch::channel(None);
        Self {
            state: Mutex::new(ProcessManagerState::new()),
            startup_error: OnceLock::new(),
            failure_tx,
        }
    }

    /// Opens a spawn section that must end by tracking the child PID.
    ///
    /// The returned guard serializes the short spawn-to-registration window with
    /// reaping. Production exec requests are already spawned serially by the agent
    /// loop, so allowing parallel spawns here adds complexity without throughput.
    ///
    /// # Errors
    ///
    /// Returns an error if the process manager has terminated.
    pub fn spawn_guard(&self) -> AgentdResult<ProcessSpawnGuard<'_>> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(error) = state.terminal_error.as_ref() {
            return Err(AgentdError::ExecSession(error.clone()));
        }
        Ok(ProcessSpawnGuard { state })
    }

    /// Subscribes to terminal process-manager failures.
    ///
    /// The receiver is created before checking current state so a failure cannot
    /// occur between the check and subscription without being observed.
    pub fn subscribe_failure(&self) -> AgentdResult<watch::Receiver<Option<String>>> {
        let receiver = self.failure_tx.subscribe();
        if let Some(error) = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .terminal_error
            .as_ref()
        {
            return Err(AgentdError::ExecSession(error.clone()));
        }
        Ok(receiver)
    }

    /// Signals a tracked process group only while its registration is current.
    ///
    /// Holding the state lock across the identity check and `kill` prevents a
    /// reaped PID from being registered to a new session in between them.
    pub fn signal_process_group(&self, identity: ProcessIdentity, signum: i32) -> AgentdResult<()> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(process) = state.processes.get(&identity.pid) else {
            return Ok(());
        };
        if process.generation != identity.generation {
            return Ok(());
        }

        if process.exit_tx.is_some() {
            signal_process_group_or_process(identity.pid, signum)
        } else {
            // Once the leader has been reaped, a direct-PID fallback could hit
            // an unrelated process that reused its PID. Only the still-existing
            // process group is a valid target for the completed registration.
            signal_process_group_only(identity.pid, signum)
        }
    }

    /// Releases a process registration when its exec session is no longer signalable.
    pub(crate) fn release(&self, identity: ProcessIdentity) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.matches(identity) {
            state.processes.remove(&identity.pid);
        }
    }

    fn launch_thread(self: &Arc<Self>) {
        let (startup_tx, startup_rx) = mpsc::sync_channel(1);
        let manager = Arc::clone(self);
        let spawn_result = thread::Builder::new()
            .name("agentd-process-manager".to_string())
            .spawn(move || {
                let failure_manager = Arc::clone(&manager);
                let result = catch_unwind(AssertUnwindSafe(|| {
                    run_process_manager_thread(manager, startup_tx)
                }));
                let error = match result {
                    Ok(Err(error)) => error,
                    Ok(Ok(())) => "process manager thread stopped unexpectedly".to_string(),
                    Err(_) => "process manager thread panicked".to_string(),
                };
                failure_manager.fail(error);
            });

        let startup_result = match spawn_result {
            Ok(_) => startup_rx
                .recv()
                .unwrap_or_else(|error| Err(format!("receive thread startup: {error}"))),
            Err(error) => Err(format!("spawn process manager thread: {error}")),
        };
        if let Err(error) = startup_result {
            let _ = self.startup_error.set(error);
        }
    }

    fn result(self: &Arc<Self>) -> AgentdResult<Arc<Self>> {
        if let Some(error) = self.startup_error.get() {
            return Err(AgentdError::ExecSession(format!(
                "start process manager: {error}"
            )));
        }
        match self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .terminal_error
            .as_ref()
        {
            Some(error) => Err(AgentdError::ExecSession(error.clone())),
            None => Ok(Arc::clone(self)),
        }
    }

    fn fail(&self, error: String) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.terminal_error.is_some() {
            return;
        }

        state.terminal_error = Some(error.clone());
        for (pid, process) in &state.processes {
            if process.exit_tx.is_some() {
                let _ = signal_process_group_or_process(*pid, libc::SIGKILL);
            } else {
                let _ = signal_process_group_only(*pid, libc::SIGKILL);
            }
        }
        state.processes.clear();
        drop(state);

        // `send_replace` retains the failure even if the agent has not subscribed yet.
        self.failure_tx.send_replace(Some(error));
    }

    async fn run(self: Arc<Self>, mut signal: Signal) -> Result<(), String> {
        self.reap_until_idle()?;
        while signal.recv().await.is_some() {
            self.reap_until_idle()?;
        }
        Err("process manager SIGCHLD listener closed".to_string())
    }

    fn reap_until_idle(&self) -> Result<(), String> {
        while self.reap_exited_batch()? {
            // The state lock is released between batches. Yielding here gives
            // a waiting spawn or signal request a chance to acquire it.
            thread::yield_now();
        }
        Ok(())
    }

    fn reap_exited_batch(&self) -> Result<bool, String> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state
            .reap_exited_batch()
            .map_err(|error| format!("waitpid failed while reaping processes: {error}"))
    }
}

impl ProcessManagerState {
    fn new() -> Self {
        Self {
            processes: HashMap::new(),
            next_generation: 1,
            terminal_error: None,
        }
    }

    fn track(&mut self, pid: i32) -> AgentdResult<ProcessExitWatcher> {
        if pid <= 0 {
            return Err(AgentdError::ExecSession(format!(
                "cannot track invalid process PID {pid}"
            )));
        }

        let generation = self.next_generation;
        self.next_generation = self.next_generation.checked_add(1).ok_or_else(|| {
            AgentdError::ExecSession("process registration generation exhausted".to_string())
        })?;
        let identity = ProcessIdentity { pid, generation };
        let (exit_tx, receiver) = oneshot::channel();
        match self.processes.entry(pid) {
            Entry::Vacant(entry) => {
                entry.insert(TrackedProcess {
                    generation,
                    exit_tx: Some(exit_tx),
                });
                Ok(ProcessExitWatcher { identity, receiver })
            }
            Entry::Occupied(mut entry) if entry.get().exit_tx.is_none() => {
                // A PID can only be reused after its old process group is gone.
                // Replacing the completed registration invalidates the old
                // session identity without rejecting the new exec request.
                entry.insert(TrackedProcess {
                    generation,
                    exit_tx: Some(exit_tx),
                });
                Ok(ProcessExitWatcher { identity, receiver })
            }
            Entry::Occupied(_) => Err(AgentdError::ExecSession(format!(
                "process PID {pid} is already tracked"
            ))),
        }
    }

    fn matches(&self, identity: ProcessIdentity) -> bool {
        self.processes
            .get(&identity.pid)
            .is_some_and(|process| process.generation == identity.generation)
    }

    /// Reaps at most one bounded batch.
    ///
    /// Returns `true` when the batch filled completely, which tells the caller
    /// to yield and immediately check for more exited children without relying
    /// on another (possibly coalesced) `SIGCHLD` notification.
    fn reap_exited_batch(&mut self) -> std::io::Result<bool> {
        let mut reaped = 0;
        while reaped < REAP_BATCH_SIZE {
            let mut status = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid > 0 {
                reaped += 1;
                let mut remove = false;
                if let Some(process) = self.processes.get_mut(&pid)
                    && let Some(exit_tx) = process.exit_tx.take()
                {
                    // Keep a completed registration as a tombstone while the
                    // exec session drains output and remains signalable. If the
                    // watcher was already dropped, no session owns the identity.
                    remove = exit_tx.send(exit_code(status)).is_err();
                }
                if remove {
                    self.processes.remove(&pid);
                }
                continue;
            }
            if pid == 0 {
                return Ok(false);
            }

            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                return Ok(false);
            }
            return Err(error);
        }
        Ok(true)
    }
}

impl ProcessSpawnGuard<'_> {
    /// Tracks the spawned PID before allowing process reaping to proceed.
    ///
    /// Consuming the guard makes the manager the sole owner of that PID's exit
    /// status during normal operation. Await the returned [`ProcessExitWatcher`]
    /// instead of calling `waitpid` or a child handle's wait method. Terminal
    /// teardown may bypass the manager as a last-resort fallback.
    ///
    /// # Errors
    ///
    /// Returns an error when `pid` is not positive or is already tracked.
    pub fn track(mut self, pid: i32) -> AgentdResult<ProcessExitWatcher> {
        match self.state.track(pid) {
            Ok(exit_watcher) => Ok(exit_watcher),
            Err(error) => {
                // Registration failed while the state lock still prevents the
                // reaper from freeing and reusing this PID.
                if pid > 0 {
                    let _ = signal_process_group_or_process(pid, libc::SIGKILL);
                }
                Err(error)
            }
        }
    }
}

impl ProcessIdentity {
    /// Returns the operating-system PID associated with this registration.
    pub fn pid(self) -> i32 {
        self.pid
    }
}

impl ProcessExitWatcher {
    /// Returns the stable identity of the tracked process.
    pub fn identity(&self) -> ProcessIdentity {
        self.identity
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Future for ProcessExitWatcher {
    type Output = i32;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.receiver).poll(cx) {
            Poll::Ready(Ok(code)) => Poll::Ready(code),
            Poll::Ready(Err(error)) => {
                eprintln!(
                    "agentd: process manager dropped the exit notification for PID {}: {error}",
                    self.identity.pid
                );
                Poll::Ready(-1)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn run_process_manager_thread(
    manager: Arc<ProcessManager>,
    startup: mpsc::SyncSender<Result<(), String>>,
) -> Result<(), String> {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let error = format!("build process manager Tokio runtime: {error}");
            let _ = startup.send(Err(error.clone()));
            return Err(error);
        }
    };

    runtime.block_on(async move {
        match tokio::signal::unix::signal(SignalKind::child()) {
            Ok(signal) => {
                let _ = startup.send(Ok(()));
                manager.run(signal).await
            }
            Err(error) => {
                let error = format!("install process manager SIGCHLD listener: {error}");
                let _ = startup.send(Err(error.clone()));
                Err(error)
            }
        }
    })
}

fn signal_process_group_or_process(pid: i32, signum: i32) -> AgentdResult<()> {
    let group_result = unsafe { libc::kill(-pid, signum) };
    if group_result == 0 {
        return Ok(());
    }

    let group_error = std::io::Error::last_os_error();
    if group_error.raw_os_error() != Some(libc::ESRCH) {
        return Err(group_error.into());
    }

    // A failed pre-exec may exit before establishing its process group. The
    // direct PID is still safe to target because the caller holds the current
    // registration lock, so it cannot refer to a reused process here.
    let process_result = unsafe { libc::kill(pid, signum) };
    if process_result == 0 {
        return Ok(());
    }

    let process_error = std::io::Error::last_os_error();
    if process_error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(process_error.into())
    }
}

fn signal_process_group_only(pid: i32, signum: i32) -> AgentdResult<()> {
    let result = unsafe { libc::kill(-pid, signum) };
    if result == 0 {
        return Ok(());
    }

    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(error.into())
    }
}

fn exit_code(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    const HELPER_ENV: &str = "MSB_AGENTD_PROCESS_MANAGER_HELPER";
    const HELPER_SENTINEL: &str = "process-manager-helper-passed";
    const TEST_NAME: &str = "process::tests::reaping_is_batched_and_tracks_exit_codes";

    #[test]
    fn reaping_is_batched_and_tracks_exit_codes() {
        if std::env::var_os(HELPER_ENV).is_some() {
            run_batched_reap_scenario();
            println!("{HELPER_SENTINEL}");
            return;
        }

        let mut helper = Command::new(std::env::current_exe().expect("current test binary"))
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(HELPER_ENV, "1")
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn isolated process manager test");
        let mut output = String::new();
        helper
            .stdout
            .take()
            .expect("helper stdout")
            .read_to_string(&mut output)
            .expect("read helper stdout");

        match helper.wait() {
            Ok(status) => assert!(status.success(), "helper failed: {status}\n{output}"),
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {}
            Err(error) => panic!("wait for helper: {error}"),
        }
        assert!(
            output.contains(HELPER_SENTINEL),
            "helper did not complete the reap scenario:\n{output}"
        );
    }

    #[test]
    fn invalid_pids_are_rejected() {
        let manager = ProcessManager::new();
        for pid in [-1, 0] {
            let error = match manager
                .spawn_guard()
                .expect("acquire process spawn guard")
                .track(pid)
            {
                Ok(_) => panic!("invalid PID should be rejected"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(&pid.to_string()));
        }
    }

    #[test]
    fn terminal_failure_rejects_spawns_and_wakes_exits() {
        const UNUSED_PID: i32 = i32::MAX;

        let manager = Arc::new(ProcessManager::new());
        let mut failure_rx = manager
            .subscribe_failure()
            .expect("subscribe to process manager failure");
        let exit_watcher = manager
            .spawn_guard()
            .expect("acquire process spawn guard")
            .track(UNUSED_PID)
            .expect("track test PID");

        manager.fail("process manager test failure".to_string());

        assert!(manager.result().is_err());
        assert!(manager.spawn_guard().is_err());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime");
        runtime
            .block_on(failure_rx.changed())
            .expect("receive process manager failure");
        assert_eq!(
            failure_rx.borrow().as_deref(),
            Some("process manager test failure")
        );
        assert_eq!(runtime.block_on(exit_watcher), -1);
    }

    #[test]
    fn stale_identity_does_not_match_reused_pid() {
        const PID: i32 = i32::MAX;

        let manager = ProcessManager::new();
        let first = manager
            .spawn_guard()
            .expect("acquire first process spawn guard")
            .track(PID)
            .expect("track first PID generation");
        let first_identity = first.identity();
        let first_exit_tx = manager
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .processes
            .get_mut(&PID)
            .expect("first process registration")
            .exit_tx
            .take()
            .expect("first exit sender");
        first_exit_tx.send(0).expect("send first exit code");

        assert!(
            manager
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .matches(first_identity)
        );

        let second = manager
            .spawn_guard()
            .expect("acquire second process spawn guard")
            .track(PID)
            .expect("track reused PID generation");
        let second_identity = second.identity();
        assert_ne!(first_identity, second_identity);

        let state = manager
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(!state.matches(first_identity));
        assert!(state.matches(second_identity));
        drop(state);

        // Releasing an old session must not unregister the new owner of the
        // reused PID.
        manager.release(first_identity);
        assert!(
            manager
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .matches(second_identity)
        );
        manager.release(second_identity);
        assert!(
            !manager
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .matches(second_identity)
        );
    }

    fn run_batched_reap_scenario() {
        let manager = Arc::new(ProcessManager::new());
        let mut tracked = Vec::with_capacity(REAP_BATCH_SIZE + 1);
        for offset in 0..=REAP_BATCH_SIZE {
            let code = 10 + (offset % 50) as i32;
            let guard = manager.spawn_guard().expect("acquire process spawn guard");
            let child = Command::new("/bin/sh")
                .args(["-c", &format!("exit {code}")])
                .spawn()
                .expect("spawn tracked child");
            let pid = child.id() as i32;
            drop(child);
            let exit_watcher = guard.track(pid).expect("track child");
            tracked.push((pid, code, exit_watcher));
        }

        for (pid, _, _) in &tracked {
            wait_until_exited_without_reaping(*pid);
        }

        assert!(
            manager
                .reap_exited_batch()
                .expect("reap first bounded batch")
        );
        drop(
            manager
                .spawn_guard()
                .expect("spawn lock should be released between reap batches"),
        );
        assert!(
            !manager
                .reap_exited_batch()
                .expect("reap remaining children")
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime");
        for (_, expected_code, exit_watcher) in tracked {
            assert_eq!(runtime.block_on(exit_watcher), expected_code);
        }

        let orphan = Command::new("/bin/sh")
            .args(["-c", "exit 43"])
            .spawn()
            .expect("spawn untracked child");
        let orphan_pid = orphan.id() as i32;
        drop(orphan);
        wait_until_exited_without_reaping(orphan_pid);

        assert!(!manager.reap_exited_batch().expect("reap untracked child"));
        assert_already_reaped(orphan_pid);
    }

    fn wait_until_exited_without_reaping(pid: i32) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
            let ret = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            assert_eq!(ret, 0, "waitid failed: {}", std::io::Error::last_os_error());
            if unsafe { info.si_pid() } == pid {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }

        panic!("child {pid} did not exit");
    }

    fn assert_already_reaped(pid: i32) {
        let ret = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
        assert_eq!(ret, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
}
