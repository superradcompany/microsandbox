//! Linux child collection that survives replacement of SIGCHLD and Tokio shutdown.

use std::sync::{OnceLock, Weak, mpsc};
use std::time::{Duration, Instant};

use tokio::process::Child;
use tokio::runtime::Handle;
use tokio::sync::Mutex;

use super::child_exit::ChildExit;
use super::handle::ProcessHandle;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const POLL_INTERVAL: Duration = Duration::from_millis(250);
static FALLBACK: OnceLock<Option<mpsc::Sender<Work>>> = OnceLock::new();

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Exactly one owner collects an owned child; retained observers access its existing mutex.
enum Work {
    Released(Child),
    Retained(Weak<Mutex<ProcessHandle>>),
}

/// Dropping an unpolled or cancelled task must transfer, rather than lose, its responsibility.
struct Handoff(Option<Work>);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Work {
    fn collect(&mut self) -> bool {
        match self {
            Self::Released(child) => match child.try_wait() {
                Ok(status) => status.is_some(),
                Err(error) => {
                    tracing::warn!(%error, "failed to collect released child");
                    true
                }
            },
            Self::Retained(weak) => {
                let Some(handle) = weak.upgrade() else {
                    // Dropping ProcessHandle transfers its child to Released work.
                    return true;
                };
                let Ok(mut process) = handle.try_lock() else {
                    return false;
                };
                match process.try_wait() {
                    Ok(status) => status.is_some(),
                    Err(error) => {
                        tracing::warn!(%error, "failed to collect retained child");
                        true
                    }
                }
            }
        }
    }

    async fn observe(&self) -> Option<ChildExit> {
        match self {
            Self::Released(child) => ChildExit::observe(child),
            Self::Retained(weak) => {
                let handle = weak.upgrade()?;
                let process = handle.lock().await;
                process.observe_exit()
            }
        }
    }
}

impl Handoff {
    async fn reap(mut self) {
        let work = self.0.as_mut().expect("pending collection");
        if !work.collect() {
            let Some(mut exit) = work.observe().await else {
                self.0 = None;
                return;
            };
            loop {
                // Never hold the process mutex or a strong resource reference while waiting.
                let notified = exit.wait().await;
                if work.collect() {
                    break;
                }
                if notified {
                    // A ready pidfd stays readable. Back off if a concurrent waiter holds
                    // the mutex, rather than spinning on the already delivered readiness.
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
        self.0 = None;
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for Handoff {
    fn drop(&mut self) {
        if let Some(work) = self.0.take() {
            enqueue(work);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn released(mut child: Child, runtime: Option<Handle>) {
    if !matches!(child.try_wait(), Ok(None)) {
        return;
    }
    // Preserve drop's pipe semantics; never keep a guest waiting for a parent pipe EOF.
    drop(child.stdin.take());
    drop(child.stdout.take());
    drop(child.stderr.take());
    schedule(Work::Released(child), runtime);
}

pub(super) fn retained(handle: Weak<Mutex<ProcessHandle>>) {
    schedule(Work::Retained(handle), Handle::try_current().ok());
}

fn schedule(work: Work, runtime: Option<Handle>) {
    let handoff = Handoff(Some(work));
    let Some(runtime) = runtime.or_else(|| Handle::try_current().ok()) else {
        return; // Handoff queues work on the process-wide fallback thread.
    };
    runtime.spawn(handoff.reap());
}

fn enqueue(work: Work) {
    let sender = FALLBACK.get_or_init(|| {
        let (sender, receiver) = mpsc::channel();
        match std::thread::Builder::new()
            .name("msb-reaper".into())
            .spawn(move || fallback_loop(receiver))
        {
            Ok(_) => Some(sender),
            Err(error) => {
                tracing::error!(%error, "cannot start child reaper; using Tokio orphan cleanup");
                None
            }
        }
    });
    if let Some(sender) = sender
        && sender.send(work).is_err()
    {
        tracing::error!("child reaper stopped unexpectedly");
    }
}

fn fallback_loop(receiver: mpsc::Receiver<Work>) {
    let mut pending = Vec::new();
    loop {
        if pending.is_empty() {
            let Ok(work) = receiver.recv() else { return };
            pending.push(work);
        }
        pending.retain_mut(|work| !work.collect());
        if pending.is_empty() {
            continue;
        }
        // One timer for the entire fallback population; arrivals do not accelerate polling.
        let deadline = Instant::now() + POLL_INTERVAL;
        loop {
            match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(work) => pending.push(work),
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
            if Instant::now() >= deadline {
                break;
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests;
