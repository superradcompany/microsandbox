use std::future::Future;
use std::process::Stdio;
use std::sync::Arc;
use std::task::{Context, Wake, Waker};
use std::time::Duration;

use nix::errno::Errno;
use nix::sys::wait::{WaitPidFlag, waitpid};
use nix::unistd::Pid;
use tokio::process::Command;
use tokio::sync::{Mutex, Notify};
use tokio::time::timeout;

use super::{Handoff, ProcessHandle, Work};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Drive the reaper separately from the caller so cancellation can occur exactly
/// after its exit notification, while the caller still holds the process mutex.
struct ReaperWake(Notify);

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Wake for ReaperWake {
    fn wake(self: Arc<Self>) {
        self.0.notify_one();
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn cancelled_wait_after_exit_still_reaps_retained_child() {
    let mut child = Command::new("cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let pid = child.id().unwrap();
    let mut process = ProcessHandle::new(pid, "cancel-at-exit".into(), child, vec![], None, None);
    process.disarm().unwrap();
    let handle = Arc::new(Mutex::new(process));

    let wake = Arc::new(ReaperWake(Notify::new()));
    let waker = Waker::from(wake.clone());
    let mut reaper = Box::pin(Handoff(Some(Work::Retained(Arc::downgrade(&handle)))).reap());
    assert!(
        reaper
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );

    // Poll the same lock-and-wait operation as Sandbox::wait(), then suspend the caller.
    let mut waiter = Box::pin(async { handle.lock().await.wait().await });
    assert!(
        waiter
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(stdin);
    let deadline = Duration::from_secs(5);
    timeout(deadline, wake.0.notified())
        .await
        .expect("reaper never woke");
    assert!(handle.try_lock().is_err());
    assert!(
        reaper
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    drop(waiter);

    timeout(deadline, reaper)
        .await
        .expect("cancelled waiter left the reaper stuck");
    assert_eq!(
        waitpid(Pid::from_raw(pid as i32), Some(WaitPidFlag::WNOHANG)),
        Err(Errno::ECHILD)
    );
    assert!(handle.lock().await.wait().await.unwrap().success());
}
