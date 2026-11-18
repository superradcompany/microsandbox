//! Preserve failed-creation diagnostics until the exact process has been reaped.

use std::time::Duration;

use crate::{MicrosandboxError, MicrosandboxResult, runtime::ProcessHandle};

use super::{DEFAULT_KILL_TIMEOUT, Sandbox};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Attempt existing creator-owned cleanup without reacquiring the name transition lock.
    /// A failure to prove exit must not disappear behind the original creation error.
    pub(crate) async fn creation_failure(&self, error: MicrosandboxError) -> MicrosandboxError {
        let result = if let Some(local) = self.local()
            && let Some(handle) = &local.handle
        {
            let mut handle = handle.lock().await;
            terminate_creation_process(&mut handle, DEFAULT_KILL_TIMEOUT, ProcessHandle::kill).await
        } else {
            Err(MicrosandboxError::Runtime(
                "creator-owned process handle is unavailable".into(),
            ))
        };
        creation_error(error, result)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn terminate_creation_process(
    handle: &mut ProcessHandle,
    timeout: Duration,
    terminate: impl FnOnce(&ProcessHandle) -> MicrosandboxResult<()>,
) -> MicrosandboxResult<()> {
    if handle.try_wait()?.is_some() {
        return Ok(());
    }
    // Keep the existing immediate kill and bounded wait. A refused signal is not proof
    // of survival either: a concurrently departing child can still be reaped successfully.
    let signal_error = terminate(handle).err();
    let wait_error = match tokio::time::timeout(timeout, handle.wait()).await {
        Ok(Ok(_)) => return Ok(()),
        Ok(Err(error)) => error.to_string(),
        Err(_) => "timed out waiting for process exit".into(),
    };
    let signal_detail = signal_error
        .map(|error| format!("; termination request failed: {error}"))
        .unwrap_or_default();
    Err(MicrosandboxError::Runtime(format!(
        "process {} for {:?}: {wait_error}{signal_detail}",
        handle.pid(),
        handle.sandbox_name(),
    )))
}

fn creation_error(
    original: MicrosandboxError,
    cleanup: MicrosandboxResult<()>,
) -> MicrosandboxError {
    match cleanup {
        Ok(()) => original,
        Err(error) => MicrosandboxError::Runtime(format!(
            "{original}; startup cleanup uncertain: termination was not confirmed; \
             the runtime may still be running: {error}"
        )),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, unix))]
mod tests {
    use std::{cell::Cell, process::Stdio};

    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        process::Command,
    };

    use super::*;

    async fn child() -> (ProcessHandle, tokio::process::ChildStdin) {
        let mut child = Command::new("sh")
            .args(["-c", "printf 'ready\\n'; read release"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .await
            .unwrap();
        assert_eq!(ready, "ready\n");
        // Retain stdin outside Child so wait cannot turn a refused kill into an EOF exit.
        let stdin = child.stdin.take().unwrap();
        (
            ProcessHandle::new(
                child.id().unwrap(),
                "creation-confirmation".into(),
                child,
                Vec::new(),
                None,
                None,
            ),
            stdin,
        )
    }

    #[tokio::test]
    async fn confirmed_cleanup_preserves_original_error_kind_and_reaps_child() {
        let (mut handle, _stdin) = child().await;
        let cleanup =
            terminate_creation_process(&mut handle, Duration::from_secs(2), ProcessHandle::kill)
                .await;
        let error = creation_error(
            MicrosandboxError::InvalidConfig("confirmation failed".into()),
            cleanup,
        );
        assert!(matches!(error, MicrosandboxError::InvalidConfig(_)));
        assert!(handle.try_wait().unwrap().is_some());
    }

    #[tokio::test]
    async fn refused_and_unconfirmed_termination_retains_both_failures() {
        let (mut handle, mut stdin) = child().await;
        let calls = Cell::new(0);
        let result = terminate_creation_process(&mut handle, Duration::from_millis(20), |_| {
            calls.set(calls.get() + 1);
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into())
        })
        .await;
        let error = creation_error(
            MicrosandboxError::InvalidConfig("confirmation failed".into()),
            result,
        );
        let message = error.to_string();
        assert!(message.contains("confirmation failed"), "{message}");
        assert!(
            message.contains("termination was not confirmed"),
            "{message}"
        );
        assert!(message.contains("termination request failed"), "{message}");
        assert!(message.contains(&handle.pid().to_string()), "{message}");
        assert_eq!(calls.get(), 1, "cleanup must not replay the mutation");
        assert!(
            handle.try_wait().unwrap().is_none(),
            "the failed cleanup must not claim exit"
        );
        stdin.write_all(b"release\n").await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), handle.wait())
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn accepted_termination_without_exit_is_still_uncertain() {
        let (mut handle, _stdin) = child().await;
        let result =
            terminate_creation_process(&mut handle, Duration::from_millis(20), |_| Ok(())).await;
        let message = creation_error(MicrosandboxError::Custom("original failure".into()), result)
            .to_string();
        assert!(message.contains("timed out"), "{message}");
        assert!(
            message.contains("runtime may still be running"),
            "{message}"
        );
        assert!(handle.try_wait().unwrap().is_none());
        terminate_creation_process(&mut handle, Duration::from_secs(2), ProcessHandle::kill)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn reaped_child_does_not_receive_another_termination_request() {
        let (mut handle, mut stdin) = child().await;
        stdin.write_all(b"release\n").await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), handle.wait())
            .await
            .unwrap()
            .unwrap();
        terminate_creation_process(&mut handle, Duration::from_secs(2), |_| {
            panic!("already reaped")
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn refused_signal_does_not_override_a_confirmed_concurrent_exit() {
        let (mut handle, mut stdin) = child().await;
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            stdin.write_all(b"release\n").await.unwrap();
        });
        let result = terminate_creation_process(&mut handle, Duration::from_secs(2), |_| {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into())
        })
        .await;
        release.await.unwrap();
        result.unwrap();
        assert!(handle.try_wait().unwrap().is_some());
    }
}
