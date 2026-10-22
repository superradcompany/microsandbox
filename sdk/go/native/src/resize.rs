//! Live resize readback and waiting through the Go C ABI.

use std::{
    ffi::{c_char, c_uchar},
    future::Future,
    time::Duration,
};

use microsandbox::{
    MicrosandboxError,
    sandbox::{DEFAULT_RESIZE_READ_TIMEOUT, ResizeOperation, ResourceResizeStatus, SandboxHandle},
};

use super::{FfiError, Handle, cstr, get, identified_sandbox_handle, run_c};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn resize_status_json(
    status: Vec<microsandbox::sandbox::ResourceResizeStatus>,
) -> Result<String, FfiError> {
    serde_json::to_string(&status)
        .map_err(|e| FfiError::internal(format!("serialize resize status: {e}")))
}

pub(super) fn resize_wait_timeout(timeout_ms: u64) -> Option<Duration> {
    (timeout_ms != u64::MAX).then(|| Duration::from_millis(timeout_ms))
}

pub(super) fn ensure_expected_identity(
    name: &str,
    expected_id: &str,
    actual_id: String,
) -> Result<(), FfiError> {
    if actual_id == expected_id {
        return Ok(());
    }
    Err(FfiError::from(MicrosandboxError::SandboxReplaced {
        name: name.to_string(),
        expected: expected_id.to_string(),
        actual: actual_id,
    }))
}

/// Bound lookup and wait by one deadline. Zero checks once.
async fn wait_identified_until_resized(
    name: &str,
    expected_id: &str,
    timeout: Option<Duration>,
) -> Result<Vec<microsandbox::sandbox::ResourceResizeStatus>, FfiError> {
    wait_with_lookup(
        name,
        timeout,
        identified_sandbox_handle(name, expected_id),
        None,
    )
    .await
}

/// Lookup is part of the same deadline, including the bounded single-read case.
pub(super) async fn wait_with_lookup<L>(
    name: &str,
    timeout: Option<Duration>,
    lookup: L,
    operations: Option<&[ResizeOperation]>,
) -> Result<Vec<ResourceResizeStatus>, FfiError>
where
    L: Future<Output = Result<SandboxHandle, FfiError>> + Send,
{
    let Some(timeout) = timeout else {
        return wait_selected(&lookup.await?, operations, None)
            .await
            .map_err(FfiError::from);
    };
    let budget = if timeout.is_zero() {
        DEFAULT_RESIZE_READ_TIMEOUT
    } else {
        timeout
    };
    let started = tokio::time::Instant::now();
    let expired = |status| {
        FfiError::from(MicrosandboxError::ResizeTimeout {
            name: name.to_string(),
            timeout,
            status,
        })
    };
    let handle = tokio::time::timeout(budget, lookup)
        .await
        .map_err(|_| expired(Vec::new()))??;
    let remaining = budget
        .checked_sub(started.elapsed())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| expired(Vec::new()))?;
    let result = if timeout.is_zero() {
        // The SDK owns this reduced budget so a stalled later resource cannot erase
        // replies already received. Zero still means one check, never a polling wait.
        handle
            .check_resize_operations_with_budget(operations, remaining)
            .await
    } else {
        // Let the SDK own the polling deadline: a competing outer timer can discard
        // its last observed status when both deadlines expire together.
        wait_selected(&handle, operations, Some(remaining)).await
    };
    match result {
        Err(MicrosandboxError::ResizeTimeout { status, .. }) => Err(expired(status)),
        result => result.map_err(FfiError::from),
    }
}

/// Share deadline handling without changing how the original current-operation wait selects IDs.
async fn wait_selected(
    handle: &SandboxHandle,
    operations: Option<&[ResizeOperation]>,
    timeout: Option<Duration>,
) -> Result<Vec<ResourceResizeStatus>, MicrosandboxError> {
    match operations {
        Some(operations) => handle.wait_for_resize_operations(operations, timeout).await,
        None => match timeout {
            Some(timeout) => handle.wait_until_resized_with_timeout(timeout).await,
            None => handle.wait_until_resized().await,
        },
    }
}

/// Read live resize status for the sandbox `expected_id` names.
/// Output: a `ResourceResizeStatus` JSON array.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_sandbox_handle_resize_status(
    cancel_id: u64,
    name: *const c_char,
    expected_id: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let name = unsafe { cstr(name) }?;
        let expected_id = unsafe { cstr(expected_id) }?;
        Ok(Box::pin(async move {
            let h = identified_sandbox_handle(&name, &expected_id).await?;
            resize_status_json(h.resize_status().await.map_err(FfiError::from)?)
        }))
    })
}

/// Wait for live resizes on the sandbox `expected_id` names to settle.
/// `u64::MAX` waits without a deadline; 0 checks once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_sandbox_handle_wait_until_resized(
    cancel_id: u64,
    name: *const c_char,
    expected_id: *const c_char,
    timeout_ms: u64,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let name = unsafe { cstr(name) }?;
        let expected_id = unsafe { cstr(expected_id) }?;
        Ok(Box::pin(async move {
            let status =
                wait_identified_until_resized(&name, &expected_id, resize_wait_timeout(timeout_ms))
                    .await?;
            resize_status_json(status)
        }))
    })
}

/// Read live resize status. Output: a `ResourceResizeStatus` JSON array.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_sandbox_resize_status(
    cancel_id: u64,
    handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        Ok(Box::pin(async move {
            resize_status_json(sb.resize_status().await.map_err(FfiError::from)?)
        }))
    })
}

/// Wait for live resizes to settle. `u64::MAX` waits without a deadline; 0 checks once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_sandbox_wait_until_resized(
    cancel_id: u64,
    handle: Handle,
    timeout_ms: u64,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sb = get(handle)?;
        Ok(Box::pin(async move {
            let status = match resize_wait_timeout(timeout_ms) {
                Some(timeout) => sb.wait_until_resized_with_timeout(timeout).await,
                None => sb.wait_until_resized().await,
            }
            .map_err(FfiError::from)?;
            resize_status_json(status)
        }))
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn exact_wait_includes_identity_lookup_in_its_deadline() {
        for timeout in [Duration::from_millis(5), Duration::ZERO] {
            let budget = if timeout.is_zero() {
                DEFAULT_RESIZE_READ_TIMEOUT
            } else {
                timeout
            };
            let lookup = std::future::pending::<Result<SandboxHandle, FfiError>>();
            let error = tokio::time::timeout(
                budget + Duration::from_secs(2),
                wait_with_lookup("blocked-exact-lookup", Some(timeout), lookup, Some(&[])),
            )
            .await
            .expect("exact wait lookup exceeded its budget")
            .unwrap_err();
            assert_eq!(error.kind, "resize_timeout");
            assert!(error.resize_status.as_ref().is_some_and(Vec::is_empty));
        }
    }

    #[tokio::test]
    async fn zero_and_positive_waits_bound_a_pending_identity_lookup() {
        for timeout in [Duration::from_millis(5), Duration::ZERO] {
            let budget = if timeout.is_zero() {
                DEFAULT_RESIZE_READ_TIMEOUT
            } else {
                timeout
            };
            let lookup = std::future::pending::<Result<SandboxHandle, FfiError>>();
            let error = tokio::time::timeout(
                budget + Duration::from_secs(2),
                wait_with_lookup("blocked-lookup", Some(timeout), lookup, None),
            )
            .await
            .expect("identity lookup exceeded the complete wait budget")
            .unwrap_err();
            assert_eq!(error.kind, "resize_timeout");
            let payload: serde_json::Value = serde_json::from_str(&error.to_json()).unwrap();
            assert_eq!(payload["resize_status"], serde_json::json!([]));
        }
    }
}
