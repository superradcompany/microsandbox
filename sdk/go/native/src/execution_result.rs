//! Owned collected output crosses the SDK FFI once, without replaying execution.

use std::{
    os::raw::{c_char, c_uchar},
    time::Duration,
};

use super::{
    ExecOpts, FfiError, Handle, cancel_unregister, cstr, err_ptr, exec_adapter, get, get_exec,
    lookup_cancel_token, rt, run_cancellable, write_agent_bytes,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Return JSON in an owned byte allocation, released by this library's
/// msb_agent_free_bytes. Existing fixed-buffer entry points remain ABI-compatible.
///
/// # Safety
/// Strings must be valid C strings. Output slots must be writable and must not
/// alias each other or any input; the caller must release a successful allocation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_execution_result(
    cancel_id: u64,
    handle: Handle,
    operation: *const c_char,
    command: *const c_char,
    options: *const c_char,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut usize,
) -> *mut c_char {
    let result = (|| -> Result<(), FfiError> {
        // Validate outputs before starting a command or consuming stream events.
        if out_ptr.is_null() || out_len.is_null() {
            return Err(FfiError::invalid_argument("null execution output slot"));
        }
        unsafe {
            *out_ptr = std::ptr::null_mut();
            *out_len = 0;
        }
        let token = lookup_cancel_token(cancel_id)?;
        let operation = unsafe { cstr(operation) }?;
        let output = if operation == "collect" {
            let entry = get_exec(handle)?;
            let mut execution = entry
                .handle
                .lock()
                .map_err(|_| FfiError::internal("exec handle mutex poisoned"))?;
            rt().block_on(run_cancellable(token, async {
                execution.collect().await.map_err(FfiError::from)
            }))?
        } else {
            if operation != "exec" && operation != "default" {
                return Err(FfiError::invalid_argument(
                    "unknown execution result operation",
                ));
            }
            let sandbox = get(handle)?;
            let command = unsafe { cstr(command) }?;
            let options: ExecOpts =
                serde_json::from_str(&unsafe { cstr(options) }?).map_err(|error| {
                    FfiError::invalid_argument(format!("invalid exec opts: {error}"))
                })?;
            if options.stdin_pipe == Some(true) {
                return Err(FfiError::invalid_argument(
                    "collected execution does not expose stdin; use streaming execution",
                ));
            }
            rt().block_on(run_cancellable(token, async move {
                let configure = |mut builder: microsandbox::sandbox::ExecOptionsBuilder| {
                    if let Some(args) = options.args {
                        builder = builder.args(args);
                    }
                    if let Some(cwd) = options.cwd {
                        builder = builder.cwd(cwd);
                    }
                    if let Some(tty) = options.tty {
                        builder = builder.tty(tty);
                    }
                    if let Some(seconds) = options.timeout_secs {
                        builder = builder.timeout(Duration::from_secs(seconds));
                    }
                    if let Some(user) = options.user {
                        builder = builder.user(user);
                    }
                    for (key, value) in options.env {
                        builder = builder.env(key, value);
                    }
                    builder
                };
                if operation == "default" {
                    sandbox
                        .exec_default_with(configure)
                        .await
                        .map_err(FfiError::from)
                } else {
                    sandbox
                        .exec_with(&command, configure)
                        .await
                        .map_err(FfiError::from)
                }
            }))?
        };
        // The native ExecHandle already retains completion. Output ownership is
        // transferred only for this call and does not add replay or permanent caching.
        write_agent_bytes(
            exec_adapter::collected_output_json(&output).into_bytes(),
            out_ptr,
            out_len,
        )
    })();
    cancel_unregister(cancel_id);
    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(error) => err_ptr(error),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    #[test]
    fn null_output_is_rejected_before_execution_and_releases_cancellation() {
        let id = unsafe { crate::msb_cancel_alloc() };
        let operation = CString::new("collect").unwrap();
        let empty = CString::new("").unwrap();
        let mut length = 0;
        let error = unsafe {
            msb_execution_result(
                id,
                999,
                operation.as_ptr(),
                empty.as_ptr(),
                empty.as_ptr(),
                std::ptr::null_mut(),
                &mut length,
            )
        };
        assert!(!error.is_null());
        let message = unsafe { CStr::from_ptr(error) }.to_str().unwrap();
        assert!(message.contains("null execution output slot"));
        unsafe { crate::msb_free_string(error) };
        assert!(lookup_cancel_token(id).is_err());
    }

    #[test]
    fn owned_transfer_preserves_large_binary_payload_without_fixed_buffer() {
        let bytes: Vec<u8> = (0..4 * 1024 * 1024)
            .map(|index| (index % 256) as u8)
            .collect();
        let mut pointer = std::ptr::null_mut();
        let mut length = 0;
        assert!(write_agent_bytes(bytes.clone(), &mut pointer, &mut length).is_ok());
        assert_eq!(length, bytes.len());
        assert_eq!(
            unsafe { std::slice::from_raw_parts(pointer, length) },
            bytes
        );
        unsafe { crate::msb_agent_free_bytes(pointer, length) };
    }
}
