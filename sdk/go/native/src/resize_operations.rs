//! Exact-operation resize methods through an optional additive Go ABI entry point.

use std::ffi::{c_char, c_uchar};

use microsandbox::Sandbox;
use microsandbox::sandbox::{
    ResizeOperation, SandboxModificationBuilder, SandboxModificationResult,
};
use serde::Deserialize;

use super::{
    FfiError, Handle, SandboxModifyOpts, configure_modify, cstr, get, identified_sandbox_handle,
    parse_modify_policy, resize, run_c,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum Request {
    Modify {
        options: Box<SandboxModifyOpts>,
    },
    Read,
    Wait {
        operations: Vec<ResizeOperation>,
        timeout_ms: u64,
    },
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Apply with tracking, read current operations, or wait on supplied identities.
/// A nonzero handle retains its backend; zero uses the supplied name. Reads and waits require
/// the expected sandbox identity. Modify preserves the existing fresh-by-name planning contract.
/// The optional symbol itself advertises support; no mutation is replayed through an older ABI.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_sandbox_resize_operations(
    cancel_id: u64,
    handle: Handle,
    name: *const c_char,
    expected_id: *const c_char,
    request_json: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let request = parse_request(&unsafe { cstr(request_json) }?)?;
        let name = unsafe { cstr(name) }?;
        let expected_id = unsafe { cstr(expected_id) }?;
        let sandbox = if handle == 0 {
            None
        } else {
            Some(get(handle)?)
        };
        Ok(Box::pin(async move {
            match request {
                Request::Modify { options } => {
                    let policy = parse_modify_policy(options.policy.as_deref())?;
                    let builder = match sandbox {
                        Some(sb) => sb.modify(),
                        None => Sandbox::get(&name).await.map_err(FfiError::from)?.modify(),
                    };
                    let builder = configure_modify(builder, options.patch, policy);
                    tracked_modify(builder, options.dry_run).await
                }
                Request::Read => {
                    let operations = match sandbox {
                        Some(sb) => sb.resize_operations().await.map_err(FfiError::from)?,
                        None => identified_sandbox_handle(&name, &expected_id)
                            .await?
                            .resize_operations()
                            .await
                            .map_err(FfiError::from)?,
                    };
                    serde_json::to_string(&operations).map_err(serialization_error)
                }
                Request::Wait {
                    operations,
                    timeout_ms,
                } => {
                    let timeout = resize::resize_wait_timeout(timeout_ms);
                    let status = match sandbox {
                        Some(sb) => sb
                            .wait_for_resize_operations(&operations, timeout)
                            .await
                            .map_err(FfiError::from)?,
                        None => {
                            resize::wait_with_lookup(
                                &name,
                                timeout,
                                identified_sandbox_handle(&name, &expected_id),
                                Some(&operations),
                            )
                            .await?
                        }
                    };
                    resize::resize_status_json(status)
                }
            }
        }))
    })
}

fn parse_request(raw: &str) -> Result<Request, FfiError> {
    let request: Request = serde_json::from_str(raw)
        .map_err(|_| FfiError::invalid_argument("invalid resize operation request"))?;
    if let Request::Wait { operations, .. } = &request
        && (operations.is_empty() || operations.len() > 2)
    {
        return Err(FfiError::invalid_argument(
            "expected one or two resize operations",
        ));
    }
    Ok(request)
}

async fn tracked_modify(
    builder: SandboxModificationBuilder,
    dry_run: bool,
) -> Result<String, FfiError> {
    let result = if dry_run {
        SandboxModificationResult {
            plan: builder.dry_run().await.map_err(FfiError::from)?,
            resize_operations: None,
        }
    } else {
        builder
            .apply_with_resize_tracking()
            .await
            .map_err(FfiError::from)?
    };
    serde_json::to_string(&result).map_err(serialization_error)
}

fn serialization_error(error: serde_json::Error) -> FfiError {
    FfiError::internal(format!("serialize resize operation result: {error}"))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_waits_fail_before_native_lookup() {
        for raw in [
            "null",
            "{}",
            r#"{"operation":"wait","operations":[],"timeout_ms":0}"#,
            r#"{"operation":"wait","operations":[{},{},{}],"timeout_ms":0}"#,
        ] {
            assert!(parse_request(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn generations_and_memory_targets_remain_full_width() {
        let request = serde_json::json!({"operation":"wait","timeout_ms":u64::MAX,"operations":[{
            "id":"operation", "runtime_boot_id":"runtime", "generation":u64::MAX,
            "requested_target":{"resource":"memory","total_mib":u64::MAX},
            "accepted_target":{"resource":"memory","total_mib":u64::MAX},
            "status":{"resource":"memory","requested":"target","actual":"current","enforced":"target","state":"accepted"},
            "outcome":"pending","observation":"unavailable"
        }]});
        let Request::Wait {
            operations,
            timeout_ms,
        } = parse_request(&request.to_string())
            .unwrap_or_else(|error| panic!("{}", error.to_json()))
        else {
            panic!("wrong request");
        };
        assert_eq!(timeout_ms, u64::MAX);
        assert_eq!(operations[0].generation, u64::MAX);
        assert_eq!(
            serde_json::to_value(&operations[0]).unwrap(),
            request["operations"][0]
        );
    }
}
