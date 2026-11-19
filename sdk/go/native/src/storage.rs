//! Storage bindings delegate accounting and ownership checks to the Rust SDK.

use std::os::raw::{c_char, c_uchar};
use std::time::Duration;

use microsandbox::Storage;
use microsandbox::storage::MemoryPruneOptions;

use crate::{FfiError, cstr, get, run_c};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PruneOptions {
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    older_than_seconds: u64,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Observe one live sandbox through its retained native backend and stable identity.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_sandbox_storage_usage(
    cancel_id: u64,
    handle: u64,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sandbox = get(handle)?;
        Ok(Box::pin(async move {
            let report = sandbox.storage_usage().await.map_err(FfiError::from)?;
            serde_json::to_string(&report).map_err(|error| FfiError::internal(error.to_string()))
        }))
    })
}

/// Observe the selected backend's storage, returning the shared Rust report as JSON.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_storage_usage(
    cancel_id: u64,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        Ok(Box::pin(async move {
            let report = Storage::usage().await.map_err(FfiError::from)?;
            serde_json::to_string(&report).map_err(|error| FfiError::internal(error.to_string()))
        }))
    })
}

/// Prune unused runtime RAM using explicit JSON options; no interactive confirmation is performed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_storage_prune(
    cancel_id: u64,
    options_json: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    #[cfg(not(feature = "local"))]
    {
        run_c(cancel_id, buf, buf_len, || {
            Err(FfiError::from(microsandbox::MicrosandboxError::local_only(
                microsandbox::Operation::StoragePrune,
            )))
        })
    }
    #[cfg(feature = "local")]
    {
        run_c(cancel_id, buf, buf_len, || {
            let options: PruneOptions = serde_json::from_str(&unsafe { cstr(options_json) }?)
                .map_err(|error| {
                    FfiError::invalid_argument(format!("invalid storage prune options: {error}"))
                })?;
            Ok(Box::pin(async move {
                let options = MemoryPruneOptions {
                    dry_run: options.dry_run,
                    older_than: Duration::from_secs(options.older_than_seconds),
                    max_entries: None,
                    ..Default::default()
                };
                let report = Storage::prune(&options).await.map_err(FfiError::from)?;
                serde_json::to_string(&report)
                    .map_err(|error| FfiError::internal(error.to_string()))
            }))
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_options_reject_unrecognized_or_invalid_age_before_dispatch() {
        for invalid in [
            r#"{"older_than_seconds":-1}"#,
            r#"{"older_than_seconds":0.5}"#,
            r#"{"dry_run":"true"}"#,
            r#"{"older_than":12}"#,
        ] {
            assert!(
                serde_json::from_str::<PruneOptions>(invalid).is_err(),
                "{invalid}"
            );
        }
        let options: PruneOptions =
            serde_json::from_str(r#"{"dry_run":true,"older_than_seconds":600}"#).unwrap();
        assert!(options.dry_run);
        assert_eq!(options.older_than_seconds, 600);
    }
}
