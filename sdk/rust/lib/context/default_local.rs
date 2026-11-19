//! Immutable default-local routing, independent of remote profiles and ambient scopes.

use std::sync::{
    Arc,
    atomic::{AtomicPtr, Ordering},
};

use super::Context;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

static DEFAULT_LOCAL: AtomicPtr<ProcessContext> = AtomicPtr::new(std::ptr::null_mut());

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct ProcessContext {
    pid: u32,
    context: Arc<dyn Context>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// The shared destination for explicit local selectors. Remote-only builds fail closed.
///
/// Bindings use this hook for their explicit local selectors.
#[doc(hidden)]
pub fn default_local_context() -> Arc<dyn Context> {
    let pid = std::process::id();
    loop {
        let current = DEFAULT_LOCAL.load(Ordering::Acquire);
        if !current.is_null() {
            // Published entries live until process exit. In particular, never drop inherited
            // pools after fork: their Tokio workers no longer exist in the child.
            let entry = unsafe { &*current };
            if entry.pid == pid {
                return entry.context.clone();
            }
        }
        #[cfg(feature = "local")]
        let context = super::LocalContext::lazy().map(|local| local.clone_shared());
        #[cfg(not(feature = "local"))]
        let context: crate::MicrosandboxResult<Arc<dyn Context>> = Err(
            crate::MicrosandboxError::InvalidConfig(
                "default-local operations require the local provider; select a RemoteContext explicitly".into(),
            ),
        );
        let context = context.unwrap_or_else(|error| {
            Arc::new(super::misconfigured::ConfigurationErrorBackend::new(error))
        });
        let candidate = Box::into_raw(Box::new(ProcessContext { pid, context }));
        match DEFAULT_LOCAL.compare_exchange(
            current,
            candidate,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return unsafe { &*candidate }.context.clone(),
            Err(_) => {
                // No I/O has started on the losing lazy context; only unpublished state is dropped.
                drop(unsafe { Box::from_raw(candidate) });
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "local"))]
mod tests {
    use super::*;

    #[test]
    fn explicit_local_calls_share_one_destination() {
        let first = default_local_context();
        let second = default_local_context();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.kind(), crate::ContextKind::Local);
    }
}
