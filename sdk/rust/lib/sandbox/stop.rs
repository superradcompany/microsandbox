//! Shared bounded and unbounded graceful-stop contract.

use std::sync::Arc;
use std::time::Duration;

use crate::backend::{Backend, sandbox::SandboxIdentity};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn stop(
    backend: Arc<dyn Backend>,
    name: &str,
    identity: SandboxIdentity,
    _ephemeral: bool,
    timeout: Option<Duration>,
) -> MicrosandboxResult<()> {
    let timed_out = || MicrosandboxError::StopTimeout {
        name: name.to_string(),
        identity: format!("{identity:?}"),
        timeout: timeout.expect("only timed stops can expire"),
    };
    // A zero budget must not dispatch shutdown, and in particular must never select Kill.
    if timeout.is_some_and(|timeout| timeout.is_zero()) {
        return Err(timed_out());
    }
    let operation = async {
        #[cfg(feature = "local")]
        if let (Some(local), SandboxIdentity::Local(id)) = (backend.as_local(), &identity) {
            return local.stop_complete(name, *id, _ephemeral).await;
        }
        // The cloud control-plane's terminal status is its completion authority. Local process
        // locks have no meaning there; keep the backend identity checks on every observation.
        let handle = backend.sandboxes().get(backend.clone(), name).await?;
        if handle.identity() != identity {
            return Err(MicrosandboxError::SandboxReplaced {
                name: name.to_string(),
                expected: format!("{identity:?}"),
                actual: handle.id().to_string(),
            });
        }
        handle.request_stop().await?;
        handle.wait_until_stopped().await.map(|_| ())
    };
    match timeout {
        // This single deadline includes transition locks, dispatch and ownership observation.
        Some(timeout) => tokio::time::timeout(timeout, operation)
            .await
            .map_err(|_| timed_out())?,
        None => operation.await,
    }
}
