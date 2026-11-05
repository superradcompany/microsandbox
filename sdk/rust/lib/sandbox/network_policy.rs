//! Replacing a running sandbox's network policy.

use microsandbox_control_client::{NetworkPolicyUpdate, UpdateNetworkPolicy};

use super::NetworkPolicy;
use crate::backend::Backend;
use crate::{MicrosandboxError, MicrosandboxResult, Operation, UnsupportedReason};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Send `policy` to the running sandbox's runtime over its control channel. The run is
/// selected for `sandbox_id`, so a handle never reaches a sandbox that replaced its own
/// under the same name.
pub(super) async fn set(
    backend: &dyn Backend,
    name: &str,
    sandbox_id: Option<i32>,
    policy: &NetworkPolicy,
) -> MicrosandboxResult<()> {
    let unsupported = |reason| MicrosandboxError::Unsupported {
        op: Operation::SandboxSetNetworkPolicy,
        reason,
    };
    let (Some(local), Some(sandbox_id)) = (backend.as_local(), sandbox_id) else {
        return Err(unsupported(UnsupportedReason::LocalOnly));
    };
    let run = local.control_run_identity(name, sandbox_id).await?;
    let session = super::modify::control_session_for_run(local, name, run).await?;
    if !session.capabilities().network_policy_update {
        return Err(unsupported(UnsupportedReason::NotAvailable(
            "this sandbox's runtime cannot replace its network policy".into(),
        )));
    }
    let policy: microsandbox_types::NetworkPolicy =
        serde_json::from_value(serde_json::to_value(policy)?)?;
    session
        .request(&UpdateNetworkPolicy(NetworkPolicyUpdate { policy }))
        .await
        .map_err(MicrosandboxError::ControlClient)?;
    Ok(())
}
