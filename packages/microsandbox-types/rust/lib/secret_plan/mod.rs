//! Secret modification planning shared by every backend.
//!
//! One pure planner classifies a secret patch against value-free settings:
//! what changes, when it can take effect, which patches conflict, and why a
//! plan cannot be applied. Each backend states its own status, capability and
//! view of the running sandbox; the comparison rules and messages live here
//! only. [`config_change`] also classifies non-secret configuration fields, so
//! Local plans those by the same rules. This module is shared code, not part
//! of the contract: nothing in it is generated for TypeScript or re-exported by
//! the SDK.

mod input;
mod plan;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub use input::{
    DesiredMaterial, DesiredSecret, RunningSecret, SecretPlanCapability, SecretPlanInput,
    SecretPlanStatus, SecretSettings,
};
pub use plan::{
    LIVE_SECRET_RECONFIGURE_UNAVAILABLE, SECRET_FIELD, SecretAspect, SecretPlanOutput,
    config_change, plan, refusal_reason, secret_name_from_policy_field,
};
