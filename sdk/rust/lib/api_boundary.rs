//! Compile checks of the SDK's public surface, run as doctests.

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The secret planner in `microsandbox_types::secret_plan` is not SDK API: the plan types are,
/// the planner is not.
///
/// ```
/// fn applied(plan: &microsandbox::SandboxModificationPlan) -> bool {
///     plan.applied
/// }
/// ```
///
/// ```compile_fail
/// use microsandbox::secret_plan;
/// ```
///
/// ```compile_fail
/// use microsandbox::SecretPlanInput;
/// ```
///
/// ```compile_fail
/// fn refusal_reason(plan: &microsandbox::SandboxModificationPlan) -> Option<String> {
///     plan.refusal_reason()
/// }
/// ```
pub(crate) struct SecretPlanIsNotUserApi;
