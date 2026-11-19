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

/// Context names replace the public backend abstraction without compatibility aliases.
///
/// ```
/// use microsandbox::{Context, Sandbox, Sandboxes, Snapshot, Snapshots, Volume, Volumes};
/// fn collections(context: &dyn Context) -> (Sandboxes, Volumes, Snapshots) {
///     (Sandbox::ctx(context), Volume::ctx(context), Snapshot::ctx(context))
/// }
/// ```
///
/// ```compile_fail
/// use microsandbox::{Backend, LocalBackend, CloudBackend};
/// ```
///
/// ```compile_fail
/// use microsandbox::backend;
/// ```
pub(crate) struct ExplicitContextSurface;

/// Creation and lookup share one resource type; deletion has distinct selection and identity forms.
///
/// ```no_run
/// use microsandbox::{MicrosandboxResult, Volume, VolumeConfig, VolumeId};
/// async fn volumes(config: VolumeConfig) -> MicrosandboxResult<()> {
///     let created: Volume = Volume::create(config).await?;
///     let fetched: Volume = Volume::get(created.name()).await?;
///     let listed: Vec<Volume> = Volume::list().await?;
///     let identity: &VolumeId = fetched.id();
///     fetched.destroy().await?;
///     Volume::remove("another-volume").await?;
///     Ok(())
/// }
/// ```
///
/// ```compile_fail
/// use microsandbox::VolumeHandle;
/// ```
///
/// ```compile_fail
/// use microsandbox::volume::VolumeHandle;
/// ```
pub(crate) struct UnifiedVolumeSurface;

/// Snapshots have one public resource type, including lightweight lookup and list results.
///
/// ```no_run
/// use microsandbox::{MicrosandboxResult, Snapshot};
/// async fn snapshots() -> MicrosandboxResult<()> {
///     let snapshot: Snapshot = Snapshot::get("group:member").await?;
///     let listed: Vec<Snapshot> = Snapshot::list().await?;
///     let manifest = snapshot.manifest().await?;
///     let state = snapshot.state().await?;
///     snapshot.destroy(false).await?;
///     Snapshot::remove("another:member", false).await?;
///     Ok(())
/// }
/// ```
///
/// ```compile_fail
/// use microsandbox::SnapshotHandle;
/// ```
///
/// ```compile_fail
/// use microsandbox::snapshot::SnapshotHandle;
/// ```
pub(crate) struct UnifiedSnapshotSurface;
