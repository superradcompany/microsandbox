//! Explicit, stopped-sandbox storage import and recovery without booting a VM.

use serde::{Deserialize, Serialize};

#[cfg(feature = "local")]
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

#[cfg(feature = "local")]
use crate::backend::local::creation::{self, CreationStorage};
#[cfg(feature = "local")]
use crate::db::entity::sandbox;
#[cfg(feature = "local")]
use crate::runtime::{launch_contract, owned_volumes, protected_state};
#[cfg(feature = "local")]
use crate::{LocalBackend, SandboxConfig};
use crate::{MicrosandboxError, MicrosandboxResult};

use super::Sandbox;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One complete disk view returned by storage inspection, scoped to its configured disk role.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageRecoverySelection {
    /// `root` or the owned-volume mount ID reported by inspection.
    pub disk_id: String,
    /// Opaque candidate identity returned by the current inspection.
    pub candidate_id: String,
}

/// Explicit recovery choices. Empty selections import or resume the existing validated view.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageRecoveryOptions {
    /// Candidate views selected after inspecting ambiguous or damaged legacy metadata.
    pub selections: Vec<StorageRecoverySelection>,
    /// Acknowledge that explicit selection preserves only that view, which can omit later writes.
    /// This never grants access to a new resource or bypasses source validation.
    pub accept_selected_view: bool,
    /// On macOS, confirm all legacy VMs across all homes have stopped, and prevent old-tool
    /// launches or writes to the selected storage until recovery finishes. This operational
    /// prerequisite cannot be inferred from one home's catalog. New/Ready storage skips it.
    pub legacy_writers_stopped: bool,
}

/// Successful recovery leaves a stopped sandbox and retains original inputs for verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageRecovery {
    /// Sandbox whose complete storage group is ready.
    pub name: String,
    /// The sandbox has completed the protected storage layout.
    pub ready: bool,
    /// Recovery did not remove original legacy disks or checkpoints.
    pub originals_retained: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Import or resume a stopped sandbox's storage without starting it or stopping another VM.
    ///
    /// Inspect first with `setup::diagnose_storage`. Candidate IDs are revalidated under locks;
    /// an old report cannot authorize changed files or a different sandbox incarnation. Original
    /// inputs remain retained after success. This does not restore pending memory/device state.
    pub async fn recover_storage(
        name: &str,
        options: StorageRecoveryOptions,
    ) -> MicrosandboxResult<StorageRecovery> {
        if !options.selections.is_empty() && !options.accept_selected_view {
            return Err(MicrosandboxError::InvalidConfig(
                "explicit storage selection requires acknowledging that the selected view may omit later writes".into(),
            ));
        }
        #[cfg(not(feature = "local"))]
        {
            let _ = name;
            Err(MicrosandboxError::InvalidConfig(
                "storage recovery requires the local backend".into(),
            ))
        }
        #[cfg(feature = "local")]
        {
            recover_local(name, options).await
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "local")]
async fn recover_local(
    name: &str,
    options: StorageRecoveryOptions,
) -> MicrosandboxResult<StorageRecovery> {
    with_locked_storage(
        crate::backend::default_backend(),
        name,
        async |local, config, storage| {
            protected_state::prepare_selected(local, config, storage, &options).await?;
            Ok(StorageRecovery {
                name: name.into(),
                ready: true,
                originals_retained: true,
            })
        },
    )
    .await
}

#[cfg(feature = "local")]
pub(super) async fn with_locked_storage<T>(
    backend: std::sync::Arc<dyn crate::backend::Backend>,
    name: &str,
    action: impl AsyncFnOnce(&LocalBackend, &SandboxConfig, &CreationStorage) -> MicrosandboxResult<T>,
) -> MicrosandboxResult<T> {
    with_target_locks(backend, name, async |local| {
        with_catalog_storage(local, name, action).await
    })
    .await
}

/// The same lifecycle locks serve private browsing and explicit adoption. Only the latter
/// may initialize or migrate the user's catalog.
#[cfg(feature = "local")]
pub(super) async fn with_target_locks<T>(
    backend: std::sync::Arc<dyn crate::backend::Backend>,
    name: &str,
    action: impl AsyncFnOnce(&LocalBackend) -> MicrosandboxResult<T>,
) -> MicrosandboxResult<T> {
    super::validate_sandbox_name(name)?;
    backend.info()?;
    let local = backend.as_local().ok_or_else(|| {
        MicrosandboxError::InvalidConfig("storage recovery requires the local backend".into())
    })?;
    let run = local.config().run_dir();
    let _transition = LocalBackend::acquire_sandbox_transition_guard(&run, name).await?;
    let _lineage = crate::snapshot::lineage::lock_source(&run, name).await?;
    let _lifecycle = crate::runtime::acquire_sandbox_lifecycle_guard(
        &run,
        name,
        std::time::Duration::from_secs(5),
    )
    .await?;
    action(local).await
}

#[cfg(feature = "local")]
async fn with_catalog_storage<T>(
    local: &LocalBackend,
    name: &str,
    action: impl AsyncFnOnce(&LocalBackend, &SandboxConfig, &CreationStorage) -> MicrosandboxResult<T>,
) -> MicrosandboxResult<T> {
    let db = local.db().await?;
    let model = sandbox::Entity::find()
        .filter(sandbox::Column::Name.eq(name))
        .one(db.read())
        .await?
        .ok_or_else(|| MicrosandboxError::SandboxNotFound(name.into()))?;
    if model.status.has_active_runtime_state() {
        return Err(MicrosandboxError::SandboxStillRunning(format!(
            "stop sandbox '{name}' before recovering its storage"
        )));
    }
    // Older generations can publish a stopped row before their process and disk handles exit.
    // The PID check is conservative on reuse and never sends a signal to another process.
    if LocalBackend::load_latest_run(db.read(), model.id)
        .await?
        .and_then(|run| run.pid)
        .is_some_and(microsandbox_utils::process::pid_exists)
    {
        return Err(MicrosandboxError::SandboxStillRunning(format!(
            "sandbox '{name}' still has a recorded runtime process; wait for teardown and retry"
        )));
    }
    creation::require_complete(db.read(), model.id, name).await?;
    let config =
        SandboxConfig::from_stored(&model.config, model.caller_config_overrides.as_deref())?;
    let storage = guard_target_storage(local, name, &config).await?;
    action(local, &config, &storage).await
}

#[cfg(feature = "local")]
pub(super) async fn guard_target_storage(
    local: &LocalBackend,
    name: &str,
    config: &SandboxConfig,
) -> MicrosandboxResult<CreationStorage> {
    LocalBackend::validate_completed_restore(config)?;
    launch_contract::validate_runtime_config(config, local.config()).await?;
    owned_volumes::wait_for_disk_release(
        &local.sandboxes_dir().join(name),
        &config.spec.mounts,
        std::time::Duration::from_secs(5),
    )
    .await?;
    CreationStorage::acquire(local, name)
}
