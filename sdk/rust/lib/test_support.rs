//! Fixture decoding, isolated backend construction, and synchronization for crate unit tests.

use std::sync::{Mutex, MutexGuard};

pub(crate) mod fixtures;
mod json;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Serializes process-global environment mutation across SDK unit tests.
static ENV_LOCK: Mutex<()> = Mutex::new(());

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Lock process-global environment mutation for the duration of a unit test.
pub(crate) fn lock_env() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

/// Construct a cloud backend with explicitly empty config sources, independent of the host.
#[cfg(feature = "cloud")]
pub(crate) fn cloud_backend(
    url: impl Into<String>,
    api_key: impl Into<String>,
) -> crate::MicrosandboxResult<crate::CloudBackend> {
    crate::CloudBackend::builder()
        .url(url)
        .api_key(api_key)
        .config_sources(crate::config::layers::BackendConfig::new(
            Default::default(),
            Default::default(),
        ))
        .build()
}

/// Construct a local backend from explicit settings without reading machine configuration.
#[cfg(feature = "local")]
pub(crate) fn local_backend(config: crate::config::GlobalConfig) -> crate::LocalBackend {
    crate::LocalBackend::from_backend_config(
        crate::config::layers::BackendConfig::new(
            crate::config::GlobalConfigPatch::from_present_fields(config),
            Default::default(),
        ),
        crate::BackendSelectionSource::Programmatic,
        None,
    )
}

/// Build against user and managed config files inside a test's temporary home.
/// Runtime environment paths are still honored for live runtime fixtures.
#[cfg(feature = "local")]
pub(crate) fn local_backend_builder(
    home: impl AsRef<std::path::Path>,
) -> crate::backend::local::LocalBackendBuilder {
    let home = home.as_ref();
    crate::LocalBackend::builder()
        .config_path(home.join("config.json"))
        .managed_config_path(home.join("managed.json"))
        .home(home)
}

/// Seed a running row whose live run is owned by this test process.
#[cfg(feature = "local")]
pub(crate) async fn seed_control_run(local: &crate::LocalBackend, name: &str) {
    use crate::db::entity::{run, sandbox};
    use sea_orm::{EntityTrait, Set};

    let db = local.db().await.unwrap();
    let sandbox_id = sandbox::Entity::insert(sandbox::ActiveModel {
        name: Set(name.into()),
        config: Set("{}".into()),
        status: Set(crate::sandbox::SandboxStatus::Running),
        ephemeral: Set(false),
        ..Default::default()
    })
    .exec(db.write())
    .await
    .unwrap()
    .last_insert_id;
    run::Entity::insert(run::ActiveModel {
        sandbox_id: Set(sandbox_id),
        pid: Set(Some(std::process::id() as i32)),
        status: Set(run::RunStatus::Running),
        ..Default::default()
    })
    .exec(db.write())
    .await
    .unwrap();
}

/// Drive plan, apply, and resume through `sandboxes` and assert each returns
/// the typed default `SandboxModify` refusal.
pub(crate) async fn assert_modification_unsupported(
    sandboxes: &dyn crate::backend::SandboxBackend,
    backend: std::sync::Arc<dyn crate::Backend>,
    identity: crate::backend::SandboxIdentity,
) {
    use crate::sandbox::{ModificationPolicy, SandboxModificationPatch};

    let results = [
        sandboxes
            .plan_modification_identified(
                backend.clone(),
                "modify-default",
                identity.clone(),
                SandboxModificationPatch::default(),
                ModificationPolicy::NoRestart,
            )
            .await,
        sandboxes
            .apply_modification_identified(
                backend.clone(),
                "modify-default",
                identity.clone(),
                SandboxModificationPatch::default(),
                ModificationPolicy::Restart,
            )
            .await,
        sandboxes
            .resume_modification_identified(backend, "modify-default", identity, "op-1".into())
            .await,
    ];
    for result in results {
        assert!(
            matches!(
                result,
                Err(crate::MicrosandboxError::Unsupported {
                    op: crate::Operation::SandboxModify,
                    reason: crate::UnsupportedReason::NotAvailable(_),
                })
            ),
            "expected typed modify refusal, got {result:?}"
        );
    }
}
