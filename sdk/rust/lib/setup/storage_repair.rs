//! Read-only target selection and generation-bound graceful stops for explicit repair.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use sea_orm::sqlx::{self, Connection, Row, SqliteConnection};

use super::{
    MAX_SANDBOXES, diagnostic_error, inspection_config, open_catalog, storage_alias_catalog,
};
use crate::config::GlobalConfigPatch;
use crate::{MicrosandboxError, MicrosandboxResult, Sandbox};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A running sandbox identified by host catalog relationships during a repair check.
/// Its private identity prevents a consent prompt from applying to a replacement generation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct StorageRepairBlocker {
    /// Name to show before asking permission for a graceful stop.
    pub name: String,
    target: String,
    home: PathBuf,
    sandbox_id: i32,
    run_id: i32,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Gracefully stop exactly the observed blocker, after checking it still blocks this repair.
    #[doc(hidden)]
    pub async fn stop_storage_repair_blocker(
        blocker: &StorageRepairBlocker,
    ) -> MicrosandboxResult<()> {
        let blockers =
            storage_repair_blockers(GlobalConfigPatch::default(), &blocker.target).await?;
        if !blockers.contains(blocker) {
            return Err(diagnostic_error(
                "the selected blocker changed; inspect storage again",
            ));
        }
        let backend = crate::backend::default_backend();
        backend.info()?;
        let local = backend
            .as_local()
            .ok_or_else(|| diagnostic_error("storage repair requires the local backend"))?;
        if std::path::absolute(local.config().home())? != blocker.home {
            return Err(diagnostic_error(
                "the selected storage home changed; inspect storage again",
            ));
        }
        let timeout = Duration::from_secs(30);
        tokio::time::timeout(
            timeout,
            local.stop_complete_generation(
                &blocker.name,
                blocker.sandbox_id,
                false,
                Some(blocker.run_id),
            ),
        )
        .await
        .map_err(|_| MicrosandboxError::StopTimeout {
            name: blocker.name.clone(),
            identity: format!("local:{} run {}", blocker.sandbox_id, blocker.run_id),
            timeout,
        })?
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Fresh compatibility-decoded reads for both inventory passes of the execution resolver.
pub(crate) async fn preview_alias_catalog(
    db: &mut SqliteConnection,
) -> MicrosandboxResult<(
    Vec<crate::runtime::storage_aliases::CatalogSandbox>,
    Vec<crate::runtime::storage_aliases::CatalogSnapshot>,
)> {
    let catalog = storage_alias_catalog::read(db).await?;
    Ok((catalog.sandboxes, catalog.snapshots))
}

/// Load the exact released row without upgrading its schema or rewriting its JSON. The
/// original bytes bind candidate identities; only the in-memory config is compatibility decoded.
pub(crate) async fn preview_target(
    db: &mut SqliteConnection,
    name: &str,
) -> MicrosandboxResult<(i32, String, crate::SandboxConfig)> {
    let rows = super::read_catalog(db, Some(&BTreeSet::from([name.to_owned()]))).await?;
    let row = rows
        .first()
        .ok_or_else(|| MicrosandboxError::SandboxNotFound(name.into()))?;
    if !matches!(row.status.as_str(), "Created" | "Stopped" | "Crashed") || row.incomplete {
        return Err(diagnostic_error(
            "the sandbox must be stopped and its creation complete before private preview",
        ));
    }
    let saved = super::decode_config(row)?;
    if saved.spec.name != name {
        return Err(diagnostic_error(
            "saved sandbox identity changed before private preview",
        ));
    }
    // Preview cannot initialize a missing runtime-generation schema to make an uncertain
    // process invisible. Released catalogs with a known run table can establish teardown.
    let pid = sqlx::query_scalar::<_, Option<i32>>(
        "SELECT pid FROM run WHERE sandbox_id=? ORDER BY id DESC LIMIT 1",
    )
    .bind(row.id)
    .fetch_optional(&mut *db)
    .await
    .map_err(|_| diagnostic_error("cannot verify released sandbox process ownership"))?
    .flatten();
    if pid.is_some_and(microsandbox_utils::process::pid_exists) {
        return Err(diagnostic_error(
            "a recorded runtime is still present; wait for teardown before private preview",
        ));
    }
    Ok((
        row.id,
        row.config
            .clone()
            .ok_or_else(|| diagnostic_error("saved config exceeds its inspection bound"))?,
        saved,
    ))
}

/// List only catalog names for an explicitly opened repair picker. No sandbox disk is inspected.
#[doc(hidden)]
pub async fn storage_repair_targets(options: GlobalConfigPatch) -> MicrosandboxResult<Vec<String>> {
    let config = inspection_config(options)?;
    let mut db = open_catalog(config.resolved_config()).await?;
    // Bound both individual names and the row count before retaining any catalog data.
    let rows = sqlx::query("SELECT CASE WHEN length(CAST(name AS BLOB))<=128 THEN name END AS name FROM sandbox ORDER BY name LIMIT 4097")
        .fetch_all(&mut db).await.map_err(|_| diagnostic_error("storage target names are unavailable"))?;
    db.close().await.map_err(|_| {
        diagnostic_error("storage target inventory could not close its catalog read")
    })?;
    if rows.len() > MAX_SANDBOXES {
        return Err(diagnostic_error(
            "the repair picker exceeds 4096 sandboxes; select a named sandbox",
        ));
    }
    rows.into_iter()
        .map(|row| {
            let name: String = row
                .try_get("name")
                .map_err(|_| diagnostic_error("invalid sandbox name in storage catalog"))?;
            crate::sandbox::validate_sandbox_name(&name)?;
            Ok(name)
        })
        .collect()
}

/// Inspect known blockers for one selected legacy sandbox. Cross-home macOS maintenance still
/// requires the operator's independent confirmation. A terminal row never authorizes a stop.
#[doc(hidden)]
pub async fn storage_repair_blockers(
    options: GlobalConfigPatch,
    name: &str,
) -> MicrosandboxResult<Vec<StorageRepairBlocker>> {
    crate::sandbox::validate_sandbox_name(name)?;
    let sources = inspection_config(options)?;
    blockers_resolved(sources.resolved_config(), name).await
}

pub(super) async fn blockers_resolved(
    config: &crate::config::GlobalConfig,
    name: &str,
) -> MicrosandboxResult<Vec<StorageRepairBlocker>> {
    let mut db = open_catalog(config).await?;
    let rows = super::read_catalog(&mut db, Some(&BTreeSet::from([name.to_owned()]))).await?;
    let row = rows
        .first()
        .ok_or_else(|| MicrosandboxError::SandboxNotFound(name.into()))?;
    let home = std::path::absolute(config.home())?;
    let sandboxes = config.sandboxes_dir();
    let sandbox = sandboxes.join(name);
    let runtime = sandbox.join("runtime");
    let mut result = Vec::new();
    if microsandbox_runtime::checkpoint::layout::require_ready(&runtime).is_ok() {
        return Ok(result);
    }
    let saved = super::decode_config(row)?;
    if saved.spec.name != name || row.incomplete {
        return Err(diagnostic_error(
            "incomplete or inconsistent sandbox configuration cannot authorize stopping a VM",
        ));
    }
    if matches!(
        row.status.as_str(),
        "Running" | "Starting" | "Paused" | "Draining"
    ) {
        if saved.spec.lifecycle.ephemeral {
            return Err(diagnostic_error(
                "stopping this ephemeral sandbox could remove its storage; preserve its data before stopping it separately",
            ));
        }
        // The running target itself is identifiable even when Windows sharing rules prohibit
        // opening a disk. Inspect its remaining relationships after this consented stop.
        result.push(observed_blocker(&mut db, &home, name, name, row.id).await?);
        return Ok(result);
    }
    require_teardown(&mut db, row.id).await?;
    let bindings = crate::runtime::protected_state::bindings(
        &saved,
        &sandbox,
        row.id,
        row.config.as_deref().unwrap_or_default(),
    )?;
    if bindings.root.is_none() && bindings.owned_disks.is_empty() {
        return Ok(result);
    }
    let aliases = storage_alias_catalog::read(&mut db).await?;
    #[cfg(target_os = "macos")]
    for peer in &aliases.sandboxes {
        if peer.id != row.id
            && !peer.status.has_active_runtime_state()
            && microsandbox_runtime::checkpoint::layout::require_ready(
                &sandboxes.join(&peer.name).join("runtime"),
            )
            .is_err()
        {
            require_teardown(&mut db, peer.id).await?;
        }
    }
    let volumes = config.volumes_dir();
    let id = row.id;
    let peers = tokio::task::spawn_blocking(move || {
        let discovery = crate::runtime::storage_aliases::discover(
            &sandboxes,
            &volumes,
            id,
            &bindings,
            &aliases.sandboxes,
            &aliases.snapshots,
        )?;
        Ok::<_, MicrosandboxError>(
            aliases
                .sandboxes
                .into_iter()
                .filter(|peer| {
                    peer.status.has_active_runtime_state()
                        && discovery.related_sandbox_ids.contains(&peer.id)
                })
                .map(|peer| (peer.name, peer.id))
                .collect::<Vec<_>>(),
        )
    })
    .await
    .map_err(|_| diagnostic_error("related writer inspection failed"))??;
    for (peer, id) in peers {
        result.push(observed_blocker(&mut db, &home, name, &peer, id).await?);
    }
    result.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(result)
}

async fn require_teardown(db: &mut SqliteConnection, id: i32) -> MicrosandboxResult<()> {
    // Some very old catalogs lack a run table. No process identity exists to authorize a stop.
    let table: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='run'")
            .fetch_one(&mut *db)
            .await
            .map_err(|_| diagnostic_error("runtime generation inventory unavailable"))?;
    if table == 0 {
        return Ok(());
    }
    let pid: Option<Option<i32>> =
        sqlx::query_scalar("SELECT pid FROM run WHERE sandbox_id=? ORDER BY id DESC LIMIT 1")
            .bind(id)
            .fetch_optional(db)
            .await
            .map_err(|_| diagnostic_error("runtime teardown cannot be established"))?;
    if pid
        .flatten()
        .is_some_and(microsandbox_utils::process::pid_exists)
    {
        return Err(diagnostic_error(
            "a stopped sandbox still has a recorded runtime process; wait for teardown and inspect again",
        ));
    }
    Ok(())
}

async fn observed_blocker(
    db: &mut SqliteConnection,
    home: &std::path::Path,
    target: &str,
    name: &str,
    sandbox_id: i32,
) -> MicrosandboxResult<StorageRepairBlocker> {
    let row = sqlx::query("SELECT id, status FROM run WHERE sandbox_id=? ORDER BY id DESC LIMIT 1")
        .bind(sandbox_id)
        .fetch_optional(db)
        .await
        .map_err(|_| diagnostic_error("cannot identify the current runtime generation"))?
        .ok_or_else(|| {
            diagnostic_error(
                "cannot identify the current runtime generation; inspect it before stopping",
            )
        })?;
    let status: String = row
        .try_get("status")
        .map_err(|_| diagnostic_error("unavailable runtime generation state"))?;
    if status != "Running" {
        return Err(diagnostic_error(
            "the runtime generation is already stopping or changed; inspect storage again",
        ));
    }
    Ok(StorageRepairBlocker {
        name: name.into(),
        target: target.into(),
        home: home.to_owned(),
        sandbox_id,
        run_id: row
            .try_get("id")
            .map_err(|_| diagnostic_error("unavailable runtime generation identity"))?,
    })
}
