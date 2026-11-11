//! Account for existing disk aliases without granting authority to another sandbox's bytes.
//!
//! Discovery is read-only and provisional. The runtime reopens every admitted object and checks
//! complete link counts while the execution caller retains this module's related-writer guards.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use cap_primitives::fs as cap_fs;
use microsandbox_image::checkpoint::{CheckpointManifest, DiskGenerationManifest, ObjectId};
use microsandbox_image::snapshot::{DESCRIPTOR_FILENAME, Manifest, OwnedVolumeData, SnapshotState};
use microsandbox_image::storage_lease::StorageLease;
use microsandbox_runtime::checkpoint::migration::{
    self, AliasSource, AuthorizedAlias, MigrationBindings,
};
use microsandbox_runtime::ipc::{self, SandboxLifecycleGuard};
use microsandbox_types::VolumeMount;
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

use crate::backend::local::creation::CreationStorage;
use crate::sandbox::{RootfsSource, SandboxConfig, SandboxStatus, validate_sandbox_name};
use crate::{LocalBackend, MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_ROWS: usize = 4096;
const MAX_ENTRIES: usize = 16384;
const MAX_METADATA: u64 = 1024 * 1024;
const MAX_CATALOG_BYTES: usize = 16 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A host-catalog record; the saved configuration, not a guest journal, defines its roles.
pub(crate) struct CatalogSandbox {
    pub id: i32,
    pub name: String,
    pub config: SandboxConfig,
    pub stored_config: String,
    pub status: SandboxStatus,
}

pub(crate) struct CatalogSnapshot {
    pub id: String,
    pub path: PathBuf,
    pub descriptor_digest: Option<String>,
}

#[derive(Default)]
pub(crate) struct AliasDiscovery {
    pub aliases: Vec<AuthorizedAlias>,
    pub related_sandbox_ids: Vec<i32>,
    pub snapshot_paths: Vec<PathBuf>,
    pub reasons: Vec<String>,
}

/// These resources must outlive capture, including cancellation of the public async operation.
/// The caller performs capture synchronously with these guards in scope, never in a detached task.
#[derive(Default)]
pub(crate) struct AliasGuards {
    _files: Vec<File>,
    _lifecycles: Vec<SandboxLifecycleGuard>,
    _storage: Vec<CreationStorage>,
    _snapshots: Vec<StorageLease>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Discover only aliases of already selected objects. No payload bytes or arbitrary sibling
/// directories are read. Missing unrelated artifacts do not prevent an independent migration.
pub(crate) fn discover(
    sandboxes_dir: &Path,
    volumes_dir: &Path,
    current_id: i32,
    bindings: &MigrationBindings,
    sandboxes: &[CatalogSandbox],
    snapshots: &[CatalogSnapshot],
) -> MicrosandboxResult<AliasDiscovery> {
    if sandboxes.len() > MAX_ROWS || snapshots.len() > MAX_ROWS {
        return Err(failure(
            "related storage catalog exceeds the inspection bound",
        ));
    }
    let current = sandboxes
        .iter()
        .find(|row| row.id == current_id)
        .ok_or_else(|| failure("sandbox catalog identity changed during storage inspection"))?;
    validate_sandbox_name(&current.name)?;
    let sources =
        migration::alias_sources(&sandboxes_dir.join(&current.name).join("runtime"), bindings)
            .map_err(failure)?;
    let by_identity: BTreeMap<_, _> = sources
        .iter()
        .filter(|source| source.links > 1)
        .map(|source| (source.identity_object.clone(), source))
        .collect();
    let mut result = AliasDiscovery::default();
    #[cfg(target_os = "macos")]
    for peer in sandboxes.iter().filter(|row| row.id != current_id) {
        validate_sandbox_name(&peer.name)?;
        if peer.status.has_active_runtime_state()
            && migration_layout_is_legacy(sandboxes_dir, &peer.name)
        {
            result.related_sandbox_ids.push(peer.id);
            result.reasons.push(unclassified_writer(&peer.name));
        }
    }
    let mut budget = MAX_ENTRIES;
    let mut metadata_budget = MAX_CATALOG_BYTES;
    let (snapshot_resources, related_snapshot_ids, snapshot_sources) =
        snapshot_relations(sandboxes_dir, current, snapshots, &mut metadata_budget)?;
    for peer in sandboxes.iter().filter(|row| row.id != current_id) {
        validate_sandbox_name(&peer.name)?;
        if peer.config.spec.name != peer.name {
            return Err(failure(
                "related catalog configuration has a different sandbox name",
            ));
        }
        let directory = sandboxes_dir.join(&peer.name);
        let runtime = directory.join("runtime");
        let authority = super::protected_state::bindings(
            &peer.config,
            &directory,
            peer.id,
            &peer.stored_config,
        )?;
        let paths = if by_identity.is_empty() {
            Vec::new()
        } else {
            producer_paths(&directory, &authority, &mut budget)?
        };
        let mut matching = Vec::new();
        for path in paths {
            if let Some(identity) = identity_at(&path)?
                && let Some(source) = by_identity.get(&identity)
            {
                matching.push((path, *source));
            }
        }
        let mounted = writable_bindings(&peer.config, volumes_dir)
            .iter()
            .any(|path| {
                sources.iter().any(|source| overlaps(path, source))
                    || snapshot_resources
                        .iter()
                        .any(|resource| namespaces_overlap(path, resource))
            });
        // Catalog ancestry remains useful after a guest unlinks a previously opened alias.
        // It only extends writer exclusion, never the set of readable source objects.
        let related_snapshot = snapshot_sources.contains(&peer.name)
            || peer
                .config
                .snapshot_parent
                .as_ref()
                .is_some_and(|id| related_snapshot_ids.contains(id));
        if matching.is_empty() && !mounted && !related_snapshot {
            continue;
        }
        result.related_sandbox_ids.push(peer.id);
        // Check status before source admission: on Windows a live write handle deliberately
        // prevents the runtime's restrictive disk handle from opening at all.
        if peer.status.has_active_runtime_state() {
            result.reasons.push(format!(
                "related writer '{}' is active; stop it before migrating this storage",
                peer.name
            ));
            continue;
        }
        if matching.is_empty() {
            continue;
        }
        let selected = match migration::selected_sources(&runtime, &authority) {
            Ok(selected) => selected,
            Err(_) => {
                result.reasons.push(format!(
                    "cannot establish the selected storage of related sandbox '{}'",
                    peer.name
                ));
                continue;
            }
        };
        for (path, source) in matching {
            let role = migration::producer_role(&runtime, &authority, &path);
            let sealed = selected.iter().any(|other| {
                other.identity_object == source.identity_object
                    && other.disk_id == source.disk_id
                    && other.readonly
            });
            let writable = selected
                .iter()
                .any(|other| other.identity_object == source.identity_object && !other.readonly);
            if role.as_deref() != Some(&source.disk_id) || !sealed || writable {
                result.reasons.push(format!(
                    "related sandbox '{}' has an unsealed or different-role disk alias",
                    peer.name
                ));
                continue;
            }
            result.aliases.push(AuthorizedAlias {
                disk_id: source.disk_id.clone(),
                path,
            });
        }
        // Runtime checkpoints are guest-writable in old releases. They supply no authority:
        // count their names only after a matching host-managed selected sealed producer exists.
        let checkpoint_roots = entries(&runtime.join("checkpoints"), &mut budget)?;
        for checkpoint in checkpoint_roots {
            for path in entries(&checkpoint.join("layers"), &mut budget)? {
                if !checkpoint_layer_name(&path) {
                    continue;
                }
                let Some(identity) = identity_at(&path)? else {
                    continue;
                };
                let Some(source) = by_identity.get(&identity) else {
                    continue;
                };
                if selected.iter().any(|other| {
                    other.identity_object == identity
                        && other.disk_id == source.disk_id
                        && other.readonly
                }) && result.aliases.iter().any(|alias| {
                    alias.disk_id == source.disk_id && alias.path.starts_with(&directory)
                }) {
                    result.aliases.push(AuthorizedAlias {
                        disk_id: source.disk_id.clone(),
                        path,
                    });
                }
            }
        }
    }
    if sources.iter().any(|source| source.links > 1) {
        for snapshot in snapshots {
            // A stale snapshot index must not disable unrelated sandboxes. Invalid descriptors
            // never admit aliases; an actual unresolved link is rejected by the runtime count.
            let Ok(payloads) = snapshot_payloads(snapshot, &mut metadata_budget) else {
                if metadata_budget == 0 {
                    return Err(failure(
                        "related snapshot metadata exceeds the aggregate inspection bound",
                    ));
                }
                continue;
            };
            let mut used = false;
            for (path, role) in payloads {
                spend(&mut budget)?;
                let Some(identity) = identity_at(&path)? else {
                    continue;
                };
                let Some(source) = by_identity.get(&identity) else {
                    continue;
                };
                if role != source.disk_id {
                    result
                        .reasons
                        .push("installed snapshot has a different-role disk alias".into());
                    continue;
                }
                result.aliases.push(AuthorizedAlias {
                    disk_id: role,
                    path,
                });
                used = true;
            }
            if used {
                result.snapshot_paths.push(snapshot.path.clone());
            }
        }
    }
    // A directory mount can expose a second name for the inode without containing its selected
    // source path. Recheck explicit writers against every discovered alias (including installed
    // snapshots), otherwise a live guest could mutate a sealed source through that other name.
    let mut exposed = sources.clone();
    for alias in &result.aliases {
        let Some(identity) = identity_at(&alias.path)? else {
            continue;
        };
        if let Some(source) = by_identity.get(&identity) {
            let mut source = (*source).clone();
            source.path = alias.path.clone();
            exposed.push(source);
        }
    }
    for peer in sandboxes.iter().filter(|row| row.id != current_id) {
        if writable_bindings(&peer.config, volumes_dir)
            .iter()
            .any(|path| exposed.iter().any(|source| overlaps(path, source)))
        {
            result.related_sandbox_ids.push(peer.id);
            if peer.status.has_active_runtime_state() {
                result.reasons.push(format!(
                    "related writer '{}' is active; stop it before migrating this storage",
                    peer.name
                ));
            }
        }
    }
    result.aliases.sort_by(|a, b| a.path.cmp(&b.path));
    result
        .aliases
        .dedup_by(|a, b| a.path == b.path && a.disk_id == b.disk_id);
    result.related_sandbox_ids.sort_unstable();
    result.related_sandbox_ids.dedup();
    result.snapshot_paths.sort();
    result.snapshot_paths.dedup();
    result.reasons.sort();
    result.reasons.dedup();
    Ok(result)
}

/// Exclude all discovered writers, then repeat discovery under the retained guards. Every
/// related acquisition is nonblocking: the caller already owns its own lifecycle and lineage.
pub(crate) async fn resolve(
    backend: &LocalBackend,
    _config: &SandboxConfig,
    current_id: i32,
    bindings: &mut MigrationBindings,
) -> MicrosandboxResult<AliasGuards> {
    resolve_with_catalog(backend, current_id, bindings, None).await
}

/// Explicit browsing supplies a read-only released catalog. Ownership, two-pass discovery and
/// teardown checks stay identical to adoption; only SQL access and compatibility decoding differ.
pub(crate) async fn resolve_with_catalog(
    backend: &LocalBackend,
    current_id: i32,
    bindings: &mut MigrationBindings,
    mut readonly: Option<&mut sea_orm::sqlx::SqliteConnection>,
) -> MicrosandboxResult<AliasGuards> {
    if bindings.root.is_none() && bindings.owned_disks.is_empty() {
        return Ok(AliasGuards::default());
    }
    let (sandboxes, snapshots) = catalog(backend, &mut readonly).await?;
    let mut guards = AliasGuards::default();
    #[cfg(target_os = "macos")]
    let excluded =
        exclude_unclassified_writers(backend, current_id, &sandboxes, &mut guards, &mut readonly)
            .await?;
    #[cfg(not(target_os = "macos"))]
    let excluded: Vec<i32> = Vec::new();
    let first = discover(
        &backend.sandboxes_dir(),
        &backend.volumes_dir(),
        current_id,
        bindings,
        &sandboxes,
        &snapshots,
    )?;
    require_clear(&first)?;
    for id in &first.related_sandbox_ids {
        let peer = sandboxes
            .iter()
            .find(|row| row.id == *id)
            .expect("discovered catalog record");
        if !excluded.contains(id) {
            guards._files.push(
                ipc::try_acquire_transition_guard(&backend.config().run_dir(), &peer.name)?
                    .ok_or_else(|| busy(&peer.name))?,
            );
            guards._files.push(
                ipc::try_acquire_snapshot_lineage_guard(&backend.config().run_dir(), &peer.name)?
                    .ok_or_else(|| busy(&peer.name))?,
            );
            guards._lifecycles.push(
                SandboxLifecycleGuard::try_acquire(&backend.config().run_dir(), &peer.name)?
                    .ok_or_else(|| busy(&peer.name))?,
            );
        }
        guards
            ._storage
            .push(CreationStorage::acquire(backend, &peer.name)?);
        guards._files.extend(
            super::owned_volumes::try_acquire_disk_guards(
                &backend.sandboxes_dir().join(&peer.name),
                &peer.config.spec.mounts,
            )?
            .ok_or_else(|| busy(&peer.name))?,
        );
        // Old runtimes need not participate in all new guards. A live recorded PID therefore
        // remains a refusal even if its catalog status says Stopped (PID reuse fails closed).
        let pid = if let Some(db) = readonly.as_deref_mut() {
            sea_orm::sqlx::query_scalar::<_, Option<i32>>(
                "SELECT pid FROM run WHERE sandbox_id=? ORDER BY id DESC LIMIT 1",
            )
            .bind(*id)
            .fetch_optional(db)
            .await
            .map_err(|_| failure("cannot verify related runtime process ownership"))?
            .flatten()
        } else {
            let pools = backend.db().await?;
            LocalBackend::load_latest_run(pools.read(), *id)
                .await?
                .and_then(|run| run.pid)
        };
        if pid.is_some_and(microsandbox_utils::process::pid_is_alive) {
            return Err(busy(&peer.name));
        }
    }
    for path in &first.snapshot_paths {
        // Descriptor pins also coordinate with Windows descriptor-only readers/deleters.
        guards._snapshots.push(
            StorageLease::descriptor(&path.join(DESCRIPTOR_FILENAME), false)?.ok_or_else(|| {
                failure("related snapshot is busy; retry migration after its operation completes")
            })?,
        );
    }
    let (current, snapshots) = catalog(backend, &mut readonly).await?;
    #[cfg(target_os = "macos")]
    {
        let latest = unclassified_writers(backend, current_id, &current, &mut readonly).await?;
        if latest != excluded {
            return Err(failure(
                "legacy runtime set changed while acquiring migration ownership; retry",
            ));
        }
    }
    // Only retained resources need unchanged revisions. A second full discovery below catches
    // newly introduced relationships; unrelated starts/stops must not force migration retries.
    for before in sandboxes
        .iter()
        .filter(|row| row.id == current_id || first.related_sandbox_ids.contains(&row.id))
    {
        if let Some(after) = current.iter().find(|row| row.id == before.id) {
            if before.name != after.name
                || before.stored_config != after.stored_config
                || before.status != after.status
                || serde_json::to_value(&before.config)? != serde_json::to_value(&after.config)?
            {
                return Err(failure(
                    "related storage configuration changed; retry migration",
                ));
            }
        } else {
            return Err(failure("related storage catalog changed; retry migration"));
        }
    }
    let after = discover(
        &backend.sandboxes_dir(),
        &backend.volumes_dir(),
        current_id,
        bindings,
        &current,
        &snapshots,
    )?;
    require_clear(&after)?;
    if after.related_sandbox_ids != first.related_sandbox_ids
        || after.snapshot_paths != first.snapshot_paths
        || after.aliases != first.aliases
    {
        return Err(failure("related storage aliases changed; retry migration"));
    }
    bindings.aliases = after.aliases;
    Ok(guards)
}

/// macOS file leases require a private entitlement. Hold the launch guards of stopped legacy
/// peers instead, and refuse any still-running unclassified peer: an unlinked writable handle
/// cannot be ruled out by inode link counts or a racy process-file enumeration. Protected peers
/// need only the ordinary explicit-alias checks and are not stopped or locked by this gate.
#[cfg(target_os = "macos")]
async fn exclude_unclassified_writers(
    backend: &LocalBackend,
    current_id: i32,
    sandboxes: &[CatalogSandbox],
    guards: &mut AliasGuards,
    readonly: &mut Option<&mut sea_orm::sqlx::SqliteConnection>,
) -> MicrosandboxResult<Vec<i32>> {
    let excluded = unclassified_writers(backend, current_id, sandboxes, readonly).await?;
    for id in &excluded {
        let peer = sandboxes
            .iter()
            .find(|row| row.id == *id)
            .ok_or_else(|| failure("legacy runtime identity changed; retry migration"))?;
        guards._files.push(
            ipc::try_acquire_transition_guard(&backend.config().run_dir(), &peer.name)?
                .ok_or_else(|| busy(&peer.name))?,
        );
        guards._files.push(
            ipc::try_acquire_snapshot_lineage_guard(&backend.config().run_dir(), &peer.name)?
                .ok_or_else(|| busy(&peer.name))?,
        );
        guards._lifecycles.push(
            SandboxLifecycleGuard::try_acquire(&backend.config().run_dir(), &peer.name)?
                .ok_or_else(|| busy(&peer.name))?,
        );
    }
    Ok(excluded)
}

#[cfg(target_os = "macos")]
async fn unclassified_writers(
    backend: &LocalBackend,
    current_id: i32,
    sandboxes: &[CatalogSandbox],
    readonly: &mut Option<&mut sea_orm::sqlx::SqliteConnection>,
) -> MicrosandboxResult<Vec<i32>> {
    // Resolve the latest owner for each bounded catalog row, rather than inspecting processes
    // or scanning historical disk payloads. A terminal status does not prove process teardown.
    let query = "SELECT s.id, (SELECT r.pid FROM run r WHERE r.sandbox_id=s.id ORDER BY r.id DESC LIMIT 1) AS pid FROM sandbox s LIMIT ?";
    let limit = (MAX_ROWS + 1) as i64;
    let pids = if let Some(db) = readonly.as_deref_mut() {
        sea_orm::sqlx::query_as::<_, (i32, Option<i32>)>(query)
            .bind(limit)
            .fetch_all(db)
            .await
            .map_err(|_| failure("cannot verify released runtime process inventory"))?
            .into_iter()
            .collect::<BTreeMap<_, _>>()
    } else {
        let pools = backend.db().await?;
        let rows = pools
            .read()
            .query_all_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                query,
                [limit.into()],
            ))
            .await?;
        let mut pids = BTreeMap::new();
        for row in rows {
            pids.insert(
                row.try_get::<i32>("", "id")?,
                row.try_get::<Option<i32>>("", "pid")?,
            );
        }
        pids
    };
    if pids.len() > MAX_ROWS {
        return Err(failure(
            "legacy runtime inventory exceeds the inspection bound",
        ));
    }
    let mut excluded = Vec::new();
    for peer in sandboxes.iter().filter(|row| row.id != current_id) {
        validate_sandbox_name(&peer.name)?;
        if !migration_layout_is_legacy(&backend.sandboxes_dir(), &peer.name) {
            continue;
        }
        let pid = pids
            .get(&peer.id)
            .ok_or_else(|| failure("legacy runtime catalog changed; retry migration"))?;
        if peer.status.has_active_runtime_state()
            || pid.is_some_and(microsandbox_utils::process::pid_exists)
        {
            return Err(failure(unclassified_writer(&peer.name)));
        }
        excluded.push(peer.id);
    }
    excluded.sort_unstable();
    Ok(excluded)
}

#[cfg(target_os = "macos")]
fn migration_layout_is_legacy(sandboxes: &Path, name: &str) -> bool {
    microsandbox_runtime::checkpoint::layout::require_ready(&sandboxes.join(name).join("runtime"))
        .is_err()
}

#[cfg(target_os = "macos")]
fn unclassified_writer(name: &str) -> String {
    format!(
        "legacy storage migration on macOS cannot exclude a writer in sandbox '{name}'; stop that legacy runtime, wait for its process to exit, then retry. Protected sandboxes can remain running"
    )
}

async fn catalog(
    backend: &LocalBackend,
    readonly: &mut Option<&mut sea_orm::sqlx::SqliteConnection>,
) -> MicrosandboxResult<(Vec<CatalogSandbox>, Vec<CatalogSnapshot>)> {
    if let Some(db) = readonly.as_deref_mut() {
        return crate::setup::preview_alias_catalog(db).await;
    }
    let pools = backend.db().await?;
    // Bound data in SQLite before materialization, not only after allocating host strings.
    let budget = pools.read().query_one_raw(Statement::from_string(DatabaseBackend::Sqlite,
        "SELECT COALESCE(SUM(length(CAST(config AS BLOB)) + COALESCE(length(CAST(active_config AS BLOB)),0)),0) AS bytes FROM sandbox".to_owned()))
        .await?.ok_or_else(|| failure("related catalog budget is unavailable"))?;
    let bytes: i64 = budget.try_get("", "bytes")?;
    if bytes < 0 || bytes as u64 > MAX_CATALOG_BYTES as u64 {
        return Err(failure(
            "related catalog configuration exceeds the inspection bound",
        ));
    }
    let rows = pools.read().query_all_raw(Statement::from_string(DatabaseBackend::Sqlite, format!(
        "SELECT id, CASE WHEN length(name)<=256 THEN name END AS name, status, CASE WHEN length(CAST(config AS BLOB))<=1048576 THEN config END AS config, CASE WHEN active_config IS NULL OR length(CAST(active_config AS BLOB))<=1048576 THEN active_config END AS active_config, active_config IS NOT NULL AND length(CAST(active_config AS BLOB))>1048576 AS active_too_large FROM sandbox LIMIT {}", MAX_ROWS + 1))).await?;
    let snapshots = pools.read().query_all_raw(Statement::from_string(DatabaseBackend::Sqlite, format!(
        "SELECT CASE WHEN length(COALESCE(snapshot_id,digest))<=512 THEN COALESCE(snapshot_id,digest) END AS id, CASE WHEN length(artifact_path)<=4096 THEN artifact_path END AS path, CASE WHEN length(COALESCE(descriptor_digest,digest))<=256 THEN COALESCE(descriptor_digest,digest) END AS digest FROM snapshot_index LIMIT {}", MAX_ROWS + 1))).await?;
    if rows.len() > MAX_ROWS || snapshots.len() > MAX_ROWS {
        return Err(failure(
            "related storage catalog exceeds the inspection bound",
        ));
    }
    let mut total = 0usize;
    let mut sandboxes = Vec::new();
    for row in rows {
        let id: i32 = row.try_get("", "id")?;
        let name: String = row
            .try_get("", "name")
            .map_err(|_| failure("related sandbox name exceeds its bound"))?;
        let status: SandboxStatus = row.try_get("", "status")?;
        let stored_config: String = row
            .try_get("", "config")
            .map_err(|_| failure("related sandbox configuration exceeds its bound"))?;
        let active_config: Option<String> = row.try_get("", "active_config")?;
        let active_too_large: bool = row.try_get("", "active_too_large")?;
        if active_too_large {
            return Err(failure("active related configuration exceeds its bound"));
        }
        // A live VM's active config can differ from the next-start config. Both mount sets
        // must be considered, so merge the active explicit mounts into the discovery view.
        total = total
            .checked_add(stored_config.len() + active_config.as_ref().map_or(0, String::len))
            .ok_or_else(|| failure("related catalog configuration exceeds the inspection bound"))?;
        if total > MAX_CATALOG_BYTES {
            return Err(failure(
                "related catalog configuration exceeds the inspection bound",
            ));
        }
        let mut config = SandboxConfig::from_stored(&stored_config, None).map_err(|_| {
            failure(format!(
                "cannot establish explicit mount writers from sandbox '{name}' configuration"
            ))
        })?;
        if let Some(active) = &active_config {
            let active = SandboxConfig::from_stored(active, None)
                .map_err(|_| failure(format!("cannot establish explicit mount writers from sandbox '{name}' active configuration")))?;
            merge_active_bindings(&mut config, active);
        }
        sandboxes.push(CatalogSandbox {
            id,
            name,
            config,
            stored_config,
            status,
        });
    }
    Ok((
        sandboxes,
        snapshots
            .into_iter()
            .map(|row| {
                Ok(CatalogSnapshot {
                    id: row.try_get("", "id")?,
                    path: PathBuf::from(row.try_get::<String>("", "path")?),
                    descriptor_digest: row.try_get("", "digest")?,
                })
            })
            .collect::<MicrosandboxResult<Vec<_>>>()?,
    ))
}

/// Add active explicit host bindings for writer discovery without duplicating owned disk roles.
/// The catalog's desired configuration still defines the sandbox's producer namespace.
pub(crate) fn merge_active_bindings(config: &mut SandboxConfig, active: SandboxConfig) {
    config
        .spec
        .mounts
        .extend(active.spec.mounts.into_iter().filter(|mount| {
            matches!(
                mount,
                VolumeMount::Bind { .. }
                    | VolumeMount::Named { .. }
                    | VolumeMount::DiskImage { .. }
            )
        }));
    let root = match active.spec.image {
        RootfsSource::Bind { path, .. } | RootfsSource::DiskImage { path, .. } => Some(path),
        RootfsSource::Oci(oci) => match oci.root_disk {
            Some(crate::sandbox::RootDisk::DiskImage { path, .. }) => Some(path),
            _ => None,
        },
    };
    if let Some(path) = root {
        // This synthetic mount is never persisted or launched. Its directory/file overlap is
        // only an extra writer relation; it cannot become source authority.
        config.spec.mounts.push(VolumeMount::DiskImage {
            host: path,
            guest: "/".into(),
            format: microsandbox_types::DiskImageFormat::Raw,
            fstype: None,
            options: Default::default(),
        });
    }
}

fn producer_paths(
    directory: &Path,
    bindings: &MigrationBindings,
    budget: &mut usize,
) -> MicrosandboxResult<Vec<PathBuf>> {
    let runtime = directory.join("runtime");
    let mut paths = entries(directory, budget)?;
    if let Some(root) = &bindings.root {
        paths.push(root.path.clone());
    }
    for disk in &bindings.owned_disks {
        if let Some(parent) = disk.path.parent() {
            paths.extend(entries(parent, budget)?);
        }
    }
    for stage in entries(&runtime, budget)? {
        if stage
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(".grow-") || name.starts_with(".compact-"))
        {
            paths.extend(entries(&stage, budget)?);
        }
    }
    paths.retain(|path| migration::producer_role(&runtime, bindings, path).is_some());
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn writable_bindings(config: &SandboxConfig, volumes: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    match &config.spec.image {
        RootfsSource::Bind { path, .. } | RootfsSource::DiskImage { path, .. } => {
            paths.push(path.clone())
        }
        RootfsSource::Oci(oci) => {
            if let Some(crate::sandbox::RootDisk::DiskImage { path, .. }) = &oci.root_disk {
                paths.push(path.clone());
            }
        }
    }
    for mount in &config.spec.mounts {
        match mount {
            VolumeMount::Bind { host, options, .. }
            | VolumeMount::DiskImage { host, options, .. }
                if !options.readonly =>
            {
                paths.push(host.clone())
            }
            VolumeMount::Named { name, options, .. } if !options.readonly => {
                paths.push(volumes.join(name))
            }
            _ => {}
        }
    }
    paths
}

fn overlaps(binding: &Path, source: &AliasSource) -> bool {
    // Canonicalization here is comparison only. No persisted paths or source authority change.
    let direct = match (fs::canonicalize(binding), fs::canonicalize(&source.path)) {
        (Ok(binding), Ok(source)) => source.starts_with(binding),
        _ => source.path.starts_with(binding),
    };
    direct
        || identity_at(binding)
            .ok()
            .flatten()
            .is_some_and(|identity| identity == source.identity_object)
}

fn namespaces_overlap(left: &Path, right: &Path) -> bool {
    let left = fs::canonicalize(left).or_else(|_| std::path::absolute(left));
    let right = fs::canonicalize(right).or_else(|_| std::path::absolute(right));
    match (left, right) {
        (Ok(left), Ok(right)) => left.starts_with(&right) || right.starts_with(&left),
        _ => false,
    }
}

/// Bound the resource namespaces that can retain detached aliases using host-recorded ancestry.
/// Missing payload names do not erase the relation. A deleted catalog artifact supplies no
/// source authority; its remaining child still needs independent producer-role admission.
fn snapshot_relations(
    sandboxes_dir: &Path,
    current: &CatalogSandbox,
    snapshots: &[CatalogSnapshot],
    budget: &mut usize,
) -> MicrosandboxResult<(Vec<PathBuf>, BTreeSet<String>, BTreeSet<String>)> {
    let mut pending = current
        .config
        .snapshot_parent
        .clone()
        .into_iter()
        .collect::<Vec<_>>();
    let sandbox = sandboxes_dir.join(&current.name);
    match fs::symlink_metadata(sandbox.join("snapshot-lineage.json")) {
        Ok(_) => {
            let bytes = budgeted_metadata(&sandbox, Path::new("snapshot-lineage.json"), budget)?;
            let cursor: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|_| failure("invalid host snapshot ancestry cursor"))?;
            if cursor.get("sandbox_id").and_then(|id| id.as_i64()) != Some(i64::from(current.id)) {
                return Err(failure(
                    "host snapshot ancestry belongs to another sandbox incarnation",
                ));
            }
            let id = cursor
                .get("snapshot_id")
                .and_then(|id| id.as_str())
                .ok_or_else(|| failure("invalid host snapshot ancestry identity"))?;
            pending.push(id.to_owned());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut visited = BTreeSet::new();
    let mut resources = BTreeSet::new();
    let mut sources = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if id.len() > 512 || visited.len() >= MAX_ROWS {
            return Err(failure("snapshot ancestry exceeds its inspection bound"));
        }
        if !visited.insert(id.clone()) {
            continue;
        }
        for snapshot in snapshots.iter().filter(|snapshot| snapshot.id == id) {
            resources.insert(snapshot.path.clone());
            // Catalog paths are already sufficient for conservative writer fencing. Invalid
            // or deleted descriptors cannot grant aliases or invent further lineage edges.
            let Ok(manifest) = snapshot_manifest(snapshot, budget) else {
                if *budget == 0 {
                    return Err(failure("snapshot ancestry exceeds its metadata bound"));
                }
                continue;
            };
            if let Some(source) = manifest.capture.source_lineage
                && validate_sandbox_name(&source).is_ok()
            {
                sources.insert(source);
            }
            if let Some(parent) = manifest.parent {
                pending.push(parent.to_string());
            }
        }
    }
    Ok((resources.into_iter().collect(), visited, sources))
}

fn checkpoint_layer_name(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some((id, format)) = name.rsplit_once('.') else {
        return false;
    };
    let Some(id) = id.strip_prefix("layer_") else {
        return false;
    };
    matches!(format, "raw" | "qcow2")
        && id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn snapshot_payloads(
    snapshot: &CatalogSnapshot,
    budget: &mut usize,
) -> MicrosandboxResult<Vec<(PathBuf, String)>> {
    let manifest = snapshot_manifest(snapshot, budget)?;
    let mut payloads = Vec::new();
    match &manifest.state {
        SnapshotState::File(state) => {
            for layer in &state.layers {
                payloads.push((snapshot.path.join(state.layer_path(layer)), "root".into()));
            }
        }
        SnapshotState::Checkpoint(state) => {
            let bytes = budgeted_metadata(
                &snapshot.path,
                Path::new("checkpoint/checkpoint.json"),
                budget,
            )?;
            if ObjectId::from_bytes(&bytes)
                .map_err(|_| failure("invalid checkpoint identity"))?
                .as_str()
                != state.checkpoint_root
            {
                return Err(failure(
                    "installed checkpoint identity differs from its descriptor",
                ));
            }
            let checkpoint = CheckpointManifest::from_bytes(&bytes)
                .map_err(|_| failure("invalid checkpoint manifest"))?;
            for object in checkpoint.disks {
                let relative = Path::new("checkpoint/objects/sha256")
                    .join(&object.hex()[..2])
                    .join(object.hex());
                let bytes = budgeted_metadata(&snapshot.path, &relative, budget)?;
                if ObjectId::from_bytes(&bytes)
                    .map_err(|_| failure("invalid disk generation identity"))?
                    != object
                {
                    return Err(failure("installed disk generation identity changed"));
                }
                let generation = DiskGenerationManifest::from_bytes(&bytes)
                    .map_err(|_| failure("invalid disk generation"))?;
                let role = if matches!(generation.device_id.as_str(), "vda" | "vdb") {
                    "root"
                } else {
                    &generation.device_id
                };
                add_generation(
                    &snapshot.path.join("checkpoint"),
                    &generation,
                    role,
                    &mut payloads,
                )?;
            }
        }
    }
    for owned in manifest
        .owned_volumes()
        .map_err(|_| failure("invalid snapshot owned-volume inventory"))?
    {
        if let OwnedVolumeData::Disk { generation } = owned.data {
            add_generation(&snapshot.path, &generation, &owned.mount_id, &mut payloads)?;
        }
    }
    if payloads.len() > 1024 {
        return Err(failure("snapshot disk inventory exceeds its bound"));
    }
    Ok(payloads)
}

fn snapshot_manifest(
    snapshot: &CatalogSnapshot,
    budget: &mut usize,
) -> MicrosandboxResult<Manifest> {
    let descriptor = budgeted_metadata(&snapshot.path, Path::new(DESCRIPTOR_FILENAME), budget)?;
    let manifest = Manifest::from_bytes(&descriptor)
        .map_err(|_| failure("invalid installed snapshot descriptor"))?;
    if manifest.snapshot_id.as_str() != snapshot.id
        || snapshot
            .descriptor_digest
            .as_ref()
            .is_none_or(|digest| manifest.digest().ok().as_ref() != Some(digest))
    {
        return Err(failure(
            "installed snapshot identity differs from its catalog binding",
        ));
    }
    Ok(manifest)
}

fn add_generation(
    root: &Path,
    generation: &DiskGenerationManifest,
    role: &str,
    paths: &mut Vec<(PathBuf, String)>,
) -> MicrosandboxResult<()> {
    for layer in &generation.layers {
        let name = format!("{}.{}", layer.layer_id, layer.format);
        if Path::new(&name).components().count() != 1
            || !matches!(layer.format.as_str(), "raw" | "qcow2")
        {
            return Err(failure("invalid snapshot layer name"));
        }
        paths.push((root.join("layers").join(name), role.into()));
    }
    Ok(())
}

fn entries(path: &Path, budget: &mut usize) -> MicrosandboxResult<Vec<PathBuf>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_dir() || linked(&metadata) {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    for entry in fs::read_dir(path)? {
        spend(budget)?;
        paths.push(entry?.path());
    }
    Ok(paths)
}

fn spend(budget: &mut usize) -> MicrosandboxResult<()> {
    *budget = budget
        .checked_sub(1)
        .ok_or_else(|| failure("related storage inventory exceeds its entry bound"))?;
    Ok(())
}

fn identity_at(path: &Path) -> MicrosandboxResult<Option<String>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || linked(&metadata) {
        return Ok(None);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(Some(format!("{}:{}", metadata.dev(), metadata.ino())))
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::*;
        let file = fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        if linked(&file.metadata()?) {
            return Ok(None);
        }
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Some(format!(
            "{}:{}:{}",
            info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow
        )))
    }
}

fn linked(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn read_metadata(root: &Path, relative: &Path) -> MicrosandboxResult<Vec<u8>> {
    let absolute = std::path::absolute(root)?;
    let parent = absolute
        .parent()
        .ok_or_else(|| failure("snapshot has no parent directory"))?;
    let anchor = cap_fs::open_ambient_dir(parent, cap_primitives::ambient_authority())?;
    let mut cursor = cap_fs::open_dir_nofollow(
        &anchor,
        Path::new(
            absolute
                .file_name()
                .ok_or_else(|| failure("snapshot has no directory name"))?,
        ),
    )?;
    let parts = relative.components().collect::<Vec<_>>();
    if parts.is_empty()
        || parts.len() > 8
        || parts
            .iter()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(failure("invalid snapshot metadata path"));
    }
    for part in &parts[..parts.len() - 1] {
        cursor = cap_fs::open_dir_nofollow(&cursor, Path::new(part.as_os_str()))?;
        if linked(&cursor.metadata()?) {
            return Err(failure("linked snapshot metadata directory"));
        }
    }
    let mut options = cap_fs::OpenOptions::new();
    options
        .read(true)
        ._cap_fs_ext_follow(cap_fs::FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = cap_fs::open(
        &cursor,
        Path::new(parts.last().unwrap().as_os_str()),
        &options,
    )?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || linked(&metadata) || metadata.len() > MAX_METADATA {
        return Err(failure(
            "snapshot metadata is linked, nonregular, or exceeds its size bound",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_METADATA + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_METADATA {
        return Err(failure("snapshot metadata exceeds its size bound"));
    }
    Ok(bytes)
}

fn budgeted_metadata(
    root: &Path,
    relative: &Path,
    budget: &mut usize,
) -> MicrosandboxResult<Vec<u8>> {
    let bytes = read_metadata(root, relative)?;
    let Some(remaining) = budget.checked_sub(bytes.len()) else {
        *budget = 0;
        return Err(failure(
            "related snapshot metadata exceeds the aggregate inspection bound",
        ));
    };
    *budget = remaining;
    Ok(bytes)
}

fn require_clear(discovery: &AliasDiscovery) -> MicrosandboxResult<()> {
    if let Some(reason) = discovery.reasons.first() {
        return Err(failure(reason));
    }
    Ok(())
}

fn failure(message: impl Into<String>) -> MicrosandboxError {
    MicrosandboxError::Runtime(format!("storage migration: {}", message.into()))
}

fn busy(name: &str) -> MicrosandboxError {
    failure(format!(
        "related writer '{name}' is active or finishing storage work; stop it and retry migration"
    ))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: i32, name: &str) -> CatalogSandbox {
        let mut config = SandboxConfig::default();
        config.spec.name = name.into();
        let stored_config = serde_json::to_string(&config).unwrap();
        CatalogSandbox {
            id,
            name: name.into(),
            config,
            stored_config,
            status: SandboxStatus::Stopped,
        }
    }

    fn initialize(root: &Path, row: &CatalogSandbox, layered: bool) -> MigrationBindings {
        let path = root.join(&row.name);
        fs::create_dir_all(path.join("runtime")).unwrap();
        if !path.join("upper.ext4").exists() {
            fs::write(path.join("upper.ext4"), vec![21; 131072]).unwrap();
        }
        let bindings =
            super::super::protected_state::bindings(&row.config, &path, row.id, &row.stored_config)
                .unwrap();
        let mut layers = vec![
            serde_json::json!({"layer_id":format!("layer_{}", "a".repeat(32)), "path":path.join("upper.ext4"), "format":"raw", "integrity_root":null}),
        ];
        if layered {
            let head = path.join(format!("upper-{}.qcow2", "b".repeat(32)));
            // Discovery must not interpret disk bytes. Deliberately not a QCOW header.
            fs::write(&head, vec![22; 65536]).unwrap();
            layers.push(serde_json::json!({"layer_id":format!("layer_{}", "b".repeat(32)), "path":head,"format":"qcow2", "integrity_root":null}));
        }
        fs::write(path.join("runtime/root-disk.json"), serde_json::to_vec(&serde_json::json!({
            "schema":"microsandbox.runtime-root-disk/1", "volume_id":format!("vol_{}", "c".repeat(32)),
            "device_id":"vdb", "layout":"managed-upper", "published_generation":1,
            "launch_base":path.join("upper.ext4"), "layers":layers
        })).unwrap()).unwrap();
        bindings
    }

    fn share_base(root: &Path, left: &str, right: &str) {
        fs::remove_file(root.join(right).join("upper.ext4")).unwrap();
        fs::hard_link(
            root.join(left).join("upper.ext4"),
            root.join(right).join("upper.ext4"),
        )
        .unwrap();
    }

    #[test]
    fn direct_fork_without_ancestry_accounts_only_sealed_same_role_aliases() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let rows = [record(1, "child"), record(2, "parent")];
        let bindings = initialize(&root, &rows[0], true);
        initialize(&root, &rows[1], true);
        share_base(&root, "child", "parent");
        let checkpoint = root.join("parent/runtime/checkpoints/checkpoint-old/layers");
        fs::create_dir_all(&checkpoint).unwrap();
        let layer = checkpoint.join(format!("layer_{}.raw", "d".repeat(32)));
        fs::hard_link(root.join("child/upper.ext4"), &layer).unwrap();
        let report = discover(&root, &root.join("volumes"), 1, &bindings, &rows, &[]).unwrap();
        assert!(report.reasons.is_empty(), "{:?}", report.reasons);
        assert_eq!(report.related_sandbox_ids, [2]);
        assert_eq!(report.aliases.len(), 2);
        assert!(report.aliases.iter().any(|alias| alias.path == layer));
        assert!(
            !root.join("run").exists(),
            "read-only discovery must not create guards"
        );
    }

    #[test]
    fn writable_peer_head_is_refused_even_when_peer_is_stopped() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let rows = [record(1, "child"), record(2, "peer")];
        let bindings = initialize(&root, &rows[0], true);
        initialize(&root, &rows[1], false);
        share_base(&root, "child", "peer");
        let report = discover(&root, &root.join("volumes"), 1, &bindings, &rows, &[]).unwrap();
        assert!(
            report
                .reasons
                .iter()
                .any(|reason| reason.contains("unsealed"))
        );
        assert!(report.aliases.is_empty());
    }

    #[test]
    fn protected_peer_writable_original_base_is_still_a_writer() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let rows = [record(1, "child"), record(2, "peer")];
        let bindings = initialize(&root, &rows[0], true);
        initialize(&root, &rows[1], false);
        let journal = fs::read(root.join("peer/runtime/root-disk.json")).unwrap();
        fs::remove_file(root.join("peer/runtime/root-disk.json")).unwrap();
        microsandbox_runtime::checkpoint::layout::initialize_new(&root.join("peer/runtime"))
            .unwrap();
        fs::write(root.join("peer/root-disk.json"), journal).unwrap();
        share_base(&root, "child", "peer");
        let report = discover(&root, &root.join("volumes"), 1, &bindings, &rows, &[]).unwrap();
        assert!(
            report
                .reasons
                .iter()
                .any(|reason| reason.contains("unsealed"))
        );
    }

    #[test]
    fn single_link_source_still_detects_running_explicit_directory_writer() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let mut rows = [record(1, "child"), record(2, "peer")];
        let bindings = initialize(&root, &rows[0], false);
        rows[1].config.spec.image = RootfsSource::Bind {
            path: root.join("child"),
            follow_root_symlinks: false,
        };
        rows[1].status = SandboxStatus::Running;
        // The unrelated peer's storage does not even exist: nlink1 checks must need only its
        // host catalog mount bindings, never enumerate that peer's guest-controlled files.
        let report = discover(&root, &root.join("volumes"), 1, &bindings, &rows, &[]).unwrap();
        assert_eq!(report.related_sandbox_ids, [2]);
        assert!(
            report
                .reasons
                .iter()
                .any(|reason| reason.contains("active"))
        );
    }

    #[test]
    fn explicit_directory_writer_of_a_different_alias_is_excluded() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let mut rows = [record(1, "child"), record(2, "parent"), record(3, "writer")];
        let bindings = initialize(&root, &rows[0], true);
        initialize(&root, &rows[1], true);
        share_base(&root, "child", "parent");
        rows[2].config.spec.image = RootfsSource::Bind {
            path: root.join("parent"),
            follow_root_symlinks: false,
        };
        rows[2].status = SandboxStatus::Running;
        let report = discover(&root, &root.join("volumes"), 1, &bindings, &rows, &[]).unwrap();
        assert_eq!(report.related_sandbox_ids, [2, 3]);
        assert!(
            report
                .reasons
                .iter()
                .any(|reason| reason.contains("writer 'writer' is active"))
        );
    }

    #[test]
    fn catalog_snapshot_namespace_fences_detached_alias_writer_with_single_link() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let mut rows = [record(1, "child"), record(2, "writer")];
        rows[0].config.snapshot_parent = Some(format!("snap_{}", "a".repeat(32)));
        let bindings = initialize(&root, &rows[0], false);
        let artifact = root.join("installed-snapshot");
        fs::create_dir_all(artifact.join("layers")).unwrap();
        let former_alias = artifact.join("layers/removed.raw");
        fs::hard_link(root.join("child/upper.ext4"), &former_alias).unwrap();
        // An old guest can retain the open inode after removing its exported name.
        let _detached = File::open(&former_alias).unwrap();
        fs::remove_file(&former_alias).unwrap();
        rows[1].config.spec.image = RootfsSource::Bind {
            path: artifact.join("layers"),
            follow_root_symlinks: false,
        };
        rows[1].status = SandboxStatus::Running;
        let snapshots = [CatalogSnapshot {
            id: rows[0].config.snapshot_parent.clone().unwrap(),
            path: artifact,
            descriptor_digest: None,
        }];
        let report = discover(
            &root,
            &root.join("volumes"),
            1,
            &bindings,
            &rows,
            &snapshots,
        )
        .unwrap();
        assert_eq!(report.related_sandbox_ids, [2]);
        assert!(
            report
                .reasons
                .iter()
                .any(|reason| reason.contains("writer 'writer' is active"))
        );
        assert!(
            report.aliases.is_empty(),
            "catalog relation is not payload authority"
        );
    }

    #[test]
    fn checkpoint_metadata_names_never_account_as_disk_aliases() {
        assert!(checkpoint_layer_name(Path::new(&format!(
            "layer_{}.raw",
            "a".repeat(32)
        ))));
        for name in [
            "disk.json",
            "root-disk.json",
            "layer_../root.raw",
            "layer_a.raw",
            "layer_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json",
        ] {
            assert!(!checkpoint_layer_name(Path::new(name)));
        }
    }

    #[test]
    fn active_mount_merge_preserves_owned_role_count() {
        let mut desired = record(1, "test").config;
        let mut active = record(1, "test").config;
        active.spec.image = RootfsSource::Bind {
            path: PathBuf::from("/old-root"),
            follow_root_symlinks: false,
        };
        active.spec.mounts.push(VolumeMount::Owned {
            guest: "/data".into(),
            storage: microsandbox_types::OwnedVolumeStorage::Disk { capacity_mib: 64 },
            options: Default::default(),
            stat_virtualization: microsandbox_types::StatVirtualization::Strict,
            host_permissions: microsandbox_types::HostPermissions::Private,
        });
        desired.spec.mounts = active.spec.mounts.clone();
        merge_active_bindings(&mut desired, active);
        assert_eq!(
            desired
                .spec
                .mounts
                .iter()
                .filter(|mount| matches!(mount, VolumeMount::Owned { .. }))
                .count(),
            1
        );
        assert!(
            writable_bindings(&desired, Path::new("/volumes"))
                .contains(&PathBuf::from("/old-root"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_metadata_refuses_fifo_and_linked_parent_without_reading_target() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("snapshot");
        fs::create_dir(&root).unwrap();
        fs::write(temp.path().join("private"), b"not snapshot metadata").unwrap();
        symlink(temp.path(), root.join("checkpoint")).unwrap();
        assert!(read_metadata(&root, Path::new("checkpoint/private")).is_err());
        let fifo = root.join("snapshot.json");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_metadata(&root, Path::new("snapshot.json")).is_err());
    }

    async fn save(backend: &LocalBackend, row: &CatalogSandbox) {
        backend
            .db()
            .await
            .unwrap()
            .write()
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO sandbox(id,name,config,status,ephemeral) VALUES(?,?,?,'Stopped',0)",
                [
                    row.id.into(),
                    row.name.clone().into(),
                    row.stored_config.clone().into(),
                ],
            ))
            .await
            .unwrap();
    }

    fn private_test_home() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Linux hosts may use umask 0002. Catalog security deliberately refuses a
            // group-writable temp home, so give this test the private root it promises.
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        temp
    }

    #[tokio::test]
    async fn related_start_guard_is_held_until_capture_owner_drops() {
        let temp = private_test_home();
        let backend = crate::test_support::local_backend_builder(temp.path())
            .build()
            .await
            .unwrap();
        let mut rows = [record(1, "child"), record(2, "peer")];
        let root = backend.sandboxes_dir();
        let mut bindings = initialize(&root, &rows[0], false);
        rows[1].config.spec.image = RootfsSource::Bind {
            path: root.join("child"),
            follow_root_symlinks: false,
        };
        rows[1].stored_config = serde_json::to_string(&rows[1].config).unwrap();
        for row in &rows {
            save(&backend, row).await;
        }
        let existing = ipc::try_acquire_transition_guard(&backend.config().run_dir(), "peer")
            .unwrap()
            .unwrap();
        let error = resolve(&backend, &rows[0].config, 1, &mut bindings)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("related writer 'peer'"));
        drop(existing);
        let guards = resolve(&backend, &rows[0].config, 1, &mut bindings)
            .await
            .unwrap();
        assert!(
            ipc::try_acquire_transition_guard(&backend.config().run_dir(), "peer")
                .unwrap()
                .is_none()
        );
        assert!(
            ipc::try_acquire_snapshot_lineage_guard(&backend.config().run_dir(), "peer")
                .unwrap()
                .is_none()
        );
        drop(guards);
        assert!(
            ipc::try_acquire_transition_guard(&backend.config().run_dir(), "peer")
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn live_legacy_pid_refuses_even_when_catalog_says_stopped() {
        let temp = private_test_home();
        let backend = crate::test_support::local_backend_builder(temp.path())
            .build()
            .await
            .unwrap();
        let rows = [record(1, "child"), record(2, "peer")];
        let root = backend.sandboxes_dir();
        let mut bindings = initialize(&root, &rows[0], true);
        initialize(&root, &rows[1], true);
        share_base(&root, "child", "peer");
        for row in &rows {
            save(&backend, row).await;
        }
        backend
            .db()
            .await
            .unwrap()
            .write()
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO run(sandbox_id,pid,status) VALUES(2,?,'Running')",
                [(std::process::id() as i32).into()],
            ))
            .await
            .unwrap();
        let error = resolve(&backend, &rows[0].config, 1, &mut bindings)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("'peer'"), "{error}");
        assert!(!root.join("child/state-layout.json").exists());
        assert!(!root.join("child/.storage-migration").exists());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_excludes_an_unclassified_owner_even_without_a_visible_alias() {
        let temp = private_test_home();
        let backend = crate::test_support::local_backend_builder(temp.path())
            .build()
            .await
            .unwrap();
        let rows = [record(1, "child"), record(2, "legacy")];
        let root = backend.sandboxes_dir();
        let mut bindings = initialize(&root, &rows[0], false);
        fs::create_dir_all(root.join("legacy/runtime")).unwrap();
        let alias = root.join("legacy/runtime/retained.raw");
        fs::hard_link(root.join("child/upper.ext4"), &alias).unwrap();
        let writer = fs::OpenOptions::new().write(true).open(&alias).unwrap();
        fs::remove_file(alias).unwrap();
        for row in &rows {
            save(&backend, row).await;
        }
        backend
            .db()
            .await
            .unwrap()
            .write()
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO run(sandbox_id,pid,status) VALUES(2,?,'Terminated')",
                [(std::process::id() as i32).into()],
            ))
            .await
            .unwrap();

        let error = resolve(&backend, &rows[0].config, 1, &mut bindings)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.contains("macOS") && error.contains("'legacy'"),
            "{error}"
        );
        assert!(!root.join("child/.storage-migration").exists());
        assert!(!root.join("child/state-layout.json").exists());

        drop(writer);
        backend
            .db()
            .await
            .unwrap()
            .write()
            .execute_unprepared("UPDATE run SET pid=NULL WHERE sandbox_id=2")
            .await
            .unwrap();
        let guards = resolve(&backend, &rows[0].config, 1, &mut bindings)
            .await
            .unwrap();
        assert!(
            ipc::try_acquire_transition_guard(&backend.config().run_dir(), "legacy")
                .unwrap()
                .is_none()
        );
        drop(guards);
        assert!(
            ipc::try_acquire_transition_guard(&backend.config().run_dir(), "legacy")
                .unwrap()
                .is_some()
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_leaves_an_unrelated_protected_runtime_unlocked_and_running() {
        let temp = private_test_home();
        let backend = crate::test_support::local_backend_builder(temp.path())
            .build()
            .await
            .unwrap();
        let rows = [record(1, "child"), record(2, "protected")];
        let root = backend.sandboxes_dir();
        let mut bindings = initialize(&root, &rows[0], false);
        fs::create_dir_all(root.join("protected/runtime")).unwrap();
        microsandbox_runtime::checkpoint::layout::initialize_new(&root.join("protected/runtime"))
            .unwrap();
        for row in &rows {
            save(&backend, row).await;
        }
        backend
            .db()
            .await
            .unwrap()
            .write()
            .execute_unprepared("UPDATE sandbox SET status='Running' WHERE id=2")
            .await
            .unwrap();
        backend
            .db()
            .await
            .unwrap()
            .write()
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO run(sandbox_id,pid,status) VALUES(2,?,'Running')",
                [(std::process::id() as i32).into()],
            ))
            .await
            .unwrap();
        let own = ipc::try_acquire_transition_guard(&backend.config().run_dir(), "protected")
            .unwrap()
            .unwrap();
        let lifecycle =
            SandboxLifecycleGuard::try_acquire(&backend.config().run_dir(), "protected")
                .unwrap()
                .unwrap();

        let guards = resolve(&backend, &rows[0].config, 1, &mut bindings)
            .await
            .unwrap();
        assert!(bindings.aliases.is_empty());
        assert!(microsandbox_utils::process::pid_exists(
            std::process::id() as i32
        ));
        let row = backend
            .db()
            .await
            .unwrap()
            .read()
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT status FROM sandbox WHERE id=2",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get::<String>("", "status").unwrap(), "Running");
        drop((guards, own, lifecycle));
    }
}
