//! Local sandbox create flow: image pull, rootfs preparation, record
//! insertion, and process spawn, as [`LocalContext`] inherent methods.
//!
//! [`LocalContext::create_sandbox`] is the single entry point; the trait
//! impl's `create`/`create_detached` and the pull-progress shims on
//! [`Sandbox`] and `SandboxBuilder` all dispatch here.
//!
//! # OCI image protection
//!
//! File leases and saved database ownership overlap; there must be no unprotected handoff:
//!
//! 1. The creator retains shared leases on cached image files while resolving and preparing them.
//! 2. The `Starting` sandbox row and its image dependency commit in one transaction, before
//!    the runtime is spawned. The creator still holds its leases during this commit.
//! 3. Creation releases its operation leases when it finishes. The saved image dependency
//!    continues to protect the backing files, including while the sandbox is stopped.
//!
//! Each concurrent creator retains its own leases. One creator finishing cannot release
//! another's protection, even when readers within one process share an underlying file handle.
//! OS file locks coordinate separate processes; prune skips leased files and rechecks saved
//! dependencies before deletion. Database ownership is a durable record, not a database lock
//! held for the sandbox's lifetime. The runtime need not retain these creation-time leases.
//!
//! # Crashes and cancellation
//!
//! Before the ownership transaction commits, no runtime has started; the transaction either
//! commits or rolls back atomically. After commit, a creator or runtime panic, cancellation,
//! or process exit does not by itself remove the saved image dependency. Releasing file
//! leases therefore does not expose the backing to prune. Interrupted creation can leave
//! a stale record retaining unused files until normal sandbox cleanup removes the dependency.

mod cleanup;
mod disk_editor;
mod replacement;
mod restore;
mod root_growth;

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use microsandbox_db::DbWriteConnection;
use microsandbox_db::pool::DbPools;
use microsandbox_image::snapshot::SnapshotRootDisk;
use microsandbox_image::{
    CachedImageMetadata, Digest, GlobalCache, PullOptions, PullProgress, PullProgressSender,
    PullResult, Reference, Registry, RootfsMaterialization, ext4, tree,
};
use microsandbox_runtime::ipc::SandboxSocketPaths;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait, QueryFilter, Set, Statement,
    sea_query::Expr,
};
use tokio::sync::Mutex;

use super::LocalContext;
use crate::agent::AgentClient;
use crate::config::RegistryOptions;
use crate::context::Context;
use crate::context::local::creation::{self, CreationStorage};
use crate::context::local::sandbox::create::restore::RestoreStaging;
use crate::context::local::volume::EnsuredNamedVolumes;
use crate::db::entity::{
    run as run_entity, sandbox as sandbox_entity, sandbox_label as sandbox_label_entity,
    sandbox_rootfs as sandbox_rootfs_entity,
};
use crate::runtime::handle::StartupProcess;
use crate::runtime::launch_contract;
use crate::runtime::protected_state::StoragePreparation;
use crate::runtime::{ProcessHandle, SpawnMode};
use crate::sandbox::{
    FsEntryKind, FsMetadata, PullPolicy, RootDisk, RootfsSource, Sandbox, SandboxBuilder,
    SandboxConfig, SandboxFsOps, SandboxStatus, apply_patches, build_flat_tree, build_upper_tree,
    config::SnapshotRestoreMode, remove_dir_if_exists, validate_env, validate_hostname,
    validate_labels, validate_sandbox_name, validate_volume_mounts,
};
use crate::timing::{self, TARGET};
use crate::{MicrosandboxError, MicrosandboxResult, WorkdirProblem};
use cleanup::CreationCleanup;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum time to wait for the sandbox process to expose the agent relay.
const AGENT_RELAY_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// OCI materialization selected for a create request.
///
/// Carry the admitted metadata through catalog publication even if the tag moves.
struct ResolvedOciImage {
    cache_operation: GlobalCache,
    pull_result: PullResult,
    metadata_reference: String,
    metadata: CachedImageMetadata,
}

/// Only the OCI architecture is needed to check historical disk launches.
#[derive(serde::Deserialize)]
struct ImagePlatform<'a> {
    architecture: Option<&'a str>,
}

/// Short-lived ownership of one sandbox name while persisted state or host resources change.
///
/// The file handle owns a process-held lock. Closing it releases the lock on both Unix and
/// Windows, including when a lifecycle caller exits unexpectedly.
pub(crate) struct SandboxTransitionGuard {
    _file: File,
}

//--------------------------------------------------------------------------------------------------
// Methods: Create Flow
//--------------------------------------------------------------------------------------------------

impl LocalContext {
    /// Local create path. Returns a complete [`Sandbox`] wrapping the supplied
    /// backend Arc.
    ///
    /// `backend` must be the `Arc<dyn Context>` wrapping `self`: the trait
    /// impl and the pull-progress shims forward the Arc they were handed so
    /// the returned [`Sandbox`] routes follow-up calls through this same
    /// backend.
    #[tracing::instrument(target = TARGET, level = "trace", name = "sandbox_local_create", skip_all, fields(sandbox_name))]
    pub(crate) async fn create_sandbox(
        &self,
        backend: Arc<dyn Context>,
        input: impl Into<SandboxBuilder>,
        mode: SpawnMode,
        progress: Option<PullProgressSender>,
    ) -> MicrosandboxResult<Sandbox> {
        let mut attempt = None;
        let result = Box::pin(self.create_with_replacement(
            backend,
            input.into(),
            mode,
            progress,
            &mut attempt,
        ))
        .await;
        let Some(attempt) = attempt else {
            return result;
        };
        let recovered = Box::pin(self.finish_replacement(&attempt)).await;
        match (result, recovered) {
            (Err(error), Ok(true)) => Err(MicrosandboxError::ReplacementStopped {
                name: attempt.name,
                original_id: attempt.original,
                source: Box::new(error),
            }),
            (Err(error), Err(recovery)) => Err(MicrosandboxError::ReplacementRecoveryPending {
                name: attempt.name,
                original_id: attempt.original,
                source: Box::new(error),
                recovery: Box::new(recovery),
            }),
            (Ok(sandbox), Err(error)) => {
                // The replacement has published. Reporting a launch failure here
                // would invite callers to repeat an already successful mutation.
                tracing::warn!(sandbox = %attempt.name, %error, "replacement published with original cleanup pending");
                Ok(sandbox)
            }
            (result, Ok(_)) => result,
        }
    }

    async fn create_with_replacement(
        &self,
        backend: Arc<dyn Context>,
        mut builder: SandboxBuilder,
        mode: SpawnMode,
        progress: Option<PullProgressSender>,
        attempt: &mut Option<replacement::Attempt>,
    ) -> MicrosandboxResult<Sandbox> {
        let options = builder.prepare(backend.clone()).await?;
        tracing::Span::current().record(
            "sandbox_name",
            options.spec.name.as_deref().unwrap_or_default(),
        );
        self.warn_cloud_only(
            options.spec.name.as_deref().unwrap_or_default(),
            options.slug.as_ref().and_then(Option::as_deref),
        );
        validate_sandbox_name(options.spec.name.as_deref().unwrap_or_default())?;

        let image = options.resolve_image(&self.inner.config);
        if matches!(&image, RootfsSource::Oci(oci) if !oci.reference.is_empty()) {
            Self::validate_rootfs_source(&image)?;
        }

        let restoring = options.snapshot_reference.is_some()
            || options.snapshot_archive_source.is_some()
            || options
                .snapshot_upper_source
                .as_ref()
                .and_then(Option::as_ref)
                .is_some()
            || options.checkpoint_restore.is_some()
            || options.branch_source.is_some()
            || options.snapshot_parent.is_some();
        let profile = self.resolve_deployment_profile(
            options.spec.name.as_deref().unwrap_or_default(),
            options.spec.deployment_profile.unwrap_or_default(),
        );
        let mut resolved_image = None;
        let mut image_operations = Vec::new();
        if !restoring && let RootfsSource::Oci(oci) = &image {
            let name = options.spec.name.as_deref().unwrap_or_default();
            if !options.replace_existing.unwrap_or_default() {
                Self::check_create_target(self.db().await?, name, &self.sandboxes_dir().join(name))
                    .await?;
            }
            let materialization = if matches!(oci.root_disk, Some(RootDisk::Flat { .. })) {
                RootfsMaterialization::Flat
            } else {
                RootfsMaterialization::Layered
            };
            let registry = RegistryOptions {
                auth: options
                    .registry_auth
                    .as_ref()
                    .and_then(Option::as_ref)
                    .cloned(),
                insecure: options.insecure.unwrap_or_default(),
                ca_certs: options.ca_certs.clone().unwrap_or_default(),
                ..Default::default()
            };
            resolved_image = Some(
                self.resolve_oci_image_for_create(
                    &oci.reference,
                    options.spec.pull_policy.unwrap_or_default(),
                    registry,
                    options.image_cache_dir.as_ref().and_then(Option::as_deref),
                    None,
                    false,
                    materialization,
                    progress.clone(),
                )
                .await?,
            );
        }
        builder = builder.deployment_profile(profile);
        let mut config = builder.finish_local(
            &self.inner.config,
            resolved_image
                .as_ref()
                .map(|image| crate::SandboxConfigPatch::from_image(&image.pull_result.config)),
        )?;
        config.apply_rootfs_defaults(&self.config().sandbox_defaults.oci)?;
        super::super::host_paths::resolve_host_paths(&mut config)?;

        let timing_name = config.spec.name.clone();
        tracing::debug!(
            sandbox = %config.spec.name,
            image = ?config.spec.image,
            mode = ?mode,
            cpus = config.spec.resources.cpus,
            memory_mib = config.spec.resources.memory_mib,
            "create_local: starting"
        );
        let mut pinned_manifest_digest: Option<String> = None;
        let mut pinned_reference: Option<String> = None;

        config.apply_runtime_defaults();
        validate_hostname(config.spec.runtime.hostname.as_deref())?;
        self.validate_sandbox_name_for_runtime(&config.spec.name)?;
        Self::validate_rootfs_source(&config.spec.image)?;
        validate_env(&config.spec.env)?;
        validate_labels(&config.spec.labels)?;
        validate_volume_mounts(&mut config.spec.mounts)?;
        if let Some(init) = &config.spec.init {
            crate::sandbox::init::validate(init)?;
        }

        // Fresh OCI creates already checked for conflicts before pulling. Snapshot
        // restores reach the catalog here, before staging or replacing a destination.
        let db = self.db().await?;
        // Runtime compatibility is independent of the upgraded catalog. Keep
        // unsupported requests from deleting a replace target before launch.
        launch_contract::validate_runtime_config(&config, self.config()).await?;
        let sandbox_dir = self.sandboxes_dir().join(&config.spec.name);
        // Installed sources and archives have separate materialization paths.
        let mut installed_checkpoint_restore = config.checkpoint_restore.take();
        let mut installed_file_sources = std::mem::take(&mut config.snapshot_root_layer_sources);
        let installed_file_virtual_size = config.snapshot_root_virtual_size.take();

        let branch_image = config.branch_source.is_some();
        let mut archive_bundled_image = config.snapshot_has_bundled_image
            || config
                .snapshot_prepared_sources
                .as_ref()
                .is_some_and(|prepared| prepared.bundled_image());
        let mut archive_stage = if let Some(archive) = config.snapshot_archive_source.clone() {
            let stage = RestoreStaging::reserve(backend.clone(), self, &config).await?;

            let admitted = async {
                let materialized = Box::pin(self.materialize_archive_for_child(
                    &archive,
                    &stage.storage,
                    config.snapshot_restore_mode == SnapshotRestoreMode::DiskOnly,
                    config.snapshot_base.as_deref(),
                    &config.restore_resources,
                    config.caller_config_overrides.as_deref(),
                    config.image_cache_dir.as_deref(),
                ))
                .await?;
                archive_bundled_image |= materialized.bundled_image;

                let admitted = config
                    .restore_resources
                    .archive_manifest
                    .as_ref()
                    .ok_or_else(|| {
                        MicrosandboxError::SnapshotIntegrity(
                            "archive metadata was not admitted".into(),
                        )
                    })?;

                if admitted.digest()? != materialized.manifest.digest()? {
                    return Err(MicrosandboxError::SnapshotIntegrity(
                        "snapshot archive changed after configuration was built".into(),
                    ));
                }

                image_operations.push(self.apply_materialized_archive(
                    &mut config,
                    stage.path(),
                    materialized,
                )?);

                validate_volume_mounts(&mut config.spec.mounts)?;
                // Extracted checkpoint paths may introduce additional runtime requirements.
                launch_contract::validate_runtime_config(&config, self.config()).await?;

                config.snapshot_archive_source = None;
                config.snapshot_base = None;

                Ok::<_, MicrosandboxError>(())
            }
            .await;

            if let Err(error) = admitted {
                return Err(match stage.discard(self).await {
                    Ok(()) => error,
                    Err(cleanup) => MicrosandboxError::Runtime(format!("{error}; {cleanup}")),
                });
            }

            Some(stage)
        } else {
            None
        };

        let direct_flat = matches!(
            config.spec.image.oci_root_disk(),
            Some(RootDisk::Flat { .. })
        ) && config.branch_source.is_none()
            && config.checkpoint_restore.is_none()
            && (config.snapshot_upper_source.is_some()
                || !config.snapshot_upper_layers.is_empty()
                || !installed_file_sources.is_empty());
        let edit_child =
            (config.snapshot_disk_edits || direct_flat) && !config.spec.patches.is_empty();
        if config.snapshot_root_growth_mib.is_some() || edit_child {
            // The complete disk/filesystem rewrite must succeed before replacement can
            // stop the old sandbox. The worker owns staging and source leases through
            // caller cancellation; publication later moves the directory without copying.
            let stage = match archive_stage.take() {
                Some(stage) => stage,
                None => RestoreStaging::reserve(backend.clone(), self, &config).await?,
            };
            let storage = stage.storage.clone();
            let prepared = root_growth::prepare_owned(
                config,
                std::mem::take(&mut installed_file_sources),
                installed_file_virtual_size,
                installed_checkpoint_restore.take(),
                stage,
                storage,
                self.config().fs_state_limit(),
            )
            .await?;
            config = prepared.0;
            archive_stage = Some(prepared.1);
        }

        let _prepared_snapshot_sources = config.snapshot_prepared_sources.take();

        // Resolve the captured base while the old destination is still intact. In particular,
        // an offline cache miss must not stop/delete a sandbox before returning an error.
        // Keep the image's cache lease through the existing materialization/publication path.
        // Branch capture resolves its source later, so leave that path's ordering unchanged.
        let has_snapshot_image = config.snapshot_upper_source.is_some()
            || config.checkpoint_restore.is_some()
            || !config.snapshot_upper_layers.is_empty()
            || installed_checkpoint_restore.is_some()
            || !installed_file_sources.is_empty();
        if resolved_image.is_none()
            && has_snapshot_image
            && config.branch_source.is_none()
            && let RootfsSource::Oci(oci) = &config.spec.image
        {
            // Preserve option admission ahead of image/cache effects. Direct resolved
            // snapshot inputs can bypass the public builder's reference-based check.
            if !edit_child && !config.spec.patches.is_empty() {
                let source = if config.snapshot_upper_source.is_some() {
                    "from_snapshot"
                } else {
                    "full snapshot restore"
                };
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "patches cannot be combined with {source}"
                )));
            }
            let materialization = if matches!(oci.root_disk, Some(RootDisk::Flat { .. })) {
                RootfsMaterialization::Flat
            } else {
                RootfsMaterialization::Layered
            };
            let registry = RegistryOptions {
                auth: config.registry_auth.clone(),
                insecure: config.insecure,
                ca_certs: config.ca_certs.clone(),
                ..Default::default()
            };
            let image = timing::measure(
                &timing_name,
                "image_resolution",
                self.resolve_oci_image_for_create(
                    &oci.reference,
                    config.spec.pull_policy,
                    registry,
                    config.image_cache_dir.as_deref(),
                    config.manifest_digest.as_deref(),
                    archive_bundled_image,
                    materialization,
                    progress.clone(),
                ),
            )
            .await?;
            validate_snapshot_image_architecture(&image.metadata.raw_config_json)?;
            resolved_image = Some(image);
        }

        if edit_child {
            let runtime = crate::setup::resolve_runtime(self.config())?;
            let image = resolved_image.take().ok_or_else(|| {
                MicrosandboxError::InvalidConfig(
                    "snapshot edits require the captured OCI root".into(),
                )
            })?;
            let stage = archive_stage
                .take()
                .expect("child preparation reserved staging");
            let (prepared, edited_stage, image) = disk_editor::apply(
                config,
                stage,
                runtime.msb_path,
                runtime.libkrunfw_path,
                image,
                self.patch_staging().clone(),
            )
            .await?;
            config = prepared;
            archive_stage = Some(edited_stage);
            resolved_image = Some(image);
        }

        // Transition ownership is deliberately separate from the runtime lifecycle lock: this
        // guard serializes database/storage mutation and launcher-to-runtime handoff, while the
        // lifecycle lock remains owned by the VM for its entire runtime generation.
        let _transition_guard = timing::measure(
            &timing_name,
            "transition_lock",
            Self::acquire_sandbox_transition_guard(&self.config().run_dir(), &config.spec.name),
        )
        .await?;
        Box::pin(self.recover_replacement(&config.spec.name, None)).await?;
        if config.replace_existing {
            self.remove_interrupted_create_for_replacement(db, &config)
                .await?;
        }

        let preparation = CreationStorage::acquire(self, &config.spec.name)?;
        Self::prepare_create_target(
            db,
            &config,
            &sandbox_dir,
            &self.config().run_dir(),
            Some(self),
            attempt,
        )
        .await?;
        // Hold the existing lifecycle lock across reservation, capture and spawn. Recheck
        // under the lock so two creates cannot both own the same child staging directory.
        let lifecycle_guard = crate::runtime::acquire_sandbox_lifecycle_guard(
            &self.config().run_dir(),
            &config.spec.name,
            std::time::Duration::from_secs(5),
        )
        .await?;
        Self::check_create_target(db, &config.spec.name, &sandbox_dir).await?;

        // Persist ownership before any deterministic sandbox path is created. An interrupted
        // insert can leave a row, but never untracked storage.
        let mut reserved_config = config.clone_for_persistence();
        // Persistence strips the captured agent advertisement. Carry its selected policy
        // to the reservation transaction separately from the legacy configuration JSON.
        reserved_config.restored_exec_limits = config.retained_exec_limits();
        let reserved_config_json = serde_json::to_string(&reserved_config)?;
        let sandbox_id = Self::insert_with_replacement(
            db.write(),
            &reserved_config,
            SandboxStatus::Starting,
            true,
            attempt.as_ref().and_then(|a| a.token.as_deref()),
        )
        .await?;

        // Preparation errors are handled only after awaited filesystem work has finished.
        let prepared = {
            let preparation = &preparation;
            Box::pin(async {
                if let Some(stage) = archive_stage {
                    relocate_archive_config(&mut config, stage.path(), &sandbox_dir);
                    let destination = sandbox_dir.clone();
                    let destination = preparation.at(destination);
                    let source = stage.storage.clone();
                    tokio::task::spawn_blocking(move || {
                        std::fs::rename(source.path(), destination.path())
                    })
                    .await
                    .map_err(|error| MicrosandboxError::Runtime(error.to_string()))??;
                    stage.discard(self).await?;
                }

                let _branch_pin = if let Some(source) = config.branch_source.take() {
                    let directory = sandbox_dir.clone();
                    let worker_storage = preparation.clone();
                    tokio::task::spawn_blocking(move || {
                        let _storage = worker_storage;
                        std::fs::create_dir(directory)
                    })
                    .await
                    .map_err(|error| MicrosandboxError::Runtime(error.to_string()))??;

                    let pin = crate::sandbox::branch::capture_child(
                        self,
                        &mut config,
                        &source,
                        preparation,
                        sandbox_id,
                    )
                    .await?;

                    // Capture resolves automatic nesting to its actual execution mode. Recheck
                    // managed policy before publishing or launching the child, as for archives.
                    config = SandboxBuilder::from(config.clone())
                        .finish(Some(&self.inner.config), None)?;
                    launch_contract::validate_runtime_config(&config, self.config()).await?;

                    Some(pin)
                } else {
                    None
                };

                // Installed full snapshots likewise become child-owned before image resolution. The
                // closure is retained only through eager construction; the disk layers and fresh writable
                // head remain under the ordinary sandbox directory and root-disk journal.
                if let Some(source) = installed_checkpoint_restore {
                    let root_layout = snapshot_root_layout_from_config(&config)?;
                    match config.snapshot_restore_mode {
                        SnapshotRestoreMode::Full => {
                            let materialized = crate::snapshot::materialize_checkpoint_for_child(
                                &source,
                                preparation,
                                &root_layout,
                                &config.restore_resources,
                                self.config().fs_state_limit(),
                            )
                            .await?;
                            #[cfg(feature = "net")]
                            {
                                let tls = config.spec.network.tls.as_ref();
                                // An explicit destination signer takes precedence and the
                                // runtime checks it against the captured proxy fingerprint.
                                if tls.is_none_or(|t| t.enabled && t.intercept_ca.cert_path.is_none()
                                    && t.intercept_ca.key_path.is_none())
                                {
                                    let expected = microsandbox_image::checkpoint::ObjectId::new(&source.checkpoint_root)
                                        .map_err(|e| MicrosandboxError::SnapshotIntegrity(e.to_string()))?;
                                    let checkpoint = microsandbox_image::checkpoint::CheckpointClosure::inspect_manifest(
                                        &source.closure, Some(&expected),
                                    ).map_err(|e| MicrosandboxError::SnapshotIntegrity(e.to_string()))?;
                                    let artifact = source.closure.parent().ok_or_else(|| MicrosandboxError::SnapshotIntegrity("checkpoint has no artifact directory".into()))?;
                                    if let Some(ca) = microsandbox_runtime::checkpoint::tls_receipt::restore(
                                        &self.config().home(), sandbox_id, artifact, &checkpoint.resources, &source.checkpoint_root,
                                    ).map_err(MicrosandboxError::Runtime)? {
                                        let tls = config.spec.network.tls.get_or_insert_with(Default::default);
                                        tls.enabled = true;
                                        tls.intercept_ca = ca;
                                    }
                                }
                            }
                            config.checkpoint_restore = Some(materialized.restore);
                            crate::snapshot::apply_additional_disks(
                                &mut config,
                                materialized.disk_mounts,
                            );
                            config.snapshot_upper_layers = materialized.upper_layers;
                            config.suppress_launch_for_full_restore();
                        }
                        SnapshotRestoreMode::DiskOnly => {
                            let materialized =
                                crate::snapshot::materialize_checkpoint_disk_for_child(
                                    &source.closure,
                                    &source.checkpoint_root,
                                    &source.checkpoint_id,
                                    preparation,
                                    &root_layout,
                                    &config.restore_resources,
                                    self.config().fs_state_limit(),
                                )
                                .await?;
                            crate::snapshot::apply_additional_disks(
                                &mut config,
                                materialized.disk_mounts,
                            );
                            config.snapshot_upper_layers = materialized.upper_layers;
                        }
                    }
                }
                crate::sandbox::resolve_external_mounts(self, &mut config).await?;
                // Resource inheritance may add legacy relative bindings after initial admission.
                // This is a new child: pin its launch inputs without rewriting the saved source.
                super::super::host_paths::resolve_host_paths(&mut config)?;
                // After external-mount admission, so a relaxed restore can still mark a vanished
                // mount unavailable, and before the sandbox row is inserted. Earlier work (image
                // pull, archive decode, child materialization, a `--replace` deletion) has already
                // happened, as with the runtime's own boot-time failure. Older runtimes follow
                // root symlinks, so only a runtime that refuses them is checked.
                let enforce = match crate::setup::resolve_runtime(self.config()) {
                    Ok(runtime) => launch_contract::resolve(&runtime.msb_path)
                        .await?
                        .refuses_symlinked_bind_roots(),
                    Err(MicrosandboxError::RuntimeNotInstalled(_)) => true,
                    Err(error) => return Err(error),
                };
                if enforce {
                    super::super::host_paths::check_bind_roots_do_not_follow_symlinks(&config)?;
                }

                if !installed_file_sources.is_empty() {
                    let virtual_size = installed_file_virtual_size.ok_or_else(|| {
                        MicrosandboxError::SnapshotIntegrity(
                            "file snapshot is missing its root-disk capacity".into(),
                        )
                    })?;
                    let root_layout = snapshot_root_layout_from_config(&config)?;
                    let materialized = crate::snapshot::materialize_file_snapshot_for_child(
                        &installed_file_sources,
                        virtual_size,
                        preparation,
                        &root_layout,
                    )
                    .await?;
                    config.snapshot_upper_layers = materialized.upper_layers;
                }
                if let Some((source, owned)) = config.snapshot_owned_source.take() {
                    let mounts = crate::snapshot::materialize_owned_volumes(
                        &owned,
                        &source,
                        preparation,
                        &config.restore_resources,
                    )
                    .await?;
                    crate::snapshot::apply_additional_disks(&mut config, mounts);
                }
                // All source payloads are now child-owned; runtime handles must not retain the source.
                config.snapshot_lease = None;

                // Resolve OCI images before spawning the sandbox process.
                if let RootfsSource::Oci(oci) = config.spec.image.clone() {
                    let reference = oci.reference;
                    let expected_snapshot_manifest_digest =
                        (branch_image
                            || config.snapshot_upper_source.is_some()
                            || config.checkpoint_restore.is_some()
                            || !config.snapshot_upper_layers.is_empty())
                        .then(|| config.manifest_digest.clone())
                        .flatten();
                    let root_disk = oci
                        .root_disk
                        .clone()
                        .unwrap_or(RootDisk::Managed { size_mib: None });
                    // Reject incompatible snapshot + patch combinations before image resolution and
                    // before the sandbox directory exists. A rejected run must leave no on-disk state,
                    // because the leftover directory blocks retries under the same name (see #1550).
                    // Flat roots bake patches into a private tree and are compatible with both paths.
                    if !config.spec.patches.is_empty()
                        && !matches!(root_disk, RootDisk::Flat { .. })
                    {
                        if config.snapshot_upper_source.is_some() {
                            return Err(MicrosandboxError::InvalidConfig(
                                "patches cannot be combined with from_snapshot".into(),
                            ));
                        }
                        if !config.snapshot_upper_layers.is_empty() {
                            return Err(MicrosandboxError::InvalidConfig(
                                "patches cannot be combined with full snapshot restore".into(),
                            ));
                        }
                    }
                    let image_materialization = if matches!(root_disk, RootDisk::Flat { .. }) {
                        RootfsMaterialization::Flat
                    } else {
                        RootfsMaterialization::Layered
                    };
                    let overrides = RegistryOptions {
                        auth: config.registry_auth.clone(),
                        insecure: config.insecure,
                        ca_certs: config.ca_certs.clone(),
                        ..Default::default()
                    };
                    let ResolvedOciImage {
                        cache_operation,
                        pull_result,
                        metadata_reference,
                        metadata,
                    } = if let Some(image) = resolved_image.take() {
                        image
                    } else {
                        timing::measure(
                            &timing_name,
                            "image_resolution",
                            self.resolve_oci_image_for_create(
                                &reference,
                                if branch_image && config.spec.pull_policy == PullPolicy::Always {
                                    PullPolicy::IfMissing
                                } else {
                                    config.spec.pull_policy
                                },
                                overrides,
                                config.image_cache_dir.as_deref(),
                                expected_snapshot_manifest_digest.as_deref(),
                                archive_bundled_image || branch_image,
                                image_materialization,
                                progress,
                            ),
                        )
                        .await?
                    };

                    // Retain file ownership through insertion of the sandbox/rootfs catalog rows.
                    let cache = cache_operation.clone();
                    image_operations.push(cache_operation);
                    let using_default_cache =
                        self.is_default_image_cache_dir(config.image_cache_dir.as_deref());
                    tracing::trace!(
                        target: timing::TARGET,
                        sandbox_name = %timing_name,
                        layers_cached = pull_result.cached,
                        layer_count = pull_result.layer_diff_ids.len(),
                        materialization = ?image_materialization,
                        "sandbox image resolved"
                    );

                    // Snapshot overlays are meaningful only against the exact base
                    // image digest captured in their descriptor.
                    if let Some(expected) = expected_snapshot_manifest_digest.as_deref()
                        && pull_result.manifest_digest.to_string() != expected
                    {
                        return Err(MicrosandboxError::SnapshotIntegrity(format!(
                            "snapshot image digest mismatch: manifest pinned {}, resolved {}",
                            expected, pull_result.manifest_digest
                        )));
                    }

                    // Merge image config defaults under user-provided config.
                    if restoring {
                        config.merge_image_defaults(&pull_result.config);
                    }
                    if let Some(init) = &config.spec.init {
                        crate::sandbox::init::validate(init)?;
                    }

                    if using_default_cache {
                        pinned_manifest_digest = Some(pull_result.manifest_digest.to_string());
                        pinned_reference = Some(metadata_reference.clone());
                    }

                    // Layered roots boot through the stitched VMDK descriptor. Flat
                    // roots intentionally skip both fsmeta and VMDK materialization,
                    // so requiring the descriptor here would make a cold SDK create
                    // fail after successfully publishing its flat ext4 artifact.
                    if image_materialization.includes_layered() {
                        let vmdk_path = cache.vmdk_path(&pull_result.manifest_digest);
                        if tokio::fs::metadata(&vmdk_path).await.is_err() {
                            return Err(MicrosandboxError::Custom(format!(
                                "VMDK not materialized: {}",
                                vmdk_path.display()
                            )));
                        }
                    }

                    // For patches, pass per-layer EROFS paths.
                    let layer_erofs_paths: Vec<std::path::PathBuf> = pull_result
                        .layer_diff_ids
                        .iter()
                        .map(|d| cache.layer_erofs_path(d))
                        .collect();

                    let flat_spec = match &root_disk {
                        RootDisk::Flat {
                            size_mib,
                            clone,
                            fstype,
                        } => {
                            if fstype.as_deref().unwrap_or("ext4") != "ext4" {
                                return Err(MicrosandboxError::InvalidConfig(format!(
                                    "flat root disks currently require fstype=ext4, got {}",
                                    fstype.as_deref().unwrap_or_default()
                                )));
                            }
                            if config.snapshot_upper_source.is_some()
                                || !config.snapshot_upper_layers.is_empty()
                                || !config.spec.patches.is_empty()
                            {
                                None
                            } else {
                                let flat_ref = cache
                                    .read_flat_ref(&pull_result.manifest_digest)?
                                    .ok_or_else(|| {
                                    MicrosandboxError::Custom(
                                        "flat rootfs was not published by the image pull".into(),
                                    )
                                })?;
                                let artifact_digest: Digest =
                                    flat_ref.artifact_digest.parse().map_err(|e| {
                                        MicrosandboxError::Custom(format!(
                                            "invalid flat rootfs artifact digest in cache: {e}"
                                        ))
                                    })?;
                                let minimum_mib = flat_ref.virtual_size_bytes.div_ceil(1024 * 1024);
                                let requested_mib = size_mib.map(u64::from).unwrap_or(u64::from(
                                    crate::sandbox::config::DEFAULT_OCI_UPPER_SIZE_MIB,
                                ));
                                let target_mib = size_mib
                                    .map(|_| requested_mib)
                                    .unwrap_or_else(|| requested_mib.max(minimum_mib));
                                let target_mib = u32::try_from(target_mib).map_err(|_| {
                                    MicrosandboxError::InvalidConfig(
                                        "flat root disk size exceeds supported MiB range".into(),
                                    )
                                })?;
                                Some((cache.flat_blob_path(&artifact_digest), target_mib, *clone))
                            }
                        }
                        _ => None,
                    };

                    // Flat patches modify a complete private tree. Managed patches remain a compact
                    // OverlayFS upper and therefore retain their existing fast path.
                    let directory = sandbox_dir.clone();
                    let worker_storage = preparation.clone();
                    tokio::task::spawn_blocking(move || {
                        let _storage = worker_storage;
                        std::fs::create_dir_all(directory)
                    })
                    .await
                    .map_err(|error| MicrosandboxError::Runtime(error.to_string()))??;

                    let flat_patch_spool = sandbox_dir.join(".flat-patch.spool");
                    let flat_tree = if !config.spec.patches.is_empty()
                        && matches!(root_disk, RootDisk::Flat { .. })
                    {
                        match timing::measure(
                            &timing_name,
                            "patch_tree",
                            build_flat_tree(
                                &config.spec.patches,
                                &layer_erofs_paths,
                                &preparation.at(&flat_patch_spool),
                                self.patch_staging(),
                            ),
                        )
                        .await
                        {
                            Ok(tree) => Some(tree),
                            Err(error) => {
                                let spool = flat_patch_spool.clone();
                                let worker_storage = preparation.clone();
                                let _ = tokio::task::spawn_blocking(move || {
                                    let _storage = worker_storage;
                                    std::fs::remove_file(spool)
                                })
                                .await;
                                return Err(error);
                            }
                        }
                    } else {
                        None
                    };
                    let upper_tree = if !config.spec.patches.is_empty()
                        && !matches!(root_disk, RootDisk::Flat { .. })
                    {
                        Some(
                            timing::measure(
                                &timing_name,
                                "patch_tree",
                                build_upper_tree(
                                    &config.spec.patches,
                                    &layer_erofs_paths,
                                    self.patch_staging(),
                                ),
                            )
                            .await?,
                        )
                    } else {
                        None
                    };

                    // Ensure sandbox storage exists before provisioning either a private flat rootfs or
                    // the writable overlay upper image.
                    let upper_path = sandbox_dir.join("upper.ext4");
                    let writable_disk_path = if matches!(root_disk, RootDisk::Flat { .. }) {
                        sandbox_dir.join(crate::sandbox::flat_rootfs::FLAT_ROOTFS_FILENAME)
                    } else {
                        upper_path.clone()
                    };
                    if let Some(flat_tree) = flat_tree {
                        let requested_mib = match &root_disk {
                            RootDisk::Flat { size_mib, .. } => *size_mib,
                            _ => unreachable!("flat patch tree requires a flat root"),
                        };
                        let materialized = crate::sandbox::flat_rootfs::create_patched_flat_rootfs(
                            &preparation.at(writable_disk_path.clone()),
                            flat_tree,
                            requested_mib,
                        )
                        .await;

                        let spool = flat_patch_spool.clone();
                        let worker_storage = preparation.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            let _storage = worker_storage;
                            std::fs::remove_file(spool)
                        })
                        .await;

                        let target_mib = materialized?;
                        if let RootfsSource::Oci(oci) = &mut config.spec.image
                            && let Some(RootDisk::Flat { size_mib, .. }) = &mut oci.root_disk
                        {
                            *size_mib = Some(target_mib);
                        }
                    } else if let Some((base, target_mib, clone)) = flat_spec {
                        timing::measure(
                            &timing_name,
                            "flat_root_clone",
                            crate::sandbox::flat_rootfs::create_private_flat_rootfs(
                                base,
                                &preparation.at(sandbox_dir
                                    .join(crate::sandbox::flat_rootfs::FLAT_ROOTFS_FILENAME)),
                                target_mib,
                                clone,
                            ),
                        )
                        .await?;
                        if let RootfsSource::Oci(oci) = &mut config.spec.image
                            && let Some(RootDisk::Flat { size_mib, .. }) = &mut oci.root_disk
                        {
                            *size_mib = Some(target_mib);
                        }
                    } else if !config.snapshot_upper_layers.is_empty() {
                        // Restored upper layers are attached by the runtime, so there is no writable
                        // disk to provision here.
                    } else if let Some(snap_upper) = config.snapshot_upper_source.take() {
                        // Booting from a snapshot: copy the captured upper into
                        // place, preserving sparseness. Patches are not
                        // compatible with this path because they'd need to be
                        // re-baked into the snapshot's upper, which we don't do.
                        // That combination is rejected before this directory exists.
                        if snap_upper != writable_disk_path {
                            let dst = writable_disk_path.clone();
                            {
                                let worker_storage = preparation.clone();
                                tokio::task::spawn_blocking(move || {
                                    let _storage = worker_storage;

                                    microsandbox_utils::copy::fast_copy(&snap_upper, &dst)
                                })
                            }
                            .await
                            .map_err(|e| {
                                MicrosandboxError::Custom(format!("snapshot copy task: {e}"))
                            })??;
                        }
                    } else {
                        match &root_disk {
                            RootDisk::Managed { size_mib } => {
                                let upper_size_mib = size_mib
                                    .unwrap_or(crate::sandbox::config::DEFAULT_OCI_UPPER_SIZE_MIB);
                                if !upper_path.exists() || upper_tree.is_some() {
                                    timing::measure(
                                        &timing_name,
                                        "writable_disk_create",
                                        Self::create_upper_ext4(
                                            &preparation.at(&upper_path),
                                            upper_size_mib,
                                            upper_tree,
                                        ),
                                    )
                                    .await?;
                                }
                            }
                            // The builder rejects patches with tmpfs root disks and
                            // agentd creates the in-memory upper inside the guest.
                            RootDisk::Tmpfs { .. } => {}
                            RootDisk::DiskImage { path, .. } => {
                                if tokio::fs::metadata(path).await.is_err() {
                                    return Err(MicrosandboxError::InvalidConfig(format!(
                                        "root disk image not found: {}",
                                        path.display()
                                    )));
                                }
                            }
                            RootDisk::Flat { .. } => {
                                unreachable!(
                                    "flat root disks are provisioned before overlay handling"
                                )
                            }
                        }
                    }

                    // Store manifest digest for spawn to derive paths.
                    config.manifest_digest = Some(pull_result.manifest_digest.to_string());

                    if !using_default_cache {
                        // Retain the admitted digest across later retags for offline snapshots and forks.
                        let pinned = Self::digest_pinned_reference(&reference, &metadata.manifest_digest)?;
                        let pinned: Reference = pinned.parse().map_err(|error| {
                            MicrosandboxError::InvalidConfig(format!("invalid pinned reference: {error}"))
                        })?;
                        cache.install_image_metadata_if_compatible_async(
                            &pinned, serde_json::to_vec(&metadata)?,
                        ).await?;
                    } else {
                        // Persist snapshot restores under their immutable digest-pinned
                        // reference, even when the cache match came from an older tag.
                        // Releasing operation leases is safe only after durable ownership is recorded.
                        // A catalog failure must not produce a live sandbox with untracked image backing.
                        crate::image::Image::persist(self, &metadata_reference, metadata).await?;
                        Self::persist_oci_manifest_pin(
                            db.write(),
                            sandbox_id,
                            &pull_result.manifest_digest.to_string(),
                        )
                        .await?;
                    }
                }

                // Apply rootfs patches before VM start. OCI patches were baked into their managed upper or
                // complete private flat root above; this path handles bind roots only.
                if !config.spec.patches.is_empty()
                    && !matches!(config.spec.image, RootfsSource::Oci(_))
                {
                    apply_patches(
                        &config.spec.image,
                        &config.spec.patches,
                        self.patch_staging(),
                    )
                    .await?;
                }

                crate::runtime::owned_volumes::prepare(
                    preparation,
                    &config.spec.mounts,
                    config.snapshot_parent.is_some() || config.checkpoint_restore.is_some(),
                )
                .await?;

                // Track newly provisioned named volumes under the reserved sandbox so
                // interruption cannot leave their ownership ambiguous.
                let volumes = timing::measure(
                    &timing_name,
                    "named_volumes",
                    self.ensure_named_volumes(preparation, &config),
                )
                .await?;
                self.prepare_sandbox_launch(
                    &config,
                    preparation,
                    StoragePreparation::New {
                        catalog_id: sandbox_id,
                        expected_config: &reserved_config_json,
                    },
                )
                .await?;
                #[cfg(feature = "net")]
                if !restoring
                    && config.spec.network.enabled
                    && let Some(tls) = config.spec.network.tls.as_mut()
                    && tls.enabled
                    && tls.intercept_ca.cert_path.is_none()
                    && tls.intercept_ca.key_path.is_none()
                {
                    // Persist ordinary explicit CA paths so restarts (including
                    // previous compatible runtimes) reopen exactly this identity.
                    tls.intercept_ca = microsandbox_runtime::checkpoint::tls_identity::provision(
                        &self.config().home(),
                        sandbox_id,
                    )
                    .map_err(MicrosandboxError::Runtime)?;
                }
                Ok::<_, MicrosandboxError>((volumes, _branch_pin))
            })
            .await
        };

        drop(preparation);
        let (created_named_volumes, _branch_pin) = match prepared {
            Ok((volumes, pin)) => (Arc::new(volumes), pin),
            Err(error) => {
                // Both guards are still held and no runtime has been published. Retain the
                // recovery row if cleanup fails; otherwise remove it after all files are gone.
                if let Err(cleanup) = self
                    .remove_incomplete_sandbox(
                        sandbox_id,
                        &config.spec.name,
                        creation::RemovalMode::PreparationFailed,
                    )
                    .await
                {
                    return Err(MicrosandboxError::Runtime(format!("{error}; {cleanup}")));
                }
                return Err(error);
            }
        };

        // Restores must not receive an attached watchdog or Windows kill-on-close job.
        let mode = crate::sandbox::create_spawn_mode(&config, mode);
        let mut creation_cleanup = CreationCleanup::new(
            backend.clone(),
            config.spec.name.clone(),
            _transition_guard,
            created_named_volumes.clone(),
        );

        // Persist the fully prepared config before launch. The recovery row remains armed
        // until all create-time validation and publication have succeeded.
        let write_db = db.write();
        let mut persisted_config = config.clone_for_persistence();
        // Keep restore intent until activation succeeds so an interrupted restore cannot boot cold.
        persisted_config.checkpoint_restore = config.checkpoint_restore.clone();
        match timing::measure(
            &timing_name,
            "persist_start",
            self.prepare_reserved_sandbox(write_db, sandbox_id, &persisted_config),
        )
        .await
        {
            Ok(()) => {}
            Err(err) => {
                // A failed commit may have an uncertain catalog outcome. Staging
                // already belongs to cleanup's writer-side ownership recheck.
                drop(lifecycle_guard);
                return Err(creation_cleanup.finish_failure(err).await);
            }
        };
        tracing::debug!(sandbox_id, sandbox = %config.spec.name, "create_local: db record inserted");

        // Spawn the sandbox process and create the bridge. On failure, mark the sandbox
        // from Starting to Stopped so it cannot remain as a phantom boot.
        let restore_closure = config
            .checkpoint_restore
            .as_ref()
            .map(|restore| restore.closure.clone());
        // Keep the large launch future out of this outer future's inline storage.
        // Nested group restores can otherwise exhaust a default-sized thread stack
        // in debug builds. Poll it here so ownership and cancellation stay unchanged.
        let created =
            Box::pin(self.create_sandbox_inner(config, sandbox_id, mode, Some(lifecycle_guard)))
                .await;
        let (local_state, mut returned_config) = match created {
            Ok(pair) => pair,
            Err(e) => {
                self.rollback_failed_startup(
                    write_db,
                    sandbox_id,
                    &persisted_config.spec.name,
                    &created_named_volumes,
                )
                .await
                .map_err(|cleanup| MicrosandboxError::Runtime(format!("{e}; {cleanup}")))?;
                return Err(creation_cleanup.finish_failure(e).await);
            }
        };
        creation_cleanup.retain_process(local_state.handle.clone());
        returned_config.checkpoint_restore = None;
        #[cfg(target_os = "linux")]
        {
            returned_config.branch_memory = None;
        }
        returned_config.snapshot_upper_layers.clear();
        let mut sandbox = Sandbox::from_local(backend.clone(), local_state, returned_config);
        // Keep Starting through every create-time validation. Publication and retirement of
        // recovery ownership commit together only after the sandbox is ready to return.
        if let Err(err) = Self::update_sandbox_active_config(
            write_db,
            sandbox_id,
            &sandbox.prepared_runtime()?.config.clone_for_persistence(),
        )
        .await
        {
            let err = sandbox.creation_failure(err).await;
            return Err(creation_cleanup.finish_failure(err).await);
        }

        let validated = async {
            if let (Some(_reference), Some(manifest_digest)) = (
                pinned_reference.as_deref(),
                pinned_manifest_digest.as_deref(),
            ) {
                Self::persist_oci_manifest_pin(write_db, sandbox_id, manifest_digest).await?;
            }

            // Accept a workdir only after proving it is a directory in the ready guest.
            if let Some(workdir) = &sandbox.prepared_runtime()?.config.spec.runtime.workdir {
                check_workdir(
                    workdir,
                    SandboxFsOps::stat_prepared(&sandbox, workdir).await,
                )?;
            }
            Ok::<_, MicrosandboxError>(())
        }
        .await;
        if let Err(error) = validated {
            let error = sandbox.creation_failure(error).await;
            // A bounded termination attempt can expire before runtime ownership ends.
            // Keep the original failure, but never remove storage without the lifecycle lock.
            self.rollback_failed_startup(
                write_db,
                sandbox_id,
                sandbox.name(),
                &created_named_volumes,
            )
            .await
            .map_err(|cleanup| MicrosandboxError::Runtime(format!("{error}; {cleanup}")))?;
            return Err(creation_cleanup.finish_failure(error).await);
        }

        if let Some(closure) = restore_closure {
            // Do not lose the recovery discriminator if any preceding creation check failed.
            // RAM/device state has been consumed and the runtime owns its disk chain and pins.
            if let Err(error) = Self::complete_sandbox_restore(
                write_db,
                sandbox_id,
                &persisted_config,
                &sandbox.prepared_runtime()?.config,
            )
            .await
            {
                let error = sandbox.creation_failure(error).await;
                return Err(creation_cleanup.finish_failure(error).await);
            }
            if let Err(error) = remove_dir_if_exists(&closure) {
                tracing::warn!(error = %error, path = %closure.display(), "failed to remove consumed checkpoint closure");
            }
        }
        if matches!(mode, SpawnMode::Detached) {
            sandbox.finish_detached_creation().await?;
        }
        creation_cleanup.begin_publication();
        if let Err(error) = creation::complete(write_db, sandbox_id, SandboxStatus::Running).await {
            return Err(creation_cleanup.finish_failure(error).await);
        }
        creation_cleanup.disarm();
        Ok(sandbox)
    }

    /// Roll back a failed launch while the caller still owns the name transition.
    async fn rollback_failed_startup(
        &self,
        write_db: &DbWriteConnection,
        sandbox_id: i32,
        sandbox_name: &str,
        created_named_volumes: &EnsuredNamedVolumes,
    ) -> MicrosandboxResult<()> {
        // A timeout is not evidence of process exit. Keep the runtime ownership guard through
        // database reconciliation and volume rollback; no live owner may lose its storage.
        let Some(runtime_guard) = microsandbox_runtime::ipc::try_acquire_lifecycle_guard(
            &self.config().run_dir(),
            sandbox_name,
        )?
        else {
            return Err(MicrosandboxError::Runtime(format!(
                "startup cleanup pending: runtime still owns sandbox {sandbox_name:?}",
            )));
        };
        self.rollback_failed_startup_guarded(
            write_db,
            sandbox_id,
            created_named_volumes,
            &runtime_guard,
        )
        .await
    }

    async fn rollback_failed_startup_guarded(
        &self,
        write_db: &DbWriteConnection,
        sandbox_id: i32,
        created_named_volumes: &EnsuredNamedVolumes,
        _runtime_guard: &microsandbox_runtime::ipc::SandboxLifecycleGuard,
    ) -> MicrosandboxResult<()> {
        run_entity::Entity::update_many()
            .col_expr(
                run_entity::Column::Status,
                Expr::value(run_entity::RunStatus::Terminated),
            )
            .col_expr(
                run_entity::Column::TerminationReason,
                Expr::value(run_entity::TerminationReason::Failed),
            )
            .col_expr(
                run_entity::Column::TerminatedAt,
                Expr::value(chrono::Utc::now().naive_utc()),
            )
            .filter(run_entity::Column::SandboxId.eq(sandbox_id))
            .filter(run_entity::Column::Status.eq(run_entity::RunStatus::Running))
            .exec(write_db)
            .await?;
        if creation::pending(write_db, sandbox_id).await? {
            if creation::can_retain(write_db, sandbox_id).await? {
                creation::complete(write_db, sandbox_id, SandboxStatus::Stopped).await?;
            } else {
                let model = sandbox_entity::Entity::find_by_id(sandbox_id)
                    .one(write_db)
                    .await?
                    .ok_or_else(|| {
                        MicrosandboxError::Runtime(
                            "incomplete sandbox lost its catalog owner".into(),
                        )
                    })?;
                self.remove_incomplete_sandbox(
                    sandbox_id,
                    &model.name,
                    creation::RemovalMode::Creator,
                )
                .await?;
            }
            return Ok(());
        }

        if created_named_volumes.is_empty() {
            Self::compare_and_set_sandbox_status(
                write_db,
                sandbox_id,
                &[SandboxStatus::Starting, SandboxStatus::Running],
                SandboxStatus::Stopped,
            )
            .await?;
        } else {
            self.rollback_created_named_volumes(created_named_volumes)
                .await?;
            microsandbox_runtime::checkpoint::remove_sandbox_identity(
                &self.config().home(),
                sandbox_id,
            )
            .map_err(MicrosandboxError::Runtime)?;
            Self::delete_sandbox_record(write_db, sandbox_id).await?;
        }
        Ok(())
    }

    /// Finish construction and project captured targets without overwriting desired edits.
    async fn complete_sandbox_restore(
        db: &DbWriteConnection,
        sandbox_id: i32,
        construction: &SandboxConfig,
        restored: &SandboxConfig,
    ) -> MicrosandboxResult<()> {
        // Construction needs the original boot geometry, but future starts/modifications need
        // the captured requested sizes. Replace only values that still match construction:
        // a concurrent explicit desired edit must survive this readiness publication.
        db.transaction(|txn| async move {
            let before = microsandbox_db::catalog::sandbox_query(&txn)
                .await?
                .filter(sandbox_entity::Column::Id.eq(sandbox_id))
                .one(&txn)
                .await?;

            sandbox_entity::Entity::update_many()
                .col_expr(
                    sandbox_entity::Column::Config,
                    Expr::cust_with_values(
                        "json_set(json_remove(config, '$.checkpoint_restore'), \
                         '$.resources.cpus', CASE WHEN json_extract(config, '$.resources.cpus') = ? \
                         THEN ? ELSE json_extract(config, '$.resources.cpus') END, \
                         '$.resources.memory_mib', CASE WHEN json_extract(config, '$.resources.memory_mib') = ? \
                         THEN ? ELSE json_extract(config, '$.resources.memory_mib') END)",
                        [
                            u32::from(construction.spec.resources.cpus),
                            u32::from(restored.spec.resources.cpus),
                            construction.spec.resources.memory_mib,
                            restored.spec.resources.memory_mib,
                        ],
                    ),
                )
                .filter(sandbox_entity::Column::Id.eq(sandbox_id))
                .exec(&txn)
                .await?;

            if let Some(before) = before
                && microsandbox_db::catalog::has_column(&txn, "sandbox", "caller_config_overrides").await?
            {
                let intent = SandboxConfig::from_stored(&before.config, before.caller_config_overrides.as_deref())?;
                if let Some(after) = microsandbox_db::catalog::sandbox_query(&txn)
                    .await?
                    .filter(sandbox_entity::Column::Id.eq(sandbox_id))
                    .one(&txn)
                    .await?
                {
                    sandbox_entity::Entity::update_many()
                        .col_expr(
                            sandbox_entity::Column::CallerConfigOverrides,
                            Expr::value(intent.caller_config_overrides_json(&after.config)?),
                        )
                        .filter(sandbox_entity::Column::Id.eq(sandbox_id))
                        .exec(&txn)
                        .await?;
                }
            }

            Ok::<_, crate::MicrosandboxError>((txn, ()))
        })
        .await?;
        Ok(())
    }

    pub(crate) fn validate_completed_restore(config: &SandboxConfig) -> MicrosandboxResult<()> {
        if config.checkpoint_restore.is_some() {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "sandbox {:?} has an incomplete restore; remove and recreate it from the snapshot; refusing a cold boot",
                config.spec.name
            )));
        }
        Ok(())
    }

    /// Inner local create logic separated for error-cleanup wrapper. Returns
    /// the local-variant state plus the (possibly mutated) config.
    pub(super) async fn create_sandbox_inner(
        &self,
        mut config: SandboxConfig,
        sandbox_id: i32,
        mode: SpawnMode,
        lifecycle_guard: Option<microsandbox_runtime::ipc::SandboxLifecycleGuard>,
    ) -> MicrosandboxResult<(crate::context::SandboxLocalState, SandboxConfig)> {
        let (handle, agent_sock_path) = timing::measure(
            &config.spec.name,
            "process_launch",
            self.launch_sandbox(&config, sandbox_id, mode, lifecycle_guard),
        )
        .await?;
        let mut startup_process = StartupProcess::new(handle);
        let log_dir = self.sandboxes_dir().join(&config.spec.name).join("logs");
        if let Err(error) = startup_process
            .handle_mut()
            .wait_for_preparation(&config.creation_progress)
            .await
        {
            // Preserve the runtime's structured diagnosis when an invalid checkpoint
            // closes the startup channel before activation can be announced.
            let error = Self::read_boot_start_error(&log_dir, &config.spec.name).unwrap_or(error);
            if let Err(cleanup) = startup_process
                .handle_mut()
                .terminate_failed_startup()
                .await
            {
                return Err(MicrosandboxError::Runtime(format!("{error}; {cleanup}")));
            }
            // A legacy runtime can close telemetry before publishing its error. Once this
            // exact child is reaped, one final read also covers publication during teardown.
            return Err(Self::read_boot_start_error(&log_dir, &config.spec.name).unwrap_or(error));
        }
        // Cold backing construction and lock waits do not consume activation's budget.
        let startup_deadline = tokio::time::Instant::now() + AGENT_RELAY_READY_TIMEOUT;

        // Wait for the relay socket to become available.
        let client = match timing::measure(
            &config.spec.name,
            "agent_ready",
            Self::wait_for_relay(
                &agent_sock_path,
                &log_dir,
                startup_process.handle_mut(),
                &config.spec.name,
                startup_deadline.saturating_duration_since(tokio::time::Instant::now()),
                self.config().in_band_agent_transport(),
            ),
        )
        .await
        {
            Ok(client) => client,
            Err(error) => {
                if let Err(cleanup) = startup_process
                    .handle_mut()
                    .terminate_failed_startup()
                    .await
                {
                    return Err(MicrosandboxError::Runtime(format!("{error}; {cleanup}")));
                }
                return Err(error);
            }
        };

        if let Ok(ready) = client.ready() {
            tracing::info!(
                sandbox_name = %config.spec.name,
                boot_time_ms = ready.boot_time_ns / 1_000_000,
                init_time_ms = ready.init_time_ns / 1_000_000,
                ready_time_ms = ready.ready_time_ns / 1_000_000,
                "sandbox ready",
            );
        }
        if config.checkpoint_restore.is_some() {
            // Resource reporting is part of readiness, not an unbounded wait after it.
            let restored = tokio::time::timeout_at(
                startup_deadline,
                self.restore_requested_resources(&mut config),
            )
            .await
            .unwrap_or_else(|_| {
                Err(MicrosandboxError::Runtime(
                    "startup deadline expired while reading restored resource targets".into(),
                ))
            });
            if let Err(error) = restored {
                if let Err(cleanup) = startup_process
                    .handle_mut()
                    .terminate_failed_startup()
                    .await
                {
                    return Err(MicrosandboxError::Runtime(format!("{error}; {cleanup}")));
                }
                return Err(error);
            }
        }
        // Capture the generation while startup still owns the transition. Scoped
        // cleanup must never rediscover a later run merely by sandbox ID or name.
        let run = Self::load_latest_run(self.db().await?.read(), sandbox_id)
            .await?
            .ok_or_else(|| MicrosandboxError::Runtime("ready runtime has no run record".into()))?;
        #[cfg(windows)]
        if let Some((process, lifecycle_lock)) = &startup_process.handle_mut().ownership {
            process.publish(
                &self.sandboxes_dir().join(&config.spec.name).join("runtime"),
                &run,
                *lifecycle_lock,
            )?;
        }
        // Even detached launches remain creator-owned until catalog publication and validation
        // finish. Cancellation or failure before that boundary must terminate this exact child.
        let process = startup_process.into_handle();
        let cleanup = Some(process.cleanup_control());
        let handle = Some(Arc::new(Mutex::new(process)));

        Ok((
            crate::context::SandboxLocalState {
                db_id: sandbox_id,
                run_id: Some(run.id),
                handle,
                cleanup,
                owned_run_id: Some(run.id),
                client: Arc::new(client),
            },
            config,
        ))
    }

    /// Wait for the agent relay socket to become available and connect.
    ///
    /// The sandbox process creates the relay socket asynchronously during startup.
    /// This function retries the connection with brief delays until it succeeds
    /// or a timeout is reached.
    async fn wait_for_relay(
        sock_path: &std::path::Path,
        log_dir: &std::path::Path,
        handle: &mut ProcessHandle,
        sandbox_name: &str,
        timeout: std::time::Duration,
        in_band_transport: bool,
    ) -> MicrosandboxResult<AgentClient> {
        tracing::debug!(
            sock = %sock_path.display(),
            pid = handle.pid(),
            "wait_for_relay: waiting for agent socket"
        );
        let deadline = tokio::time::Instant::now() + timeout;
        let max_backoff = std::time::Duration::from_millis(10);
        let mut backoff = std::time::Duration::from_millis(1);
        let mut attempts = 0u32;

        loop {
            attempts += 1;
            let connect = async {
                if in_band_transport {
                    AgentClient::connect_in_band_with_deadline(sock_path, deadline).await
                } else {
                    AgentClient::connect(sock_path).await
                }
            };
            match tokio::time::timeout(
                deadline.saturating_duration_since(tokio::time::Instant::now()),
                connect,
            )
            .await
            {
                Ok(Ok(client)) => {
                    tracing::debug!(attempts, "wait_for_relay: connected");
                    // The relay is up — clear any stale boot-error.json from
                    // a previous failed attempt so it cannot misattribute a
                    // future crash.
                    let _ = microsandbox_runtime::boot_error::BootError::delete(log_dir);
                    return Ok(client);
                }
                Ok(Err(_)) | Err(_) if tokio::time::Instant::now() < deadline => {
                    // Check if the sandbox process is still alive before retrying.
                    // If it crashed, there's no point waiting for the socket.
                    if let Some(status) = handle.try_wait()? {
                        tracing::debug!(
                            attempts,
                            ?status,
                            "wait_for_relay: sandbox process exited"
                        );

                        // Prefer the structured boot-error record if the
                        // sandbox got far enough to write one.
                        if let Some(error) = Self::read_boot_start_error(log_dir, sandbox_name) {
                            return Err(error);
                        }

                        // No structured boot-error.json — the sandbox died
                        // too early or too violently (e.g. a Rust panic exits
                        // 101 without running our atomic-writer). Synthesize
                        // an `Other`-stage record so the CLI still renders
                        // the styled error block with the `msb logs` hint
                        // instead of dumping a raw log directory path.
                        let synthetic = microsandbox_runtime::boot_error::BootError {
                            t: chrono::Utc::now()
                                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                            stage: microsandbox_runtime::boot_error::BootErrorStage::Other,
                            reason: None,
                            errno: None,
                            message: format!(
                                "sandbox process exited ({status}) before agent relay became available"
                            ),
                        };
                        return Err(MicrosandboxError::BootStart {
                            name: sandbox_name.to_string(),
                            err: synthetic,
                        });
                    }

                    // Keep early retries tight so relay readiness doesn't inherit a
                    // coarse fixed delay on warm starts.
                    tokio::time::sleep(
                        backoff
                            .min(deadline.saturating_duration_since(tokio::time::Instant::now())),
                    )
                    .await;
                    backoff = std::cmp::min(backoff.saturating_mul(2), max_backoff);
                }
                Ok(Err(e)) => {
                    tracing::debug!(
                        attempts,
                        error = %e,
                        "wait_for_relay: agent connection failed"
                    );
                    if let Some(error) = Self::read_boot_start_error(log_dir, sandbox_name) {
                        return Err(error);
                    }
                    return Err(relay_readiness_timeout(sandbox_name, timeout, &e));
                }
                Err(e) => {
                    tracing::debug!(
                        attempts,
                        error = %e,
                        "wait_for_relay: timed out"
                    );
                    // Even when the process is still running, the sandbox
                    // may have written a structured boot-error before
                    // stalling (e.g. agentd reported a recoverable failure
                    // and never produced the handshake bytes). Prefer that
                    // typed record over the raw IO/timeout error so the CLI
                    // can render the styled boot-error block.
                    if let Some(error) = Self::read_boot_start_error(log_dir, sandbox_name) {
                        return Err(error);
                    }
                    return Err(relay_readiness_timeout(sandbox_name, timeout, &e));
                }
            }
        }
    }

    /// Read `boot-error.json` from `log_dir` if present and parseable.
    ///
    /// Returns `None` when the directory is unknown, the file is missing, or
    /// the contents cannot be deserialized — callers fall back to a raw
    /// error in those cases.
    pub(crate) fn read_boot_error(
        log_dir: &std::path::Path,
    ) -> Option<microsandbox_runtime::boot_error::BootError> {
        microsandbox_runtime::boot_error::BootError::read(log_dir)
            .ok()
            .flatten()
    }

    /// Read a persisted boot error and attach the sandbox name expected by
    /// SDK create/start callers.
    fn read_boot_start_error(
        log_dir: &std::path::Path,
        sandbox_name: &str,
    ) -> Option<MicrosandboxError> {
        Self::read_boot_error(log_dir).map(|err| MicrosandboxError::BootStart {
            name: sandbox_name.to_string(),
            err,
        })
    }

    /// Resolve a fresh create by tag, but restore a snapshot by its captured
    /// manifest digest so a moved tag cannot change the snapshot's base.
    #[allow(clippy::too_many_arguments)]
    async fn resolve_oci_image_for_create(
        &self,
        reference: &str,
        pull_policy: PullPolicy,
        registry_overrides: RegistryOptions,
        image_cache_dir: Option<&Path>,
        expected_snapshot_manifest_digest: Option<&str>,
        owns_cached_image: bool,
        materialization: RootfsMaterialization,
        progress: Option<PullProgressSender>,
    ) -> MicrosandboxResult<ResolvedOciImage> {
        let Some(pinned_digest) = expected_snapshot_manifest_digest else {
            let cache_dir = self.resolve_image_cache_dir(image_cache_dir)?;
            let cache = GlobalCache::new_async(&cache_dir).await?.operation();
            let (pull_result, metadata) = self
                .pull_oci_image(
                    &cache,
                    reference,
                    pull_policy,
                    registry_overrides,
                    materialization,
                    progress,
                )
                .await?;
            return Ok(ResolvedOciImage {
                cache_operation: cache,
                pull_result,
                metadata_reference: reference.to_string(),
                metadata,
            });
        };

        self.resolve_snapshot_oci_image(
            reference,
            pinned_digest,
            pull_policy,
            registry_overrides,
            image_cache_dir,
            owns_cached_image,
            materialization,
            progress,
        )
        .await
    }

    /// Resolve the immutable image backing a snapshot from cache or registry.
    #[allow(clippy::too_many_arguments)]
    async fn resolve_snapshot_oci_image(
        &self,
        reference: &str,
        pinned_digest: &str,
        pull_policy: PullPolicy,
        registry_overrides: RegistryOptions,
        image_cache_dir: Option<&Path>,
        owns_cached_image: bool,
        materialization: microsandbox_image::RootfsMaterialization,
        progress: Option<PullProgressSender>,
    ) -> MicrosandboxResult<ResolvedOciImage> {
        let manifest_digest: Digest = pinned_digest.parse().map_err(|e| {
            MicrosandboxError::SnapshotIntegrity(format!(
                "invalid snapshot image digest {pinned_digest}: {e}"
            ))
        })?;
        let pinned_reference = Self::digest_pinned_reference(reference, pinned_digest)?;
        let using_default_cache = self.is_default_image_cache_dir(image_cache_dir);
        let cache_dir = self.resolve_image_cache_dir(image_cache_dir)?;
        let cache = GlobalCache::new_async(&cache_dir).await?.operation();
        cache
            .lease_paths_async(vec![cache.fsmeta_erofs_path(&manifest_digest)])
            .await?;

        let pinned_ref: Reference = pinned_reference.parse().map_err(|e| {
            MicrosandboxError::InvalidConfig(format!("invalid pinned reference: {e}"))
        })?;
        let original_ref: Reference = reference.parse().map_err(|e| {
            MicrosandboxError::InvalidConfig(format!("invalid image reference: {e}"))
        })?;
        let explicit_auth = registry_overrides
            .auth
            .as_ref()
            .is_some_and(|auth| !matches!(auth, microsandbox_image::RegistryAuth::Anonymous));
        let allow_restricted_cache = owns_cached_image || (!using_default_cache && !explicit_auth);
        // Explicit Always revalidates the immutable registry reference even when
        // metadata is cached. On a shared cache, digest lookup only accepts entries
        // whose provenance allows unauthenticated hits; restricted entries are
        // permitted for a verified archive, an authorized branch, or an explicitly
        // selected isolated cache without competing registry credentials.
        if pull_policy != PullPolicy::Always
            && (!explicit_auth || allow_restricted_cache)
            && let Some((pull_result, metadata)) = if allow_restricted_cache {
                Registry::pull_snapshot_cached_allow_restricted(
                    &cache,
                    &[pinned_ref.clone(), original_ref],
                    &manifest_digest,
                    materialization,
                )
                .await?
            } else {
                Registry::pull_snapshot_cached(
                    &cache,
                    &[pinned_ref.clone(), original_ref],
                    &manifest_digest,
                    materialization,
                )
                .await?
            }
        {
            if owns_cached_image
                && materialization == RootfsMaterialization::Layered
                && !cache.is_vmdk_complete_for_layers(&manifest_digest, &pull_result.layer_diff_ids)
            {
                cache
                    .rewrite_vmdk_async(&manifest_digest, &pull_result.layer_diff_ids)
                    .await?;
            }
            Self::emit_cached_pull_progress(progress.as_ref(), reference, &metadata);
            return Ok(ResolvedOciImage {
                cache_operation: cache,
                pull_result,
                metadata_reference: pinned_reference,
                metadata,
            });
        }

        if pull_policy == PullPolicy::Never {
            return Err(MicrosandboxError::SnapshotIntegrity(format!(
                "snapshot base image {pinned_digest} is not cached locally and pull policy is `never`; \
                 this snapshot cannot be restored losslessly"
            )));
        }

        if materialization == microsandbox_image::RootfsMaterialization::Flat {
            // The snapshot supplies the complete disk. Fetch its pinned image
            // defaults, not a second root filesystem that will never be used.
            let config = self
                .registry_config(pinned_ref.registry(), registry_overrides)
                .await?;
            let registry =
                Registry::builder(microsandbox_image::Platform::host_linux(), cache.clone())
                    .auth(config.auth)
                    .extra_ca_certs(config.ca_certs)
                    .add_insecure_registries(config.insecure_registries)
                    .build()?;
            let (pull_result, metadata) = registry
                .pull_snapshot_metadata_with_metadata(&pinned_ref)
                .await?;
            return Ok(ResolvedOciImage {
                cache_operation: cache,
                pull_result,
                metadata_reference: pinned_reference,
                metadata,
            });
        }

        // Pull by digest, never by the mutable source tag, when the exact
        // snapshot base is absent from the local cache.
        let (pull_result, metadata) = match self
            .pull_oci_image(
                &cache,
                &pinned_reference,
                pull_policy,
                registry_overrides,
                RootfsMaterialization::Layered,
                progress,
            )
            .await
        {
            Ok(result) => result,
            Err(err) => {
                return Err(MicrosandboxError::SnapshotIntegrity(format!(
                    "snapshot base image {pinned_digest} no longer available in registry \
                     (it may have been garbage-collected upstream); this snapshot \
                     cannot be restored losslessly: {err}"
                )));
            }
        };

        Ok(ResolvedOciImage {
            cache_operation: cache,
            pull_result,
            metadata_reference: pinned_reference,
            metadata,
        })
    }

    /// Build an immutable OCI reference using a captured manifest digest.
    fn digest_pinned_reference(reference: &str, pinned_digest: &str) -> MicrosandboxResult<String> {
        let parsed: Reference = reference.parse().map_err(|e| {
            MicrosandboxError::InvalidConfig(format!("invalid image reference: {e}"))
        })?;

        Ok(Reference::with_digest(
            parsed.registry().to_string(),
            parsed.repository().to_string(),
            pinned_digest.to_string(),
        )
        .whole())
    }

    /// Emit the same progress sequence for a cache hit as a registry pull.
    fn emit_cached_pull_progress(
        progress: Option<&PullProgressSender>,
        reference: &str,
        metadata: &CachedImageMetadata,
    ) {
        let Some(sender) = progress else {
            return;
        };

        let reference: std::sync::Arc<str> = reference.to_string().into();
        sender.send(PullProgress::Resolving {
            reference: reference.clone(),
        });
        sender.send(PullProgress::Resolved {
            reference: reference.clone(),
            manifest_digest: metadata.manifest_digest.clone().into(),
            layer_count: metadata.layers.len(),
            total_download_bytes: metadata
                .layers
                .iter()
                .filter_map(|layer| layer.size_bytes)
                .reduce(|a, b| a + b),
        });
        sender.send(PullProgress::Complete {
            reference,
            layer_count: metadata.layers.len(),
        });
    }

    /// Pull an OCI image and return the pull result.
    ///
    /// Auth resolution:
    /// 1. Explicit `RegistryAuth` from `SandboxBuilder::registry_auth()` (if provided)
    /// 2. OS keyring / credential store
    /// 3. Global config `registries.auth` matched by registry hostname
    /// 4. Docker credential store/config fallback
    /// 5. Anonymous fallback
    ///
    /// The caller must consume the matching progress handle when a sender is supplied.
    async fn pull_oci_image(
        &self,
        cache: &GlobalCache,
        reference: &str,
        pull_policy: PullPolicy,
        registry_overrides: RegistryOptions,
        materialization: RootfsMaterialization,
        progress: Option<PullProgressSender>,
    ) -> MicrosandboxResult<(PullResult, CachedImageMetadata)> {
        let platform = microsandbox_image::Platform::host_linux();
        let image_ref: Reference = reference.parse().map_err(|e| {
            MicrosandboxError::InvalidConfig(format!("invalid image reference: {e}"))
        })?;
        let options = PullOptions {
            pull_policy: Self::image_pull_policy(pull_policy),
            materialization,
            ..Default::default()
        };

        // Warm public/anonymous runs spend most of their time outside the guest,
        // so avoid constructing the registry client when an unauthenticated image
        // is already complete in the selected cache. Skip this fast path whenever
        // explicit credentials are supplied; `pull_cached_async` also refuses any
        // cached entry that was pulled with authentication.
        let explicit_auth = registry_overrides
            .auth
            .as_ref()
            .is_some_and(|auth| !matches!(auth, microsandbox_image::RegistryAuth::Anonymous));
        if !explicit_auth
            && let Some((result, metadata)) =
                Registry::pull_cached_async(cache, &image_ref, &options).await?
        {
            Self::emit_cached_pull_progress(progress.as_ref(), reference, &metadata);
            return Ok((result, metadata));
        }

        let config = self
            .registry_config(image_ref.registry(), registry_overrides)
            .await?;
        let registry = Registry::builder(platform, cache.clone())
            .auth(config.auth)
            .extra_ca_certs(config.ca_certs)
            .add_insecure_registries(config.insecure_registries)
            .build()?;

        Ok(registry
            .pull_with_metadata(&image_ref, &options, progress)
            .await?)
    }

    /// Map the SDK pull policy onto the image crate's pull policy.
    fn image_pull_policy(policy: PullPolicy) -> microsandbox_image::PullPolicy {
        match policy {
            PullPolicy::IfMissing => microsandbox_image::PullPolicy::IfMissing,
            PullPolicy::Always => microsandbox_image::PullPolicy::Always,
            PullPolicy::Never => microsandbox_image::PullPolicy::Never,
        }
    }

    /// Validate sandbox-name-derived runtime paths for this backend.
    pub(crate) fn validate_sandbox_name_for_runtime(&self, name: &str) -> MicrosandboxResult<()> {
        validate_sandbox_name(name)?;
        self.resolve_agent_socket_path(name).map(|_| ())
    }

    /// Validate rootfs configuration that depends on host filesystem state.
    pub(super) fn validate_rootfs_source(rootfs: &RootfsSource) -> MicrosandboxResult<()> {
        match rootfs {
            RootfsSource::Bind { path, .. } => {
                if !path.exists() {
                    return Err(MicrosandboxError::InvalidConfig(format!(
                        "rootfs bind path does not exist: {}",
                        path.display()
                    )));
                }

                if !path.is_dir() {
                    return Err(MicrosandboxError::InvalidConfig(format!(
                        "rootfs bind path is not a directory: {}",
                        path.display()
                    )));
                }
            }
            RootfsSource::Oci(_) => {}
            RootfsSource::DiskImage { path, .. } => {
                if !path.exists() {
                    return Err(MicrosandboxError::InvalidConfig(format!(
                        "disk image does not exist: {}",
                        path.display()
                    )));
                }

                if !path.is_file() {
                    return Err(MicrosandboxError::InvalidConfig(format!(
                        "disk image is not a regular file: {}",
                        path.display()
                    )));
                }
            }
        }

        Ok(())
    }

    /// Check availability without stopping or removing any existing sandbox.
    async fn check_create_target(
        pools: &DbPools,
        name: &str,
        sandbox_dir: &Path,
    ) -> MicrosandboxResult<()> {
        let existing = microsandbox_db::catalog::sandbox_query(pools.read())
            .await?
            .filter(sandbox_entity::Column::Name.eq(name))
            .one(pools.read())
            .await?;
        if let Some(model) = &existing {
            creation::require_complete(pools.read(), model.id, name).await?;
        }

        if existing.is_some() || sandbox_dir.exists() {
            return Err(MicrosandboxError::SandboxAlreadyExists(format!(
                "sandbox '{name}' already exists; remove it, start the stopped sandbox, or recreate with .replace()"
            )));
        }
        Ok(())
    }

    /// Clear the way for a create: reject conflicting persisted state, or
    /// (with `.replace()`) stop and remove the prior sandbox.
    async fn prepare_create_target(
        pools: &DbPools,
        config: &SandboxConfig,
        sandbox_dir: &Path,
        run_dir: &Path,
        local: Option<&Self>,
        attempt: &mut Option<replacement::Attempt>,
    ) -> MicrosandboxResult<()> {
        if !config.replace_existing {
            return Self::check_create_target(pools, &config.spec.name, sandbox_dir).await;
        }
        let socket_paths = SandboxSocketPaths::new(run_dir, sandbox_dir, &config.spec.name);
        let existing = microsandbox_db::catalog::sandbox_query(pools.read())
            .await?
            .filter(sandbox_entity::Column::Name.eq(&config.spec.name))
            .one(pools.read())
            .await?;

        if let Some(model) = existing {
            let sandboxes_dir = sandbox_dir.parent().ok_or_else(|| {
                MicrosandboxError::InvalidConfig(format!(
                    "sandbox directory has no storage root: {}",
                    sandbox_dir.display()
                ))
            })?;
            let _lineage =
                crate::snapshot::lineage::lock_source(run_dir, &config.spec.name).await?;
            *attempt = Some(replacement::Attempt {
                name: config.spec.name.clone(),
                original: model.id,
                token: None,
            });
            if model.ephemeral {
                replacement::retain_ephemeral(pools.write(), model.id).await?;
            }
            let model = Self::reconcile_sandbox_runtime_state_owned(
                pools,
                model,
                Some((run_dir, sandboxes_dir)),
                true,
            )
            .await?;
            let active = matches!(
                model.status,
                SandboxStatus::Running | SandboxStatus::Draining | SandboxStatus::Paused
            );
            if active {
                Self::stop_sandbox_for_replacement(
                    pools,
                    &model,
                    config.replace_with_timeout,
                    local,
                )
                .await?;
            }

            let _guard = crate::runtime::acquire_sandbox_lifecycle_guard(
                run_dir,
                &config.spec.name,
                std::time::Duration::from_secs(5),
            )
            .await?;
            if Self::load_latest_run(pools.read(), model.id)
                .await?
                .and_then(|run| run.pid)
                .is_some_and(Self::pid_is_alive)
            {
                return Err(MicrosandboxError::SandboxStillRunning(format!(
                    "cannot replace sandbox {:?}: its recorded runtime process is still alive",
                    config.spec.name
                )));
            }

            // Recheck under this lifecycle guard: reconciliation released its guard,
            // and legacy runtimes do not participate in lifecycle locking.
            #[cfg(unix)]
            if model.status == SandboxStatus::Starting && socket_paths.may_be_live().await? {
                return Err(MicrosandboxError::SandboxStillRunning(format!(
                    "cannot replace sandbox {:?}: a runtime endpoint may still be live",
                    config.spec.name
                )));
            }

            socket_paths.runtime.remove_artifacts()?;
            replacement::park(
                pools.write(),
                &config.spec.name,
                model.id,
                sandbox_dir,
                attempt,
            )
            .await?;
            return Ok(());
        }

        let _lineage = crate::snapshot::lineage::lock_source(run_dir, &config.spec.name).await?;
        let _guard = crate::runtime::acquire_sandbox_lifecycle_guard(
            run_dir,
            &config.spec.name,
            std::time::Duration::from_secs(5),
        )
        .await?;
        #[cfg(unix)]
        if socket_paths.may_be_live().await? {
            return Err(MicrosandboxError::SandboxStillRunning(format!(
                "cannot replace sandbox {:?}: an untracked runtime endpoint may still be live",
                config.spec.name
            )));
        }
        socket_paths.runtime.remove_artifacts()?;
        remove_dir_if_exists(sandbox_dir)?;
        Ok(())
    }

    /// Acquire exclusive transition ownership for a sandbox name without blocking the async runtime.
    pub(crate) async fn acquire_sandbox_transition_guard(
        run_dir: &Path,
        name: &str,
    ) -> MicrosandboxResult<SandboxTransitionGuard> {
        let file = open_transition_lock(run_dir, name).await?;

        // LockFileEx/flock is process-wide coordination, but the nonblocking form is a short
        // syscall. Polling it asynchronously avoids pinning one blocking-pool thread per waiter
        // when many callers converge on the same name.
        loop {
            if microsandbox_utils::process_lock::try_lock_exclusive(&file)? {
                return Ok(SandboxTransitionGuard { _file: file });
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// Stop the prior sandbox before recreating it.
    ///
    /// Sends SIGTERM with the configured grace, then escalates to SIGKILL
    /// and waits a short reap window. Single path for both same-process and
    /// foreign-process owners: SIGKILL bypasses any signal handler so the
    /// process is dead within kernel time, and the reap completes via the
    /// owning process's existing wait machinery (tokio's SIGCHLD driver
    /// when we're the parent, or the foreign parent's own `waitpid`).
    /// Replaces the previous "wait 30s and give up" behavior, which spun
    /// the full timeout when libkrun's SIGTERM handler did a slow
    /// graceful shutdown.
    async fn stop_sandbox_for_replacement(
        pools: &DbPools,
        sandbox: &sandbox_entity::Model,
        grace: std::time::Duration,
        local: Option<&Self>,
    ) -> MicrosandboxResult<()> {
        let run = Self::load_active_run(pools.read(), sandbox.id).await?;
        let pids: Vec<i32> = run
            .as_ref()
            .and_then(|model| model.pid)
            .filter(|pid| Self::pid_is_alive(*pid))
            .into_iter()
            .collect();

        if !pids.is_empty() {
            // Polite phase: SIGTERM and wait up to `grace` for graceful exit.
            if !grace.is_zero() {
                let deadline = tokio::time::Instant::now() + grace;
                // The guest shutdown handler flushes dirty disks. Sending the host
                // process SIGTERM first can discard an already returned guest write.
                let requested = if let Some(local) = local
                    && sandbox.status == SandboxStatus::Running
                {
                    matches!(
                        tokio::time::timeout_at(
                            deadline,
                            local.request_agent_shutdown(&sandbox.name, sandbox.id)
                        )
                        .await,
                        Ok(Ok(()))
                    )
                } else {
                    false
                };
                if !requested {
                    for pid in &pids {
                        let _ = Self::terminate_pid_gracefully(*pid);
                    }
                }
                Self::wait_for_pids_to_exit(
                    &pids,
                    deadline.saturating_duration_since(tokio::time::Instant::now()),
                )
                .await;
            }

            // SIGKILL anything still alive, then prove every recorded owner
            // exited before deterministic sockets or storage can be reused.
            for pid in pids.iter().copied().filter(|p| Self::pid_is_alive(*p)) {
                if let Err(error) = Self::kill_pid(pid)
                    && Self::pid_is_alive(pid)
                {
                    return Err(error);
                }
            }
            Self::wait_for_pids_to_exit(&pids, std::time::Duration::from_secs(5)).await;
            if pids.iter().any(|pid| !Self::pid_has_exited(*pid)) {
                return Err(MicrosandboxError::SandboxStillRunning(format!(
                    "cannot replace sandbox {:?}: runtime did not exit after SIGKILL",
                    sandbox.name
                )));
            }
        }

        Self::mark_sandbox_stopped_for_replacement(
            pools.write(),
            sandbox.id,
            run.as_ref().map(|model| model.id),
        )
        .await
    }

    /// Mark the replaced sandbox row (and its run, when any) stopped.
    async fn mark_sandbox_stopped_for_replacement(
        db: &DbWriteConnection,
        sandbox_id: i32,
        run_id: Option<i32>,
    ) -> MicrosandboxResult<()> {
        db.transaction(|txn| async move {
            let now = chrono::Utc::now().naive_utc();

            if let Some(run_id) = run_id {
                run_entity::Entity::update_many()
                    .col_expr(
                        run_entity::Column::Status,
                        Expr::value(run_entity::RunStatus::Terminated),
                    )
                    .col_expr(
                        run_entity::Column::TerminationReason,
                        Expr::value(run_entity::TerminationReason::Signal),
                    )
                    .col_expr(run_entity::Column::TerminatedAt, Expr::value(now))
                    .filter(run_entity::Column::Id.eq(run_id))
                    .exec(&txn)
                    .await?;
            }

            sandbox_entity::Entity::update_many()
                .col_expr(
                    sandbox_entity::Column::Status,
                    Expr::value(SandboxStatus::Stopped),
                )
                .col_expr(
                    sandbox_entity::Column::ActiveConfig,
                    Expr::value(Option::<String>::None),
                )
                .col_expr(
                    sandbox_entity::Column::NetworkSlot,
                    Expr::value(Option::<u16>::None),
                )
                .col_expr(sandbox_entity::Column::UpdatedAt, Expr::value(now))
                .filter(sandbox_entity::Column::Id.eq(sandbox_id))
                .exec(&txn)
                .await?;

            Ok((txn, ()))
        })
        .await
    }

    /// Poll until every pid has exited or `timeout` elapses.
    async fn wait_for_pids_to_exit(pids: &[i32], timeout: std::time::Duration) {
        let start = std::time::Instant::now();
        let poll_interval = std::time::Duration::from_millis(50);

        loop {
            if pids.iter().all(|pid| Self::pid_has_exited(*pid)) {
                return;
            }

            if start.elapsed() >= timeout {
                return;
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Insert the sandbox record in the database and return its ID.
    #[cfg(test)]
    pub(in crate::context::local) async fn insert_sandbox_record(
        db: &DbWriteConnection,
        config: &SandboxConfig,
    ) -> MicrosandboxResult<i32> {
        Self::insert_sandbox_record_with_status(db, config, SandboxStatus::Running).await
    }

    async fn prepare_reserved_sandbox(
        &self,
        db: &DbWriteConnection,
        id: i32,
        config: &SandboxConfig,
    ) -> MicrosandboxResult<()> {
        launch_contract::validate_runtime_config(config, self.config()).await?;
        let config_json = serde_json::to_string(config)?;
        let caller_config_overrides_json = config.caller_config_overrides_json(&config_json)?;
        db.transaction(|txn| {
            let config_json = config_json.clone();
            let caller_config_overrides_json = caller_config_overrides_json.clone();
            async move {
                sandbox_entity::Entity::update_many()
                    .col_expr(sandbox_entity::Column::Config, Expr::value(config_json))
                    .col_expr(
                        sandbox_entity::Column::CallerConfigOverrides,
                        Expr::value(caller_config_overrides_json),
                    )
                    .col_expr(
                        sandbox_entity::Column::Status,
                        Expr::value(SandboxStatus::Starting),
                    )
                    .filter(sandbox_entity::Column::Id.eq(id))
                    .exec(&txn)
                    .await?;
                // Restore preparation can merge image labels after the name was reserved.
                sandbox_label_entity::Entity::delete_many()
                    .filter(sandbox_label_entity::Column::SandboxId.eq(id))
                    .exec(&txn)
                    .await?;
                if !config.spec.labels.is_empty() {
                    sandbox_label_entity::Entity::insert_many(config.spec.labels.iter().map(
                        |(key, value)| sandbox_label_entity::ActiveModel {
                            sandbox_id: Set(id),
                            key: Set(key.clone()),
                            value: Set(value.clone()),
                        },
                    ))
                    .exec(&txn)
                    .await?;
                }

                if self.is_default_image_cache_dir(config.image_cache_dir.as_deref())
                    && let Some(digest) = &config.manifest_digest
                {
                    Self::replace_oci_manifest_pin(&txn, id, digest).await?;
                }
                txn.execute_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "UPDATE sandbox SET creation_state = 'prepared' WHERE id = ? AND creation_state = 'preparing'",
                    [id.into()],
                ))
                .await?;
                Ok::<_, MicrosandboxError>((txn, ()))
            }
        })
        .await?;
        Ok(())
    }

    /// Called with transition ownership; recovery never runs during an ordinary create retry.
    async fn remove_interrupted_create_for_replacement(
        &self,
        pools: &DbPools,
        config: &SandboxConfig,
    ) -> MicrosandboxResult<()> {
        let Some(model) = sandbox_entity::Entity::find()
            .filter(sandbox_entity::Column::Name.eq(&config.spec.name))
            .one(pools.write())
            .await?
        else {
            return Ok(());
        };
        if !creation::pending(pools.write(), model.id).await? {
            return Ok(());
        }
        Self::stop_sandbox_for_replacement(pools, &model, config.replace_with_timeout, None)
            .await?;
        let _lineage =
            crate::snapshot::lineage::lock_source(&self.config().run_dir(), &model.name).await?;
        let _runtime = crate::runtime::acquire_sandbox_lifecycle_guard(
            &self.config().run_dir(),
            &model.name,
            std::time::Duration::from_secs(5),
        )
        .await?;
        self.remove_incomplete_sandbox(model.id, &model.name, creation::RemovalMode::Recovery)
            .await
    }

    /// Insert a provisional local create record that remains non-connectable until ready.
    #[cfg(test)]
    async fn insert_starting_sandbox_record(
        db: &DbWriteConnection,
        config: &SandboxConfig,
        runtime: Option<&crate::config::GlobalConfig>,
    ) -> MicrosandboxResult<i32> {
        // Image defaults and restore preparation can enrich the initial request.
        // Recheck at create admission, not in shared configuration persistence:
        // editing a stopped sandbox must not require an installed runtime.
        if let Some(runtime) = runtime {
            launch_contract::validate_runtime_config(config, runtime).await?;
        }
        Self::insert_sandbox_record_with_status(db, config, SandboxStatus::Starting).await
    }

    /// Insert the sandbox record with an explicit initial lifecycle status.
    #[cfg(test)]
    async fn insert_sandbox_record_with_status(
        db: &DbWriteConnection,
        config: &SandboxConfig,
        status: SandboxStatus,
    ) -> MicrosandboxResult<i32> {
        Self::insert_sandbox_record_impl(db, config, status, false).await
    }

    async fn insert_sandbox_record_impl(
        db: &DbWriteConnection,
        config: &SandboxConfig,
        status: SandboxStatus,
        reserve: bool,
    ) -> MicrosandboxResult<i32> {
        Self::insert_with_replacement(db, config, status, reserve, None).await
    }

    async fn insert_with_replacement(
        db: &DbWriteConnection,
        config: &SandboxConfig,
        status: SandboxStatus,
        reserve: bool,
        token: Option<&str>,
    ) -> MicrosandboxResult<i32> {
        let config_json = serde_json::to_string(config)?;
        let caller_config_overrides_json = config.caller_config_overrides_json(&config_json)?;
        let labels = config.spec.labels.clone();

        db.transaction(|txn| {
            let config_json = config_json.clone();
            let caller_config_overrides_json = caller_config_overrides_json.clone();
            let labels = labels.clone();
            async move {
                let now = chrono::Utc::now().naive_utc();
                let model = sandbox_entity::ActiveModel {
                    name: Set(config.spec.name.clone()),
                    config: Set(config_json),
                    caller_config_overrides: Set(caller_config_overrides_json.clone()),
                    status: Set(status),
                    ephemeral: Set(!reserve && config.spec.lifecycle.ephemeral),
                    created_at: Set(Some(now)),
                    updated_at: Set(Some(now)),
                    ..Default::default()
                };
                if let Some(token) = token {
                    let admitted = txn.execute_raw(Statement::from_sql_and_values(
                        DatabaseBackend::Sqlite,
                        "UPDATE sandbox_replacement SET admitting = 1 WHERE name = ? AND token = ? AND candidate IS NULL",
                        [config.spec.name.as_str().into(), token.into()],
                    )).await?;
                    if admitted.rows_affected() != 1 {
                        return Err(MicrosandboxError::Runtime("lost replacement admission before reservation".into()));
                    }
                }
                let result = sandbox_entity::Entity::insert(model).exec(&txn).await?;
                let sandbox_id = result.last_insert_id;
                microsandbox_runtime::command_bindings::install(&txn, sandbox_id, &config.deferred_command_bindings).await?;
                microsandbox_runtime::restored_exec_limits::install(&txn, sandbox_id, config.retained_exec_limits()).await?;
                if reserve {
                    txn.execute_raw(Statement::from_sql_and_values(
                        DatabaseBackend::Sqlite,
                        "UPDATE sandbox SET creation_state = 'preparing' WHERE id = ?",
                        [sandbox_id.into()],
                    ))
                    .await?;
                }
                // Starting already owns backing: cancellation or a crash during VM launch
                // must not release operation leases before a durable root protects it.
                if status == SandboxStatus::Starting
                    && config.image_cache_dir.is_none()
                    && matches!(config.spec.image, RootfsSource::Oci(_))
                    && let Some(digest) = &config.manifest_digest
                {
                    Self::replace_oci_manifest_pin(&txn, sandbox_id, digest).await?;
                }
                if !labels.is_empty() {
                    sandbox_label_entity::Entity::insert_many(labels.into_iter().map(
                        |(key, value)| sandbox_label_entity::ActiveModel {
                            sandbox_id: Set(sandbox_id),
                            key: Set(key),
                            value: Set(value),
                        },
                    ))
                    .exec(&txn)
                    .await?;
                }
                Ok((txn, sandbox_id))
            }
        })
        .await
    }

    /// Delete a sandbox row by id.
    async fn delete_sandbox_record(
        db: &DbWriteConnection,
        sandbox_id: i32,
    ) -> MicrosandboxResult<()> {
        sandbox_entity::Entity::delete_by_id(sandbox_id)
            .exec(db)
            .await?;
        Ok(())
    }

    /// Pin a sandbox to its resolved OCI manifest inside a transaction.
    async fn persist_oci_manifest_pin(
        db: &DbWriteConnection,
        sandbox_id: i32,
        manifest_digest: &str,
    ) -> MicrosandboxResult<()> {
        db.transaction(|txn| async move {
            Self::replace_oci_manifest_pin(&txn, sandbox_id, manifest_digest).await?;
            Ok((txn, ()))
        })
        .await
    }

    /// Pin a sandbox to its resolved OCI manifest.
    async fn replace_oci_manifest_pin<C: ConnectionTrait>(
        db: &C,
        sandbox_id: i32,
        manifest_digest: &str,
    ) -> MicrosandboxResult<()> {
        use crate::db::entity::manifest as manifest_entity;

        let now = chrono::Utc::now().naive_utc();

        let manifest = manifest_entity::Entity::find()
            .filter(manifest_entity::Column::Digest.eq(manifest_digest))
            .one(db)
            .await?;

        let manifest_id = manifest.map(|m| m.id);

        sandbox_rootfs_entity::Entity::delete_many()
            .filter(sandbox_rootfs_entity::Column::SandboxId.eq(sandbox_id))
            .exec(db)
            .await?;

        sandbox_rootfs_entity::Entity::insert(sandbox_rootfs_entity::ActiveModel {
            sandbox_id: Set(sandbox_id),
            manifest_id: Set(manifest_id),
            mode: Set("erofs".to_string()),
            upper_fstype: Set(Some("ext4".to_string())),
            created_at: Set(Some(now)),
            ..Default::default()
        })
        .exec(db)
        .await?;

        Ok(())
    }

    /// Create a sparse ext4 image for the writable overlay upper layer.
    async fn create_upper_ext4(
        path: &CreationStorage,
        size_mib: u32,
        tree: Option<tree::FileTree>,
    ) -> MicrosandboxResult<()> {
        let ext4_options = ext4::Ext4FormatOptions {
            size_bytes: u64::from(size_mib) * 1024 * 1024,
            ..Default::default()
        };
        let overlay_tree = Self::build_overlay_upper_tree(tree);
        let path = path.clone();

        tokio::task::spawn_blocking(move || {
            let _ = std::fs::remove_file(&path);
            // The formatter truncates an existing inode, preserving its private host mode.
            // This disk can later be hardlinked into checkpoint and snapshot storage.
            #[cfg(unix)]
            microsandbox_utils::private_file::create_new(&path)?;
            ext4::format_ext4_with_tree(&path, &ext4_options, overlay_tree)
        })
        .await
        .map_err(|e| MicrosandboxError::Custom(format!("ext4 format task failed: {e}")))?
        .map_err(|e| MicrosandboxError::Custom(format!("failed to create upper.ext4: {e}")))?;

        Ok(())
    }

    /// Build the ext4 root directory tree that overlayfs expects.
    fn build_overlay_upper_tree(tree: Option<tree::FileTree>) -> tree::FileTree {
        use tree::{DirectoryNode, FileTree, InodeMetadata, TreeNode};

        let mut overlay_tree = FileTree::new();
        let mut upper_dir = DirectoryNode::new(InodeMetadata::default());
        let work_dir = DirectoryNode::new(InodeMetadata::default());

        if let Some(mut tree) = tree {
            upper_dir.entries = std::mem::take(&mut tree.root.entries);
        }

        overlay_tree
            .root
            .entries
            .insert("upper".into(), TreeNode::Directory(upper_dir));
        overlay_tree
            .root
            .entries
            .insert("work".into(), TreeNode::Directory(work_dir));

        overlay_tree
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Historical file checkpoints can carry architecture only in the pinned OCI config.
/// Without recognizable source evidence, preserve their existing launch behavior.
fn validate_snapshot_image_architecture(raw_config: &str) -> MicrosandboxResult<()> {
    let Ok(ImagePlatform {
        architecture: Some(arch),
    }) = serde_json::from_str(raw_config)
    else {
        return Ok(());
    };
    let source = match arch {
        "amd64" | "x86_64" => "x86_64",
        "arm64" | "aarch64" => "aarch64",
        other
            if matches!(
                microsandbox_image::Arch::from(other),
                microsandbox_image::Arch::Other(_)
            ) =>
        {
            return Ok(());
        }
        other => other,
    };
    let host = std::env::consts::ARCH;
    if source != host {
        return Err(MicrosandboxError::SnapshotIntegrity(format!(
            "checkpoint architecture {source} cannot restore on {host}"
        )));
    }
    Ok(())
}

/// Repoint only extracted child-owned paths after same-filesystem publication.
/// Disk headers use relative basenames, so moving the whole directory preserves
/// root and owned-volume chains without rewriting or copying their contents.
fn relocate_archive_config(config: &mut SandboxConfig, stage: &Path, child: &Path) {
    let relocate = |path: &mut PathBuf| {
        if let Ok(relative) = path.strip_prefix(stage) {
            *path = child.join(relative);
        }
    };
    if let Some(restore) = config.checkpoint_restore.as_mut() {
        relocate(&mut restore.closure);
    }
    if let Some(source) = config.snapshot_upper_source.as_mut() {
        relocate(source);
    }
    for layer in &mut config.snapshot_upper_layers {
        relocate(&mut layer.path);
    }
    for mount in &mut config.spec.mounts {
        if let microsandbox_types::VolumeMount::DiskImage { host, .. } = mount {
            relocate(host);
        }
    }
}

fn snapshot_root_layout_from_config(
    config: &SandboxConfig,
) -> MicrosandboxResult<SnapshotRootDisk> {
    let RootfsSource::Oci(oci) = &config.spec.image else {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "snapshot restore did not resolve to an OCI rootfs".into(),
        ));
    };
    Ok(match oci.root_disk.as_ref() {
        None | Some(RootDisk::Managed { .. }) => SnapshotRootDisk::Managed,
        Some(RootDisk::Flat { .. }) => SnapshotRootDisk::Flat,
        Some(RootDisk::Tmpfs { size_mib }) => SnapshotRootDisk::Tmpfs {
            size_mib: *size_mib,
        },
        Some(RootDisk::DiskImage { .. }) => {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "snapshot descriptor cannot select a user-owned disk-image root".into(),
            ));
        }
    })
}

/// Keep an expired readiness budget distinct from the last transient socket failure.
fn relay_readiness_timeout(
    sandbox_name: &str,
    timeout: std::time::Duration,
    last_error: &impl std::fmt::Display,
) -> MicrosandboxError {
    MicrosandboxError::Runtime(format!(
        "sandbox {sandbox_name:?} startup timed out after {} seconds before agent readiness; \
         restore preparation may still be pending; last connection error: {last_error}",
        timeout.as_secs_f64(),
    ))
}

/// Derive a stable, filesystem-safe transition-lock path for one sandbox name.
async fn open_transition_lock(run_dir: &Path, name: &str) -> MicrosandboxResult<File> {
    let path = sandbox_transition_lock_path(run_dir, name);
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("transition lock has no parent: {}", path.display()),
        )
    })?;
    tokio::fs::create_dir_all(parent).await?;
    Ok(microsandbox_utils::process_lock::open_lock_file(&path)?)
}

fn sandbox_transition_lock_path(run_dir: &Path, name: &str) -> PathBuf {
    microsandbox_runtime::ipc::sandbox_transition_lock_path(run_dir, name)
}

fn check_workdir(
    path: &str,
    answer: MicrosandboxResult<Result<FsMetadata, String>>,
) -> MicrosandboxResult<()> {
    match answer {
        Err(error) => {
            // A fast-exiting startup command can close the transport during stat.
            Err(MicrosandboxError::InvalidConfig(format!(
                "could not validate workdir in guest {path:?}: {error}"
            )))
        }
        Ok(Err(message)) => Err(MicrosandboxError::InvalidWorkdir {
            path: path.to_owned(),
            problem: WorkdirProblem::StatFailed { message },
        }),
        Ok(Ok(metadata)) if metadata.kind != FsEntryKind::Directory => {
            Err(MicrosandboxError::InvalidWorkdir {
                path: path.to_owned(),
                problem: WorkdirProblem::NotADirectory,
            })
        }
        Ok(Ok(_)) => Ok(()),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::future::{Future, poll_fn};
    use std::process::Command;
    use std::task::Poll;
    use std::{
        fs,
        path::PathBuf,
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use microsandbox_db::entity::{run as run_entity, sandbox_rootfs as sandbox_rootfs_entity};
    use microsandbox_db::pool::DbPools;
    use microsandbox_image::{GlobalCache, RegistryAuth, RootfsMaterialization};
    use microsandbox_migration::{Migrator, MigratorTrait};
    #[cfg(unix)]
    use microsandbox_runtime::ipc::RuntimeSocketPaths;
    use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set};
    use tempfile::tempdir;

    use super::{check_workdir, sandbox_entity, sandbox_label_entity};
    use crate::AgentClientError;
    use crate::config::RegistryOptions;
    use crate::context::local::creation::{self, CreationStorage};
    use crate::context::{Context, LocalContext};
    use crate::db::entity::{sandbox, volume};
    use crate::runtime::SpawnMode;
    use crate::sandbox::{
        FsEntryKind, FsMetadata, HostPermissions, MAX_HOSTNAME_BYTES, MountOptions,
        OciRootfsSource, PullPolicy, RootfsSource, SandboxBuilder, SandboxConfig,
        SandboxListBuilder, SandboxStatus, StatVirtualization, VolumeMount,
    };
    use crate::snapshot::SnapshotReference;
    use crate::{MicrosandboxError, WorkdirProblem};

    //--------------------------------------------------------------------------------------------------
    // Types
    //--------------------------------------------------------------------------------------------------

    struct RecoveryFixture {
        _home: tempfile::TempDir,
        local: Arc<LocalContext>,
        config: SandboxConfig,
        id: i32,
    }

    //--------------------------------------------------------------------------------------------------
    // Methods
    //--------------------------------------------------------------------------------------------------

    impl RecoveryFixture {
        async fn new() -> Self {
            #[cfg(unix)]
            let home = tempfile::tempdir_in("/tmp").unwrap();
            #[cfg(not(unix))]
            let home = tempfile::tempdir().unwrap();
            let local = Arc::new(
                crate::test_support::local_backend_builder(home.path())
                    .build()
                    .unwrap(),
            );

            let rootfs = home.path().join("rootfs");
            std::fs::create_dir_all(&rootfs).unwrap();

            let config = SandboxBuilder::new("recoverable")
                .image(rootfs.canonicalize().unwrap())
                .ephemeral(true)
                .volume("/data", |mount| {
                    mount.named_with("new", |volume| volume.ensure_exists())
                })
                .build()
                .await
                .unwrap();

            let id = LocalContext::insert_sandbox_record_impl(
                local.db().await.unwrap().write(),
                &config,
                SandboxStatus::Starting,
                true,
            )
            .await
            .unwrap();

            Self {
                _home: home,
                local,
                config,
                id,
            }
        }
    }

    //--------------------------------------------------------------------------------------------------
    // Tests
    //--------------------------------------------------------------------------------------------------

    #[test]
    fn check_workdir_classifies_guest_answers() {
        let metadata = |kind| FsMetadata {
            kind,
            size: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            readonly: false,
            accessed: None,
            modified: None,
            created: None,
        };
        let path = "/work";

        let missing = check_workdir(
            path,
            Ok(Err("stat: No such file or directory (os error 2)".into())),
        );
        assert!(matches!(
            &missing,
            Err(MicrosandboxError::InvalidWorkdir {
                path: error_path,
                problem: WorkdirProblem::StatFailed { message },
            }) if error_path == path && message == "stat: No such file or directory (os error 2)"
        ));
        assert_eq!(
            missing.unwrap_err().to_string(),
            "invalid config: could not validate workdir in guest \"/work\": sandbox fs error: stat: No such file or directory (os error 2)"
        );

        let file = check_workdir(path, Ok(Ok(metadata(FsEntryKind::File))));
        assert!(matches!(
            &file,
            Err(MicrosandboxError::InvalidWorkdir {
                path: error_path,
                problem: WorkdirProblem::NotADirectory,
            }) if error_path == path
        ));
        assert_eq!(
            file.unwrap_err().to_string(),
            "invalid config: workdir is not a directory in guest: /work"
        );

        let closed = check_workdir(
            path,
            Err(MicrosandboxError::AgentClient(AgentClientError::Closed)),
        );
        assert!(matches!(
            &closed,
            Err(MicrosandboxError::InvalidConfig(message))
                if message == "could not validate workdir in guest \"/work\": agent client error: client closed"
        ));
        assert_eq!(
            closed.unwrap_err().to_string(),
            "invalid config: could not validate workdir in guest \"/work\": agent client error: client closed"
        );

        let directory = check_workdir(path, Ok(Ok(metadata(FsEntryKind::Directory))));
        assert!(directory.is_ok());
    }

    #[tokio::test]
    async fn starting_sandbox_owns_image_before_runtime_launch() {
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .unwrap();
        let reference = "example.com/starting:latest";
        let digest = format!("sha256:{}", "a".repeat(64));
        crate::Image::persist(
            &local,
            reference,
            microsandbox_image::CachedImageMetadata {
                manifest_digest: digest.clone(),
                config_digest: format!("sha256:{}", "b".repeat(64)),
                raw_manifest_json: "{}".into(),
                raw_config_json: "{}".into(),
                config: Default::default(),
                layers: Vec::new(),
            },
        )
        .await
        .unwrap();
        let mut config = crate::SandboxConfig::default();
        config.spec.name = "starting".into();
        config.spec.image = RootfsSource::oci(reference);
        config.manifest_digest = Some(digest);
        let db = local.db().await.unwrap().write();
        let id = LocalContext::insert_starting_sandbox_record(db, &config, None)
            .await
            .unwrap();
        assert_eq!(
            crate::Image::prune_local(&local)
                .await
                .unwrap()
                .image_refs_removed,
            0
        );
        LocalContext::delete_sandbox_record(db, id).await.unwrap();
        assert_eq!(
            crate::Image::prune_local(&local)
                .await
                .unwrap()
                .image_refs_removed,
            1
        );
    }

    /// Open both pools at `db_path` for tests, with migrations applied.
    async fn open_test_pools(db_path: &std::path::Path) -> DbPools {
        // Connect timeout matches the production default (30s). 1s was too
        // tight on cold ci runners and surfaced as `PoolTimedOut` flakes
        // before the test body had a chance to run.
        let pools = DbPools::open(
            db_path,
            1,
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap();
        Migrator::up(pools.write().inner(), None).await.unwrap();
        pools
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn managed_upper_is_private_before_snapshot_linking() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("upper.ext4");
        LocalContext::create_upper_ext4(&CreationStorage::for_test(&path), 256, None)
            .await
            .unwrap();
        microsandbox_utils::private_file::verify(&fs::File::open(&path).unwrap()).unwrap();
        let snapshot = directory.path().join("snapshot.raw");
        fs::hard_link(&path, &snapshot).unwrap();
        microsandbox_utils::private_file::verify(&fs::File::open(snapshot).unwrap()).unwrap();
    }

    #[tokio::test]
    async fn existing_name_fails_before_image_pull() {
        use crate::config::{GlobalConfigPatch, layers::BackendConfig};
        let temp = tempfile::Builder::new()
            .prefix("msb-preflight")
            .tempdir_in("/tmp")
            .unwrap();
        for persisted in [false, true] {
            let home = temp
                .path()
                .join(if persisted { "database" } else { "directory" });
            let layers = BackendConfig::new(
                GlobalConfigPatch::new().home(home.clone()),
                Default::default(),
            );
            let backend = Arc::new(LocalContext::from_backend_config(
                layers
                    .prepare_for_local_backend(Default::default())
                    .unwrap(),
                crate::context::ContextSelectionSource::Programmatic,
                None,
            ));
            if persisted {
                let pools = backend.db().await.unwrap();
                LocalContext::insert_sandbox_record(pools.write(), &test_config("existing"))
                    .await
                    .unwrap();
            } else {
                fs::create_dir_all(home.join("sandboxes/existing")).unwrap();
            }
            // This uncached image would fail under PullPolicy::Never if pulling were reached.
            let input = crate::sandbox::SandboxBuilder::new("existing")
                .image("registry.invalid/review-never-pulled:missing")
                .pull_policy(crate::sandbox::PullPolicy::Never);
            let error = backend
                .create_sandbox(backend.clone(), input, SpawnMode::Attached, None)
                .await
                .err()
                .unwrap();
            assert!(
                matches!(error, crate::MicrosandboxError::SandboxAlreadyExists(_)),
                "{error}"
            );
        }
    }

    #[test]
    fn snapshot_architecture_uses_only_known_oci_evidence() {
        for config in [
            "{}",
            r#"{"architecture":null}"#,
            r#"{"architecture":"unknown"}"#,
        ] {
            super::validate_snapshot_image_architecture(config).unwrap();
        }
        let host = std::env::consts::ARCH;
        let native = microsandbox_image::Platform::host_linux().arch.to_string();
        let foreign = if host == "x86_64" { "arm64" } else { "amd64" };
        for name in [native.as_str(), host] {
            super::validate_snapshot_image_architecture(
                &serde_json::json!({"architecture": name}).to_string(),
            )
            .unwrap();
        }
        let error = super::validate_snapshot_image_architecture(
            &serde_json::json!({"architecture": foreign}).to_string(),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains(&format!("cannot restore on {host}"))
        );
    }

    #[test]
    fn cleared_host_deployment_policy_preserves_create_and_restart_selection() {
        use crate::config::{GlobalConfigPatch, layers::BackendConfig};
        use microsandbox_types::DeploymentProfile;
        let user = GlobalConfigPatch::new().deployment_profile(DeploymentProfile::SingleTenant);
        let managed = serde_json::from_str(r#"{"deployment_profile":null}"#).unwrap();
        let layers = BackendConfig::new(user, managed);
        let backend = LocalContext::from_backend_config(
            layers
                .prepare_for_local_backend(Default::default())
                .unwrap(),
            crate::context::ContextSelectionSource::Programmatic,
            None,
        );
        let requested = DeploymentProfile::MultiTenant;
        let restart = backend.resolve_deployment_profile("policy-clear", requested);
        let created = crate::sandbox::SandboxBuilder::new("policy-clear")
            .image("alpine")
            .deployment_profile(restart)
            .finish(Some(backend.config_sources()), None)
            .unwrap();
        assert_eq!(restart, requested);
        assert_eq!(created.spec.deployment_profile, requested);
    }

    #[tokio::test]
    async fn create_layers_managed_resources_before_final_validation() {
        use crate::config::{GlobalConfigPatch, layers::BackendConfig};
        let temp = tempfile::Builder::new()
            .prefix("msb-layers")
            .tempdir_in("/tmp")
            .unwrap();
        let layers = BackendConfig::new(
            GlobalConfigPatch::new().home(temp.path().join("home")),
            serde_json::from_str(r#"{"sandbox_defaults":{"cpus":2}}"#).unwrap(),
        );
        let backend = Arc::new(LocalContext::from_backend_config(
            layers
                .prepare_for_local_backend(Default::default())
                .unwrap(),
            crate::context::ContextSelectionSource::Programmatic,
            None,
        ));
        let builder = crate::sandbox::SandboxBuilder::new("late-resources")
            .image(temp.path().join("missing-rootfs"))
            .cpus(8)
            .max_cpus(3);
        let error = backend
            .create_sandbox(backend.clone(), builder, SpawnMode::Attached, None)
            .await
            .err()
            .expect("missing rootfs must fail without starting a VM");
        // cpus=8/max_cpus=3 is invalid before layering. Managed cpus=2 repairs
        // that input, so the final config reaches the subsequent rootfs check.
        assert!(
            error
                .to_string()
                .contains("rootfs bind path does not exist"),
            "{error}"
        );
        assert!(backend.inner.db.get().is_none());
    }

    #[tokio::test]
    async fn invalid_final_config_does_not_replace_existing_state() {
        use crate::config::{GlobalConfigPatch, layers::BackendConfig};
        let temp = tempfile::Builder::new()
            .prefix("msb-layers")
            .tempdir_in("/tmp")
            .unwrap();
        let home = temp.path().join("home");
        let sandbox_dir = home.join("sandboxes").join("retained");
        fs::create_dir_all(&sandbox_dir).unwrap();
        let marker = sandbox_dir.join("keep");
        fs::write(&marker, "existing state").unwrap();
        let layers = BackendConfig::new(
            GlobalConfigPatch::new().home(home),
            serde_json::from_str(r#"{"sandbox_defaults":{"cpus":0}}"#).unwrap(),
        );
        let backend = Arc::new(LocalContext::from_backend_config(
            layers
                .prepare_for_local_backend(Default::default())
                .unwrap(),
            crate::context::ContextSelectionSource::Programmatic,
            None,
        ));
        let builder = crate::sandbox::SandboxBuilder::new("retained")
            .image(temp.path().to_path_buf())
            .cpus(2)
            .replace();
        let error = backend
            .create_sandbox(backend.clone(), builder, SpawnMode::Attached, None)
            .await
            .err()
            .expect("invalid managed CPU count must fail");
        assert!(
            error.to_string().contains("cpus must be greater than 0"),
            "{error}"
        );
        assert_eq!(fs::read_to_string(marker).unwrap(), "existing state");
        assert!(backend.inner.db.get().is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unsupported_nesting_preserves_replace_target() {
        use std::os::unix::fs::PermissionsExt;

        use crate::config::{GlobalConfigPatch, layers::BackendConfig};

        let temp = tempfile::Builder::new()
            .prefix("msb-nesting")
            .tempdir_in("/tmp")
            .unwrap();
        let home = temp.path().join("home");
        let runtime = temp.path().join("msb");
        let firmware = temp.path().join("libkrunfw");
        fs::write(
            &runtime,
            r#"#!/bin/sh
case "$1" in
--version) printf 'msb 0.6.18';;
__launch-protocol) printf '%s' '{"protocols":[2,1],"protected_guest_state":true,"nested_virt":false}';;
*) exit 1;;
esac
"#,
        )
        .unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&firmware, b"not loaded before host validation").unwrap();
        let managed = serde_json::from_value(serde_json::json!({
            "paths": {"msb": runtime, "libkrunfw": firmware}
        }))
        .unwrap();
        let sources = BackendConfig::new(GlobalConfigPatch::new().home(home), managed);
        let backend = Arc::new(LocalContext::from_backend_config(
            sources
                .prepare_for_local_backend(Default::default())
                .unwrap(),
            crate::context::ContextSelectionSource::Programmatic,
            None,
        ));
        let pools = backend.db().await.unwrap();
        let config =
            test_config_with_rootfs("retained", RootfsSource::oci("missing.invalid/image"));
        let id = LocalContext::insert_sandbox_record_with_status(
            pools.write(),
            &config,
            SandboxStatus::Stopped,
        )
        .await
        .unwrap();
        let directory = backend.sandboxes_dir().join("retained");
        fs::create_dir_all(&directory).unwrap();
        let marker = directory.join("keep");
        fs::write(&marker, b"existing sandbox state").unwrap();
        let root = temp.path().join("rootfs");
        fs::create_dir(&root).unwrap();
        let builder = crate::Sandbox::builder("retained")
            .image(root)
            .nested_virt(true)
            .replace();

        let error = backend
            .create_sandbox(backend.clone(), builder, SpawnMode::Attached, None)
            .await
            .err()
            .expect("unsupported nesting must reject before replacement");

        assert!(
            error
                .to_string()
                .contains("nested virtualization is unavailable"),
            "{error}"
        );
        assert_eq!(fs::read(marker).unwrap(), b"existing sandbox state");
        assert!(
            sandbox_entity::Entity::find_by_id(id)
                .one(pools.read())
                .await
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn readiness_deadline_reports_timeout_not_only_missing_socket() {
        let error = super::relay_readiness_timeout(
            "slow-restore",
            super::AGENT_RELAY_READY_TIMEOUT,
            &std::io::Error::from(std::io::ErrorKind::NotFound),
        )
        .to_string();
        assert!(error.contains("startup timed out after 180 seconds"));
        assert!(error.contains("slow-restore"));
        assert!(error.contains("restore preparation"));
        assert!(error.contains("last connection error"));
    }

    #[cfg(unix)]
    async fn exercise_readiness_deadline(silent_peer: bool) -> String {
        use crate::runtime::handle::{ProcessHandle, StartupProcess};

        let directory = tempfile::Builder::new()
            .prefix("msb-readiness")
            .tempdir_in("/tmp")
            .unwrap();
        let socket = directory.path().join("agent.sock");
        let server = if silent_peer {
            let listener = tokio::net::UnixListener::bind(&socket).unwrap();
            Some(tokio::spawn(async move {
                let (_connection, _) = listener.accept().await.unwrap();
                // Accept the transport but never finish the agent handshake, exercising the
                // connection-attempt deadline rather than an immediately missing endpoint.
                std::future::pending::<()>().await;
            }))
        } else {
            None
        };
        let child = tokio::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let mut owner = StartupProcess::new(ProcessHandle::new(
            child.id().unwrap(),
            "slow-restore".into(),
            child,
            Vec::new(),
            None,
            None,
        ));
        let result = LocalContext::wait_for_relay(
            &socket,
            directory.path(),
            owner.handle_mut(),
            "slow-restore",
            std::time::Duration::from_millis(50),
            false,
        )
        .await;
        let still_alive = owner.handle_mut().try_wait().unwrap().is_none();
        owner.handle_mut().terminate_failed_startup().await.unwrap();
        if let Some(server) = server {
            server.abort();
            let _ = server.await;
        }
        assert!(still_alive, "fixture exited before readiness expired");
        let error = result
            .err()
            .expect("relay unexpectedly became ready")
            .to_string();
        assert!(
            error.contains("startup timed out after 0.05 seconds"),
            "{error}"
        );
        assert!(error.contains("slow-restore"), "{error}");
        assert!(error.contains("last connection error"), "{error}");
        error
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn readiness_loop_reports_missing_socket_deadline() {
        let error = exercise_readiness_deadline(false).await;
        assert!(
            error.contains("No such file") || error.contains("not found"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn readiness_loop_reports_stalled_handshake_deadline() {
        let error = exercise_readiness_deadline(true).await;
        assert!(error.contains("deadline has elapsed"), "{error}");
    }

    async fn exercise_failed_startup_rollback(with_created_volume: bool, status: SandboxStatus) {
        use crate::db::entity::volume as volume_entity;

        use crate::sandbox::SandboxBuilder;

        let directory = tempdir().unwrap();
        let rootfs = directory.path().join("rootfs");
        fs::create_dir_all(&rootfs).unwrap();
        let local = crate::test_support::local_backend_builder(directory.path().join("home"))
            .build()
            .unwrap();
        let mut builder = SandboxBuilder::new("rollback-owner").image(rootfs.display().to_string());
        if with_created_volume {
            builder = builder.volume("/data", |mount| {
                mount.named_with("created-during-startup", |volume| volume.ensure_exists())
            });
        }
        let mut config = builder.build().await.unwrap();
        config.checkpoint_restore = Some(microsandbox_runtime::launch::CheckpointRestoreConfig {
            memory_descriptor: false,
            network_gateway_mac: None,
            external_mount_policy: Default::default(),
            external_mounts: Vec::new(),
            unavailable_disks: Default::default(),
            local_branch: false,
            forked: true,
            closure: directory.path().join("pending-checkpoint"),
            checkpoint_root: "blake3:pending".into(),
            checkpoint_id: "pending".into(),
        });
        let pools = local.db().await.unwrap();
        let write_db = pools.write();
        let _transition = microsandbox_runtime::ipc::try_acquire_transition_guard(
            &local.config().run_dir(),
            &config.spec.name,
        )
        .unwrap()
        .unwrap();
        let sandbox_id = LocalContext::insert_sandbox_record_impl(
            write_db,
            &config,
            SandboxStatus::Starting,
            true,
        )
        .await
        .unwrap();
        let created = local
            .ensure_named_volumes(
                &crate::context::local::creation::CreationStorage::for_test(
                    local.sandboxes_dir().join(&config.spec.name),
                ),
                &config,
            )
            .await
            .unwrap();
        crate::context::local::creation::complete(write_db, sandbox_id, status)
            .await
            .unwrap();
        let active_run = run_entity::Entity::insert(run_entity::ActiveModel {
            sandbox_id: Set(sandbox_id),
            status: Set(run_entity::RunStatus::Running),
            ..Default::default()
        })
        .exec(write_db)
        .await
        .unwrap()
        .last_insert_id;

        let sandbox_before = sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(write_db)
            .await
            .unwrap()
            .unwrap();
        let run_before = run_entity::Entity::find_by_id(active_run)
            .one(write_db)
            .await
            .unwrap()
            .unwrap();
        let volumes_before = volume_entity::Entity::find().all(write_db).await.unwrap();
        assert_eq!(volumes_before.len(), usize::from(with_created_volume));
        let volume_path = local.volume_path("created-during-startup");
        if with_created_volume {
            fs::write(volume_path.join("sentinel"), b"still owned").unwrap();
            // Sandbox deletion cascades to run rows. Check the actual run state at each
            // deletion, rather than inferring reconciliation from the rows being absent.
            for (table, id) in [("sandbox", sandbox_id), ("volume", volumes_before[0].id)] {
                write_db
                    .execute_unprepared(&format!(
                        "CREATE TRIGGER check_{table}_rollback BEFORE DELETE ON {table}
                     WHEN OLD.id = {id} BEGIN
                     SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM run WHERE id = {active_run}
                     AND status = 'Terminated' AND termination_reason = 'Failed'
                     AND terminated_at IS NOT NULL)
                     THEN RAISE(ABORT, 'rollback before run reconciliation') END; END;"
                    ))
                    .await
                    .unwrap();
            }
        }

        let runtime_owner = microsandbox_runtime::ipc::try_acquire_lifecycle_guard(
            &local.config().run_dir(),
            &config.spec.name,
        )
        .unwrap()
        .unwrap();
        let error = local
            .rollback_failed_startup(write_db, sandbox_id, &config.spec.name, &created)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("startup cleanup pending"),
            "{error}"
        );
        assert_eq!(
            sandbox_entity::Entity::find_by_id(sandbox_id)
                .one(write_db)
                .await
                .unwrap(),
            Some(sandbox_before)
        );
        assert_eq!(
            run_entity::Entity::find_by_id(active_run)
                .one(write_db)
                .await
                .unwrap(),
            Some(run_before)
        );
        assert_eq!(
            volume_entity::Entity::find().all(write_db).await.unwrap(),
            volumes_before
        );
        if with_created_volume {
            assert_eq!(
                fs::read(volume_path.join("sentinel")).unwrap(),
                b"still owned"
            );
        }

        drop(runtime_owner);
        // A concurrent test's fork may still hold a CLOEXEC copy until exec. A pending
        // cleanup is correct in that interval; only retry that explicit ownership refusal.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match local
                    .rollback_failed_startup(write_db, sandbox_id, &config.spec.name, &created)
                    .await
                {
                    Ok(()) => break,
                    Err(error) => {
                        assert!(
                            error.to_string().contains("startup cleanup pending"),
                            "{error}"
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    }
                }
            }
        })
        .await
        .expect("runtime ownership was not released before rollback");
        if with_created_volume {
            assert!(!volume_path.exists());
            assert!(
                volume_entity::Entity::find()
                    .all(write_db)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(
                sandbox_entity::Entity::find_by_id(sandbox_id)
                    .one(write_db)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                run_entity::Entity::find_by_id(active_run)
                    .one(write_db)
                    .await
                    .unwrap()
                    .is_none()
            );
        } else {
            let sandbox = sandbox_entity::Entity::find_by_id(sandbox_id)
                .one(write_db)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(sandbox.status, SandboxStatus::Stopped);
            let run = run_entity::Entity::find_by_id(active_run)
                .one(write_db)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(run.status, run_entity::RunStatus::Terminated);
            assert_eq!(
                run.termination_reason,
                Some(run_entity::TerminationReason::Failed)
            );
            assert!(run.terminated_at.is_some());
        }
    }

    #[tokio::test]
    async fn failed_startup_rollback_waits_for_runtime_before_stopping_record() {
        exercise_failed_startup_rollback(false, SandboxStatus::Starting).await;
    }

    #[tokio::test]
    async fn failed_startup_rollback_preserves_owned_volumes_then_reconciles_before_deletion() {
        exercise_failed_startup_rollback(true, SandboxStatus::Starting).await;
    }

    #[tokio::test]
    async fn post_readiness_rollback_preserves_live_row_restore_intent_and_storage() {
        // Pin/workdir validation occurs after Running publication. Both the no-volume
        // and created-volume paths must keep this live state until the owner releases it.
        exercise_failed_startup_rollback(false, SandboxStatus::Running).await;
        exercise_failed_startup_rollback(true, SandboxStatus::Running).await;
    }

    #[tokio::test]
    async fn deferred_command_reservation_installs_guard_atomically_and_deletes_it_with_destination()
     {
        use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
        let temp = tempdir().unwrap();
        let pools = open_test_pools(&temp.path().join("test.db")).await;
        let db = pools.write();
        let mut config = test_config("bound");
        config
            .deferred_command_bindings
            .env
            .insert("TOKEN".into(), "token".into());
        let sandbox_id = LocalContext::insert_sandbox_record(db, &config)
            .await
            .unwrap();
        let try_legacy_run = |id| {
            run_entity::Entity::insert(run_entity::ActiveModel {
                sandbox_id: Set(id),
                status: Set(run_entity::RunStatus::Running),
                ..Default::default()
            })
            .exec(db)
        };
        assert!(
            try_legacy_run(sandbox_id)
                .await
                .unwrap_err()
                .to_string()
                .contains("outstanding command bindings")
        );
        let ordinary = LocalContext::insert_sandbox_record(db, &test_config("ordinary"))
            .await
            .unwrap();
        assert!(try_legacy_run(ordinary).await.is_ok());
        let persisted = sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(db)
            .await
            .unwrap()
            .unwrap();
        assert!(!persisted.config.contains("token"));
        let guard_count = || {
            db.query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT count(*) AS n FROM sandbox_command_bindings",
            ))
        };
        assert_eq!(
            guard_count()
                .await
                .unwrap()
                .unwrap()
                .try_get::<i64>("", "n")
                .unwrap(),
            1
        );
        LocalContext::delete_sandbox_record(db, sandbox_id)
            .await
            .unwrap();
        assert_eq!(
            guard_count()
                .await
                .unwrap()
                .unwrap()
                .try_get::<i64>("", "n")
                .unwrap(),
            0
        );

        config
            .deferred_command_bindings
            .env
            .insert("BAD=KEY".into(), "token".into());
        assert!(
            LocalContext::insert_sandbox_record(db, &config)
                .await
                .is_err()
        );
        assert!(
            sandbox_entity::Entity::find()
                .filter(sandbox_entity::Column::Name.eq("bound"))
                .one(db)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn retained_execution_limits_guard_only_the_restored_sandbox() {
        use microsandbox_types::ExecLimits;
        use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
        let temp = tempdir().unwrap();
        let pools = open_test_pools(&temp.path().join("limits.db")).await;
        let db = pools.write();
        let mut config = test_config("limited");
        config.restored_exec_limits = Some(ExecLimits {
            max_executions: 2,
            ..Default::default()
        });
        let limited = LocalContext::insert_sandbox_record(db, &config)
            .await
            .unwrap();
        let try_legacy_start = |id| {
            run_entity::Entity::insert(run_entity::ActiveModel {
                sandbox_id: Set(id),
                status: Set(run_entity::RunStatus::Running),
                ..Default::default()
            })
            .exec(db)
        };
        assert!(
            try_legacy_start(limited)
                .await
                .unwrap_err()
                .to_string()
                .contains("saved execution limits")
        );

        let mut ordinary = test_config("ordinary");
        ordinary.restored_exec_limits = Some(ExecLimits::default());
        let id = LocalContext::insert_sandbox_record(db, &ordinary)
            .await
            .unwrap();
        try_legacy_start(id).await.unwrap();
        LocalContext::delete_sandbox_record(db, limited)
            .await
            .unwrap();
        let any_policy = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT 1 FROM sandbox_restored_exec_limits LIMIT 1",
            ))
            .await
            .unwrap();
        assert!(any_policy.is_none());

        config.restored_exec_limits.as_mut().unwrap().max_executions = 0;
        assert!(
            LocalContext::insert_sandbox_record(db, &config)
                .await
                .is_err()
        );
        assert!(
            sandbox_entity::Entity::find()
                .filter(sandbox_entity::Column::Name.eq("limited"))
                .one(db)
                .await
                .unwrap()
                .is_none()
        );
    }

    fn test_config(name: impl Into<String>) -> SandboxConfig {
        SandboxConfig {
            spec: microsandbox_types::SandboxSpec {
                name: name.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn test_config_with_rootfs(name: impl Into<String>, image: RootfsSource) -> SandboxConfig {
        SandboxConfig {
            spec: microsandbox_types::SandboxSpec {
                name: name.into(),
                image,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn bind_rootfs(path: impl Into<PathBuf>) -> RootfsSource {
        RootfsSource::Bind {
            path: path.into(),
            follow_root_symlinks: false,
        }
    }

    fn unique_temp_path(suffix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("microsandbox-rootfs-{suffix}-{nanos}"))
    }

    fn dead_pid() -> i32 {
        let mut pid = 900_000;
        while LocalContext::pid_is_alive(pid) {
            pid += 1;
        }
        pid
    }

    #[tokio::test]
    async fn test_runtime_name_validation_uses_explicit_backend_paths() {
        let temp = tempfile::Builder::new()
            .prefix("msb")
            .tempdir_in("/tmp")
            .unwrap();
        let home = temp.path().join("msb-home");
        let backend = LocalContext::builder()
            .config_path(home.join("config.json"))
            .managed_config_path(home.join("managed.json"))
            .home(&home)
            .build()
            .unwrap();

        backend
            .validate_sandbox_name_for_runtime("sdk-socket-test")
            .unwrap();
    }

    #[tokio::test]
    async fn snapshot_root_growth_policy_refuses_before_staging_or_replacement() {
        // Keep policy admission ahead of the unrelated Unix socket path-length guard.
        #[cfg(unix)]
        let temp = tempfile::Builder::new()
            .prefix("msb-growth-policy-")
            .tempdir_in("/tmp")
            .unwrap();
        #[cfg(not(unix))]
        let temp = tempdir().unwrap();
        let home = temp.path().join("home");
        fs::create_dir(&home).unwrap();
        fs::write(
            home.join("managed.json"),
            r#"{"overrides":{"sandbox_defaults":{"oci":{"root_disk":{"kind":"managed","size_mib":512}}}}}"#,
        )
        .unwrap();
        // Managed policy is security-sensitive; do not depend on the host's umask.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(home.join("managed.json"), fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let backend = Arc::new(
            crate::test_support::local_backend_builder(&home)
                .build()
                .unwrap(),
        );
        assert_eq!(
            serde_json::to_value(&backend.config().sandbox_defaults.oci.root_disk).unwrap()["size_mib"],
            512
        );
        let pools = backend.db().await.unwrap();
        let mut config = test_config_with_rootfs(
            "protected",
            RootfsSource::oci("example.invalid/saved:latest"),
        );
        let RootfsSource::Oci(image) = &mut config.spec.image else {
            unreachable!()
        };
        image.root_disk = Some(crate::sandbox::RootDisk::managed(256));
        config.spec.pull_policy = PullPolicy::Never;
        let id = LocalContext::insert_sandbox_record_with_status(
            pools.write(),
            &config,
            SandboxStatus::Stopped,
        )
        .await
        .unwrap();
        let original = sandbox_entity::Entity::find_by_id(id)
            .one(pools.read())
            .await
            .unwrap()
            .unwrap();
        let directory = backend.sandboxes_dir().join("protected");
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("keep"), b"existing destination").unwrap();

        // The policy check must win before even opening a snapshot disk. An invalid
        // sentinel makes accidental filesystem preparation fail with a different error.
        let source = temp.path().join("sealed.raw");
        fs::write(&source, b"sealed source must not be opened for growth").unwrap();
        config.snapshot_parent = Some("captured".into());
        config.snapshot_upper_layers = vec![microsandbox_runtime::launch::RootfsUpperLayerConfig {
            path: source.clone(),
            format: "raw".into(),
        }];
        config.snapshot_root_growth_mib = Some(1024);
        config.replace_existing = true;
        let error = match backend
            .create_sandbox(backend.clone(), config, SpawnMode::Attached, None)
            .await
        {
            Ok(_) => panic!("managed disk policy must reject conflicting growth"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("1024 MiB conflicts with managed root capacity 512 MiB"),
            "{error}"
        );
        assert_eq!(
            fs::read(&source).unwrap(),
            b"sealed source must not be opened for growth"
        );
        assert_eq!(
            fs::read(directory.join("keep")).unwrap(),
            b"existing destination"
        );
        assert_eq!(
            sandbox_entity::Entity::find_by_id(id)
                .one(pools.read())
                .await
                .unwrap()
                .unwrap(),
            original
        );
        assert_eq!(
            fs::read_dir(backend.sandboxes_dir()).unwrap().count(),
            1,
            "policy refusal must not create a private staging directory"
        );
    }

    #[tokio::test]
    async fn test_create_local_missing_snapshot_descriptor_preserves_replace_target() {
        let temp = tempdir().unwrap();
        let backend = Arc::new(
            crate::test_support::local_backend_builder(temp.path().join("home"))
                .build()
                .unwrap(),
        );
        let pools = backend.db().await.unwrap();
        let mut config = test_config_with_rootfs(
            "replaceable",
            RootfsSource::oci("example.invalid/snapshot-resolved:missing"),
        );
        // A regression must fail locally after target preparation, never pull or boot an image.
        config.spec.pull_policy = PullPolicy::Never;
        let sandbox_id = LocalContext::insert_sandbox_record_with_status(
            pools.write(),
            &config,
            SandboxStatus::Stopped,
        )
        .await
        .unwrap();
        let original = sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(pools.read())
            .await
            .unwrap()
            .unwrap();
        let sandbox_dir = backend.sandboxes_dir().join(&config.spec.name);
        fs::create_dir_all(&sandbox_dir).unwrap();
        let sentinel = sandbox_dir.join("keep");
        fs::write(&sentinel, b"existing sandbox state").unwrap();

        let snapshot_dir = temp.path().join("snapshot-without-descriptor");
        fs::create_dir(&snapshot_dir).unwrap();
        // A loose upper file is not an artifact and must not become an implicit fallback.
        fs::write(snapshot_dir.join("upper.ext4"), b"unvalidated disk").unwrap();
        config.snapshot_reference = Some(SnapshotReference::path(snapshot_dir.to_string_lossy()));
        config.replace_existing = true;

        let error = match backend
            .create_sandbox(backend.clone(), config, SpawnMode::Attached, None)
            .await
        {
            Ok(_) => panic!("snapshot descriptor must be validated before replacement"),
            Err(error) => error,
        };

        assert!(
            matches!(&error, crate::MicrosandboxError::SnapshotNotFound(_)),
            "{error}"
        );
        assert_eq!(fs::read(sentinel).unwrap(), b"existing sandbox state");
        let preserved = sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(pools.read())
            .await
            .unwrap()
            .expect("snapshot resolution must not delete the existing sandbox row");
        assert_eq!(preserved, original);
    }

    #[tokio::test]
    async fn test_create_local_stored_snapshot_reference_error_is_not_ignored() {
        let temp = tempdir().unwrap();
        let backend = Arc::new(
            crate::test_support::local_backend_builder(temp.path().join("home"))
                .build()
                .unwrap(),
        );
        let mut config = test_config_with_rootfs(
            "missing-snapshot",
            bind_rootfs(temp.path().join("missing-rootfs")),
        );
        config.snapshot_reference = Some(SnapshotReference::path(
            temp.path().join("missing-snapshot").to_string_lossy(),
        ));

        let error = match backend
            .create_sandbox(backend.clone(), config, SpawnMode::Attached, None)
            .await
        {
            Ok(_) => panic!("stored snapshot references must be resolved before ordinary creation"),
            Err(error) => error,
        };

        assert!(
            matches!(&error, crate::MicrosandboxError::SnapshotNotFound(_)),
            "{error}"
        );
        assert!(!backend.sandboxes_dir().join("missing-snapshot").exists());
    }

    #[tokio::test]
    async fn test_create_local_rejects_snapshot_patches_before_creating_directory() {
        // Keep Unix socket paths short; Windows uses named pipes instead.
        let temp_root = if cfg!(windows) {
            std::env::temp_dir()
        } else {
            std::path::PathBuf::from("/tmp")
        };
        let temp = tempfile::Builder::new()
            .prefix("msb")
            .tempdir_in(temp_root)
            .unwrap();
        let backend = Arc::new(
            crate::test_support::local_backend_builder(temp.path().join("home"))
                .build()
                .unwrap(),
        );
        let mut config = test_config_with_rootfs(
            "patched-snapshot",
            RootfsSource::oci("registry.invalid/review-never-pulled:missing"),
        );
        // A regression would either pull this uncached image or create the sandbox
        // directory before rejecting the incompatible combination.
        config.spec.pull_policy = PullPolicy::Never;
        config.spec.patches = vec![microsandbox_types::Patch::Text {
            path: "/etc/motd".to_string(),
            content: "hello".to_string(),
            mode: None,
            replace: true,
        }];
        config.snapshot_upper_source = Some(temp.path().join("upper.ext4"));

        let error = match backend
            .create_sandbox(backend.clone(), config, SpawnMode::Attached, None)
            .await
        {
            Ok(_) => panic!("patches must be rejected when combined with from_snapshot"),
            Err(error) => error,
        };

        assert_eq!(
            error.to_string(),
            "invalid config: patches cannot be combined with from_snapshot"
        );
        // A rejected create must leave no sandbox name behind, otherwise retries under
        // the same name fail with "sandbox already exists" (see #1550).
        assert!(!backend.sandboxes_dir().join("patched-snapshot").exists());
    }

    #[tokio::test]
    async fn test_create_local_validates_direct_config_mounts() {
        let temp = tempfile::Builder::new()
            .prefix("msb")
            .tempdir_in("/tmp")
            .unwrap();
        let rootfs = temp.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();
        let backend = Arc::new(
            LocalContext::builder()
                .config_path(temp.path().join("home").join("config.json"))
                .managed_config_path(temp.path().join("home").join("managed.json"))
                .home(temp.path().join("home"))
                .build()
                .unwrap(),
        );
        let backend_trait: Arc<dyn Context> = backend.clone();
        let mut config = test_config_with_rootfs("bad-mounts", bind_rootfs(rootfs));
        config.spec.mounts = vec![
            VolumeMount::Tmpfs {
                guest: "/dup".to_string(),
                size_mib: None,
                options: MountOptions::default(),
            },
            VolumeMount::Tmpfs {
                guest: "/dup".to_string(),
                size_mib: None,
                options: MountOptions::default(),
            },
        ];

        let err = match backend
            .create_sandbox(backend_trait, config, SpawnMode::Attached, None)
            .await
        {
            Ok(_) => panic!("expected invalid direct-config mounts to be rejected"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("multiple volumes cannot mount"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn test_create_local_rejects_invalid_hostname_before_rootfs_validation() {
        let temp = tempdir().unwrap();
        let backend = Arc::new(
            LocalContext::builder()
                .config_path(temp.path().join("config.json"))
                .managed_config_path(temp.path().join("managed.json"))
                .home(temp.path())
                .build()
                .unwrap(),
        );
        let mut config = test_config_with_rootfs("test", bind_rootfs(unique_temp_path("missing")));
        config.spec.runtime.hostname = Some("y".repeat(MAX_HOSTNAME_BYTES + 1));

        let err = match backend
            .create_sandbox(backend.clone(), config, SpawnMode::Attached, None)
            .await
        {
            Ok(_) => panic!("invalid hostname should fail before sandbox creation"),
            Err(err) => err,
        };

        assert_eq!(
            err.to_string(),
            "invalid config: hostname is too long: 65 bytes (max 64)"
        );
    }

    #[test]
    fn test_validate_rootfs_source_missing_bind_path() {
        let path = unique_temp_path("missing");
        let err = LocalContext::validate_rootfs_source(&bind_rootfs(path.clone())).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "invalid config: rootfs bind path does not exist: {}",
                path.display()
            )
        );
    }

    #[test]
    fn test_validate_rootfs_source_bind_path_must_be_directory() {
        let path = unique_temp_path("file");
        fs::write(&path, b"not a directory").unwrap();

        let err = LocalContext::validate_rootfs_source(&bind_rootfs(path.clone())).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "invalid config: rootfs bind path is not a directory: {}",
                path.display()
            )
        );

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_validate_rootfs_source_existing_bind_directory() {
        let path = unique_temp_path("dir");
        fs::create_dir(&path).unwrap();

        LocalContext::validate_rootfs_source(&bind_rootfs(path.clone())).unwrap();

        fs::remove_dir(path).unwrap();
    }

    #[tokio::test]
    async fn incomplete_restore_survives_failure_until_explicit_completion() {
        let temp = tempdir().unwrap();
        let pools = open_test_pools(&temp.path().join("test.db")).await;
        let mut config = test_config_with_rootfs("pending", bind_rootfs(temp.path().to_path_buf()));
        config.checkpoint_restore = Some(microsandbox_runtime::launch::CheckpointRestoreConfig {
            memory_descriptor: false,
            network_gateway_mac: None,
            external_mount_policy: Default::default(),
            external_mounts: Vec::new(),
            unavailable_disks: Default::default(),
            local_branch: false,
            forked: true,
            closure: temp.path().join("checkpoint"),
            checkpoint_root: "blake3:pending".into(),
            checkpoint_id: "pending".into(),
        });
        let mut options = crate::SandboxConfigPatch::new();
        options.spec.runtime.workdir = Some(None);
        options.spec.runtime.cmd = Some(Vec::new());
        config.caller_config_overrides = Some(Box::new(options));
        let id = LocalContext::insert_sandbox_record(pools.write(), &config)
            .await
            .unwrap();
        LocalContext::update_sandbox_status(pools.write(), id, SandboxStatus::Stopped)
            .await
            .unwrap();
        let model = sandbox_entity::Entity::find_by_id(id)
            .one(pools.read())
            .await
            .unwrap()
            .unwrap();
        let pending: SandboxConfig = serde_json::from_str(&model.config).unwrap();
        assert!(
            LocalContext::validate_completed_restore(&pending)
                .unwrap_err()
                .to_string()
                .contains("refusing a cold boot")
        );
        assert!(pending.checkpoint_restore.as_ref().unwrap().forked);

        // Ordinary post-success/snapshot projections must not perpetuate one-shot restore input.
        assert!(pending.clone_for_persistence().checkpoint_restore.is_none());
        let mut restored = config.clone();
        restored.spec.resources.cpus = 2;
        restored.spec.resources.memory_mib = 768;
        LocalContext::complete_sandbox_restore(pools.write(), id, &config, &restored)
            .await
            .unwrap();
        let model = sandbox_entity::Entity::find_by_id(id)
            .one(pools.read())
            .await
            .unwrap()
            .unwrap();
        let completed =
            SandboxConfig::from_stored(&model.config, model.caller_config_overrides.as_deref())
                .unwrap();
        let options = completed.caller_config_overrides.as_ref().unwrap();
        assert_eq!(options.spec.runtime.workdir, Some(None));
        assert_eq!(options.spec.runtime.cmd, Some(Vec::new()));
        assert!(options.spec.init.is_none());
        assert!(completed.checkpoint_restore.is_none());
        assert_eq!(completed.spec.name, "pending");
        assert_eq!(completed.spec.resources.cpus, 2);
        assert_eq!(completed.spec.resources.memory_mib, 768);
        LocalContext::validate_completed_restore(&completed).unwrap();
    }

    #[tokio::test]
    async fn restore_completion_preserves_concurrent_desired_resource_edits() {
        let temp = tempdir().unwrap();
        let pools = open_test_pools(&temp.path().join("test.db")).await;
        let mut construction =
            test_config_with_rootfs("edited", bind_rootfs(temp.path().to_path_buf()));
        construction.spec.resources.cpus = 1;
        construction.spec.resources.max_cpus = 4;
        construction.spec.resources.memory_mib = 256;
        construction.spec.resources.max_memory_mib = 1024;
        let mut edited = construction.clone();
        edited.spec.resources.cpus = 3;
        let id = LocalContext::insert_sandbox_record(pools.write(), &edited)
            .await
            .unwrap();
        let mut restored = construction.clone();
        restored.spec.resources.cpus = 2;
        restored.spec.resources.memory_mib = 768;
        LocalContext::complete_sandbox_restore(pools.write(), id, &construction, &restored)
            .await
            .unwrap();
        let model = sandbox_entity::Entity::find_by_id(id)
            .one(pools.read())
            .await
            .unwrap()
            .unwrap();
        let completed: SandboxConfig = serde_json::from_str(&model.config).unwrap();
        assert_eq!(completed.spec.resources.cpus, 3);
        assert_eq!(completed.spec.resources.memory_mib, 768);
        assert_eq!(completed.spec.resources.max_memory_mib, 1024);
    }

    #[tokio::test]
    async fn test_persist_oci_manifest_pin_upserts_rootfs_record() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let mut config = test_config_with_rootfs(
            "pinned",
            RootfsSource::Oci(OciRootfsSource {
                reference: "docker.io/library/alpine".into(),
                root_disk: None,
            }),
        );
        config.manifest_digest = Some("sha256:aaaa".into());
        let sandbox_id = LocalContext::insert_sandbox_record(pools.write(), &config)
            .await
            .unwrap();

        // First pin (no matching manifest in DB, so manifest_id will be None).
        LocalContext::persist_oci_manifest_pin(
            pools.write(),
            sandbox_id,
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .await
        .unwrap();

        // Second pin replaces the first.
        LocalContext::persist_oci_manifest_pin(
            pools.write(),
            sandbox_id,
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        )
        .await
        .unwrap();

        let pins = sandbox_rootfs_entity::Entity::find()
            .all(pools.write())
            .await
            .unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].sandbox_id, sandbox_id);
        assert_eq!(pins[0].mode, "erofs");
        assert_eq!(pins[0].manifest_id, None);
    }

    #[tokio::test]
    async fn test_persist_oci_manifest_pin_replaces_stale_pin_for_different_digest() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let mut config = test_config_with_rootfs(
            "recreated",
            RootfsSource::Oci(OciRootfsSource {
                reference: "docker.io/library/alpine".into(),
                root_disk: None,
            }),
        );
        config.manifest_digest = Some("sha256:aaaa".into());
        let sandbox_id = LocalContext::insert_sandbox_record(pools.write(), &config)
            .await
            .unwrap();

        LocalContext::persist_oci_manifest_pin(
            pools.write(),
            sandbox_id,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .await
        .unwrap();

        // Replacing with a different digest should delete the old pin.
        LocalContext::persist_oci_manifest_pin(
            pools.write(),
            sandbox_id,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .await
        .unwrap();

        let pins = sandbox_rootfs_entity::Entity::find()
            .all(pools.write())
            .await
            .unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].sandbox_id, sandbox_id);
        assert_eq!(pins[0].mode, "erofs");
        assert_eq!(pins[0].manifest_id, None);
    }

    #[tokio::test]
    async fn test_insert_sandbox_record_persists_manifest_digest_in_config_json() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let mut config = test_config_with_rootfs(
            "persisted-digest",
            RootfsSource::Oci(OciRootfsSource {
                reference: "docker.io/library/alpine".into(),
                root_disk: None,
            }),
        );
        config.manifest_digest = Some("sha256:abc123".into());

        let sandbox_id = LocalContext::insert_sandbox_record(pools.write(), &config)
            .await
            .unwrap();
        let row = sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(pools.write())
            .await
            .unwrap()
            .unwrap();
        let decoded: SandboxConfig = serde_json::from_str(&row.config).unwrap();

        assert_eq!(decoded.manifest_digest, config.manifest_digest);
    }

    #[tokio::test]
    async fn test_local_create_record_stays_starting_until_readiness_publication() {
        let temp = tempdir().unwrap();
        let pools = open_test_pools(&temp.path().join("test.db")).await;
        let config = test_config("booting");

        let sandbox_id = LocalContext::insert_starting_sandbox_record(pools.write(), &config, None)
            .await
            .unwrap();
        let row = sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(pools.read())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(row.status, SandboxStatus::Starting);
        assert!(
            LocalContext::compare_and_set_sandbox_status(
                pools.write(),
                sandbox_id,
                &[SandboxStatus::Starting],
                SandboxStatus::Running,
            )
            .await
            .unwrap()
        );
        let ready = sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(pools.read())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ready.status, SandboxStatus::Running);
    }

    #[tokio::test]
    async fn test_desired_and_active_configs_persist_mount_owner() {
        let temp = tempdir().unwrap();
        let pools = open_test_pools(&temp.path().join("test.db")).await;
        let mut config = test_config("owned-mount");
        config.spec.mounts.push(VolumeMount::Bind {
            host: "/host/data".into(),
            guest: "/data".into(),
            options: MountOptions {
                override_uid: Some(1000),
                override_gid: Some(1001),
                ..MountOptions::default()
            },
            stat_virtualization: StatVirtualization::Strict,
            host_permissions: HostPermissions::Private,
            follow_root_symlinks: false,
            quota_mib: None,
        });

        let sandbox_id = LocalContext::insert_sandbox_record(pools.write(), &config)
            .await
            .unwrap();
        LocalContext::update_sandbox_active_config(pools.write(), sandbox_id, &config)
            .await
            .unwrap();

        let row = sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(pools.read())
            .await
            .unwrap()
            .unwrap();
        for persisted in [row.config.as_str(), row.active_config.as_deref().unwrap()] {
            let decoded: SandboxConfig = serde_json::from_str(persisted).unwrap();
            let options = match &decoded.spec.mounts[0] {
                VolumeMount::Bind { options, .. } => options,
                other => panic!("expected bind mount, got {other:?}"),
            };
            assert_eq!(options.override_uid, Some(1000));
            assert_eq!(options.override_gid, Some(1001));
        }
    }

    #[tokio::test]
    async fn test_insert_sandbox_record_persists_label_projection() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;
        let mut config = test_config("labelled");
        config.spec.labels.insert("team".into(), "metrics".into());
        config.spec.labels.insert("tier".into(), "gold".into());

        let sandbox_id = LocalContext::insert_sandbox_record(pools.write(), &config)
            .await
            .unwrap();
        let mut rows = sandbox_label_entity::Entity::find()
            .filter(sandbox_label_entity::Column::SandboxId.eq(sandbox_id))
            .all(pools.read())
            .await
            .unwrap();
        rows.sort_by(|left, right| left.key.cmp(&right.key));

        assert_eq!(
            rows.into_iter()
                .map(|row| (row.key, row.value))
                .collect::<Vec<_>>(),
            vec![
                ("team".into(), "metrics".into()),
                ("tier".into(), "gold".into()),
            ]
        );
    }

    #[tokio::test]
    async fn test_label_rebuild_migrates_serialized_sandbox_config() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;
        let mut config = test_config("migration-labels");
        config.spec.labels.insert("team".into(), "metrics".into());
        config.spec.labels.insert("tier".into(), "gold".into());
        let sandbox_id = LocalContext::insert_sandbox_record(pools.write(), &config)
            .await
            .unwrap();

        sandbox_label_entity::Entity::delete_many()
            .filter(sandbox_label_entity::Column::SandboxId.eq(sandbox_id))
            .exec(pools.write())
            .await
            .unwrap();
        pools
            .write()
            .inner()
            .execute_unprepared(
                "DELETE FROM seaql_migrations \
                 WHERE version = 'm20260810_000001_rebuild_sandbox_labels'",
            )
            .await
            .unwrap();

        Migrator::up(pools.write().inner(), None).await.unwrap();

        let mut rows = sandbox_label_entity::Entity::find()
            .filter(sandbox_label_entity::Column::SandboxId.eq(sandbox_id))
            .all(pools.read())
            .await
            .unwrap();
        rows.sort_by(|left, right| left.key.cmp(&right.key));
        assert_eq!(
            rows.into_iter()
                .map(|row| (row.key, row.value))
                .collect::<Vec<_>>(),
            vec![
                ("team".into(), "metrics".into()),
                ("tier".into(), "gold".into()),
            ]
        );
    }

    #[tokio::test]
    async fn test_prepare_create_target_rejects_existing_state_without_force() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let sandbox_dir = temp.path().join("sandboxes").join("existing");
        fs::create_dir_all(&sandbox_dir).unwrap();

        let config = test_config("existing");

        let run_dir = temp.path().join("run");
        let err = LocalContext::prepare_create_target(
            &pools,
            &config,
            &sandbox_dir,
            &run_dir,
            None,
            &mut None,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_transition_guard_serializes_conflict_check_and_insert() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = Arc::new(open_test_pools(&db_path).await);
        let run_dir = temp.path().join("run");
        let sandbox_dir = temp.path().join("sandboxes").join("contended");
        let config = test_config("contended");

        let winner = LocalContext::acquire_sandbox_transition_guard(&run_dir, "contended")
            .await
            .unwrap();
        LocalContext::prepare_create_target(
            &pools,
            &config,
            &sandbox_dir,
            &run_dir,
            None,
            &mut None,
        )
        .await
        .unwrap();
        LocalContext::insert_sandbox_record(pools.write(), &config)
            .await
            .unwrap();

        // A distinct file handle must observe the process-held lock, proving the guard is not an
        // in-process mutex and therefore also coordinates independent SDK processes.
        let competing_file = microsandbox_utils::process_lock::open_lock_file(
            &super::sandbox_transition_lock_path(&run_dir, "contended"),
        )
        .unwrap();
        assert!(
            !tokio::task::spawn_blocking(move || {
                microsandbox_utils::process_lock::try_lock_exclusive(&competing_file)
            })
            .await
            .unwrap()
            .unwrap()
        );

        let contender_pools = pools.clone();
        let contender_run_dir = run_dir.clone();
        let contender_sandbox_dir = sandbox_dir.clone();
        let mut contender = tokio::spawn(async move {
            let _guard =
                LocalContext::acquire_sandbox_transition_guard(&contender_run_dir, "contended")
                    .await?;
            LocalContext::prepare_create_target(
                &contender_pools,
                &test_config("contended"),
                &contender_sandbox_dir,
                &contender_run_dir,
                None,
                &mut None,
            )
            .await
        });

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut contender)
                .await
                .is_err(),
            "the losing creator must wait while the winner owns the creation lock"
        );
        drop(winner);

        let error = tokio::time::timeout(std::time::Duration::from_secs(5), contender)
            .await
            .expect("losing creator did not resume after lock release")
            .unwrap()
            .unwrap_err();
        assert!(matches!(
            error,
            crate::MicrosandboxError::SandboxAlreadyExists(_)
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn replacement_preserves_live_legacy_runtime() {
        for tracked in [false, true] {
            let temp = tempfile::tempdir_in("/tmp").unwrap();
            let pools = open_test_pools(&temp.path().join("test.db")).await;
            let run_dir = temp.path().join("run");
            let sandbox_dir = temp.path().join("sandboxes/legacy");
            fs::create_dir_all(&sandbox_dir).unwrap();
            let marker = sandbox_dir.join("state");
            fs::write(&marker, b"runtime state").unwrap();
            let mut config = test_config("legacy");
            config.replace_existing = true;
            let sandbox_id = if tracked {
                Some(
                    LocalContext::insert_starting_sandbox_record(pools.write(), &config, None)
                        .await
                        .unwrap(),
                )
            } else {
                None
            };
            let socket = RuntimeSocketPaths::new(&run_dir, "legacy").legacy_agent;
            fs::create_dir_all(socket.parent().unwrap()).unwrap();
            let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
            let _transition = LocalContext::acquire_sandbox_transition_guard(&run_dir, "legacy")
                .await
                .unwrap();

            let error = LocalContext::prepare_create_target(
                &pools,
                &config,
                &sandbox_dir,
                &run_dir,
                None,
                &mut None,
            )
            .await
            .expect_err("replacement must preserve a live legacy runtime");
            assert!(matches!(
                error,
                crate::MicrosandboxError::SandboxStillRunning(_)
            ));
            assert!(socket.exists());
            assert_eq!(fs::read(&marker).unwrap(), b"runtime state");
            if let Some(id) = sandbox_id {
                let model = sandbox_entity::Entity::find_by_id(id)
                    .one(pools.read())
                    .await
                    .unwrap()
                    .expect("replacement must preserve the sandbox row");
                assert_eq!(model.status, SandboxStatus::Starting);
            }

            drop(listener);
            fs::remove_file(&socket).unwrap();
            LocalContext::prepare_create_target(
                &pools,
                &config,
                &sandbox_dir,
                &run_dir,
                None,
                &mut None,
            )
            .await
            .unwrap();
            assert!(!sandbox_dir.exists());
            if let Some(id) = sandbox_id {
                assert!(
                    sandbox_entity::Entity::find_by_id(id)
                        .one(pools.read())
                        .await
                        .unwrap()
                        .is_some_and(|row| row.name.starts_with(".msb-retained-"))
                );
            }
        }
    }

    #[tokio::test]
    async fn test_prepare_create_target_force_replaces_stopped_sandbox_state() {
        #[cfg(unix)]
        let temp = tempfile::Builder::new()
            .prefix("msb-replace")
            .tempdir_in("/tmp")
            .unwrap();
        #[cfg(not(unix))]
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let sandbox_dir = temp.path().join("sandboxes").join("replaceable");
        fs::create_dir_all(sandbox_dir.join("rw")).unwrap();
        let config = test_config("replaceable");
        let sandbox_id = LocalContext::insert_sandbox_record(pools.write(), &config)
            .await
            .unwrap();
        LocalContext::update_sandbox_status(pools.write(), sandbox_id, SandboxStatus::Stopped)
            .await
            .unwrap();

        let mut forced = test_config("replaceable");
        forced.replace_existing = true;

        let run_dir = temp.path().join("run");
        #[cfg(unix)]
        let socket_paths = {
            let paths = RuntimeSocketPaths::new(&run_dir, "replaceable");
            fs::create_dir_all(&paths.canonical_dir).unwrap();
            fs::write(&paths.agent, b"stale").unwrap();
            fs::write(&paths.control, b"stale").unwrap();
            paths.publish_legacy_agent_link(&paths.agent).unwrap();
            paths.publish_legacy_control_link(&paths.control).unwrap();
            paths
        };
        LocalContext::prepare_create_target(
            &pools,
            &forced,
            &sandbox_dir,
            &run_dir,
            None,
            &mut None,
        )
        .await
        .unwrap();

        assert!(!sandbox_dir.exists());
        #[cfg(unix)]
        for path in [
            &socket_paths.agent,
            &socket_paths.control,
            &socket_paths.legacy_agent,
            &socket_paths.legacy_control,
            &socket_paths.canonical_dir,
        ] {
            assert!(std::fs::symlink_metadata(path).is_err());
        }
        assert!(
            sandbox_entity::Entity::find_by_id(sandbox_id)
                .one(pools.write())
                .await
                .unwrap()
                .is_some_and(|row| row.name.starts_with(".msb-retained-"))
        );
    }

    #[tokio::test]
    async fn test_prepare_create_target_force_replaces_stale_running_sandbox_state() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let sandbox_dir = temp.path().join("sandboxes").join("stale-running");
        fs::create_dir_all(sandbox_dir.join("rw")).unwrap();
        let config = test_config("stale-running");
        let sandbox_id = LocalContext::insert_sandbox_record(pools.write(), &config)
            .await
            .unwrap();

        let run = run_entity::ActiveModel {
            sandbox_id: Set(sandbox_id),
            pid: Set(Some(dead_pid())),
            status: Set(run_entity::RunStatus::Running),
            ..Default::default()
        };
        run_entity::Entity::insert(run)
            .exec(pools.write())
            .await
            .unwrap();

        let mut forced = test_config("stale-running");
        forced.replace_existing = true;

        let run_dir = temp.path().join("run");
        LocalContext::prepare_create_target(
            &pools,
            &forced,
            &sandbox_dir,
            &run_dir,
            None,
            &mut None,
        )
        .await
        .unwrap();

        assert!(!sandbox_dir.exists());
        assert!(
            sandbox_entity::Entity::find_by_id(sandbox_id)
                .one(pools.write())
                .await
                .unwrap()
                .is_some_and(|row| row.name.starts_with(".msb-retained-"))
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_prepare_create_target_force_replaces_running_sandbox() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let pools = open_test_pools(&db_path).await;

        let sandbox_dir = temp.path().join("sandboxes").join("running");
        fs::create_dir_all(&sandbox_dir).unwrap();
        let config = test_config("running");
        let sandbox_id = LocalContext::insert_sandbox_record(pools.write(), &config)
            .await
            .unwrap();

        let child = Command::new("sleep").arg("30").spawn().unwrap();
        let live_pid = child.id() as i32;
        let waiter = std::thread::spawn(move || {
            let mut child = child;
            child.wait().unwrap()
        });
        let run = run_entity::ActiveModel {
            sandbox_id: Set(sandbox_id),
            pid: Set(Some(live_pid)),
            status: Set(run_entity::RunStatus::Running),
            ..Default::default()
        };
        run_entity::Entity::insert(run)
            .exec(pools.write())
            .await
            .unwrap();

        let mut forced = test_config("running");
        forced.replace_existing = true;

        let run_dir = temp.path().join("run");
        LocalContext::prepare_create_target(
            &pools,
            &forced,
            &sandbox_dir,
            &run_dir,
            None,
            &mut None,
        )
        .await
        .unwrap();

        waiter.join().unwrap();

        assert!(!LocalContext::pid_is_alive(live_pid));
        assert!(!sandbox_dir.exists());
        assert!(
            sandbox_entity::Entity::find_by_id(sandbox_id)
                .one(pools.write())
                .await
                .unwrap()
                .is_some_and(|row| row.name.starts_with(".msb-retained-"))
        );
    }

    #[tokio::test]
    async fn crash_child() {
        let Some(home) = std::env::var_os("MSB_CREATION_TEST_HOME") else {
            return;
        };

        let home = PathBuf::from(home);
        let phase = std::env::var("MSB_CREATION_TEST_PHASE").unwrap();
        let local = Arc::new(
            crate::test_support::local_backend_builder(&home)
                .build()
                .unwrap(),
        );
        let rootfs = home.join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();
        let rootfs = rootfs.canonicalize().unwrap();

        crate::volume::create_local(
            local.clone(),
            crate::volume::Volume::builder("shared").directory().build(),
        )
        .await
        .unwrap();
        std::fs::write(local.volume_path("shared").join("sentinel"), b"shared data").unwrap();

        let config = SandboxBuilder::new("interrupted")
            .image(rootfs)
            .volume("/shared", |m| m.named("shared"))
            .volume("/new", |m| m.named_with("new", |v| v.ensure_exists()))
            .build()
            .await
            .unwrap();
        let pools = local.db().await.unwrap();
        let _transition = LocalContext::acquire_sandbox_transition_guard(
            &local.config().run_dir(),
            "interrupted",
        )
        .await
        .unwrap();
        let _runtime = crate::runtime::acquire_sandbox_lifecycle_guard(
            &local.config().run_dir(),
            "interrupted",
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap();
        let preparation = CreationStorage::acquire(&local, "interrupted").unwrap();
        let id = LocalContext::insert_sandbox_record_impl(
            pools.write(),
            &config,
            SandboxStatus::Starting,
            true,
        )
        .await
        .unwrap();
        if phase == "before-storage" {
            std::process::exit(73);
        }

        let _volumes = local
            .ensure_named_volumes(
                &crate::context::local::creation::CreationStorage::for_test(
                    local.sandboxes_dir().join(&config.spec.name),
                ),
                &config,
            )
            .await
            .unwrap();
        let directory = local.sandboxes_dir().join("interrupted");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("upper.ext4"), b"partial disk").unwrap();
        if phase == "after-volumes" {
            let error = local
                .remove_incomplete_sandbox(id, "interrupted", creation::RemovalMode::Recovery)
                .await
                .unwrap_err();
            assert!(error.to_string().contains("preparation is still finishing"));
            assert!(directory.exists());
            assert!(local.volume_path("new").exists());
        }

        drop(preparation);

        if phase == "delete-error" {
            let path = local.volume_path("new");
            std::fs::remove_dir_all(&path).unwrap();
            std::fs::write(path, b"not a directory").unwrap();
            assert!(
                local
                    .remove_incomplete_sandbox(id, "interrupted", creation::RemovalMode::Creator)
                    .await
                    .is_err()
            );
        } else if phase == "after-unlink" {
            pools.write().execute_unprepared(
                "CREATE TRIGGER interrupt_delete BEFORE DELETE ON sandbox BEGIN SELECT RAISE(ABORT, 'interrupted final commit'); END;",
            ).await.unwrap();
            assert!(
                local
                    .remove_incomplete_sandbox(id, "interrupted", creation::RemovalMode::Creator)
                    .await
                    .is_err()
            );
            assert!(!directory.exists());
            assert!(!local.volume_path("new").exists());
        }
        std::process::exit(73);
    }

    #[tokio::test]
    async fn interrupted_creates_refuse_start_and_remain_removable_after_reopen() {
        for phase in [
            "before-storage",
            "after-volumes",
            "delete-error",
            "after-unlink",
        ] {
            #[cfg(unix)]
            let home = tempfile::tempdir_in("/tmp").unwrap();
            #[cfg(not(unix))]
            let home = tempfile::tempdir().unwrap();
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "context::local::sandbox::create::tests::crash_child",
                    "--nocapture",
                ])
                .env("MSB_CREATION_TEST_HOME", home.path())
                .env("MSB_CREATION_TEST_PHASE", phase)
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(73),
                "{phase}: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );

            let local = Arc::new(
                crate::test_support::local_backend_builder(home.path())
                    .build()
                    .unwrap(),
            );
            let pools = local.db().await.unwrap();
            let rows = sandbox::Entity::find().all(pools.read()).await.unwrap();
            assert_eq!(rows.len(), 1, "{phase}: the recovery owner must survive");
            assert!(creation::pending(pools.read(), rows[0].id).await.unwrap());
            assert_eq!(
                volume::Entity::find()
                    .all(pools.read())
                    .await
                    .unwrap()
                    .len(),
                if phase == "before-storage" { 1 } else { 2 }
            );
            let error = local
                .start_sandbox(local.clone(), "interrupted", None, SpawnMode::Detached)
                .await
                .err()
                .unwrap();
            assert!(
                error.to_string().contains("incomplete creation"),
                "{phase}: {error}"
            );

            let error = LocalContext::check_create_target(
                pools,
                "interrupted",
                &local.sandboxes_dir().join("interrupted"),
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("incomplete creation"), "{error}");
            assert!(
                !error.to_string().contains("start the stopped sandbox"),
                "{error}"
            );

            if phase != "before-storage" {
                let error = crate::volume::get_local(local.clone(), "new")
                    .await
                    .err()
                    .unwrap();
                assert!(error.to_string().contains("incomplete sandbox"), "{error}");
                let error = crate::volume::fs::VolumeFs::with_backend(local.clone(), "new")
                    .write("unexpected", b"must not adopt provisional storage")
                    .await
                    .unwrap_err();
                assert!(error.to_string().contains("incomplete sandbox"), "{error}");
            }

            if phase == "after-unlink" {
                pools
                    .write()
                    .execute_unprepared("DROP TRIGGER interrupt_delete")
                    .await
                    .unwrap();
            } else if phase == "delete-error" {
                // Repair the deliberate filesystem obstruction, not any catalog state.
                std::fs::remove_file(local.volume_path("new")).unwrap();
            }
            local
                .remove_sandbox(local.clone(), "interrupted", None)
                .await
                .unwrap();
            assert!(
                sandbox::Entity::find()
                    .all(pools.read())
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(!local.sandboxes_dir().join("interrupted").exists());
            assert!(!local.volume_path("new").exists());
            assert_eq!(
                std::fs::read(local.volume_path("shared").join("sentinel")).unwrap(),
                b"shared data"
            );
            assert_eq!(
                volume::Entity::find()
                    .all(pools.read())
                    .await
                    .unwrap()
                    .len(),
                1
            );
        }
    }

    #[test]
    fn cancelled_preparation_remains_fenced_until_its_worker_finishes() {
        // Queue the real formatter behind one blocked worker. Cancellation is deterministic
        // without adding a test hook to the production storage path.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let fixture = RecoveryFixture::new().await;
            let directory = fixture.local.sandboxes_dir().join("recoverable");
            std::fs::create_dir_all(&directory).unwrap();
            let transition = LocalContext::acquire_sandbox_transition_guard(
                &fixture.local.config().run_dir(),
                "recoverable",
            )
            .await
            .unwrap();
            let lifecycle = crate::runtime::acquire_sandbox_lifecycle_guard(
                &fixture.local.config().run_dir(),
                "recoverable",
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            let guard = CreationStorage::acquire(&fixture.local, "recoverable").unwrap();
            let (release, released) = std::sync::mpsc::channel();
            let (started, started_rx) = tokio::sync::oneshot::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                started.send(()).unwrap();
                // Dropping release also unblocks the thread if an assertion fails.
                let _ = released.recv();
            });
            started_rx.await.unwrap();

            let config = crate::volume::Volume::builder("formatting")
                .disk()
                .size(128)
                .build();
            let destination = directory.join("formatting");
            let resource = guard.at(&destination);
            let mut provision = Box::pin(crate::volume::provision_volume_path(&config, &resource));
            let first_poll = poll_fn(|cx| Poll::Ready(provision.as_mut().poll(cx))).await;
            assert!(first_poll.is_pending());
            drop(provision);
            drop(resource);
            drop(guard);

            assert!(
                CreationStorage::acquire(&fixture.local, "recoverable").is_err(),
                "the queued volume formatter must retain preparation ownership"
            );
            let error = fixture
                .local
                .remove_incomplete_sandbox(
                    fixture.id,
                    "recoverable",
                    creation::RemovalMode::Recovery,
                )
                .await
                .unwrap_err();
            drop(lifecycle);
            drop(transition);
            assert!(
                error.to_string().contains("preparation is still finishing"),
                "{error}"
            );
            assert!(directory.exists());

            release.send(()).unwrap();
            blocker.await.unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Ok(guard) = CreationStorage::acquire(&fixture.local, "recoverable") {
                        drop(guard);
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            assert_eq!(
                std::fs::metadata(destination.join("disk.raw"))
                    .unwrap()
                    .len(),
                128 * 1024 * 1024
            );

            // The creator process is still alive; only unfinished work blocks recovery.
            fixture
                .local
                .remove_sandbox(fixture.local.clone(), "recoverable", None)
                .await
                .unwrap();
            assert!(!directory.exists());
            assert!(
                sandbox::Entity::find_by_id(fixture.id)
                    .one(fixture.local.db().await.unwrap().read())
                    .await
                    .unwrap()
                    .is_none()
            );
        });
    }

    #[tokio::test]
    async fn prepared_config_preserves_labels_and_caller_overrides() {
        let mut fixture = RecoveryFixture::new().await;
        let mut overrides = crate::SandboxConfigPatch::new();
        overrides.spec.runtime.cmd = Some(Vec::new());
        fixture.config.caller_config_overrides = Some(Box::new(overrides));

        // This is the same late merge used by snapshot and archive restores.
        let mut image = microsandbox_image::ImageConfig::default();
        image.labels.insert("tier".into(), "web".into());
        fixture.config.merge_image_defaults(&image);
        fixture
            .local
            .prepare_reserved_sandbox(
                fixture.local.db().await.unwrap().write(),
                fixture.id,
                &fixture.config,
            )
            .await
            .unwrap();

        let (rows, _) = fixture
            .local
            .list_sandbox_handle_state(&SandboxListBuilder::default().label("tier", "web"))
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        let saved = SandboxConfig::from_stored(
            &rows[0].0.config,
            rows[0].0.caller_config_overrides.as_deref(),
        )
        .unwrap();
        assert_eq!(
            saved
                .caller_config_overrides
                .as_ref()
                .unwrap()
                .spec
                .runtime
                .cmd,
            Some(Vec::new()),
        );
        assert_eq!(
            saved.spec.labels.get("tier").map(String::as_str),
            Some("web")
        );
    }

    #[tokio::test]
    async fn publication_and_recovery_retirement_commit_together() {
        let fixture = RecoveryFixture::new().await;
        let pools = fixture.local.db().await.unwrap();
        fixture
            .local
            .prepare_reserved_sandbox(pools.write(), fixture.id, &fixture.config)
            .await
            .unwrap();
        let transition = LocalContext::acquire_sandbox_transition_guard(
            &fixture.local.config().run_dir(),
            "recoverable",
        )
        .await
        .unwrap();
        let volumes = Arc::new(
            fixture
                .local
                .ensure_named_volumes(
                    &crate::context::local::creation::CreationStorage::for_test(
                        fixture
                            .local
                            .sandboxes_dir()
                            .join(&fixture.config.spec.name),
                    ),
                    &fixture.config,
                )
                .await
                .unwrap(),
        );
        let mut cleanup = super::cleanup::CreationCleanup::new(
            fixture.local.clone(),
            "recoverable".into(),
            transition,
            volumes,
        );
        cleanup.begin_publication();
        pools.write().execute_unprepared(
            "CREATE TRIGGER refuse_publication BEFORE UPDATE OF pending_creation_sandbox_id ON volume WHEN OLD.pending_creation_sandbox_id IS NOT NULL AND NEW.pending_creation_sandbox_id IS NULL BEGIN SELECT RAISE(ABORT, 'test publication failure'); END;",
        ).await.unwrap();
        assert!(
            creation::complete(pools.write(), fixture.id, SandboxStatus::Running)
                .await
                .is_err()
        );

        let row = sandbox::Entity::find_by_id(fixture.id)
            .one(pools.read())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, SandboxStatus::Starting);
        assert!(!row.ephemeral);
        assert!(creation::pending(pools.read(), fixture.id).await.unwrap());
        assert!(
            crate::volume::get_local(fixture.local.clone(), "new")
                .await
                .is_err()
        );

        pools
            .write()
            .execute_unprepared("DROP TRIGGER refuse_publication")
            .await
            .unwrap();
        creation::complete(pools.write(), fixture.id, SandboxStatus::Running)
            .await
            .unwrap();
        // Model cancellation after SQLite commits but before the caller observes success.
        cleanup
            .finish_failure(crate::MicrosandboxError::Runtime(
                "cancelled publication".into(),
            ))
            .await;
        let row = sandbox::Entity::find_by_id(fixture.id)
            .one(pools.read())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, SandboxStatus::Running);
        assert!(row.ephemeral);
        assert!(!creation::pending(pools.read(), fixture.id).await.unwrap());
        assert!(
            crate::volume::get_local(fixture.local.clone(), "new")
                .await
                .is_ok()
        );
    }

    async fn start_mock_oci_registry(
        required_auth_header: Option<&'static str>,
    ) -> (
        std::net::SocketAddr,
        Arc<std::sync::atomic::AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        use sha2::{Digest as Sha2Digest, Sha256};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let data = b"sdk test layer\n";
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "etc/test.txt", &data[..])
                .unwrap();
            builder.finish().unwrap();
        }

        let layer_digest = format!("sha256:{}", hex::encode(Sha256::digest(&tar_bytes)));
        let config_bytes = serde_json::to_vec(&serde_json::json!({
            "architecture": microsandbox_image::Platform::host_linux().arch.to_string(),
            "os": "linux",
            "config": { "Env": ["PATH=/usr/bin"] },
            "rootfs": { "type": "layers", "diff_ids": [layer_digest] }
        }))
        .unwrap();
        let config_digest = format!("sha256:{}", hex::encode(Sha256::digest(&config_bytes)));
        let manifest_bytes = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": config_bytes.len()
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": layer_digest,
                "size": tar_bytes.len()
            }]
        }))
        .unwrap();
        let manifest_digest = format!("sha256:{}", hex::encode(Sha256::digest(&manifest_bytes)));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&requests);

        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") && request.len() < 32 * 1024 {
                    let Ok(n) = stream.read(&mut buf).await else {
                        break;
                    };
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..n]);
                }

                observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let req_text = String::from_utf8_lossy(&request);
                let mut lines = req_text.lines();
                let path = lines
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or_default();
                let auth_header = lines.find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("authorization")
                        .then(|| value.trim().to_owned())
                });

                if let Some(expected) = required_auth_header
                    && auth_header.as_deref() != Some(expected)
                {
                    let body = br#"{"errors":[{"code":"UNAUTHORIZED","message":"auth required"}]}"#;
                    let header = format!(
                        "HTTP/1.1 401 Unauthorized\r\n\
                         WWW-Authenticate: Basic realm=\"sdk-test\"\r\n\
                         Content-Type: application/json\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(header.as_bytes()).await;
                    let _ = stream.write_all(body).await;
                    continue;
                }

                if path == "/v2/" {
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\n\
                              Docker-Distribution-Api-Version: registry/2.0\r\n\
                              Content-Length: 2\r\n\
                              Connection: close\r\n\r\n{}",
                        )
                        .await;
                } else if path.contains("/manifests/") {
                    let header = format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: application/vnd.oci.image.manifest.v1+json\r\n\
                         Docker-Content-Digest: {manifest_digest}\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\r\n",
                        manifest_bytes.len()
                    );
                    let _ = stream.write_all(header.as_bytes()).await;
                    let _ = stream.write_all(&manifest_bytes).await;
                } else if path.ends_with(&format!("/blobs/{config_digest}")) {
                    let header = format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: application/vnd.oci.image.config.v1+json\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\r\n",
                        config_bytes.len()
                    );
                    let _ = stream.write_all(header.as_bytes()).await;
                    let _ = stream.write_all(&config_bytes).await;
                } else if path.ends_with(&format!("/blobs/{layer_digest}")) {
                    let header = format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: application/vnd.oci.image.layer.v1.tar\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\r\n",
                        tar_bytes.len()
                    );
                    let _ = stream.write_all(header.as_bytes()).await;
                    let _ = stream.write_all(&tar_bytes).await;
                } else {
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                }
            }
        });

        (addr, requests, handle)
    }

    #[tokio::test]
    async fn pull_oci_image_blocks_anonymous_reuse_and_isolates_org_caches() {
        let temp = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(temp.path())
            .build()
            .unwrap();

        // Private registry requiring Basic "tenant-a:secret-a".
        let (private_addr, _private_requests, private_server) =
            start_mock_oci_registry(Some("Basic dGVuYW50LWE6c2VjcmV0LWE=")).await;
        let private_ref = format!("{private_addr}/acme/secret:v1");

        // 1. Even on the shared cache, Tenant A's authenticated pull cannot be served to an
        //    anonymous Tenant B pull under PullPolicy::IfMissing.
        let tenant_a_shared = local
            .resolve_oci_image_for_create(
                &private_ref,
                PullPolicy::IfMissing,
                RegistryOptions {
                    auth: Some(microsandbox_image::RegistryAuth::Basic {
                        username: "tenant-a".into(),
                        password: "secret-a".into(),
                    }),
                    insecure: true,
                    ..Default::default()
                },
                None,
                None,
                false,
                RootfsMaterialization::Layered,
                None,
            )
            .await
            .unwrap();
        assert!(!tenant_a_shared.pull_result.cached);

        let tenant_b_anon = local
            .resolve_oci_image_for_create(
                &private_ref,
                PullPolicy::IfMissing,
                RegistryOptions {
                    auth: Some(microsandbox_image::RegistryAuth::Anonymous),
                    insecure: true,
                    ..Default::default()
                },
                None,
                None,
                false,
                RootfsMaterialization::Layered,
                None,
            )
            .await;
        assert!(
            tenant_b_anon.is_err(),
            "anonymous pull must not receive cached authenticated image from shared cache"
        );

        // 2. Per-org cache_dir isolates artifacts under cache/orgs/<org_id>.
        let org_a_dir = local.cache_dir().join("orgs/org-a");
        let org_b_dir = local.cache_dir().join("orgs/org-b");
        let org_a_image = local
            .resolve_oci_image_for_create(
                &private_ref,
                PullPolicy::IfMissing,
                RegistryOptions {
                    auth: Some(microsandbox_image::RegistryAuth::Basic {
                        username: "tenant-a".into(),
                        password: "secret-a".into(),
                    }),
                    insecure: true,
                    ..Default::default()
                },
                Some(&org_a_dir),
                None,
                false,
                RootfsMaterialization::Layered,
                None,
            )
            .await
            .unwrap();
        let org_a_cache = GlobalCache::new(&org_a_dir).unwrap();
        let org_b_cache = GlobalCache::new(&org_b_dir).unwrap();
        assert!(
            org_a_cache
                .vmdk_path(&org_a_image.pull_result.manifest_digest)
                .exists()
        );
        assert!(
            !org_b_cache
                .vmdk_path(&org_a_image.pull_result.manifest_digest)
                .exists()
        );

        // Org B querying its own isolated cache cannot see org A's artifacts.
        let org_b_err = local
            .resolve_oci_image_for_create(
                &private_ref,
                PullPolicy::Never,
                RegistryOptions {
                    auth: Some(microsandbox_image::RegistryAuth::Anonymous),
                    insecure: true,
                    ..Default::default()
                },
                Some(&org_b_dir),
                None,
                false,
                RootfsMaterialization::Layered,
                None,
            )
            .await;
        assert!(org_b_err.is_err());
        private_server.abort();

        // 3. Anonymous/public warm cache hits stay fast and never construct a Registry client.
        let (public_addr, public_requests, public_server) = start_mock_oci_registry(None).await;
        let public_ref = format!("{public_addr}/library/public:v1");

        let cold_public = local
            .resolve_oci_image_for_create(
                &public_ref,
                PullPolicy::IfMissing,
                RegistryOptions {
                    auth: Some(microsandbox_image::RegistryAuth::Anonymous),
                    insecure: true,
                    ..Default::default()
                },
                None,
                None,
                false,
                RootfsMaterialization::Layered,
                None,
            )
            .await
            .unwrap();
        assert!(!cold_public.pull_result.cached);
        let requests_after_cold = public_requests.load(std::sync::atomic::Ordering::SeqCst);
        assert!(requests_after_cold > 0);
        public_server.abort();

        // Pass an invalid CA PEM: if pull_oci_image constructed a Registry client,
        // RegistryBuilder::build() would fail with InvalidCertificate.
        let warm_public = local
            .resolve_oci_image_for_create(
                &public_ref,
                PullPolicy::IfMissing,
                RegistryOptions {
                    insecure: true,
                    ca_certs: vec![b"not a valid pem".to_vec()],
                    ..Default::default()
                },
                None,
                None,
                false,
                RootfsMaterialization::Layered,
                None,
            )
            .await
            .unwrap();
        assert!(warm_public.pull_result.cached);
        assert_eq!(
            warm_public.pull_result.manifest_digest,
            cold_public.pull_result.manifest_digest
        );
        assert_eq!(
            public_requests.load(std::sync::atomic::Ordering::SeqCst),
            requests_after_cold
        );
    }

    #[tokio::test]
    async fn sandbox_builder_image_cache_dir_persists_and_resolves_for_restart() {
        let temp = tempfile::tempdir().unwrap();
        let local = Arc::new(
            crate::test_support::local_backend_builder(temp.path())
                .build()
                .unwrap(),
        );
        let org_cache_dir = local.cache_dir().join("orgs/org-42");

        // 1. RegistryConfigBuilder::cache_dir populates image_cache_dir.
        let config = SandboxBuilder::for_context(local.clone(), "org-sandbox")
            .image("ghcr.io/acme/app:v1")
            .registry(|r| {
                r.auth(RegistryAuth::Basic {
                    username: "org".into(),
                    password: "secret".into(),
                })
                .cache_dir(&org_cache_dir)
            })
            .build()
            .await
            .unwrap();
        assert_eq!(
            config.image_cache_dir.as_deref(),
            Some(org_cache_dir.as_path())
        );

        // Persisted JSON retains image_cache_dir while redacting registry_auth.
        let persisted = config.clone_for_persistence();
        let json = serde_json::to_string(&persisted).unwrap();
        assert!(json.contains("image_cache_dir"));
        assert!(!json.contains("registry_auth"));
        let mut decoded: SandboxConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            decoded.image_cache_dir.as_deref(),
            Some(org_cache_dir.as_path())
        );

        // 2. Restart state validation looks up the VMDK in the isolated image_cache_dir,
        //    not the shared global cache.
        let digest = format!("sha256:{}", "c".repeat(64));
        decoded.manifest_digest = Some(digest.clone());
        let sandbox_dir = local.sandboxes_dir().join("org-sandbox");
        std::fs::create_dir_all(&sandbox_dir).unwrap();
        assert!(
            local.validate_start_state(&decoded, &sandbox_dir).is_err(),
            "missing VMDK in isolated cache must fail start validation"
        );
        let org_cache = GlobalCache::new(&org_cache_dir).unwrap();
        let vmdk_path = org_cache.vmdk_path(&digest.parse().unwrap());
        std::fs::write(&vmdk_path, b"vmdk").unwrap();
        local.validate_start_state(&decoded, &sandbox_dir).unwrap();

        // 3. Direct SandboxBuilder::image_cache_dir works and preserves through .registry().
        let direct = SandboxBuilder::for_context(local.clone(), "direct-cache")
            .image("ghcr.io/acme/app:v1")
            .image_cache_dir(&org_cache_dir)
            .registry(|r| r.insecure())
            .build()
            .await
            .unwrap();
        assert_eq!(
            direct.image_cache_dir.as_deref(),
            Some(org_cache_dir.as_path())
        );

        // 4. Default sandboxes omit image_cache_dir from serialized JSON.
        let default_cfg = SandboxBuilder::for_context(local.clone(), "public-sandbox")
            .image("alpine:latest")
            .build()
            .await
            .unwrap();
        let default_json = serde_json::to_string(&default_cfg.clone_for_persistence()).unwrap();
        assert!(!default_json.contains("image_cache_dir"));

        // 5. Empty image_cache_dir is rejected.
        let empty_err = SandboxBuilder::for_context(local.clone(), "bad-cache")
            .image("alpine:latest")
            .image_cache_dir("")
            .build()
            .await
            .unwrap_err();
        assert!(
            empty_err.to_string().contains("image cache directory"),
            "unexpected error: {empty_err}"
        );

        // 6. Unavailable image_cache_dir (regular file blocking cache init) returns an error
        //    from validate_start_state instead of silently succeeding or panicking.
        let blocking_file = temp.path().join("not-a-dir");
        std::fs::write(&blocking_file, b"file").unwrap();
        let mut broken = decoded.clone();
        broken.image_cache_dir = Some(blocking_file);
        let cache_err = local
            .validate_start_state(&broken, &sandbox_dir)
            .unwrap_err();
        assert!(
            cache_err.to_string().contains("image cache unavailable"),
            "unexpected error: {cache_err}"
        );

        // 7. prepare_reserved_sandbox does not attach a shared sandbox_rootfs pin for isolated caches.
        let pools = local.db().await.unwrap();
        let reserved_id = LocalContext::insert_sandbox_record_impl(
            pools.write(),
            &decoded,
            SandboxStatus::Starting,
            true,
        )
        .await
        .unwrap();
        local
            .prepare_reserved_sandbox(pools.write(), reserved_id, &decoded)
            .await
            .unwrap();
        let pins = sandbox_rootfs_entity::Entity::find()
            .filter(sandbox_rootfs_entity::Column::SandboxId.eq(reserved_id))
            .all(pools.read())
            .await
            .unwrap();
        assert!(
            pins.is_empty(),
            "isolated image_cache_dir must not pin shared sandbox_rootfs rows"
        );
    }

    #[tokio::test]
    async fn snapshot_restore_rejects_authenticated_shared_cache_and_strict_host_files_blocks_symlink_alias()
     {
        let temp = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(temp.path())
            .build()
            .unwrap();
        let (private_addr, _requests, private_server) =
            start_mock_oci_registry(Some("Basic dGVuYW50LWE6c2VjcmV0LWE=")).await;
        let private_ref = format!("{private_addr}/acme/secret:v1");

        // Pull authenticated image into shared cache.
        let pulled = local
            .resolve_oci_image_for_create(
                &private_ref,
                PullPolicy::IfMissing,
                RegistryOptions {
                    auth: Some(RegistryAuth::Basic {
                        username: "tenant-a".into(),
                        password: "secret-a".into(),
                    }),
                    insecure: true,
                    ..Default::default()
                },
                None,
                None,
                false,
                RootfsMaterialization::Layered,
                None,
            )
            .await
            .unwrap();
        let digest = pulled.pull_result.manifest_digest.to_string();

        // Unauthenticated snapshot restore by digest on shared cache must NOT reuse the
        // authenticated entry under either Never or IfMissing.
        for policy in [PullPolicy::Never, PullPolicy::IfMissing] {
            let err = local
                .resolve_snapshot_oci_image(
                    &private_ref,
                    &digest,
                    policy,
                    RegistryOptions {
                        auth: Some(RegistryAuth::Anonymous),
                        insecure: true,
                        ..Default::default()
                    },
                    None,
                    false,
                    RootfsMaterialization::Layered,
                    None,
                )
                .await;
            assert!(
                err.is_err(),
                "unauthenticated snapshot restore ({policy:?}) must not read authenticated shared cache"
            );
        }

        // When the caller's own `--with-image` archive supplied the image, offline restore succeeds.
        let from_archive = local
            .resolve_snapshot_oci_image(
                &private_ref,
                &digest,
                PullPolicy::Never,
                RegistryOptions {
                    auth: Some(RegistryAuth::Anonymous),
                    insecure: true,
                    ..Default::default()
                },
                None,
                true,
                RootfsMaterialization::Layered,
                None,
            )
            .await
            .unwrap();
        assert_eq!(from_archive.pull_result.manifest_digest.to_string(), digest);
        private_server.abort();

        // Symlink alias to the shared cache is recognized as the default cache, and rejected
        // under runtime.strict_host_files (multi-tenant profile on Unix).
        #[cfg(unix)]
        {
            std::fs::create_dir_all(local.cache_dir()).unwrap();
            let alias = temp.path().join("org-alias");
            std::os::unix::fs::symlink(local.cache_dir(), &alias).unwrap();
            assert!(local.is_default_image_cache_dir(Some(&alias)));

            let strict_cfg = temp.path().join("strict-config.json");
            std::fs::write(&strict_cfg, r#"{"runtime":{"strict_host_files":true}}"#).unwrap();
            let strict_local = crate::test_support::local_backend_builder(temp.path())
                .config_path(&strict_cfg)
                .build()
                .unwrap();
            let err = strict_local
                .resolve_image_cache_dir(Some(&alias))
                .unwrap_err();
            assert!(
                err.to_string().contains("strict_host_files"),
                "expected strict_host_files rejection, got: {err}"
            );
        }
    }
}
