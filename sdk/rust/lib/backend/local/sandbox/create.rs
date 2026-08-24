//! Local sandbox create flow: image pull, rootfs preparation, record
//! insertion, and process spawn, as [`LocalBackend`] inherent methods.
//!
//! [`LocalBackend::create_sandbox`] is the single entry point; the trait
//! impl's `create`/`create_detached` and the pull-progress shims on
//! [`Sandbox`] and `SandboxBuilder` all dispatch here.

use std::path::Path;
use std::sync::Arc;

use microsandbox_db::DbWriteConnection;
use microsandbox_db::pool::DbPools;
use microsandbox_image::{
    CachedImageMetadata, Digest, GlobalCache, PullOptions, PullProgress, PullProgressSender,
    PullResult, Reference, Registry, ext4, tree,
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set, sea_query::Expr};
use tokio::sync::Mutex;

use super::LocalBackend;
use crate::MicrosandboxResult;
use crate::agent::AgentClient;
use crate::backend::Backend;
use crate::db::entity::{
    run as run_entity, sandbox as sandbox_entity, sandbox_label as sandbox_label_entity,
    sandbox_rootfs as sandbox_rootfs_entity,
};
use crate::runtime::{
    ProcessHandle, SpawnMode, ensure_named_volumes, rollback_created_named_volumes, spawn_sandbox,
};
use crate::sandbox::{
    FsEntryKind, PullPolicy, RootDisk, RootfsSource, Sandbox, SandboxConfig, SandboxStatus,
    apply_patches, build_upper_tree, remove_dir_if_exists, validate_env, validate_hostname,
    validate_labels, validate_sandbox_name, validate_volume_mounts,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum time to wait for the sandbox process to expose the agent relay.
const AGENT_RELAY_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Transient registry overrides from the SDK, merged with global config at pull time.
struct RegistryOverrides {
    auth: Option<microsandbox_image::RegistryAuth>,
    insecure: bool,
    ca_certs: Vec<Vec<u8>>,
}

/// OCI materialization selected for a create request.
///
/// Snapshot restores carry both their digest-pinned persistence reference and,
/// when found directly by digest, the cache metadata that may not be indexed by
/// that immutable reference yet.
struct ResolvedOciImage {
    pull_result: PullResult,
    metadata_reference: String,
    cached_metadata: Option<CachedImageMetadata>,
}

//--------------------------------------------------------------------------------------------------
// Methods: Create Flow
//--------------------------------------------------------------------------------------------------

impl LocalBackend {
    /// Local create path. Returns a complete [`Sandbox`] wrapping the supplied
    /// backend Arc.
    ///
    /// `backend` must be the `Arc<dyn Backend>` wrapping `self`: the trait
    /// impl and the pull-progress shims forward the Arc they were handed so
    /// the returned [`Sandbox`] routes follow-up calls through this same
    /// backend.
    pub(crate) async fn create_sandbox(
        &self,
        backend: Arc<dyn Backend>,
        mut config: SandboxConfig,
        mode: SpawnMode,
        progress: Option<PullProgressSender>,
    ) -> MicrosandboxResult<Sandbox> {
        tracing::debug!(
            sandbox = %config.spec.name,
            image = ?config.spec.image,
            mode = ?mode,
            cpus = config.spec.resources.cpus,
            memory_mib = config.spec.resources.memory_mib,
            "create_local: starting"
        );

        self.apply_deployment_profile(&mut config);
        config.apply_rootfs_defaults(&self.config().sandbox_defaults.oci)?;

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

        // Initialize the database before any expensive image pull so we can
        // fail fast on conflicting persisted sandbox state.
        let db = self.db().await?;
        let sandbox_dir = self.sandboxes_dir().join(&config.spec.name);
        Self::prepare_create_target(db, &config, &sandbox_dir, &self.config().run_dir()).await?;

        // Resolve OCI images before spawning the sandbox process.
        if let RootfsSource::Oci(oci) = config.spec.image.clone() {
            let reference = oci.reference;
            let expected_snapshot_manifest_digest = config
                .snapshot_upper_source
                .as_ref()
                .and(config.manifest_digest.clone());
            let root_disk = oci
                .root_disk
                .unwrap_or(RootDisk::Managed { size_mib: None });
            let image_materialization = if matches!(&root_disk, RootDisk::Flat { .. }) {
                microsandbox_image::RootfsMaterialization::Flat
            } else {
                microsandbox_image::RootfsMaterialization::Layered
            };
            let overrides = RegistryOverrides {
                auth: config.registry_auth.clone(),
                insecure: config.insecure,
                ca_certs: config.ca_certs.clone(),
            };
            let ResolvedOciImage {
                pull_result,
                metadata_reference,
                cached_metadata,
            } = self
                .resolve_oci_image_for_create(
                    &reference,
                    config.spec.pull_policy,
                    overrides,
                    expected_snapshot_manifest_digest.as_deref(),
                    image_materialization,
                    progress,
                )
                .await?;

            // Snapshot overlays are meaningful only against the exact base
            // image digest captured in their descriptor.
            if let Some(expected) = expected_snapshot_manifest_digest.as_deref()
                && pull_result.manifest_digest.to_string() != expected
            {
                return Err(crate::MicrosandboxError::SnapshotIntegrity(format!(
                    "snapshot image digest mismatch: manifest pinned {}, resolved {}",
                    expected, pull_result.manifest_digest
                )));
            }

            // Merge image config defaults under user-provided config.
            config.merge_image_defaults(&pull_result.config);
            if let Some(init) = &config.spec.init {
                crate::sandbox::init::validate(init)?;
            }

            pinned_manifest_digest = Some(pull_result.manifest_digest.to_string());
            pinned_reference = Some(metadata_reference.clone());

            // Layered roots boot through the stitched VMDK descriptor. Flat
            // roots intentionally skip both fsmeta and VMDK materialization,
            // so requiring the descriptor here would make a cold SDK create
            // fail after successfully publishing its flat ext4 artifact.
            let cache_dir = self.cache_dir();
            let cache = GlobalCache::new_async(&cache_dir).await?;
            if image_materialization.includes_layered() {
                let vmdk_path = cache.vmdk_path(&pull_result.manifest_digest);
                if tokio::fs::metadata(&vmdk_path).await.is_err() {
                    return Err(crate::MicrosandboxError::Custom(format!(
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
                        return Err(crate::MicrosandboxError::InvalidConfig(format!(
                            "flat root disks currently require fstype=ext4, got {}",
                            fstype.as_deref().unwrap_or_default()
                        )));
                    }
                    if !config.spec.patches.is_empty() {
                        return Err(crate::MicrosandboxError::InvalidConfig(
                            "patches are not yet compatible with flat OCI rootfs".into(),
                        ));
                    }
                    if config.snapshot_upper_source.is_some() {
                        return Err(crate::MicrosandboxError::InvalidConfig(
                            "from_snapshot is not yet compatible with flat OCI rootfs".into(),
                        ));
                    }

                    let flat_ref = cache
                        .read_flat_ref(&pull_result.manifest_digest)?
                        .ok_or_else(|| {
                            crate::MicrosandboxError::Custom(
                                "flat rootfs was not published by the image pull".into(),
                            )
                        })?;
                    let artifact_digest: Digest =
                        flat_ref.artifact_digest.parse().map_err(|e| {
                            crate::MicrosandboxError::Custom(format!(
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
                        crate::MicrosandboxError::InvalidConfig(
                            "flat root disk size exceeds supported MiB range".into(),
                        )
                    })?;
                    Some((cache.flat_blob_path(&artifact_digest), target_mib, *clone))
                }
                _ => None,
            };

            let upper_tree = if !config.spec.patches.is_empty() {
                Some(build_upper_tree(&config.spec.patches, &layer_erofs_paths).await?)
            } else {
                None
            };

            // Ensure sandbox storage exists before provisioning either a private flat rootfs or
            // the writable overlay upper image.
            tokio::fs::create_dir_all(&sandbox_dir).await?;
            let upper_path = sandbox_dir.join("upper.ext4");
            if let Some((base, target_mib, clone)) = flat_spec {
                crate::sandbox::flat_rootfs::create_private_flat_rootfs(
                    base,
                    sandbox_dir.join(crate::sandbox::flat_rootfs::FLAT_ROOTFS_FILENAME),
                    target_mib,
                    clone,
                )
                .await?;
                if let RootfsSource::Oci(oci) = &mut config.spec.image
                    && let Some(RootDisk::Flat { size_mib, .. }) = &mut oci.root_disk
                {
                    *size_mib = Some(target_mib);
                }
            } else if let Some(snap_upper) = config.snapshot_upper_source.take() {
                // Booting from a snapshot: copy the captured upper into
                // place, preserving sparseness. Patches are not
                // compatible with this path because they'd need to be
                // re-baked into the snapshot's upper, which we don't do.
                if upper_tree.is_some() {
                    return Err(crate::MicrosandboxError::InvalidConfig(
                        "patches cannot be combined with from_snapshot".into(),
                    ));
                }
                let dst = upper_path.clone();
                tokio::task::spawn_blocking(move || {
                    microsandbox_utils::copy::fast_copy(&snap_upper, &dst)
                })
                .await
                .map_err(|e| {
                    crate::MicrosandboxError::Custom(format!("snapshot copy task: {e}"))
                })??;
            } else {
                match &root_disk {
                    RootDisk::Managed { size_mib } => {
                        let upper_size_mib =
                            size_mib.unwrap_or(crate::sandbox::config::DEFAULT_OCI_UPPER_SIZE_MIB);
                        if !upper_path.exists() || upper_tree.is_some() {
                            Self::create_upper_ext4(&upper_path, upper_size_mib, upper_tree)
                                .await?;
                        }
                    }
                    // The builder rejects patches with tmpfs root disks and
                    // agentd creates the in-memory upper inside the guest.
                    RootDisk::Tmpfs { .. } => {}
                    RootDisk::DiskImage { path, .. } => {
                        if tokio::fs::metadata(path).await.is_err() {
                            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                                "root disk image not found: {}",
                                path.display()
                            )));
                        }
                    }
                    RootDisk::Flat { .. } => {
                        unreachable!("flat root disks are provisioned before overlay handling")
                    }
                }
            }

            // Store manifest digest for spawn to derive paths.
            config.manifest_digest = Some(pull_result.manifest_digest.to_string());

            // Persist snapshot restores under their immutable digest-pinned
            // reference, even when the cache match came from an older tag.
            if let Some(metadata) = cached_metadata {
                if let Err(e) =
                    crate::image::Image::persist(self, &metadata_reference, metadata).await
                {
                    tracing::warn!(
                        error = %e,
                        "failed to persist image metadata to database"
                    );
                }
            } else if let Ok(image_ref) = metadata_reference.parse::<Reference>() {
                match cache.read_image_metadata_async(&image_ref).await {
                    Ok(Some(metadata)) => {
                        if let Err(e) =
                            crate::image::Image::persist(self, &metadata_reference, metadata).await
                        {
                            tracing::warn!(
                                error = %e,
                                "failed to persist image metadata to database"
                            );
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to read cached image metadata");
                    }
                }
            }
        }

        // Apply rootfs patches before VM start (bind mounts only — OCI patches
        // are baked into upper.ext4 above).
        if !config.spec.patches.is_empty() && !matches!(config.spec.image, RootfsSource::Oci(_)) {
            apply_patches(&config.spec.image, &config.spec.patches).await?;
        }

        // Sandbox-time named-volume creation is one-shot create intent. Provision
        // before inserting the sandbox row so volume conflicts or incompatibilities
        // cannot leave a stopped sandbox that never booted.
        let created_named_volumes = ensure_named_volumes(self, &config).await?;

        // Insert the sandbox record and keep its stable database ID.
        let write_db = db.write();
        let persisted_config = config.clone_for_persistence();
        let sandbox_id = match Self::insert_sandbox_record(write_db, &persisted_config).await {
            Ok(sandbox_id) => sandbox_id,
            Err(err) => {
                rollback_created_named_volumes(self, &created_named_volumes).await;
                return Err(err);
            }
        };
        tracing::debug!(sandbox_id, sandbox = %config.spec.name, "create_local: db record inserted");

        // Spawn the sandbox process and create the bridge. On failure, mark the sandbox
        // as stopped so it doesn't appear as a phantom "Running" entry.
        let (local_state, returned_config) = match self
            .create_sandbox_inner(config, sandbox_id, mode, None)
            .await
        {
            Ok(pair) => pair,
            Err(e) => {
                if created_named_volumes.is_empty() {
                    let _ =
                        Self::update_sandbox_status(write_db, sandbox_id, SandboxStatus::Stopped)
                            .await;
                } else {
                    rollback_created_named_volumes(self, &created_named_volumes).await;
                    let _ = Self::delete_sandbox_record(write_db, sandbox_id).await;
                }
                return Err(e);
            }
        };
        let sandbox = Sandbox::from_local(backend.clone(), local_state, returned_config);
        if let Err(err) = Self::update_sandbox_active_config(
            write_db,
            sandbox_id,
            &sandbox.config().clone_for_persistence(),
        )
        .await
        {
            let _ = sandbox.stop().await;
            return Err(err);
        }

        if let (Some(_reference), Some(manifest_digest)) = (
            pinned_reference.as_deref(),
            pinned_manifest_digest.as_deref(),
        ) && let Err(err) =
            Self::persist_oci_manifest_pin(write_db, sandbox_id, manifest_digest).await
        {
            let _ = sandbox.stop().await;
            if created_named_volumes.is_empty() {
                let _ =
                    Self::update_sandbox_status(write_db, sandbox_id, SandboxStatus::Stopped).await;
            } else {
                rollback_created_named_volumes(self, &created_named_volumes).await;
                let _ = Self::delete_sandbox_record(write_db, sandbox_id).await;
            }
            return Err(err);
        }

        // Validate that the configured workdir exists inside the guest and is a
        // directory before returning a ready sandbox. Shell/exec calls inherit this
        // cwd, so accepting a regular file here leads to later, murkier failures.
        if let Some(ref workdir) = sandbox.config().spec.runtime.workdir {
            match sandbox.fs().stat(workdir).await {
                Ok(metadata) if metadata.kind == FsEntryKind::Directory => {}
                Ok(_) => {
                    let _ = sandbox.stop().await;
                    if created_named_volumes.is_empty() {
                        let _ = Self::update_sandbox_status(
                            write_db,
                            sandbox_id,
                            SandboxStatus::Stopped,
                        )
                        .await;
                    } else {
                        rollback_created_named_volumes(self, &created_named_volumes).await;
                        let _ = Self::delete_sandbox_record(write_db, sandbox_id).await;
                    }
                    return Err(crate::MicrosandboxError::InvalidConfig(format!(
                        "workdir is not a directory in guest: {workdir}"
                    )));
                }
                Err(_) => {
                    let _ = sandbox.stop().await;
                    if created_named_volumes.is_empty() {
                        let _ = Self::update_sandbox_status(
                            write_db,
                            sandbox_id,
                            SandboxStatus::Stopped,
                        )
                        .await;
                    } else {
                        rollback_created_named_volumes(self, &created_named_volumes).await;
                        let _ = Self::delete_sandbox_record(write_db, sandbox_id).await;
                    }
                    return Err(crate::MicrosandboxError::InvalidConfig(format!(
                        "workdir does not exist in guest: {workdir}"
                    )));
                }
            }
        }

        Ok(sandbox)
    }

    /// Inner local create logic separated for error-cleanup wrapper. Returns
    /// the local-variant state plus the (possibly mutated) config.
    pub(super) async fn create_sandbox_inner(
        &self,
        config: SandboxConfig,
        sandbox_id: i32,
        mode: SpawnMode,
        lifecycle_guard: Option<microsandbox_runtime::ipc::SandboxLifecycleGuard>,
    ) -> MicrosandboxResult<(crate::backend::SandboxLocalState, SandboxConfig)> {
        let (mut handle, agent_sock_path) =
            spawn_sandbox(self, &config, sandbox_id, mode, lifecycle_guard).await?;
        let log_dir = self.sandboxes_dir().join(&config.spec.name).join("logs");

        // Wait for the relay socket to become available.
        let client =
            Self::wait_for_relay(&agent_sock_path, &log_dir, &mut handle, &config.spec.name)
                .await?;

        if let Ok(ready) = client.ready() {
            tracing::info!(
                boot_time_ms = ready.boot_time_ns / 1_000_000,
                init_time_ms = ready.init_time_ns / 1_000_000,
                ready_time_ms = ready.ready_time_ns / 1_000_000,
                "sandbox ready",
            );
        }
        let handle = if matches!(mode, SpawnMode::Detached) {
            handle.disarm();
            None
        } else {
            Some(Arc::new(Mutex::new(handle)))
        };

        Ok((
            crate::backend::SandboxLocalState {
                db_id: sandbox_id,
                handle,
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
    ) -> MicrosandboxResult<AgentClient> {
        tracing::debug!(
            sock = %sock_path.display(),
            pid = handle.pid(),
            "wait_for_relay: waiting for agent socket"
        );
        let deadline = tokio::time::Instant::now() + AGENT_RELAY_READY_TIMEOUT;
        let max_backoff = std::time::Duration::from_millis(10);
        let mut backoff = std::time::Duration::from_millis(1);
        let mut attempts = 0u32;

        loop {
            attempts += 1;
            match tokio::time::timeout(
                deadline.saturating_duration_since(tokio::time::Instant::now()),
                AgentClient::connect(sock_path),
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
                        if let Some(boot_err) = Self::read_boot_error(log_dir) {
                            return Err(crate::MicrosandboxError::BootStart {
                                name: sandbox_name.to_string(),
                                err: boot_err,
                            });
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
                            errno: None,
                            message: format!(
                                "sandbox process exited ({status}) before agent relay became available"
                            ),
                        };
                        return Err(crate::MicrosandboxError::BootStart {
                            name: sandbox_name.to_string(),
                            err: synthetic,
                        });
                    }

                    // Keep early retries tight so relay readiness doesn't inherit a
                    // coarse fixed delay on warm starts.
                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(backoff.saturating_mul(2), max_backoff);
                }
                Ok(Err(e)) => {
                    tracing::debug!(
                        attempts,
                        error = %e,
                        "wait_for_relay: agent connection failed"
                    );
                    if let Some(boot_err) = Self::read_boot_error(log_dir) {
                        return Err(crate::MicrosandboxError::BootStart {
                            name: sandbox_name.to_string(),
                            err: boot_err,
                        });
                    }
                    return Err(e.into());
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
                    if let Some(boot_err) = Self::read_boot_error(log_dir) {
                        return Err(crate::MicrosandboxError::BootStart {
                            name: sandbox_name.to_string(),
                            err: boot_err,
                        });
                    }
                    return Err(crate::MicrosandboxError::Runtime(format!(
                        "timed out waiting for agent relay: {e}"
                    )));
                }
            }
        }
    }

    /// Read `boot-error.json` from `log_dir` if present and parseable.
    ///
    /// Returns `None` when the directory is unknown, the file is missing, or
    /// the contents cannot be deserialized — callers fall back to a raw
    /// error in those cases.
    fn read_boot_error(
        log_dir: &std::path::Path,
    ) -> Option<microsandbox_runtime::boot_error::BootError> {
        microsandbox_runtime::boot_error::BootError::read(log_dir)
            .ok()
            .flatten()
    }

    /// Resolve a fresh create by tag, but restore a snapshot by its captured
    /// manifest digest so a moved tag cannot change the snapshot's base.
    async fn resolve_oci_image_for_create(
        &self,
        reference: &str,
        pull_policy: PullPolicy,
        registry_overrides: RegistryOverrides,
        expected_snapshot_manifest_digest: Option<&str>,
        materialization: microsandbox_image::RootfsMaterialization,
        progress: Option<PullProgressSender>,
    ) -> MicrosandboxResult<ResolvedOciImage> {
        let Some(pinned_digest) = expected_snapshot_manifest_digest else {
            let pull_result = self
                .pull_oci_image(
                    reference,
                    pull_policy,
                    registry_overrides,
                    materialization,
                    progress,
                )
                .await?;
            return Ok(ResolvedOciImage {
                pull_result,
                metadata_reference: reference.to_string(),
                cached_metadata: None,
            });
        };

        self.resolve_snapshot_oci_image(
            reference,
            pinned_digest,
            pull_policy,
            registry_overrides,
            progress,
        )
        .await
    }

    /// Resolve the immutable image backing a snapshot from cache or registry.
    async fn resolve_snapshot_oci_image(
        &self,
        reference: &str,
        pinned_digest: &str,
        pull_policy: PullPolicy,
        registry_overrides: RegistryOverrides,
        progress: Option<PullProgressSender>,
    ) -> MicrosandboxResult<ResolvedOciImage> {
        let manifest_digest: Digest = pinned_digest.parse().map_err(|e| {
            crate::MicrosandboxError::SnapshotIntegrity(format!(
                "invalid snapshot image digest {pinned_digest}: {e}"
            ))
        })?;
        let pinned_reference = Self::digest_pinned_reference(reference, pinned_digest)?;
        let cache = GlobalCache::new_async(&self.cache_dir()).await?;

        if let Some((pull_result, metadata)) =
            Registry::pull_cached_by_manifest_digest(&cache, &manifest_digest).await?
        {
            Self::emit_cached_pull_progress(progress.as_ref(), reference, &metadata);
            return Ok(ResolvedOciImage {
                pull_result,
                metadata_reference: pinned_reference,
                cached_metadata: Some(metadata),
            });
        }

        if pull_policy == PullPolicy::Never {
            return Err(crate::MicrosandboxError::SnapshotIntegrity(format!(
                "snapshot base image {pinned_digest} is not cached locally and pull policy is `never`; \
                 this snapshot cannot be restored losslessly"
            )));
        }

        // Pull by digest, never by the mutable source tag, when the exact
        // snapshot base is absent from the local cache.
        let pull_result = match self
            .pull_oci_image(
                &pinned_reference,
                pull_policy,
                registry_overrides,
                microsandbox_image::RootfsMaterialization::Layered,
                progress,
            )
            .await
        {
            Ok(result) => result,
            Err(err) => {
                return Err(crate::MicrosandboxError::SnapshotIntegrity(format!(
                    "snapshot base image {pinned_digest} no longer available in registry \
                     (it may have been garbage-collected upstream); this snapshot \
                     cannot be restored losslessly: {err}"
                )));
            }
        };

        Ok(ResolvedOciImage {
            pull_result,
            metadata_reference: pinned_reference,
            cached_metadata: None,
        })
    }

    /// Build an immutable OCI reference using a captured manifest digest.
    fn digest_pinned_reference(reference: &str, pinned_digest: &str) -> MicrosandboxResult<String> {
        let parsed: Reference = reference.parse().map_err(|e| {
            crate::MicrosandboxError::InvalidConfig(format!("invalid image reference: {e}"))
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
    /// When `progress` is `Some`, uses `pull_with_sender()` to emit per-layer
    /// progress events. The caller must consume the corresponding `PullProgressHandle`.
    async fn pull_oci_image(
        &self,
        reference: &str,
        pull_policy: PullPolicy,
        registry_overrides: RegistryOverrides,
        materialization: microsandbox_image::RootfsMaterialization,
        progress: Option<PullProgressSender>,
    ) -> MicrosandboxResult<PullResult> {
        let global = self.config();
        let cache = GlobalCache::new(&self.cache_dir())?;
        let platform = microsandbox_image::Platform::host_linux();
        let image_ref: Reference = reference.parse().map_err(|e| {
            crate::MicrosandboxError::InvalidConfig(format!("invalid image reference: {e}"))
        })?;
        let options = PullOptions {
            pull_policy: Self::image_pull_policy(pull_policy),
            materialization,
            ..Default::default()
        };

        // Warm runs spend most of their time outside the guest, so avoid
        // constructing the registry client when the image is already complete
        // in the local cache.
        if let Some((result, metadata)) = Registry::pull_cached(&cache, &image_ref, &options)? {
            Self::emit_cached_pull_progress(progress.as_ref(), reference, &metadata);
            return Ok(result);
        }

        let auth = match registry_overrides.auth {
            Some(auth) => auth,
            None => global.resolve_registry_auth(image_ref.registry())?,
        };

        // Merge global config with SDK overrides.
        let mut ca_certs = global.resolve_ca_certs().await?;
        ca_certs.extend(registry_overrides.ca_certs);

        let mut insecure_registries = global.insecure_registries();
        if registry_overrides.insecure {
            insecure_registries.push(image_ref.registry().to_string());
        }

        let registry = Registry::builder(platform, cache)
            .auth(auth)
            .extra_ca_certs(ca_certs)
            .add_insecure_registries(insecure_registries)
            .build()?;

        if let Some(sender) = progress {
            let task = registry.pull_with_sender(&image_ref, &options, sender);
            let result = task.await.map_err(|e| {
                crate::MicrosandboxError::Custom(format!("pull task panicked: {e}"))
            })??;
            Ok(result)
        } else {
            let result = registry.pull(&image_ref, &options).await?;
            Ok(result)
        }
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
    pub(super) fn validate_sandbox_name_for_runtime(&self, name: &str) -> MicrosandboxResult<()> {
        validate_sandbox_name(name)?;
        crate::runtime::resolve_sandbox_agent_socket_path_for(self, name).map(|_| ())
    }

    /// Validate rootfs configuration that depends on host filesystem state.
    pub(super) fn validate_rootfs_source(rootfs: &RootfsSource) -> MicrosandboxResult<()> {
        match rootfs {
            RootfsSource::Bind { path, .. } => {
                if !path.exists() {
                    return Err(crate::MicrosandboxError::InvalidConfig(format!(
                        "rootfs bind path does not exist: {}",
                        path.display()
                    )));
                }

                if !path.is_dir() {
                    return Err(crate::MicrosandboxError::InvalidConfig(format!(
                        "rootfs bind path is not a directory: {}",
                        path.display()
                    )));
                }
            }
            RootfsSource::Oci(_) => {}
            RootfsSource::DiskImage { path, .. } => {
                if !path.exists() {
                    return Err(crate::MicrosandboxError::InvalidConfig(format!(
                        "disk image does not exist: {}",
                        path.display()
                    )));
                }

                if !path.is_file() {
                    return Err(crate::MicrosandboxError::InvalidConfig(format!(
                        "disk image is not a regular file: {}",
                        path.display()
                    )));
                }
            }
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
    ) -> MicrosandboxResult<()> {
        let existing = sandbox_entity::Entity::find()
            .filter(sandbox_entity::Column::Name.eq(&config.spec.name))
            .one(pools.read())
            .await?;

        let dir_exists = sandbox_dir.exists();

        if !config.replace_existing {
            if existing.is_some() || dir_exists {
                return Err(crate::MicrosandboxError::SandboxAlreadyExists(format!(
                    "sandbox '{}' already exists; remove it, start the stopped sandbox, or recreate with .replace()",
                    config.spec.name
                )));
            }
            return Ok(());
        }

        if let Some(model) = existing {
            let sandboxes_dir = sandbox_dir.parent().ok_or_else(|| {
                crate::MicrosandboxError::InvalidConfig(format!(
                    "sandbox directory has no storage root: {}",
                    sandbox_dir.display()
                ))
            })?;
            let model = Self::reconcile_sandbox_runtime_state_with_paths(
                pools,
                model,
                Some((run_dir, sandboxes_dir)),
            )
            .await?;
            let active = matches!(
                model.status,
                SandboxStatus::Running | SandboxStatus::Draining | SandboxStatus::Paused
            );
            if active {
                Self::stop_sandbox_for_replacement(pools, &model, config.replace_with_timeout)
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
                return Err(crate::MicrosandboxError::SandboxStillRunning(format!(
                    "cannot replace sandbox {:?}: its recorded runtime process is still alive",
                    config.spec.name
                )));
            }

            microsandbox_runtime::ipc::remove_sandbox_socket_artifacts(run_dir, &config.spec.name)?;
            remove_dir_if_exists(sandbox_dir)?;

            sandbox_entity::Entity::delete_by_id(model.id)
                .exec(pools.write())
                .await?;
            return Ok(());
        }

        let _guard = crate::runtime::acquire_sandbox_lifecycle_guard(
            run_dir,
            &config.spec.name,
            std::time::Duration::from_secs(5),
        )
        .await?;
        if sandbox_runtime_endpoint_is_live(run_dir, sandbox_dir, &config.spec.name)? {
            return Err(crate::MicrosandboxError::SandboxStillRunning(format!(
                "cannot replace sandbox {:?}: an untracked runtime endpoint is still live",
                config.spec.name
            )));
        }
        microsandbox_runtime::ipc::remove_sandbox_socket_artifacts(run_dir, &config.spec.name)?;
        remove_dir_if_exists(sandbox_dir)?;
        Ok(())
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
                for pid in &pids {
                    let _ = Self::terminate_pid_gracefully(*pid);
                }
                Self::wait_for_pids_to_exit(&pids, grace).await;
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
                return Err(crate::MicrosandboxError::SandboxStillRunning(format!(
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
    pub(super) async fn insert_sandbox_record(
        db: &DbWriteConnection,
        config: &SandboxConfig,
    ) -> MicrosandboxResult<i32> {
        let config_json = serde_json::to_string(config)?;
        let labels = config.spec.labels.clone();

        db.transaction(|txn| {
            let config_json = config_json.clone();
            let labels = labels.clone();
            async move {
                let now = chrono::Utc::now().naive_utc();
                let model = sandbox_entity::ActiveModel {
                    name: Set(config.spec.name.clone()),
                    config: Set(config_json),
                    status: Set(SandboxStatus::Running),
                    ephemeral: Set(config.spec.lifecycle.ephemeral),
                    created_at: Set(Some(now)),
                    updated_at: Set(Some(now)),
                    ..Default::default()
                };
                let result = sandbox_entity::Entity::insert(model).exec(&txn).await?;
                let sandbox_id = result.last_insert_id;
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
        path: &std::path::Path,
        size_mib: u32,
        tree: Option<tree::FileTree>,
    ) -> MicrosandboxResult<()> {
        let _ = tokio::fs::remove_file(path).await;
        let ext4_options = ext4::Ext4FormatOptions {
            size_bytes: u64::from(size_mib) * 1024 * 1024,
            ..Default::default()
        };
        let overlay_tree = Self::build_overlay_upper_tree(tree);
        let path = path.to_path_buf();

        tokio::task::spawn_blocking(move || {
            ext4::format_ext4_with_tree(&path, &ext4_options, overlay_tree)
        })
        .await
        .map_err(|e| crate::MicrosandboxError::Custom(format!("ext4 format task failed: {e}")))?
        .map_err(|e| {
            crate::MicrosandboxError::Custom(format!("failed to create upper.ext4: {e}"))
        })?;

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

/// Probe every backward-compatible Unix endpoint before recovering an
/// untracked namespace. A successful connection is direct evidence that an
/// older runtime (which predates lifecycle locks) still owns the name.
#[cfg(unix)]
fn sandbox_runtime_endpoint_is_live(
    run_dir: &Path,
    sandbox_dir: &Path,
    name: &str,
) -> std::io::Result<bool> {
    let paths = microsandbox_runtime::ipc::sandbox_socket_paths(run_dir, name);
    let fallback_agent = sandbox_dir.join("runtime").join("agent.sock");
    let fallback_control = microsandbox_runtime::ipc::control_socket_path_for(&fallback_agent);
    for path in [
        paths.agent,
        paths.control,
        paths.legacy_agent,
        paths.legacy_control,
        fallback_agent,
        fallback_control,
    ] {
        if std::fs::symlink_metadata(&path).is_err() {
            continue;
        }
        match std::os::unix::net::UnixStream::connect(&path) {
            Ok(_) => return Ok(true),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

#[cfg(not(unix))]
fn sandbox_runtime_endpoint_is_live(
    _run_dir: &Path,
    _sandbox_dir: &Path,
    _name: &str,
) -> std::io::Result<bool> {
    Ok(false)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::process::Command;
    use std::{
        fs,
        path::PathBuf,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use microsandbox_db::entity::{run as run_entity, sandbox_rootfs as sandbox_rootfs_entity};
    use microsandbox_db::pool::DbPools;
    use microsandbox_migration::{Migrator, MigratorTrait};
    use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set};
    use tempfile::tempdir;

    #[cfg(unix)]
    use super::sandbox_runtime_endpoint_is_live;
    use super::{sandbox_entity, sandbox_label_entity};
    use crate::backend::{Backend, LocalBackend};
    use crate::runtime::SpawnMode;
    use crate::sandbox::{
        HostPermissions, MAX_HOSTNAME_BYTES, MountOptions, OciRootfsSource, RootfsSource,
        SandboxConfig, SandboxStatus, StatVirtualization, VolumeMount,
    };

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

    #[test]
    #[cfg(unix)]
    fn untracked_runtime_probe_distinguishes_live_and_stale_endpoints() {
        let temp = tempfile::Builder::new()
            .prefix("msb-untracked")
            .tempdir_in("/tmp")
            .unwrap();
        let run_dir = temp.path().join("run");
        let sandbox_dir = temp.path().join("sandboxes").join("worker");
        let paths = microsandbox_runtime::ipc::sandbox_socket_paths(&run_dir, "worker");
        std::fs::create_dir_all(paths.legacy_agent.parent().unwrap()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&paths.legacy_agent).unwrap();

        assert!(sandbox_runtime_endpoint_is_live(&run_dir, &sandbox_dir, "worker").unwrap());
        drop(listener);
        assert!(!sandbox_runtime_endpoint_is_live(&run_dir, &sandbox_dir, "worker").unwrap());
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
        while LocalBackend::pid_is_alive(pid) {
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
        let backend = LocalBackend::builder().home(&home).build().await.unwrap();

        backend
            .validate_sandbox_name_for_runtime("sdk-socket-test")
            .unwrap();
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
            LocalBackend::builder()
                .home(temp.path().join("home"))
                .build()
                .await
                .unwrap(),
        );
        let backend_trait: Arc<dyn Backend> = backend.clone();
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
            LocalBackend::builder()
                .home(temp.path())
                .build()
                .await
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
        let err = LocalBackend::validate_rootfs_source(&bind_rootfs(path.clone())).unwrap_err();
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

        let err = LocalBackend::validate_rootfs_source(&bind_rootfs(path.clone())).unwrap_err();
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

        LocalBackend::validate_rootfs_source(&bind_rootfs(path.clone())).unwrap();

        fs::remove_dir(path).unwrap();
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
        let sandbox_id = LocalBackend::insert_sandbox_record(pools.write(), &config)
            .await
            .unwrap();

        // First pin (no matching manifest in DB, so manifest_id will be None).
        LocalBackend::persist_oci_manifest_pin(
            pools.write(),
            sandbox_id,
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .await
        .unwrap();

        // Second pin replaces the first.
        LocalBackend::persist_oci_manifest_pin(
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
        let sandbox_id = LocalBackend::insert_sandbox_record(pools.write(), &config)
            .await
            .unwrap();

        LocalBackend::persist_oci_manifest_pin(
            pools.write(),
            sandbox_id,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .await
        .unwrap();

        // Replacing with a different digest should delete the old pin.
        LocalBackend::persist_oci_manifest_pin(
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

        let sandbox_id = LocalBackend::insert_sandbox_record(pools.write(), &config)
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

        let sandbox_id = LocalBackend::insert_sandbox_record(pools.write(), &config)
            .await
            .unwrap();
        LocalBackend::update_sandbox_active_config(pools.write(), sandbox_id, &config)
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

        let sandbox_id = LocalBackend::insert_sandbox_record(pools.write(), &config)
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
        let sandbox_id = LocalBackend::insert_sandbox_record(pools.write(), &config)
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
        let err = LocalBackend::prepare_create_target(&pools, &config, &sandbox_dir, &run_dir)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already exists"));
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
        let sandbox_id = LocalBackend::insert_sandbox_record(pools.write(), &config)
            .await
            .unwrap();
        LocalBackend::update_sandbox_status(pools.write(), sandbox_id, SandboxStatus::Stopped)
            .await
            .unwrap();

        let mut forced = test_config("replaceable");
        forced.replace_existing = true;

        let run_dir = temp.path().join("run");
        #[cfg(unix)]
        let socket_paths = {
            let paths = microsandbox_runtime::ipc::sandbox_socket_paths(&run_dir, "replaceable");
            fs::create_dir_all(&paths.canonical_dir).unwrap();
            fs::write(&paths.agent, b"stale").unwrap();
            fs::write(&paths.control, b"stale").unwrap();
            microsandbox_runtime::ipc::publish_legacy_agent_link(
                &run_dir,
                "replaceable",
                &paths.agent,
            )
            .unwrap();
            microsandbox_runtime::ipc::publish_legacy_control_link(
                &run_dir,
                "replaceable",
                &paths.control,
            )
            .unwrap();
            paths
        };
        LocalBackend::prepare_create_target(&pools, &forced, &sandbox_dir, &run_dir)
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
                .is_none()
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
        let sandbox_id = LocalBackend::insert_sandbox_record(pools.write(), &config)
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
        LocalBackend::prepare_create_target(&pools, &forced, &sandbox_dir, &run_dir)
            .await
            .unwrap();

        assert!(!sandbox_dir.exists());
        assert!(
            sandbox_entity::Entity::find_by_id(sandbox_id)
                .one(pools.write())
                .await
                .unwrap()
                .is_none()
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
        let sandbox_id = LocalBackend::insert_sandbox_record(pools.write(), &config)
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
        LocalBackend::prepare_create_target(&pools, &forced, &sandbox_dir, &run_dir)
            .await
            .unwrap();

        waiter.join().unwrap();

        assert!(!LocalBackend::pid_is_alive(live_pid));
        assert!(!sandbox_dir.exists());
        assert!(
            sandbox_entity::Entity::find_by_id(sandbox_id)
                .one(pools.write())
                .await
                .unwrap()
                .is_none()
        );
    }
}
