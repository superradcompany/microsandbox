//! OCI image management.
//!
//! Provides a high-level interface for persisting, querying, and removing
//! OCI image metadata in the database. The on-disk layer cache is managed
//! by [`microsandbox_image::GlobalCache`]; this module owns the DB lifecycle.

use std::{collections::HashSet, path::Path};

use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, JoinType, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, RelationTrait, Set,
    sea_query::{Expr, OnConflict},
};

use microsandbox_image::{
    CachedImageMetadata, CachedLayerMetadata, Digest, GlobalCache, ImageArchiveFormat, ImageConfig,
    ImageLoadOptions, ImageSaveRequest, Platform, Reference,
};

use crate::{
    MicrosandboxError, MicrosandboxResult,
    backend::LocalBackend,
    db::entity::{
        config as config_entity, image_ref as image_ref_entity, layer as layer_entity,
        manifest as manifest_entity, manifest_layer as manifest_layer_entity,
        sandbox_rootfs as sandbox_rootfs_entity, snapshot as snapshot_entity,
    },
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Static methods namespace for OCI image operations.
pub struct Image;

/// A lightweight handle to a cached OCI image from the database.
///
/// Provides metadata access without requiring live queries. Obtained via
/// [`Image::get`] or [`Image::list`].
#[derive(Debug)]
pub struct ImageHandle {
    #[allow(dead_code)]
    db_id: i32,
    reference: String,
    manifest_digest: Option<String>,
    architecture: Option<String>,
    os: Option<String>,
    layer_count: usize,
    total_size_bytes: Option<i64>,
    created_at: Option<chrono::DateTime<chrono::Utc>>,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Full detail for a single image, including config and layer information.
#[derive(Debug)]
pub struct ImageDetail {
    /// Core image metadata.
    pub handle: ImageHandle,
    /// Parsed OCI config fields.
    pub config: Option<ImageConfigDetail>,
    /// Layers in bottom-to-top order.
    pub layers: Vec<ImageLayerDetail>,
}

/// OCI image config fields extracted from the database.
#[derive(Debug)]
pub struct ImageConfigDetail {
    /// Config blob digest.
    pub digest: String,
    /// Environment variables in `KEY=VALUE` format.
    pub env: Vec<String>,
    /// Default command.
    pub cmd: Option<Vec<String>>,
    /// Entrypoint.
    pub entrypoint: Option<Vec<String>>,
    /// Working directory.
    pub working_dir: Option<String>,
    /// Default user.
    pub user: Option<String>,
    /// Labels (key-value pairs).
    pub labels: Option<serde_json::Value>,
    /// Stop signal.
    pub stop_signal: Option<String>,
}

/// Metadata for a single layer.
#[derive(Debug)]
pub struct ImageLayerDetail {
    /// Uncompressed diff ID (canonical layer identity).
    pub diff_id: String,
    /// Compressed blob digest from registry.
    pub blob_digest: String,
    /// OCI media type.
    pub media_type: Option<String>,
    /// Compressed blob size in bytes.
    pub compressed_size_bytes: Option<i64>,
    /// EROFS image size in bytes.
    pub erofs_size_bytes: Option<i64>,
    /// Layer position (0 = bottom).
    pub position: i32,
}

/// Summary of artifacts removed by an image prune operation.
#[derive(Debug, Clone, Default)]
pub struct ImagePruneReport {
    /// Cached image references removed from the local image index.
    pub image_refs_removed: u32,
    /// OCI manifests removed from the local image index.
    pub manifests_removed: u32,
    /// Layer records removed from the local image index.
    pub layers_removed: u32,
    /// Merged fsmeta EROFS artifacts removed from disk.
    pub fsmeta_removed: u32,
    /// VMDK descriptor artifacts removed from disk.
    pub vmdk_removed: u32,
    /// Best-effort count of bytes reclaimed from deleted on-disk artifacts.
    pub bytes_reclaimed: Option<u64>,
}

/// Disk artifacts to clean up after a successful image prune transaction.
#[derive(Debug, Default)]
struct ImagePruneCleanup {
    references: Vec<String>,
    manifest_digests: Vec<String>,
    layer_diff_ids: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods: ImageHandle
//--------------------------------------------------------------------------------------------------

impl ImageHandle {
    /// Image reference (e.g. `docker.io/library/python`).
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Total image size in bytes, if known.
    pub fn size_bytes(&self) -> Option<i64> {
        self.total_size_bytes
    }

    /// Content-addressable manifest digest.
    pub fn manifest_digest(&self) -> Option<&str> {
        self.manifest_digest.as_deref()
    }

    /// CPU architecture resolved during pull.
    pub fn architecture(&self) -> Option<&str> {
        self.architecture.as_deref()
    }

    /// Operating system resolved during pull.
    pub fn os(&self) -> Option<&str> {
        self.os.as_deref()
    }

    /// Number of layers in the image.
    pub fn layer_count(&self) -> usize {
        self.layer_count
    }

    /// When this image reference was last updated.
    pub fn last_used_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.updated_at
    }

    /// When this image was first pulled.
    pub fn created_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.created_at
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Static
//--------------------------------------------------------------------------------------------------

impl Image {
    /// Persist full image metadata to the database after a pull.
    ///
    /// Upserts the manifest, config, layers, junction records, and image_ref
    /// inside a single transaction.
    ///
    /// Fast path: when the `image_ref` already points to a manifest whose
    /// digest matches `metadata.manifest_digest`, skip the transactional
    /// upsert entirely and only refresh `layer.last_used_at` for LRU GC.
    /// This avoids ~25–30 redundant write statements per cached create
    /// and keeps SQLite's single-writer lock free for other work.
    pub async fn persist(
        local: &LocalBackend,
        reference: &str,
        metadata: CachedImageMetadata,
    ) -> MicrosandboxResult<i32> {
        let pools = local.db().await?;
        let db = pools.write();
        let reference = reference.to_string();

        if let Some(image_ref_id) = try_persist_fast_path(db, &reference, &metadata).await? {
            return Ok(image_ref_id);
        }

        db.transaction(|txn| {
            let reference = reference.clone();
            let metadata = metadata.clone();
            async move {
                let total_size: i64 = metadata
                    .layers
                    .iter()
                    .filter_map(|l| l.size_bytes)
                    .map(|s| i64::try_from(s).unwrap_or(i64::MAX))
                    .fold(0i64, |acc, s| acc.saturating_add(s));

                let platform = Platform::host_linux();

                // 1. Upsert manifest record.
                let manifest_id = upsert_manifest_record(
                    &txn,
                    &metadata.manifest_digest,
                    &metadata.config_digest,
                    &platform,
                    metadata.layers.len() as i32,
                    total_size,
                )
                .await?;

                // 2. Upsert config record.
                upsert_config_record(&txn, manifest_id, &metadata.config_digest, &metadata.config)
                    .await?;

                // 3. Clear old manifest_layer entries.
                manifest_layer_entity::Entity::delete_many()
                    .filter(manifest_layer_entity::Column::ManifestId.eq(manifest_id))
                    .exec(&txn)
                    .await?;

                // 4. Upsert layers and insert junction records.
                let mut manifest_layers = Vec::with_capacity(metadata.layers.len());
                for (position, layer_meta) in metadata.layers.iter().enumerate() {
                    let layer_id = upsert_layer_record(&txn, layer_meta).await?;
                    manifest_layers.push(manifest_layer_entity::ActiveModel {
                        manifest_id: Set(manifest_id),
                        layer_id: Set(layer_id),
                        position: Set(position as i32),
                        ..Default::default()
                    });
                }
                if !manifest_layers.is_empty() {
                    manifest_layer_entity::Entity::insert_many(manifest_layers)
                        .exec(&txn)
                        .await?;
                }

                // 5. Upsert image_ref record.
                let image_ref_id = upsert_image_ref_record(&txn, &reference, manifest_id).await?;

                Ok((txn, image_ref_id))
            }
        })
        .await
    }

    /// Get an image handle by reference from the active local backend.
    pub async fn get(reference: &str) -> MicrosandboxResult<ImageHandle> {
        let backend = crate::backend::default_backend();
        let local = backend.as_local().ok_or_else(image_ops_unsupported)?;
        Self::get_local(local, reference).await
    }

    /// List all cached images from the active local backend, ordered by creation time.
    pub async fn list() -> MicrosandboxResult<Vec<ImageHandle>> {
        let backend = crate::backend::default_backend();
        let local = backend.as_local().ok_or_else(image_ops_unsupported)?;
        Self::list_local(local).await
    }

    /// Get full detail for an image from the active local backend.
    pub async fn inspect(reference: &str) -> MicrosandboxResult<ImageDetail> {
        let backend = crate::backend::default_backend();
        let local = backend.as_local().ok_or_else(image_ops_unsupported)?;
        Self::inspect_local(local, reference).await
    }

    /// Remove an image from the active local backend.
    ///
    /// If `force` is false and the image is referenced by any sandbox, returns
    /// [`MicrosandboxError::ImageInUse`].
    pub async fn remove(reference: &str, force: bool) -> MicrosandboxResult<()> {
        let backend = crate::backend::default_backend();
        let local = backend.as_local().ok_or_else(image_ops_unsupported)?;
        Self::remove_local(local, reference, force).await
    }

    /// Remove cached image data that is not used by any sandbox or indexed snapshot.
    pub async fn prune() -> MicrosandboxResult<ImagePruneReport> {
        let backend = crate::backend::default_backend();
        let local = backend.as_local().ok_or_else(image_ops_unsupported)?;
        Self::prune_local(local).await
    }

    /// Load images from a local archive into the active local backend's cache.
    ///
    /// Accepts `docker save` tarballs and OCI Image Layout archives. `tags`
    /// applies extra references to the first image in the archive. Returns a
    /// handle for every image reference imported.
    pub async fn load(input: &Path, tags: Vec<String>) -> MicrosandboxResult<Vec<ImageHandle>> {
        let backend = crate::backend::default_backend();
        let local = backend.as_local().ok_or_else(image_ops_unsupported)?;
        Self::load_local(local, input, tags).await
    }

    /// Save cached images from the active local backend to an archive at `output`.
    ///
    /// If any reference is missing from the local cache, returns
    /// [`MicrosandboxError::ImageNotFound`].
    pub async fn save(
        references: &[String],
        output: &Path,
        format: ImageArchiveFormat,
    ) -> MicrosandboxResult<()> {
        let backend = crate::backend::default_backend();
        let local = backend.as_local().ok_or_else(image_ops_unsupported)?;
        Self::save_local(local, references, output, format).await
    }

    /// Get an image handle by reference from an explicit local backend.
    pub async fn get_local(
        local: &LocalBackend,
        reference: &str,
    ) -> MicrosandboxResult<ImageHandle> {
        let db = local.db().await?.read();

        let (image_ref_model, manifest) = image_ref_entity::Entity::find()
            .filter(image_ref_entity::Column::Reference.eq(reference))
            .find_also_related(manifest_entity::Entity)
            .one(db)
            .await?
            .ok_or_else(|| MicrosandboxError::ImageNotFound(reference.into()))?;

        Ok(build_handle_from_parts(
            &image_ref_model,
            manifest.as_ref(),
            None,
        ))
    }

    /// List all cached images from an explicit local backend, ordered by creation time.
    pub async fn list_local(local: &LocalBackend) -> MicrosandboxResult<Vec<ImageHandle>> {
        let db = local.db().await?.read();

        let models = image_ref_entity::Entity::find()
            .order_by_desc(image_ref_entity::Column::CreatedAt)
            .find_also_related(manifest_entity::Entity)
            .all(db)
            .await?;

        let mut handles = Vec::with_capacity(models.len());
        for (model, manifest) in models {
            handles.push(build_handle_from_parts(&model, manifest.as_ref(), None));
        }
        Ok(handles)
    }

    /// Get full detail for an image from an explicit local backend.
    pub async fn inspect_local(
        local: &LocalBackend,
        reference: &str,
    ) -> MicrosandboxResult<ImageDetail> {
        let db = local.db().await?.read();

        let image_ref_model = image_ref_entity::Entity::find()
            .filter(image_ref_entity::Column::Reference.eq(reference))
            .one(db)
            .await?
            .ok_or_else(|| MicrosandboxError::ImageNotFound(reference.into()))?;

        let manifest = manifest_entity::Entity::find_by_id(image_ref_model.manifest_id)
            .one(db)
            .await?;

        let (config_detail, layers) = if let Some(ref manifest) = manifest {
            let config = config_entity::Entity::find()
                .filter(config_entity::Column::ManifestId.eq(manifest.id))
                .one(db)
                .await?;

            let config_detail = config.map(|c| {
                let parse_vec = |field: &str, raw: Option<String>| -> Vec<String> {
                    raw.and_then(|s| {
                        serde_json::from_str::<Vec<String>>(&s)
                            .map_err(|e| {
                                tracing::warn!("failed to parse config {field}: {e}");
                                e
                            })
                            .ok()
                    })
                    .unwrap_or_default()
                };
                let parse_opt_vec = |field: &str, raw: Option<String>| -> Option<Vec<String>> {
                    raw.and_then(|s| {
                        serde_json::from_str::<Vec<String>>(&s)
                            .map_err(|e| {
                                tracing::warn!("failed to parse config {field}: {e}");
                                e
                            })
                            .ok()
                    })
                };

                ImageConfigDetail {
                    digest: c.digest,
                    env: parse_vec("env", c.env),
                    cmd: parse_opt_vec("cmd", c.cmd),
                    entrypoint: parse_opt_vec("entrypoint", c.entrypoint),
                    working_dir: c.working_dir,
                    user: c.user,
                    labels: c.labels.and_then(|s| serde_json::from_str(&s).ok()),
                    stop_signal: c.stop_signal,
                }
            });

            let ml_rows = manifest_layer_entity::Entity::find()
                .filter(manifest_layer_entity::Column::ManifestId.eq(manifest.id))
                .order_by_asc(manifest_layer_entity::Column::Position)
                .find_also_related(layer_entity::Entity)
                .all(db)
                .await?;

            let mut layers = Vec::with_capacity(ml_rows.len());
            for (ml, layer) in ml_rows {
                if let Some(layer) = layer {
                    layers.push(ImageLayerDetail {
                        diff_id: layer.diff_id,
                        blob_digest: layer.blob_digest,
                        media_type: layer.media_type,
                        compressed_size_bytes: layer.compressed_size_bytes,
                        erofs_size_bytes: layer.erofs_size_bytes,
                        position: ml.position,
                    });
                }
            }

            (config_detail, layers)
        } else {
            (None, Vec::new())
        };

        let handle =
            build_handle_from_parts(&image_ref_model, manifest.as_ref(), Some(layers.len()));

        Ok(ImageDetail {
            handle,
            config: config_detail,
            layers,
        })
    }

    /// Remove an image from the database and clean up orphaned layers on disk.
    ///
    /// If `force` is false and the image is referenced by any sandbox, returns
    /// [`MicrosandboxError::ImageInUse`].
    pub async fn remove_local(
        local: &LocalBackend,
        reference: &str,
        force: bool,
    ) -> MicrosandboxResult<()> {
        let pools = local.db().await?;
        let db = pools.write();

        let image_ref_model = image_ref_entity::Entity::find()
            .filter(image_ref_entity::Column::Reference.eq(reference))
            .one(pools.read())
            .await?
            .ok_or_else(|| MicrosandboxError::ImageNotFound(reference.into()))?;

        let manifest_id = image_ref_model.manifest_id;
        let image_ref_id = image_ref_model.id;

        let (layer_diff_ids, flat_manifest_digest) = db
            .transaction(|txn| async move {
                // Check sandbox references inside transaction to avoid TOCTOU.
                if !force {
                    let refs = sandbox_rootfs_entity::Entity::find()
                        .filter(sandbox_rootfs_entity::Column::ManifestId.eq(manifest_id))
                        .all(&txn)
                        .await?;
                    if !refs.is_empty() {
                        let sandbox_ids: Vec<String> =
                            refs.iter().map(|r| r.sandbox_id.to_string()).collect();
                        return Err(MicrosandboxError::ImageInUse(sandbox_ids.join(", ")));
                    }
                }

                let manifest_digest = manifest_entity::Entity::find_by_id(manifest_id)
                    .one(&txn)
                    .await?
                    .map(|manifest| manifest.digest);

                // Collect layer diff_ids before cascade delete removes junction rows.
                let layer_diff_ids: Vec<String> = layer_entity::Entity::find()
                    .join(
                        JoinType::InnerJoin,
                        layer_entity::Relation::ManifestLayer.def(),
                    )
                    .filter(manifest_layer_entity::Column::ManifestId.eq(manifest_id))
                    .all(&txn)
                    .await?
                    .into_iter()
                    .map(|l| l.diff_id)
                    .collect();

                // Delete the image_ref.
                image_ref_entity::Entity::delete_by_id(image_ref_id)
                    .exec(&txn)
                    .await?;

                // Check if any other image_refs still point to this manifest.
                let remaining_refs = image_ref_entity::Entity::find()
                    .filter(image_ref_entity::Column::ManifestId.eq(manifest_id))
                    .count(&txn)
                    .await?;

                if remaining_refs == 0 {
                    // No more references — delete manifest (cascades to config, manifest_layers).
                    manifest_entity::Entity::delete_by_id(manifest_id)
                        .exec(&txn)
                        .await?;

                    // Clean up orphaned layers with zero remaining manifest refs.
                    let mut orphaned = Vec::new();
                    for diff_id in &layer_diff_ids {
                        let refs = manifest_layer_entity::Entity::find()
                            .join(
                                JoinType::InnerJoin,
                                manifest_layer_entity::Relation::Layer.def(),
                            )
                            .filter(layer_entity::Column::DiffId.eq(diff_id.as_str()))
                            .count(&txn)
                            .await?;

                        if refs == 0 {
                            layer_entity::Entity::delete_many()
                                .filter(layer_entity::Column::DiffId.eq(diff_id.as_str()))
                                .exec(&txn)
                                .await?;
                            orphaned.push(diff_id.clone());
                        }
                    }

                    return Ok((txn, (orphaned, manifest_digest)));
                }

                Ok((txn, (Vec::new(), None)))
            })
            .await?;

        // Best-effort on-disk cleanup (outside transaction).
        let cache_dir = local.cache_dir();
        if let Ok(cache) = GlobalCache::new(&cache_dir) {
            for diff_id_str in &layer_diff_ids {
                if let Ok(diff_id) = diff_id_str.parse::<Digest>() {
                    let _ = tokio::fs::remove_file(cache.layer_erofs_path(&diff_id)).await;
                    let _ = tokio::fs::remove_file(cache.layer_erofs_lock_path(&diff_id)).await;
                }
            }

            if let Some(manifest_digest) = flat_manifest_digest
                && let Ok(digest) = manifest_digest.parse::<Digest>()
            {
                let _ = tokio::fs::remove_file(cache.fsmeta_erofs_path(&digest)).await;
                let _ = tokio::fs::remove_file(cache.fsmeta_erofs_lock_path(&digest)).await;
                let _ = tokio::fs::remove_file(cache.vmdk_path(&digest)).await;
                let _ = tokio::fs::remove_file(cache.vmdk_lock_path(&digest)).await;
            }

            if let Ok(image_ref) = reference.parse::<Reference>() {
                let _ = cache.delete_image_metadata(&image_ref);
                let _ = tokio::fs::remove_file(cache.image_lock_path(&image_ref)).await;
            }
        }

        Ok(())
    }

    /// Remove cached image data that is not used by any sandbox or indexed snapshot.
    ///
    /// Pruning removes unused image references, then removes manifests and layers
    /// that become unreachable. Images used by existing sandboxes or snapshots
    /// are preserved.
    pub async fn prune_local(local: &LocalBackend) -> MicrosandboxResult<ImagePruneReport> {
        let pools = local.db().await?;
        let db = pools.write();

        let (mut report, cleanup) = db
            .transaction(|txn| async move {
                let sandbox_refs = sandbox_rootfs_entity::Entity::find()
                    .all(&txn)
                    .await?
                    .into_iter()
                    .filter_map(|r| r.manifest_id)
                    .collect::<HashSet<_>>();

                let snapshot_refs = snapshot_entity::Entity::find()
                    .all(&txn)
                    .await?
                    .into_iter()
                    .map(|s| s.image_manifest_digest)
                    .collect::<HashSet<_>>();

                let mut report = ImagePruneReport::default();
                let mut cleanup = ImagePruneCleanup::default();

                let image_refs = image_ref_entity::Entity::find()
                    .find_also_related(manifest_entity::Entity)
                    .all(&txn)
                    .await?;

                for (image_ref, manifest) in image_refs {
                    let Some(manifest) = manifest else {
                        continue;
                    };
                    if sandbox_refs.contains(&manifest.id)
                        || snapshot_refs.contains(manifest.digest.as_str())
                    {
                        continue;
                    }

                    image_ref_entity::Entity::delete_by_id(image_ref.id)
                        .exec(&txn)
                        .await?;
                    cleanup.references.push(image_ref.reference);
                    report.image_refs_removed += 1;
                }

                let manifests = manifest_entity::Entity::find().all(&txn).await?;
                for manifest in manifests {
                    if sandbox_refs.contains(&manifest.id)
                        || snapshot_refs.contains(manifest.digest.as_str())
                    {
                        continue;
                    }

                    let remaining_refs = image_ref_entity::Entity::find()
                        .filter(image_ref_entity::Column::ManifestId.eq(manifest.id))
                        .count(&txn)
                        .await?;
                    if remaining_refs > 0 {
                        continue;
                    }

                    manifest_entity::Entity::delete_by_id(manifest.id)
                        .exec(&txn)
                        .await?;

                    cleanup.manifest_digests.push(manifest.digest);
                    report.manifests_removed += 1;
                }

                let orphaned_layers = layer_entity::Entity::find()
                    .left_join(manifest_layer_entity::Entity)
                    .filter(manifest_layer_entity::Column::Id.is_null())
                    .all(&txn)
                    .await?;

                for layer in orphaned_layers {
                    layer_entity::Entity::delete_by_id(layer.id)
                        .exec(&txn)
                        .await?;
                    cleanup.layer_diff_ids.push(layer.diff_id);
                    report.layers_removed += 1;
                }

                cleanup.layer_diff_ids.sort();
                cleanup.layer_diff_ids.dedup();

                Ok::<_, MicrosandboxError>((txn, (report, cleanup)))
            })
            .await?;

        let cache_dir = local.cache_dir();
        if let Ok(cache) = GlobalCache::new(&cache_dir) {
            let mut bytes_reclaimed = 0u64;
            let mut measured = false;

            for reference in &cleanup.references {
                if let Ok(image_ref) = reference.parse::<Reference>() {
                    let (removed, bytes) =
                        remove_file_measured(&cache.image_metadata_path(&image_ref)).await;
                    measured |= removed;
                    bytes_reclaimed = bytes_reclaimed.saturating_add(bytes);

                    let _ = tokio::fs::remove_file(cache.image_lock_path(&image_ref)).await;
                }
            }

            for diff_id_str in &cleanup.layer_diff_ids {
                if let Ok(diff_id) = diff_id_str.parse::<Digest>() {
                    let (removed, bytes) =
                        remove_file_measured(&cache.layer_erofs_path(&diff_id)).await;
                    measured |= removed;
                    bytes_reclaimed = bytes_reclaimed.saturating_add(bytes);
                    let _ = tokio::fs::remove_file(cache.layer_erofs_lock_path(&diff_id)).await;
                }
            }

            for manifest_digest in &cleanup.manifest_digests {
                if let Ok(digest) = manifest_digest.parse::<Digest>() {
                    let (removed, bytes) =
                        remove_file_measured(&cache.fsmeta_erofs_path(&digest)).await;
                    if removed {
                        report.fsmeta_removed += 1;
                    }
                    measured |= removed;
                    bytes_reclaimed = bytes_reclaimed.saturating_add(bytes);
                    let _ = tokio::fs::remove_file(cache.fsmeta_erofs_lock_path(&digest)).await;

                    let (removed, bytes) = remove_file_measured(&cache.vmdk_path(&digest)).await;
                    if removed {
                        report.vmdk_removed += 1;
                    }
                    measured |= removed;
                    bytes_reclaimed = bytes_reclaimed.saturating_add(bytes);
                    let _ = tokio::fs::remove_file(cache.vmdk_lock_path(&digest)).await;
                }
            }

            if measured {
                report.bytes_reclaimed = Some(bytes_reclaimed);
            }
        }

        Ok(report)
    }

    /// Load images from a local archive into an explicit local backend's cache.
    ///
    /// Accepts `docker save` tarballs and OCI Image Layout archives. `tags`
    /// applies extra references to the first image in the archive. Each loaded
    /// image is persisted to the database and returned as an [`ImageHandle`].
    pub async fn load_local(
        local: &LocalBackend,
        input: &Path,
        tags: Vec<String>,
    ) -> MicrosandboxResult<Vec<ImageHandle>> {
        let cache_dir = local.cache_dir();
        let loaded = microsandbox_image::load_archive(
            &cache_dir,
            input,
            ImageLoadOptions {
                tags,
                progress: None,
            },
        )
        .await?;

        let mut handles = Vec::with_capacity(loaded.len());
        for image in loaded {
            Self::persist(local, &image.reference, image.metadata).await?;
            handles.push(Self::get_local(local, &image.reference).await?);
        }
        Ok(handles)
    }

    /// Save cached images from an explicit local backend to an archive at `output`.
    ///
    /// If any reference is missing from the local cache, returns
    /// [`MicrosandboxError::ImageNotFound`].
    pub async fn save_local(
        local: &LocalBackend,
        references: &[String],
        output: &Path,
        format: ImageArchiveFormat,
    ) -> MicrosandboxResult<()> {
        let cache_dir = local.cache_dir();
        let references = references.to_vec();
        let output = output.to_path_buf();

        // Metadata reads and the archive write are all blocking filesystem
        // work, so the whole save runs off the async runtime.
        tokio::task::spawn_blocking(move || -> MicrosandboxResult<()> {
            let cache = GlobalCache::new(&cache_dir)?;

            let mut requests = Vec::with_capacity(references.len());
            for reference in references {
                let parsed: Reference = reference.parse().map_err(|e| {
                    MicrosandboxError::Custom(format!("invalid image reference '{reference}': {e}"))
                })?;
                let metadata = cache
                    .read_image_metadata(&parsed)?
                    .ok_or_else(|| MicrosandboxError::ImageNotFound(reference.clone()))?;
                requests.push(ImageSaveRequest::from_cached(reference, metadata));
            }

            microsandbox_image::save_archive(&cache, &output, &requests, format)?;
            Ok(())
        })
        .await
        .map_err(|e| MicrosandboxError::Custom(format!("image save task panicked: {e}")))?
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build an [`ImageHandle`] from pre-fetched parts.
fn build_handle_from_parts(
    model: &image_ref_entity::Model,
    manifest: Option<&manifest_entity::Model>,
    layer_count: Option<usize>,
) -> ImageHandle {
    ImageHandle {
        db_id: model.id,
        reference: model.reference.clone(),
        manifest_digest: manifest.map(|m| m.digest.clone()),
        architecture: manifest.and_then(|m| m.architecture.clone()),
        os: manifest.and_then(|m| m.os.clone()),
        layer_count: layer_count
            .or_else(|| {
                manifest.and_then(|m| usize::try_from(m.layer_count.unwrap_or_default()).ok())
            })
            .unwrap_or_default(),
        total_size_bytes: manifest.and_then(|m| m.total_size_bytes),
        created_at: model.created_at.map(|dt| dt.and_utc()),
        updated_at: model.updated_at.map(|dt| dt.and_utc()),
    }
}

/// Error returned when local image-cache operations are used with a cloud backend.
fn image_ops_unsupported() -> MicrosandboxError {
    MicrosandboxError::Unsupported {
        feature: "image ops on cloud".into(),
        available_when: "with a local backend".into(),
    }
}

/// Remove a file and return whether it existed plus its measured size.
async fn remove_file_measured(path: &Path) -> (bool, u64) {
    let bytes = tokio::fs::metadata(path)
        .await
        .map(|m| m.len())
        .unwrap_or_default();

    match tokio::fs::remove_file(path).await {
        Ok(()) => (true, bytes),
        Err(_) => (false, 0),
    }
}

/// Upsert an image_ref record by reference. Returns the image_ref ID.
pub(crate) async fn upsert_image_ref_record<C: ConnectionTrait>(
    db: &C,
    reference: &str,
    manifest_id: i32,
) -> MicrosandboxResult<i32> {
    let now = chrono::Utc::now().naive_utc();

    image_ref_entity::Entity::insert(image_ref_entity::ActiveModel {
        reference: Set(reference.to_string()),
        manifest_id: Set(manifest_id),
        created_at: Set(Some(now)),
        updated_at: Set(Some(now)),
        ..Default::default()
    })
    .on_conflict(
        OnConflict::column(image_ref_entity::Column::Reference)
            .update_columns([
                image_ref_entity::Column::ManifestId,
                image_ref_entity::Column::UpdatedAt,
            ])
            .to_owned(),
    )
    .exec(db)
    .await?;

    image_ref_entity::Entity::find()
        .filter(image_ref_entity::Column::Reference.eq(reference))
        .one(db)
        .await?
        .map(|model| model.id)
        .ok_or_else(|| {
            crate::MicrosandboxError::Custom(format!(
                "image_ref '{}' missing after upsert",
                reference
            ))
        })
}

/// Upsert a manifest record by digest. Returns the manifest ID.
async fn upsert_manifest_record<C: ConnectionTrait>(
    db: &C,
    digest: &str,
    config_digest: &str,
    platform: &Platform,
    layer_count: i32,
    total_size_bytes: i64,
) -> MicrosandboxResult<i32> {
    let now = chrono::Utc::now().naive_utc();

    manifest_entity::Entity::insert(manifest_entity::ActiveModel {
        digest: Set(digest.to_string()),
        config_digest: Set(Some(config_digest.to_string())),
        architecture: Set(Some(platform.arch.to_string())),
        os: Set(Some(platform.os.to_string())),
        variant: Set(None),
        layer_count: Set(Some(layer_count)),
        total_size_bytes: Set(Some(total_size_bytes)),
        created_at: Set(Some(now)),
        ..Default::default()
    })
    .on_conflict(
        OnConflict::column(manifest_entity::Column::Digest)
            .do_nothing()
            .to_owned(),
    )
    .exec(db)
    .await
    .ok(); // Ignore conflict — manifest already exists.

    manifest_entity::Entity::find()
        .filter(manifest_entity::Column::Digest.eq(digest))
        .one(db)
        .await?
        .map(|model| model.id)
        .ok_or_else(|| {
            crate::MicrosandboxError::Custom(format!("manifest '{}' missing after upsert", digest))
        })
}

/// Upsert a config record for a manifest.
async fn upsert_config_record<C: ConnectionTrait>(
    db: &C,
    manifest_id: i32,
    digest: &str,
    config: &ImageConfig,
) -> MicrosandboxResult<()> {
    let env_json = if config.env.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&config.env)?)
    };
    let cmd_json = config.cmd.as_ref().map(serde_json::to_string).transpose()?;
    let entrypoint_json = config
        .entrypoint
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;

    let now = chrono::Utc::now().naive_utc();

    // Delete existing config for this manifest (1:1 relationship).
    config_entity::Entity::delete_many()
        .filter(config_entity::Column::ManifestId.eq(manifest_id))
        .exec(db)
        .await?;

    config_entity::Entity::insert(config_entity::ActiveModel {
        manifest_id: Set(manifest_id),
        digest: Set(digest.to_string()),
        env: Set(env_json),
        cmd: Set(cmd_json),
        entrypoint: Set(entrypoint_json),
        working_dir: Set(config.working_dir.clone()),
        user: Set(config.user.clone()),
        labels: Set(None),
        stop_signal: Set(None),
        created_at: Set(Some(now)),
        ..Default::default()
    })
    .exec(db)
    .await?;

    Ok(())
}

/// Upsert a layer record by diff_id. Returns the layer ID.
async fn upsert_layer_record<C: ConnectionTrait>(
    db: &C,
    layer_meta: &CachedLayerMetadata,
) -> MicrosandboxResult<i32> {
    let now = chrono::Utc::now().naive_utc();

    layer_entity::Entity::insert(layer_entity::ActiveModel {
        diff_id: Set(layer_meta.diff_id.clone()),
        blob_digest: Set(layer_meta.digest.clone()),
        media_type: Set(layer_meta.media_type.clone()),
        compressed_size_bytes: Set(layer_meta
            .size_bytes
            .map(|s| i64::try_from(s).unwrap_or(i64::MAX))),
        erofs_size_bytes: Set(None),
        created_at: Set(Some(now)),
        last_used_at: Set(Some(now)),
        ..Default::default()
    })
    .on_conflict(
        OnConflict::column(layer_entity::Column::DiffId)
            .update_column(layer_entity::Column::LastUsedAt)
            .to_owned(),
    )
    .exec(db)
    .await
    .ok(); // Ignore conflict — layer already exists.

    layer_entity::Entity::find()
        .filter(layer_entity::Column::DiffId.eq(&layer_meta.diff_id))
        .one(db)
        .await?
        .map(|model| model.id)
        .ok_or_else(|| {
            crate::MicrosandboxError::Custom(format!(
                "layer '{}' missing after upsert",
                layer_meta.diff_id
            ))
        })
}

/// Attempt to satisfy `Image::persist` with a couple of bulk UPDATEs.
///
/// Returns `Some(image_ref_id)` when the database is already consistent with
/// `metadata` (i.e. the `image_ref` row exists, points to a manifest whose
/// digest matches `metadata.manifest_digest`, and every expected `layer` row
/// is present). In that case the only writes performed are a bulk
/// `UPDATE layer SET last_used_at` and an `UPDATE image_ref SET updated_at`
/// for LRU bookkeeping — the manifest, config, layer, and junction rows are
/// content-addressed and guaranteed to be unchanged for a given manifest
/// digest.
///
/// Returns `None` when the caller must fall through to the full transactional
/// upsert (fresh DB, manifest digest changed, partially persisted state).
async fn try_persist_fast_path(
    db: &microsandbox_db::DbWriteConnection,
    reference: &str,
    metadata: &CachedImageMetadata,
) -> MicrosandboxResult<Option<i32>> {
    let Some((image_ref_model, Some(manifest))) = image_ref_entity::Entity::find()
        .filter(image_ref_entity::Column::Reference.eq(reference))
        .find_also_related(manifest_entity::Entity)
        .one(db)
        .await?
    else {
        return Ok(None);
    };

    if manifest.digest != metadata.manifest_digest {
        return Ok(None);
    }

    let now = chrono::Utc::now().naive_utc();

    if !metadata.layers.is_empty() {
        let diff_ids: Vec<String> = metadata
            .layers
            .iter()
            .map(|layer| layer.diff_id.clone())
            .collect();

        // Sanity count check to verify all layers exist in the database.
        let existing_layer_count = layer_entity::Entity::find()
            .filter(layer_entity::Column::DiffId.is_in(diff_ids.clone()))
            .count(db)
            .await?;
        if existing_layer_count != metadata.layers.len() as u64 {
            return Ok(None);
        }

        // Refresh layer.last_used_at
        layer_entity::Entity::update_many()
            .col_expr(layer_entity::Column::LastUsedAt, Expr::value(now))
            .filter(layer_entity::Column::DiffId.is_in(diff_ids))
            .exec(db)
            .await?;
    }

    // Refresh image_ref.updated_at
    image_ref_entity::Entity::update_many()
        .col_expr(image_ref_entity::Column::UpdatedAt, Expr::value(now))
        .filter(image_ref_entity::Column::Id.eq(image_ref_model.id))
        .exec(db)
        .await?;

    Ok(Some(image_ref_model.id))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[test]
    fn test_default_backend_image_api_methods_stay_available() {
        // Compile-time tripwire for the pre-backend-routing Rust API shape.
        // The functions are referenced without invoking them so this test does
        // not touch the user's image cache.
        let _ = super::Image::get;
        let _ = super::Image::list;
        let _ = super::Image::inspect;
        let _ = super::Image::remove;
        let _ = super::Image::prune;
        let _ = super::Image::load;
        let _ = super::Image::save;
    }
}
