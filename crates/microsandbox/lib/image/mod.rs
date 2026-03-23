//! OCI image management.
//!
//! Provides a high-level interface for persisting, querying, and removing
//! OCI image metadata in the database. The on-disk layer cache is managed
//! by [`microsandbox_image::GlobalCache`]; this module owns the DB lifecycle.

use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, JoinType, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, RelationTrait, Set, TransactionTrait, sea_query::OnConflict,
};

use crate::{
    MicrosandboxError, MicrosandboxResult,
    db::entity::{
        config as config_entity, image as image_entity, layer as layer_entity,
        manifest as manifest_entity, manifest_layer as manifest_layer_entity,
        sandbox_image as sandbox_image_entity,
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
    size_bytes: Option<i64>,
    manifest_digest: Option<String>,
    architecture: Option<String>,
    os: Option<String>,
    layer_count: usize,
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: Option<chrono::DateTime<chrono::Utc>>,
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
    /// CPU architecture (e.g. `amd64`).
    pub architecture: Option<String>,
    /// Operating system (e.g. `linux`).
    pub os: Option<String>,
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
    /// Exposed ports.
    pub exposed_ports: Vec<String>,
    /// Declared volume mount points.
    pub volumes: Vec<String>,
}

/// Metadata for a single layer.
#[derive(Debug)]
pub struct ImageLayerDetail {
    /// Compressed layer digest.
    pub digest: String,
    /// Uncompressed diff ID.
    pub diff_id: String,
    /// OCI media type.
    pub media_type: Option<String>,
    /// Compressed blob size in bytes.
    pub size_bytes: Option<i64>,
    /// Layer position (0 = bottom).
    pub position: i32,
}

//--------------------------------------------------------------------------------------------------
// Methods: ImageHandle
//--------------------------------------------------------------------------------------------------

impl ImageHandle {
    /// Image reference (e.g. `docker.io/library/python:3.11`).
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Total image size in bytes, if known.
    pub fn size_bytes(&self) -> Option<i64> {
        self.size_bytes
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

    /// When this image was last used by a sandbox or pull.
    pub fn last_used_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.last_used_at
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
    /// Upserts the image, manifest, config, layers, and junction records
    /// inside a single transaction.
    pub async fn persist(
        reference: &str,
        metadata: microsandbox_image::CachedImageMetadata,
    ) -> MicrosandboxResult<i32> {
        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

        let reference = reference.to_string();

        db.transaction::<_, i32, MicrosandboxError>(|txn| {
            Box::pin(async move {
                let total_size: i64 = metadata
                    .layers
                    .iter()
                    .filter_map(|l| l.size_bytes)
                    .map(|s| i64::try_from(s).unwrap_or(i64::MAX))
                    .fold(0i64, |acc, s| acc.saturating_add(s));

                // 1. Upsert image record.
                let image_id = upsert_image_record(txn, &reference, Some(total_size)).await?;

                // 2. Upsert manifest record.
                let manifest_id =
                    upsert_manifest_record(txn, image_id, &metadata.manifest_digest).await?;

                // 3. Upsert config record.
                let platform = microsandbox_image::Platform::host_linux();
                upsert_config_record(
                    txn,
                    manifest_id,
                    &metadata.config_digest,
                    &metadata.config,
                    &platform,
                )
                .await?;

                // 4. Clear old manifest_layer entries.
                manifest_layer_entity::Entity::delete_many()
                    .filter(manifest_layer_entity::Column::ManifestId.eq(manifest_id))
                    .exec(txn)
                    .await?;

                // 5. Upsert layers and insert junction records.
                for (position, layer_meta) in metadata.layers.iter().enumerate() {
                    let layer_id = upsert_layer_record(txn, layer_meta).await?;
                    manifest_layer_entity::Entity::insert(manifest_layer_entity::ActiveModel {
                        manifest_id: Set(manifest_id),
                        layer_id: Set(layer_id),
                        position: Set(position as i32),
                        ..Default::default()
                    })
                    .exec(txn)
                    .await?;
                }

                Ok(image_id)
            })
        })
        .await
        .map_err(|err| match err {
            sea_orm::TransactionError::Connection(db_err) => db_err.into(),
            sea_orm::TransactionError::Transaction(err) => err,
        })
    }

    /// Get an image handle by reference.
    pub async fn get(reference: &str) -> MicrosandboxResult<ImageHandle> {
        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

        let image_model = image_entity::Entity::find()
            .filter(image_entity::Column::Reference.eq(reference))
            .one(db)
            .await?
            .ok_or_else(|| MicrosandboxError::ImageNotFound(reference.into()))?;

        build_handle(db, image_model).await
    }

    /// List all cached images, ordered by creation time (newest first).
    pub async fn list() -> MicrosandboxResult<Vec<ImageHandle>> {
        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

        let image_models = image_entity::Entity::find()
            .order_by_desc(image_entity::Column::CreatedAt)
            .all(db)
            .await?;

        let mut handles = Vec::with_capacity(image_models.len());
        for model in image_models {
            handles.push(build_handle(db, model).await?);
        }
        Ok(handles)
    }

    /// Get full detail for an image (config + layers).
    pub async fn inspect(reference: &str) -> MicrosandboxResult<ImageDetail> {
        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

        let image_model = image_entity::Entity::find()
            .filter(image_entity::Column::Reference.eq(reference))
            .one(db)
            .await?
            .ok_or_else(|| MicrosandboxError::ImageNotFound(reference.into()))?;

        let manifest = manifest_entity::Entity::find()
            .filter(manifest_entity::Column::ImageId.eq(image_model.id))
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
                    architecture: c.architecture,
                    os: c.os,
                    env: parse_vec("env", c.env),
                    cmd: parse_opt_vec("cmd", c.cmd),
                    entrypoint: parse_opt_vec("entrypoint", c.entrypoint),
                    working_dir: c.working_dir,
                    user: c.user,
                    exposed_ports: parse_vec("exposed_ports", c.exposed_ports),
                    volumes: parse_vec("volumes", c.volumes),
                }
            });

            let ml_rows = manifest_layer_entity::Entity::find()
                .filter(manifest_layer_entity::Column::ManifestId.eq(manifest.id))
                .order_by_asc(manifest_layer_entity::Column::Position)
                .all(db)
                .await?;

            let mut layers = Vec::with_capacity(ml_rows.len());
            for ml in ml_rows {
                if let Some(layer) = layer_entity::Entity::find_by_id(ml.layer_id)
                    .one(db)
                    .await?
                {
                    layers.push(ImageLayerDetail {
                        digest: layer.digest,
                        diff_id: layer.diff_id,
                        media_type: layer.media_type,
                        size_bytes: layer.size_bytes,
                        position: ml.position,
                    });
                }
            }

            (config_detail, layers)
        } else {
            (None, Vec::new())
        };

        let handle = build_handle_from_parts(
            &image_model,
            manifest.as_ref().map(|m| m.digest.as_str()),
            config_detail
                .as_ref()
                .and_then(|c| c.architecture.as_deref()),
            config_detail.as_ref().and_then(|c| c.os.as_deref()),
            layers.len(),
        );

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
    pub async fn remove(reference: &str, force: bool) -> MicrosandboxResult<()> {
        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

        let image_model = image_entity::Entity::find()
            .filter(image_entity::Column::Reference.eq(reference))
            .one(db)
            .await?
            .ok_or_else(|| MicrosandboxError::ImageNotFound(reference.into()))?;

        // Run all DB mutations in a transaction to avoid orphaned state.
        let image_id = image_model.id;
        let layer_digests = db
            .transaction::<_, Vec<String>, MicrosandboxError>(|txn| {
                Box::pin(async move {
                    // Check sandbox references inside transaction to avoid TOCTOU.
                    if !force {
                        let refs = sandbox_image_entity::Entity::find()
                            .filter(sandbox_image_entity::Column::ImageId.eq(image_id))
                            .all(txn)
                            .await?;
                        if !refs.is_empty() {
                            let sandbox_ids: Vec<String> =
                                refs.iter().map(|r| r.sandbox_id.to_string()).collect();
                            return Err(MicrosandboxError::ImageInUse(sandbox_ids.join(", ")));
                        }
                    }

                    // Collect layer digests before cascade delete removes junction rows.
                    let layer_digests: Vec<String> = layer_entity::Entity::find()
                        .join(
                            JoinType::InnerJoin,
                            layer_entity::Relation::ManifestLayer.def(),
                        )
                        .join(
                            JoinType::InnerJoin,
                            manifest_layer_entity::Relation::Manifest.def(),
                        )
                        .filter(manifest_entity::Column::ImageId.eq(image_id))
                        .all(txn)
                        .await?
                        .into_iter()
                        .map(|l| l.digest)
                        .collect();

                    // Delete sandbox_image references if forcing.
                    if force {
                        sandbox_image_entity::Entity::delete_many()
                            .filter(sandbox_image_entity::Column::ImageId.eq(image_id))
                            .exec(txn)
                            .await?;
                    }

                    // Delete image (cascades to manifest, config, manifest_layer).
                    image_entity::Entity::delete_by_id(image_id)
                        .exec(txn)
                        .await?;

                    // Clean up orphaned layers — only collect digests with zero remaining refs.
                    let mut orphaned_digests = Vec::new();
                    for digest_str in &layer_digests {
                        let refs = manifest_layer_entity::Entity::find()
                            .join(
                                JoinType::InnerJoin,
                                manifest_layer_entity::Relation::Layer.def(),
                            )
                            .filter(layer_entity::Column::Digest.eq(digest_str.as_str()))
                            .count(txn)
                            .await?;

                        if refs == 0 {
                            layer_entity::Entity::delete_many()
                                .filter(layer_entity::Column::Digest.eq(digest_str.as_str()))
                                .exec(txn)
                                .await?;
                            orphaned_digests.push(digest_str.clone());
                        }
                    }

                    Ok(orphaned_digests)
                })
            })
            .await
            .map_err(|err| match err {
                sea_orm::TransactionError::Connection(db_err) => db_err.into(),
                sea_orm::TransactionError::Transaction(err) => err,
            })?;

        // Best-effort on-disk cleanup (outside transaction).
        let cache_dir = crate::config::config().cache_dir();
        if let Ok(cache) = microsandbox_image::GlobalCache::new(&cache_dir) {
            for digest_str in &layer_digests {
                if let Ok(digest) = digest_str.parse::<microsandbox_image::Digest>() {
                    let _ = tokio::fs::remove_dir_all(cache.extracted_dir(&digest)).await;
                    let _ = tokio::fs::remove_file(cache.tar_path(&digest)).await;
                    let _ = tokio::fs::remove_file(cache.index_path(&digest)).await;
                    // Clean up ancillary files left by the download/extraction pipeline.
                    let _ = tokio::fs::remove_file(cache.lock_path(&digest)).await;
                    let _ = tokio::fs::remove_file(cache.download_lock_path(&digest)).await;
                    let _ = tokio::fs::remove_file(cache.part_path(&digest)).await;
                    let _ = tokio::fs::remove_file(cache.implicit_dirs_path(&digest)).await;
                    let _ = tokio::fs::remove_dir_all(cache.extracting_dir(&digest)).await;
                }
            }

            if let Ok(image_ref) = reference.parse::<microsandbox_image::Reference>() {
                let _ = cache.delete_image_metadata(&image_ref);
            }
        }

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build an [`ImageHandle`] from an image model by fetching related data.
async fn build_handle<C: ConnectionTrait>(
    db: &C,
    model: image_entity::Model,
) -> MicrosandboxResult<ImageHandle> {
    let manifest = manifest_entity::Entity::find()
        .filter(manifest_entity::Column::ImageId.eq(model.id))
        .one(db)
        .await?;

    let (digest, arch, os, layer_count) = if let Some(ref manifest) = manifest {
        let config = config_entity::Entity::find()
            .filter(config_entity::Column::ManifestId.eq(manifest.id))
            .one(db)
            .await?;

        let count = manifest_layer_entity::Entity::find()
            .filter(manifest_layer_entity::Column::ManifestId.eq(manifest.id))
            .count(db)
            .await? as usize;

        (
            Some(manifest.digest.clone()),
            config.as_ref().and_then(|c| c.architecture.clone()),
            config.as_ref().and_then(|c| c.os.clone()),
            count,
        )
    } else {
        (None, None, None, 0)
    };

    Ok(build_handle_from_parts(
        &model,
        digest.as_deref(),
        arch.as_deref(),
        os.as_deref(),
        layer_count,
    ))
}

/// Build an [`ImageHandle`] from pre-fetched parts.
fn build_handle_from_parts(
    model: &image_entity::Model,
    manifest_digest: Option<&str>,
    architecture: Option<&str>,
    os: Option<&str>,
    layer_count: usize,
) -> ImageHandle {
    ImageHandle {
        db_id: model.id,
        reference: model.reference.clone(),
        size_bytes: model.size_bytes,
        manifest_digest: manifest_digest.map(|s| s.to_string()),
        architecture: architecture.map(|s| s.to_string()),
        os: os.map(|s| s.to_string()),
        layer_count,
        last_used_at: model.last_used_at.map(|dt| dt.and_utc()),
        created_at: model.created_at.map(|dt| dt.and_utc()),
    }
}

/// Upsert an image record by reference. Returns the image ID.
pub(crate) async fn upsert_image_record<C: ConnectionTrait>(
    db: &C,
    reference: &str,
    size_bytes: Option<i64>,
) -> MicrosandboxResult<i32> {
    let now = chrono::Utc::now().naive_utc();

    let mut update_columns = vec![image_entity::Column::LastUsedAt];
    if size_bytes.is_some() {
        update_columns.push(image_entity::Column::SizeBytes);
    }

    image_entity::Entity::insert(image_entity::ActiveModel {
        reference: Set(reference.to_string()),
        size_bytes: Set(size_bytes),
        last_used_at: Set(Some(now)),
        created_at: Set(Some(now)),
        ..Default::default()
    })
    .on_conflict(
        OnConflict::column(image_entity::Column::Reference)
            .update_columns(update_columns)
            .to_owned(),
    )
    .exec(db)
    .await?;

    image_entity::Entity::find()
        .filter(image_entity::Column::Reference.eq(reference))
        .one(db)
        .await?
        .map(|model| model.id)
        .ok_or_else(|| {
            crate::MicrosandboxError::Custom(format!("image '{}' missing after upsert", reference))
        })
}

/// Upsert a manifest record by digest. Returns the manifest ID.
async fn upsert_manifest_record<C: ConnectionTrait>(
    db: &C,
    image_id: i32,
    digest: &str,
) -> MicrosandboxResult<i32> {
    let now = chrono::Utc::now().naive_utc();

    // Use DO NOTHING on conflict — manifests are shared across images when
    // multiple tags resolve to the same digest. We must not steal the manifest
    // by overwriting image_id.
    manifest_entity::Entity::insert(manifest_entity::ActiveModel {
        image_id: Set(image_id),
        digest: Set(digest.to_string()),
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
    config: &microsandbox_image::ImageConfig,
    platform: &microsandbox_image::Platform,
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
    let volumes_json = if config.volumes.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&config.volumes)?)
    };
    let exposed_ports_json = if config.exposed_ports.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&config.exposed_ports)?)
    };

    let now = chrono::Utc::now().naive_utc();

    // Delete existing config for this manifest (1:1 relationship).
    config_entity::Entity::delete_many()
        .filter(config_entity::Column::ManifestId.eq(manifest_id))
        .exec(db)
        .await?;

    config_entity::Entity::insert(config_entity::ActiveModel {
        manifest_id: Set(manifest_id),
        digest: Set(digest.to_string()),
        architecture: Set(Some(platform.arch.clone())),
        os: Set(Some(platform.os.clone())),
        os_variant: Set(None),
        env: Set(env_json),
        cmd: Set(cmd_json),
        entrypoint: Set(entrypoint_json),
        working_dir: Set(config.working_dir.clone()),
        volumes: Set(volumes_json),
        exposed_ports: Set(exposed_ports_json),
        user: Set(config.user.clone()),
        rootfs_type: Set(Some("layers".to_string())),
        rootfs_diff_ids: Set(None),
        history: Set(None),
        created_at: Set(Some(now)),
        ..Default::default()
    })
    .exec(db)
    .await?;

    Ok(())
}

/// Upsert a layer record by digest. Returns the layer ID.
async fn upsert_layer_record<C: ConnectionTrait>(
    db: &C,
    layer_meta: &microsandbox_image::CachedLayerMetadata,
) -> MicrosandboxResult<i32> {
    let now = chrono::Utc::now().naive_utc();

    layer_entity::Entity::insert(layer_entity::ActiveModel {
        digest: Set(layer_meta.digest.clone()),
        diff_id: Set(layer_meta.diff_id.clone()),
        media_type: Set(layer_meta.media_type.clone()),
        size_bytes: Set(layer_meta
            .size_bytes
            .map(|s| i64::try_from(s).unwrap_or(i64::MAX))),
        created_at: Set(Some(now)),
        ..Default::default()
    })
    .on_conflict(
        OnConflict::column(layer_entity::Column::Digest)
            .do_nothing()
            .to_owned(),
    )
    .exec(db)
    .await
    .ok(); // Ignore conflict — layer already exists.

    layer_entity::Entity::find()
        .filter(layer_entity::Column::Digest.eq(&layer_meta.digest))
        .one(db)
        .await?
        .map(|model| model.id)
        .ok_or_else(|| {
            crate::MicrosandboxError::Custom(format!(
                "layer '{}' missing after upsert",
                layer_meta.digest
            ))
        })
}
