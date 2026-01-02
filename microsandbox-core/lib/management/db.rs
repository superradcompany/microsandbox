//! Database management for Microsandbox.
//!
//! This module provides database functionality for Microsandbox, managing both sandbox
//! and OCI (Open Container Initiative) related data. It handles database initialization,
//! migrations, and operations for storing and retrieving container images, layers,
//! and sandbox configurations.

use std::path::Path;

use chrono::{DateTime, NaiveDateTime, Utc};
use oci_client::{
    config::ConfigFile,
    manifest::{OciDescriptor, OciImageManifest},
};
use oci_spec::image::MediaType;
use sqlx::{Pool, Row, Sqlite, migrate::Migrator, sqlite::SqlitePoolOptions};
use tokio::fs;

use crate::{
    MicrosandboxResult,
    models::{Config, Image, Layer, Manifest, Sandbox},
    runtime::SANDBOX_STATUS_RUNNING,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Migrator for the sandbox database
pub static SANDBOX_DB_MIGRATOR: Migrator = sqlx::migrate!("lib/migrations/sandbox");

/// Migrator for the OCI database
pub static OCI_DB_MIGRATOR: Migrator = sqlx::migrate!("lib/migrations/oci");

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Initializes a new SQLite database if it doesn't already exist at the specified path.
///
/// ## Arguments
///
/// * `db_path` - Path where the SQLite database file should be created
/// * `migrator` - SQLx migrator containing database schema migrations to run
pub async fn initialize(
    db_path: impl AsRef<Path>,
    migrator: &Migrator,
) -> MicrosandboxResult<Pool<Sqlite>> {
    let db_path = db_path.as_ref();

    // Ensure parent directory exists
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent).await?;
    }

    // Create an empty database file if it doesn't exist
    if !db_path.exists() {
        fs::File::create(&db_path).await?;
    }

    // Create database connection pool
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&format!("sqlite://{}?mode=rwc", db_path.display()))
        .await?;

    // Run migrations
    migrator.run(&pool).await?;

    Ok(pool)
}

/// Creates and returns a connection pool for SQLite database operations.
///
/// This function initializes a new SQLite connection pool with specified configuration parameters
/// for managing database connections efficiently. The pool is configured with a maximum of 5
/// concurrent connections.
pub async fn get_pool(db_path: impl AsRef<Path>) -> MicrosandboxResult<Pool<Sqlite>> {
    let db_path = db_path.as_ref();
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&format!("sqlite://{}?mode=rwc", db_path.display()))
        .await?;

    Ok(pool)
}

/// Gets an existing database connection pool or creates a new one if the database doesn't exist.
///
/// This function combines database initialization and pool creation into a single operation.
/// If the database doesn't exist, it will be created and migrations will be run before
/// returning the connection pool.
///
/// ## Arguments
///
/// * `db_path` - Path to the SQLite database file
/// * `migrator` - SQLx migrator containing database schema migrations to run
pub async fn get_or_create_pool(
    db_path: impl AsRef<Path>,
    migrator: &Migrator,
) -> MicrosandboxResult<Pool<Sqlite>> {
    // Initialize the database if it doesn't exist
    initialize(&db_path, migrator).await
}

//--------------------------------------------------------------------------------------------------
// Functions: Sandboxes
//--------------------------------------------------------------------------------------------------

/// Saves or updates a sandbox in the database and returns its ID.
/// If a sandbox with the same name and config_file exists, it will be updated.
/// Otherwise, a new sandbox record will be created.
pub(crate) async fn save_or_update_sandbox(
    pool: &Pool<Sqlite>,
    name: &str,
    config_file: &str,
    config_last_modified: &DateTime<Utc>,
    status: &str,
    supervisor_pid: u32,
    microvm_pid: u32,
    rootfs_paths: &str,
) -> MicrosandboxResult<i64> {
    let sandbox = Sandbox {
        id: 0,
        name: name.to_string(),
        config_file: config_file.to_string(),
        config_last_modified: config_last_modified.clone(),
        status: status.to_string(),
        supervisor_pid,
        microvm_pid,
        rootfs_paths: rootfs_paths.to_string(),
        created_at: Utc::now(),
        modified_at: Utc::now(),
    };

    // Try to update first
    let update_result = sqlx::query(
        r#"
        UPDATE sandboxes
        SET config_last_modified = ?,
            status = ?,
            supervisor_pid = ?,
            microvm_pid = ?,
            rootfs_paths = ?,
            modified_at = CURRENT_TIMESTAMP
        WHERE name = ? AND config_file = ?
        RETURNING id
        "#,
    )
    .bind(&sandbox.config_last_modified.to_rfc3339())
    .bind(&sandbox.status)
    .bind(&sandbox.supervisor_pid)
    .bind(&sandbox.microvm_pid)
    .bind(&sandbox.rootfs_paths)
    .bind(&sandbox.name)
    .bind(&sandbox.config_file)
    .fetch_optional(pool)
    .await?;

    if let Some(record) = update_result {
        tracing::debug!("updated existing sandbox record");
        Ok(record.get::<i64, _>("id"))
    } else {
        // If no record was updated, insert a new one
        tracing::debug!("creating new sandbox record");
        let record = sqlx::query(
            r#"
            INSERT INTO sandboxes (
                name, config_file, config_last_modified,
                status, supervisor_pid, microvm_pid, rootfs_paths
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            RETURNING id
            "#,
        )
        .bind(sandbox.name)
        .bind(sandbox.config_file)
        .bind(sandbox.config_last_modified.to_rfc3339())
        .bind(sandbox.status)
        .bind(sandbox.supervisor_pid)
        .bind(sandbox.microvm_pid)
        .bind(sandbox.rootfs_paths)
        .fetch_one(pool)
        .await?;

        Ok(record.get::<i64, _>("id"))
    }
}

pub(crate) async fn get_sandbox(
    pool: &Pool<Sqlite>,
    name: &str,
    config_file: &str,
) -> MicrosandboxResult<Option<Sandbox>> {
    let record = sqlx::query(
        r#"
        SELECT id, name, config_file, config_last_modified, status,
               supervisor_pid, microvm_pid, rootfs_paths,
               created_at, modified_at
        FROM sandboxes
        WHERE name = ? AND config_file = ?
        "#,
    )
    .bind(name)
    .bind(config_file)
    .fetch_optional(pool)
    .await?;

    Ok(record.map(|row| Sandbox {
        id: row.get("id"),
        name: row.get("name"),
        config_file: row.get("config_file"),
        config_last_modified: row
            .get::<String, _>("config_last_modified")
            .parse::<DateTime<Utc>>()
            .unwrap(),
        status: row.get("status"),
        supervisor_pid: row.get("supervisor_pid"),
        microvm_pid: row.get("microvm_pid"),
        rootfs_paths: row.get("rootfs_paths"),
        created_at: parse_sqlite_datetime(&row.get::<String, _>("created_at")),
        modified_at: parse_sqlite_datetime(&row.get::<String, _>("modified_at")),
    }))
}

/// Updates the status of a sandbox identified by name and config file
pub(crate) async fn update_sandbox_status(
    pool: &Pool<Sqlite>,
    name: &str,
    config_file: &str,
    status: &str,
) -> MicrosandboxResult<()> {
    sqlx::query(
        r#"
        UPDATE sandboxes
        SET status = ?,
            modified_at = CURRENT_TIMESTAMP
        WHERE name = ? AND config_file = ?
        "#,
    )
    .bind(status)
    .bind(name)
    .bind(config_file)
    .execute(pool)
    .await?;

    Ok(())
}

/// Gets all sandboxes associated with a specific config file
pub(crate) async fn get_running_config_sandboxes(
    pool: &Pool<Sqlite>,
    config_file: &str,
) -> MicrosandboxResult<Vec<Sandbox>> {
    let records = sqlx::query(
        r#"
        SELECT id, name, config_file, config_last_modified, status,
               supervisor_pid, microvm_pid, rootfs_paths,
               created_at, modified_at
        FROM sandboxes
        WHERE config_file = ? AND status = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(config_file)
    .bind(SANDBOX_STATUS_RUNNING)
    .fetch_all(pool)
    .await?;

    Ok(records
        .into_iter()
        .map(|row| Sandbox {
            id: row.get("id"),
            name: row.get("name"),
            config_file: row.get("config_file"),
            config_last_modified: row
                .get::<String, _>("config_last_modified")
                .parse::<DateTime<Utc>>()
                .unwrap(),
            status: row.get("status"),
            supervisor_pid: row.get("supervisor_pid"),
            microvm_pid: row.get("microvm_pid"),
            rootfs_paths: row.get("rootfs_paths"),
            created_at: parse_sqlite_datetime(&row.get::<String, _>("created_at")),
            modified_at: parse_sqlite_datetime(&row.get::<String, _>("modified_at")),
        })
        .collect())
}

/// Deletes a sandbox from the database by name and config file.
pub(crate) async fn delete_sandbox(
    pool: &Pool<Sqlite>,
    name: &str,
    config_file: &str,
) -> MicrosandboxResult<()> {
    sqlx::query(
        r#"
        DELETE FROM sandboxes
        WHERE name = ? AND config_file = ?
        "#,
    )
    .bind(name)
    .bind(config_file)
    .execute(pool)
    .await?;

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Images
//--------------------------------------------------------------------------------------------------

/// Saves an image to the database and returns its ID
pub(crate) async fn save_image(
    pool: &Pool<Sqlite>,
    reference: &str,
    size_bytes: i64,
) -> MicrosandboxResult<i64> {
    let image = Image {
        id: 0, // Will be set by the database
        reference: reference.to_string(),
        size_bytes,
        last_used_at: Some(Utc::now()),
        created_at: Utc::now(),
        modified_at: Utc::now(),
    };

    let record = sqlx::query(
        r#"
        INSERT INTO images (reference, size_bytes, last_used_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        RETURNING id
        "#,
    )
    .bind(&image.reference)
    .bind(image.size_bytes)
    .fetch_one(pool)
    .await?;

    Ok(record.get::<i64, _>("id"))
}

/// Saves an image manifest to the database and returns its ID
pub(crate) async fn save_manifest(
    pool: &Pool<Sqlite>,
    image_id: i64,
    manifest: &OciImageManifest,
) -> MicrosandboxResult<i64> {
    let manifest_model = Manifest {
        id: 0, // Will be set by the database
        image_id,
        schema_version: manifest.schema_version as i64,
        media_type: manifest
            .media_type
            .as_ref()
            .map(|mt| mt.to_string())
            .unwrap_or_else(|| MediaType::ImageManifest.to_string()),
        annotations_json: manifest
            .annotations
            .as_ref()
            .map(|a| serde_json::to_string(a).unwrap_or_default()),
        created_at: Utc::now(),
        modified_at: Utc::now(),
    };

    let record = sqlx::query(
        r#"
        INSERT INTO manifests (
            image_id, schema_version,
            media_type, annotations_json
        )
        VALUES (?, ?, ?, ?)
        RETURNING id
        "#,
    )
    .bind(manifest_model.image_id)
    .bind(manifest_model.schema_version)
    .bind(&manifest_model.media_type)
    .bind(&manifest_model.annotations_json)
    .fetch_one(pool)
    .await?;

    Ok(record.get::<i64, _>("id"))
}

/// Saves an image configuration to the database
pub(crate) async fn save_config(
    pool: &Pool<Sqlite>,
    manifest_id: i64,
    config: &ConfigFile,
) -> MicrosandboxResult<i64> {
    let config_model = Config {
        id: 0, // Will be set by the database
        manifest_id,
        media_type: MediaType::ImageConfig.to_string(),
        created: config.created.clone(),
        architecture: config.architecture.to_string(),
        os: config.os.to_string(),
        // os_variant isn't in the formal spec, and is up to the implementer.
        // Since we don't need it, we skip it for backward compatibility.
        os_variant: None,
        config_env_json: config
            .config
            .as_ref()
            .map(|c| serde_json::to_string(&c.env).unwrap_or_default()),
        config_cmd_json: config
            .config
            .as_ref()
            .map(|c| serde_json::to_string(&c.cmd).unwrap_or_default()),
        config_working_dir: config
            .config
            .as_ref()
            .and_then(|c| c.working_dir.as_ref().map(String::from)),
        config_entrypoint_json: config
            .config
            .as_ref()
            .map(|c| serde_json::to_string(&c.entrypoint).unwrap_or_default()),
        config_volumes_json: config
            .config
            .as_ref()
            .map(|c| serde_json::to_string(&c.volumes).unwrap_or_default()),
        config_exposed_ports_json: config
            .config
            .as_ref()
            .map(|c| serde_json::to_string(&c.exposed_ports).unwrap_or_default()),
        config_user: config
            .config
            .as_ref()
            .and_then(|c| c.user.as_ref().map(String::from)),
        rootfs_type: config.rootfs.r#type.to_string(),
        rootfs_diff_ids_json: Some(
            serde_json::to_string(&config.rootfs.diff_ids).unwrap_or_default(),
        ),
        history_json: Some(serde_json::to_string(&config.history).unwrap_or_default()),
        created_at: Utc::now(),
        modified_at: Utc::now(),
    };

    let record = sqlx::query(
        r#"
        INSERT INTO configs (
            manifest_id, media_type, created, architecture,
            os, os_variant, config_env_json, config_cmd_json,
            config_working_dir, config_entrypoint_json,
            config_volumes_json, config_exposed_ports_json,
            config_user, rootfs_type, rootfs_diff_ids_json,
            history_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING id
        "#,
    )
    .bind(config_model.manifest_id)
    .bind(&config_model.media_type)
    .bind(config_model.created.map(|dt| dt.to_rfc3339()))
    .bind(&config_model.architecture)
    .bind(&config_model.os)
    .bind(&config_model.os_variant)
    .bind(&config_model.config_env_json)
    .bind(&config_model.config_cmd_json)
    .bind(&config_model.config_working_dir)
    .bind(&config_model.config_entrypoint_json)
    .bind(&config_model.config_volumes_json)
    .bind(&config_model.config_exposed_ports_json)
    .bind(&config_model.config_user)
    .bind(&config_model.rootfs_type)
    .bind(&config_model.rootfs_diff_ids_json)
    .bind(&config_model.history_json)
    .fetch_one(pool)
    .await?;

    Ok(record.get::<i64, _>("id"))
}

/// Saves an image layer to the database
pub(crate) async fn save_layer(
    pool: &Pool<Sqlite>,
    media_type: &str,
    digest: &str,
    size_bytes: i64,
    diff_id: &str,
) -> MicrosandboxResult<i64> {
    let layer_model = Layer {
        id: 0, // Will be set by the database
        media_type: media_type.to_string(),
        digest: digest.to_string(),
        diff_id: diff_id.to_string(),
        size_bytes,
        created_at: Utc::now(),
        modified_at: Utc::now(),
    };

    let record = sqlx::query(
        r#"
        INSERT INTO layers (
            media_type, digest, size_bytes, diff_id
        )
        VALUES (?, ?, ?, ?)
        RETURNING id
        "#,
    )
    .bind(&layer_model.media_type)
    .bind(&layer_model.digest)
    .bind(layer_model.size_bytes)
    .bind(&layer_model.diff_id)
    .fetch_one(pool)
    .await?;

    Ok(record.get::<i64, _>("id"))
}

/// Saves or updates a layer in the database.
/// If the layer exists, it updates the size_bytes and other fields.
/// If it doesn't exist, creates a new record.
pub(crate) async fn save_or_update_layer(
    pool: &Pool<Sqlite>,
    media_type: &str,
    digest: &str,
    size_bytes: i64,
    diff_id: &str,
) -> MicrosandboxResult<i64> {
    let layer_model = Layer {
        id: 0, // Will be set by the database
        media_type: media_type.to_string(),
        digest: digest.to_string(),
        diff_id: diff_id.to_string(),
        size_bytes,
        created_at: Utc::now(),
        modified_at: Utc::now(),
    };

    // Try to update first
    let update_result = sqlx::query(
        r#"
        UPDATE layers
        SET media_type = ?,
            size_bytes = ?,
            diff_id = ?,
            modified_at = CURRENT_TIMESTAMP
        WHERE digest = ?
        RETURNING id
        "#,
    )
    .bind(&layer_model.media_type)
    .bind(layer_model.size_bytes)
    .bind(&layer_model.diff_id)
    .bind(&layer_model.digest)
    .fetch_optional(pool)
    .await?;

    if let Some(record) = update_result {
        Ok(record.get::<i64, _>("id"))
    } else {
        // If no record was updated, insert a new one
        save_layer(pool, media_type, digest, size_bytes, diff_id).await
    }
}

/// Associates a layer with a manifest in the manifest_layers join table
pub(crate) async fn save_manifest_layer(
    pool: &Pool<Sqlite>,
    manifest_id: i64,
    layer_id: i64,
) -> MicrosandboxResult<i64> {
    let record = sqlx::query(
        r#"
        INSERT INTO manifest_layers (manifest_id, layer_id)
        VALUES (?, ?)
        ON CONFLICT (manifest_id, layer_id) DO NOTHING
        RETURNING id
        "#,
    )
    .bind(manifest_id)
    .bind(layer_id)
    .fetch_optional(pool)
    .await?;

    if let Some(record) = record {
        Ok(record.get::<i64, _>("id"))
    } else {
        // If no record was inserted (because it already exists), fetch the existing ID
        let record = sqlx::query(
            r#"
            SELECT id FROM manifest_layers
            WHERE manifest_id = ? AND layer_id = ?
            "#,
        )
        .bind(manifest_id)
        .bind(layer_id)
        .fetch_one(pool)
        .await?;

        Ok(record.get::<i64, _>("id"))
    }
}

/// Gets all layers for an image from the database.
pub async fn get_image_layers(
    pool: &Pool<Sqlite>,
    reference: &str,
) -> MicrosandboxResult<Vec<Layer>> {
    let records = sqlx::query(
        r#"
        SELECT l.id, l.media_type, l.digest,
               l.diff_id, l.size_bytes, l.created_at, l.modified_at
        FROM layers l
        JOIN manifest_layers ml ON l.id = ml.layer_id
        JOIN manifests m ON ml.manifest_id = m.id
        JOIN images i ON m.image_id = i.id
        WHERE i.reference = ?
        ORDER BY l.id ASC
        "#,
    )
    .bind(reference)
    .fetch_all(pool)
    .await?;

    Ok(records
        .into_iter()
        .map(|row| Layer {
            id: row.get("id"),
            media_type: row.get("media_type"),
            digest: row.get("digest"),
            diff_id: row.get("diff_id"),
            size_bytes: row.get("size_bytes"),
            created_at: parse_sqlite_datetime(&row.get::<String, _>("created_at")),
            modified_at: parse_sqlite_datetime(&row.get::<String, _>("modified_at")),
        })
        .collect())
}

/// Checks if an image exists in the database.
pub(crate) async fn image_exists(pool: &Pool<Sqlite>, reference: &str) -> MicrosandboxResult<bool> {
    let record = sqlx::query(
        r#"
        SELECT COUNT(*) as count
        FROM images
        WHERE reference = ?
        "#,
    )
    .bind(reference)
    .fetch_one(pool)
    .await?;

    Ok(record.get::<i64, _>("count") > 0)
}

/// Gets the configuration for an image from the database.
///
/// This function retrieves the configuration details for a specified image reference.
/// It includes information like architecture, OS, environment variables, command,
/// working directory, and other container configuration metadata.
///
/// ## Arguments
///
/// * `pool` - SQLite connection pool
/// * `reference` - OCI image reference string (e.g., "ubuntu:latest")
///
/// ## Returns
///
/// Returns a `MicrosandboxResult` containing either the image `Config` or an error
pub(crate) async fn get_image_config(
    pool: &Pool<Sqlite>,
    reference: &str,
) -> MicrosandboxResult<Option<Config>> {
    let record = sqlx::query(
        r#"
        SELECT c.id, c.manifest_id, c.media_type, c.created, c.architecture,
               c.os, c.os_variant, c.config_env_json, c.config_cmd_json,
               c.config_working_dir, c.config_entrypoint_json,
               c.config_volumes_json, c.config_exposed_ports_json,
               c.config_user, c.rootfs_type, c.rootfs_diff_ids_json,
               c.history_json, c.created_at, c.modified_at
        FROM configs c
        JOIN manifests m ON c.manifest_id = m.id
        JOIN images i ON m.image_id = i.id
        WHERE i.reference = ?
        LIMIT 1
        "#,
    )
    .bind(reference)
    .fetch_optional(pool)
    .await?;

    Ok(record.map(|row| Config {
        id: row.get("id"),
        manifest_id: row.get("manifest_id"),
        media_type: row.get("media_type"),
        created: row
            .get::<Option<String>, _>("created")
            .map(|dt| dt.parse::<DateTime<Utc>>().unwrap()),
        architecture: row.get("architecture"),
        os: row.get("os"),
        os_variant: row.get("os_variant"),
        config_env_json: null_to_none(row.get("config_env_json")),
        config_cmd_json: null_to_none(row.get("config_cmd_json")),
        config_working_dir: row.get("config_working_dir"),
        config_entrypoint_json: null_to_none(row.get("config_entrypoint_json")),
        config_volumes_json: null_to_none(row.get("config_volumes_json")),
        config_exposed_ports_json: null_to_none(row.get("config_exposed_ports_json")),
        config_user: row.get("config_user"),
        rootfs_type: row.get("rootfs_type"),
        rootfs_diff_ids_json: row.get("rootfs_diff_ids_json"),
        history_json: null_to_none(row.get("history_json")),
        created_at: parse_sqlite_datetime(&row.get::<String, _>("created_at")),
        modified_at: parse_sqlite_datetime(&row.get::<String, _>("modified_at")),
    }))
}

/// Saves or updates an image in the database.
/// If the image exists, it updates the size_bytes and last_used_at.
/// If it doesn't exist, creates a new record.
pub(crate) async fn save_or_update_image(
    pool: &Pool<Sqlite>,
    reference: &str,
    size_bytes: i64,
) -> MicrosandboxResult<i64> {
    // Try to update first
    let update_result = sqlx::query(
        r#"
        UPDATE images
        SET size_bytes = ?, last_used_at = CURRENT_TIMESTAMP, modified_at = CURRENT_TIMESTAMP
        WHERE reference = ?
        RETURNING id, reference, size_bytes, last_used_at, created_at, modified_at
        "#,
    )
    .bind(size_bytes)
    .bind(reference)
    .fetch_optional(pool)
    .await?;

    if let Some(record) = update_result {
        Ok(record.get::<i64, _>("id"))
    } else {
        // If no record was updated, insert a new one
        save_image(pool, reference, size_bytes).await
    }
}

/// Gets a layer from the database by its digest value.
///
/// ## Arguments
///
/// * `pool` - SQLite connection pool
/// * `digest` - Layer digest string to search for
pub(crate) async fn get_layer_by_digest(
    pool: &Pool<Sqlite>,
    digest: &str,
) -> MicrosandboxResult<Option<Layer>> {
    let mut layers = get_layers_by_digest(pool, &[digest.to_string()]).await?;
    Ok(layers.pop())
}

/// Gets layers from the database by their digest values.
///
/// This function retrieves layer information for a list of digest values without
/// requiring a manifest relationship. This is useful for checking if specific layers
/// exist in the database before trying to download them.
///
/// ## Arguments
///
/// * `pool` - SQLite connection pool
/// * `digests` - List of layer digest strings to search for
///
/// ## Returns
///
/// Returns a `MicrosandboxResult` containing a vector of `Layer` objects that match the provided digests
pub(crate) async fn get_layers_by_digest(
    pool: &Pool<Sqlite>,
    digests: &[String],
) -> MicrosandboxResult<Vec<Layer>> {
    if digests.is_empty() {
        return Ok(Vec::new());
    }

    // Create placeholders for the IN clause (?,?,?)
    let placeholders = (0..digests.len())
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(",");

    let query = format!(
        r#"
        SELECT id, media_type, digest, diff_id, size_bytes, created_at, modified_at
        FROM layers
        WHERE digest IN ({})
        "#,
        placeholders
    );

    // Build the query with the dynamic number of parameters
    let mut query_builder = sqlx::query(&query);
    for digest in digests {
        query_builder = query_builder.bind(digest);
    }

    let records = query_builder.fetch_all(pool).await?;

    Ok(records
        .into_iter()
        .map(|row| Layer {
            id: row.get("id"),
            media_type: row.get("media_type"),
            digest: row.get("digest"),
            diff_id: row.get("diff_id"),
            size_bytes: row.get("size_bytes"),
            created_at: parse_sqlite_datetime(&row.get::<String, _>("created_at")),
            modified_at: parse_sqlite_datetime(&row.get::<String, _>("modified_at")),
        })
        .collect())
}

/// Gets all layer digests for an image manifest from the database.
///
/// This function retrieves just the digest strings for all layers associated with a specific
/// image reference. This is useful for checking if layers exist without needing the full layer details.
///
/// ## Arguments
///
/// * `pool` - SQLite connection pool
/// * `reference` - OCI image reference string (e.g., "ubuntu:latest")
///
/// ## Returns
///
/// Returns a `MicrosandboxResult` containing a vector of layer digest strings
pub(crate) async fn get_image_layer_digests(
    pool: &Pool<Sqlite>,
    reference: &str,
) -> MicrosandboxResult<Vec<String>> {
    let records = sqlx::query(
        r#"
        SELECT l.digest
        FROM layers l
        JOIN manifest_layers ml ON l.id = ml.layer_id
        JOIN manifests m ON ml.manifest_id = m.id
        JOIN images i ON m.image_id = i.id
        WHERE i.reference = ?
        ORDER BY l.id ASC
        "#,
    )
    .bind(reference)
    .fetch_all(pool)
    .await?;

    Ok(records
        .into_iter()
        .map(|row| row.get::<String, _>("digest"))
        .collect())
}

/// Associates a layer with a manifest in the database.
///
/// If the layer doesn't exist, it will be created first, before being
/// linked to the manifest.
///
/// ## Arguments
///
/// * `pool` - SQLite connection pool
/// * `layer` - OCI layer descriptor
/// * `diff_id` - Diff ID of the layer
/// * `manifest_id` - ID of the manifest to link the layer to
///
/// ## Returns
///
/// Returns the ID of the manifest layer if successful.
pub(crate) async fn create_or_update_manifest_layer(
    pool: &Pool<Sqlite>,
    layer: &OciDescriptor,
    diff_id: &str,
    manifest_id: i64,
) -> MicrosandboxResult<i64> {
    // if None, it means the layer doesn't exist in database yet
    let db_layer_id = get_layer_by_digest(pool, &layer.digest.to_string())
        .await?
        .map(|l| l.id);

    let db_layer_id = match db_layer_id {
        Some(layer_id) => layer_id,
        None => {
            save_or_update_layer(pool, &layer.media_type, &layer.digest, layer.size, &diff_id)
                .await?
        }
    };

    // finally, link the layer to the manifest
    save_manifest_layer(pool, manifest_id, db_layer_id).await
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_init_sandbox_db() -> MicrosandboxResult<()> {
        // Create temporary directory
        let temp_dir = tempdir()?;
        let db_path = temp_dir.path().join("test_sandbox.db");

        // Initialize database
        initialize(&db_path, &SANDBOX_DB_MIGRATOR).await?;

        // Test database connection
        let pool = get_pool(&db_path).await?;

        // Verify tables exist by querying them
        let tables = sqlx::query("SELECT name FROM sqlite_master WHERE type='table'")
            .fetch_all(&pool)
            .await?;

        let table_names: Vec<String> = tables
            .iter()
            .map(|row| row.get::<String, _>("name"))
            .collect();

        assert!(
            table_names.contains(&"sandboxes".to_string()),
            "sandboxes table not found"
        );
        assert!(
            table_names.contains(&"sandbox_metrics".to_string()),
            "sandbox_metrics table not found"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_init_oci_db() -> MicrosandboxResult<()> {
        // Create temporary directory
        let temp_dir = tempdir()?;
        let db_path = temp_dir.path().join("test_oci.db");

        // Initialize database
        initialize(&db_path, &OCI_DB_MIGRATOR).await?;

        // Test database connection
        let pool = get_pool(&db_path).await?;

        // Verify tables exist by querying them
        let tables = sqlx::query("SELECT name FROM sqlite_master WHERE type='table'")
            .fetch_all(&pool)
            .await?;

        let table_names: Vec<String> = tables
            .iter()
            .map(|row| row.get::<String, _>("name"))
            .collect();

        assert!(
            table_names.contains(&"images".to_string()),
            "images table not found"
        );
        assert!(
            table_names.contains(&"manifests".to_string()),
            "manifests table not found"
        );
        assert!(
            table_names.contains(&"configs".to_string()),
            "configs table not found"
        );
        assert!(
            table_names.contains(&"layers".to_string()),
            "layers table not found"
        );

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Parses a SQLite datetime string (in "YYYY-MM-DD HH:MM:SS" format) to a DateTime<Utc>.
fn parse_sqlite_datetime(s: &str) -> DateTime<Utc> {
    let naive_dt = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .unwrap_or_else(|e| panic!("Failed to parse datetime string '{}': {:?}", s, e));
    DateTime::from_naive_utc_and_offset(naive_dt, Utc)
}

/// Sometimes the json columns in the database can have literal "null" values.
/// This function converts those to None.
fn null_to_none(value: Option<String>) -> Option<String> {
    value.filter(|v| v != "null")
}
