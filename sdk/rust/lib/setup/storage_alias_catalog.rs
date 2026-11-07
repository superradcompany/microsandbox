//! Bounded read-only host bindings used only when inspecting a legacy disk transition.

use std::path::PathBuf;

use sea_orm::sqlx::{self, Connection, Row, SqliteConnection};

use crate::MicrosandboxResult;
use crate::runtime::storage_aliases::{CatalogSandbox, CatalogSnapshot};

use super::{MAX_SANDBOXES, decode_config, decode_stored_config, diagnostic_error, read_catalog};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(super) struct AliasCatalog {
    pub sandboxes: Vec<CatalogSandbox>,
    pub snapshots: Vec<CatalogSnapshot>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn read(connection: &mut SqliteConnection) -> MicrosandboxResult<AliasCatalog> {
    let rows = read_catalog(connection, None).await?;
    let sandboxes = rows
        .iter()
        .map(|row| {
            // An interrupted create still has host-saved bindings and can be a writer.
            // Keep it in discovery, matching recovery; only its own diagnostic is incomplete.
            let mut config = decode_config(row)?;
            if let Some(active) = &row.active_config {
                crate::runtime::storage_aliases::merge_active_bindings(
                    &mut config,
                    decode_stored_config(active, None)?,
                );
            }
            if config.spec.name != row.name
                || crate::sandbox::validate_sandbox_name(&row.name).is_err()
            {
                return Err(diagnostic_error("legacy writer identity is unavailable"));
            }
            let status = match row.status.as_str() {
                "Created" => crate::sandbox::SandboxStatus::Created,
                "Starting" => crate::sandbox::SandboxStatus::Starting,
                "Running" => crate::sandbox::SandboxStatus::Running,
                "Draining" => crate::sandbox::SandboxStatus::Draining,
                "Paused" => crate::sandbox::SandboxStatus::Paused,
                "Stopped" => crate::sandbox::SandboxStatus::Stopped,
                "Crashed" => crate::sandbox::SandboxStatus::Crashed,
                _ => return Err(diagnostic_error("legacy writer status is unavailable")),
            };
            Ok(CatalogSandbox {
                id: row.id,
                name: row.name.clone(),
                config,
                stored_config: row.config.clone().unwrap_or_default(),
                status,
            })
        })
        .collect::<MicrosandboxResult<Vec<_>>>()?;
    let mut transaction = connection
        .begin()
        .await
        .map_err(|_| diagnostic_error("snapshot inventory unavailable"))?;
    let columns = sqlx::query("PRAGMA table_info(snapshot_index)")
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| diagnostic_error("snapshot inventory schema unavailable"))?;
    let columns = columns
        .iter()
        .filter_map(|row| row.try_get::<String, _>("name").ok())
        .collect::<std::collections::BTreeSet<_>>();
    let mut snapshots = Vec::new();
    if !columns.is_empty() {
        if !columns.contains("artifact_path") || !columns.contains("digest") {
            return Err(diagnostic_error(
                "snapshot inventory has an unsupported schema",
            ));
        }
        let id = if columns.contains("snapshot_id") {
            "COALESCE(snapshot_id,digest)"
        } else {
            "digest"
        };
        let digest = if columns.contains("descriptor_digest") {
            "COALESCE(descriptor_digest,digest)"
        } else {
            "digest"
        };
        // Only fixed, audited schema expressions are interpolated. Payloads remain bounded.
        let query = format!(
            "SELECT CASE WHEN length({id})<=512 THEN {id} END AS id, CASE WHEN length(artifact_path)<=4096 THEN artifact_path END AS path, CASE WHEN length({digest})<=256 THEN {digest} END AS digest FROM snapshot_index LIMIT {}",
            MAX_SANDBOXES + 1
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(query.as_str()))
            .fetch_all(&mut *transaction)
            .await
            .map_err(|_| diagnostic_error("snapshot inventory could not be read"))?;
        if rows.len() > MAX_SANDBOXES {
            return Err(diagnostic_error(
                "snapshot inventory exceeds inspection bound",
            ));
        }
        for row in rows {
            let id: String = row
                .try_get("id")
                .map_err(|_| diagnostic_error("snapshot identity is unavailable"))?;
            let path: String = row
                .try_get("path")
                .map_err(|_| diagnostic_error("snapshot path is unavailable"))?;
            let descriptor_digest: Option<String> = row
                .try_get("digest")
                .map_err(|_| diagnostic_error("snapshot digest is unavailable"))?;
            snapshots.push(CatalogSnapshot {
                id,
                path: PathBuf::from(path),
                descriptor_digest,
            });
        }
    }
    transaction
        .rollback()
        .await
        .map_err(|_| diagnostic_error("snapshot inventory read could not finish"))?;
    Ok(AliasCatalog {
        sandboxes,
        snapshots,
    })
}
