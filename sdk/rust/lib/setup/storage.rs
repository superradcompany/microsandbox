//! Explicitly scoped storage inspection without backend initialization or catalog migration.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use futures::TryStreamExt;
use microsandbox_runtime::checkpoint::migration::{self, Inspection, MigrationStatus};
use sea_orm::sqlx::{self, Connection, Row, SqliteConnection, sqlite::SqliteConnectOptions};
use serde::{Deserialize, Serialize};

use crate::backend::BackendKind;
use crate::config::backend::BackendSelection;
use crate::config::{GlobalConfig, GlobalConfigPatch, layers::BackendConfig};
use crate::{MicrosandboxError, MicrosandboxResult, SandboxConfig};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_SANDBOXES: usize = 4096;
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_REPORT_CONFIG_BYTES: usize = 16 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Explicit scope of a storage check. There is deliberately no implicit all-sandboxes default.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageSelection {
    /// Check only these names; duplicates are checked once, in sorted order.
    Named(Vec<String>),
    /// Check every catalog sandbox in the configured local home, within the diagnostic bound.
    All,
}

/// A storage-readiness report. Inspection is provisional and never authorizes migration itself.
#[derive(Debug, Serialize)]
pub struct StorageDiagnosis {
    /// Configured local home that was inspected.
    pub home: PathBuf,
    /// Individually reported results, including inaccessible requested sandboxes.
    pub sandboxes: Vec<StorageSandboxDiagnosis>,
    /// Runtime capability required before any protected start.
    pub required_runtime_capability: String,
}

/// Storage status independent of the operation that triggered the check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageDiagnosticStatus {
    /// Protected layout is complete.
    Ready,
    /// The inspected legacy view is eligible for migration after revalidation.
    Eligible,
    /// The legacy view is eligible, but macOS requires explicit maintenance recovery.
    MaintenanceRequired,
    /// The layout requires an explicit supported recovery decision.
    RecoveryRequired,
    /// A durable transition must finish before ordinary storage use.
    InProgress,
    /// Inspection could not establish this sandbox's state.
    Unavailable,
}

/// Stable classification for a failed per-sandbox inspection; excludes saved configuration values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageDiagnosticReason {
    /// No sandbox with the requested name exists in this catalog snapshot.
    NotFound,
    /// The saved configuration is malformed, unsupported, inconsistent, or exceeds its bound.
    InvalidConfiguration,
    /// The sandbox is an unfinished create or restore operation.
    IncompleteCreation,
    /// The storage engine could not safely inspect its files.
    StorageUnavailable,
}

/// One requested sandbox's diagnostic result.
#[derive(Debug, Serialize)]
pub struct StorageSandboxDiagnosis {
    /// Host-saved guest mount paths, keyed by the disk roles used in candidate summaries.
    pub guest_mounts: std::collections::BTreeMap<String, String>,
    /// Catalog sandbox name, never a guest-provided path.
    pub name: String,
    /// Result of the bounded storage inspection.
    pub status: StorageDiagnosticStatus,
    /// A recorded running/transitioning VM makes the report provisional; no VM is stopped.
    pub running: bool,
    /// Protection registration does not imply filesystem migration completed.
    pub protection_registered: bool,
    /// Safe reason code for a check that could not finish.
    pub reason: Option<StorageDiagnosticReason>,
    /// Shared storage engine's report, with candidate summaries and resource estimates.
    pub inspection: Option<Inspection>,
}

#[derive(Clone)]
struct CatalogSandbox {
    id: i32,
    name: String,
    status: String,
    config: Option<String>,
    overrides: Option<String>,
    active_config: Option<String>,
    incomplete: bool,
    protection_registered: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl StorageDiagnosis {
    /// CLI status: 0 means no blockers, 2 means a complete report with blockers, and 3 means
    /// at least one requested sandbox could not be inspected. Top-level errors remain errors.
    pub fn exit_code(&self) -> i32 {
        if self
            .sandboxes
            .iter()
            .any(|item| item.status == StorageDiagnosticStatus::Unavailable)
        {
            3
        } else if self.sandboxes.iter().any(|item| {
            (item.running && item.status != StorageDiagnosticStatus::Ready)
                || matches!(
                    item.status,
                    StorageDiagnosticStatus::RecoveryRequired
                        | StorageDiagnosticStatus::MaintenanceRequired
                        | StorageDiagnosticStatus::InProgress
                )
        }) {
            2
        } else {
            0
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Inspect explicitly selected local sandbox storage without opening a `LocalBackend`.
///
/// Resolves ordinary settings and managed policy without downloading or launching a runtime.
/// No catalog records, migration history, permissions, guards, configuration or disk contents
/// are changed. SQLite may create/update WAL shared-memory sidecars for normal read-lock
/// coordination; this is not an immutable-file read and includes committed live WAL contents.
/// Running sandboxes remain running and all results require locked revalidation before use.
pub async fn diagnose_storage(
    options: GlobalConfigPatch,
    selection: StorageSelection,
) -> MicrosandboxResult<StorageDiagnosis> {
    let sources = inspection_config(options)?;
    diagnose_resolved(sources.resolved_config(), selection).await
}

fn inspection_config(options: GlobalConfigPatch) -> MicrosandboxResult<BackendConfig> {
    let (source, sources) = if let Some(captured) = crate::backend::initialized_backend_config()? {
        if captured.info.kind != BackendKind::Local {
            return Err(diagnostic_error(
                "storage diagnostics are local-only; select the intended local backend",
            ));
        }
        let sources = captured.config.ok_or_else(|| {
            diagnostic_error("storage diagnostics require a local backend with captured settings")
        })?;
        (
            captured.info.source,
            sources.apply_operation_patch(options)?,
        )
    } else {
        let (selection, source, sources) =
            BackendSelection::inspect(&crate::config::config_path())?;
        if !matches!(selection, BackendSelection::Local { .. }) {
            return Err(diagnostic_error(
                "storage diagnostics are local-only; select the intended local backend",
            ));
        }
        (source, sources.prepare_for_local_backend(options)?)
    };
    sources.require_backend(BackendKind::Local, Some(source))?;
    Ok(sources)
}

async fn diagnose_resolved(
    config: &GlobalConfig,
    selection: StorageSelection,
) -> MicrosandboxResult<StorageDiagnosis> {
    let names = selected_names(selection)?;
    let home = std::path::absolute(config.home())?;
    let mut connection = open_catalog(config).await?;
    let rows = read_catalog(&mut connection, names.as_ref()).await?;
    let preview_config = config.clone();
    let (rows, needs_aliases) = tokio::task::spawn_blocking(move || {
        let needed = needs_alias_inventory(&preview_config, &rows);
        (rows, needed)
    })
    .await
    .map_err(|_| diagnostic_error("storage readiness worker failed"))?;
    let aliases = if needs_aliases {
        storage_alias_catalog::read(&mut connection).await.ok()
    } else {
        None
    };
    let closed = connection.close().await;
    closed.map_err(|_| diagnostic_error("storage inspection could not close its catalog read"))?;
    let config = config.clone();
    // Source inventory can block on disk I/O. It is read-only, so a cancelled caller may
    // safely leave this bounded inspection finishing without holding lifecycle ownership.
    tokio::task::spawn_blocking(move || {
        let mut sandboxes = Vec::new();
        let mut pending_names = names.unwrap_or_default();
        for row in rows {
            pending_names.remove(&row.name);
            sandboxes.push(inspect_sandbox(&config, row, aliases.as_ref()));
        }
        for name in pending_names {
            sandboxes.push(StorageSandboxDiagnosis {
                guest_mounts: Default::default(),
                name,
                status: StorageDiagnosticStatus::Unavailable,
                running: false,
                protection_registered: false,
                reason: Some(StorageDiagnosticReason::NotFound),
                inspection: None,
            });
        }
        sandboxes.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(StorageDiagnosis {
            home,
            sandboxes,
            required_runtime_capability: "protected_guest_state".into(),
        })
    })
    .await
    .map_err(|_| diagnostic_error("storage inspection worker failed"))?
}

pub(crate) async fn open_catalog(config: &GlobalConfig) -> MicrosandboxResult<SqliteConnection> {
    let path = config
        .home()
        .join(microsandbox_utils::DB_SUBDIR)
        .join(microsandbox_utils::DB_FILENAME);
    let path = microsandbox_db::private_storage::validate_database_inspection(&path)?;
    // Normal backend reads may repair permissions. This path opens only the existing catalog
    // and observes committed WAL data, including for the names-only interactive picker.
    let options = SqliteConnectOptions::new()
        .filename(path)
        .read_only(true)
        .create_if_missing(false)
        .busy_timeout(Duration::from_secs(5));
    SqliteConnection::connect_with(&options)
        .await
        .map_err(|_| diagnostic_error("storage inspection could not open the existing catalog"))
}

fn selected_names(selection: StorageSelection) -> MicrosandboxResult<Option<BTreeSet<String>>> {
    match selection {
        StorageSelection::All => Ok(None),
        StorageSelection::Named(names) => {
            if names.is_empty() || names.len() > MAX_SANDBOXES {
                return Err(diagnostic_error(
                    "select between one and 4096 sandbox names, or explicitly select all sandboxes",
                ));
            }
            for name in &names {
                crate::sandbox::validate_sandbox_name(name)?;
            }
            Ok(Some(names.into_iter().collect()))
        }
    }
}

fn needs_alias_inventory(config: &GlobalConfig, rows: &[CatalogSandbox]) -> bool {
    // Completed layouts need neither unrelated catalog inventory nor legacy disk reads.
    // Validate every catalog name before joining a path, including whole-home results.
    rows.iter().any(|row| {
        if crate::sandbox::validate_sandbox_name(&row.name).is_err() || row.incomplete {
            return false;
        }
        decode_config(row).is_ok_and(|saved| {
            if saved.spec.name != row.name {
                return false;
            }
            let sandbox = config.sandboxes_dir().join(&row.name);
            microsandbox_runtime::checkpoint::layout::require_ready(&sandbox.join("runtime"))
                .is_err()
                && crate::runtime::protected_state::bindings(
                    &saved,
                    &sandbox,
                    row.id,
                    row.config.as_deref().unwrap_or_default(),
                )
                .is_ok_and(|binding| binding.root.is_some() || !binding.owned_disks.is_empty())
        })
    })
}

async fn read_catalog(
    connection: &mut SqliteConnection,
    names: Option<&BTreeSet<String>>,
) -> MicrosandboxResult<Vec<CatalogSandbox>> {
    let mut transaction = connection
        .begin()
        .await
        .map_err(|_| diagnostic_error("catalog read transaction unavailable"))?;
    let columns = sqlx::query("PRAGMA table_info(sandbox)")
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| diagnostic_error("catalog schema is unavailable"))?;
    let columns = columns
        .iter()
        .filter_map(|row| row.try_get::<String, _>("name").ok())
        .collect::<BTreeSet<_>>();
    if !["id", "name", "status", "config"]
        .iter()
        .all(|name| columns.contains(*name))
    {
        return Err(diagnostic_error(
            "catalog has no supported sandbox table; no changes were made",
        ));
    }
    let protection: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='protected_sandbox_state'",
    )
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| diagnostic_error("catalog protection metadata is unavailable"))?;
    // All interpolated SQL is selected from fixed schema identifiers, never names or config data.
    let overrides = if columns.contains("caller_config_overrides") {
        "CASE WHEN length(CAST(caller_config_overrides AS BLOB)) <= 1048576 THEN caller_config_overrides ELSE NULL END"
    } else {
        "NULL"
    };
    let active_config = if columns.contains("active_config") {
        "CASE WHEN length(CAST(active_config AS BLOB)) <= 1048576 THEN active_config ELSE NULL END"
    } else {
        "NULL"
    };
    let active_valid = if columns.contains("active_config") {
        " AND (active_config IS NULL OR length(CAST(active_config AS BLOB)) <= 1048576)"
    } else {
        ""
    };
    let incomplete = if columns.contains("creation_state") {
        "creation_state IS NOT NULL"
    } else {
        "0"
    };
    let protected = if protection != 0 {
        "EXISTS(SELECT 1 FROM protected_sandbox_state p WHERE p.sandbox_id=sandbox.id)"
    } else {
        "0"
    };
    let valid_overrides = if columns.contains("caller_config_overrides") {
        " AND (caller_config_overrides IS NULL OR length(CAST(caller_config_overrides AS BLOB)) <= 1048576)"
    } else {
        ""
    };
    let base = format!(
        "SELECT id, CASE WHEN length(name)<=256 THEN name ELSE printf('<invalid-name:%d>',id) END AS name, CASE WHEN length(status)<=32 THEN status ELSE '' END AS status, CASE WHEN length(CAST(config AS BLOB)) <= {MAX_CONFIG_BYTES}{valid_overrides}{active_valid} THEN config ELSE NULL END AS config, {overrides} AS overrides, {active_config} AS active_config, {incomplete} AS incomplete, {protected} AS protected FROM sandbox"
    );
    let mut rows = Vec::new();
    let mut config_bytes = 0usize;
    if let Some(names) = names {
        for name in names {
            let query = format!("{base} WHERE name = ?");
            if let Some(row) = sqlx::query(sqlx::AssertSqlSafe(query.as_str()))
                .bind(name)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| diagnostic_error("requested sandbox metadata could not be read"))?
            {
                check_config_budget(&row, &mut config_bytes)?;
                rows.push(row);
            }
        }
    } else {
        let query = format!("{base} ORDER BY name LIMIT {}", MAX_SANDBOXES + 1);
        let mut stream = sqlx::query(sqlx::AssertSqlSafe(query.as_str())).fetch(&mut *transaction);
        while let Some(row) = stream
            .try_next()
            .await
            .map_err(|_| diagnostic_error("sandbox catalog could not be inspected"))?
        {
            if rows.len() == MAX_SANDBOXES {
                return Err(diagnostic_error(
                    "catalog exceeds the diagnostic sandbox bound; inspect named subsets",
                ));
            }
            check_config_budget(&row, &mut config_bytes)?;
            rows.push(row);
        }
    }
    let rows = rows
        .into_iter()
        .map(|row| -> Result<CatalogSandbox, sqlx::Error> {
            Ok(CatalogSandbox {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                status: row.try_get("status")?,
                config: row.try_get("config")?,
                overrides: row.try_get("overrides")?,
                active_config: row.try_get("active_config")?,
                incomplete: row.try_get::<i64, _>("incomplete")? != 0,
                protection_registered: row.try_get::<i64, _>("protected")? != 0,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| diagnostic_error("catalog fields are not a supported representation"))?;
    transaction
        .rollback()
        .await
        .map_err(|_| diagnostic_error("catalog read transaction could not finish"))?;
    Ok(rows)
}

fn check_config_budget(row: &sqlx::sqlite::SqliteRow, total: &mut usize) -> MicrosandboxResult<()> {
    for column in ["config", "overrides", "active_config"] {
        let value: Option<&str> = row
            .try_get(column)
            .map_err(|_| diagnostic_error("catalog configuration is not text"))?;
        *total = total
            .checked_add(value.map_or(0, str::len))
            .ok_or_else(|| {
                diagnostic_error("catalog inspection exceeds its configuration bound")
            })?;
    }
    if *total > MAX_REPORT_CONFIG_BYTES {
        return Err(diagnostic_error(
            "selected configurations exceed the diagnostic bound; inspect smaller named subsets",
        ));
    }
    Ok(())
}

fn inspect_sandbox(
    global: &GlobalConfig,
    row: CatalogSandbox,
    aliases: Option<&storage_alias_catalog::AliasCatalog>,
) -> StorageSandboxDiagnosis {
    let mut result = StorageSandboxDiagnosis {
        guest_mounts: Default::default(),
        name: row.name.clone(),
        status: StorageDiagnosticStatus::Unavailable,
        running: !matches!(row.status.as_str(), "Created" | "Stopped" | "Crashed"),
        protection_registered: row.protection_registered,
        reason: None,
        inspection: None,
    };
    if crate::sandbox::validate_sandbox_name(&row.name).is_err() {
        result.reason = Some(StorageDiagnosticReason::InvalidConfiguration);
        return result;
    }
    if row.incomplete {
        result.status = StorageDiagnosticStatus::RecoveryRequired;
        result.reason = Some(StorageDiagnosticReason::IncompleteCreation);
        return result;
    }
    let config = decode_config(&row);
    let Ok(config) = config else {
        result.reason = Some(StorageDiagnosticReason::InvalidConfiguration);
        return result;
    };
    if config.spec.name != row.name {
        result.reason = Some(StorageDiagnosticReason::InvalidConfiguration);
        return result;
    }
    result.guest_mounts = crate::sandbox::storage_preview::guest_mounts(&config);
    let sandbox = global.sandboxes_dir().join(&row.name);
    let inspected = crate::runtime::protected_state::bindings(
        &config,
        &sandbox,
        row.id,
        row.config.as_deref().unwrap_or_default(),
    )
    .and_then(|mut bindings| {
        let runtime = sandbox.join("runtime");
        if microsandbox_runtime::checkpoint::layout::require_ready(&runtime).is_err()
            && (bindings.root.is_some() || !bindings.owned_disks.is_empty())
        {
            let aliases = aliases
                .ok_or_else(|| diagnostic_error("legacy writer inventory is unavailable"))?;
            let current = aliases
                .sandboxes
                .iter()
                .find(|item| item.id == row.id)
                .filter(|item| {
                    item.name == row.name
                        && Some(item.stored_config.as_str()) == row.config.as_deref()
                })
                .ok_or_else(|| {
                    diagnostic_error("selected catalog state changed during inspection")
                })?;
            result.running |= current.status.has_active_runtime_state();
            let discovery = crate::runtime::storage_aliases::discover(
                &global.sandboxes_dir(),
                &global.volumes_dir(),
                row.id,
                &bindings,
                &aliases.sandboxes,
                &aliases.snapshots,
            )?;
            if !discovery.reasons.is_empty() {
                return Ok(Inspection {
                    preview_available: false,
                    status: MigrationStatus::RecoveryRequired,
                    reasons: discovery.reasons,
                    candidates: Vec::new(),
                    estimated_bytes: 0,
                });
            }
            bindings.aliases = discovery.aliases;
        }
        migration::inspect(&runtime, &bindings).map_err(MicrosandboxError::Runtime)
    });
    match inspected {
        Ok(inspection) => {
            result.status = match inspection.status {
                MigrationStatus::Ready => StorageDiagnosticStatus::Ready,
                MigrationStatus::Eligible if cfg!(target_os = "macos") => {
                    StorageDiagnosticStatus::MaintenanceRequired
                }
                MigrationStatus::Eligible => StorageDiagnosticStatus::Eligible,
                MigrationStatus::RecoveryRequired => StorageDiagnosticStatus::RecoveryRequired,
                MigrationStatus::InProgress => StorageDiagnosticStatus::InProgress,
            };
            result.inspection = Some(inspection);
        }
        Err(_) => result.reason = Some(StorageDiagnosticReason::StorageUnavailable),
    }
    result
}

fn decode_config(row: &CatalogSandbox) -> MicrosandboxResult<SandboxConfig> {
    decode_stored_config(
        row.config
            .as_deref()
            .ok_or_else(|| diagnostic_error("configuration exceeds bound"))?,
        row.overrides.as_deref(),
    )
}

fn decode_stored_config(raw: &str, overrides: Option<&str>) -> MicrosandboxResult<SandboxConfig> {
    let mut value: serde_json::Value = serde_json::from_str(raw)?;
    let original = value.clone();
    microsandbox_db::compat::config::to_current(&mut value).map_err(diagnostic_error)?;
    let converted;
    let bytes = if value == original {
        raw
    } else {
        converted = serde_json::to_string(&value)?;
        &converted
    };
    SandboxConfig::from_stored(bytes, overrides)
}

fn diagnostic_error(message: impl Into<String>) -> MicrosandboxError {
    MicrosandboxError::Custom(message.into())
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;

#[path = "storage_alias_catalog.rs"]
mod storage_alias_catalog;

#[path = "storage_repair.rs"]
mod repair;
pub use repair::{StorageRepairBlocker, storage_repair_blockers, storage_repair_targets};
pub(crate) use repair::{preview_alias_catalog, preview_target};
