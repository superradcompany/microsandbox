//! Select a released format without copying another sandbox's values or list shapes.

use sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde_json::Value;

use super::{admission, config::decode, historical::HistoricalFormat};
use crate::{MicrosandboxError, MicrosandboxResult, SandboxConfig};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Validate historical runtime semantics before create can replace a sandbox.
/// The catalog can be current while the selected executable is still old;
/// checking its representation here does not store that representation.
pub(crate) async fn validate_runtime_config(
    config: &SandboxConfig,
    runtime: &crate::config::GlobalConfig,
) -> MicrosandboxResult<()> {
    if let Some(patch) = crate::runtime::launch_contract::catalog_patch(runtime).await? {
        HistoricalFormat::for_patch(patch).encode(&config.clone_for_persistence())?;
        // These transient fields are intentionally absent from persisted cold-start
        // configuration, but still require the newer process-launch contract.
        if config.checkpoint_restore.is_some()
            || config.branch_source.is_some()
            || !config.snapshot_upper_layers.is_empty()
            || !config.snapshot_root_layer_sources.is_empty()
        {
            return Err(MicrosandboxError::Runtime(
                "checkpoint restore, branch, or disk chains require a newer runtime launch contract"
                    .into(),
            ));
        }
    }
    Ok(())
}

pub(crate) async fn encode_new<C: ConnectionTrait>(
    db: &C,
    config: &SandboxConfig,
    runtime: Option<&crate::config::GlobalConfig>,
) -> MicrosandboxResult<String> {
    // Persistence is not launch admission. A current catalog can store desired
    // configuration even when no complete runtime is installed. Create/start
    // validate execution requirements separately, before launching a VM.
    if admission::is_current(db).await? {
        return Ok(serde_json::to_string(config)?);
    }
    let mut format = HistoricalFormat::for_patch(admission::historical_patch(db).await?);
    let selected = if let Some(runtime) = runtime {
        crate::runtime::launch_contract::catalog_patch(runtime).await?
    } else {
        None
    };
    let selected = selected.filter(|patch| admission::same_historical_schema(format.patch, *patch));
    if let Some(patch) = selected {
        format = HistoricalFormat::for_patch(patch);
    }
    // v0.6.4 and v0.6.5 share a SQL schema but differ in enum spelling. Observe
    // only that discriminator; names, mounts, policies and their lengths do not
    // define the storage contract of another sandbox.
    if format.patch == 4 && selected.is_none() {
        let rows = db
            .query_all_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT config FROM sandbox",
            ))
            .await?;
        let mut snake = None;
        for row in rows {
            let raw = row.try_get_by_index::<String>(0)?;
            decode(&raw)?;
            let raw: Value = serde_json::from_str(&raw)?;
            let candidate = raw["resources"].get("vcpus").is_some();
            if snake.is_some_and(|previous| previous != candidate) {
                return Err(ambiguous());
            }
            snake = Some(candidate);
        }
        format.snake = snake.ok_or_else(ambiguous)?;
    }
    format.encode(config)
}

pub(crate) async fn encode_existing<C: ConnectionTrait>(
    db: &C,
    config: &SandboxConfig,
    original: &str,
    runtime: Option<&crate::config::GlobalConfig>,
) -> MicrosandboxResult<String> {
    // Preserve exact bytes for a semantic no-op, including historical aliases.
    if serde_json::to_value(decode(original)?)? == serde_json::to_value(config)? {
        return Ok(original.to_owned());
    }
    encode_new(db, config, runtime).await
}

fn ambiguous() -> MicrosandboxError {
    MicrosandboxError::InvalidConfig("cannot identify the enum spelling of this historical catalog; initialize it with its owning CLI before writing with this SDK".into())
}
