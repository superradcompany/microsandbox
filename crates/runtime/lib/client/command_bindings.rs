//! Host-private command requirements for restored sandboxes.

use microsandbox_protocol::exec_bindings::DeferredCommandBindings;
use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_ENTRIES, valid_binding_id, valid_saved_env_key,
};
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseTransaction, DbErr, Statement};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Install the guard in the same transaction that reserves the destination sandbox.
/// Store only logical identifiers and their consumers. Command values never enter this row.
pub async fn install(
    txn: &DatabaseTransaction,
    sandbox_id: i32,
    policy: &DeferredCommandBindings,
) -> Result<(), DbErr> {
    if policy.is_empty() {
        return Ok(());
    }
    validate(policy)?;
    let json = serde_json::to_string(policy).map_err(|_| invalid())?;
    txn.execute_unprepared(include_str!("command_bindings.sql"))
        .await?;
    txn.execute_raw(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "INSERT INTO sandbox_command_bindings(sandbox_id, requirements) VALUES (?, ?)",
        [sandbox_id.into(), json.into()],
    ))
    .await?;
    Ok(())
}

#[cfg(feature = "runner")]
pub(crate) async fn admit(
    txn: &DatabaseTransaction,
    sandbox_id: i32,
) -> Result<Option<DeferredCommandBindings>, DbErr> {
    if txn
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sandbox_command_bindings'",
        ))
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT requirements, admitting FROM sandbox_command_bindings WHERE sandbox_id = ?",
            [sandbox_id.into()],
        ))
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let encoded: String = row.try_get("", "requirements")?;
    if encoded.len() > microsandbox_types::snapshot::saved_config::MAX_SAVED_CONFIG_BYTES
        || row.try_get::<i64>("", "admitting")? != 0
    {
        return Err(invalid());
    }
    let policy = serde_json::from_str(&encoded).map_err(|_| invalid())?;
    validate(&policy)?;
    // Only this write transaction can see the permit. Its caller inserts the run and
    // closes the permit before commit. A crash rolls back the permit and run together.
    set_admitting(txn, sandbox_id, true).await?;
    Ok(Some(policy))
}

#[cfg(feature = "runner")]
pub(crate) async fn set_admitting(
    txn: &DatabaseTransaction,
    sandbox_id: i32,
    open: bool,
) -> Result<(), DbErr> {
    let updated = txn.execute_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
        "UPDATE sandbox_command_bindings SET admitting = ? WHERE sandbox_id = ? AND admitting = ?",
        [open.into(), sandbox_id.into(), (!open).into()])).await?;
    if updated.rows_affected() != 1 {
        return Err(invalid());
    }
    Ok(())
}

fn invalid() -> DbErr {
    DbErr::Custom("invalid saved command binding requirements".into())
}

fn validate(policy: &DeferredCommandBindings) -> Result<(), DbErr> {
    if policy.is_empty()
        || [policy.env.len(), policy.entrypoint.len(), policy.cmd.len()]
            .into_iter()
            .any(|n| n > MAX_SAVED_CONFIG_ENTRIES)
        || !policy.env.keys().all(|key| valid_saved_env_key(key))
        || !policy
            .env
            .values()
            .chain(&policy.entrypoint)
            .chain(&policy.cmd)
            .all(|id| valid_binding_id(id))
    {
        return Err(invalid());
    }
    Ok(())
}
