//! Destination-owned execution limits retained across starts by old and new SDKs.

use microsandbox_types::{ExecLimits, snapshot::saved_config::SavedExecLimits};
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseTransaction, DbErr, Statement};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Install the restart guard in the same transaction that creates the destination.
pub async fn install(
    txn: &DatabaseTransaction,
    sandbox_id: i32,
    policy: Option<ExecLimits>,
) -> Result<(), DbErr> {
    let Some(policy) = policy.filter(|value| *value != ExecLimits::default()) else {
        return Ok(());
    };
    policy
        .validate()
        .map_err(|reason| DbErr::Custom(reason.into()))?;
    let encoded = serde_json::to_string(&SavedExecLimits(policy))
        .map_err(|e| DbErr::Custom(e.to_string()))?;
    txn.execute_unprepared(include_str!("restored_exec_limits.sql"))
        .await?;
    txn.execute_raw(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "INSERT INTO sandbox_restored_exec_limits(sandbox_id, policy) VALUES (?, ?)",
        [sandbox_id.into(), encoded.into()],
    ))
    .await?;
    Ok(())
}

#[cfg(feature = "runner")]
pub(crate) async fn admit(
    txn: &DatabaseTransaction,
    sandbox_id: i32,
) -> Result<Option<ExecLimits>, DbErr> {
    if txn.query_one_raw(Statement::from_string(DatabaseBackend::Sqlite,
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sandbox_restored_exec_limits'")).await?.is_none() {
        return Ok(None);
    }
    let Some(row) = txn
        .query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT policy FROM sandbox_restored_exec_limits WHERE sandbox_id = ?",
            [sandbox_id.into()],
        ))
        .await?
    else {
        return Ok(None);
    };
    // The strict saved representation requires all five fields. A damaged row must
    // never acquire serde defaults that increase the sandbox's admission limits.
    let encoded: String = row.try_get("", "policy")?;
    let SavedExecLimits(policy) = serde_json::from_str(&encoded)
        .map_err(|_| DbErr::Custom("invalid retained execution policy".into()))?;
    policy
        .validate()
        .map_err(|reason| DbErr::Custom(reason.into()))?;
    set_admitting(txn, sandbox_id, true).await?;
    Ok(Some(policy))
}

#[cfg(feature = "runner")]
pub(crate) async fn set_admitting(
    txn: &DatabaseTransaction,
    sandbox_id: i32,
    open: bool,
) -> Result<(), DbErr> {
    let changed = txn.execute_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
        "UPDATE sandbox_restored_exec_limits SET admitting = ? WHERE sandbox_id = ? AND admitting = ?",
        [open.into(), sandbox_id.into(), (!open).into()])).await?;
    if changed.rows_affected() != 1 {
        return Err(DbErr::Custom(
            "invalid retained execution policy admission".into(),
        ));
    }
    Ok(())
}
