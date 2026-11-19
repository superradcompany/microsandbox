//! SDK-only identity persistence. The shared runtime ORM intentionally omits this column.

use microsandbox_db::{DbReadConnection, DbWriteConnection};
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde::{Deserialize, Serialize};

use super::super::control::identity::ProcessIdentity;
use super::run_entity;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProcessRecord {
    version: u32,
    pub(super) platform: String,
    pub(super) boot: String,
    pub(super) birth: [u64; 2],
    sandbox_id: i32,
    run_id: i32,
    pid: i32,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ProcessRecord {
    /// Called only for the still-owned launch, never to backfill a PID from the catalog.
    pub(super) async fn publish(
        db: &DbWriteConnection,
        run: &run_entity::Model,
        identity: &ProcessIdentity,
    ) -> MicrosandboxResult<()> {
        if run.pid != Some(identity.pid) {
            return Err(invalid("launch PID differs from the ready run"));
        }
        identity
            .verify()
            .map_err(|error| invalid(&error.to_string()))?;
        let record = Self {
            version: 1,
            platform: std::env::consts::OS.into(),
            boot: boot_identity()?,
            birth: [identity.start.0, identity.start.1],
            sandbox_id: run.sandbox_id,
            run_id: run.id,
            pid: identity.pid,
        };
        let updated = db.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,
            "UPDATE run SET process_identity = ? WHERE id = ? AND sandbox_id = ? AND pid = ? AND process_identity IS NULL",
            [serde_json::to_string(&record)?.into(), run.id.into(), run.sandbox_id.into(), identity.pid.into()],
        )).await?;
        if updated.rows_affected() != 1 {
            return Err(invalid("run changed before identity publication"));
        }
        Ok(())
    }

    pub(super) async fn load(
        db: &DbReadConnection,
        run: &run_entity::Model,
    ) -> MicrosandboxResult<Option<Self>> {
        let row = db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT process_identity FROM run WHERE id = ? AND sandbox_id = ? AND pid IS ?",
                [run.id.into(), run.sandbox_id.into(), run.pid.into()],
            ))
            .await?
            .ok_or_else(|| invalid("run changed during identity lookup"))?;
        let Some(json) = row.try_get_by_index::<Option<String>>(0)? else {
            return Ok(None);
        };
        let record: Self =
            serde_json::from_str(&json).map_err(|_| invalid("malformed recorded identity"))?;
        if record.pid <= 0
            || record.version != 1
            || record.sandbox_id != run.sandbox_id
            || record.run_id != run.id
            || Some(record.pid) != run.pid
            || record.boot.is_empty()
            || record.platform != std::env::consts::OS
        {
            return Err(invalid(
                "recorded identity does not match this run and host platform",
            ));
        }
        Ok(Some(record))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn invalid(reason: &str) -> MicrosandboxError {
    MicrosandboxError::Runtime(format!("cannot prove recorded process identity: {reason}"))
}

pub(super) fn boot_identity() -> MicrosandboxResult<String> {
    #[cfg(target_os = "linux")]
    let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    #[cfg(target_os = "macos")]
    let value = {
        let mut bytes = [0u8; 128];
        let mut size = bytes.len();
        if unsafe {
            libc::sysctlbyname(
                c"kern.bootsessionuuid".as_ptr(),
                bytes.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        String::from_utf8(bytes[..size].to_vec())
            .map_err(|_| invalid("invalid kernel boot identity"))?
    };
    let value = value.trim_end_matches('\0').trim().to_owned();
    if value.is_empty() {
        return Err(invalid("empty kernel boot identity"));
    }
    Ok(value)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
#[path = "process_record_tests.rs"]
pub(super) mod tests;
