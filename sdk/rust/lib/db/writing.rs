//! Select a persisted format without upgrading the shared catalog.

use microsandbox_db::catalog::{has_column, has_table};
use sea_orm::{ConnectionTrait, DbBackend, Statement};

use crate::{MicrosandboxError, MicrosandboxResult, SandboxConfig};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn encode_new<C: ConnectionTrait>(
    db: &C,
    config: &SandboxConfig,
) -> MicrosandboxResult<String> {
    let current_migrations =
        microsandbox_migration::schema_metadata::migration_ids().count() as i64;
    let count = db
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT COUNT(*) FROM seaql_migrations",
        ))
        .await?
        .expect("COUNT returns one row")
        .try_get_by_index::<i64>(0)?;
    if count == current_migrations {
        return Ok(serde_json::to_string(config)?);
    }
    // Pre-placement catalogs belong to several incompatible serializers. An
    // existing row supplies the owning representation; schema 14 by itself
    // cannot distinguish v0.6.4's format from v0.6.5's.
    let rows = db
        .query_all_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT config FROM sandbox ORDER BY id",
        ))
        .await?;
    let mut encoded = None;
    for row in rows {
        let original = row.try_get_by_index::<String>(0)?;
        let candidate = super::encoding::encode_like(config, &original)?;
        let value: serde_json::Value = serde_json::from_str(&candidate)?;
        if let Some((_, previous)) = &encoded {
            if previous != &value {
                return Err(ambiguous());
            }
        } else {
            encoded = Some((candidate, value));
        }
    }
    if let Some((encoded, _)) = encoded {
        return Ok(encoded);
    }
    if has_table(db, "cpu_allocation").await? {
        return super::encoding::encode_like(config, include_str!("fixtures/config-0.6.9.json"));
    }
    if !has_column(db, "sandbox", "active_config").await? {
        return super::encoding::encode_like(config, include_str!("fixtures/config-0.6.0.json"));
    }
    Err(ambiguous())
}

fn ambiguous() -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(
        "cannot identify one compatible configuration format for this historical catalog; create the initial sandbox with its owning older CLI before adding sandboxes with this SDK".into(),
    )
}
