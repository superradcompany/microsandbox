//! Local capture identity. This metadata is never part of a portable descriptor or archive.

use microsandbox_db::{DbWriteConnection, catalog::has_table};
use sea_orm::{ConnectionTrait, DbBackend, EntityTrait, Statement};
use serde::{Deserialize, Serialize};

use crate::backend::LocalBackend;
use crate::db::entity::sandbox;
use crate::{MicrosandboxError, MicrosandboxResult, SnapshotSourceBinding, SnapshotSourceStatus};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const IDENTITY_TABLE: &str = "microsandbox_catalog_identity";
pub(super) const SOURCE_FILENAME: &str = "group-source.json";
const SOURCE_SCHEMA: &str = "microsandbox.snapshot-group-source/1";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A source name is display information; only the catalog UUID and row ID identify it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Source {
    schema: String,
    database_uuid: String,
    sandbox_id: i32,
    name: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Source {
    /// Inspect the binding without manufacturing a catalog identity or resolving by name.
    pub(super) async fn inspect(
        &self,
        local: &LocalBackend,
    ) -> MicrosandboxResult<SnapshotSourceBinding> {
        self.validate()?;
        let pools = local.db().await?;
        let db = pools.read();
        let mut status = SnapshotSourceStatus::DifferentCatalog;
        let mut current_name = None;
        if has_table(db, IDENTITY_TABLE).await? {
            let rows = db
                .query_all_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    "SELECT singleton, version, uuid FROM microsandbox_catalog_identity",
                ))
                .await?;
            if rows.len() != 1
                || rows[0].try_get_by_index::<i64>(0)? != 1
                || rows[0].try_get_by_index::<i64>(1)? != 1
            {
                return Err(invalid("invalid or unsupported catalog identity metadata"));
            }
            let uuid: String = rows[0].try_get_by_index(2)?;
            if !valid_uuid(&uuid) {
                return Err(invalid("invalid catalog UUID"));
            }
            if uuid == self.database_uuid {
                let row = sandbox::Entity::find_by_id(self.sandbox_id).one(db).await?;
                current_name = row.map(|row| row.name);
                status = if current_name.is_some() {
                    SnapshotSourceStatus::Available
                } else {
                    SnapshotSourceStatus::MissingSandbox
                };
            }
        }
        Ok(SnapshotSourceBinding {
            database_uuid: self.database_uuid.clone(),
            sandbox_id: self.sandbox_id,
            recorded_name: self.name.clone(),
            current_name,
            status,
        })
    }

    pub(super) async fn capture(
        db: &DbWriteConnection,
        sandbox_id: i32,
        name: &str,
    ) -> MicrosandboxResult<Self> {
        if sandbox_id <= 0 {
            return Err(invalid("invalid source sandbox ID"));
        }
        Ok(Self {
            schema: SOURCE_SCHEMA.into(),
            database_uuid: database_uuid(db).await?,
            sandbox_id,
            name: name.into(),
        })
    }

    pub(super) fn validate(&self) -> MicrosandboxResult<()> {
        if self.schema != SOURCE_SCHEMA || !valid_uuid(&self.database_uuid) || self.sandbox_id <= 0
        {
            return Err(invalid(
                "invalid or unsupported snapshot group source metadata",
            ));
        }
        Ok(())
    }

    pub(super) fn require_same(&self, expected: &Self) -> MicrosandboxResult<()> {
        self.validate()?;
        expected.validate()?;
        if self.database_uuid != expected.database_uuid || self.sandbox_id != expected.sandbox_id {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "snapshot group is bound to another sandbox instance (recorded name '{}'); create a new group for '{}'",
                self.name, expected.name,
            )));
        }
        Ok(())
    }

    /// Resolve the bound row in this installation, never the saved display name.
    pub(super) async fn resolve(&self, local: &LocalBackend) -> MicrosandboxResult<String> {
        self.validate()?;
        let db = local.db().await?;
        if self.database_uuid != database_uuid(db.write()).await? {
            return Err(MicrosandboxError::InvalidConfig(
                "snapshot group belongs to another catalog; create a new group for this sandbox"
                    .into(),
            ));
        }
        sandbox::Entity::find_by_id(self.sandbox_id)
            .one(db.read()).await?
            .map(|source| source.name)
            .ok_or_else(|| MicrosandboxError::InvalidConfig(format!(
                "snapshot group's source sandbox '{}' no longer exists; create a new group to capture another sandbox",
                self.name,
            )))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Install the optional identity atomically without extending the catalog migration ledger.
/// Older readers ignore this table. No runtime SQL or existing table is changed, and no
/// connection to the database file is opened outside the existing pools (important on macOS).
async fn database_uuid(db: &DbWriteConnection) -> MicrosandboxResult<String> {
    db.transaction(|txn| async move {
        // Acquire SQLite's writer before testing for the table. Two processes must not
        // observe absence and subsequently create competing identities. This also avoids
        // upgrading a stale WAL read transaction to a writer.
        txn.execute_unprepared("UPDATE maintenance_lease SET holder_pid = holder_pid WHERE name = 'install_exclusive'").await?;
        if !has_table(&txn, IDENTITY_TABLE).await? {
            txn.execute_unprepared("CREATE TABLE microsandbox_catalog_identity (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), version INTEGER NOT NULL, uuid TEXT NOT NULL)").await?;
            let mut bytes: [u8; 16] = rand::random();
            bytes[6] = (bytes[6] & 0x0f) | 0x40;
            bytes[8] = (bytes[8] & 0x3f) | 0x80;
            let hex = format!("{:032x}", u128::from_be_bytes(bytes));
            let uuid = format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..]);
            txn.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,
                "INSERT INTO microsandbox_catalog_identity (singleton, version, uuid) VALUES (1, 1, ?)", [uuid.into()])).await?;
        }
        // Never regenerate an existing but empty/corrupt identity: that would silently
        // orphan every bound group. Initialization and its row commit in one transaction.
        let rows = txn.query_all_raw(Statement::from_string(DbBackend::Sqlite,
            "SELECT singleton, version, uuid FROM microsandbox_catalog_identity")).await?;
        if rows.len() != 1 || rows[0].try_get_by_index::<i64>(0)? != 1 || rows[0].try_get_by_index::<i64>(1)? != 1 {
            return Err(invalid("invalid or unsupported catalog identity metadata"));
        }
        let uuid: String = rows[0].try_get_by_index(2)?;
        if !valid_uuid(&uuid) {
            return Err(invalid("invalid catalog UUID"));
        }
        Ok((txn, uuid))
    }).await
}

fn valid_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
            }
        })
        && bytes[14] == b'4'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

fn invalid(message: &str) -> MicrosandboxError {
    MicrosandboxError::SnapshotIntegrity(message.into())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::LocalBackend;

    #[tokio::test]
    async fn identity_is_stable_separate_from_migrations_and_unique_per_database() {
        let home = tempfile::tempdir().unwrap();
        let local = LocalBackend::builder()
            .home(home.path())
            .build()
            .await
            .unwrap();
        let db = local.db().await.unwrap().write();
        let history = || {
            Statement::from_string(
                DbBackend::Sqlite,
                "SELECT group_concat(version) FROM (SELECT version FROM seaql_migrations ORDER BY version)",
            )
        };
        let before: String = db
            .query_one_raw(history())
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index(0)
            .unwrap();
        let first = database_uuid(db).await.unwrap();
        assert!(valid_uuid(&first));
        assert_eq!(first, database_uuid(db).await.unwrap());
        db.execute_unprepared("VACUUM").await.unwrap();
        assert_eq!(first, database_uuid(db).await.unwrap());
        let after: String = db
            .query_one_raw(history())
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index(0)
            .unwrap();
        assert_eq!(before, after);
        let reopened = LocalBackend::builder()
            .home(home.path())
            .build()
            .await
            .unwrap();
        assert_eq!(
            first,
            database_uuid(reopened.db().await.unwrap().write())
                .await
                .unwrap()
        );
        let other_home = tempfile::tempdir().unwrap();
        let other = LocalBackend::builder()
            .home(other_home.path())
            .build()
            .await
            .unwrap();
        assert_ne!(
            first,
            database_uuid(other.db().await.unwrap().write())
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn concurrent_initializers_agree_and_corruption_is_not_repaired_silently() {
        let home = tempfile::tempdir().unwrap();
        let a = LocalBackend::builder()
            .home(home.path())
            .build()
            .await
            .unwrap();
        let b = LocalBackend::builder()
            .home(home.path())
            .build()
            .await
            .unwrap();
        let a = a.db().await.unwrap().write();
        let b = b.db().await.unwrap().write();
        let (left, right) = tokio::join!(database_uuid(a), database_uuid(b));
        assert_eq!(left.unwrap(), right.unwrap());
        a.execute_unprepared("UPDATE microsandbox_catalog_identity SET version = 2")
            .await
            .unwrap();
        assert!(database_uuid(a).await.is_err());
        a.execute_unprepared("DELETE FROM microsandbox_catalog_identity")
            .await
            .unwrap();
        assert!(database_uuid(a).await.is_err());
    }

    #[tokio::test]
    async fn binding_uses_incarnation_not_display_name() {
        let home = tempfile::tempdir().unwrap();
        let local = LocalBackend::builder()
            .home(home.path())
            .build()
            .await
            .unwrap();
        let db = local.db().await.unwrap().write();
        let source = Source::capture(db, 1, "app").await.unwrap();
        source
            .require_same(&Source::capture(db, 1, "renamed").await.unwrap())
            .unwrap();
        assert!(
            source
                .require_same(&Source::capture(db, 2, "app").await.unwrap())
                .is_err()
        );
    }
    #[tokio::test]
    async fn inspection_distinguishes_rename_replacement_and_foreign_catalog_without_rebinding() {
        use sea_orm::{ActiveModelTrait, ActiveValue::Set};
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let db = local.db().await.unwrap();
        let insert = || sandbox::ActiveModel {
            name: Set("app".into()),
            config: Set(serde_json::to_string(&crate::sandbox::SandboxConfig::default()).unwrap()),
            status: Set(sandbox::SandboxStatus::Stopped),
            ephemeral: Set(false),
            ..Default::default()
        };
        let row = insert().insert(db.write()).await.unwrap();
        let source = Source::capture(db.write(), row.id, "app").await.unwrap();
        assert_eq!(
            source.inspect(&local).await.unwrap().status,
            SnapshotSourceStatus::Available
        );
        db.write()
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE sandbox SET name = ? WHERE id = ?",
                ["renamed".into(), row.id.into()],
            ))
            .await
            .unwrap();
        let renamed = source.inspect(&local).await.unwrap();
        assert_eq!(renamed.recorded_name, "app");
        assert_eq!(renamed.current_name.as_deref(), Some("renamed"));
        sandbox::Entity::delete_by_id(row.id)
            .exec(db.write())
            .await
            .unwrap();
        let replacement = insert().insert(db.write()).await.unwrap();
        assert_ne!(replacement.id, row.id);
        let missing = source.inspect(&local).await.unwrap();
        assert_eq!(missing.status, SnapshotSourceStatus::MissingSandbox);
        assert!(missing.current_name.is_none());
        let other_home = tempfile::tempdir().unwrap();
        let other = crate::test_support::local_backend_builder(other_home.path())
            .build()
            .await
            .unwrap();
        assert_eq!(
            source.inspect(&other).await.unwrap().status,
            SnapshotSourceStatus::DifferentCatalog
        );
        assert!(
            !has_table(other.db().await.unwrap().read(), IDENTITY_TABLE)
                .await
                .unwrap()
        );
        Source::capture(other.db().await.unwrap().write(), 1, "app")
            .await
            .unwrap();
        assert_eq!(
            source.inspect(&other).await.unwrap().status,
            SnapshotSourceStatus::DifferentCatalog
        );
        db.write()
            .execute_unprepared("UPDATE microsandbox_catalog_identity SET version = 2")
            .await
            .unwrap();
        assert!(source.inspect(&local).await.is_err());
    }
}
