//! Migration: Add `sandbox.caller_config_overrides` for sparse caller overrides.

use sea_orm_migration::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Types: Identifiers
//--------------------------------------------------------------------------------------------------

#[derive(Iden)]
enum Sandbox {
    Table,
    CallerConfigOverrides,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261022_000001_sandbox_caller_config_overrides"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Sandbox::Table)
                    .add_column(ColumnDef::new(Sandbox::CallerConfigOverrides).text())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Sandbox::Table)
                    .drop_column(Sandbox::CallerConfigOverrides)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use sea_orm_migration::sea_orm::{ConnectionTrait, Database, DatabaseBackend, Statement};

    use super::*;
    use crate::{Migrator, MigratorTrait};

    #[tokio::test]
    async fn caller_config_overrides_migration_and_downgrade_preserve_resolved_settings() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let preceding = Migrator::migrations()
            .iter()
            .position(|migration| migration.name() == Migration.name())
            .unwrap();
        Migrator::up(&db, Some(preceding as u32)).await.unwrap();
        db.execute_unprepared(r#"INSERT INTO sandbox (name, config, active_config, status, ephemeral) VALUES ('legacy', '{"runtime":{"workdir":"/desired"}}', '{"runtime":{"workdir":"/active"}}', 'Stopped', 0)"#).await.unwrap();
        let manager = SchemaManager::new(&db);
        Migration.up(&manager).await.unwrap();
        let row = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT config, active_config, caller_config_overrides FROM sandbox WHERE name='legacy'",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.try_get::<Option<String>>("", "caller_config_overrides")
                .unwrap(),
            None
        );
        let desired: String = row.try_get("", "config").unwrap();
        let active: String = row.try_get("", "active_config").unwrap();
        db.execute_unprepared(
            "UPDATE sandbox SET caller_config_overrides = '{}' WHERE name='legacy'",
        )
        .await
        .unwrap();

        Migration.down(&manager).await.unwrap();
        assert!(
            !manager
                .has_column("sandbox", "caller_config_overrides")
                .await
                .unwrap()
        );
        let row = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT config, active_config FROM sandbox WHERE name='legacy'",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get::<String>("", "config").unwrap(), desired);
        assert_eq!(row.try_get::<String>("", "active_config").unwrap(), active);

        Migration.up(&manager).await.unwrap();
        let row = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT caller_config_overrides FROM sandbox WHERE name='legacy'",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.try_get::<Option<String>>("", "caller_config_overrides")
                .unwrap(),
            None
        );
    }
}
