//! Migration: Replace exclusive logical-CPU rows with shareable vCPU assignments.

use sea_orm_migration::{prelude::*, sea_orm::ConnectionTrait};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const SHAREABLE_SCHEMA: &str = "
    CREATE TABLE cpu_allocation_cpu (
        allocation_id TEXT NOT NULL,
        vcpu_index INTEGER NOT NULL,
        logical_cpu INTEGER NOT NULL,
        role TEXT NOT NULL,
        PRIMARY KEY (allocation_id, vcpu_index),
        FOREIGN KEY (allocation_id) REFERENCES cpu_allocation(id) ON DELETE CASCADE
    );
";

const EXCLUSIVE_SCHEMA: &str = "
    CREATE TABLE cpu_allocation_cpu (
        logical_cpu INTEGER NOT NULL PRIMARY KEY,
        allocation_id TEXT NOT NULL,
        vcpu_index INTEGER,
        role TEXT NOT NULL,
        FOREIGN KEY (allocation_id) REFERENCES cpu_allocation(id) ON DELETE CASCADE
    );
";

const COPY_ASSIGNED_ROWS: &str = "
    INSERT INTO cpu_allocation_cpu (allocation_id, vcpu_index, logical_cpu, role)
    SELECT allocation_id, vcpu_index, logical_cpu, 'assigned'
    FROM cpu_allocation_cpu_previous
    WHERE vcpu_index IS NOT NULL;
";

const COPY_EXCLUSIVE_ROWS: &str = "
    INSERT INTO cpu_allocation_cpu (logical_cpu, allocation_id, vcpu_index, role)
    SELECT logical_cpu, allocation_id, vcpu_index, role
    FROM cpu_allocation_cpu_previous;
";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260813_000001_share_cpu_allocations"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        rebuild_assignments(
            manager,
            SHAREABLE_SCHEMA,
            COPY_ASSIGNED_ROWS,
            "CREATE INDEX idx_cpu_allocation_cpu_logical ON cpu_allocation_cpu(logical_cpu);",
        )
        .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        rebuild_assignments(
            manager,
            EXCLUSIVE_SCHEMA,
            COPY_EXCLUSIVE_ROWS,
            "CREATE UNIQUE INDEX idx_cpu_allocation_cpu_vcpu \
             ON cpu_allocation_cpu(allocation_id, vcpu_index);",
        )
        .await
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn rebuild_assignments(
    manager: &SchemaManager<'_>,
    schema: &'static str,
    copy: &'static str,
    index: &'static str,
) -> Result<(), DbErr> {
    const SAVEPOINT: &str = "share_cpu_allocations";
    let connection = manager.get_connection();
    connection
        .execute_unprepared(&format!("SAVEPOINT {SAVEPOINT};"))
        .await?;

    let result = async {
        connection
            .execute_unprepared(
                "ALTER TABLE cpu_allocation_cpu RENAME TO cpu_allocation_cpu_previous;",
            )
            .await?;
        connection.execute_unprepared(schema).await?;
        connection.execute_unprepared(copy).await?;
        connection
            .execute_unprepared("DROP TABLE cpu_allocation_cpu_previous;")
            .await?;
        connection.execute_unprepared(index).await?;
        Ok::<_, DbErr>(())
    }
    .await;

    match result {
        Ok(()) => {
            connection
                .execute_unprepared(&format!("RELEASE SAVEPOINT {SAVEPOINT};"))
                .await?;
            Ok(())
        }
        Err(error) => {
            let _ = connection
                .execute_unprepared(&format!("ROLLBACK TO SAVEPOINT {SAVEPOINT};"))
                .await;
            let _ = connection
                .execute_unprepared(&format!("RELEASE SAVEPOINT {SAVEPOINT};"))
                .await;
            Err(error)
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use sea_orm_migration::sea_orm::{Database, DatabaseConnection, Statement};

    use super::*;

    async fn exclusive_catalog() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared(
            "CREATE TABLE cpu_allocation (id TEXT PRIMARY KEY);
             CREATE TABLE cpu_allocation_cpu (
                 logical_cpu INTEGER NOT NULL PRIMARY KEY,
                 allocation_id TEXT NOT NULL,
                 vcpu_index INTEGER,
                 role TEXT NOT NULL,
                 FOREIGN KEY (allocation_id) REFERENCES cpu_allocation(id) ON DELETE CASCADE
             );
             CREATE UNIQUE INDEX idx_cpu_allocation_cpu_vcpu
                 ON cpu_allocation_cpu(allocation_id, vcpu_index);
             INSERT INTO cpu_allocation VALUES ('first');
             INSERT INTO cpu_allocation VALUES ('second');
             INSERT INTO cpu_allocation_cpu VALUES (0, 'first', 0, 'assigned');
             INSERT INTO cpu_allocation_cpu VALUES (1, 'first', NULL, 'smt-reserved');",
        )
        .await
        .unwrap();
        db
    }

    #[tokio::test]
    async fn migration_drops_hard_sibling_holds_and_allows_shared_logical_cpus() {
        let db = exclusive_catalog().await;
        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        db.execute_unprepared(
            "INSERT INTO cpu_allocation_cpu
                (allocation_id, vcpu_index, logical_cpu, role)
             VALUES ('second', 0, 0, 'assigned');",
        )
        .await
        .unwrap();

        let rows = db
            .query_all_raw(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                "SELECT allocation_id, vcpu_index, logical_cpu, role
                 FROM cpu_allocation_cpu ORDER BY allocation_id",
            ))
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter()
                .all(|row| row.try_get_by_index::<i64>(2).unwrap() == 0)
        );
        assert!(
            rows.iter()
                .all(|row| row.try_get_by_index::<String>(3).unwrap() == "assigned")
        );
    }

    #[tokio::test]
    async fn downgrade_restores_the_exclusive_shape_when_allocations_are_stopped() {
        let db = exclusive_catalog().await;
        Migration.up(&SchemaManager::new(&db)).await.unwrap();
        db.execute_unprepared("DELETE FROM cpu_allocation_cpu;")
            .await
            .unwrap();

        Migration.down(&SchemaManager::new(&db)).await.unwrap();

        let columns = db
            .query_all_raw(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                "PRAGMA table_info(cpu_allocation_cpu)",
            ))
            .await
            .unwrap();
        let logical_cpu = columns
            .iter()
            .find(|row| row.try_get_by_index::<String>(1).unwrap() == "logical_cpu")
            .unwrap();
        assert_eq!(logical_cpu.try_get_by_index::<i32>(5).unwrap(), 1);
    }
}
