//! Migration: establish the durable-config floor for mount ownership.
//!
//! The schema itself does not change. Recording this migration makes older
//! binaries refuse an ahead database instead of deserializing sandbox configs
//! while silently discarding mount ownership policy.

use sea_orm_migration::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Migration;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260824_000001_mount_owner_config"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // The migration row itself is the compatibility marker.
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration(
            "mount_owner_downgrade_unrepresentable: older binaries can silently discard persisted mount ownership"
                .into(),
        ))
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use sea_orm_migration::sea_orm::Database;

    use super::*;

    #[tokio::test]
    async fn downgrade_refuses_before_mutating_state() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let error = Migration.down(&SchemaManager::new(&db)).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("mount_owner_downgrade_unrepresentable")
        );
    }
}
