//! Database migrations for microsandbox.

mod m20260305_000001_create_image_tables;
mod m20260305_000002_create_sandbox_tables;
mod m20260305_000003_create_storage_tables;
mod m20260305_000004_create_sandbox_images_table;
mod m20260410_000001_erofs_image_schema;
mod m20260501_000001_create_snapshot_index;

use sea_orm_migration::prelude::*;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use sea_orm_migration::MigratorTrait;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The migrator that runs all migrations in order.
pub struct Migrator;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260305_000001_create_image_tables::Migration),
            Box::new(m20260305_000002_create_sandbox_tables::Migration),
            Box::new(m20260305_000003_create_storage_tables::Migration),
            Box::new(m20260305_000004_create_sandbox_images_table::Migration),
            Box::new(m20260410_000001_erofs_image_schema::Migration),
            Box::new(m20260501_000001_create_snapshot_index::Migration),
        ]
    }
}
