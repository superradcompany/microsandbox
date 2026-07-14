//! Database migrations for microsandbox.

mod m20260305_000001_create_image_tables;
mod m20260305_000002_create_sandbox_tables;
mod m20260305_000003_create_storage_tables;
mod m20260305_000004_create_sandbox_images_table;
mod m20260410_000001_erofs_image_schema;
mod m20260501_000001_create_snapshot_index;
mod m20260517_000001_drop_sandbox_metric;
mod m20260527_000001_migrate_oci_rootfs_source;
mod m20260531_000001_create_sandbox_labels;
mod m20260531_000002_index_sandbox_labels_key_value;
mod m20260606_000001_named_volume_kinds;
mod m20260621_000001_add_sandbox_ephemeral;
mod m20260621_000002_create_maintenance_lease;
mod m20260703_000001_add_sandbox_active_config;
mod m20260708_000001_migrate_bind_rootfs_source;
mod m20260710_000001_migrate_root_disk;
mod m20260714_000001_add_snapshot_scope;
pub mod schema_metadata;

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
            Box::new(m20260517_000001_drop_sandbox_metric::Migration),
            Box::new(m20260527_000001_migrate_oci_rootfs_source::Migration),
            Box::new(m20260531_000001_create_sandbox_labels::Migration),
            Box::new(m20260531_000002_index_sandbox_labels_key_value::Migration),
            Box::new(m20260606_000001_named_volume_kinds::Migration),
            Box::new(m20260621_000001_add_sandbox_ephemeral::Migration),
            Box::new(m20260621_000002_create_maintenance_lease::Migration),
            Box::new(m20260703_000001_add_sandbox_active_config::Migration),
            Box::new(m20260708_000001_migrate_bind_rootfs_source::Migration),
            Box::new(m20260710_000001_migrate_root_disk::Migration),
            Box::new(m20260714_000001_add_snapshot_scope::Migration),
        ]
    }
}
