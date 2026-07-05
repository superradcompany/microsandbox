//! Static metadata for downgrade planning.
//!
//! `Migrator::migrations()` owns the executable migration order. This module
//! keeps the user-facing downgrade metadata in the same crate so release checks
//! can ensure every migration has an explicit reversibility and cache-impact
//! decision before a new binary ships.

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Version of the hidden schema-baseline JSON shape emitted by the CLI.
pub const SCHEMA_BASELINE_FORMAT_VERSION: u32 = 1;

/// Oldest release supported by the downgrade flow.
pub const DOWNGRADE_FLOOR: &str = "0.6.0";

/// Migration that introduced the DB-backed maintenance lease table.
pub const MAINTENANCE_LEASE_MIGRATION_ID: &str = "m20260621_000002_create_maintenance_lease";

/// Migration that introduced desired-vs-active sandbox config tracking.
pub const ACTIVE_CONFIG_MIGRATION_ID: &str = "m20260703_000001_add_sandbox_active_config";

/// Frozen migration baseline for the transitional 0.6.0 release.
///
/// The released 0.6.0 binary predates `msb __schema-baseline --json`, so
/// downgrade uses this fixture when inspecting that exact target. Do not extend
/// this list when adding later migrations; future targets should answer with
/// their own hidden baseline command.
pub const BASELINE_0_6_0_MIGRATIONS: &[&str] = &[
    "m20260305_000001_create_image_tables",
    "m20260305_000002_create_sandbox_tables",
    "m20260305_000003_create_storage_tables",
    "m20260305_000004_create_sandbox_images_table",
    "m20260410_000001_erofs_image_schema",
    "m20260501_000001_create_snapshot_index",
    "m20260517_000001_drop_sandbox_metric",
    "m20260527_000001_migrate_oci_rootfs_source",
    "m20260531_000001_create_sandbox_labels",
    "m20260531_000002_index_sandbox_labels_key_value",
    "m20260606_000001_named_volume_kinds",
    "m20260621_000001_add_sandbox_ephemeral",
    MAINTENANCE_LEASE_MIGRATION_ID,
];

/// Metadata for every migration in `Migrator::migrations()` order.
pub const MIGRATION_METADATA: &[MigrationMetadata] = &[
    MigrationMetadata {
        id: "m20260305_000001_create_image_tables",
        reversible: true,
        affects_cache: true,
        affects_user_data: false,
        summary: "remove legacy OCI image catalog tables",
    },
    MigrationMetadata {
        id: "m20260305_000002_create_sandbox_tables",
        reversible: true,
        affects_cache: false,
        affects_user_data: false,
        summary: "remove sandbox and run tables",
    },
    MigrationMetadata {
        id: "m20260305_000003_create_storage_tables",
        reversible: true,
        affects_cache: false,
        affects_user_data: false,
        summary: "remove volume and snapshot storage tables",
    },
    MigrationMetadata {
        id: "m20260305_000004_create_sandbox_images_table",
        reversible: true,
        affects_cache: true,
        affects_user_data: false,
        summary: "remove sandbox image references",
    },
    MigrationMetadata {
        id: "m20260410_000001_erofs_image_schema",
        reversible: true,
        affects_cache: true,
        affects_user_data: false,
        summary: "remove EROFS rootfs catalog tables",
    },
    MigrationMetadata {
        id: "m20260501_000001_create_snapshot_index",
        reversible: true,
        affects_cache: false,
        affects_user_data: false,
        summary: "remove snapshot index table",
    },
    MigrationMetadata {
        id: "m20260517_000001_drop_sandbox_metric",
        reversible: false,
        affects_cache: false,
        affects_user_data: false,
        summary: "restore legacy sandbox metrics table",
    },
    MigrationMetadata {
        id: "m20260527_000001_migrate_oci_rootfs_source",
        reversible: false,
        affects_cache: false,
        affects_user_data: false,
        summary: "rewrite OCI rootfs config back to the legacy string shape",
    },
    MigrationMetadata {
        id: "m20260531_000001_create_sandbox_labels",
        reversible: true,
        affects_cache: false,
        affects_user_data: false,
        summary: "remove sandbox labels table",
    },
    MigrationMetadata {
        id: "m20260531_000002_index_sandbox_labels_key_value",
        reversible: true,
        affects_cache: false,
        affects_user_data: false,
        summary: "remove sandbox label key/value index",
    },
    MigrationMetadata {
        id: "m20260606_000001_named_volume_kinds",
        reversible: true,
        affects_cache: false,
        affects_user_data: false,
        summary: "remove named volume kind columns and attachments",
    },
    MigrationMetadata {
        id: "m20260621_000001_add_sandbox_ephemeral",
        reversible: true,
        affects_cache: false,
        affects_user_data: false,
        summary: "remove sandbox ephemeral flag",
    },
    MigrationMetadata {
        id: MAINTENANCE_LEASE_MIGRATION_ID,
        reversible: true,
        affects_cache: false,
        affects_user_data: false,
        summary: "remove maintenance lease table",
    },
    MigrationMetadata {
        id: ACTIVE_CONFIG_MIGRATION_ID,
        reversible: true,
        affects_cache: false,
        affects_user_data: false,
        summary: "remove active sandbox config snapshots",
    },
];

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Downgrade metadata for one migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationMetadata {
    /// Migration identifier returned by `MigrationName::name()`.
    pub id: &'static str,

    /// Whether `down()` actually restores a target-compatible schema/state.
    pub reversible: bool,

    /// Whether rolling this migration back invalidates re-pullable image cache
    /// contents on disk.
    pub affects_cache: bool,

    /// Whether rolling this migration back may leave snapshots or disk-backed
    /// named volumes in a format the target release cannot read.
    pub affects_user_data: bool,

    /// Short human-readable summary used in destructive downgrade prompts.
    pub summary: &'static str,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Return all migration identifiers in schema order.
pub fn migration_ids() -> impl Iterator<Item = &'static str> {
    MIGRATION_METADATA.iter().map(|metadata| metadata.id)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Migrator, MigratorTrait};

    #[test]
    fn metadata_matches_migrator_order() {
        let migrations = Migrator::migrations();
        let migrator_ids: Vec<_> = migrations
            .iter()
            .map(|migration| migration.name().to_string())
            .collect();
        let metadata_ids: Vec<_> = migration_ids().map(str::to_string).collect();

        assert_eq!(metadata_ids, migrator_ids);
    }

    #[test]
    fn frozen_0_6_0_baseline_is_current_prefix() {
        let metadata_ids: Vec<_> = migration_ids().collect();
        assert!(metadata_ids.starts_with(BASELINE_0_6_0_MIGRATIONS));
    }
}
