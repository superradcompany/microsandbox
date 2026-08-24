//! Static metadata for downgrade planning.
//!
//! `Migrator::migrations()` owns the executable migration order. This module
//! keeps the user-facing downgrade metadata in the same crate so release checks
//! can ensure every migration has an explicit reversibility and cache-impact
//! decision before a new binary ships.

use std::collections::HashSet;

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

/// Migration that adds payload scope metadata to the snapshot index.
pub const SNAPSHOT_SCOPE_MIGRATION_ID: &str = "m20260714_000001_add_snapshot_scope";

/// Migration that projects final snapshot state and journals legacy conversion.
pub const SNAPSHOT_ARTIFACT_TRANSITION_MIGRATION_ID: &str =
    "m20260723_000001_snapshot_artifact_transition";

/// Migration that introduces cooperative host CPU allocation state.
pub const CPU_ALLOCATION_MIGRATION_ID: &str = "m20260719_000001_create_cpu_allocations";

/// Migration that introduces host-global writeback dirty-credit reservations.
pub const WRITEBACK_ALLOCATION_MIGRATION_ID: &str = "m20260803_000001_create_writeback_allocations";

/// Migration that records per-NUMA-node guest memory promises for CPU allocations.
pub const MEMORY_ALLOCATION_NODES_MIGRATION_ID: &str =
    "m20260808_000001_create_memory_allocation_nodes";

/// Migration that rebuilds the sandbox label index from persisted configs.
pub const SANDBOX_LABEL_REBUILD_MIGRATION_ID: &str = "m20260810_000001_rebuild_sandbox_labels";

/// Migration that permits several managed vCPUs to share one host logical processor.
pub const SHARED_CPU_ALLOCATION_MIGRATION_ID: &str = "m20260813_000001_share_cpu_allocations";

/// Migration that prevents old binaries from discarding persisted mount ownership.
pub const MOUNT_OWNER_CONFIG_MIGRATION_ID: &str = "m20260824_000001_mount_owner_config";

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
    MigrationMetadata {
        id: "m20260708_000001_migrate_bind_rootfs_source",
        reversible: true,
        affects_cache: false,
        affects_user_data: true,
        summary: "rewrite bind rootfs config back to the legacy string shape",
    },
    MigrationMetadata {
        id: "m20260710_000001_migrate_root_disk",
        reversible: true,
        affects_cache: false,
        affects_user_data: true,
        summary: "rewrite root disk config back to the upper size shape",
    },
    MigrationMetadata {
        id: SNAPSHOT_SCOPE_MIGRATION_ID,
        reversible: true,
        affects_cache: false,
        affects_user_data: false,
        summary: "remove snapshot scope index metadata",
    },
    MigrationMetadata {
        id: SNAPSHOT_ARTIFACT_TRANSITION_MIGRATION_ID,
        reversible: true,
        affects_cache: false,
        affects_user_data: true,
        summary: "reverse final snapshot descriptors before removing migration state",
    },
    MigrationMetadata {
        id: CPU_ALLOCATION_MIGRATION_ID,
        reversible: true,
        affects_cache: false,
        affects_user_data: false,
        summary: "remove cooperative host CPU allocation tables",
    },
    MigrationMetadata {
        id: WRITEBACK_ALLOCATION_MIGRATION_ID,
        reversible: true,
        affects_cache: false,
        affects_user_data: false,
        summary: "remove host-global writeback allocation state",
    },
    MigrationMetadata {
        id: MEMORY_ALLOCATION_NODES_MIGRATION_ID,
        reversible: true,
        affects_cache: false,
        affects_user_data: false,
        summary: "remove cooperative NUMA memory allocation state",
    },
    MigrationMetadata {
        id: SANDBOX_LABEL_REBUILD_MIGRATION_ID,
        reversible: true,
        affects_cache: false,
        affects_user_data: false,
        summary: "retain the rebuilt sandbox label index",
    },
    MigrationMetadata {
        id: SHARED_CPU_ALLOCATION_MIGRATION_ID,
        reversible: true,
        affects_cache: false,
        affects_user_data: false,
        summary: "restore exclusive logical CPU allocation rows",
    },
    MigrationMetadata {
        id: MOUNT_OWNER_CONFIG_MIGRATION_ID,
        reversible: true,
        affects_cache: false,
        affects_user_data: false,
        summary: "remove the compatibility marker after confirming no persisted mount ownership",
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

/// Resolve an unordered collection of applied migration identifiers to its canonical prefix.
///
/// SeaORM records migration timestamps with insufficient precision to recover execution order
/// when several migrations run together. Treat the migration table as a set and use this binary's
/// append-only metadata as the only source of ordering instead.
pub fn canonical_applied_prefix<'a>(
    applied_ids: impl IntoIterator<Item = &'a str>,
) -> Option<&'static [MigrationMetadata]> {
    let mut applied_count = 0;
    let applied_ids: HashSet<_> = applied_ids
        .into_iter()
        .inspect(|_| applied_count += 1)
        .collect();

    // Duplicate migration rows are invalid even if their distinct identifiers resemble a prefix.
    if applied_ids.len() != applied_count {
        return None;
    }

    let prefix = MIGRATION_METADATA.get(..applied_count)?;
    prefix
        .iter()
        .all(|metadata| applied_ids.contains(metadata.id))
        .then_some(prefix)
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
    fn canonical_applied_prefix_uses_metadata_order() {
        let applied = [
            MOUNT_OWNER_CONFIG_MIGRATION_ID,
            SHARED_CPU_ALLOCATION_MIGRATION_ID,
            SANDBOX_LABEL_REBUILD_MIGRATION_ID,
            MEMORY_ALLOCATION_NODES_MIGRATION_ID,
            WRITEBACK_ALLOCATION_MIGRATION_ID,
            SNAPSHOT_ARTIFACT_TRANSITION_MIGRATION_ID,
            CPU_ALLOCATION_MIGRATION_ID,
        ];
        let prefix_len = MIGRATION_METADATA.len();
        let mut all_applied: Vec<_> = MIGRATION_METADATA[..prefix_len - applied.len()]
            .iter()
            .map(|metadata| metadata.id)
            .collect();
        all_applied.extend(applied);

        let prefix = canonical_applied_prefix(all_applied).expect("valid unordered prefix");
        assert_eq!(prefix, MIGRATION_METADATA);
    }

    #[test]
    fn canonical_applied_prefix_rejects_gaps_and_unknown_migrations() {
        let without_first = MIGRATION_METADATA
            .iter()
            .skip(1)
            .map(|metadata| metadata.id);
        assert!(canonical_applied_prefix(without_first).is_none());

        let with_unknown = MIGRATION_METADATA
            .iter()
            .map(|metadata| metadata.id)
            .chain(["m20990101_000001_future"]);
        assert!(canonical_applied_prefix(with_unknown).is_none());
    }

    #[test]
    fn frozen_0_6_0_baseline_is_current_prefix() {
        let metadata_ids: Vec<_> = migration_ids().collect();
        assert!(metadata_ids.starts_with(BASELINE_0_6_0_MIGRATIONS));
    }
}
