//! Entity definition for active host-global writeback reservations.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One active dirty-credit reservation owned by a sandbox run.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "writeback_allocation")]
pub struct Model {
    /// Cryptographically random allocation identifier.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    /// Run that originally acquired the reservation.
    ///
    /// This is deliberately not a foreign key: crash recovery must retain dirty credit even if
    /// lifecycle cleanup removes the run row before another runtime can inspect the stale lease.
    pub run_id: i32,
    /// Owner-only lock-file basename held for the process lifetime.
    pub lease_name: String,
    /// Hard limit passed to each eligible writable raw disk.
    pub per_disk_limit_bytes: i64,
    /// Number of disks charged to this reservation.
    pub disk_count: i32,
    /// Total dirty credit reserved by this run.
    pub reserved_bytes: i64,
    /// Host-global pool observed when the reservation was admitted.
    pub pool_bytes: i64,
    /// Linux boot identifier recorded when dirty credit was admitted.
    pub boot_id: String,
    /// Sorted Linux backing-filesystem device identities (`major:minor`, comma-separated).
    pub backing_devices: String,
    /// Allocation creation time.
    pub created_at: DateTime,
}

/// Writeback reservations intentionally have no cascading database relation.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl ActiveModelBehavior for ActiveModel {}
