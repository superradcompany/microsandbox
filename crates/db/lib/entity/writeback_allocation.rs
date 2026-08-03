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
    /// Owning run row.
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
    /// Allocation creation time.
    pub created_at: DateTime,
}

/// Relations for a writeback allocation.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The allocation belongs to one sandbox run.
    #[sea_orm(
        belongs_to = "super::run::Entity",
        from = "Column::RunId",
        to = "super::run::Column::Id",
        on_delete = "Cascade"
    )]
    Run,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Related<super::run::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Run.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
