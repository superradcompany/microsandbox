//! Entity definition for cooperative per-NUMA-node memory promises.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One guest proximity domain backed by a host NUMA node under an active allocation lease.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "memory_allocation_node")]
pub struct Model {
    /// Parent CPU/allocation lease identifier.
    #[sea_orm(primary_key, auto_increment = false)]
    pub allocation_id: String,
    /// Dense guest proximity-domain identifier.
    #[sea_orm(primary_key, auto_increment = false)]
    pub guest_numa_node: i32,
    /// Host NUMA node selected by the planner.
    pub host_numa_node: i32,
    /// Guest memory online at boot, in MiB.
    pub boot_mib: i64,
    /// Maximum memory promised to this guest node, in MiB.
    pub max_mib: i64,
}

/// Relations for a memory-node promise.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The memory promise belongs to one allocation lease.
    #[sea_orm(
        belongs_to = "super::cpu_allocation::Entity",
        from = "Column::AllocationId",
        to = "super::cpu_allocation::Column::Id",
        on_delete = "Cascade"
    )]
    Allocation,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Related<super::cpu_allocation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Allocation.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
