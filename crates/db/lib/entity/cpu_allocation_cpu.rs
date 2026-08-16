//! Entity definition for logical processors reserved by active allocations.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One guest vCPU assignment coordinated by a host allocation.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cpu_allocation_cpu")]
pub struct Model {
    /// Owning allocation identifier.
    #[sea_orm(primary_key, auto_increment = false)]
    pub allocation_id: String,
    /// Guest vCPU index within the allocation.
    #[sea_orm(primary_key, auto_increment = false)]
    pub vcpu_index: i32,
    /// Host logical processor selected for this vCPU. Multiple allocations may share it.
    pub logical_cpu: i64,
    /// Assignment role: `planned` before the OS acknowledgement, then `assigned` when confirmed.
    pub role: String,
}

/// Relations for a CPU reservation.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The reserved processor belongs to one allocation.
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
