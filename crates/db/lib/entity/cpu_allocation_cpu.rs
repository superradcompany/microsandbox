//! Entity definition for logical processors reserved by active allocations.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One host logical processor reserved by a cooperative allocation.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cpu_allocation_cpu")]
pub struct Model {
    /// Host logical processor identifier and global conflict key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub logical_cpu: i64,
    /// Owning allocation identifier.
    pub allocation_id: String,
    /// Possible guest vCPU index, or `None` for policy-only sibling reservations.
    pub vcpu_index: Option<i32>,
    /// Reservation role (`assigned` or `smt-reserved`).
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
