//! Entity definition for active cooperative CPU allocations.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One active managed CPU allocation owned by a sandbox run.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cpu_allocation")]
pub struct Model {
    /// Cryptographically random allocation identifier.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    /// Owning run row.
    pub run_id: i32,
    /// Policy requested by the caller.
    pub requested_policy: String,
    /// Policy selected by the planner.
    pub resolved_policy: String,
    /// Host enforcement class.
    pub enforcement: String,
    /// Fingerprint of the topology used for planning.
    pub topology_fingerprint: String,
    /// Owner-only lock-file basename held for the process lifetime.
    pub lease_name: String,
    /// Allocation lifecycle state.
    pub state: String,
    /// Allocation creation time.
    pub created_at: DateTime,
}

/// Relations for a CPU allocation.
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
