//! Entity definition for the `microvms` table.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The microVM process entity model.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "microvm")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub sandbox_id: i32,
    pub supervisor_id: i32,
    pub pid: Option<i32>,
    pub status: String,
    pub exit_code: Option<i32>,
    pub exit_signal: Option<i32>,
    pub termination_reason: Option<String>,
    pub termination_detail: Option<String>,
    pub signals_sent: Option<String>,
    pub started_at: Option<DateTime>,
    pub terminated_at: Option<DateTime>,
}

//--------------------------------------------------------------------------------------------------
// Types: Relations
//--------------------------------------------------------------------------------------------------

/// Relations for the microvm entity.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// A microvm belongs to a sandbox.
    #[sea_orm(
        belongs_to = "super::sandbox::Entity",
        from = "Column::SandboxId",
        to = "super::sandbox::Column::Id",
        on_delete = "Cascade"
    )]
    Sandbox,

    /// A microvm belongs to a supervisor.
    #[sea_orm(
        belongs_to = "super::supervisor::Entity",
        from = "Column::SupervisorId",
        to = "super::supervisor::Column::Id",
        on_delete = "Cascade"
    )]
    Supervisor,
}

impl Related<super::sandbox::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sandbox.def()
    }
}

impl Related<super::supervisor::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Supervisor.def()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl ActiveModelBehavior for ActiveModel {}
