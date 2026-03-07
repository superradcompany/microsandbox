//! Entity definition for the `supervisors` table.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The status of a supervisor process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum SupervisorStatus {
    /// The supervisor is running.
    #[sea_orm(string_value = "Running")]
    Running,

    /// The supervisor has stopped.
    #[sea_orm(string_value = "Stopped")]
    Stopped,
}

/// The supervisor process entity model.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "supervisor")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub sandbox_id: i32,
    pub pid: Option<i32>,
    pub status: SupervisorStatus,
    pub started_at: Option<DateTime>,
    pub stopped_at: Option<DateTime>,
}

//--------------------------------------------------------------------------------------------------
// Types: Relations
//--------------------------------------------------------------------------------------------------

/// Relations for the supervisor entity.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// A supervisor belongs to a sandbox.
    #[sea_orm(
        belongs_to = "super::sandbox::Entity",
        from = "Column::SandboxId",
        to = "super::sandbox::Column::Id",
        on_delete = "Cascade"
    )]
    Sandbox,

    /// A supervisor has many microvms.
    #[sea_orm(has_many = "super::microvm::Entity")]
    Microvm,

    /// A supervisor has many msbnets.
    #[sea_orm(has_many = "super::msbnet::Entity")]
    Msbnet,
}

impl Related<super::sandbox::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sandbox.def()
    }
}

impl Related<super::microvm::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Microvm.def()
    }
}

impl Related<super::msbnet::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Msbnet.def()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl ActiveModelBehavior for ActiveModel {}
