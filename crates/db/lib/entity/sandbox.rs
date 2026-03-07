//! Entity definition for the `sandboxes` table.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The status of a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum SandboxStatus {
    /// The sandbox is running.
    #[sea_orm(string_value = "Running")]
    Running,

    /// The sandbox is draining (shutting down gracefully).
    #[sea_orm(string_value = "Draining")]
    Draining,

    /// The sandbox is paused.
    #[sea_orm(string_value = "Paused")]
    Paused,

    /// The sandbox is stopped.
    #[sea_orm(string_value = "Stopped")]
    Stopped,

    /// The sandbox crashed.
    #[sea_orm(string_value = "Crashed")]
    Crashed,
}

/// The sandbox entity model.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "sandbox")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub name: String,
    pub config: String,
    pub status: SandboxStatus,
    pub created_at: Option<DateTime>,
    pub updated_at: Option<DateTime>,
}

//--------------------------------------------------------------------------------------------------
// Types: Relations
//--------------------------------------------------------------------------------------------------

/// Relations for the sandbox entity.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// A sandbox has many supervisors.
    #[sea_orm(has_many = "super::supervisor::Entity")]
    Supervisor,

    /// A sandbox has many microvms.
    #[sea_orm(has_many = "super::microvm::Entity")]
    Microvm,

    /// A sandbox has many msbnets.
    #[sea_orm(has_many = "super::msbnet::Entity")]
    Msbnet,

    /// A sandbox has many metrics.
    #[sea_orm(has_many = "super::sandbox_metric::Entity")]
    SandboxMetric,

    /// A sandbox has many snapshots.
    #[sea_orm(has_many = "super::snapshot::Entity")]
    Snapshot,
}

impl Related<super::supervisor::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Supervisor.def()
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

impl Related<super::sandbox_metric::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SandboxMetric.def()
    }
}

impl Related<super::snapshot::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Snapshot.def()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl ActiveModelBehavior for ActiveModel {}
