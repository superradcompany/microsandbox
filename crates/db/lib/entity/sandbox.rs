//! Entity definition for the `sandboxes` table.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The status of a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum SandboxStatus {
    /// The sandbox has been created but not yet started.
    ///
    /// Cloud-only today: msb-cloud's create-without-start state. Local
    /// sandboxes transition straight to `Running` after create.
    #[sea_orm(string_value = "Created")]
    Created,

    /// A start request has been submitted but the sandbox is not yet running.
    ///
    /// Cloud-only today: covers the gap between accepting a start request
    /// and the runtime reporting the VM as live.
    #[sea_orm(string_value = "Starting")]
    Starting,

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
    /// Desired sandbox configuration used for the next start.
    pub config: String,
    /// Configuration actually used by the currently running VM, when active.
    pub active_config: Option<String>,
    pub status: SandboxStatus,
    /// Denormalized copy of `config.policy.ephemeral`.
    ///
    /// Indexed alongside `status` so host-runtime lifecycle maintenance can
    /// find terminal ephemeral cleanup candidates without scanning and
    /// parsing every stopped sandbox's serialized config.
    pub ephemeral: bool,
    pub created_at: Option<DateTime>,
    pub updated_at: Option<DateTime>,
}

//--------------------------------------------------------------------------------------------------
// Types: Relations
//--------------------------------------------------------------------------------------------------

/// Relations for the sandbox entity.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// A sandbox has many runs.
    #[sea_orm(has_many = "super::run::Entity")]
    Run,
}

impl Related<super::run::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Run.def()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl ActiveModelBehavior for ActiveModel {}
