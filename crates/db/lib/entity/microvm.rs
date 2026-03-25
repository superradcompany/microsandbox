//! Entity definition for the `microvms` table.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The status of a microVM process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum MicrovmStatus {
    /// The microVM is running.
    #[sea_orm(string_value = "Running")]
    Running,

    /// The microVM has terminated.
    #[sea_orm(string_value = "Terminated")]
    Terminated,
}

/// The reason a sandbox's microVM terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum TerminationReason {
    /// VM exited with code 0 (guest shutdown cleanly).
    #[sea_orm(string_value = "VmCompleted")]
    VmCompleted,

    /// VM exited with non-zero code or was killed by signal.
    #[sea_orm(string_value = "VmFailed")]
    VmFailed,

    /// Sandbox exceeded `max_duration_secs`.
    #[sea_orm(string_value = "MaxDurationExceeded")]
    MaxDurationExceeded,

    /// agentd reported no activity for `idle_timeout_secs`.
    #[sea_orm(string_value = "IdleTimeout")]
    IdleTimeout,

    /// SIGUSR1 received (explicit drain request).
    #[sea_orm(string_value = "DrainRequested")]
    DrainRequested,

    /// SIGTERM/SIGINT received from external source.
    #[sea_orm(string_value = "SupervisorSignal")]
    SupervisorSignal,

    /// Supervisor internal error.
    #[sea_orm(string_value = "InternalError")]
    InternalError,
}

/// The microVM process entity model.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "microvm")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub sandbox_id: i32,
    pub supervisor_id: i32,
    pub pid: Option<i32>,
    pub status: MicrovmStatus,
    pub exit_code: Option<i32>,
    pub exit_signal: Option<i32>,
    pub termination_reason: Option<TerminationReason>,
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

impl std::fmt::Display for TerminationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VmCompleted => f.write_str("VmCompleted"),
            Self::VmFailed => f.write_str("VmFailed"),
            Self::MaxDurationExceeded => f.write_str("MaxDurationExceeded"),
            Self::IdleTimeout => f.write_str("IdleTimeout"),
            Self::DrainRequested => f.write_str("DrainRequested"),
            Self::SupervisorSignal => f.write_str("SupervisorSignal"),
            Self::InternalError => f.write_str("InternalError"),
        }
    }
}

impl ActiveModelBehavior for ActiveModel {}
