//! Entity definition for the `run` table.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The status of a sandbox run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum RunStatus {
    /// The sandbox is running.
    #[sea_orm(string_value = "Running")]
    Running,

    /// The run has terminated.
    #[sea_orm(string_value = "Terminated")]
    Terminated,
}

/// The reason a sandbox run terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum TerminationReason {
    /// Sandbox exited cleanly (exit code 0).
    #[sea_orm(string_value = "Completed")]
    Completed,

    /// Sandbox exited with non-zero code or was killed by signal.
    #[sea_orm(string_value = "Failed")]
    Failed,

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
    #[sea_orm(string_value = "Signal")]
    Signal,

    /// Internal error.
    #[sea_orm(string_value = "InternalError")]
    InternalError,
}

/// A single run of a sandbox.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "run")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub sandbox_id: i32,
    pub pid: Option<i32>,
    pub status: RunStatus,
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

/// Relations for the run entity.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// A run belongs to a sandbox.
    #[sea_orm(
        belongs_to = "super::sandbox::Entity",
        from = "Column::SandboxId",
        to = "super::sandbox::Column::Id",
        on_delete = "Cascade"
    )]
    Sandbox,
}

impl Related<super::sandbox::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sandbox.def()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Display for TerminationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Completed => f.write_str("Completed"),
            Self::Failed => f.write_str("Failed"),
            Self::MaxDurationExceeded => f.write_str("MaxDurationExceeded"),
            Self::IdleTimeout => f.write_str("IdleTimeout"),
            Self::DrainRequested => f.write_str("DrainRequested"),
            Self::Signal => f.write_str("Signal"),
            Self::InternalError => f.write_str("InternalError"),
        }
    }
}

impl ActiveModelBehavior for ActiveModel {}
