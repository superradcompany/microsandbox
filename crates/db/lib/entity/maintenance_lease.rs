//! Entity definition for the `maintenance_lease` table.
//!
//! A single-row coordination primitive used by host-runtime sandbox
//! lifecycle maintenance. Each `msb sandbox` process performs a cheap
//! read-gated lease attempt on startup; only the runtime that wins the
//! lease runs the bounded maintenance sweep, so a burst of sandbox starts
//! does not turn into N concurrent full scans.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Primary-key value of the single lifecycle-maintenance lease row.
pub const SANDBOX_LIFECYCLE_MAINTENANCE: &str = "sandbox_lifecycle_maintenance";

/// Primary-key value of the install-exclusive lease row.
pub const INSTALL_EXCLUSIVE: &str = "install_exclusive";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The maintenance-lease entity model.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "maintenance_lease")]
pub struct Model {
    /// Lease name. Acts as the primary key; there is one row per kind of
    /// maintenance work (for example [`SANDBOX_LIFECYCLE_MAINTENANCE`] or
    /// [`INSTALL_EXCLUSIVE`]).
    #[sea_orm(primary_key, auto_increment = false)]
    pub name: String,

    /// PID of the runtime that currently holds the lease, for diagnostics.
    pub holder_pid: Option<i32>,

    /// When the current lease expires. A runtime may claim the lease once
    /// this time has passed, even if the prior holder never released it.
    pub lease_expires_at: DateTime,

    /// When maintenance last completed successfully. Used to read-gate the
    /// lease so runtimes skip the write entirely between sweep windows.
    pub last_completed_at: Option<DateTime>,
}

//--------------------------------------------------------------------------------------------------
// Types: Relations
//--------------------------------------------------------------------------------------------------

/// Relations for the maintenance-lease entity (none).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl ActiveModelBehavior for ActiveModel {}
