//! Shared database entity definitions and connection helpers for the
//! microsandbox project.
//!
//! Used by both `microsandbox` (host CLI) and `microsandbox-runtime`
//! (in-VM supervisor). They share the same SQLite file, so the connection
//! builder lives here to keep PRAGMAs in one place.

#![warn(missing_docs)]

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod connection;
#[allow(missing_docs)]
pub mod entity;
pub mod pool;
mod remote;
pub mod retry;
pub mod stats;

pub use connection::{DbReadConnection, DbWriteConnection};
pub use stats::{DbStats, DbStatsSnapshot};
