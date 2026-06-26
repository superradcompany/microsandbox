//! Database entity + pool type re-exports.
//!
//! The actual `DbPools` instance is owned by [`LocalBackend`](crate::backend::LocalBackend)
//! per D6.7. This module just re-exports the entity types and pool aliases so
//! the rest of the crate has one place to import them from.

pub use microsandbox_db::entity;
#[allow(unused_imports)]
pub use microsandbox_db::pool::DbPools;
#[allow(unused_imports)]
pub use microsandbox_db::{DbReadConnection, DbWriteConnection};
