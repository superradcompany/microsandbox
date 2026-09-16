//! Database entity + pool type re-exports.
//!
//! The actual `DbPools` instance is owned by [`LocalBackend`](crate::backend::LocalBackend)
//! per D6.7. This module just re-exports the entity types and pool aliases so
//! the rest of the crate has one place to import them from.

// Configuration decoding is pure JSON and is also used by backend-neutral
// handles. Only catalog access and writes require the local backend feature.
#[cfg(feature = "local")]
pub(crate) mod admission;
pub(crate) mod config;
#[cfg(feature = "local")]
pub(crate) mod encoding;
mod json;
#[cfg(feature = "local")]
pub(crate) mod writing;

#[cfg(feature = "local")]
pub use microsandbox_db::entity;
#[cfg(feature = "local")]
#[allow(unused_imports)]
pub use microsandbox_db::pool::DbPools;
#[cfg(feature = "local")]
#[allow(unused_imports)]
pub use microsandbox_db::{DbReadConnection, DbWriteConnection};
