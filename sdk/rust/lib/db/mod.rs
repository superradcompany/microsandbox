//! Database entity + handle re-exports.
//!
//! The actual [`DbConnection`] instance is owned by [`LocalBackend`](crate::backend::LocalBackend)
//! per D6.7. This module just re-exports the entity types and the database
//! handle so the rest of the crate has one place to import them from.

#[allow(unused_imports)]
pub use microsandbox_db::DbConnection;
pub use microsandbox_db::entity;
