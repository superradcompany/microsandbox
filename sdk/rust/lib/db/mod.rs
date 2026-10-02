//! Shared database type re-exports for the SDK.
//!
//! The actual `DbPools` instance is owned by [`LocalBackend`](crate::backend::LocalBackend)
//! per D6.7. Catalog migrations normalize saved configurations before use.

#[cfg(feature = "local")]
pub use microsandbox_db::entity;
#[cfg(feature = "local")]
#[allow(unused_imports)]
pub use microsandbox_db::pool::DbPools;
#[cfg(feature = "local")]
#[allow(unused_imports)]
pub use microsandbox_db::{DbReadConnection, DbWriteConnection};
