//! Catalog configuration access, writes, and database type re-exports.
//!
//! The actual `DbPools` instance is owned by [`LocalBackend`](crate::backend::LocalBackend)
//! per D6.7. Catalog migrations normalize saved configurations before use.

// Historical codecs are used at conversion boundaries, not normal application reads.
#[cfg(feature = "local")]
pub(crate) mod admission;
pub(crate) mod config;
#[cfg(feature = "local")]
pub(crate) mod historical;
pub(crate) mod json;
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
