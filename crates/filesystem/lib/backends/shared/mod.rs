//! Shared infrastructure for filesystem backends.
//!
//! Contains data structures and utilities shared by the filesystem backends.

pub(crate) mod dir_snapshot;
pub(crate) mod handle_table;
pub(crate) mod init_binary;
pub(crate) mod inode_table;
pub(crate) mod name_validation;
pub(crate) mod platform;
pub(crate) mod stat_override;
