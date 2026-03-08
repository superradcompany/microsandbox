//! Shared infrastructure for filesystem backends.
//!
//! Contains data structures and utilities used by both [`PassthroughFs`](super::passthrough)
//! and the future `OverlayFs`.

pub(crate) mod handle_table;
pub(crate) mod init_binary;
pub(crate) mod inode_table;
pub(crate) mod name_validation;
pub(crate) mod platform;
pub(crate) mod stat_override;
