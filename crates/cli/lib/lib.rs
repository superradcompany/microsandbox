//! `microsandbox-cli` provides the `msb` CLI binary for managing microsandbox
//! environments.

#![warn(missing_docs)]

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod boot_error_render;
pub mod commands;
pub mod exec_error_render;
pub mod log_args;
#[cfg(feature = "net")]
pub mod net_rule;
pub mod sandbox_cmd;
pub mod styles;
pub mod tree;
pub mod ui;
