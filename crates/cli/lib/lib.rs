//! `microsandbox-cli` provides the `msb` CLI binary for managing microsandbox
//! environments. Includes hidden runtime subcommands (`supervisor`, `microvm`)
//! used internally by the `microsandbox` library.

#![warn(missing_docs)]

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod microvm_cmd;
pub mod styles;
pub mod supervisor_cmd;
