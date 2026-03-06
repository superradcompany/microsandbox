//! `microsandbox` is the core library for the microsandbox project.

#![warn(missing_docs)]
#![allow(clippy::module_inception)]

mod error;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

#[allow(dead_code)]
pub(crate) mod db;
pub mod agent;
pub mod config;
pub mod runtime;
pub mod sandbox;
pub mod setup;

pub use error::*;
