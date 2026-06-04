//! RunLoop-compatible local HTTP API for microsandbox.

#![warn(missing_docs)]

pub mod adapter;
pub mod auth;
pub mod dto;
pub mod error;
pub mod ids;
pub mod routes;
pub mod server;
pub mod state;
pub mod store;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub use server::{ServeConfig, ServeHandle, serve};
