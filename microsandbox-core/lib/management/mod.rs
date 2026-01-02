//! Management components for the Microsandbox runtime.
//!
//! This module serves as the central management system for Microsandbox, providing
//! functionality for managing sandboxes, images, environments, root filesystems,
//! and databases. It coordinates the various components needed for container
//! and sandbox operations.
//!
//! Key components:
//! - `db`: Database management for storing container and sandbox metadata
//! - `image`: Container image handling and registry operations
//! - `menv`: Microsandbox environment management
//! - `rootfs`: Root filesystem operations for containers
//! - `sandbox`: Sandbox creation and management
//! - `orchestra`: Orchestra management for sandboxes
//! - `home`: Home directory management
//! - `toolchain`: Toolchain management

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod config;
pub mod db;
pub mod home;
pub mod menv;
pub mod orchestra;
pub mod rootfs;
pub mod sandbox;
pub mod toolchain;
