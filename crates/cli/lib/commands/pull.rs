//! `msb pull` argument definitions.
//!
//! The pull logic lives in [`super::image::run_pull`]; this module only
//! defines the shared [`PullArgs`] struct.

use clap::Args;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Pull an image from a registry.
#[derive(Debug, Args)]
pub struct PullArgs {
    /// Image reference (e.g., python:3.11, ubuntu:22.04).
    pub reference: String,

    /// Force re-download and re-extract even if cached.
    #[arg(short, long)]
    pub force: bool,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,
}
