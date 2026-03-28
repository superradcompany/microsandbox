//! `msb pull` argument definitions.
//!
//! The pull logic lives in [`super::image::run_pull`]; this module only
//! defines the shared [`PullArgs`] struct.

use clap::Args;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Download an image from a container registry.
#[derive(Debug, Args)]
pub struct PullArgs {
    /// Image to pull (e.g. python:3.12, ubuntu:22.04).
    pub reference: String,

    /// Re-download even if the image is already cached.
    #[arg(short, long)]
    pub force: bool,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,
}
