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
    /// Image to pull (e.g. python, ubuntu).
    pub reference: String,

    /// Re-download even if the image is already cached.
    #[arg(short, long)]
    pub force: bool,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,

    /// Connect to the registry over plain HTTP instead of HTTPS.
    #[arg(long)]
    pub insecure: bool,

    /// Path to a PEM file containing additional CA root certificates to trust.
    #[arg(long, value_name = "PATH")]
    pub ca_certs: Option<String>,
}
