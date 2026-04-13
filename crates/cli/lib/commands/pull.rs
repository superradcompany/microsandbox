//! `msb pull` argument definitions.
//!
//! The pull logic lives in [`super::image::run_pull`]; this module only
//! defines the shared [`PullArgs`] struct.

use clap::{Args, ValueEnum};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Rootfs materialization mode for `msb pull`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum PullLayerMode {
    /// Materialize one EROFS image per OCI layer.
    Layered,
    /// Materialize one merged EROFS image per manifest.
    Flat,
}

/// Download an image from a container registry.
#[derive(Debug, Args)]
pub struct PullArgs {
    /// Image to pull (e.g. python, ubuntu).
    pub reference: String,

    /// Re-download even if the image is already cached.
    #[arg(short, long)]
    pub force: bool,

    /// Rootfs materialization mode.
    #[arg(long, value_enum, default_value_t = PullLayerMode::Layered)]
    pub layer_mode: PullLayerMode,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<PullLayerMode> for microsandbox_image::LayerMode {
    fn from(value: PullLayerMode) -> Self {
        match value {
            PullLayerMode::Layered => Self::Layered,
            PullLayerMode::Flat => Self::Flat,
        }
    }
}
