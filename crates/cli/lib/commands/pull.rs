//! `msb pull` argument definitions.
//!
//! The pull logic lives in [`super::image::run_pull`]; this module only
//! defines the shared [`PullArgs`] struct.

use clap::{Args, ValueEnum};

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

    /// Rootfs artifacts to prepare in addition to downloaded OCI content.
    ///
    /// When omitted, a configured flat OCI root-disk default selects flat materialization;
    /// otherwise the layered representation is prepared.
    #[arg(long, value_enum)]
    pub materialize: Option<PullMaterialization>,
}

/// Rootfs representation prepared by `msb pull`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum PullMaterialization {
    /// Prepare the existing stitched layered rootfs.
    #[default]
    Layered,
    /// Also prepare one reusable flat ext4 rootfs.
    Flat,
    /// Prepare both layered and flat rootfs artifacts.
    All,
}

impl PullMaterialization {
    pub(super) fn includes_flat(self) -> bool {
        matches!(self, Self::Flat | Self::All)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        pull: PullArgs,
    }

    #[test]
    fn materialization_mode_distinguishes_omitted_and_explicit_flat() {
        let default = TestCli::try_parse_from(["test", "alpine"]).unwrap();
        assert_eq!(default.pull.materialize, None);

        let flat = TestCli::try_parse_from(["test", "alpine", "--materialize", "flat"]).unwrap();
        assert_eq!(flat.pull.materialize, Some(PullMaterialization::Flat));
        assert!(flat.pull.materialize.unwrap().includes_flat());
    }
}
