//! Pull options, policy, and result types.

use serde::{Deserialize, Serialize};

use crate::{config::ImageConfig, digest::Digest};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Controls when the registry is contacted for manifest freshness.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PullPolicy {
    /// Use cached layers if complete, pull otherwise.
    #[default]
    IfMissing,

    /// Always fetch manifest from registry, even if cached.
    /// Reuses cached layers whose digests still match.
    Always,

    /// Never contact registry. Error if image not fully cached locally.
    Never,
}

/// Filesystem representations produced by an image pull.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RootfsMaterialization {
    /// Produce the stitched EROFS, fsmeta and VMDK representation.
    #[default]
    Layered,

    /// Produce a reusable flat ext4 rootfs without layered-only artifacts.
    Flat,

    /// Produce both layered and flat rootfs representations from one layer stage.
    All,
}

/// Options for [`Registry::pull()`](crate::Registry::pull).
#[derive(Debug, Clone, Default)]
pub struct PullOptions {
    /// Controls when the registry is contacted.
    pub pull_policy: PullPolicy,

    /// Re-download blobs and re-materialize rootfs images even if cached.
    pub force: bool,

    /// Filesystem representations to prepare. Defaults to [`RootfsMaterialization::Layered`].
    pub materialization: RootfsMaterialization,
}

/// Result of a successful image pull.
pub struct PullResult {
    /// Layer diff_ids in bottom-to-top order.
    pub layer_diff_ids: Vec<Digest>,

    /// Parsed OCI image configuration.
    pub config: ImageConfig,

    /// Content-addressable digest of the resolved manifest.
    pub manifest_digest: Digest,

    /// True if all layers were already cached and no downloads occurred.
    pub cached: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RootfsMaterialization {
    /// Whether the pull must produce the stitched layered representation.
    pub const fn includes_layered(self) -> bool {
        matches!(self, Self::Layered | Self::All)
    }

    /// Whether the pull must produce a flat ext4 representation.
    pub const fn includes_flat(self) -> bool {
        matches!(self, Self::Flat | Self::All)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------
