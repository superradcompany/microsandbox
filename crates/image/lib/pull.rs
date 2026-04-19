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

/// Options for [`Registry::pull()`](crate::Registry::pull).
#[derive(Debug, Clone, Default)]
pub struct PullOptions {
    /// Controls when the registry is contacted.
    pub pull_policy: PullPolicy,

    /// Re-download blobs and re-materialize rootfs images even if cached.
    pub force: bool,
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
// Trait Implementations
//--------------------------------------------------------------------------------------------------
