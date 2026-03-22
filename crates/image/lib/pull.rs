//! Pull options, policy, and result types.

use std::path::PathBuf;

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
#[derive(Debug, Clone)]
pub struct PullOptions {
    /// Controls when the registry is contacted.
    pub pull_policy: PullPolicy,

    /// Re-download and re-extract even if all layers are already cached.
    pub force: bool,

    /// Generate binary sidecar indexes after extraction.
    pub build_index: bool,
}

/// Result of a successful image pull.
pub struct PullResult {
    /// Extracted layer directories in bottom-to-top order.
    pub layers: Vec<PathBuf>,

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

impl Default for PullOptions {
    fn default() -> Self {
        Self {
            pull_policy: PullPolicy::default(),
            force: false,
            build_index: true,
        }
    }
}
