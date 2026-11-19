//! Progress contract for the existing launcher-to-runtime startup channel.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Current startup work. Percentages apply only to bounded materialization work.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupPhase {
    /// Resolving a snapshot, preparing artifacts, or loading eager guest RAM.
    PreparingSnapshot,
    /// Another process owns construction of this RAM cache entry.
    WaitingForMemoryBacking,
    /// Verifying objects and writing their required RAM slices.
    PreparingMemoryBacking,
    /// A completed immutable backing can be reused without materialization.
    ReusingMemoryBacking,
    /// Persisting the prepared backing before making it reusable.
    SyncingMemoryBacking,
    /// Preparation is complete; the bounded VM activation phase has begun.
    Activating,
}

/// A cumulative startup progress update, never an assertion of successful creation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartupProgress {
    /// Phase currently executing.
    pub phase: StartupPhase,
    /// RAM bytes whose required slices have been verified and written in this phase.
    /// This excludes untouched zero reservations and does not count verification twice.
    pub completed_bytes: u64,
    /// Required RAM bytes to materialize, when measurable; not configured RAM capacity.
    pub total_bytes: Option<u64>,
}

/// Non-blocking observer supplied by the startup-channel owner.
pub type StartupProgressCallback = Arc<dyn Fn(StartupProgress) + Send + Sync>;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl StartupProgress {
    /// Report an unmeasured phase such as lock waiting or file synchronization.
    pub fn phase(phase: StartupPhase) -> Self {
        Self {
            phase,
            completed_bytes: 0,
            total_bytes: None,
        }
    }
}

impl StartupPhase {
    /// Stable phase name shared with the language SDKs and startup wire contract.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreparingSnapshot => "preparing_snapshot",
            Self::WaitingForMemoryBacking => "waiting_for_memory_backing",
            Self::PreparingMemoryBacking => "preparing_memory_backing",
            Self::ReusingMemoryBacking => "reusing_memory_backing",
            Self::SyncingMemoryBacking => "syncing_memory_backing",
            Self::Activating => "activating",
        }
    }
}
