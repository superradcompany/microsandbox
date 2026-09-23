//! Explicit external-bind checkpoint semantics.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Destination policy for a user-owned external filesystem checkpoint.
#[derive(Clone, Debug, Default)]
pub struct ExternalCheckpointOptions {
    /// Preserve unreconstructable object IDs as permanently stale entries.
    pub relaxed: bool,
    /// The caller explicitly supplied a different backing tree. Match referenced content
    /// and object types rather than requiring source-local host inode numbers.
    pub remapped: bool,
    /// Destination-only report populated when validated backend state is installed.
    pub invalid_inodes: Arc<Mutex<Vec<u64>>>,
}

/// Validated private state exposed to the isolated single-file facade.
pub(crate) struct ExternalSingleFileIndex {
    pub inodes: BTreeSet<u64>,
    pub files: BTreeMap<u64, u64>,
    pub invalid_inodes: BTreeSet<u64>,
}
