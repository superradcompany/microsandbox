//! Checked layer selection shared by compaction and dependent archive planning.
//!
//! These plans describe physical layers, not logical snapshot ancestry. Callers resolve and pin
//! the chain before planning and retain that same chain until the operation finishes.

use std::ops::Range;

use thiserror::Error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Invalid physical-layer selection; no disk or archive mutation has occurred.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum LayerSelectionError {
    /// A runtime or checkpoint chain must contain at least one physical layer.
    #[error("a disk chain must contain at least one layer")]
    EmptyChain,
    /// Compaction must combine at least two sealed layers, including the base.
    #[error("compaction requires at least two layers, including the base")]
    TooFewLayersToCompact,
    /// The explicit count includes the unsealed writable head or exceeds the chain.
    #[error("cannot compact {requested} layers: only {sealed} sealed layers are available")]
    CompactionIncludesWritableHead {
        /// Requested oldest-first count, including the base.
        requested: usize,
        /// Number of sealed layers, excluding the writable head.
        sealed: usize,
    },
    /// Explicit suffix selection must include at least one checkpoint layer.
    #[error("cannot export the last {requested} layers of a {available}-layer checkpoint")]
    InvalidExportCount {
        /// Requested newest-first count.
        requested: usize,
        /// Total immutable layers in the checkpoint.
        available: usize,
    },
    /// The supplied baseline is not the exact physical prefix of the target.
    #[error(
        "the export baseline is not an exact physical prefix; export the new base first or save a complete archive"
    )]
    IncompatibleExportBase,
}

/// A prefix of an oldest-first runtime chain to consolidate into one base.
///
/// The last runtime layer is writable even when the sandbox is stopped. It is never selected.
/// A missing count means all sealed layers; fewer than two sealed layers then produces a no-op.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiskCompactionPlan {
    input_layers: usize,
    prefix_layers: usize,
}

/// A contiguous suffix of an immutable checkpoint chain to include in an archive.
///
/// Unlike a runtime chain, every checkpoint layer is sealed. Its newest layer must not be
/// subtracted as though it were the live writable head. Omitted layers are explicit dependencies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiskLayerExportPlan {
    checkpoint_layers: usize,
    required_layers: usize,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DiskCompactionPlan {
    /// Resolve an optional count of oldest layers, including the base but not the writable head.
    pub fn new(runtime_layers: usize, layers: Option<usize>) -> Result<Self, LayerSelectionError> {
        let sealed = runtime_layers
            .checked_sub(1)
            .ok_or(LayerSelectionError::EmptyChain)?;
        let prefix_layers = match layers {
            Some(0 | 1) => return Err(LayerSelectionError::TooFewLayersToCompact),
            Some(requested) if requested > sealed => {
                return Err(LayerSelectionError::CompactionIncludesWritableHead {
                    requested,
                    sealed,
                });
            }
            Some(requested) => requested,
            None if sealed < 2 => 0,
            None => sealed,
        };
        Ok(Self {
            input_layers: runtime_layers,
            prefix_layers,
        })
    }

    /// Selected oldest-first prefix; an empty range means no rewrite is necessary.
    pub fn prefix(&self) -> Range<usize> {
        0..self.prefix_layers
    }

    /// Layers retained after the prefix, including the writable head.
    pub fn retained(&self) -> Range<usize> {
        self.prefix_layers..self.input_layers
    }

    /// Physical layer count after replacing the selected prefix with a single base.
    pub fn output_layers(&self) -> usize {
        if self.prefix_layers == 0 {
            self.input_layers
        } else {
            self.input_layers - self.prefix_layers + 1
        }
    }

    /// Whether this operation would leave the chain unchanged.
    pub fn is_noop(&self) -> bool {
        self.prefix_layers == 0
    }
}

impl DiskLayerExportPlan {
    /// Include every physical layer, with no external disk-layer dependencies.
    pub fn complete(checkpoint_layers: usize) -> Result<Self, LayerSelectionError> {
        if checkpoint_layers == 0 {
            return Err(LayerSelectionError::EmptyChain);
        }
        Ok(Self {
            checkpoint_layers,
            required_layers: 0,
        })
    }

    /// Include the newest `layers` immutable layers; explicitly require the preceding prefix.
    pub fn last(checkpoint_layers: usize, layers: usize) -> Result<Self, LayerSelectionError> {
        let mut plan = Self::complete(checkpoint_layers)?;
        if layers == 0 || layers > checkpoint_layers {
            return Err(LayerSelectionError::InvalidExportCount {
                requested: layers,
                available: checkpoint_layers,
            });
        }
        plan.required_layers = checkpoint_layers - layers;
        Ok(plan)
    }

    /// Require an exact baseline prefix and include only later physical layers.
    ///
    /// Supply comparable identity records containing both layer identity and interpretation
    /// metadata, not just filenames or logical parent IDs. Resolve archive-local backing paths
    /// before comparison. A compacted representation is not interchangeable with its old prefix.
    pub fn since<T: PartialEq>(target: &[T], baseline: &[T]) -> Result<Self, LayerSelectionError> {
        let mut plan = Self::complete(target.len())?;
        if baseline.is_empty() || !target.starts_with(baseline) {
            return Err(LayerSelectionError::IncompatibleExportBase);
        }
        plan.required_layers = baseline.len();
        Ok(plan)
    }

    /// Immutable payload layers to include, in oldest-first order.
    pub fn included(&self) -> Range<usize> {
        self.required_layers..self.checkpoint_layers
    }

    /// Exact omitted prefix that the importer must resolve before publication or restore.
    pub fn required(&self) -> Range<usize> {
        0..self.required_layers
    }

    /// Whether the disk payload can be opened without an externally supplied prefix.
    pub fn is_disk_complete(&self) -> bool {
        self.required_layers == 0
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{DiskCompactionPlan, DiskLayerExportPlan, LayerSelectionError};

    #[test]
    fn compaction_count_includes_base_and_excludes_writable_head() {
        let plan = DiskCompactionPlan::new(5, Some(3)).unwrap();
        assert_eq!(plan.prefix(), 0..3);
        assert_eq!(plan.retained(), 3..5);
        assert_eq!(plan.output_layers(), 3);
        assert!(!plan.is_noop());
    }

    #[test]
    fn default_compacts_all_sealed_layers_only() {
        let plan = DiskCompactionPlan::new(5, None).unwrap();
        assert_eq!(plan.prefix(), 0..4);
        assert_eq!(plan.retained(), 4..5);
        assert_eq!(plan.output_layers(), 2);
    }

    #[test]
    fn insufficient_default_selection_is_a_noop_not_a_conversion() {
        for count in [1, 2] {
            let plan = DiskCompactionPlan::new(count, None).unwrap();
            assert!(plan.is_noop());
            assert_eq!(plan.prefix(), 0..0);
            assert_eq!(plan.retained(), 0..count);
            assert_eq!(plan.output_layers(), count);
        }
    }

    #[test]
    fn explicit_compaction_never_silently_clamps() {
        assert_eq!(
            DiskCompactionPlan::new(0, None),
            Err(LayerSelectionError::EmptyChain)
        );
        for count in [0, 1] {
            assert_eq!(
                DiskCompactionPlan::new(5, Some(count)),
                Err(LayerSelectionError::TooFewLayersToCompact)
            );
        }
        for count in [5, 6, usize::MAX] {
            assert_eq!(
                DiskCompactionPlan::new(5, Some(count)),
                Err(LayerSelectionError::CompactionIncludesWritableHead {
                    requested: count,
                    sealed: 4
                })
            );
        }
    }

    #[test]
    fn export_includes_the_checkpoint_top_layer() {
        let plan = DiskLayerExportPlan::last(5, 2).unwrap();
        assert_eq!(plan.included(), 3..5);
        assert_eq!(plan.required(), 0..3);
        assert!(!plan.is_disk_complete());
    }

    #[test]
    fn exporting_all_layers_is_disk_complete() {
        let plan = DiskLayerExportPlan::last(5, 5).unwrap();
        assert_eq!(plan, DiskLayerExportPlan::complete(5).unwrap());
        assert_eq!(plan.required(), 0..0);
        assert!(plan.is_disk_complete());
    }

    #[test]
    fn export_rejects_empty_and_out_of_range_counts() {
        assert_eq!(
            DiskLayerExportPlan::complete(0),
            Err(LayerSelectionError::EmptyChain)
        );
        for count in [0, 6, usize::MAX] {
            assert!(DiskLayerExportPlan::last(5, count).is_err());
        }
    }

    #[test]
    fn since_requires_the_exact_physical_prefix() {
        let target = [("base", "raw"), ("a", "qcow2"), ("b", "qcow2")];
        let plan = DiskLayerExportPlan::since(&target, &target[..2]).unwrap();
        assert_eq!(plan.required(), 0..2);
        assert_eq!(plan.included(), 2..3);
        for invalid in [
            vec![],
            vec![("compacted", "raw")],
            vec![("base", "qcow2")],
            vec![("a", "qcow2")],
        ] {
            assert_eq!(
                DiskLayerExportPlan::since(&target, &invalid),
                Err(LayerSelectionError::IncompatibleExportBase)
            );
        }
        assert!(DiskLayerExportPlan::since(&target[..1], &target).is_err());
    }

    #[test]
    fn equal_disk_prefix_can_omit_all_disk_bytes_without_omitting_vm_state() {
        // This only plans disk payload. The exporter must still include the target descriptor
        // and all required memory/execution objects, even when the disk has not changed.
        let target = ["base", "a"];
        let plan = DiskLayerExportPlan::since(&target, &target).unwrap();
        assert_eq!(plan.included(), 2..2);
        assert_eq!(plan.required(), 0..2);
        assert!(!plan.is_disk_complete());
    }
}
