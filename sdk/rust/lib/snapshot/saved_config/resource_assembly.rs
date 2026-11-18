//! Compose requested destination resources without claiming guest-confirmed application.

use std::fmt;

use microsandbox_types::snapshot::saved_config::{SavedResourcesConfig, SavedValue};
use microsandbox_types::{SandboxResources, SandboxResourcesPatch};

use super::{
    ResourceDefaultClear, ResourceDefaultSelection, ResourceRestoreMode, SnapshotConfigMode,
    select_resource_defaults,
};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Known launch dimensions plus retained source observations. Host capacity, mandatory
/// destination constraints and full-state guest policy remain separate admission checks.
pub struct ResourceConfigurationPlan {
    resources: SandboxResources,
    selection: ResourceDefaultSelection,
    requires_full_compatibility: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ResourceConfigurationPlan {
    /// Inspect unavailable observations without rewriting them as requested allocations.
    pub fn selection(&self) -> &ResourceDefaultSelection {
        &self.selection
    }

    /// Full resume still requires captured THP/guest-policy, backing and host compatibility.
    pub fn requires_full_compatibility(&self) -> bool {
        self.requires_full_compatibility
    }

    /// Return known requested launch settings, not proof that a guest applied them. Unknown
    /// active values need explicit disk-boot resolution; they never borrow a pending target.
    pub fn resources(&self) -> MicrosandboxResult<SandboxResources> {
        if !self.selection.unknown_fields.is_empty() {
            return Err(error(
                "SCFG_UNKNOWN",
                "resource observations need explicit resolution",
            ));
        }
        Ok(self.resources.clone())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for ResourceConfigurationPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceConfigurationPlan")
            .field("selection", &self.selection)
            .field(
                "requires_full_compatibility",
                &self.requires_full_compatibility,
            )
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Compose sparse lower defaults, saved values and explicit destination inputs. Preserve
/// sparse maximum intent: the existing SDK defaults an omitted maximum to the final boot
/// allocation, whereas a configured lower/saved/explicit maximum is a real ceiling.
pub fn prepare_resource_configuration(
    saved: &SavedResourcesConfig,
    lower: &SandboxResourcesPatch,
    explicit: &SandboxResourcesPatch,
    clears: &[ResourceDefaultClear],
    mode: SnapshotConfigMode,
    restore_mode: ResourceRestoreMode<'_>,
) -> MicrosandboxResult<ResourceConfigurationPlan> {
    let selection = select_resource_defaults(saved, explicit, clears, mode, restore_mode)?;
    let builtin = SandboxResources::default();
    let mut resources = builtin.clone();
    lower.clone().apply_to(&mut resources);
    let mut max_cpus = lower.max_cpus;
    let mut max_memory = lower.max_memory_mib;
    for clear in clears {
        match clear {
            ResourceDefaultClear::Cpus => resources.cpus = builtin.cpus,
            ResourceDefaultClear::Memory => resources.memory_mib = builtin.memory_mib,
            ResourceDefaultClear::MaxCpus => max_cpus = None,
            ResourceDefaultClear::MaxMemory => max_memory = None,
            ResourceDefaultClear::Thp => resources.thp = builtin.thp,
        }
    }
    scalar(&selection.defaults.cpus, &mut resources.cpus, builtin.cpus);
    scalar(
        &selection.defaults.memory_mib,
        &mut resources.memory_mib,
        builtin.memory_mib,
    );
    scalar(&selection.defaults.thp, &mut resources.thp, builtin.thp);
    maximum(&selection.defaults.max_cpus, &mut max_cpus);
    maximum(&selection.defaults.max_memory_mib, &mut max_memory);
    if let Some(geometry) = &selection.required_geometry {
        geometry.clone().apply_to(&mut resources);
        max_cpus = geometry.max_cpus;
        max_memory = geometry.max_memory_mib;
    }
    // Host placement comes exclusively from these destination patches. The source's
    // construction record is not copied wholesale, even during full resume.
    explicit.clone().apply_to(&mut resources);
    resources.max_cpus = explicit.max_cpus.or(max_cpus).unwrap_or(resources.cpus);
    resources.max_memory_mib = explicit
        .max_memory_mib
        .or(max_memory)
        .unwrap_or(resources.memory_mib);
    validate_pair(
        &selection,
        "resources.cpus",
        "resources.max_cpus",
        u64::from(resources.cpus),
        u64::from(resources.max_cpus),
    )?;
    validate_pair(
        &selection,
        "resources.memory_mib",
        "resources.max_memory_mib",
        u64::from(resources.memory_mib),
        u64::from(resources.max_memory_mib),
    )?;
    Ok(ResourceConfigurationPlan {
        resources,
        selection,
        requires_full_compatibility: matches!(restore_mode, ResourceRestoreMode::Full(_)),
    })
}

fn scalar<T: Copy>(saved: &Option<SavedValue<T>>, target: &mut T, builtin: T) {
    match saved {
        Some(SavedValue::Value { value, .. }) => *target = *value,
        Some(SavedValue::Default {}) => *target = builtin,
        None | Some(SavedValue::Unknown { .. }) => {} // Unknown is guarded by resources().
    }
}

fn maximum<T: Copy>(saved: &Option<SavedValue<T>>, target: &mut Option<T>) {
    match saved {
        Some(SavedValue::Value { value, .. }) => *target = Some(*value),
        Some(SavedValue::Default {}) => *target = None,
        None | Some(SavedValue::Unknown { .. }) => {}
    }
}

fn validate_pair(
    selection: &ResourceDefaultSelection,
    current_path: &str,
    maximum_path: &str,
    current: u64,
    maximum: u64,
) -> MicrosandboxResult<()> {
    // Do not manufacture a cross-field conflict from placeholder values while observation
    // is unavailable. The plan cannot expose resources until those unknowns are resolved.
    if selection.unknown_fields.contains(current_path)
        || selection.unknown_fields.contains(maximum_path)
    {
        return Ok(());
    }
    if current == 0 || maximum == 0 || current > maximum {
        return Err(error(
            "SCFG_VALUE",
            "selected allocation must be positive and within its maximum",
        ));
    }
    Ok(())
}

fn error(code: &str, message: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!("{code}: resources: {message}"))
}
