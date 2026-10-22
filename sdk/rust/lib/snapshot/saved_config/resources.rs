//! Select portable resource defaults without substituting them for checkpoint geometry.

use std::collections::BTreeSet;

use microsandbox_types::snapshot::saved_config::{SavedResourcesConfig, SavedValue};
use microsandbox_types::{SandboxResources, SandboxResourcesPatch};

use crate::{MicrosandboxError, MicrosandboxResult};

use super::SnapshotConfigMode;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Geometry comes from the checked execution closure, never the saved-config document.
#[derive(Clone, Copy)]
pub enum ResourceRestoreMode<'a> {
    /// Cold boot may choose a new allocation within destination constraints.
    Disk,
    /// These four construction dimensions have passed the existing checkpoint checks.
    /// Placement and THP in this input are deliberately not copied by this selector.
    Full(&'a SandboxResources),
}

/// Optional disk-boot defaults that may be discarded before destination inputs apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceDefaultClear {
    /// Current CPU allocation.
    Cpus,
    /// Current memory allocation.
    Memory,
    /// CPU hotplug ceiling.
    MaxCpus,
    /// Memory hotplug ceiling.
    MaxMemory,
    /// Guest boot huge-page policy.
    Thp,
}

/// A saved overlay plus mandatory full-resume geometry, not a complete launch config.
#[derive(Debug)]
pub struct ResourceDefaultSelection {
    /// Surviving optional defaults; captured THP remains evidence during full resume.
    pub defaults: SavedResourcesConfig,
    /// Full-resume dimensions to apply after existing equal-geometry admission.
    /// Host placement, source profile names and THP are never populated here.
    pub required_geometry: Option<SandboxResourcesPatch>,
    /// Unknown optional source values still requiring explicit resolution/reporting.
    pub unknown_fields: BTreeSet<&'static str>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve resource precedence and full-state restrictions without host I/O.
///
/// The caller must validate the complete active document first, including observation
/// provenance. Final destination defaults, host capacity and managed policy still need
/// validation after assembly. Pending/construction configuration is not an input.
pub fn select_resource_defaults(
    saved: &SavedResourcesConfig,
    explicit: &SandboxResourcesPatch,
    clears: &[ResourceDefaultClear],
    config_mode: SnapshotConfigMode,
    restore_mode: ResourceRestoreMode<'_>,
) -> MicrosandboxResult<ResourceDefaultSelection> {
    saved
        .validate()
        .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))?;
    if clears.len() > microsandbox_types::snapshot::saved_config::MAX_SAVED_CONFIG_ENTRIES {
        return invalid("SCFG_LIMIT", "too many resource clear selectors");
    }

    if let ResourceRestoreMode::Full(captured) = restore_mode {
        // Fresh mode cannot erase execution geometry, and equal explicit values
        // remain supported exactly as in the existing restore path.
        if !clears.is_empty() || explicit.thp.is_some() {
            return invalid(
                "SCFG_FULL_STATE",
                "resource clears and THP overrides require disk boot",
            );
        }
        validate_pair(
            Some(captured.cpus.into()),
            Some(captured.max_cpus.into()),
            "cpus",
        )?;
        validate_pair(
            Some(captured.memory_mib.into()),
            Some(captured.max_memory_mib.into()),
            "memory_mib",
        )?;
        if explicit.cpus.is_some_and(|value| value != captured.cpus)
            || explicit
                .max_cpus
                .is_some_and(|value| value != captured.max_cpus)
            || explicit
                .memory_mib
                .is_some_and(|value| value != captured.memory_mib)
            || explicit
                .max_memory_mib
                .is_some_and(|value| value != captured.max_memory_mib)
        {
            return invalid(
                "SCFG_FULL_STATE",
                "full resume requires captured CPU and memory geometry",
            );
        }
        let defaults = SavedResourcesConfig {
            thp: saved.thp.clone(),
            ..Default::default()
        };
        let unknown_fields = unknown_fields(&defaults);
        return Ok(ResourceDefaultSelection {
            defaults,
            required_geometry: Some(
                SandboxResourcesPatch::new()
                    .cpus(captured.cpus)
                    .memory_mib(captured.memory_mib)
                    .max_cpus(captured.max_cpus)
                    .max_memory_mib(captured.max_memory_mib),
            ),
            unknown_fields,
        });
    }

    let mut defaults = match config_mode {
        SnapshotConfigMode::Saved => saved.clone(),
        SnapshotConfigMode::Fresh => SavedResourcesConfig::default(),
    };
    for clear in clears {
        match clear {
            ResourceDefaultClear::Cpus => defaults.cpus = None,
            ResourceDefaultClear::Memory => defaults.memory_mib = None,
            ResourceDefaultClear::MaxCpus => defaults.max_cpus = None,
            ResourceDefaultClear::MaxMemory => defaults.max_memory_mib = None,
            ResourceDefaultClear::Thp => defaults.thp = None,
        }
    }

    // Check the combination, not just the two valid inputs independently: an
    // explicit allocation can exceed a retained saved maximum (and vice versa).
    validate_pair(
        explicit
            .cpus
            .or_else(|| concrete(&defaults.cpus))
            .map(u64::from),
        explicit
            .max_cpus
            .or_else(|| concrete(&defaults.max_cpus))
            .map(u64::from),
        "cpus",
    )?;
    validate_pair(
        explicit
            .memory_mib
            .or_else(|| concrete(&defaults.memory_mib))
            .map(u64::from),
        explicit
            .max_memory_mib
            .or_else(|| concrete(&defaults.max_memory_mib))
            .map(u64::from),
        "memory_mib",
    )?;
    if explicit.cpus.is_some() {
        defaults.cpus = None;
    }
    if explicit.memory_mib.is_some() {
        defaults.memory_mib = None;
    }
    if explicit.max_cpus.is_some() {
        defaults.max_cpus = None;
    }
    if explicit.max_memory_mib.is_some() {
        defaults.max_memory_mib = None;
    }
    if explicit.thp.is_some() {
        defaults.thp = None;
    }
    let unknown_fields = unknown_fields(&defaults);
    Ok(ResourceDefaultSelection {
        defaults,
        required_geometry: None,
        unknown_fields,
    })
}

fn concrete<T: Copy>(value: &Option<SavedValue<T>>) -> Option<T> {
    value.as_ref().and_then(SavedValue::value).copied()
}

fn validate_pair(
    current: Option<u64>,
    maximum: Option<u64>,
    field: &str,
) -> MicrosandboxResult<()> {
    if current == Some(0) || maximum == Some(0) {
        return invalid(
            "SCFG_VALUE",
            &format!("{field}: allocation and maximum must be positive"),
        );
    }
    if let (Some(current), Some(maximum)) = (current, maximum)
        && current > maximum
    {
        return invalid(
            "SCFG_VALUE",
            &format!("{field}: allocation exceeds selected maximum"),
        );
    }
    Ok(())
}

fn unknown_fields(saved: &SavedResourcesConfig) -> BTreeSet<&'static str> {
    let SavedResourcesConfig {
        cpus,
        memory_mib,
        max_cpus,
        max_memory_mib,
        thp,
    } = saved;
    [
        (
            "resources.cpus",
            matches!(cpus, Some(SavedValue::Unknown { .. })),
        ),
        (
            "resources.memory_mib",
            matches!(memory_mib, Some(SavedValue::Unknown { .. })),
        ),
        (
            "resources.max_cpus",
            matches!(max_cpus, Some(SavedValue::Unknown { .. })),
        ),
        (
            "resources.max_memory_mib",
            matches!(max_memory_mib, Some(SavedValue::Unknown { .. })),
        ),
        (
            "resources.thp",
            matches!(thp, Some(SavedValue::Unknown { .. })),
        ),
    ]
    .into_iter()
    .filter_map(|(path, unknown)| unknown.then_some(path))
    .collect()
}

fn invalid<T>(code: &str, reason: &str) -> MicrosandboxResult<T> {
    Err(MicrosandboxError::InvalidConfig(format!(
        "{code}: resources: {reason}"
    )))
}
