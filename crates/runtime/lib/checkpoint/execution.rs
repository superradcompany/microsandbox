//! Restore policy bound to captured execution state.

use microsandbox_image::checkpoint::{ResourceDescriptor, ResourceTreatment};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const NESTED_RESOURCE: &str = "vm:nested-virt";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Read the nesting requirement from a checkpoint's captured resource plan.
/// Ordinary checkpoints omit this resource and retain their existing encoding.
pub fn captured_nested_virt(resources: &[ResourceDescriptor]) -> Result<bool, String> {
    let mut matches = resources
        .iter()
        .filter(|resource| resource.id == NESTED_RESOURCE || resource.kind == "nested-virt");
    let Some(resource) = matches.next() else {
        return Ok(false);
    };
    if matches.next().is_some()
        || resource.id != NESTED_RESOURCE
        || resource.kind != "nested-virt"
        || resource.treatment != ResourceTreatment::Serialize
        || resource.binding.len() != 1
        || resource.binding.get("enabled").map(String::as_str) != Some("true")
    {
        return Err("invalid captured nested virtualization requirement".into());
    }
    Ok(true)
}

#[cfg(feature = "runner")]
pub(crate) fn nested_execution_resource() -> ResourceDescriptor {
    ResourceDescriptor {
        id: NESTED_RESOURCE.into(),
        kind: "nested-virt".into(),
        treatment: ResourceTreatment::Serialize,
        binding: [("enabled".into(), "true".into())].into(),
    }
}
