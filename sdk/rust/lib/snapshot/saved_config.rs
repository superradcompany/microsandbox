//! Internal saved-default resolution, separate from portable metadata and VM activation.
//!
//! No launch path calls this module until complete policy and deferred-exec enforcement land.

#[cfg(feature = "local")]
mod capture;
#[cfg(all(test, feature = "local"))]
mod capture_tests;
mod configuration;
#[cfg(test)]
mod configuration_tests;
mod demand;
#[cfg(test)]
mod demand_tests;
mod destination_bindings;
#[cfg(test)]
mod destination_input_tests;
mod destination_inputs;
mod execution;
mod execution_assembly;
#[cfg(test)]
mod execution_assembly_tests;
#[cfg(test)]
mod execution_tests;
#[cfg(test)]
mod gateway_input_tests;
mod gateway_inputs;
mod gateway_preparation;
#[cfg(test)]
mod gateway_preparation_tests;
#[cfg(test)]
mod listener_tests;
mod listeners;
mod network_assembly;
#[cfg(test)]
mod network_assembly_tests;
#[cfg(feature = "local")]
mod network_capture;
#[cfg(feature = "local")]
mod network_capture_presence;
#[cfg(all(test, feature = "local"))]
mod network_capture_tests;
mod network_inputs;
mod network_policy;
#[cfg(test)]
mod network_policy_tests;
#[cfg(feature = "local")]
mod network_requirements;
#[cfg(all(test, feature = "local"))]
mod pending_capture_tests;
#[cfg(feature = "local")]
mod policy_capture;
#[cfg(all(test, feature = "local"))]
mod policy_capture_tests;
mod resource_assembly;
#[cfg(test)]
mod resource_assembly_tests;
#[cfg(test)]
mod resource_tests;
mod resources;
mod runtime;
mod runtime_assembly;
#[cfg(test)]
mod runtime_assembly_tests;
#[cfg(feature = "local")]
mod runtime_capture;
#[cfg(all(test, feature = "local"))]
mod runtime_capture_tests;
#[cfg(test)]
mod runtime_input_tests;
mod runtime_inputs;
#[cfg(all(feature = "local", unix))]
mod script_backing;
#[cfg(all(test, feature = "local", unix))]
mod script_backing_tests;
mod secret_preparation;
#[cfg(test)]
mod secret_preparation_tests;
#[cfg(test)]
mod secret_tests;
mod secrets;
mod storage;
#[cfg(feature = "local")]
mod storage_capture;
#[cfg(all(test, feature = "local"))]
mod storage_capture_tests;
mod storage_preparation;
#[cfg(test)]
mod storage_preparation_tests;
#[cfg(test)]
mod storage_tests;
#[cfg(test)]
mod tests;
mod types;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "local")]
pub use capture::{CaptureDocumentRequest, PendingCaptureSource};
pub use configuration::{
    SavedConfigurationClears, SavedConfigurationContext, SavedConfigurationPlan,
    SavedConfigurationRequest, prepare_saved_configuration,
};
pub use demand::{
    BindingDemand, BindingDemandContext, BindingDemandPlan, BindingSupplyGaps, plan_binding_demand,
};
pub use destination_bindings::ConfigurationBindingInput;
pub use destination_inputs::SavedDestinationInputs;
pub use execution::{
    DestinationGuestSecurity, ExecutionDefaultClear, ExecutionDefaultSelection,
    ExecutionRestoreMode, LifetimeDefaultSelection, select_execution_defaults,
};
pub use execution_assembly::{ExecutionConfigurationPlan, prepare_execution_configuration};
pub use gateway_inputs::{GatewayInputPlan, select_gateway_inputs};
pub use gateway_preparation::{
    GatewayBindingInput, GatewayConfigurationPlan, prepare_gateway_configuration,
};
pub use listeners::{
    ListenerBindingInput, ListenerConfigurationPlan, ListenerInputPlan, ListenerInputSelection,
    prepare_listener_configuration, select_listener_inputs,
};
pub use network_assembly::{NetworkPolicyConfigurationPlan, prepare_network_policy_configuration};
#[cfg(feature = "local")]
pub use network_capture::{NetworkCaptureBindings, NetworkCaptureControls, ProxyCaptureBindings};
pub use network_policy::{
    DestinationNetworkBaseline, NetworkPolicyApproval, NetworkPolicyClear, NetworkPolicySelection,
    select_network_policy_defaults,
};
#[cfg(feature = "local")]
pub(crate) use network_requirements::NetworkCaptureSection;
#[cfg(feature = "local")]
pub use policy_capture::{ExecutionCaptureControls, ResourceCaptureObservation};
pub use resource_assembly::{ResourceConfigurationPlan, prepare_resource_configuration};
pub use resources::{
    ResourceDefaultClear, ResourceDefaultSelection, ResourceRestoreMode, select_resource_defaults,
};
pub use runtime::select_runtime_defaults;
pub use runtime_assembly::{
    PreparedCommandDefaults, RuntimeConfigurationPlan, prepare_runtime_configuration,
};
#[cfg(feature = "local")]
pub use runtime_capture::RuntimeCaptureSource;
pub use runtime_inputs::{
    PreparedRuntimeInit, PreparedRuntimeScript, PreparedRuntimeValue, RuntimeBindingInput,
    RuntimeInputPlan, prepare_runtime_inputs,
};
#[cfg(all(feature = "local", unix))]
pub use script_backing::capture_runtime_scripts;
pub use secret_preparation::{
    SecretBindingInput, SecretConfigurationPlan, prepare_secret_configuration,
};
pub use secrets::{SecretInputPlan, SecretInputSelection, select_secret_inputs};
pub use storage::{
    MountInputSelection, StorageApprovalRequirement, StorageInputSelection, StorageRelaxation,
    VsockInputSelection, select_storage_inputs,
};
#[cfg(feature = "local")]
pub use storage_capture::StorageCaptureBindings;
pub use storage_preparation::{
    StorageBindingInput, StorageConfigurationPlan, prepare_storage_configuration,
};
pub use types::{
    RuntimeDefaultClear, RuntimeDefaultSelection, RuntimeSelectionContext, SnapshotConfigMode,
};
