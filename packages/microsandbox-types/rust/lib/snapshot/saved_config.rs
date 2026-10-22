//! Strict, portable saved-configuration values, separate from host launch configuration.
//!
//! This module does not advertise the extension as supported. A reader may only do so
//! once capture, restore, and deferred command binding enforcement are implemented.

mod bindings;
mod capture_controls;
mod document;
mod execution;
mod gateway_capture;
mod inventory;
mod network;
mod network_capture;
mod network_validation;
mod resources;
mod runtime;
mod runtime_capture;
mod script_backing;
mod storage;
mod storage_capture;
mod storage_validation;
mod validation;
mod value;

#[cfg(test)]
mod capture_controls_tests;
#[cfg(test)]
mod document_tests;
#[cfg(test)]
mod gateway_capture_tests;
#[cfg(test)]
mod network_tests;
#[cfg(test)]
mod pending_tests;
#[cfg(test)]
mod runtime_capture_tests;
#[cfg(test)]
mod storage_tests;
#[cfg(test)]
mod tests;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use bindings::{RuntimeBindingConsumer, RuntimeBindingRequirements};
pub use capture_controls::{
    RuntimeCaptureAction, RuntimeCaptureTarget, apply_runtime_capture_controls,
};
pub use document::{
    SAVED_CONFIG_SCHEMA_VERSION, SavedActiveConfig, SavedCaptureProvenance, SavedSandboxConfig,
};
pub use execution::{SavedExecutionConfig, SavedLifetimePolicy, SavedRlimit, SavedU64};
pub use gateway_capture::SavedTlsCaptureBindings;
pub use inventory::{
    SavedBindingConsumer, SavedBindingKind, SavedBindingUse, SavedBindingUses,
    collect_binding_uses, validate_binding_inventory,
};
pub use network::*;
pub use resources::SavedResourcesConfig;
pub use runtime::{SavedHostname, SavedInit, SavedInitSelection, SavedRuntimeConfig, SavedScript};
pub use runtime_capture::{
    RuntimeCaptureInit, RuntimeCaptureInput, RuntimeCaptureProjection, RuntimeCaptureScript,
    RuntimeCaptureText, project_runtime_capture,
};
pub use script_backing::{SavedScriptBacking, SavedScriptMetadata};
pub use storage::{
    SavedBindRootKind, SavedMount, SavedMountOptions, SavedNamedStorage, SavedStorageConfig,
    SavedVsockRoute,
};
pub use storage_capture::SavedExternalMountCapture;
pub use value::{SavedOrigin, SavedText, SavedUnknownReason, SavedValue};

pub use validation::MAX_TEXT_BYTES as MAX_SAVED_TEXT_BYTES;
pub use validation::{
    MAX_SAVED_CONFIG_BYTES, MAX_SAVED_CONFIG_ENTRIES, MAX_SAVED_SCRIPT_BYTES,
    MAX_SAVED_SCRIPTS_BYTES,
};
