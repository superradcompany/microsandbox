//! Shared task and wire contract types for microsandbox.

#![warn(missing_docs)]

mod cloud;
mod error;
#[cfg(feature = "ts")]
pub mod typescript;
mod validation;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub use cloud::{
    CloudCreateSandboxRequest, CloudErrorBody, CloudErrorDetails, CloudMessageResponse,
    CloudPaginated, CloudSandbox, CloudSandboxStatus,
};
pub use error::{TypesError, TypesResult};
pub use validation::{
    MAX_HOSTNAME_BYTES, MAX_SANDBOX_NAME_BYTES, hostname_from_sandbox_name, validate_hostname,
    validate_sandbox_name,
};
