//! Public URLs for sandbox ports.
//!
//! Services require a cloud backend; the local backend returns
//! [`MicrosandboxError::Unsupported`](crate::MicrosandboxError::Unsupported).

mod api;
mod types;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use api::{Service, ServiceBuilder};
pub use microsandbox_types::CloudServiceStatus as ServiceStatus;
pub use microsandbox_types::CloudServiceTarget as ServiceTarget;
pub use types::{ServiceListBuilder, ServicePage, ServiceUpdate};
