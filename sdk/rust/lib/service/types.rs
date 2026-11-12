//! Service update fields, list options, and list pages.

use microsandbox_types::CloudUpdateServiceRequest;

use super::{Service, ServiceTarget};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default number of Services returned by one list request.
pub(crate) const DEFAULT_SERVICE_LIST_LIMIT: u32 = 20;

/// Maximum number of Services returned by one list request.
pub(crate) const MAX_SERVICE_LIST_LIMIT: u32 = 100;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fields for one [`Service::update`] call.
///
/// An update with no target, or with port zero, fails before any request.
#[derive(Debug, Clone, Default)]
pub struct ServiceUpdate {
    target: Option<ServiceTarget>,
}

/// Configures one paginated [`Service::list_with`] request.
///
/// Results are in slug order and include disabled and detached Services.
#[derive(Debug, Clone)]
pub struct ServiceListBuilder {
    pub(crate) sandbox: Option<String>,
    pub(crate) cursor: Option<String>,
    pub(crate) limit: u32,
}

/// One page of Services.
#[derive(Debug, Clone)]
pub struct ServicePage {
    /// Services in this page.
    pub services: Vec<Service>,
    /// Opaque cursor for the next page, or `None` when this is the final page.
    pub next_cursor: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ServiceUpdate {
    /// Set the running sandbox and port that receive requests.
    ///
    /// Setting a target also enables or reattaches the Service.
    pub fn target(mut self, sandbox: impl Into<String>, port: u16) -> Self {
        self.target = Some(ServiceTarget {
            sandbox: sandbox.into(),
            port,
        });
        self
    }

    pub(crate) fn into_request(self) -> CloudUpdateServiceRequest {
        CloudUpdateServiceRequest {
            target: self.target,
        }
    }
}

impl ServiceListBuilder {
    /// Only list Services whose target is the sandbox with this name.
    pub fn sandbox(mut self, name: impl Into<String>) -> Self {
        self.sandbox = Some(name.into());
        self
    }

    /// Set the maximum number of Services in this page: 1 through 100, default 20.
    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = limit;
        self
    }

    /// Continue listing after an opaque cursor returned by a previous page.
    pub fn cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for ServiceListBuilder {
    fn default() -> Self {
        Self {
            sandbox: None,
            cursor: None,
            limit: DEFAULT_SERVICE_LIST_LIMIT,
        }
    }
}
