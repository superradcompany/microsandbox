//! The [`Service`] resource and its create builder.

use std::fmt;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use microsandbox_types::{CloudCreateServiceRequest, CloudService};

use super::types::MAX_SERVICE_LIST_LIMIT;
use super::{ServiceListBuilder, ServicePage, ServiceStatus, ServiceTarget, ServiceUpdate};
use crate::backend::{Backend, default_backend};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A public URL for one sandbox port.
///
/// Services require a cloud backend. Accessors use the last response without making a request.
#[derive(Clone)]
pub struct Service {
    backend: Arc<dyn Backend>,
    info: CloudService,
}

/// Configures a new [`Service`]. Created by [`Service::builder`].
#[derive(Debug, Clone)]
pub struct ServiceBuilder {
    slug: String,
    target: Option<ServiceTarget>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Service {
    /// Start a Service builder with this slug.
    pub fn builder(slug: impl Into<String>) -> ServiceBuilder {
        ServiceBuilder {
            slug: slug.into(),
            target: None,
        }
    }

    /// Get a Service by slug through the default backend.
    pub async fn get(slug: &str) -> MicrosandboxResult<Service> {
        let backend = default_backend();
        backend.services().get(backend.clone(), slug).await
    }

    /// List the first page of the organization's Services.
    pub async fn list() -> MicrosandboxResult<ServicePage> {
        Self::list_with(|list| list).await
    }

    /// List a configured page of the organization's Services.
    ///
    /// Fails with [`MicrosandboxError::InvalidConfig`] when the limit is outside 1 through 100.
    pub async fn list_with(
        configure: impl FnOnce(ServiceListBuilder) -> ServiceListBuilder,
    ) -> MicrosandboxResult<ServicePage> {
        let query = configure(ServiceListBuilder::default());
        if !(1..=MAX_SERVICE_LIST_LIMIT).contains(&query.limit) {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "service list limit must be between 1 and {MAX_SERVICE_LIST_LIMIT}"
            )));
        }

        let backend = default_backend();
        backend.services().list(backend.clone(), query).await
    }

    /// The Service's slug.
    pub fn slug(&self) -> &str {
        &self.info.slug
    }

    /// The Service's public URL as returned by the backend.
    pub fn url(&self) -> &str {
        &self.info.url
    }

    /// Whether the Service routes requests, is disabled, or has no target, as of the read that
    /// returned this value. [`Service::refresh`] returns a current copy.
    pub fn status(&self) -> ServiceStatus {
        self.info.status
    }

    /// The target, or `None` when the Service is detached.
    pub fn target(&self) -> Option<ServiceTarget> {
        self.info.target.clone()
    }

    /// When the organization created this Service.
    pub fn created_at(&self) -> DateTime<Utc> {
        self.info.created_at
    }

    /// When the Service's state last changed, including a detach.
    pub fn updated_at(&self) -> DateTime<Utc> {
        self.info.updated_at
    }

    /// Change the target.
    ///
    /// The SDK does not retry; get and check the Service after
    /// [`OutcomeUnknown`](crate::ServiceError::OutcomeUnknown).
    pub async fn update(
        &self,
        configure: impl FnOnce(ServiceUpdate) -> ServiceUpdate,
    ) -> MicrosandboxResult<Service> {
        let request = configure(ServiceUpdate::default()).into_request();
        self.backend
            .services()
            .update(self.backend.clone(), self.slug(), request)
            .await
    }

    /// Enable the Service without retrying.
    ///
    /// To enable a detached Service, set a running target with [`Service::update`] instead.
    pub async fn enable(&self) -> MicrosandboxResult<Service> {
        self.backend
            .services()
            .enable(self.backend.clone(), self.slug())
            .await
    }

    /// Disable the Service without retrying while retaining its target.
    pub async fn disable(&self) -> MicrosandboxResult<Service> {
        self.backend
            .services()
            .disable(self.backend.clone(), self.slug())
            .await
    }

    /// Remove the Service and release its slug without retrying.
    pub async fn remove(self) -> MicrosandboxResult<()> {
        self.backend
            .services()
            .remove(self.backend.clone(), self.slug())
            .await
    }

    /// Get the Service again and return its current state. This value is not changed.
    pub async fn refresh(&self) -> MicrosandboxResult<Service> {
        self.backend
            .services()
            .get(self.backend.clone(), self.slug())
            .await
    }

    #[cfg(feature = "cloud")]
    pub(crate) fn from_cloud(backend: Arc<dyn Backend>, info: CloudService) -> Self {
        Self { backend, info }
    }
}

impl ServiceBuilder {
    /// Set the running sandbox and port that receive requests.
    pub fn target(mut self, sandbox: impl Into<String>, port: u16) -> Self {
        self.target = Some(ServiceTarget {
            sandbox: sandbox.into(),
            port,
        });
        self
    }

    /// Create the Service without retrying.
    ///
    /// A missing target or port zero fails before any request.
    pub async fn create(self) -> MicrosandboxResult<Service> {
        let Some(target) = self.target else {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "service {} requires a target",
                self.slug
            )));
        };

        let request = CloudCreateServiceRequest {
            slug: self.slug,
            target,
        };
        let backend = default_backend();
        backend.services().create(backend.clone(), request).await
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Service")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}
