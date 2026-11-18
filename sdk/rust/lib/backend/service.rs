//! Service lifecycle backend trait.
//!
//! Services are cloud-only: the local backend refuses every operation with
//! [`MicrosandboxError::Unsupported`](crate::MicrosandboxError::Unsupported) before any work.

use std::sync::Arc;

use futures::future::BoxFuture;
use microsandbox_types::{CloudCreateServiceRequest, CloudUpdateServiceRequest};

use super::Backend;
#[cfg(feature = "local")]
use super::LocalBackend;
use crate::MicrosandboxResult;
#[cfg(feature = "local")]
use crate::error::{MicrosandboxError, Operation};
use crate::service::{Service, ServiceListBuilder, ServicePage};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Resource-specific backend for Service operations.
///
/// Methods take the [`Arc<dyn Backend>`] that every returned [`Service`] carries. Change methods
/// send at most one request and never retry it.
pub trait ServiceBackend: Send + Sync {
    /// Create a Service and return it once committed.
    fn create<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        request: CloudCreateServiceRequest,
    ) -> BoxFuture<'a, MicrosandboxResult<Service>>;

    /// Get a Service by slug.
    fn get<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        slug: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Service>>;

    /// List one page of Services.
    fn list<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        query: ServiceListBuilder,
    ) -> BoxFuture<'a, MicrosandboxResult<ServicePage>>;

    /// Change a Service's target and return it once committed.
    fn update<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        slug: &'a str,
        request: CloudUpdateServiceRequest,
    ) -> BoxFuture<'a, MicrosandboxResult<Service>>;

    /// Enable a Service and return it once committed.
    fn enable<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        slug: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Service>>;

    /// Disable a Service and return it once committed.
    fn disable<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        slug: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Service>>;

    /// Remove a Service and release its slug.
    fn remove<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        slug: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: LocalBackend
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "local")]
impl ServiceBackend for LocalBackend {
    fn create<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _request: CloudCreateServiceRequest,
    ) -> BoxFuture<'a, MicrosandboxResult<Service>> {
        Box::pin(async { Err(MicrosandboxError::cloud_only(Operation::ServiceCreate)) })
    }

    fn get<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _slug: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Service>> {
        Box::pin(async { Err(MicrosandboxError::cloud_only(Operation::ServiceGet)) })
    }

    fn list<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _query: ServiceListBuilder,
    ) -> BoxFuture<'a, MicrosandboxResult<ServicePage>> {
        Box::pin(async { Err(MicrosandboxError::cloud_only(Operation::ServiceList)) })
    }

    fn update<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _slug: &'a str,
        _request: CloudUpdateServiceRequest,
    ) -> BoxFuture<'a, MicrosandboxResult<Service>> {
        Box::pin(async { Err(MicrosandboxError::cloud_only(Operation::ServiceUpdate)) })
    }

    fn enable<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _slug: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Service>> {
        Box::pin(async { Err(MicrosandboxError::cloud_only(Operation::ServiceEnable)) })
    }

    fn disable<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _slug: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Service>> {
        Box::pin(async { Err(MicrosandboxError::cloud_only(Operation::ServiceDisable)) })
    }

    fn remove<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _slug: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async { Err(MicrosandboxError::cloud_only(Operation::ServiceRemove)) })
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "local"))]
mod tests {
    use microsandbox_types::CloudServiceTarget;

    use super::*;
    use crate::error::UnsupportedReason;

    fn assert_cloud_only<T: std::fmt::Debug>(result: MicrosandboxResult<T>, expected: Operation) {
        let error = result.expect_err("Local must refuse every Service operation");
        assert!(
            matches!(
                &error,
                MicrosandboxError::Unsupported {
                    op,
                    reason: UnsupportedReason::CloudOnly,
                } if *op == expected
            ),
            "expected cloud-only {expected:?}, got {error:?}"
        );
    }

    #[tokio::test]
    async fn local_service_operations_fail_closed() {
        let home = tempfile::tempdir().unwrap();
        let backend: Arc<dyn Backend> = Arc::new(
            crate::test_support::local_backend_builder(home.path())
                .build()
                .await
                .unwrap(),
        );
        let services = backend.services();
        let target = CloudServiceTarget {
            sandbox: "web-1".into(),
            port: 8080,
        };

        let create = CloudCreateServiceRequest {
            slug: "my-app".into(),
            target: target.clone(),
        };
        let update = CloudUpdateServiceRequest {
            target: Some(target),
        };
        assert_cloud_only(
            services.create(backend.clone(), create).await,
            Operation::ServiceCreate,
        );
        assert_cloud_only(
            services.get(backend.clone(), "my-app").await,
            Operation::ServiceGet,
        );
        assert_cloud_only(
            services
                .list(backend.clone(), ServiceListBuilder::default())
                .await,
            Operation::ServiceList,
        );
        assert_cloud_only(
            services.update(backend.clone(), "my-app", update).await,
            Operation::ServiceUpdate,
        );
        assert_cloud_only(
            services.enable(backend.clone(), "my-app").await,
            Operation::ServiceEnable,
        );
        assert_cloud_only(
            services.disable(backend.clone(), "my-app").await,
            Operation::ServiceDisable,
        );
        assert_cloud_only(
            services.remove(backend.clone(), "my-app").await,
            Operation::ServiceRemove,
        );
    }
}
