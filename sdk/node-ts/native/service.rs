//! Native bindings for the cloud `Service` resource.

use microsandbox::{MicrosandboxError, Service, ServicePage, ServiceStatus};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::error::{to_napi_error, to_napi_service_change_error};
use crate::types::datetime_to_ms;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A public URL for one sandbox port.
#[napi(js_name = "Service")]
pub struct JsService {
    inner: Service,
}

/// The sandbox and port a Service routes to.
#[napi(object, js_name = "ServiceTarget")]
pub struct JsServiceTarget {
    pub sandbox: String,
    pub port: f64,
}

/// Fields for one `Service.update()` call.
#[napi(object)]
pub struct ServiceUpdateOptions {
    pub target: JsServiceTarget,
}

/// Options for one `Service.listWith()` page.
#[napi(object)]
pub struct ServiceListOptions {
    pub sandbox: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<f64>,
}

/// One page returned by `Service.list` / `Service.listWith`.
#[napi(object, object_from_js = false, js_name = "ServicePage")]
pub struct JsServicePage {
    pub services: Vec<JsService>,
    pub next_cursor: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsService {
    /// Create a Service. Without a target, the SDK refuses before any request.
    #[napi]
    pub async fn create(slug: String, target: Option<JsServiceTarget>) -> Result<JsService> {
        let mut builder = Service::builder(slug);
        if let Some(target) = target {
            let port = target_port_for_change(target.port)?;
            builder = builder.target(target.sandbox, port);
        }

        let inner = builder
            .create()
            .await
            .map_err(to_napi_service_change_error)?;
        Ok(JsService { inner })
    }

    #[napi]
    pub async fn get(slug: String) -> Result<JsService> {
        let inner = Service::get(&slug).await.map_err(to_napi_error)?;
        Ok(JsService { inner })
    }

    #[napi]
    pub async fn list() -> Result<JsServicePage> {
        let page = Service::list().await.map_err(to_napi_error)?;
        Ok(service_page_to_js(page))
    }

    #[napi(js_name = "listWith")]
    pub async fn list_with(options: ServiceListOptions) -> Result<JsServicePage> {
        let limit = options
            .limit
            .map(|limit| crate::numeric::uint32(limit, "limit"))
            .transpose()?;

        let page = Service::list_with(|list| {
            let mut list = list;
            if let Some(sandbox) = options.sandbox {
                list = list.sandbox(sandbox);
            }
            if let Some(cursor) = options.cursor {
                list = list.cursor(cursor);
            }
            if let Some(limit) = limit {
                list = list.limit(limit);
            }
            list
        })
        .await
        .map_err(to_napi_error)?;
        Ok(service_page_to_js(page))
    }

    #[napi(getter)]
    pub fn slug(&self) -> String {
        self.inner.slug().to_string()
    }

    #[napi(getter)]
    pub fn url(&self) -> String {
        self.inner.url().to_string()
    }

    #[napi(getter)]
    pub fn status(&self) -> &'static str {
        service_status(self.inner.status())
    }

    /// The target, or `null` when the Service is detached.
    #[napi(getter)]
    pub fn target(&self) -> Option<JsServiceTarget> {
        self.inner.target().map(|target| JsServiceTarget {
            sandbox: target.sandbox,
            port: f64::from(target.port),
        })
    }

    #[napi(getter)]
    pub fn created_at(&self) -> f64 {
        datetime_to_ms(&self.inner.created_at())
    }

    #[napi(getter)]
    pub fn updated_at(&self) -> f64 {
        datetime_to_ms(&self.inner.updated_at())
    }

    /// Change the target.
    #[napi]
    pub async fn update(&self, options: ServiceUpdateOptions) -> Result<JsService> {
        let target = (
            options.target.sandbox,
            target_port_for_change(options.target.port)?,
        );

        let inner = self
            .inner
            .update(|update| update.target(target.0, target.1))
            .await
            .map_err(to_napi_service_change_error)?;
        Ok(JsService { inner })
    }

    /// Enable the Service.
    #[napi]
    pub async fn enable(&self) -> Result<JsService> {
        let inner = self
            .inner
            .enable()
            .await
            .map_err(to_napi_service_change_error)?;
        Ok(JsService { inner })
    }

    /// Disable the Service while retaining its target.
    #[napi]
    pub async fn disable(&self) -> Result<JsService> {
        let inner = self
            .inner
            .disable()
            .await
            .map_err(to_napi_service_change_error)?;
        Ok(JsService { inner })
    }

    /// Remove the Service and release its slug.
    #[napi]
    pub async fn remove(&self) -> Result<()> {
        self.inner
            .clone()
            .remove()
            .await
            .map_err(to_napi_service_change_error)
    }

    #[napi]
    pub async fn refresh(&self) -> Result<JsService> {
        let inner = self.inner.refresh().await.map_err(to_napi_error)?;
        Ok(JsService { inner })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn service_page_to_js(page: ServicePage) -> JsServicePage {
    JsServicePage {
        services: page
            .services
            .into_iter()
            .map(|inner| JsService { inner })
            .collect(),
        next_cursor: page.next_cursor,
    }
}

fn target_port(port: f64) -> Result<u16> {
    let port = crate::numeric::uint32(port, "port")?;
    u16::try_from(port).map_err(|_| Error::from_reason("port must be between 1 and 65535"))
}

fn target_port_for_change(port: f64) -> Result<u16> {
    target_port(port).map_err(|error| {
        to_napi_service_change_error(MicrosandboxError::InvalidConfig(error.reason))
    })
}

fn service_status(status: ServiceStatus) -> &'static str {
    match status {
        ServiceStatus::Enabled => "enabled",
        ServiceStatus::Disabled => "disabled",
        ServiceStatus::Detached => "detached",
        ServiceStatus::Unknown => "unknown",
    }
}
