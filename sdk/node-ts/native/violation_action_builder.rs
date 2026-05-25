use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox_network::builder::ViolationActionBuilder as RustViolationActionBuilder;

/// Fluent builder for secret violation behavior.
#[napi(js_name = "ViolationActionBuilder")]
pub struct JsViolationActionBuilder {
    inner: Option<RustViolationActionBuilder>,
}

#[napi]
impl JsViolationActionBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Some(RustViolationActionBuilder::new()),
        }
    }

    /// Block the request silently.
    #[napi]
    pub fn block(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.block());
        self
    }

    /// Block the request and log a warning.
    #[napi(js_name = "blockAndLog")]
    pub fn block_and_log(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.block_and_log());
        self
    }

    /// Block the request and terminate the sandbox.
    #[napi(js_name = "blockAndTerminate")]
    pub fn block_and_terminate(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.block_and_terminate());
        self
    }

    /// Allow an exact host to receive placeholders unchanged.
    #[napi(js_name = "passthroughHost")]
    pub fn passthrough_host(&mut self, host: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.passthrough_host(host));
        self
    }

    /// Allow hosts matching a wildcard pattern to receive placeholders unchanged.
    #[napi(js_name = "passthroughHostPattern")]
    pub fn passthrough_host_pattern(&mut self, pattern: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.passthrough_host_pattern(pattern));
        self
    }

    /// Allow any host to receive placeholders unchanged.
    #[napi(js_name = "passthroughAllHosts")]
    pub fn passthrough_all_hosts(&mut self, i_understand: bool) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.passthrough_all_hosts(i_understand));
        self
    }
}

impl JsViolationActionBuilder {
    fn take_inner(&mut self) -> RustViolationActionBuilder {
        self.inner
            .take()
            .expect("ViolationActionBuilder used after consumption")
    }

    pub(crate) fn take_inner_builder(&mut self) -> Result<RustViolationActionBuilder> {
        self.inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("ViolationActionBuilder already consumed"))
    }
}
