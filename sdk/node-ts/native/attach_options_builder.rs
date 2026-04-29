use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox::sandbox::AttachOptionsBuilder as RustAttachOptionsBuilder;

use crate::exec_options_builder::parse_rlimit_resource;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fluent builder for interactive attach options.
#[napi(js_name = "AttachOptionsBuilder")]
pub struct JsAttachOptionsBuilder {
    inner: Option<RustAttachOptionsBuilder>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsAttachOptionsBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Some(RustAttachOptionsBuilder::default()),
        }
    }

    /// Append a single command argument.
    #[napi]
    pub fn arg(&mut self, arg: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.arg(arg));
        self
    }

    /// Append a list of command arguments.
    #[napi]
    pub fn args(&mut self, args: Vec<String>) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.args(args));
        self
    }

    /// Override the working directory.
    #[napi]
    pub fn cwd(&mut self, cwd: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.cwd(cwd));
        self
    }

    /// Override the running user.
    #[napi]
    pub fn user(&mut self, user: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.user(user));
        self
    }

    /// Set a single environment variable.
    #[napi]
    pub fn env(&mut self, key: String, value: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.env(key, value));
        self
    }

    /// Set environment variables from an object.
    #[napi]
    pub fn envs(&mut self, vars: std::collections::HashMap<String, String>) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.envs(vars));
        self
    }

    /// Override the detach key sequence (Docker-style spec, e.g. `"ctrl-]"` or
    /// `"ctrl-p,ctrl-q"`). Default: `Ctrl+]`.
    #[napi(js_name = "detachKeys")]
    pub fn detach_keys(&mut self, keys: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.detach_keys(keys));
        self
    }

    /// Set a hard rlimit (soft = hard).
    #[napi]
    pub fn rlimit(&mut self, resource: String, limit: u32) -> Result<&Self> {
        let res = parse_rlimit_resource(&resource)?;
        let prev = self.take_inner();
        self.inner = Some(prev.rlimit(res, limit as u64));
        Ok(self)
    }

    /// Set a separate soft and hard rlimit.
    #[napi(js_name = "rlimitRange")]
    pub fn rlimit_range(&mut self, resource: String, soft: u32, hard: u32) -> Result<&Self> {
        let res = parse_rlimit_resource(&resource)?;
        let prev = self.take_inner();
        self.inner = Some(prev.rlimit_range(res, soft as u64, hard as u64));
        Ok(self)
    }
}

impl JsAttachOptionsBuilder {
    fn take_inner(&mut self) -> RustAttachOptionsBuilder {
        self.inner
            .take()
            .expect("AttachOptionsBuilder used after consumption")
    }

    /// Internal: consume and produce the built `AttachOptions`. Used by
    /// `Sandbox.attachWith()`.
    #[allow(dead_code)]
    pub(crate) fn take_inner_builder(&mut self) -> Result<RustAttachOptionsBuilder> {
        self.inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("AttachOptionsBuilder already consumed"))
    }
}
