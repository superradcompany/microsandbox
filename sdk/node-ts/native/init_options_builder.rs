use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox::sandbox::InitOptionsBuilder as RustInitOptionsBuilder;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fluent builder for the args + env portion of a guest init handoff.
///
/// The program path is supplied positionally to
/// `SandboxBuilder.init_with`, mirroring how `ExecOptionsBuilder` omits
/// the command name.
#[napi(js_name = "InitOptionsBuilder")]
pub struct JsInitOptionsBuilder {
    inner: Option<RustInitOptionsBuilder>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsInitOptionsBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Some(RustInitOptionsBuilder::default()),
        }
    }

    /// Append a single argv entry.
    #[napi]
    pub fn arg(&mut self, arg: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.arg(arg));
        self
    }

    /// Append multiple argv entries.
    #[napi]
    pub fn args(&mut self, args: Vec<String>) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.args(args));
        self
    }

    /// Set a single env var for the init process.
    #[napi]
    pub fn env(&mut self, key: String, value: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.env(key, value));
        self
    }

    /// Set multiple env vars at once.
    #[napi]
    pub fn envs(&mut self, vars: std::collections::HashMap<String, String>) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.envs(vars));
        self
    }
}

impl Default for JsInitOptionsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl JsInitOptionsBuilder {
    fn take_inner(&mut self) -> RustInitOptionsBuilder {
        self.inner
            .take()
            .expect("InitOptionsBuilder used after consumption")
    }

    /// Take the underlying Rust builder. Used by `JsSandboxBuilder.init_with`
    /// after the user closure returns the populated builder back.
    pub(crate) fn take_inner_builder(&mut self) -> Result<RustInitOptionsBuilder> {
        self.inner.take().ok_or_else(|| {
            napi::Error::from_reason("InitOptionsBuilder already consumed".to_string())
        })
    }
}
