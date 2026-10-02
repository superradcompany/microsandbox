use napi_derive::napi;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fluent builder for HTTP denial responses.
#[napi(js_name = "HttpBuilder")]
#[derive(Default)]
pub struct JsHttpBuilder {
    pub(crate) message: Option<String>,
    pub(crate) response: Option<bool>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsHttpBuilder {
    /// Create default HTTP settings.
    #[napi(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable readable HTTP denial responses. Disabled by default.
    #[napi(js_name = "denyResponse")]
    pub fn deny_response(&mut self, enabled: bool) -> &Self {
        self.response = Some(enabled);
        self
    }

    /// Set the body used when denyResponse is enabled, substituting `{host}`.
    #[napi(js_name = "denyMessage")]
    pub fn deny_message(&mut self, message: String) -> &Self {
        self.message = Some(message);
        self
    }
}
