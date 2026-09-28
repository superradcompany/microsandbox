use napi_derive::napi;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fluent builder for HTTP denial responses.
#[napi(js_name = "HttpBuilder")]
#[derive(Default)]
pub struct JsHttpBuilder {
    pub(crate) message: Option<String>,
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

    /// Set the denial response body, substituting `{host}`.
    #[napi(js_name = "denyMessage")]
    pub fn deny_message(&mut self, message: String) -> &Self {
        self.message = Some(message);
        self
    }
}
