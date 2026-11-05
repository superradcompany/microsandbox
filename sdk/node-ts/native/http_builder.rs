use napi_derive::napi;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fluent builder for HTTP denial responses.
#[napi(js_name = "HttpBuilder")]
#[derive(Default)]
pub struct JsHttpBuilder {
    pub(crate) network_message: Option<String>,
    pub(crate) secret_message: Option<String>,
    pub(crate) response: Option<bool>,
    pub(crate) format: Option<microsandbox_network::config::HttpDenyResponseFormat>,
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

    /// Enable readable HTTP denial responses. Enabled by default locally.
    #[napi(js_name = "denyResponse")]
    pub fn deny_response(&mut self, enabled: bool) -> &Self {
        self.response = Some(enabled);
        self
    }

    /// Choose text or json (default). JSON requires a supporting runtime.
    #[napi(
        js_name = "denyResponseFormat",
        ts_args_type = "format: 'text' | 'json'"
    )]
    pub fn deny_response_format(&mut self, format: String) -> napi::Result<&Self> {
        self.format = Some(match format.as_str() {
            "text" => microsandbox_network::config::HttpDenyResponseFormat::Text,
            "json" => microsandbox_network::config::HttpDenyResponseFormat::Json,
            _ => {
                return Err(napi::Error::from_reason(
                    "denyResponseFormat must be text or json",
                ));
            }
        });
        Ok(self)
    }

    /// Deprecated: legacy text message with {host} substitution. Ignored in JSON mode.
    #[napi(js_name = "denyMessage")]
    pub fn deny_message(&mut self, message: String) -> &Self {
        self.message = Some(message);
        self
    }

    /// Set the network-denial JSON message in JSON mode without interpolation. Requires denyResponse.
    #[napi(js_name = "networkDenyMessage")]
    pub fn network_deny_message(&mut self, message: String) -> &Self {
        self.network_message = Some(message);
        self
    }

    /// Set the literal secret-denial JSON message. Requires denyResponse and JSON mode.
    #[napi(js_name = "secretDenyMessage")]
    pub fn secret_deny_message(&mut self, message: String) -> &Self {
        self.secret_message = Some(message);
        self
    }
}
