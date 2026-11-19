use super::{RemoteContext, RemoteContextBuilder};
use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RemoteContext {
    /// Derive an independent destination from captured settings, without reloading profiles,
    /// environment variables or configuration files. Existing resources keep this context.
    /// Custom clients retain their transport settings; the context API key controls auth.
    pub fn to_builder(&self) -> RemoteContextBuilder {
        RemoteContextBuilder {
            url: Some(self.inner.url.clone()),
            api_key: Some(self.inner.api_key.clone()),
            request_timeout: self.inner.request_timeout,
            user_agent: self.inner.user_agent.clone(),
            compute_type: self.inner.compute_type,
            custom_client: self.inner.custom_client.clone(),
            shared_client: Some(self.inner.http.clone()),
            config: Some(self.inner.config.clone()),
        }
    }

    /// Use an explicit API key and the environment or hosted endpoint.
    pub fn new(api_key: impl Into<String>) -> MicrosandboxResult<Self> {
        Self::builder().api_key(api_key).build()
    }

    /// Construct with an explicit endpoint and API key for any compatible provider.
    pub fn with_url(
        url: impl Into<String>,
        api_key: impl Into<String>,
    ) -> MicrosandboxResult<Self> {
        Self::builder().url(url).api_key(api_key).build()
    }
}
