use super::RemoteContext;
use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RemoteContext {
    /// Construct for the hosted service using the default API URL.
    ///
    /// This constructor does not select an endpoint from `MSB_API_URL`;
    /// use `from_env` when environment-based selection is intended.
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
