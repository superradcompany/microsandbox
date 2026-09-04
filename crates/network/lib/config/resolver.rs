//! Resolution of source-backed network configuration values.

use microsandbox_types::SecretSource;
use zeroize::Zeroizing;

use crate::proxy::{
    OutboundProxy, OutboundProxyBuildError, ResolvedOutboundProxy, ResolvedSocks5Credentials,
};

use super::types::{NetworkConfig, ResolvedNetworkConfig};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Resolves one host-side source into secret material for a network launch.
#[doc(hidden)]
pub trait NetworkSecretResolver {
    /// Resolves the configured source.
    fn resolve(
        &self,
        source: &SecretSource,
    ) -> Result<Zeroizing<String>, NetworkSecretResolveError>;
}

/// Resolves environment-backed sources for local sandbox launches.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EnvNetworkSecretResolver;

/// Error returned by a network secret resolver.
#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
pub enum NetworkSecretResolveError {
    /// A required host environment variable is not set.
    #[error("host environment variable {var} is not set")]
    MissingEnvironmentVariable {
        /// Missing host environment variable.
        var: String,
    },

    /// A required host environment variable is empty.
    #[error("host environment variable {var} is empty")]
    EmptyEnvironmentVariable {
        /// Empty host environment variable.
        var: String,
    },

    /// The configured source type cannot be resolved by this resolver.
    #[error("store-backed secret sources are not supported yet")]
    UnsupportedStoreSource,

    /// A resolver-specific source lookup failed.
    #[error("{message}")]
    ResolutionFailed {
        /// Resolver-provided failure description.
        message: String,
    },
}

/// Error returned when resolving source-backed network configuration.
#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
pub enum NetworkConfigResolveError {
    /// A source-backed network setting could not be resolved.
    #[error("{subject}: {source}")]
    SecretSource {
        /// Network setting whose value could not be resolved.
        subject: String,
        /// Underlying source-resolution failure.
        #[source]
        source: NetworkSecretResolveError,
    },

    /// The resolved proxy configuration is invalid.
    #[error(transparent)]
    OutboundProxy(#[from] OutboundProxyBuildError),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl NetworkConfig {
    /// Resolves source-backed values into a configuration ready for the network runtime.
    #[doc(hidden)]
    pub fn resolve(
        mut self,
        resolver: &impl NetworkSecretResolver,
    ) -> Result<ResolvedNetworkConfig, NetworkConfigResolveError> {
        if !self.enabled {
            return Ok(ResolvedNetworkConfig::new(self, None));
        }

        for secret in &mut self.secrets.secrets {
            if let Some(source) = &secret.source {
                secret.value =
                    Self::resolve_source(resolver, &format!("secret {}", secret.env_var), source)?;
            }
        }

        let outbound_proxy_credentials = match self.outbound_proxy.as_ref() {
            Some(OutboundProxy::Socks5 {
                credentials: Some(credentials),
                ..
            }) => {
                let password =
                    Self::resolve_source(resolver, "SOCKS5 proxy", credentials.password_source())?;
                Some(ResolvedSocks5Credentials::new(
                    credentials.username(),
                    password.as_str(),
                ))
            }
            _ => None,
        };
        let outbound_proxy =
            ResolvedOutboundProxy::build(self.outbound_proxy.as_ref(), outbound_proxy_credentials)?;

        Ok(ResolvedNetworkConfig::new(self, outbound_proxy))
    }

    fn resolve_source(
        resolver: &impl NetworkSecretResolver,
        subject: &str,
        source: &SecretSource,
    ) -> Result<Zeroizing<String>, NetworkConfigResolveError> {
        resolver
            .resolve(source)
            .map_err(|source| NetworkConfigResolveError::SecretSource {
                subject: subject.to_string(),
                source,
            })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl NetworkSecretResolver for EnvNetworkSecretResolver {
    fn resolve(
        &self,
        source: &SecretSource,
    ) -> Result<Zeroizing<String>, NetworkSecretResolveError> {
        match source {
            SecretSource::Store { .. } => Err(NetworkSecretResolveError::UnsupportedStoreSource),
            SecretSource::Env { var } => {
                let value = std::env::var(var).map_err(|_| {
                    NetworkSecretResolveError::MissingEnvironmentVariable { var: var.clone() }
                })?;
                if value.is_empty() {
                    return Err(NetworkSecretResolveError::EmptyEnvironmentVariable {
                        var: var.clone(),
                    });
                }
                Ok(Zeroizing::new(value))
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_types::SecretSource;

    use super::EnvNetworkSecretResolver;
    use crate::config::NetworkConfig;
    use crate::proxy::{OutboundProxyBuilder, OutboundProxyConfig};

    #[test]
    fn network_resolution_reads_authenticated_proxy_credentials() {
        const PASSWORD_VAR: &str = "MSB_NETWORK_CONFIG_RESOLVE_TEST_SOCKS5_PASSWORD";
        let config = NetworkConfig {
            outbound_proxy: Some(
                OutboundProxyBuilder::new()
                    .socks5("127.0.0.1:1080")
                    .credentials("sandbox", SecretSource::env(PASSWORD_VAR))
                    .build()
                    .unwrap(),
            ),
            ..Default::default()
        };

        assert!(config.clone().resolve(&EnvNetworkSecretResolver).is_err());

        // SAFETY: this test owns a purpose-specific environment variable.
        unsafe { std::env::set_var(PASSWORD_VAR, "password") };
        let resolved = config.resolve(&EnvNetworkSecretResolver).unwrap();
        unsafe { std::env::remove_var(PASSWORD_VAR) };

        assert!(format!("{resolved:?}").contains("[REDACTED]"));
    }
}
