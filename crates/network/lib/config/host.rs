//! Operator-owned limits read from the runtime process, never from guest env.

use std::num::NonZeroUsize;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Host runtime environment setting for the shared-host TCP connection budget.
pub const HOST_MAX_TCP_CONNECTIONS_ENV: &str = "MSB_HOST_MAX_TCP_CONNECTIONS";

/// No connection-count ceiling unless the operator configures one.
pub const DEFAULT_HOST_MAX_TCP_CONNECTIONS: Option<NonZeroUsize> = None;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Validated per-sandbox connection ceiling owned by a multi-tenant host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostNetworkLimits {
    max_tcp_connections: Option<NonZeroUsize>,
}

/// Invalid operator configuration must fail before allocating network resources.
#[derive(Debug, thiserror::Error)]
#[error("{HOST_MAX_TCP_CONNECTIONS_ENV} must be a non-negative integer")]
pub struct HostNetworkLimitsError;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HostNetworkLimits {
    /// Construct host policy from an optional, strictly positive ceiling.
    pub fn new(max_tcp_connections: Option<NonZeroUsize>) -> Self {
        Self {
            max_tcp_connections,
        }
    }

    /// Read the host process setting. Guest bootstrap env does not enter this path.
    pub fn from_environment() -> Result<Self, HostNetworkLimitsError> {
        match std::env::var(HOST_MAX_TCP_CONNECTIONS_ENV) {
            Ok(value) => Self::parse(&value),
            Err(std::env::VarError::NotPresent) => Ok(Self::default()),
            Err(std::env::VarError::NotUnicode(_)) => Err(HostNetworkLimitsError),
        }
    }

    /// Maximum tracked TCP connections allowed for one sandbox.
    pub fn max_tcp_connections(self) -> Option<NonZeroUsize> {
        self.max_tcp_connections
    }

    fn parse(value: &str) -> Result<Self, HostNetworkLimitsError> {
        let limit = value.parse().map_err(|_| HostNetworkLimitsError)?;
        Ok(Self::new(NonZeroUsize::new(limit)))
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for HostNetworkLimits {
    fn default() -> Self {
        Self {
            max_tcp_connections: DEFAULT_HOST_MAX_TCP_CONNECTIONS,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_operator_limits_are_positive_and_invalid_values_fail_closed() {
        assert_eq!(HostNetworkLimits::default().max_tcp_connections(), None);
        assert_eq!(
            HostNetworkLimits::parse("0").unwrap().max_tcp_connections(),
            None
        );
        for value in ["-1", "", "unlimited", "18446744073709551616"] {
            assert!(HostNetworkLimits::parse(value).is_err(), "{value}");
        }
        for limit in [1, 256, 1024, 4096, 10000] {
            assert_eq!(
                HostNetworkLimits::new(NonZeroUsize::new(limit)).max_tcp_connections(),
                NonZeroUsize::new(limit)
            );
        }
    }
}
