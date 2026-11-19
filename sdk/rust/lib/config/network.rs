//! Operator-owned network configuration.

use std::net::IpAddr;

use microsandbox_types::{ConfigPatch, DeploymentProfile};
use serde::{Deserialize, Serialize};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Host-owned network settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
#[derive(ConfigPatch)]
#[config_patch(serde)]
pub struct HostNetworkConfig {
    /// Upstream DNS resolvers for `multi-tenant` sandboxes, as IP addresses
    /// queried on port 53. `None` uses the built-in public resolvers
    /// (`1.1.1.1` and `1.0.0.1`); an empty list is invalid. Ignored for
    /// `single-tenant` sandboxes.
    pub multi_tenant_nameservers: Option<Vec<IpAddr>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HostNetworkConfig {
    /// Validate the host-owned network settings.
    pub(crate) fn validate(&self) -> MicrosandboxResult<()> {
        if self
            .multi_tenant_nameservers
            .as_ref()
            .is_some_and(Vec::is_empty)
        {
            return Err(MicrosandboxError::InvalidConfig(
                "network.multi_tenant_nameservers must not be empty".into(),
            ));
        }
        Ok(())
    }

    /// Operator resolvers to send to the runtime for a sandbox with `profile`.
    ///
    /// `None` when the sandbox is `single-tenant` or the built-in resolvers apply.
    pub(crate) fn multi_tenant_nameservers(&self, profile: DeploymentProfile) -> Option<&[IpAddr]> {
        if profile != DeploymentProfile::MultiTenant {
            return None;
        }
        self.multi_tenant_nameservers.as_deref()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::config::GlobalConfig;

    #[test]
    fn multi_tenant_nameservers_accept_ip_addresses_and_reject_an_empty_list() {
        let parse = |value: serde_json::Value| -> GlobalConfig {
            serde_json::from_value(serde_json::json!({
                "network": {"multi_tenant_nameservers": value}
            }))
            .unwrap()
        };

        let cfg = parse(serde_json::json!(["9.9.9.9", "2620:fe::fe"]));
        cfg.network.validate().unwrap();
        assert_eq!(
            cfg.network.multi_tenant_nameservers,
            Some(vec![
                "9.9.9.9".parse().unwrap(),
                "2620:fe::fe".parse().unwrap()
            ])
        );

        let error = parse(serde_json::json!([])).network.validate().unwrap_err();
        assert!(error.to_string().contains("must not be empty"));

        GlobalConfig::default().network.validate().unwrap();
        for invalid in ["dns.google", "9.9.9.9:53"] {
            let result = serde_json::from_value::<GlobalConfig>(serde_json::json!({
                "network": {"multi_tenant_nameservers": [invalid]}
            }));
            assert!(result.is_err(), "{invalid:?} should be rejected");
        }
    }
}
