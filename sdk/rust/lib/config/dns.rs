//! Operator-owned DNS configuration.

use std::net::IpAddr;

use microsandbox_types::ConfigPatch;
#[cfg(all(feature = "local", feature = "net"))]
use microsandbox_types::DeploymentProfile;
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Host-owned DNS settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
#[derive(ConfigPatch)]
#[config_patch(serde)]
pub struct HostDnsConfig {
    /// Operator DNS resolvers, as IP addresses queried on port 53. An omitted
    /// or empty list uses the profile default.
    pub nameservers: Option<Vec<IpAddr>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[cfg(all(feature = "local", feature = "net"))]
impl HostDnsConfig {
    /// An explicit host override, with an empty list treated as unset.
    pub(crate) fn nameserver_override(&self) -> Option<&[IpAddr]> {
        self.nameservers
            .as_deref()
            .filter(|servers| !servers.is_empty())
    }

    /// The trusted resolver override for a multi-tenant launch.
    pub(crate) fn multi_tenant_nameservers(&self, profile: DeploymentProfile) -> Option<&[IpAddr]> {
        if profile == DeploymentProfile::MultiTenant {
            self.nameserver_override()
        } else {
            None
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::config::GlobalConfig;

    #[test]
    fn nameservers_accept_ip_addresses_and_allow_an_empty_list() {
        let parse = |value: serde_json::Value| -> GlobalConfig {
            serde_json::from_value(serde_json::json!({
                "dns": {"nameservers": value}
            }))
            .unwrap()
        };

        let cfg = parse(serde_json::json!(["9.9.9.9", "2620:fe::fe"]));
        assert_eq!(
            cfg.dns.nameservers,
            Some(vec![
                "9.9.9.9".parse().unwrap(),
                "2620:fe::fe".parse().unwrap()
            ])
        );

        assert_eq!(parse(serde_json::json!([])).dns.nameservers, Some(vec![]));
        for invalid in ["dns.google", "9.9.9.9:53"] {
            let result = serde_json::from_value::<GlobalConfig>(serde_json::json!({
                "dns": {"nameservers": [invalid]}
            }));
            assert!(result.is_err(), "{invalid:?} should be rejected");
        }
    }
}
