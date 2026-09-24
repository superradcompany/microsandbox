//! Typed readers for previous flat and resolved network launch fields.

use microsandbox_network::config::{NetworkConfig, ResolvedNetworkConfig};
use microsandbox_network::proxy::ResolvedOutboundProxy;
use microsandbox_types::{DeploymentProfile, SecretsConfig, compat};
use serde::Deserialize;

use compat::field::Field;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum Network {
    Resolved(Resolved),
    Plain(Plain),
}

#[derive(Deserialize)]
pub(super) struct Resolved {
    config: Config,
    outbound_proxy: Option<ResolvedOutboundProxy>,
}

#[derive(Deserialize)]
pub(super) struct Plain {
    // A malformed resolved envelope must not fall back to flat defaults.
    #[serde(default)]
    config: Field<serde::de::IgnoredAny>,
    #[serde(flatten)]
    network: Config,
}

#[derive(Deserialize)]
struct Config {
    #[serde(
        default,
        deserialize_with = "compat::v0_5_0::local::secrets::deserialize_config"
    )]
    secrets: SecretsConfig,
    #[serde(default, alias = "max_tcp_connections")]
    max_connections: Option<u64>,
    #[serde(default)]
    max_udp_connections: Option<u64>,
    #[serde(flatten)]
    network: NetworkConfig,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Network {
    pub(super) fn into_current(
        self,
        profile: DeploymentProfile,
    ) -> Result<ResolvedNetworkConfig, String> {
        let (config, outbound_proxy) = match self {
            Self::Resolved(resolved) => (resolved.config, resolved.outbound_proxy),
            Self::Plain(Plain {
                config: Field::Missing,
                network,
            }) => (network, None),
            Self::Plain(_) => return Err("invalid resolved network configuration".into()),
        };
        let limit = config.max_connections.unwrap_or(256);
        if limit == 0 {
            return Err("legacy max_connections=0 cannot be represented by this runtime; use a current SDK and an explicit network policy".into());
        }
        if limit > 4096 {
            return Err("legacy network connection limit exceeds 4096".into());
        }
        if config.max_udp_connections.is_some() {
            return Err("UDP connection limits require the current launch contract".into());
        }
        let mut network = config.network;
        network.secrets = config.secrets;
        network
            .secrets
            .validate()
            .map_err(|error| format!("invalid secret configuration: {error}"))?;
        let limit = if profile == DeploymentProfile::MultiTenant {
            limit.min(256)
        } else {
            limit
        };
        network.max_tcp_connections = Some((limit as usize).into());
        network.max_udp_connections = Some(256.into());
        Ok(ResolvedNetworkConfig::new(network, outbound_proxy))
    }
}
