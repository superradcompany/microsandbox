//! Sandbox setup helpers: build an Alpine guest with the given network
//! configuration, install the DNS tooling we need, and surface the
//! guest's gateway IP for scenarios that target it explicitly.

use std::net::Ipv4Addr;

use ipnetwork::{IpNetwork, Ipv4Network};
use microsandbox::{NetworkPolicy, Sandbox};
use microsandbox_network::builder::NetworkBuilder;
use microsandbox_network::policy::{Action, Destination, Rule};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Create an Alpine sandbox with the given network configuration,
/// install `dig` inside the guest, and return the sandbox alongside
/// the gateway IP the guest's stub resolver is pointing at.
///
/// The caller builds the [`NetworkBuilder`] inline (policy, tls, dns,
/// etc.) so the test setup lives next to the scenarios it exercises.
pub(crate) async fn setup_sandbox(
    name: &str,
    configure_network: impl FnOnce(NetworkBuilder) -> NetworkBuilder,
) -> Result<(Sandbox, String), Box<dyn std::error::Error>> {
    let sb = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .network(configure_network)
        .replace()
        .create()
        .await?;
    install_dig(&sb).await?;
    let gateway_ip = read_gateway_ip(&sb).await?;
    Ok((sb, gateway_ip))
}

/// Policy that denies all outbound traffic to `resolver` (e.g.
/// `"8.8.8.8"`) so `dig @<resolver>` exercises the forwarder's REFUSED
/// path for a policy-denied `@target` resolver.
pub(crate) fn deny_resolver(resolver: &str) -> Result<NetworkPolicy, Box<dyn std::error::Error>> {
    let ip: Ipv4Addr = resolver.parse()?;
    Ok(NetworkPolicy {
        default_egress: Action::Allow,
        default_ingress: Action::Allow,
        rules: vec![Rule::deny_egress(Destination::Cidr(IpNetwork::V4(
            Ipv4Network::new(ip, 32)?,
        )))],
    })
}

//--------------------------------------------------------------------------------------------------
// Functions: Internal
//--------------------------------------------------------------------------------------------------

/// Install `dig` inside the guest. The built-in busybox `nslookup`
/// doesn't support `+tcp` / `+tls`, so bind-tools is required.
async fn install_dig(sb: &Sandbox) -> Result<(), Box<dyn std::error::Error>> {
    sb.shell("apk add --quiet --no-progress bind-tools >/dev/null 2>&1")
        .await?;
    Ok(())
}

/// Read the guest's first configured nameserver (the sandbox gateway)
/// out of `/etc/resolv.conf`. Used to target the gateway explicitly
/// for the DoT-to-gateway scenarios.
async fn read_gateway_ip(sb: &Sandbox) -> Result<String, Box<dyn std::error::Error>> {
    let out = sb
        .shell("awk '/^nameserver /{print $2; exit}' /etc/resolv.conf")
        .await?;
    let ip = out.stdout()?.trim().to_string();
    if ip.is_empty() {
        return Err("could not read gateway IP from guest /etc/resolv.conf".into());
    }
    Ok(ip)
}
