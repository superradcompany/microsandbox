//! Sandbox setup helpers: build an Alpine guest with the given network
//! configuration, install the DNS tooling we need, and surface the
//! guest's gateway IP for scenarios that target it explicitly.

use std::{net::Ipv4Addr, time::Duration};

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
    let mut last_error = String::new();
    for attempt in 1..=3 {
        let out = sb.shell("apk add --quiet --no-progress bind-tools").await?;
        if out.status().success {
            let check = sb.shell("command -v dig").await?;
            if check.status().success {
                return Ok(());
            }
            last_error = format!(
                "bind-tools installed, but dig was not found (attempt {attempt}):\n{}",
                describe_output(&check),
            );
        } else {
            last_error = format!(
                "apk add bind-tools failed (attempt {attempt}):\n{}",
                describe_output(&out),
            );
        }

        if attempt < 3 {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    Err(format!("failed to install dig inside guest after 3 attempts:\n{last_error}").into())
}

fn describe_output(output: &microsandbox::sandbox::exec::ExecOutput) -> String {
    let stdout = output
        .stdout()
        .unwrap_or_else(|_| String::from_utf8_lossy(output.stdout_bytes()).into_owned());
    let stderr = output
        .stderr()
        .unwrap_or_else(|_| String::from_utf8_lossy(output.stderr_bytes()).into_owned());
    format!(
        "exit code: {}\nstdout:\n{}\nstderr:\n{}",
        output.status().code,
        stdout.trim(),
        stderr.trim(),
    )
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
