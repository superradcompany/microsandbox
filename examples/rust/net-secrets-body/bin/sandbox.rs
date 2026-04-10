//! Sandbox creation and secret injection demo logic.

use microsandbox::{NetworkPolicy, Sandbox};
use std::path::Path;

/// Create a sandbox with a body-injected secret pointing at `hostname:port`.
pub async fn create(
    secret: &str,
    hostname: &str,
    port: u16,
    upstream_ca_cert: &Path,
) -> Result<Sandbox, Box<dyn std::error::Error>> {
    let sandbox = Sandbox::builder("net-secrets-body")
        .image("alpine")
        .cpus(1)
        .memory(512)
        .secret(|s| {
            s.env("API_KEY")
                .value(secret)
                .allow_host(hostname)
                .inject_body(true)
        })
        .network(|n| {
            n.policy(NetworkPolicy::allow_all()).tls(|t| {
                t.intercepted_ports(vec![443, port])
                    .upstream_ca_cert(upstream_ca_cert)
            })
        })
        .replace()
        .create()
        .await?;

    // Alpine only has BusyBox wget (no --post-data), so install curl.
    sandbox.shell("apk add --quiet curl").await?;

    Ok(sandbox)
}

/// POST a JSON body containing the secret env var to the server and return the response.
///
/// Uses `curl --resolve` to map `hostname` -> `host_ip` so the TLS proxy sees
/// proper SNI without needing an /etc/hosts entry.
pub async fn post_secret(
    sandbox: &Sandbox,
    hostname: &str,
    host_ip: &str,
    port: u16,
) -> Result<String, Box<dyn std::error::Error>> {
    let cmd = format!(
        r#"printf '{{"key": "%s"}}' "$API_KEY" | curl -s -X POST --resolve {hostname}:{port}:{host_ip} -H 'Content-Type: application/json' -d @- https://{hostname}:{port}/echo"#,
    );
    let out = sandbox.shell(&cmd).await?;
    Ok(out.stdout()?.trim().to_string())
}
