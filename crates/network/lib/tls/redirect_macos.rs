//! macOS pf redirect rule management for TLS interception.
//!
//! Installs per-sandbox pf anchors that redirect matching TCP traffic from
//! the guest subnet to the local TLS proxy port.

use std::{io, io::Write};

use super::RedirectConfig;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Installs pf redirect rules for TLS interception.
///
/// Creates a temporary pf configuration file and loads it as an anchor
/// `msb_tls/{sandbox_id}`.
///
/// NOTE: Currently refuses to install because `DIOCNATLOOK` (needed to recover
/// the original destination in the proxy) is not yet implemented. Once
/// `DIOCNATLOOK` support is added to `proxy.rs`, remove this gate.
pub fn install(_config: &RedirectConfig) -> io::Result<()> {
    return Err(io::Error::other(
        "TLS interception not yet supported on macOS — DIOCNATLOOK not implemented. \
         Redirect rules cannot be installed without original destination recovery.",
    ));

    #[allow(unreachable_code)]
    install_inner(_config)
}

fn install_inner(config: &RedirectConfig) -> io::Result<()> {
    let anchor = format!("msb_tls/{}", config.sandbox_id);
    let ports = config
        .intercepted_ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    let mut rules = String::new();

    if let Some(ipv4) = config.guest_ipv4 {
        rules.push_str(&format!(
            "rdr on {ifname} proto tcp from {ipv4} to any port {{ {ports} }} -> 127.0.0.1 port {proxy_port}\n",
            ifname = config.ifname,
            proxy_port = config.proxy_port,
        ));
    }

    if let Some(ipv6_prefix) = config.guest_ipv6_prefix {
        rules.push_str(&format!(
            "rdr on {ifname} proto tcp from {ipv6_prefix} to any port {{ {ports} }} -> ::1 port {proxy_port}\n",
            ifname = config.ifname,
            proxy_port = config.proxy_port,
        ));
    }

    // Write rules to a temp file.
    let tmp_path = format!("/tmp/msb_tls_{}.conf", config.sandbox_id);
    {
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(rules.as_bytes())?;
    }

    // Load the anchor.
    let output = std::process::Command::new("pfctl")
        .args(["-a", &anchor, "-f", &tmp_path])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()?;

    // Clean up temp file regardless.
    let _ = std::fs::remove_file(&tmp_path);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(format!(
            "pfctl anchor load failed: {stderr}"
        )));
    }

    // Enable pf if not already enabled.
    let _ = std::process::Command::new("pfctl")
        .arg("-e")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    Ok(())
}

/// Removes the per-sandbox pf anchor for TLS interception.
pub fn remove(sandbox_id: u32) -> io::Result<()> {
    let anchor = format!("msb_tls/{sandbox_id}");
    // Best-effort cleanup.
    let _ = std::process::Command::new("pfctl")
        .args(["-a", &anchor, "-F", "all"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    Ok(())
}
