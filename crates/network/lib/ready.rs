//! Startup handshake types for the supervisor ↔ msbnet readiness protocol.
//!
//! `msbnet` writes a single JSON line to stdout on successful bootstrap.
//! The supervisor parses this line to obtain the resolved network parameters
//! before spawning the VM.

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// JSON payload written to stdout by `msbnet` when ready.
///
/// Contains the resolved network parameters that the supervisor encodes
/// as `MSB_NET*` environment variables for the VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsbnetReady {
    /// PID of the msbnet process.
    pub pid: u32,

    /// Backend identifier (e.g. `"linux_tap"`, `"macos_vmnet"`).
    pub backend: String,

    /// Host-side interface name (e.g. `"msbtap42"`).
    pub ifname: String,

    /// Guest-side interface name (e.g. `"eth0"`).
    pub guest_iface: String,

    /// Guest MAC address (e.g. `"02:5a:7b:13:01:02"`).
    pub mac: String,

    /// MTU for the guest interface.
    pub mtu: u16,

    /// Resolved IPv4 network parameters.
    pub ipv4: Option<MsbnetReadyIpv4>,

    /// Resolved IPv6 network parameters.
    pub ipv6: Option<MsbnetReadyIpv6>,

    /// TLS interception readiness info. `None` when TLS is disabled.
    #[serde(default)]
    pub tls: Option<MsbnetReadyTls>,
}

/// TLS interception readiness info reported by `msbnet`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsbnetReadyTls {
    /// Whether TLS interception is active.
    pub enabled: bool,

    /// Local port the TLS proxy is listening on.
    pub proxy_port: u16,

    /// PEM-encoded CA certificate for guest trust store injection.
    pub ca_pem: String,

    /// Ports being intercepted.
    pub intercepted_ports: Vec<u16>,
}

/// Resolved IPv4 parameters reported by `msbnet`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsbnetReadyIpv4 {
    /// Guest IPv4 address (e.g. `"100.96.1.2"`).
    pub address: String,

    /// Prefix length (e.g. `30`).
    pub prefix_len: u8,

    /// Gateway IPv4 address (e.g. `"100.96.1.1"`).
    pub gateway: String,

    /// DNS server addresses exposed to the guest.
    pub dns: Vec<String>,
}

/// Resolved IPv6 parameters reported by `msbnet`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsbnetReadyIpv6 {
    /// Guest IPv6 address (e.g. `"fd42:6d73:62:2a::2"`).
    pub address: String,

    /// Prefix length (e.g. `64`).
    pub prefix_len: u8,

    /// Gateway IPv6 address (e.g. `"fd42:6d73:62:2a::1"`).
    pub gateway: String,

    /// DNS server addresses exposed to the guest.
    pub dns: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MsbnetReady {
    /// Encode the resolved network parameters as `MSB_NET*` env var key-value pairs.
    ///
    /// Returns a list of `(key, value)` tuples suitable for injection into the
    /// VM exec config.
    pub fn to_env_vars(&self) -> Vec<(&'static str, String)> {
        use std::fmt::Write;

        let mut vars = Vec::with_capacity(3);

        // MSB_NET=iface=eth0,mac=02:5a:7b:13:01:02,mtu=1500
        let net = format!(
            "iface={},mac={},mtu={}",
            self.guest_iface, self.mac, self.mtu
        );
        vars.push((microsandbox_protocol::ENV_NET, net));

        // MSB_NET_IPV4=addr=100.96.1.2/30,gw=100.96.1.1,dns=100.96.1.1
        if let Some(ipv4) = &self.ipv4 {
            let mut val = format!(
                "addr={}/{},gw={}",
                ipv4.address, ipv4.prefix_len, ipv4.gateway
            );
            // Only the first DNS server is emitted — the guest parser
            // supports a single dns= entry per address family.
            if let Some(dns) = ipv4.dns.first() {
                let _ = write!(val, ",dns={dns}");
            }
            vars.push((microsandbox_protocol::ENV_NET_IPV4, val));
        }

        // MSB_NET_IPV6=addr=fd42:6d73:62:2a::2/64,gw=fd42:6d73:62:2a::1,dns=fd42:6d73:62:2a::1
        if let Some(ipv6) = &self.ipv6 {
            let mut val = format!(
                "addr={}/{},gw={}",
                ipv6.address, ipv6.prefix_len, ipv6.gateway
            );
            if let Some(dns) = ipv6.dns.first() {
                let _ = write!(val, ",dns={dns}");
            }
            vars.push((microsandbox_protocol::ENV_NET_IPV6, val));
        }

        vars
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_msbnet_ready_serde_roundtrip() {
        let ready = MsbnetReady {
            pid: 12345,
            backend: "linux_tap".to_string(),
            ifname: "msbtap42".to_string(),
            guest_iface: "eth0".to_string(),
            mac: "02:5a:7b:13:01:02".to_string(),
            mtu: 1500,
            ipv4: Some(MsbnetReadyIpv4 {
                address: "100.96.1.2".to_string(),
                prefix_len: 30,
                gateway: "100.96.1.1".to_string(),
                dns: vec!["100.96.1.1".to_string()],
            }),
            ipv6: Some(MsbnetReadyIpv6 {
                address: "fd42:6d73:62:2a::2".to_string(),
                prefix_len: 64,
                gateway: "fd42:6d73:62:2a::1".to_string(),
                dns: vec!["fd42:6d73:62:2a::1".to_string()],
            }),
            tls: None,
        };

        let json = serde_json::to_string(&ready).unwrap();
        let decoded: MsbnetReady = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.pid, 12345);
        assert_eq!(decoded.backend, "linux_tap");
        assert_eq!(decoded.ifname, "msbtap42");
        assert_eq!(decoded.guest_iface, "eth0");
        assert_eq!(decoded.mtu, 1500);
        assert!(decoded.ipv4.is_some());
        assert!(decoded.ipv6.is_some());
    }

    #[test]
    fn test_msbnet_ready_to_env_vars_dual_stack() {
        let ready = MsbnetReady {
            pid: 1,
            backend: "linux_tap".to_string(),
            ifname: "msbtap42".to_string(),
            guest_iface: "eth0".to_string(),
            mac: "02:5a:7b:13:01:02".to_string(),
            mtu: 1500,
            ipv4: Some(MsbnetReadyIpv4 {
                address: "100.96.1.2".to_string(),
                prefix_len: 30,
                gateway: "100.96.1.1".to_string(),
                dns: vec!["100.96.1.1".to_string()],
            }),
            ipv6: Some(MsbnetReadyIpv6 {
                address: "fd42:6d73:62:2a::2".to_string(),
                prefix_len: 64,
                gateway: "fd42:6d73:62:2a::1".to_string(),
                dns: vec!["fd42:6d73:62:2a::1".to_string()],
            }),
            tls: None,
        };

        let vars = ready.to_env_vars();
        assert_eq!(vars.len(), 3);
        assert_eq!(vars[0].0, "MSB_NET");
        assert_eq!(vars[0].1, "iface=eth0,mac=02:5a:7b:13:01:02,mtu=1500");
        assert_eq!(vars[1].0, "MSB_NET_IPV4");
        assert_eq!(vars[1].1, "addr=100.96.1.2/30,gw=100.96.1.1,dns=100.96.1.1");
        assert_eq!(vars[2].0, "MSB_NET_IPV6");
        assert_eq!(
            vars[2].1,
            "addr=fd42:6d73:62:2a::2/64,gw=fd42:6d73:62:2a::1,dns=fd42:6d73:62:2a::1"
        );
    }

    #[test]
    fn test_msbnet_ready_to_env_vars_ipv4_only() {
        let ready = MsbnetReady {
            pid: 1,
            backend: "linux_tap".to_string(),
            ifname: "msbtap0".to_string(),
            guest_iface: "eth0".to_string(),
            mac: "02:00:00:00:00:01".to_string(),
            mtu: 1500,
            ipv4: Some(MsbnetReadyIpv4 {
                address: "100.96.0.2".to_string(),
                prefix_len: 30,
                gateway: "100.96.0.1".to_string(),
                dns: vec![],
            }),
            ipv6: None,
            tls: None,
        };

        let vars = ready.to_env_vars();
        assert_eq!(vars.len(), 2);
        assert_eq!(vars[1].0, "MSB_NET_IPV4");
        assert_eq!(vars[1].1, "addr=100.96.0.2/30,gw=100.96.0.1");
    }
}
