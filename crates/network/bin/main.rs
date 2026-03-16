//! `msbnet` — privilege-separated networking helper for microsandbox.
//!
//! Lifecycle:
//! 1. Parse CLI args (net_fd, sandbox slot, network config).
//! 2. Privileged bootstrap: create platform backend (TapLink or VmnetLink).
//! 3. Privileged: bind published port listeners.
//! 4. Drop privileges.
//! 5. Start relay tasks on pre-bound listeners.
//! 6. Write `MsbnetReady` JSON to stdout.
//! 7. Enter async packet relay loop.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use clap::Parser;
use ipnetwork::IpNetwork;

use microsandbox_network::config::{
    DnsConfig, InterfaceConfig, Ipv4Config, Ipv6Config, NetworkConfig, PortProtocol, PublishedPort,
};
use microsandbox_network::dns::{DnsFilter, DnsInterceptor};
use microsandbox_network::engine::{self, EngineConfig};
use microsandbox_network::policy::{
    Action, Destination, DestinationGroup, Direction, DnsPinSet, NetworkPolicy, PolicyEngine,
    PortRange, Protocol, Rule,
};
use microsandbox_network::publisher::PortPublisher;

#[cfg(target_os = "linux")]
type HostBackend = microsandbox_network::host::linux::TapLink;

#[cfg(target_os = "macos")]
type HostBackend = microsandbox_network::host::macos::VmnetLink;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// msbnet CLI arguments.
#[derive(Parser)]
#[command(name = "msbnet", about = "Microsandbox networking helper")]
struct Args {
    /// Unixgram socket FD connected to the VM.
    #[arg(long)]
    net_fd: RawFd,

    /// Sandbox slot (database id) for deterministic address allocation.
    #[arg(long)]
    slot: u32,

    // ── Config mode: file ────────────────────────────────────────────────
    /// Path to a serialized network config JSON file.
    #[arg(long, conflicts_with_all = ["config_json", "mac", "mtu", "ipv4_address", "ipv4_prefix_len", "ipv4_gateway", "ipv6_address", "ipv6_prefix_len", "ipv6_gateway", "port", "dns_block_domain", "dns_block_suffix", "no_dns_rebind_protection", "policy_default_action", "rule"])]
    config_file: Option<PathBuf>,

    // ── Config mode: inline JSON ─────────────────────────────────────────
    /// Network config as an inline JSON string.
    #[arg(long, conflicts_with_all = ["config_file", "mac", "mtu", "ipv4_address", "ipv4_prefix_len", "ipv4_gateway", "ipv6_address", "ipv6_prefix_len", "ipv6_gateway", "port", "dns_block_domain", "dns_block_suffix", "no_dns_rebind_protection", "policy_default_action", "rule"])]
    config_json: Option<String>,

    // ── Config mode: individual flags ────────────────────────────────────
    /// Guest MAC address (e.g. aa:bb:cc:dd:ee:ff).
    #[arg(long)]
    mac: Option<String>,

    /// Interface MTU.
    #[arg(long)]
    mtu: Option<u16>,

    /// Guest IPv4 address.
    #[arg(long)]
    ipv4_address: Option<Ipv4Addr>,

    /// IPv4 prefix length (e.g. 30).
    #[arg(long)]
    ipv4_prefix_len: Option<u8>,

    /// IPv4 gateway.
    #[arg(long)]
    ipv4_gateway: Option<Ipv4Addr>,

    /// Guest IPv6 address.
    #[arg(long)]
    ipv6_address: Option<Ipv6Addr>,

    /// IPv6 prefix length (e.g. 64).
    #[arg(long)]
    ipv6_prefix_len: Option<u8>,

    /// IPv6 gateway.
    #[arg(long)]
    ipv6_gateway: Option<Ipv6Addr>,

    /// Published port: HOST_PORT:GUEST_PORT[/PROTO][@BIND_ADDR] (repeatable).
    #[arg(long)]
    port: Vec<String>,

    /// Exact domain to block (repeatable).
    #[arg(long)]
    dns_block_domain: Vec<String>,

    /// Domain suffix to block (repeatable).
    #[arg(long)]
    dns_block_suffix: Vec<String>,

    /// Disable DNS rebinding protection.
    #[arg(long)]
    no_dns_rebind_protection: bool,

    /// Default policy action for unmatched traffic (allow or deny).
    #[arg(long)]
    policy_default_action: Option<String>,

    /// Policy rule in compact format (repeatable):
    /// DIRECTION,DESTINATION,PROTOCOL,PORTS,ACTION
    #[arg(long)]
    rule: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn main() {
    let args = Args::parse();
    let network_config = resolve_config(&args);

    // Privileged bootstrap: create platform backend.
    let (backend, ready_info) = bootstrap(args.slot, &network_config.interface);

    let guest_ipv4 = ready_info
        .ipv4
        .as_ref()
        .and_then(|ipv4| ipv4.address.parse::<Ipv4Addr>().ok());
    let guest_ipv6 = ready_info
        .ipv6
        .as_ref()
        .and_then(|ipv6| ipv6.address.parse::<Ipv6Addr>().ok());

    // Privileged: bind published port listeners before dropping privileges.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    let pending_listeners = rt
        .block_on(PortPublisher::bind(
            &network_config.ports,
            guest_ipv4,
            guest_ipv6,
        ))
        .expect("failed to bind published port listeners");

    // Drop privileges to the real uid/gid.
    drop_privileges().expect("failed to drop privileges");

    // Enter async relay loop (unprivileged).
    let pin_set = Arc::new(RwLock::new(DnsPinSet::new()));

    let gateway_ips = collect_gateway_ips(&ready_info);

    let policy = PolicyEngine::new(network_config.policy.clone(), Arc::clone(&pin_set));

    let dns = DnsInterceptor::new(
        DnsFilter::new(
            network_config.dns.blocked_domains.clone(),
            network_config.dns.blocked_suffixes.clone(),
            network_config.dns.rebind_protection,
        ),
        Arc::clone(&pin_set),
        gateway_ips,
    )
    .expect("failed to initialize DNS interceptor");

    let config = EngineConfig {
        vm_fd: args.net_fd,
        backend: Box::new(backend),
        policy,
        dns,
    };

    // Enter the tokio runtime context so start_from() can call tokio::spawn().
    let _runtime_guard = rt.enter();
    let _publisher = PortPublisher::start_from(pending_listeners);

    // Signal readiness only after all fallible startup work has succeeded.
    let json = serde_json::to_string(&ready_info).expect("failed to serialize MsbnetReady");
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{json}").expect("failed to write MsbnetReady");
    stdout.flush().expect("failed to flush MsbnetReady");

    let exit_code = match rt.block_on(engine::run(config)) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("msbnet: engine error: {e}");
            1
        }
    };

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

/// Resolves the network config from one of three mutually exclusive sources:
/// `--config-file`, `--config-json`, or individual CLI flags.
fn resolve_config(args: &Args) -> NetworkConfig {
    if let Some(ref path) = args.config_file {
        return load_config_file(path);
    }

    if let Some(ref json) = args.config_json {
        return serde_json::from_str(json)
            .unwrap_or_else(|err| panic!("failed to parse --config-json: {err}"));
    }

    // Individual flags mode — build NetworkConfig from discrete args.
    build_config_from_flags(args)
}

/// Loads a NetworkConfig from a JSON file on disk.
fn load_config_file(path: &PathBuf) -> NetworkConfig {
    let data = std::fs::read(path)
        .unwrap_or_else(|err| panic!("failed to read network config {}: {err}", path.display()));
    serde_json::from_slice(&data)
        .unwrap_or_else(|err| panic!("failed to parse network config {}: {err}", path.display()))
}

/// Builds a NetworkConfig from individual CLI flags.
fn build_config_from_flags(args: &Args) -> NetworkConfig {
    let mac = args.mac.as_deref().map(|s| parse_mac(s));

    let ipv4 = match (args.ipv4_address, args.ipv4_prefix_len, args.ipv4_gateway) {
        (Some(address), Some(prefix_len), Some(gateway)) => Some(Ipv4Config {
            address,
            prefix_len,
            gateway,
        }),
        (None, None, None) => None,
        _ => panic!("--ipv4-address, --ipv4-prefix-len, and --ipv4-gateway must all be provided together"),
    };

    let ipv6 = match (args.ipv6_address, args.ipv6_prefix_len, args.ipv6_gateway) {
        (Some(address), Some(prefix_len), Some(gateway)) => Some(Ipv6Config {
            address,
            prefix_len,
            gateway,
        }),
        (None, None, None) => None,
        _ => panic!("--ipv6-address, --ipv6-prefix-len, and --ipv6-gateway must all be provided together"),
    };

    let interface = InterfaceConfig {
        mac,
        mtu: args.mtu,
        ipv4,
        ipv6,
    };

    let ports: Vec<PublishedPort> = args.port.iter().map(|s| parse_port(s)).collect();

    let default_action = args
        .policy_default_action
        .as_deref()
        .map(parse_action)
        .unwrap_or_default();

    let rules: Vec<Rule> = args.rule.iter().map(|s| parse_rule(s)).collect();

    let policy = NetworkPolicy {
        default_action,
        rules,
    };

    let dns = DnsConfig {
        blocked_domains: args.dns_block_domain.clone(),
        blocked_suffixes: args.dns_block_suffix.clone(),
        rebind_protection: !args.no_dns_rebind_protection,
    };

    NetworkConfig {
        enabled: true,
        interface,
        ports,
        policy,
        dns,
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Parsers
//--------------------------------------------------------------------------------------------------

/// Parses a MAC address string like "aa:bb:cc:dd:ee:ff" into `[u8; 6]`.
fn parse_mac(s: &str) -> [u8; 6] {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        panic!("invalid MAC address: {s} (expected aa:bb:cc:dd:ee:ff)");
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] =
            u8::from_str_radix(part, 16).unwrap_or_else(|_| panic!("invalid MAC octet: {part}"));
    }
    mac
}

/// Parses a port spec: `HOST_PORT:GUEST_PORT[/PROTO][@BIND_ADDR]`.
fn parse_port(s: &str) -> PublishedPort {
    // Split off @bind_addr if present.
    let (rest, host_bind) = if let Some(at_pos) = s.rfind('@') {
        let addr: IpAddr = s[at_pos + 1..]
            .parse()
            .unwrap_or_else(|_| panic!("invalid bind address in port spec: {s}"));
        (&s[..at_pos], addr)
    } else {
        (s, IpAddr::V4(Ipv4Addr::LOCALHOST))
    };

    // Split off /proto if present.
    let (rest, protocol) = if let Some(slash_pos) = rest.rfind('/') {
        let proto = match rest[slash_pos + 1..].to_lowercase().as_str() {
            "tcp" => PortProtocol::Tcp,
            "udp" => PortProtocol::Udp,
            other => panic!("invalid protocol in port spec: {other} (expected tcp or udp)"),
        };
        (&rest[..slash_pos], proto)
    } else {
        (rest, PortProtocol::Tcp)
    };

    // Split host:guest ports.
    let parts: Vec<&str> = rest.split(':').collect();
    if parts.len() != 2 {
        panic!("invalid port spec: {s} (expected HOST_PORT:GUEST_PORT)");
    }
    let host_port: u16 = parts[0]
        .parse()
        .unwrap_or_else(|_| panic!("invalid host port: {}", parts[0]));
    let guest_port: u16 = parts[1]
        .parse()
        .unwrap_or_else(|_| panic!("invalid guest port: {}", parts[1]));

    PublishedPort {
        host_port,
        guest_port,
        protocol,
        host_bind,
    }
}

/// Parses an action string: "allow" or "deny".
fn parse_action(s: &str) -> Action {
    match s.to_lowercase().as_str() {
        "allow" => Action::Allow,
        "deny" => Action::Deny,
        other => panic!("invalid action: {other} (expected allow or deny)"),
    }
}

/// Parses a compact rule: `DIRECTION,DESTINATION,PROTOCOL,PORTS,ACTION`.
fn parse_rule(s: &str) -> Rule {
    let parts: Vec<&str> = s.splitn(5, ',').collect();
    if parts.len() != 5 {
        panic!("invalid rule: {s} (expected DIRECTION,DESTINATION,PROTOCOL,PORTS,ACTION)");
    }

    let direction = match parts[0].to_lowercase().as_str() {
        "outbound" => Direction::Outbound,
        "inbound" => Direction::Inbound,
        other => panic!("invalid direction: {other} (expected outbound or inbound)"),
    };

    let destination = parse_destination(parts[1]);

    let protocol = match parts[2].to_lowercase().as_str() {
        "any" => None,
        "tcp" => Some(Protocol::Tcp),
        "udp" => Some(Protocol::Udp),
        "icmpv4" => Some(Protocol::Icmpv4),
        "icmpv6" => Some(Protocol::Icmpv6),
        other => panic!("invalid protocol: {other} (expected any, tcp, udp, icmpv4, or icmpv6)"),
    };

    let ports = match parts[3].to_lowercase().as_str() {
        "any" => None,
        port_str => {
            if let Some(dash_pos) = port_str.find('-') {
                let start: u16 = port_str[..dash_pos]
                    .parse()
                    .unwrap_or_else(|_| panic!("invalid port range start: {port_str}"));
                let end: u16 = port_str[dash_pos + 1..]
                    .parse()
                    .unwrap_or_else(|_| panic!("invalid port range end: {port_str}"));
                Some(PortRange::range(start, end))
            } else {
                let port: u16 = port_str
                    .parse()
                    .unwrap_or_else(|_| panic!("invalid port: {port_str}"));
                Some(PortRange::single(port))
            }
        }
    };

    let action = parse_action(parts[4]);

    Rule {
        direction,
        destination,
        protocol,
        ports,
        action,
    }
}

/// Parses a destination: `any`, `cidr:X`, `domain:X`, `suffix:X`, `group:X`.
fn parse_destination(s: &str) -> Destination {
    let lower = s.to_lowercase();
    if lower == "any" {
        return Destination::Any;
    }

    if let Some(rest) = lower.strip_prefix("cidr:") {
        let network: IpNetwork = rest
            .parse()
            .unwrap_or_else(|_| panic!("invalid CIDR: {rest}"));
        return Destination::Cidr(network);
    }

    if let Some(rest) = lower.strip_prefix("domain:") {
        return Destination::Domain(rest.to_string());
    }

    if let Some(rest) = lower.strip_prefix("suffix:") {
        return Destination::DomainSuffix(rest.to_string());
    }

    if let Some(rest) = lower.strip_prefix("group:") {
        let group = match rest {
            "loopback" => DestinationGroup::Loopback,
            "private" => DestinationGroup::Private,
            "link-local" => DestinationGroup::LinkLocal,
            "metadata" => DestinationGroup::Metadata,
            "multicast" => DestinationGroup::Multicast,
            other => panic!("invalid destination group: {other} (expected loopback, private, link-local, metadata, or multicast)"),
        };
        return Destination::Group(group);
    }

    panic!("invalid destination: {s} (expected any, cidr:X, domain:X, suffix:X, or group:X)");
}

//--------------------------------------------------------------------------------------------------
// Functions: Bootstrap
//--------------------------------------------------------------------------------------------------

/// Creates the platform backend and returns the backend handle + ready info.
#[cfg(target_os = "linux")]
fn bootstrap(
    slot: u32,
    interface: &InterfaceConfig,
) -> (HostBackend, microsandbox_network::ready::MsbnetReady) {
    let tap = microsandbox_network::host::linux::TapLink::create(slot, interface)
        .expect("failed to create TAP device");

    let ready = tap.ready_info();
    (tap, ready)
}

/// Creates the platform backend and returns the backend handle + ready info.
#[cfg(target_os = "macos")]
fn bootstrap(
    _slot: u32,
    interface: &InterfaceConfig,
) -> (HostBackend, microsandbox_network::ready::MsbnetReady) {
    let vmnet = microsandbox_network::host::macos::VmnetLink::create(interface)
        .expect("failed to create vmnet interface");

    let ready = vmnet.ready_info();
    (vmnet, ready)
}

/// Drops privileges to the real uid/gid.
fn drop_privileges() -> std::io::Result<()> {
    use nix::unistd::{Gid, Uid};

    // Only drop if running as root (effective uid 0).
    if !nix::unistd::geteuid().is_root() {
        return Ok(());
    }

    let target_gid = std::env::var("SUDO_GID")
        .ok()
        .and_then(|gid| gid.parse::<u32>().ok())
        .map(Gid::from_raw)
        .unwrap_or_else(nix::unistd::getgid);
    let target_uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|uid| uid.parse::<u32>().ok())
        .map(Uid::from_raw)
        .unwrap_or_else(nix::unistd::getuid);

    nix::unistd::setgid(target_gid).map_err(std::io::Error::other)?;
    nix::unistd::setuid(target_uid).map_err(std::io::Error::other)?;

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac() {
        let mac = parse_mac("aa:bb:cc:dd:ee:ff");
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    #[should_panic(expected = "invalid MAC address")]
    fn test_parse_mac_invalid() {
        parse_mac("aa:bb:cc");
    }

    #[test]
    fn test_parse_port_basic() {
        let port = parse_port("8080:80");
        assert_eq!(port.host_port, 8080);
        assert_eq!(port.guest_port, 80);
        assert_eq!(port.protocol, PortProtocol::Tcp);
        assert_eq!(port.host_bind, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn test_parse_port_udp() {
        let port = parse_port("5353:53/udp");
        assert_eq!(port.host_port, 5353);
        assert_eq!(port.guest_port, 53);
        assert_eq!(port.protocol, PortProtocol::Udp);
    }

    #[test]
    fn test_parse_port_with_bind() {
        let port = parse_port("8080:80/tcp@0.0.0.0");
        assert_eq!(port.host_port, 8080);
        assert_eq!(port.guest_port, 80);
        assert_eq!(port.protocol, PortProtocol::Tcp);
        assert_eq!(port.host_bind, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn test_parse_port_bind_no_proto() {
        let port = parse_port("8080:80@0.0.0.0");
        assert_eq!(port.host_port, 8080);
        assert_eq!(port.guest_port, 80);
        assert_eq!(port.protocol, PortProtocol::Tcp);
        assert_eq!(port.host_bind, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn test_parse_action() {
        assert_eq!(parse_action("allow"), Action::Allow);
        assert_eq!(parse_action("Deny"), Action::Deny);
    }

    #[test]
    #[should_panic(expected = "invalid action")]
    fn test_parse_action_invalid() {
        parse_action("reject");
    }

    #[test]
    fn test_parse_rule_basic() {
        let rule = parse_rule("outbound,any,any,any,allow");
        assert_eq!(rule.direction, Direction::Outbound);
        assert!(matches!(rule.destination, Destination::Any));
        assert!(rule.protocol.is_none());
        assert!(rule.ports.is_none());
        assert_eq!(rule.action, Action::Allow);
    }

    #[test]
    fn test_parse_rule_cidr() {
        let rule = parse_rule("outbound,cidr:10.0.0.0/8,tcp,80-443,deny");
        assert_eq!(rule.direction, Direction::Outbound);
        assert!(matches!(rule.destination, Destination::Cidr(_)));
        assert_eq!(rule.protocol, Some(Protocol::Tcp));
        let ports = rule.ports.unwrap();
        assert_eq!(ports.start, 80);
        assert_eq!(ports.end, 443);
        assert_eq!(rule.action, Action::Deny);
    }

    #[test]
    fn test_parse_rule_domain() {
        let rule = parse_rule("outbound,domain:evil.com,any,any,deny");
        assert!(matches!(rule.destination, Destination::Domain(ref d) if d == "evil.com"));
    }

    #[test]
    fn test_parse_rule_suffix() {
        let rule = parse_rule("inbound,suffix:.example.com,udp,53,allow");
        assert_eq!(rule.direction, Direction::Inbound);
        assert!(
            matches!(rule.destination, Destination::DomainSuffix(ref s) if s == ".example.com")
        );
        assert_eq!(rule.protocol, Some(Protocol::Udp));
        let ports = rule.ports.unwrap();
        assert_eq!(ports.start, 53);
        assert_eq!(ports.end, 53);
    }

    #[test]
    fn test_parse_rule_group() {
        let rule = parse_rule("outbound,group:metadata,any,any,deny");
        assert!(matches!(
            rule.destination,
            Destination::Group(DestinationGroup::Metadata)
        ));
    }

    #[test]
    fn test_parse_destination_groups() {
        assert!(matches!(
            parse_destination("group:loopback"),
            Destination::Group(DestinationGroup::Loopback)
        ));
        assert!(matches!(
            parse_destination("group:private"),
            Destination::Group(DestinationGroup::Private)
        ));
        assert!(matches!(
            parse_destination("group:link-local"),
            Destination::Group(DestinationGroup::LinkLocal)
        ));
        assert!(matches!(
            parse_destination("group:multicast"),
            Destination::Group(DestinationGroup::Multicast)
        ));
    }

    #[test]
    #[should_panic(expected = "invalid destination")]
    fn test_parse_destination_invalid() {
        parse_destination("unknown:foo");
    }

    #[test]
    #[should_panic(expected = "invalid rule")]
    fn test_parse_rule_wrong_parts() {
        parse_rule("outbound,any,any");
    }

    #[test]
    fn test_config_json_roundtrip() {
        let config = NetworkConfig {
            enabled: true,
            interface: InterfaceConfig {
                mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
                mtu: Some(1500),
                ipv4: Some(Ipv4Config {
                    address: "10.0.0.2".parse().unwrap(),
                    prefix_len: 30,
                    gateway: "10.0.0.1".parse().unwrap(),
                }),
                ipv6: None,
            },
            ports: vec![PublishedPort {
                host_port: 8080,
                guest_port: 80,
                protocol: PortProtocol::Tcp,
                host_bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            }],
            policy: NetworkPolicy {
                default_action: Action::Allow,
                rules: vec![Rule::deny_outbound(Destination::Group(
                    DestinationGroup::Metadata,
                ))],
            },
            dns: DnsConfig {
                blocked_domains: vec!["evil.com".into()],
                blocked_suffixes: vec![],
                rebind_protection: true,
            },
        };

        let json = serde_json::to_string(&config).unwrap();
        let parsed: NetworkConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.enabled, config.enabled);
        assert_eq!(parsed.interface.mtu, Some(1500));
        assert_eq!(parsed.ports.len(), 1);
        assert_eq!(parsed.ports[0].host_port, 8080);
        assert_eq!(parsed.dns.blocked_domains, vec!["evil.com"]);
        assert_eq!(parsed.policy.rules.len(), 1);
    }
}

fn collect_gateway_ips(ready_info: &microsandbox_network::ready::MsbnetReady) -> Vec<IpAddr> {
    let mut ips = Vec::new();

    if let Some(ref ipv4) = ready_info.ipv4 {
        if let Ok(ip) = ipv4.gateway.parse() {
            ips.push(IpAddr::V4(ip));
        }
    }

    if let Some(ref ipv6) = ready_info.ipv6 {
        if let Ok(ip) = ipv6.gateway.parse() {
            ips.push(IpAddr::V6(ip));
        }
    }

    ips
}
