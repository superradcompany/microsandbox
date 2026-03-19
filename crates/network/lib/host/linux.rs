//! Linux host backend: TAP device + kernel forwarding/NAT via nftables.
//!
//! Creates one TAP device per sandbox, assigns gateway addresses, enables
//! IP forwarding, and registers the sandbox in shared nftables sets.

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};

use ipnetwork::{Ipv4Network, Ipv6Network};

use super::FrameTransport;
use crate::{
    config::InterfaceConfig,
    ready::{MsbnetReady, MsbnetReadyIpv4, MsbnetReadyIpv6},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// IPv4 base pool: `100.96.0.0/11`
const IPV4_POOL_BASE: u32 = 0x6460_0000; // 100.96.0.0

/// IPv6 base prefix: `fd42:6d73:62::`
const IPV6_PREFIX: [u8; 6] = [0xfd, 0x42, 0x6d, 0x73, 0x00, 0x62];

/// TAP device name prefix.
const TAP_PREFIX: &str = "msbtap";

/// TUN/TAP ioctl request code.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

/// IFF_TAP — TAP device (layer 2).
const IFF_TAP: libc::c_short = 0x0002;

/// IFF_NO_PI — no packet information header.
const IFF_NO_PI: libc::c_short = 0x1000;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// TAP-based network backend for Linux.
///
/// Holds the TAP file descriptor and the resolved network parameters.
/// On drop, cleans up nftables set elements and removes the TAP device.
pub struct TapLink {
    /// TAP device file descriptor.
    pub tap_fd: OwnedFd,

    /// TAP interface name (e.g. `msbtap42`).
    pub ifname: String,

    /// Gateway IPv4 address (assigned to the TAP interface).
    pub gateway_v4: Ipv4Addr,

    /// Guest IPv4 address.
    pub guest_v4: Ipv4Addr,

    /// IPv4 prefix length.
    pub prefix_v4: u8,

    /// Gateway IPv6 address (assigned to the TAP interface).
    pub gateway_v6: Ipv6Addr,

    /// Guest IPv6 address.
    pub guest_v6: Ipv6Addr,

    /// IPv6 prefix length.
    pub prefix_v6: u8,

    /// MTU.
    pub mtu: u16,

    /// Guest MAC address.
    pub mac: [u8; 6],

    /// Sandbox IPv4 subnet registered in nftables.
    pub subnet_v4: String,

    /// Sandbox IPv6 subnet registered in nftables.
    pub subnet_v6: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TapLink {
    /// Creates a new TAP device and configures host networking for the given sandbox slot.
    ///
    /// Privileged operations (must run as root):
    /// 1. Create TAP device
    /// 2. Assign gateway IPv4/IPv6 addresses to the TAP interface
    /// 3. Set MTU
    /// 4. Bring interface up
    /// 5. Enable IP forwarding (sysctl)
    /// 6. Ensure shared nftables table/chains/sets exist
    /// 7. Register this sandbox in the nftables sets
    pub fn create(slot: u32, interface: &InterfaceConfig) -> std::io::Result<Self> {
        // The IPv6 pool (fd42:6d73:62::/48) holds 2^16 /64 subnets = 65536 slots.
        // The IPv4 pool (100.96.0.0/11) is larger (2^19) but must be capped to the
        // IPv6 limit to keep both address families valid.
        const MAX_SLOT: u32 = 0xFFFF;
        if slot > MAX_SLOT {
            return Err(std::io::Error::other(format!(
                "sandbox slot {slot} exceeds maximum ({MAX_SLOT})"
            )));
        }

        let ifname = format!("{TAP_PREFIX}{slot}");
        let (gateway_v4, guest_v4, prefix_v4) = interface
            .ipv4
            .as_ref()
            .map(|ipv4| (ipv4.gateway, ipv4.address, ipv4.prefix_len))
            .unwrap_or_else(|| compute_ipv4_addresses(slot));
        let (gateway_v6, guest_v6, prefix_v6) = interface
            .ipv6
            .as_ref()
            .map(|ipv6| (ipv6.gateway, ipv6.address, ipv6.prefix_len))
            .unwrap_or_else(|| compute_ipv6_addresses(slot));
        let mac = interface.mac.unwrap_or_else(|| compute_mac(slot));
        let mtu = interface.mtu.unwrap_or(1500u16);
        if !(68..=1500).contains(&mtu) {
            return Err(std::io::Error::other(format!(
                "MTU {mtu} is outside supported range (68–1500)"
            )));
        }
        let subnet_v4 = subnet_v4_cidr(guest_v4, prefix_v4)?;
        let subnet_v6 = subnet_v6_cidr(guest_v6, prefix_v6)?;

        // 1. Create TAP device.
        let tap_fd = create_tap_device(&ifname)?;

        // 2-4. Configure TAP interface.
        run_ip_cmd(&[
            "addr",
            "add",
            &format!("{gateway_v4}/{prefix_v4}"),
            "dev",
            &ifname,
        ])?;
        run_ip_cmd(&[
            "addr",
            "add",
            &format!("{gateway_v6}/{prefix_v6}"),
            "dev",
            &ifname,
        ])?;
        run_ip_cmd(&["link", "set", &ifname, "mtu", &mtu.to_string(), "up"])?;

        // 5. Enable IP forwarding.
        enable_ip_forwarding()?;

        // 6-7. nftables setup.
        ensure_nftables_shared()?;
        add_nftables_elements(&ifname, &subnet_v4, &subnet_v6)?;

        Ok(Self {
            tap_fd,
            ifname,
            gateway_v4,
            guest_v4,
            prefix_v4,
            gateway_v6,
            guest_v6,
            prefix_v6,
            mtu,
            mac,
            subnet_v4,
            subnet_v6,
        })
    }

    /// Builds the `MsbnetReady` payload from the resolved parameters.
    pub fn ready_info(&self) -> MsbnetReady {
        MsbnetReady {
            pid: std::process::id(),
            backend: "linux_tap".to_string(),
            ifname: self.ifname.clone(),
            guest_iface: "eth0".to_string(),
            mac: format_mac(&self.mac),
            mtu: self.mtu,
            ipv4: Some(MsbnetReadyIpv4 {
                address: self.guest_v4.to_string(),
                prefix_len: self.prefix_v4,
                gateway: self.gateway_v4.to_string(),
                dns: vec![self.gateway_v4.to_string()],
            }),
            ipv6: Some(MsbnetReadyIpv6 {
                address: self.guest_v6.to_string(),
                prefix_len: self.prefix_v6,
                gateway: self.gateway_v6.to_string(),
                dns: vec![self.gateway_v6.to_string()],
            }),
            tls: None,
        }
    }

    /// Returns the raw TAP file descriptor.
    pub fn as_raw_fd(&self) -> RawFd {
        self.tap_fd.as_raw_fd()
    }

    /// Removes nftables set elements and deletes the TAP device.
    pub fn cleanup(&self) {
        // Best-effort cleanup — ignore errors.
        let _ = remove_nftables_elements(&self.ifname, &self.subnet_v4, &self.subnet_v6);
        let _ = run_ip_cmd(&["link", "delete", &self.ifname]);
    }
}

impl Drop for TapLink {
    fn drop(&mut self) {
        self.cleanup();
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl FrameTransport for TapLink {
    fn ready_fd(&self) -> RawFd {
        self.tap_fd.as_raw_fd()
    }

    fn read_frame(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::read(self.tap_fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    fn write_frame(&self, buf: &[u8]) -> std::io::Result<()> {
        let n = unsafe { libc::write(self.tap_fd.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Address Computation
//--------------------------------------------------------------------------------------------------

/// Computes IPv4 addresses from a slot index.
///
/// Each slot gets a `/30` subnet from `100.96.0.0/11`.
/// Gateway = first usable host, guest = second usable host.
fn compute_ipv4_addresses(slot: u32) -> (Ipv4Addr, Ipv4Addr, u8) {
    let subnet_base = IPV4_POOL_BASE + (slot * 4);
    let gateway = Ipv4Addr::from(subnet_base + 1);
    let guest = Ipv4Addr::from(subnet_base + 2);
    (gateway, guest, 30)
}

/// Computes IPv6 addresses from a slot index.
///
/// Each slot gets a `/64` prefix from `fd42:6d73:62::/48`.
/// Gateway = `::1`, guest = `::2`.
fn compute_ipv6_addresses(slot: u32) -> (Ipv6Addr, Ipv6Addr, u8) {
    let prefix = format_ipv6_prefix(slot);
    let gateway: Ipv6Addr = format!("{prefix}::1").parse().unwrap();
    let guest: Ipv6Addr = format!("{prefix}::2").parse().unwrap();
    (gateway, guest, 64)
}

/// Formats the IPv6 prefix for a given slot.
fn format_ipv6_prefix(slot: u32) -> String {
    format!(
        "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:x}",
        IPV6_PREFIX[0],
        IPV6_PREFIX[1],
        IPV6_PREFIX[2],
        IPV6_PREFIX[3],
        IPV6_PREFIX[4],
        IPV6_PREFIX[5],
        slot
    )
}

fn subnet_v4_cidr(addr: Ipv4Addr, prefix: u8) -> std::io::Result<String> {
    let network = Ipv4Network::new(addr, prefix).map_err(std::io::Error::other)?;
    Ok(format!("{}/{}", network.network(), prefix))
}

fn subnet_v6_cidr(addr: Ipv6Addr, prefix: u8) -> std::io::Result<String> {
    let network = Ipv6Network::new(addr, prefix).map_err(std::io::Error::other)?;
    Ok(format!("{}/{}", network.network(), prefix))
}

/// Computes a deterministic MAC address from a slot index.
///
/// Uses the locally-administered, unicast prefix `02:5a:7b` followed by
/// 3 bytes derived from the slot.
fn compute_mac(slot: u32) -> [u8; 6] {
    let slot_bytes = slot.to_be_bytes();
    [
        0x02,
        0x5a,
        0x7b,
        slot_bytes[1],
        slot_bytes[2],
        slot_bytes[3],
    ]
}

/// Formats a MAC address as `AA:BB:CC:DD:EE:FF`.
fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

//--------------------------------------------------------------------------------------------------
// Functions: TAP Device
//--------------------------------------------------------------------------------------------------

/// Creates a TAP device with the given name.
fn create_tap_device(ifname: &str) -> std::io::Result<OwnedFd> {
    let fd = unsafe {
        libc::open(
            c"/dev/net/tun".as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = ifname.as_bytes();
    if name_bytes.len() >= libc::IFNAMSIZ {
        unsafe { libc::close(fd) };
        return Err(std::io::Error::other("interface name too long"));
    }
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            ifr.ifr_name.as_mut_ptr().cast(),
            name_bytes.len(),
        );
        ifr.ifr_ifru.ifru_flags = IFF_TAP | IFF_NO_PI;
    }

    if unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) } < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

//--------------------------------------------------------------------------------------------------
// Functions: IP Command
//--------------------------------------------------------------------------------------------------

/// Runs an `ip` command with the given arguments.
fn run_ip_cmd(args: &[&str]) -> std::io::Result<()> {
    let output = std::process::Command::new("ip").args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(std::io::Error::other(format!(
            "ip {} failed: {stderr}",
            args.join(" ")
        )));
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: IP Forwarding
//--------------------------------------------------------------------------------------------------

/// Enables IPv4 and IPv6 forwarding via sysctl.
fn enable_ip_forwarding() -> std::io::Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
    std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")?;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: nftables
//--------------------------------------------------------------------------------------------------

/// Ensures the shared `inet msb` table, chains, sets, and rules exist.
///
/// Idempotent — checks for existing table before adding rules to avoid
/// duplicates when multiple msbnet processes start concurrently.
fn ensure_nftables_shared() -> std::io::Result<()> {
    // Check if the table already exists. If so, skip rule creation —
    // `add table/chain/set` are idempotent, but `add rule` is not
    // (it appends duplicates).
    let table_exists = std::process::Command::new("nft")
        .args(["list", "table", "inet", "msb"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if table_exists {
        return Ok(());
    }

    // Create table, sets, chains, and rules atomically via nft -f.
    let script = "\
        add table inet msb\n\
        add set inet msb ifaces { type ifname; }\n\
        add set inet msb nets_v4 { type ipv4_addr; flags interval; }\n\
        add set inet msb nets_v6 { type ipv6_addr; flags interval; }\n\
        add chain inet msb forward { type filter hook forward priority 0; policy drop; }\n\
        add rule inet msb forward iif @ifaces accept\n\
        add rule inet msb forward oif @ifaces ct state established,related accept\n\
        add chain inet msb postrouting { type nat hook postrouting priority 100; }\n\
        add rule inet msb postrouting ip saddr @nets_v4 masquerade\n\
        add rule inet msb postrouting ip6 saddr @nets_v6 masquerade\n";

    let output = std::process::Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(script.as_bytes())?;
            child.wait_with_output()
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // If another process created the table between our check and our
        // create, the atomic script may partially fail. Re-check existence.
        let exists_now = std::process::Command::new("nft")
            .args(["list", "table", "inet", "msb"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if !exists_now {
            return Err(std::io::Error::other(format!("nft setup failed: {stderr}")));
        }
    }

    Ok(())
}

/// Adds set elements for a sandbox atomically via `nft -f`.
fn add_nftables_elements(ifname: &str, subnet_v4: &str, subnet_v6: &str) -> std::io::Result<()> {
    let script = format!(
        "add element inet msb ifaces {{ \"{ifname}\" }}\n\
         add element inet msb nets_v4 {{ {subnet_v4} }}\n\
         add element inet msb nets_v6 {{ {subnet_v6} }}\n"
    );
    nft_script(&script)
}

/// Removes set elements for a sandbox atomically via `nft -f`.
fn remove_nftables_elements(ifname: &str, subnet_v4: &str, subnet_v6: &str) -> std::io::Result<()> {
    let script = format!(
        "delete element inet msb ifaces {{ \"{ifname}\" }}\n\
         delete element inet msb nets_v4 {{ {subnet_v4} }}\n\
         delete element inet msb nets_v6 {{ {subnet_v6} }}\n"
    );
    nft_script(&script)
}

/// Runs an `nft -f` script atomically.
pub(crate) fn nft_script(script: &str) -> std::io::Result<()> {
    let output = std::process::Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(script.as_bytes())?;
            child.wait_with_output()
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(std::io::Error::other(format!(
            "nft script failed: {stderr}"
        )));
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_ipv4_slot_0() {
        let (gw, guest, prefix) = compute_ipv4_addresses(0);
        assert_eq!(gw, Ipv4Addr::new(100, 96, 0, 1));
        assert_eq!(guest, Ipv4Addr::new(100, 96, 0, 2));
        assert_eq!(prefix, 30);
    }

    #[test]
    fn test_compute_ipv4_slot_1() {
        let (gw, guest, _) = compute_ipv4_addresses(1);
        assert_eq!(gw, Ipv4Addr::new(100, 96, 0, 5));
        assert_eq!(guest, Ipv4Addr::new(100, 96, 0, 6));
    }

    #[test]
    fn test_compute_ipv4_slot_42() {
        let (gw, guest, _) = compute_ipv4_addresses(42);
        assert_eq!(gw, Ipv4Addr::new(100, 96, 0, 169));
        assert_eq!(guest, Ipv4Addr::new(100, 96, 0, 170));
    }

    #[test]
    fn test_compute_ipv6_slot_0() {
        let (gw, guest, prefix) = compute_ipv6_addresses(0);
        assert_eq!(gw, "fd42:6d73:0062:0::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(guest, "fd42:6d73:0062:0::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(prefix, 64);
    }

    #[test]
    fn test_compute_ipv6_slot_42() {
        let (gw, guest, _) = compute_ipv6_addresses(42);
        assert_eq!(gw, "fd42:6d73:0062:2a::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(guest, "fd42:6d73:0062:2a::2".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_compute_mac() {
        let mac = compute_mac(42);
        assert_eq!(mac, [0x02, 0x5a, 0x7b, 0x00, 0x00, 0x2a]);
    }

    #[test]
    fn test_format_mac() {
        assert_eq!(
            format_mac(&[0x02, 0x5a, 0x7b, 0x13, 0x01, 0x02]),
            "02:5a:7b:13:01:02"
        );
    }

    #[test]
    fn test_subnet_v4_cidr_uses_network_base() {
        assert_eq!(
            subnet_v4_cidr(Ipv4Addr::new(100, 96, 0, 2), 30).unwrap(),
            "100.96.0.0/30"
        );
    }

    #[test]
    fn test_subnet_v6_cidr_uses_network_base() {
        assert_eq!(
            subnet_v6_cidr("fd42:6d73:62:2a::2".parse().unwrap(), 64).unwrap(),
            "fd42:6d73:62:2a::/64"
        );
    }

    #[test]
    fn test_compute_ipv6_max_slot() {
        // Slot 0xFFFF is the maximum — must produce a valid IPv6 address.
        let (gw, guest, prefix) = compute_ipv6_addresses(0xFFFF);
        assert_eq!(gw, "fd42:6d73:0062:ffff::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(guest, "fd42:6d73:0062:ffff::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(prefix, 64);
    }
}
