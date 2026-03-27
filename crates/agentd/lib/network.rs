//! Guest-side network configuration from `MSB_NET*` environment variables.
//!
//! Configures the guest network interface using ioctls and netlink, following
//! the parameters from host.
//!
//! This module only performs real work on Linux. On other platforms, it is a no-op.

#[cfg(any(target_os = "linux", test))]
use std::net::{Ipv4Addr, Ipv6Addr};

#[cfg(target_os = "linux")]
use crate::error::AgentdError;
use crate::error::AgentdResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Parsed `MSB_NET` specification.
#[derive(Debug)]
#[cfg(target_os = "linux")]
struct NetSpec<'a> {
    iface: &'a str,
    mac: [u8; 6],
    mtu: u16,
}

/// Parsed `MSB_NET_IPV4` specification.
#[derive(Debug)]
#[cfg(target_os = "linux")]
struct NetIpv4Spec {
    address: Ipv4Addr,
    prefix_len: u8,
    gateway: Ipv4Addr,
    dns: Option<Ipv4Addr>,
}

/// Parsed `MSB_NET_IPV6` specification.
#[derive(Debug)]
#[cfg(target_os = "linux")]
struct NetIpv6Spec {
    address: Ipv6Addr,
    prefix_len: u8,
    gateway: Ipv6Addr,
    dns: Option<Ipv6Addr>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Applies network configuration from `MSB_NET*` environment variables.
///
/// Always provisions loopback and a runtime `/etc/hosts`, even when no
/// external network interface is requested. Missing `MSB_NET` is not an error
/// (no networking requested). Parse failures and configuration failures are
/// hard errors.
#[cfg(target_os = "linux")]
pub fn apply_network_config() -> AgentdResult<()> {
    linux::configure_loopback()?;

    let val = match std::env::var(microsandbox_protocol::ENV_NET) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            linux::write_hosts_file()?;
            return Ok(());
        }
    };

    let net = parse_net(&val)?;

    // Parse optional IPv4 config.
    let ipv4 = match std::env::var(microsandbox_protocol::ENV_NET_IPV4) {
        Ok(v) if !v.is_empty() => Some(parse_net_ipv4(&v)?),
        _ => None,
    };

    // Parse optional IPv6 config.
    let ipv6 = match std::env::var(microsandbox_protocol::ENV_NET_IPV6) {
        Ok(v) if !v.is_empty() => Some(parse_net_ipv6(&v)?),
        _ => None,
    };

    linux::write_hosts_file()?;
    linux::configure_interface(&net, ipv4.as_ref(), ipv6.as_ref())
}

/// No-op on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn apply_network_config() -> AgentdResult<()> {
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn default_hosts_file_contents() -> String {
    concat!(
        "127.0.0.1\tlocalhost\n",
        "::1\tlocalhost ip6-localhost ip6-loopback\n",
        "fe00::\tip6-localnet\n",
        "ff00::\tip6-mcastprefix\n",
        "ff02::1\tip6-allnodes\n",
        "ff02::2\tip6-allrouters\n",
    )
    .into()
}

#[cfg(target_os = "linux")]
/// Parses `MSB_NET` value: `iface=NAME,mac=AA:BB:CC:DD:EE:FF,mtu=N`
fn parse_net(val: &str) -> AgentdResult<NetSpec<'_>> {
    let mut iface = None;
    let mut mac = None;
    let mut mtu = 1500u16;

    for part in val.split(',') {
        if let Some(v) = part.strip_prefix("iface=") {
            iface = Some(v);
        } else if let Some(v) = part.strip_prefix("mac=") {
            mac = Some(parse_mac(v)?);
        } else if let Some(v) = part.strip_prefix("mtu=") {
            mtu = v
                .parse()
                .map_err(|_| AgentdError::Init(format!("invalid MTU: {v}")))?;
        } else {
            return Err(AgentdError::Init(format!("unknown MSB_NET option: {part}")));
        }
    }

    let iface = iface.ok_or_else(|| AgentdError::Init("MSB_NET missing iface=".into()))?;
    let mac = mac.ok_or_else(|| AgentdError::Init("MSB_NET missing mac=".into()))?;

    Ok(NetSpec { iface, mac, mtu })
}

#[cfg(target_os = "linux")]
/// Parses `MSB_NET_IPV4` value: `addr=A.B.C.D/N,gw=A.B.C.D[,dns=A.B.C.D]`
fn parse_net_ipv4(val: &str) -> AgentdResult<NetIpv4Spec> {
    let mut address = None;
    let mut prefix_len = None;
    let mut gateway = None;
    let mut dns = None;

    for part in val.split(',') {
        if let Some(v) = part.strip_prefix("addr=") {
            let (addr, prefix) = parse_cidr_v4(v)?;
            address = Some(addr);
            prefix_len = Some(prefix);
        } else if let Some(v) = part.strip_prefix("gw=") {
            gateway = Some(
                v.parse::<Ipv4Addr>()
                    .map_err(|_| AgentdError::Init(format!("invalid IPv4 gateway: {v}")))?,
            );
        } else if let Some(v) = part.strip_prefix("dns=") {
            dns = Some(
                v.parse::<Ipv4Addr>()
                    .map_err(|_| AgentdError::Init(format!("invalid IPv4 DNS: {v}")))?,
            );
        } else {
            return Err(AgentdError::Init(format!(
                "unknown MSB_NET_IPV4 option: {part}"
            )));
        }
    }

    let address = address.ok_or_else(|| AgentdError::Init("MSB_NET_IPV4 missing addr=".into()))?;
    let prefix_len =
        prefix_len.ok_or_else(|| AgentdError::Init("MSB_NET_IPV4 missing addr=".into()))?;
    let gateway = gateway.ok_or_else(|| AgentdError::Init("MSB_NET_IPV4 missing gw=".into()))?;

    Ok(NetIpv4Spec {
        address,
        prefix_len,
        gateway,
        dns,
    })
}

#[cfg(target_os = "linux")]
/// Parses `MSB_NET_IPV6` value: `addr=ADDR/N,gw=ADDR[,dns=ADDR]`
fn parse_net_ipv6(val: &str) -> AgentdResult<NetIpv6Spec> {
    let mut address = None;
    let mut prefix_len = None;
    let mut gateway = None;
    let mut dns = None;

    for part in val.split(',') {
        if let Some(v) = part.strip_prefix("addr=") {
            let (addr, prefix) = parse_cidr_v6(v)?;
            address = Some(addr);
            prefix_len = Some(prefix);
        } else if let Some(v) = part.strip_prefix("gw=") {
            gateway = Some(
                v.parse::<Ipv6Addr>()
                    .map_err(|_| AgentdError::Init(format!("invalid IPv6 gateway: {v}")))?,
            );
        } else if let Some(v) = part.strip_prefix("dns=") {
            dns = Some(
                v.parse::<Ipv6Addr>()
                    .map_err(|_| AgentdError::Init(format!("invalid IPv6 DNS: {v}")))?,
            );
        } else {
            return Err(AgentdError::Init(format!(
                "unknown MSB_NET_IPV6 option: {part}"
            )));
        }
    }

    let address = address.ok_or_else(|| AgentdError::Init("MSB_NET_IPV6 missing addr=".into()))?;
    let prefix_len =
        prefix_len.ok_or_else(|| AgentdError::Init("MSB_NET_IPV6 missing addr=".into()))?;
    let gateway = gateway.ok_or_else(|| AgentdError::Init("MSB_NET_IPV6 missing gw=".into()))?;

    Ok(NetIpv6Spec {
        address,
        prefix_len,
        gateway,
        dns,
    })
}

#[cfg(target_os = "linux")]
/// Parses a MAC address string like `02:5a:7b:13:01:02`.
fn parse_mac(s: &str) -> AgentdResult<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut len = 0usize;
    for (i, part) in s.split(':').enumerate() {
        if i >= 6 {
            return Err(AgentdError::Init(format!("invalid MAC address: {s}")));
        }
        mac[i] = u8::from_str_radix(part, 16)
            .map_err(|_| AgentdError::Init(format!("invalid MAC octet: {part}")))?;
        len = i + 1;
    }
    if len != 6 {
        return Err(AgentdError::Init(format!("invalid MAC address: {s}")));
    }
    Ok(mac)
}

#[cfg(target_os = "linux")]
/// Parses an IPv4 CIDR like `100.96.1.2/30`.
fn parse_cidr_v4(s: &str) -> AgentdResult<(Ipv4Addr, u8)> {
    let (addr_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| AgentdError::Init(format!("invalid IPv4 CIDR (missing /): {s}")))?;
    let addr = addr_str
        .parse::<Ipv4Addr>()
        .map_err(|_| AgentdError::Init(format!("invalid IPv4 address: {addr_str}")))?;
    let prefix = prefix_str
        .parse::<u8>()
        .map_err(|_| AgentdError::Init(format!("invalid IPv4 prefix length: {prefix_str}")))?;
    if prefix > 32 {
        return Err(AgentdError::Init(format!(
            "IPv4 prefix length out of range (0-32): {prefix}"
        )));
    }
    Ok((addr, prefix))
}

#[cfg(target_os = "linux")]
/// Parses an IPv6 CIDR like `fd42:6d73:62:2a::2/64`.
fn parse_cidr_v6(s: &str) -> AgentdResult<(Ipv6Addr, u8)> {
    let (addr_str, prefix_str) = s
        .rsplit_once('/')
        .ok_or_else(|| AgentdError::Init(format!("invalid IPv6 CIDR (missing /): {s}")))?;
    let addr = addr_str
        .parse::<Ipv6Addr>()
        .map_err(|_| AgentdError::Init(format!("invalid IPv6 address: {addr_str}")))?;
    let prefix = prefix_str
        .parse::<u8>()
        .map_err(|_| AgentdError::Init(format!("invalid IPv6 prefix length: {prefix_str}")))?;
    if prefix > 128 {
        return Err(AgentdError::Init(format!(
            "IPv6 prefix length out of range (0-128): {prefix}"
        )));
    }
    Ok((addr, prefix))
}

//--------------------------------------------------------------------------------------------------
// Modules
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::error::{AgentdError, AgentdResult};

    use super::{NetIpv4Spec, NetIpv6Spec, NetSpec};

    //----------------------------------------------------------------------------------------------
    // Types
    //----------------------------------------------------------------------------------------------

    // Alpine's musl-target libc crate does not expose the Linux netlink
    // ifaddrmsg/rtmsg definitions, so we define the kernel-layout structs we
    // need locally and continue using libc only for constants and syscalls.
    #[repr(C)]
    struct IfAddrMsg {
        ifa_family: u8,
        ifa_prefixlen: u8,
        ifa_flags: u8,
        ifa_scope: u8,
        ifa_index: u32,
    }

    #[repr(C)]
    struct RtMsg {
        rtm_family: u8,
        rtm_dst_len: u8,
        rtm_src_len: u8,
        rtm_tos: u8,
        rtm_table: u8,
        rtm_protocol: u8,
        rtm_scope: u8,
        rtm_type: u8,
        rtm_flags: u32,
    }

    /// Configures the guest network interface using ioctls and netlink.
    ///
    /// Operations (in order):
    /// 1. Set MAC address via `ioctl(SIOCSIFHWADDR)`
    /// 2. Set MTU via `ioctl(SIOCSIFMTU)`
    /// 3. Assign IPv4 address via netlink `RTM_NEWADDR`
    /// 4. Assign IPv6 address via netlink `RTM_NEWADDR`
    /// 5. Bring interface up via `ioctl(SIOCSIFFLAGS)` with `IFF_UP`
    /// 6. Add IPv4 default route via netlink `RTM_NEWROUTE`
    /// 7. Add IPv6 default route via netlink `RTM_NEWROUTE`
    /// 8. Write `/etc/resolv.conf`
    pub fn configure_interface(
        net: &NetSpec<'_>,
        ipv4: Option<&NetIpv4Spec>,
        ipv6: Option<&NetIpv6Spec>,
    ) -> AgentdResult<()> {
        let ifindex = get_ifindex(net.iface)?;

        set_mac_address(net.iface, &net.mac)?;
        set_mtu(net.iface, net.mtu)?;

        if let Some(v4) = ipv4 {
            add_address_v4(ifindex, v4.address, v4.prefix_len)?;
        }
        if let Some(v6) = ipv6 {
            add_address_v6(ifindex, v6.address, v6.prefix_len)?;
        }

        bring_interface_up(net.iface)?;

        if let Some(v4) = ipv4 {
            add_default_route_v4(v4.gateway)?;
        }
        if let Some(v6) = ipv6 {
            add_default_route_v6(v6.gateway)?;
        }

        write_resolv_conf(ipv4.and_then(|v| v.dns), ipv6.and_then(|v| v.dns))?;

        Ok(())
    }

    /// Brings up the loopback interface and makes sure localhost addresses exist.
    pub fn configure_loopback() -> AgentdResult<()> {
        let ifindex = get_ifindex("lo")?;

        bring_interface_up("lo")?;
        add_address_v4_if_missing(ifindex, Ipv4Addr::LOCALHOST, 8)?;
        add_address_v6_if_missing(ifindex, Ipv6Addr::LOCALHOST, 128)?;

        Ok(())
    }

    // ── ioctl helpers ──────────────────────────────────────────────────

    /// Gets the interface index for a given interface name.
    fn get_ifindex(ifname: &str) -> AgentdResult<u32> {
        unsafe {
            let mut ifr: libc::ifreq = std::mem::zeroed();
            copy_ifname(&mut ifr, ifname)?;

            let sock = socket_fd()?;
            if libc::ioctl(sock, libc::SIOCGIFINDEX as _, &mut ifr) < 0 {
                libc::close(sock);
                return Err(AgentdError::Init(format!(
                    "SIOCGIFINDEX failed for {ifname}: {}",
                    std::io::Error::last_os_error()
                )));
            }
            libc::close(sock);

            Ok(ifr.ifr_ifru.ifru_ifindex as u32)
        }
    }

    /// Sets the MAC address on an interface.
    fn set_mac_address(ifname: &str, mac: &[u8; 6]) -> AgentdResult<()> {
        unsafe {
            let mut ifr: libc::ifreq = std::mem::zeroed();
            copy_ifname(&mut ifr, ifname)?;

            ifr.ifr_ifru.ifru_hwaddr.sa_family = libc::ARPHRD_ETHER;
            ifr.ifr_ifru.ifru_hwaddr.sa_data[..6].copy_from_slice(&mac.map(|b| b as libc::c_char));

            let sock = socket_fd()?;
            if libc::ioctl(sock, libc::SIOCSIFHWADDR as _, &ifr) < 0 {
                libc::close(sock);
                return Err(AgentdError::Init(format!(
                    "SIOCSIFHWADDR failed for {ifname}: {}",
                    std::io::Error::last_os_error()
                )));
            }
            libc::close(sock);
        }
        Ok(())
    }

    /// Sets the MTU on an interface.
    fn set_mtu(ifname: &str, mtu: u16) -> AgentdResult<()> {
        unsafe {
            let mut ifr: libc::ifreq = std::mem::zeroed();
            copy_ifname(&mut ifr, ifname)?;
            ifr.ifr_ifru.ifru_mtu = mtu as libc::c_int;

            let sock = socket_fd()?;
            if libc::ioctl(sock, libc::SIOCSIFMTU as _, &ifr) < 0 {
                libc::close(sock);
                return Err(AgentdError::Init(format!(
                    "SIOCSIFMTU failed for {ifname}: {}",
                    std::io::Error::last_os_error()
                )));
            }
            libc::close(sock);
        }
        Ok(())
    }

    /// Brings an interface up.
    fn bring_interface_up(ifname: &str) -> AgentdResult<()> {
        unsafe {
            let mut ifr: libc::ifreq = std::mem::zeroed();
            copy_ifname(&mut ifr, ifname)?;

            let sock = socket_fd()?;

            // Get current flags.
            if libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr) < 0 {
                libc::close(sock);
                return Err(AgentdError::Init(format!(
                    "SIOCGIFFLAGS failed for {ifname}: {}",
                    std::io::Error::last_os_error()
                )));
            }

            // Set IFF_UP.
            ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;

            if libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) < 0 {
                libc::close(sock);
                return Err(AgentdError::Init(format!(
                    "SIOCSIFFLAGS (UP) failed for {ifname}: {}",
                    std::io::Error::last_os_error()
                )));
            }
            libc::close(sock);
        }
        Ok(())
    }

    // ── netlink helpers ────────────────────────────────────────────────

    /// Adds an IPv4 address to an interface via netlink RTM_NEWADDR.
    fn add_address_v4(ifindex: u32, addr: Ipv4Addr, prefix_len: u8) -> AgentdResult<()> {
        let addr_bytes = addr.octets();
        netlink_newaddr(ifindex, libc::AF_INET as u8, prefix_len, &addr_bytes).map_err(|e| {
            AgentdError::Init(format!(
                "failed to add IPv4 address {addr}/{prefix_len}: {e}"
            ))
        })
    }

    /// Adds an IPv6 address to an interface via netlink RTM_NEWADDR.
    fn add_address_v6(ifindex: u32, addr: Ipv6Addr, prefix_len: u8) -> AgentdResult<()> {
        let addr_bytes = addr.octets();
        netlink_newaddr(ifindex, libc::AF_INET6 as u8, prefix_len, &addr_bytes).map_err(|e| {
            AgentdError::Init(format!(
                "failed to add IPv6 address {addr}/{prefix_len}: {e}"
            ))
        })
    }

    /// Adds an IPv4 address unless it already exists.
    fn add_address_v4_if_missing(ifindex: u32, addr: Ipv4Addr, prefix_len: u8) -> AgentdResult<()> {
        let addr_bytes = addr.octets();
        match netlink_newaddr(ifindex, libc::AF_INET as u8, prefix_len, &addr_bytes) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
            Err(e) => Err(AgentdError::Init(format!(
                "failed to add IPv4 address {addr}/{prefix_len}: {e}"
            ))),
        }
    }

    /// Adds an IPv6 address unless it already exists.
    fn add_address_v6_if_missing(ifindex: u32, addr: Ipv6Addr, prefix_len: u8) -> AgentdResult<()> {
        let addr_bytes = addr.octets();
        match netlink_newaddr(ifindex, libc::AF_INET6 as u8, prefix_len, &addr_bytes) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
            Err(e) => Err(AgentdError::Init(format!(
                "failed to add IPv6 address {addr}/{prefix_len}: {e}"
            ))),
        }
    }

    /// Adds an IPv4 default route via netlink RTM_NEWROUTE.
    fn add_default_route_v4(gateway: Ipv4Addr) -> AgentdResult<()> {
        let gw_bytes = gateway.octets();
        netlink_newroute(libc::AF_INET as u8, &gw_bytes).map_err(|e| {
            AgentdError::Init(format!(
                "failed to add IPv4 default route via {gateway}: {e}"
            ))
        })
    }

    /// Adds an IPv6 default route via netlink RTM_NEWROUTE.
    fn add_default_route_v6(gateway: Ipv6Addr) -> AgentdResult<()> {
        let gw_bytes = gateway.octets();
        netlink_newroute(libc::AF_INET6 as u8, &gw_bytes).map_err(|e| {
            AgentdError::Init(format!(
                "failed to add IPv6 default route via {gateway}: {e}"
            ))
        })
    }

    /// Sends a netlink RTM_NEWADDR message.
    ///
    /// For IPv4: emits both `IFA_ADDRESS` and `IFA_LOCAL` (kernel expects both).
    /// For IPv6: emits only `IFA_ADDRESS` (no `IFA_LOCAL` semantics for IPv6).
    fn netlink_newaddr(
        ifindex: u32,
        family: u8,
        prefix_len: u8,
        addr: &[u8],
    ) -> std::io::Result<()> {
        let addr_len = addr.len();
        let is_ipv4 = family == libc::AF_INET as u8;

        // IPv4 needs two RTAs (IFA_ADDRESS + IFA_LOCAL), IPv6 needs one (IFA_ADDRESS).
        let num_rtas = if is_ipv4 { 2 } else { 1 };
        let rtas_len = rta_space(addr_len) * num_rtas;
        let msg_len = NLMSG_HDRLEN + IFADDRMSG_LEN + rtas_len;
        let mut buf = vec![0u8; nlmsg_align(msg_len)];

        // nlmsghdr
        let nlh = buf.as_mut_ptr().cast::<libc::nlmsghdr>();
        unsafe {
            (*nlh).nlmsg_len = msg_len as u32;
            (*nlh).nlmsg_type = libc::RTM_NEWADDR;
            (*nlh).nlmsg_flags =
                (libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL)
                    as u16;
            (*nlh).nlmsg_seq = 1;
        }

        // ifaddrmsg
        let ifa = unsafe { buf.as_mut_ptr().add(NLMSG_HDRLEN).cast::<IfAddrMsg>() };
        unsafe {
            (*ifa).ifa_family = family;
            (*ifa).ifa_prefixlen = prefix_len;
            (*ifa).ifa_flags = 0;
            (*ifa).ifa_index = ifindex;
            (*ifa).ifa_scope = libc::RT_SCOPE_UNIVERSE;
        }

        // RTA attributes
        let mut rta_offset = NLMSG_HDRLEN + IFADDRMSG_LEN;
        write_rta(&mut buf[rta_offset..], libc::IFA_ADDRESS, addr);
        rta_offset += rta_space(addr_len);

        if is_ipv4 {
            write_rta(&mut buf[rta_offset..], libc::IFA_LOCAL, addr);
        }

        netlink_send(&buf)
    }

    /// Sends a netlink RTM_NEWROUTE message for a default route.
    fn netlink_newroute(family: u8, gateway: &[u8]) -> std::io::Result<()> {
        let gw_len = gateway.len();

        // nlmsghdr + rtmsg + RTA_GATEWAY(rta_header + addr)
        let rta_len = rta_space(gw_len);
        let msg_len = NLMSG_HDRLEN + RTMSG_LEN + rta_len;
        let mut buf = vec![0u8; nlmsg_align(msg_len)];

        // nlmsghdr
        let nlh = buf.as_mut_ptr().cast::<libc::nlmsghdr>();
        unsafe {
            (*nlh).nlmsg_len = msg_len as u32;
            (*nlh).nlmsg_type = libc::RTM_NEWROUTE;
            (*nlh).nlmsg_flags =
                (libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL)
                    as u16;
            (*nlh).nlmsg_seq = 2;
        }

        // rtmsg
        let rtm = unsafe { buf.as_mut_ptr().add(NLMSG_HDRLEN).cast::<RtMsg>() };
        unsafe {
            (*rtm).rtm_family = family;
            (*rtm).rtm_dst_len = 0; // default route
            (*rtm).rtm_src_len = 0;
            (*rtm).rtm_tos = 0;
            (*rtm).rtm_table = libc::RT_TABLE_MAIN;
            (*rtm).rtm_protocol = libc::RTPROT_BOOT;
            (*rtm).rtm_scope = libc::RT_SCOPE_UNIVERSE;
            (*rtm).rtm_type = libc::RTN_UNICAST;
            (*rtm).rtm_flags = 0;
        }

        // RTA_GATEWAY attribute
        let rta_offset = NLMSG_HDRLEN + RTMSG_LEN;
        write_rta(&mut buf[rta_offset..], libc::RTA_GATEWAY, gateway);

        netlink_send(&buf)
    }

    /// Opens a netlink socket, sends a message, and waits for the ACK.
    fn netlink_send(msg: &[u8]) -> std::io::Result<()> {
        unsafe {
            let sock = libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, libc::NETLINK_ROUTE);
            if sock < 0 {
                return Err(std::io::Error::last_os_error());
            }

            // Bind to kernel.
            let mut sa: libc::sockaddr_nl = std::mem::zeroed();
            sa.nl_family = libc::AF_NETLINK as u16;
            if libc::bind(
                sock,
                (&sa as *const libc::sockaddr_nl).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            ) < 0
            {
                libc::close(sock);
                return Err(std::io::Error::last_os_error());
            }

            // Send.
            if libc::send(sock, msg.as_ptr().cast(), msg.len(), 0) < 0 {
                libc::close(sock);
                return Err(std::io::Error::last_os_error());
            }

            // Read ACK.
            let mut ack_buf = [0u8; 1024];
            let n = libc::recv(sock, ack_buf.as_mut_ptr().cast(), ack_buf.len(), 0);
            libc::close(sock);

            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }

            // Check for error in the ACK (using from_ne_bytes to avoid
            // unaligned pointer dereference on the stack buffer).
            if (n as usize) >= NLMSG_HDRLEN + 4 {
                let nlh = ack_buf.as_ptr().cast::<libc::nlmsghdr>();
                if (*nlh).nlmsg_type == libc::NLMSG_ERROR as u16 {
                    let err = i32::from_ne_bytes(
                        ack_buf[NLMSG_HDRLEN..NLMSG_HDRLEN + 4].try_into().unwrap(),
                    );
                    if err < 0 {
                        return Err(std::io::Error::from_raw_os_error(-err));
                    }
                }
            }

            Ok(())
        }
    }

    // ── hosts + resolv.conf ────────────────────────────────────────────

    /// Writes a deterministic runtime `/etc/hosts` with localhost aliases.
    pub fn write_hosts_file() -> AgentdResult<()> {
        std::fs::create_dir_all("/etc")
            .map_err(|e| AgentdError::Init(format!("failed to create /etc: {e}")))?;
        std::fs::write("/etc/hosts", super::default_hosts_file_contents())
            .map_err(|e| AgentdError::Init(format!("failed to write /etc/hosts: {e}")))?;
        Ok(())
    }

    /// Writes `/etc/resolv.conf` with the configured DNS servers.
    fn write_resolv_conf(dns_v4: Option<Ipv4Addr>, dns_v6: Option<Ipv6Addr>) -> AgentdResult<()> {
        if dns_v4.is_none() && dns_v6.is_none() {
            return Ok(());
        }

        let mut content = String::new();
        if let Some(dns) = dns_v4 {
            content.push_str(&format!("nameserver {dns}\n"));
        }
        if let Some(dns) = dns_v6 {
            content.push_str(&format!("nameserver {dns}\n"));
        }

        std::fs::write("/etc/resolv.conf", &content)
            .map_err(|e| AgentdError::Init(format!("failed to write /etc/resolv.conf: {e}")))?;

        Ok(())
    }

    // ── low-level helpers ──────────────────────────────────────────────

    /// Creates a UDP socket for ioctl operations.
    fn socket_fd() -> AgentdResult<libc::c_int> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(AgentdError::Init(format!(
                "failed to create socket: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(fd)
    }

    /// Copies an interface name into an ifreq struct.
    fn copy_ifname(ifr: &mut libc::ifreq, ifname: &str) -> AgentdResult<()> {
        let bytes = ifname.as_bytes();
        if bytes.len() >= libc::IFNAMSIZ {
            return Err(AgentdError::Init(format!(
                "interface name too long: {ifname}"
            )));
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                ifr.ifr_name.as_mut_ptr().cast(),
                bytes.len(),
            );
        }
        Ok(())
    }

    // ── netlink constants and helpers ──────────────────────────────────

    const NLMSG_HDRLEN: usize = 16;
    const IFADDRMSG_LEN: usize = 8;
    const RTMSG_LEN: usize = 12;
    const RTA_HDRLEN: usize = 4;

    // Compile-time assertions: catch layout mismatches across platforms.
    const _: () = assert!(std::mem::size_of::<libc::nlmsghdr>() == NLMSG_HDRLEN);
    const _: () = assert!(std::mem::size_of::<IfAddrMsg>() == IFADDRMSG_LEN);
    const _: () = assert!(std::mem::size_of::<RtMsg>() == RTMSG_LEN);

    fn nlmsg_align(len: usize) -> usize {
        (len + 3) & !3
    }

    fn rta_space(data_len: usize) -> usize {
        nlmsg_align(RTA_HDRLEN + data_len)
    }

    /// Writes an rtattr (type + data) into the buffer.
    fn write_rta(buf: &mut [u8], rta_type: u16, data: &[u8]) {
        let rta_len = (RTA_HDRLEN + data.len()) as u16;
        buf[0..2].copy_from_slice(&rta_len.to_ne_bytes());
        buf[2..4].copy_from_slice(&rta_type.to_ne_bytes());
        buf[RTA_HDRLEN..RTA_HDRLEN + data.len()].copy_from_slice(data);
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_net_full() {
        let spec = parse_net("iface=eth0,mac=02:5a:7b:13:01:02,mtu=1500").unwrap();
        assert_eq!(spec.iface, "eth0");
        assert_eq!(spec.mac, [0x02, 0x5a, 0x7b, 0x13, 0x01, 0x02]);
        assert_eq!(spec.mtu, 1500);
    }

    #[test]
    fn test_parse_net_default_mtu() {
        let spec = parse_net("iface=eth0,mac=02:00:00:00:00:01").unwrap();
        assert_eq!(spec.mtu, 1500);
    }

    #[test]
    fn test_parse_net_missing_iface() {
        assert!(parse_net("mac=02:00:00:00:00:01").is_err());
    }

    #[test]
    fn test_parse_net_missing_mac() {
        assert!(parse_net("iface=eth0").is_err());
    }

    #[test]
    fn test_parse_net_unknown_option() {
        assert!(parse_net("iface=eth0,mac=02:00:00:00:00:01,bogus=42").is_err());
    }

    #[test]
    fn test_parse_net_ipv4() {
        let spec = parse_net_ipv4("addr=100.96.1.2/30,gw=100.96.1.1,dns=100.96.1.1").unwrap();
        assert_eq!(spec.address, Ipv4Addr::new(100, 96, 1, 2));
        assert_eq!(spec.prefix_len, 30);
        assert_eq!(spec.gateway, Ipv4Addr::new(100, 96, 1, 1));
        assert_eq!(spec.dns, Some(Ipv4Addr::new(100, 96, 1, 1)));
    }

    #[test]
    fn test_parse_net_ipv4_no_dns() {
        let spec = parse_net_ipv4("addr=10.0.0.2/24,gw=10.0.0.1").unwrap();
        assert_eq!(spec.dns, None);
    }

    #[test]
    fn test_parse_net_ipv4_missing_addr() {
        assert!(parse_net_ipv4("gw=10.0.0.1").is_err());
    }

    #[test]
    fn test_parse_net_ipv6() {
        let spec = parse_net_ipv6(
            "addr=fd42:6d73:62:2a::2/64,gw=fd42:6d73:62:2a::1,dns=fd42:6d73:62:2a::1",
        )
        .unwrap();
        assert_eq!(
            spec.address,
            "fd42:6d73:62:2a::2".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(spec.prefix_len, 64);
        assert_eq!(
            spec.gateway,
            "fd42:6d73:62:2a::1".parse::<Ipv6Addr>().unwrap()
        );
        assert!(spec.dns.is_some());
    }

    #[test]
    fn test_parse_mac_valid() {
        let mac = parse_mac("02:5a:7b:13:01:02").unwrap();
        assert_eq!(mac, [0x02, 0x5a, 0x7b, 0x13, 0x01, 0x02]);
    }

    #[test]
    fn test_parse_mac_invalid() {
        assert!(parse_mac("02:5a:7b").is_err());
        assert!(parse_mac("zz:00:00:00:00:00").is_err());
    }

    #[test]
    fn test_parse_cidr_v4() {
        let (addr, prefix) = parse_cidr_v4("100.96.1.2/30").unwrap();
        assert_eq!(addr, Ipv4Addr::new(100, 96, 1, 2));
        assert_eq!(prefix, 30);
    }

    #[test]
    fn test_parse_cidr_v6() {
        let (addr, prefix) = parse_cidr_v6("fd42:6d73:62:2a::2/64").unwrap();
        assert_eq!(addr, "fd42:6d73:62:2a::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(prefix, 64);
    }

    #[test]
    fn test_default_hosts_file_contents_matches_localhost_baseline() {
        assert_eq!(
            default_hosts_file_contents(),
            concat!(
                "127.0.0.1\tlocalhost\n",
                "::1\tlocalhost ip6-localhost ip6-loopback\n",
                "fe00::\tip6-localnet\n",
                "ff00::\tip6-mcastprefix\n",
                "ff02::1\tip6-allnodes\n",
                "ff02::2\tip6-allrouters\n",
            )
        );
    }
}
