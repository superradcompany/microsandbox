//! Guest-side network configuration from `MSB_NET*` environment variables.
//!
//! Configures the guest network interface using ioctls and netlink, following
//! the parameters from host.

use crate::config::{NetIpv4Spec, NetIpv6Spec, NetSpec};
use crate::error::AgentdResult;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Sets the guest hostname.
///
/// Calls `sethostname()`, writes `/etc/hostname`, and provisions
/// `/etc/hosts` with localhost aliases and the hostname entry.
pub(crate) fn apply_hostname(hostname: Option<&str>) -> AgentdResult<()> {
    linux::write_hosts_file(hostname)?;

    if let Some(name) = hostname {
        linux::set_hostname(name)?;
    }

    Ok(())
}

/// Applies network configuration.
///
/// Always provisions loopback, even when no external network interface is
/// requested. Missing `net` is not an error (no networking requested).
pub(crate) fn apply_network_config(
    net: Option<&NetSpec>,
    net_ipv4: Option<&NetIpv4Spec>,
    net_ipv6: Option<&NetIpv6Spec>,
) -> AgentdResult<()> {
    linux::configure_loopback()?;

    let Some(net) = net else {
        return Ok(());
    };

    linux::configure_interface(net, net_ipv4, net_ipv6)
}

fn hosts_file_contents(hostname: Option<&str>) -> String {
    let mut s = String::new();

    // Localhost entries — always include hostname aliases when set.
    if let Some(name) = hostname {
        s.push_str(&format!("127.0.0.1\tlocalhost {name}\n"));
        s.push_str(&format!(
            "::1\tlocalhost ip6-localhost ip6-loopback {name}\n"
        ));
    } else {
        s.push_str("127.0.0.1\tlocalhost\n");
        s.push_str("::1\tlocalhost ip6-localhost ip6-loopback\n");
    }

    s.push_str("fe00::\tip6-localnet\n");
    s.push_str("ff00::\tip6-mcastprefix\n");
    s.push_str("ff02::1\tip6-allnodes\n");
    s.push_str("ff02::2\tip6-allrouters\n");

    s
}

//--------------------------------------------------------------------------------------------------
// Modules
//--------------------------------------------------------------------------------------------------

mod linux {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::config::{NetIpv4Spec, NetIpv6Spec, NetSpec};
    use crate::error::{AgentdError, AgentdResult};

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
        net: &NetSpec,
        ipv4: Option<&NetIpv4Spec>,
        ipv6: Option<&NetIpv6Spec>,
    ) -> AgentdResult<()> {
        let ifindex = get_ifindex(&net.iface)?;

        set_mac_address(&net.iface, &net.mac)?;
        set_mtu(&net.iface, net.mtu)?;

        if let Some(v4) = ipv4 {
            add_address_v4(ifindex, v4.address, v4.prefix_len)?;
        }
        if let Some(v6) = ipv6 {
            add_address_v6(ifindex, v6.address, v6.prefix_len)?;
        }

        bring_interface_up(&net.iface)?;

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

    // ── hostname + hosts + resolv.conf ──────────────────────────────────

    /// Sets the kernel hostname via `sethostname()` and writes `/etc/hostname`.
    pub fn set_hostname(name: &str) -> AgentdResult<()> {
        nix::unistd::sethostname(name)
            .map_err(|e| AgentdError::Init(format!("sethostname({name}): {e}")))?;

        std::fs::create_dir_all("/etc")
            .map_err(|e| AgentdError::Init(format!("failed to create /etc: {e}")))?;
        std::fs::write("/etc/hostname", format!("{name}\n"))
            .map_err(|e| AgentdError::Init(format!("failed to write /etc/hostname: {e}")))?;

        Ok(())
    }

    /// Writes `/etc/hosts` with localhost aliases and an optional hostname entry.
    pub fn write_hosts_file(hostname: Option<&str>) -> AgentdResult<()> {
        std::fs::create_dir_all("/etc")
            .map_err(|e| AgentdError::Init(format!("failed to create /etc: {e}")))?;
        std::fs::write("/etc/hosts", super::hosts_file_contents(hostname))
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
    fn test_hosts_file_without_hostname() {
        assert_eq!(
            hosts_file_contents(None),
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

    #[test]
    fn test_hosts_file_with_hostname() {
        assert_eq!(
            hosts_file_contents(Some("worker-01")),
            concat!(
                "127.0.0.1\tlocalhost worker-01\n",
                "::1\tlocalhost ip6-localhost ip6-loopback worker-01\n",
                "fe00::\tip6-localnet\n",
                "ff00::\tip6-mcastprefix\n",
                "ff02::1\tip6-allnodes\n",
                "ff02::2\tip6-allrouters\n",
            )
        );
    }
}
