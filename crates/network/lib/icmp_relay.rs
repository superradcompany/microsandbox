//! External ICMP echo-only relay: host probe + reply frame synthesis.
//!
//! Relays outbound ICMP Echo Request packets from the guest to the real
//! network via unprivileged `SOCK_DGRAM + IPPROTO_ICMP` sockets, then
//! synthesizes Echo Reply frames back into `rx_ring`.
//!
//! Only Echo Request/Reply is supported. Non-echo ICMP (traceroute,
//! destination unreachable, etc.) is intentionally not relayed.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::FromRawFd;
use std::sync::Arc;

use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, Icmpv4Packet, Icmpv4Repr,
    Icmpv6Packet, Icmpv6Repr, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
};

use crate::policy::{NetworkPolicy, Protocol};
use crate::shared::SharedState;
use crate::stack::PollLoopConfig;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Timeout for each ICMP echo probe.
const ECHO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Receive buffer size for ICMP replies.
const RECV_BUF_SIZE: usize = 1500;

/// Ethernet header length.
const ETH_HDR_LEN: usize = 14;

/// IPv4 header length (no options).
const IPV4_HDR_LEN: usize = 20;

/// IPv6 header length.
const IPV6_HDR_LEN: usize = 40;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Whether unprivileged ICMP echo sockets are available on this host.
///
/// Probed once at construction, per address family. Availability may differ
/// between IPv4 and IPv6 on the same host.
#[derive(Debug, Clone, Copy)]
enum EchoBackend {
    /// The address family-specific ping socket probe succeeded.
    Available,
    /// Probe failed — ICMP relay is disabled.
    Unavailable,
}

/// Relays ICMP echo requests from the guest to the real network via
/// unprivileged ICMP sockets.
///
/// Each echo request spawns a fire-and-forget tokio task. No session
/// table is needed — ping traffic is low-volume and each probe is
/// independent.
pub struct IcmpRelay {
    shared: Arc<SharedState>,
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
    tokio_handle: tokio::runtime::Handle,
    backend_v4: EchoBackend,
    backend_v6: EchoBackend,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl IcmpRelay {
    /// Create a new ICMP relay, probing for unprivileged socket support.
    pub fn new(
        shared: Arc<SharedState>,
        gateway_mac: [u8; 6],
        guest_mac: [u8; 6],
        tokio_handle: tokio::runtime::Handle,
    ) -> Self {
        let backend_v4 = probe_icmp_socket_v4();
        let backend_v6 = probe_icmp_socket_v6();

        if matches!(backend_v4, EchoBackend::Unavailable) {
            tracing::debug!(
                "unprivileged ICMPv4 echo sockets unavailable — external ICMPv4 relay disabled"
            );
        }
        if matches!(backend_v6, EchoBackend::Unavailable) {
            tracing::debug!(
                "unprivileged ICMPv6 echo sockets unavailable — external ICMPv6 relay disabled"
            );
        }

        Self {
            shared,
            gateway_mac: EthernetAddress(gateway_mac),
            guest_mac: EthernetAddress(guest_mac),
            tokio_handle,
            backend_v4,
            backend_v6,
        }
    }

    /// Try to intercept an outbound frame as an ICMP echo request.
    ///
    /// Returns `true` if the frame was consumed (caller should
    /// `drop_staged_frame()`). Returns `false` if the frame is not an
    /// ICMP echo request or the backend is unavailable — caller should
    /// fall through to `classify_frame`.
    pub fn relay_outbound_if_echo(
        &self,
        frame: &[u8],
        config: &PollLoopConfig,
        policy: &NetworkPolicy,
    ) -> bool {
        let Ok(eth) = EthernetFrame::new_checked(frame) else {
            return false;
        };

        match eth.ethertype() {
            EthernetProtocol::Ipv4 if matches!(self.backend_v4, EchoBackend::Available) => {
                self.try_relay_icmpv4(&eth, config, policy)
            }
            EthernetProtocol::Ipv6 if matches!(self.backend_v6, EchoBackend::Available) => {
                self.try_relay_icmpv6(&eth, config, policy)
            }
            _ => false,
        }
    }
}

impl IcmpRelay {
    /// Try to relay an ICMPv4 echo request. Returns true if consumed.
    fn try_relay_icmpv4(
        &self,
        eth: &EthernetFrame<&[u8]>,
        config: &PollLoopConfig,
        policy: &NetworkPolicy,
    ) -> bool {
        let Ok(ipv4) = Ipv4Packet::new_checked(eth.payload()) else {
            return false;
        };
        if ipv4.next_header() != IpProtocol::Icmp {
            return false;
        }

        // Gateway echo is already handled upstream — skip.
        let dst_ip: Ipv4Addr = ipv4.dst_addr();
        if config.gateway.ipv4 == Some(dst_ip) {
            return false;
        }

        let Ok(icmp) = Icmpv4Packet::new_checked(ipv4.payload()) else {
            return false;
        };
        let Ok(Icmpv4Repr::EchoRequest {
            ident,
            seq_no,
            data,
        }) = Icmpv4Repr::parse(&icmp, &smoltcp::phy::ChecksumCapabilities::default())
        else {
            return false; // Not an echo request — fall through.
        };

        // Policy check.
        if policy
            .evaluate_egress_ip(IpAddr::V4(dst_ip), Protocol::Icmpv4, &self.shared)
            .is_deny()
        {
            tracing::debug!(dst = %dst_ip, "ICMP echo denied by policy");
            return true; // Consumed (silently dropped by policy).
        }

        let src_ip: Ipv4Addr = ipv4.src_addr();
        let guest_ident = ident;
        let echo_data = data.to_vec();

        let shared = self.shared.clone();
        let gateway_mac = self.gateway_mac;
        let guest_mac = self.guest_mac;

        tracing::debug!(dst = %dst_ip, seq_no, bytes = echo_data.len(), "relaying ICMPv4 echo request");

        self.tokio_handle.spawn(async move {
            if let Err(e) = icmpv4_echo_task(
                dst_ip,
                src_ip,
                guest_ident,
                seq_no,
                echo_data,
                shared,
                gateway_mac,
                guest_mac,
            )
            .await
            {
                tracing::debug!(dst = %dst_ip, error = %e, "ICMPv4 echo relay failed");
            }
        });

        true
    }

    /// Try to relay an ICMPv6 echo request. Returns true if consumed.
    fn try_relay_icmpv6(
        &self,
        eth: &EthernetFrame<&[u8]>,
        config: &PollLoopConfig,
        policy: &NetworkPolicy,
    ) -> bool {
        let Ok(ipv6) = Ipv6Packet::new_checked(eth.payload()) else {
            return false;
        };
        if ipv6.next_header() != IpProtocol::Icmpv6 {
            return false;
        }

        // Gateway echo is already handled upstream — skip.
        let dst_ip: Ipv6Addr = ipv6.dst_addr();
        if config.gateway.ipv6 == Some(dst_ip) {
            return false;
        }

        let Ok(icmp) = Icmpv6Packet::new_checked(ipv6.payload()) else {
            return false;
        };
        let Ok(Icmpv6Repr::EchoRequest {
            ident,
            seq_no,
            data,
        }) = Icmpv6Repr::parse(
            &ipv6.src_addr(),
            &ipv6.dst_addr(),
            &icmp,
            &smoltcp::phy::ChecksumCapabilities::default(),
        )
        else {
            return false; // Not an echo request — fall through.
        };

        // Policy check.
        if policy
            .evaluate_egress_ip(IpAddr::V6(dst_ip), Protocol::Icmpv6, &self.shared)
            .is_deny()
        {
            tracing::debug!(dst = %dst_ip, "ICMPv6 echo denied by policy");
            return true;
        }

        let src_ip: Ipv6Addr = ipv6.src_addr();
        let guest_ident = ident;
        let echo_data = data.to_vec();

        let shared = self.shared.clone();
        let gateway_mac = self.gateway_mac;
        let guest_mac = self.guest_mac;

        tracing::debug!(dst = %dst_ip, seq_no, bytes = echo_data.len(), "relaying ICMPv6 echo request");

        self.tokio_handle.spawn(async move {
            if let Err(e) = icmpv6_echo_task(
                dst_ip,
                src_ip,
                guest_ident,
                seq_no,
                echo_data,
                shared,
                gateway_mac,
                guest_mac,
            )
            .await
            {
                tracing::debug!(dst = %dst_ip, error = %e, "ICMPv6 echo relay failed");
            }
        });

        true
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Probe whether `SOCK_DGRAM + IPPROTO_ICMP` is available.
fn probe_icmp_socket_v4() -> EchoBackend {
    // SAFETY: socket() with valid args; immediately closed on success.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
    if fd >= 0 {
        unsafe { libc::close(fd) };
        EchoBackend::Available
    } else {
        EchoBackend::Unavailable
    }
}

/// Probe whether `SOCK_DGRAM + IPPROTO_ICMPV6` is available.
fn probe_icmp_socket_v6() -> EchoBackend {
    // SAFETY: socket() with valid args; immediately closed on success.
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_ICMPV6) };
    if fd >= 0 {
        unsafe { libc::close(fd) };
        EchoBackend::Available
    } else {
        EchoBackend::Unavailable
    }
}

/// Open an unprivileged ICMPv4 socket connected to `dst`.
///
/// Uses `SOCK_DGRAM + IPPROTO_ICMP` which the kernel intercepts to
/// provide unprivileged ping. The socket behaves like a connected UDP
/// socket but carries ICMP echo payloads.
///
/// Note: the kernel rewrites the ICMP identifier field to match the
/// socket's ephemeral "port" assignment. The caller must restore the
/// guest's original identifier on the reply.
fn open_icmp_socket_v4(dst: Ipv4Addr) -> std::io::Result<tokio::net::UdpSocket> {
    // SAFETY: socket() + fcntl() + connect() with valid args.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Set non-blocking + close-on-exec via fcntl (portable across macOS/Linux).
    if let Err(e) = set_nonblock_cloexec(fd) {
        unsafe { libc::close(fd) };
        return Err(e);
    }

    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(dst).to_be(),
        },
        sin_zero: [0; 8],
        #[cfg(target_os = "macos")]
        sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
    };

    // SAFETY: connect() with valid sockaddr_in.
    let ret = unsafe {
        libc::connect(
            fd,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    // SAFETY: fd is a valid, connected, non-blocking socket.
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    tokio::net::UdpSocket::from_std(std_sock)
}

/// Open an unprivileged ICMPv6 socket connected to `dst`.
fn open_icmp_socket_v6(dst: Ipv6Addr) -> std::io::Result<tokio::net::UdpSocket> {
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_ICMPV6) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    if let Err(e) = set_nonblock_cloexec(fd) {
        unsafe { libc::close(fd) };
        return Err(e);
    }

    let addr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: dst.octets(),
        },
        sin6_scope_id: 0,
        #[cfg(target_os = "macos")]
        sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
    };

    let ret = unsafe {
        libc::connect(
            fd,
            &addr as *const libc::sockaddr_in6 as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    tokio::net::UdpSocket::from_std(std_sock)
}

/// Set `O_NONBLOCK` and `FD_CLOEXEC` on a file descriptor.
fn set_nonblock_cloexec(fd: libc::c_int) -> std::io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Send one ICMPv4 echo request, receive reply, and inject a guest frame.
#[allow(clippy::too_many_arguments)]
async fn icmpv4_echo_task(
    dst_ip: Ipv4Addr,
    guest_src_ip: Ipv4Addr,
    guest_ident: u16,
    seq_no: u16,
    echo_data: Vec<u8>,
    shared: Arc<SharedState>,
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
) -> std::io::Result<()> {
    let socket = open_icmp_socket_v4(dst_ip)?;

    // Build the ICMP echo request payload.
    // For SOCK_DGRAM+IPPROTO_ICMP, we send the ICMP header + data
    // (type, code, checksum, ident, seq_no, data). The kernel
    // rewrites ident to match the socket's ephemeral assignment.
    let icmp_repr = Icmpv4Repr::EchoRequest {
        ident: guest_ident,
        seq_no,
        data: &echo_data,
    };
    let mut icmp_buf = vec![0u8; icmp_repr.buffer_len()];
    icmp_repr.emit(
        &mut Icmpv4Packet::new_unchecked(&mut icmp_buf),
        &smoltcp::phy::ChecksumCapabilities::default(),
    );

    socket.send(&icmp_buf).await?;

    // Receive the echo reply. Different hosts may return either:
    // - a bare ICMP message, or
    // - an IP packet containing the ICMP message.
    let mut recv_buf = vec![0u8; RECV_BUF_SIZE];
    let n = tokio::time::timeout(ECHO_TIMEOUT, socket.recv(&mut recv_buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "ICMP echo timeout"))??;

    let (reply_seq, reply_data) = parse_icmpv4_echo_reply(&recv_buf[..n])?;

    // Construct the reply frame with the guest's ORIGINAL ident restored.
    let frame = construct_icmpv4_echo_reply(
        dst_ip,
        guest_src_ip,
        guest_ident,
        reply_seq,
        reply_data,
        gateway_mac,
        guest_mac,
    );

    let frame_len = frame.len();
    if shared.rx_ring.push(frame).is_ok() {
        shared.add_rx_bytes(frame_len);
        shared.rx_wake.wake();
        tracing::debug!(dst = %dst_ip, seq_no = reply_seq, frame_len, "ICMPv4 echo reply injected");
    } else {
        tracing::debug!("ICMP echo reply dropped — rx_ring full");
    }

    Ok(())
}

/// Send one ICMPv6 echo request, receive reply, and inject a guest frame.
#[allow(clippy::too_many_arguments)]
async fn icmpv6_echo_task(
    dst_ip: Ipv6Addr,
    guest_src_ip: Ipv6Addr,
    guest_ident: u16,
    seq_no: u16,
    echo_data: Vec<u8>,
    shared: Arc<SharedState>,
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
) -> std::io::Result<()> {
    let socket = open_icmp_socket_v6(dst_ip)?;

    let icmp_repr = Icmpv6Repr::EchoRequest {
        ident: guest_ident,
        seq_no,
        data: &echo_data,
    };
    let mut icmp_buf = vec![0u8; icmp_repr.buffer_len()];
    // For SOCK_DGRAM+IPPROTO_ICMPV6, the kernel computes the checksum,
    // so the addresses used here for emit are only for serialization.
    icmp_repr.emit(
        &guest_src_ip,
        &dst_ip,
        &mut Icmpv6Packet::new_unchecked(&mut icmp_buf),
        &smoltcp::phy::ChecksumCapabilities::default(),
    );

    socket.send(&icmp_buf).await?;

    let mut recv_buf = vec![0u8; RECV_BUF_SIZE];
    let n = tokio::time::timeout(ECHO_TIMEOUT, socket.recv(&mut recv_buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "ICMPv6 echo timeout"))??;

    let (reply_seq, reply_data) = parse_icmpv6_echo_reply(&recv_buf[..n], dst_ip, guest_src_ip)?;

    let frame = construct_icmpv6_echo_reply(
        dst_ip,
        guest_src_ip,
        guest_ident,
        reply_seq,
        reply_data,
        gateway_mac,
        guest_mac,
    );

    let frame_len = frame.len();
    if shared.rx_ring.push(frame).is_ok() {
        shared.add_rx_bytes(frame_len);
        shared.rx_wake.wake();
        tracing::debug!(dst = %dst_ip, seq_no = reply_seq, frame_len, "ICMPv6 echo reply injected");
    } else {
        tracing::debug!("ICMPv6 echo reply dropped — rx_ring full");
    }

    Ok(())
}

/// Parse an ICMPv4 Echo Reply from a host ping socket receive buffer.
///
/// Some hosts return a bare ICMP message while others prepend the IPv4 header.
fn parse_icmpv4_echo_reply(buf: &[u8]) -> std::io::Result<(u16, &[u8])> {
    if let Ok(reply_icmp) = Icmpv4Packet::new_checked(buf)
        && let Ok(Icmpv4Repr::EchoReply {
            ident: _,
            seq_no,
            data,
        }) = Icmpv4Repr::parse(&reply_icmp, &smoltcp::phy::ChecksumCapabilities::default())
    {
        return Ok((seq_no, data));
    }

    let reply_icmp = Icmpv4Packet::new_checked(extract_ipv4_icmp_payload(buf)?)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let Icmpv4Repr::EchoReply {
        ident: _,
        seq_no,
        data,
    } = Icmpv4Repr::parse(&reply_icmp, &smoltcp::phy::ChecksumCapabilities::default())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?
    else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "host ICMPv4 reply was not an echo reply",
        ));
    };

    Ok((seq_no, data))
}

/// Parse an ICMPv6 Echo Reply from a host ping socket receive buffer.
///
/// Some hosts return a bare ICMPv6 message while others may prepend an IPv6
/// header. The checksum is validated against the expected remote/guest pair.
fn parse_icmpv6_echo_reply(
    buf: &[u8],
    remote_ip: Ipv6Addr,
    guest_ip: Ipv6Addr,
) -> std::io::Result<(u16, &[u8])> {
    if let Ok(reply_icmp) = Icmpv6Packet::new_checked(buf)
        && let Ok(Icmpv6Repr::EchoReply {
            ident: _,
            seq_no,
            data,
        }) = Icmpv6Repr::parse(
            &remote_ip,
            &guest_ip,
            &reply_icmp,
            &smoltcp::phy::ChecksumCapabilities::default(),
        )
    {
        return Ok((seq_no, data));
    }

    let reply_icmp = Icmpv6Packet::new_checked(extract_ipv6_icmp_payload(buf)?)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let Icmpv6Repr::EchoReply {
        ident: _,
        seq_no,
        data,
    } = Icmpv6Repr::parse(
        &remote_ip,
        &guest_ip,
        &reply_icmp,
        &smoltcp::phy::ChecksumCapabilities::default(),
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?
    else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "host ICMPv6 reply was not an echo reply",
        ));
    };

    Ok((seq_no, data))
}

/// Extract the ICMP payload from an IPv4-framed host ping-socket reply.
///
/// Some hosts prepend an IPv4 header that is not a fully self-consistent
/// wire packet, so this parser intentionally validates only the fields we
/// need to locate the embedded ICMP payload.
fn extract_ipv4_icmp_payload(buf: &[u8]) -> std::io::Result<&[u8]> {
    if buf.len() < IPV4_HDR_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "host ICMPv4 reply was shorter than an IPv4 header",
        ));
    }

    let version = buf[0] >> 4;
    let header_len = usize::from(buf[0] & 0x0f) * 4;
    if version != 4 || header_len < IPV4_HDR_LEN || header_len > buf.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "host ICMPv4 reply did not contain a usable IPv4 header",
        ));
    }
    if buf[9] != u8::from(IpProtocol::Icmp) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "host ICMPv4 reply did not contain an ICMP payload",
        ));
    }

    Ok(&buf[header_len..])
}

/// Extract the ICMPv6 payload from an IPv6-framed host ping-socket reply.
fn extract_ipv6_icmp_payload(buf: &[u8]) -> std::io::Result<&[u8]> {
    if buf.len() < IPV6_HDR_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "host ICMPv6 reply was shorter than an IPv6 header",
        ));
    }

    let version = buf[0] >> 4;
    if version != 6 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "host ICMPv6 reply did not contain a usable IPv6 header",
        ));
    }
    if buf[6] != u8::from(IpProtocol::Icmpv6) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "host ICMPv6 reply did not contain an ICMPv6 payload",
        ));
    }

    Ok(&buf[IPV6_HDR_LEN..])
}

/// Construct an Ethernet + IPv4 + ICMPv4 Echo Reply frame for the guest.
fn construct_icmpv4_echo_reply(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
) -> Vec<u8> {
    let icmp_repr = Icmpv4Repr::EchoReply {
        ident,
        seq_no,
        data,
    };
    let ipv4_repr = Ipv4Repr {
        src_addr: src_ip,
        dst_addr: dst_ip,
        next_header: IpProtocol::Icmp,
        payload_len: icmp_repr.buffer_len(),
        hop_limit: 64,
    };
    let frame_len = ETH_HDR_LEN + ipv4_repr.buffer_len() + icmp_repr.buffer_len();
    let mut buf = vec![0u8; frame_len];

    // Ethernet header.
    let mut eth_frame = EthernetFrame::new_unchecked(&mut buf);
    EthernetRepr {
        src_addr: gateway_mac,
        dst_addr: guest_mac,
        ethertype: EthernetProtocol::Ipv4,
    }
    .emit(&mut eth_frame);

    // IPv4 header.
    ipv4_repr.emit(
        &mut Ipv4Packet::new_unchecked(&mut buf[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN]),
        &smoltcp::phy::ChecksumCapabilities::default(),
    );

    // ICMP header + payload.
    icmp_repr.emit(
        &mut Icmpv4Packet::new_unchecked(&mut buf[ETH_HDR_LEN + IPV4_HDR_LEN..]),
        &smoltcp::phy::ChecksumCapabilities::default(),
    );

    buf
}

/// Construct an Ethernet + IPv6 + ICMPv6 Echo Reply frame for the guest.
fn construct_icmpv6_echo_reply(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    ident: u16,
    seq_no: u16,
    data: &[u8],
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
) -> Vec<u8> {
    let icmp_repr = Icmpv6Repr::EchoReply {
        ident,
        seq_no,
        data,
    };
    let frame_len = ETH_HDR_LEN + IPV6_HDR_LEN + icmp_repr.buffer_len();
    let mut buf = vec![0u8; frame_len];

    // Ethernet header.
    let mut eth_frame = EthernetFrame::new_unchecked(&mut buf);
    EthernetRepr {
        src_addr: gateway_mac,
        dst_addr: guest_mac,
        ethertype: EthernetProtocol::Ipv6,
    }
    .emit(&mut eth_frame);

    // IPv6 header.
    Ipv6Repr {
        src_addr: src_ip,
        dst_addr: dst_ip,
        next_header: IpProtocol::Icmpv6,
        payload_len: icmp_repr.buffer_len(),
        hop_limit: 64,
    }
    .emit(&mut Ipv6Packet::new_unchecked(
        &mut buf[ETH_HDR_LEN..ETH_HDR_LEN + IPV6_HDR_LEN],
    ));

    // ICMPv6 header + payload (checksum computed from src/dst addresses).
    icmp_repr.emit(
        &src_ip,
        &dst_ip,
        &mut Icmpv6Packet::new_unchecked(&mut buf[ETH_HDR_LEN + IPV6_HDR_LEN..]),
        &smoltcp::phy::ChecksumCapabilities::default(),
    );

    buf
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use smoltcp::phy::ChecksumCapabilities;

    #[test]
    fn construct_icmpv4_reply_roundtrips() {
        let frame = construct_icmpv4_echo_reply(
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(100, 96, 0, 2),
            0x1234,
            0x0001,
            b"hello",
            EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]),
        );

        let eth = EthernetFrame::new_checked(&frame).unwrap();
        assert_eq!(eth.ethertype(), EthernetProtocol::Ipv4);
        assert_eq!(
            eth.src_addr(),
            EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
        );
        assert_eq!(
            eth.dst_addr(),
            EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02])
        );

        let ipv4 = Ipv4Packet::new_checked(eth.payload()).unwrap();
        assert_eq!(ipv4.src_addr(), Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(ipv4.dst_addr(), Ipv4Addr::new(100, 96, 0, 2));
        assert_eq!(ipv4.next_header(), IpProtocol::Icmp);

        let icmp = Icmpv4Packet::new_checked(ipv4.payload()).unwrap();
        let repr = Icmpv4Repr::parse(&icmp, &ChecksumCapabilities::default()).unwrap();
        assert_eq!(
            repr,
            Icmpv4Repr::EchoReply {
                ident: 0x1234,
                seq_no: 0x0001,
                data: b"hello",
            }
        );
    }

    #[test]
    fn construct_icmpv6_reply_roundtrips() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "fd42:6d73:62::2".parse().unwrap();
        let frame = construct_icmpv6_echo_reply(
            src,
            dst,
            0x5678,
            0x0002,
            b"v6ping",
            EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]),
        );

        let eth = EthernetFrame::new_checked(&frame).unwrap();
        assert_eq!(eth.ethertype(), EthernetProtocol::Ipv6);

        let ipv6 = Ipv6Packet::new_checked(eth.payload()).unwrap();
        assert_eq!(ipv6.next_header(), IpProtocol::Icmpv6);

        let icmp = Icmpv6Packet::new_checked(ipv6.payload()).unwrap();
        let repr = Icmpv6Repr::parse(&src, &dst, &icmp, &ChecksumCapabilities::default()).unwrap();
        assert_eq!(
            repr,
            Icmpv6Repr::EchoReply {
                ident: 0x5678,
                seq_no: 0x0002,
                data: b"v6ping",
            }
        );

        // Verify ICMPv6 checksum is non-zero (mandatory per RFC 8200).
        assert_ne!(icmp.checksum(), 0, "ICMPv6 checksum must not be zero");
        assert!(
            icmp.verify_checksum(&src, &dst,),
            "ICMPv6 checksum must be valid"
        );
    }

    #[test]
    fn construct_icmpv4_reply_preserves_ident_and_seqno() {
        let frame = construct_icmpv4_echo_reply(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(10, 0, 0, 2),
            0xABCD,
            0xEF01,
            b"test-payload",
            EthernetAddress([0; 6]),
            EthernetAddress([0; 6]),
        );

        let eth = EthernetFrame::new_checked(&frame).unwrap();
        let ipv4 = Ipv4Packet::new_checked(eth.payload()).unwrap();
        let icmp = Icmpv4Packet::new_checked(ipv4.payload()).unwrap();
        let repr = Icmpv4Repr::parse(&icmp, &ChecksumCapabilities::default()).unwrap();
        assert_eq!(
            repr,
            Icmpv4Repr::EchoReply {
                ident: 0xABCD,
                seq_no: 0xEF01,
                data: b"test-payload",
            }
        );
    }

    #[test]
    fn construct_icmpv6_reply_preserves_ident_and_seqno() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "fd42:6d73:62::2".parse().unwrap();
        let frame = construct_icmpv6_echo_reply(
            src,
            dst,
            0xBEEF,
            0xCAFE,
            b"test6",
            EthernetAddress([0; 6]),
            EthernetAddress([0; 6]),
        );

        let eth = EthernetFrame::new_checked(&frame).unwrap();
        let ipv6 = Ipv6Packet::new_checked(eth.payload()).unwrap();
        let icmp = Icmpv6Packet::new_checked(ipv6.payload()).unwrap();
        let repr = Icmpv6Repr::parse(&src, &dst, &icmp, &ChecksumCapabilities::default()).unwrap();
        assert_eq!(
            repr,
            Icmpv6Repr::EchoReply {
                ident: 0xBEEF,
                seq_no: 0xCAFE,
                data: b"test6",
            }
        );
    }

    #[test]
    fn probe_does_not_panic() {
        // Result depends on host — just verify it doesn't panic.
        let _ = probe_icmp_socket_v4();
        let _ = probe_icmp_socket_v6();
    }

    #[test]
    fn parse_icmpv4_reply_accepts_bare_icmp() {
        let icmp_repr = Icmpv4Repr::EchoReply {
            ident: 0x1234,
            seq_no: 0x0001,
            data: b"hello",
        };
        let mut buf = vec![0u8; icmp_repr.buffer_len()];
        icmp_repr.emit(
            &mut Icmpv4Packet::new_unchecked(&mut buf),
            &ChecksumCapabilities::default(),
        );

        let (seq_no, data) = parse_icmpv4_echo_reply(&buf).unwrap();
        assert_eq!(seq_no, 0x0001);
        assert_eq!(data, b"hello");
    }

    #[test]
    fn parse_icmpv4_reply_accepts_ipv4_plus_icmp() {
        let frame = construct_icmpv4_echo_reply(
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(100, 96, 0, 2),
            0x1234,
            0x0001,
            b"hello",
            EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]),
        );
        let eth = EthernetFrame::new_checked(&frame).unwrap();

        let (seq_no, data) = parse_icmpv4_echo_reply(eth.payload()).unwrap();
        assert_eq!(seq_no, 0x0001);
        assert_eq!(data, b"hello");
    }

    #[test]
    fn parse_icmpv4_reply_accepts_macos_ping_socket_shape() {
        let buf = [
            0x45, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x75, 0x01, 0x73, 0xef, 0x08, 0x08,
            0x08, 0x08, 0xc0, 0xa8, 0x01, 0x35, 0x00, 0x00, 0xa9, 0xf8, 0x12, 0x34, 0x00, 0x01,
            0x68, 0x65, 0x6c, 0x6c, 0x6f,
        ];

        let (seq_no, data) = parse_icmpv4_echo_reply(&buf).unwrap();
        assert_eq!(seq_no, 0x0001);
        assert_eq!(data, b"hello");
    }

    #[test]
    fn parse_icmpv6_reply_accepts_bare_icmpv6() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "fd42:6d73:62::2".parse().unwrap();
        let icmp_repr = Icmpv6Repr::EchoReply {
            ident: 0x1234,
            seq_no: 0x0002,
            data: b"hello6",
        };
        let mut buf = vec![0u8; icmp_repr.buffer_len()];
        icmp_repr.emit(
            &src,
            &dst,
            &mut Icmpv6Packet::new_unchecked(&mut buf),
            &ChecksumCapabilities::default(),
        );

        let (seq_no, data) = parse_icmpv6_echo_reply(&buf, src, dst).unwrap();
        assert_eq!(seq_no, 0x0002);
        assert_eq!(data, b"hello6");
    }

    #[test]
    fn parse_icmpv6_reply_accepts_ipv6_plus_icmpv6() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "fd42:6d73:62::2".parse().unwrap();
        let frame = construct_icmpv6_echo_reply(
            src,
            dst,
            0x5678,
            0x0002,
            b"v6ping",
            EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]),
        );
        let eth = EthernetFrame::new_checked(&frame).unwrap();

        let (seq_no, data) = parse_icmpv6_echo_reply(eth.payload(), src, dst).unwrap();
        assert_eq!(seq_no, 0x0002);
        assert_eq!(data, b"v6ping");
    }
}
