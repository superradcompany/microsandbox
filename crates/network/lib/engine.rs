//! Packet relay engine.
//!
//! The common engine sits above the platform backends and drives the
//! bidirectional frame relay between the VM (via Unixgram socketpair)
//! and the host network backend (TAP or vmnet).

use std::{
    net::IpAddr,
    os::fd::{AsRawFd, RawFd},
};

use etherparse::{PacketBuilder, TransportSlice};
use tokio::io::{Interest, unix::AsyncFd};

use crate::{
    dns::{DnsInterceptResponse, DnsInterceptResult, DnsInterceptor, TcpResponseFlags},
    host::FrameTransport,
    packet::ParsedFrame,
    policy::{Action, Direction, PolicyEngine},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum ethernet frame size (14-byte header + 1500 MTU).
/// Jumbo frames are not supported — MTU > 1500 is rejected at config time.
pub const MAX_FRAME_SIZE: usize = 1514;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Packet relay engine configuration.
pub struct EngineConfig {
    /// Unixgram socket FD connected to the VM.
    pub vm_fd: RawFd,

    /// Host backend transport (TAP device or vmnet).
    pub backend: Box<dyn FrameTransport>,

    /// Policy engine for allow/deny decisions.
    pub policy: PolicyEngine,

    /// DNS interceptor for gateway-bound DNS queries.
    pub dns: DnsInterceptor,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Runs the packet relay engine.
///
/// Multiplexes between:
/// 1. Frames from VM → parse → policy → DNS intercept → write to backend
/// 2. Frames from backend → parse → policy → write to VM
///
/// Returns when either FD is closed or an unrecoverable error occurs.
pub async fn run(config: EngineConfig) -> std::io::Result<()> {
    let vm_async = AsyncFd::new(config.vm_fd)?;
    let backend_async = AsyncFd::new(config.backend.ready_fd())?;

    let mut vm_buf = [0u8; MAX_FRAME_SIZE];
    let mut backend_buf = [0u8; MAX_FRAME_SIZE];

    loop {
        tokio::select! {
            // VM → backend (outbound).
            result = vm_async.ready(Interest::READABLE) => {
                let mut guard = result?;

                match guard.try_io(|fd| read_frame(fd.as_raw_fd(), &mut vm_buf)) {
                    Ok(Ok(n)) => {
                        let frame_bytes = &vm_buf[..n];
                        handle_outbound(
                            frame_bytes,
                            &config.policy,
                            &config.dns,
                            config.backend.as_ref(),
                            vm_async.as_raw_fd(),
                        ).await;
                    }
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                        return Ok(());
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => continue,
                }
            }

            // Backend → VM (inbound).
            result = backend_async.ready(Interest::READABLE) => {
                let mut guard = result?;

                match guard.try_io(|_| config.backend.read_frame(&mut backend_buf)) {
                    Ok(Ok(n)) => {
                        if n > 0 {
                            let frame_bytes = &backend_buf[..n];
                            handle_inbound(
                                frame_bytes,
                                &config.policy,
                                vm_async.as_raw_fd(),
                            );
                        }
                        drain_backend_frames(
                            config.backend.as_ref(),
                            &config.policy,
                            vm_async.as_raw_fd(),
                            &mut backend_buf,
                        )?;
                    }
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                        return Ok(());
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => continue,
                }
            }
        }
    }
}

/// Handles an outbound frame (VM → backend).
///
/// 1. Parse headers
/// 2. Check for DNS interception
/// 3. Evaluate policy
/// 4. Forward or drop
async fn handle_outbound(
    frame: &[u8],
    policy: &PolicyEngine,
    dns: &DnsInterceptor,
    backend: &dyn FrameTransport,
    vm_fd: RawFd,
) {
    let parsed = match ParsedFrame::parse(frame) {
        Some(p) => p,
        None => return, // Malformed frame — drop silently.
    };

    // L2 control traffic (ARP, NDP, broadcast): forward unconditionally
    // without policy evaluation. The host kernel / vmnet owns the gateway
    // identity and answers ARP/NDP — msbnet only relays these frames.
    // ARP has no IP headers (dst_ip is None). NDP rides on IPv6 (ICMPv6
    // types 133-137) so dst_ip is Some — check explicitly.
    if parsed.dst_ip().is_none() || parsed.is_ndp() {
        let _ = backend.write_frame(frame);
        return;
    }

    // DNS interception: if this is a DNS query (dst port 53) to the
    // gateway, handle it locally and send the response back to the VM.
    if parsed.dst_port() == Some(crate::packet::DNS_PORT) {
        match dns.maybe_intercept(&parsed).await {
            DnsInterceptResult::NotIntercepted => {}
            DnsInterceptResult::Intercepted => return,
            DnsInterceptResult::Responses(responses) => {
                for response in responses {
                    if let Some(response_frame) = build_dns_response_frame(&parsed, &response) {
                        let _ = write_frame(vm_fd, &response_frame);
                    }
                }
                return;
            }
        }
    }

    // Policy check.
    if policy.evaluate(&parsed, Direction::Outbound) == Action::Deny {
        return; // Drop.
    }

    // Forward to backend.
    let _ = backend.write_frame(frame);
}

/// Handles an inbound frame (backend → VM).
///
/// 1. Parse headers
/// 2. Evaluate policy
/// 3. Forward or drop
fn handle_inbound(frame: &[u8], policy: &PolicyEngine, vm_fd: RawFd) {
    let parsed = match ParsedFrame::parse(frame) {
        Some(p) => p,
        None => return,
    };

    // L2 control traffic (ARP, NDP): forward unconditionally.
    if parsed.dst_ip().is_none() || parsed.is_ndp() {
        let _ = write_frame(vm_fd, frame);
        return;
    }

    if policy.evaluate(&parsed, Direction::Inbound) == Action::Deny {
        return;
    }

    let _ = write_frame(vm_fd, frame);
}

fn drain_backend_frames(
    backend: &dyn FrameTransport,
    policy: &PolicyEngine,
    vm_fd: RawFd,
    buf: &mut [u8],
) -> std::io::Result<()> {
    loop {
        match backend.read_frame(buf) {
            Ok(0) => return Ok(()),
            Ok(n) => handle_inbound(&buf[..n], policy, vm_fd),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => return Ok(()),
            Err(err) => return Err(err),
        }
    }
}

/// Reads a frame from a raw FD.
fn read_frame(fd: RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Writes a frame to a raw FD.
fn write_frame(fd: RawFd, buf: &[u8]) -> std::io::Result<()> {
    let n = unsafe { libc::send(fd, buf.as_ptr().cast(), buf.len(), 0) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn build_dns_response_frame(
    request: &ParsedFrame<'_>,
    response: &DnsInterceptResponse,
) -> Option<Vec<u8>> {
    let src_mac = request.dst_mac()?;
    let dst_mac = request.src_mac()?;
    let src_port = request.dst_port()?;
    let dst_port = request.src_port()?;
    let payload = response.payload.as_slice();

    match &request.sliced().transport {
        Some(TransportSlice::Udp(_)) => {
            let mut frame = Vec::new();

            match (request.dst_ip()?, request.src_ip()?) {
                (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
                    PacketBuilder::ethernet2(src_mac, dst_mac)
                        .ipv4(src_ip.octets(), dst_ip.octets(), 64)
                        .udp(src_port, dst_port)
                        .write(&mut frame, payload)
                        .ok()?;
                }
                (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
                    PacketBuilder::ethernet2(src_mac, dst_mac)
                        .ipv6(src_ip.octets(), dst_ip.octets(), 64)
                        .udp(src_port, dst_port)
                        .write(&mut frame, payload)
                        .ok()?;
                }
                _ => return None,
            }

            Some(frame)
        }
        Some(TransportSlice::Tcp(tcp)) => {
            let flags = response.tcp_flags.unwrap_or(TcpResponseFlags {
                syn: false,
                ack: true,
                fin: false,
                rst: false,
                psh: !payload.is_empty(),
            });

            if !tcp.ack() && !flags.syn {
                return None;
            }

            let mut sequence_advance = u32::try_from(tcp.payload().len()).ok()?;
            if tcp.syn() {
                sequence_advance = sequence_advance.wrapping_add(1);
            }
            if tcp.fin() {
                sequence_advance = sequence_advance.wrapping_add(1);
            }

            let mut frame = Vec::new();
            let sequence_number = response
                .tcp_sequence_number
                .unwrap_or_else(|| tcp.acknowledgment_number());
            let acknowledgment_number = response
                .tcp_acknowledgment_number
                .unwrap_or_else(|| tcp.sequence_number().wrapping_add(sequence_advance));

            match (request.dst_ip()?, request.src_ip()?) {
                (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
                    let mut builder = PacketBuilder::ethernet2(src_mac, dst_mac)
                        .ipv4(src_ip.octets(), dst_ip.octets(), 64)
                        .tcp(src_port, dst_port, sequence_number, tcp.window_size());
                    if flags.ack {
                        builder = builder.ack(acknowledgment_number);
                    }
                    if flags.syn {
                        builder = builder.syn();
                    }
                    if flags.fin {
                        builder = builder.fin();
                    }
                    if flags.rst {
                        builder = builder.rst();
                    }
                    if flags.psh {
                        builder = builder.psh();
                    }
                    builder.write(&mut frame, payload).ok()?;
                }
                (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
                    let mut builder = PacketBuilder::ethernet2(src_mac, dst_mac)
                        .ipv6(src_ip.octets(), dst_ip.octets(), 64)
                        .tcp(src_port, dst_port, sequence_number, tcp.window_size());
                    if flags.ack {
                        builder = builder.ack(acknowledgment_number);
                    }
                    if flags.syn {
                        builder = builder.syn();
                    }
                    if flags.fin {
                        builder = builder.fin();
                    }
                    if flags.rst {
                        builder = builder.rst();
                    }
                    if flags.psh {
                        builder = builder.psh();
                    }
                    builder.write(&mut frame, payload).ok()?;
                }
                _ => return None,
            }

            Some(frame)
        }
        _ => None,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn build_udp_frame_v4(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        PacketBuilder::ethernet2(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        )
        .ipv4(src_ip, dst_ip, 64)
        .udp(src_port, dst_port)
        .write(&mut buf, payload)
        .unwrap();
        buf
    }

    fn build_udp_frame_v6(
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        PacketBuilder::ethernet2(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        )
        .ipv6(src_ip, dst_ip, 64)
        .udp(src_port, dst_port)
        .write(&mut buf, payload)
        .unwrap();
        buf
    }

    fn build_tcp_frame_v4(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        sequence_number: u32,
        acknowledgment_number: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        PacketBuilder::ethernet2(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        )
        .ipv4(src_ip, dst_ip, 64)
        .tcp(src_port, dst_port, sequence_number, 65535)
        .ack(acknowledgment_number)
        .psh()
        .write(&mut buf, payload)
        .unwrap();
        buf
    }

    #[test]
    fn test_build_dns_response_frame_ipv4() {
        let request = build_udp_frame_v4([100, 96, 0, 2], [100, 96, 0, 1], 51000, 53, b"query");
        let parsed = ParsedFrame::parse(&request).unwrap();

        let response = build_dns_response_frame(
            &parsed,
            &DnsInterceptResponse {
                payload: b"answer".to_vec(),
                tcp_sequence_number: None,
                tcp_acknowledgment_number: None,
                tcp_flags: None,
            },
        )
        .unwrap();
        let parsed_response = ParsedFrame::parse(&response).unwrap();

        assert_eq!(
            parsed_response.src_ip(),
            Some(IpAddr::V4(Ipv4Addr::new(100, 96, 0, 1)))
        );
        assert_eq!(
            parsed_response.dst_ip(),
            Some(IpAddr::V4(Ipv4Addr::new(100, 96, 0, 2)))
        );
        assert_eq!(parsed_response.src_port(), Some(53));
        assert_eq!(parsed_response.dst_port(), Some(51000));
        assert_eq!(parsed_response.payload(), b"answer");
    }

    #[test]
    fn test_build_dns_response_frame_ipv6() {
        let request = build_udp_frame_v6(
            "fd42:6d73:62:2a::2".parse::<Ipv6Addr>().unwrap().octets(),
            "fd42:6d73:62:2a::1".parse::<Ipv6Addr>().unwrap().octets(),
            51000,
            53,
            b"query",
        );
        let parsed = ParsedFrame::parse(&request).unwrap();

        let response = build_dns_response_frame(
            &parsed,
            &DnsInterceptResponse {
                payload: b"answer".to_vec(),
                tcp_sequence_number: None,
                tcp_acknowledgment_number: None,
                tcp_flags: None,
            },
        )
        .unwrap();
        let parsed_response = ParsedFrame::parse(&response).unwrap();

        assert_eq!(
            parsed_response.src_ip(),
            Some(IpAddr::V6(
                "fd42:6d73:62:2a::1".parse::<Ipv6Addr>().unwrap()
            ))
        );
        assert_eq!(
            parsed_response.dst_ip(),
            Some(IpAddr::V6(
                "fd42:6d73:62:2a::2".parse::<Ipv6Addr>().unwrap()
            ))
        );
        assert_eq!(parsed_response.src_port(), Some(53));
        assert_eq!(parsed_response.dst_port(), Some(51000));
        assert_eq!(parsed_response.payload(), b"answer");
    }

    #[test]
    fn test_build_dns_response_frame_tcp_ipv4() {
        let request = build_tcp_frame_v4(
            [100, 96, 0, 2],
            [100, 96, 0, 1],
            51000,
            53,
            10,
            200,
            b"\x00\x06query!",
        );
        let parsed = ParsedFrame::parse(&request).unwrap();

        let response = build_dns_response_frame(
            &parsed,
            &DnsInterceptResponse {
                payload: b"\x00\x07answer!".to_vec(),
                tcp_sequence_number: Some(200),
                tcp_acknowledgment_number: Some(18),
                tcp_flags: Some(TcpResponseFlags {
                    syn: false,
                    ack: true,
                    fin: false,
                    rst: false,
                    psh: true,
                }),
            },
        )
        .unwrap();
        let parsed_response = ParsedFrame::parse(&response).unwrap();

        assert_eq!(
            parsed_response.src_ip(),
            Some(IpAddr::V4(Ipv4Addr::new(100, 96, 0, 1)))
        );
        assert_eq!(
            parsed_response.dst_ip(),
            Some(IpAddr::V4(Ipv4Addr::new(100, 96, 0, 2)))
        );
        assert_eq!(parsed_response.src_port(), Some(53));
        assert_eq!(parsed_response.dst_port(), Some(51000));
        assert_eq!(parsed_response.payload(), b"\x00\x07answer!");

        match &parsed_response.sliced().transport {
            Some(TransportSlice::Tcp(tcp)) => {
                assert_eq!(tcp.sequence_number(), 200);
                assert_eq!(tcp.acknowledgment_number(), 18);
                assert!(tcp.ack());
                assert!(tcp.psh());
            }
            _ => panic!("expected TCP response"),
        }
    }

    #[test]
    fn test_build_dns_response_frame_tcp_syn_ack_ipv4() {
        let request = build_tcp_frame_v4([100, 96, 0, 2], [100, 96, 0, 1], 51000, 53, 10, 0, b"");
        let parsed = ParsedFrame::parse(&request).unwrap();

        let response = build_dns_response_frame(
            &parsed,
            &DnsInterceptResponse {
                payload: Vec::new(),
                tcp_sequence_number: Some(200),
                tcp_acknowledgment_number: Some(11),
                tcp_flags: Some(TcpResponseFlags {
                    syn: true,
                    ack: true,
                    fin: false,
                    rst: false,
                    psh: false,
                }),
            },
        )
        .unwrap();
        let parsed_response = ParsedFrame::parse(&response).unwrap();

        match &parsed_response.sliced().transport {
            Some(TransportSlice::Tcp(tcp)) => {
                assert!(tcp.syn());
                assert!(tcp.ack());
                assert_eq!(tcp.sequence_number(), 200);
                assert_eq!(tcp.acknowledgment_number(), 11);
            }
            _ => panic!("expected TCP SYN-ACK response"),
        }
    }
}
