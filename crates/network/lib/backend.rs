//! `SmoltcpBackend` — libkrun [`NetBackend`] implementation that bridges the
//! NetWorker thread to the smoltcp poll thread via lock-free queues.
//!
//! The NetWorker calls [`write_frame()`](NetBackend::write_frame) when the
//! guest sends a frame and [`read_frame()`](NetBackend::read_frame) to deliver
//! frames back to the guest. Frames flow through [`SharedState`]'s
//! `tx_ring`/`rx_ring` queues with [`WakePipe`](crate::shared::WakePipe)
//! notifications. Unix libkrun registers [`raw_socket_fd`](NetBackend::raw_socket_fd)
//! in edge-triggered mode, while Windows libkrun waits on an event source. Reads
//! must drain the wake primitive before returning.

#[cfg(unix)]
use std::os::fd::RawFd;
use std::sync::Arc;

use microsandbox_utils::performance::PerfExperiment;
use msb_krun::backends::net::{
    NET_F_CSUM, NET_F_HOST_TSO4, NET_F_HOST_TSO6, NetBackend, ReadError, WriteError,
};
#[cfg(windows)]
use msb_krun_utils::event::{EventSource, EventToken};

use crate::shared::SharedState;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Size of the virtio-net header (`virtio_net_hdr_v1`): 12 bytes.
///
/// libkrun's NetWorker prepends this header to every frame buffer. The
/// backend must strip it on TX (guest → smoltcp) and prepend a zeroed
/// header on RX (smoltcp → guest).
const VIRTIO_NET_HDR_LEN: usize = 12;

const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;
const VIRTIO_NET_HDR_GSO_ECN: u8 = 0x80;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_PROVIDER_VLAN: u16 = 0x88a8;
const IP_PROTOCOL_TCP: u8 = 6;
const IP_PROTOCOL_UDP: u8 = 17;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Network backend that bridges libkrun's NetWorker to smoltcp via lock-free
/// queues.
///
/// - **TX path** (`write_frame`): strips the virtio-net header, pushes the
///   ethernet frame to `tx_ring`, wakes the smoltcp poll thread.
/// - **RX path** (`read_frame`): pops a frame from `rx_ring`, prepends a
///   zeroed virtio-net header for the guest.
/// - **Wake source**: returns `rx_wake`'s pollable fd on Unix or waitable
///   event handle on Windows so the NetWorker can detect new frames.
pub struct SmoltcpBackend {
    shared: Arc<SharedState>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VirtioNetHeader {
    flags: u8,
    gso_type: u8,
    hdr_len: usize,
    gso_size: usize,
    csum_start: usize,
    csum_offset: usize,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SmoltcpBackend {
    /// Create a new backend connected to the given shared state.
    pub fn new(shared: Arc<SharedState>) -> Self {
        Self { shared }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl NetBackend for SmoltcpBackend {
    fn max_queue_pairs(&self) -> u16 {
        if PerfExperiment::NetworkMultiqueue.enabled() {
            2
        } else {
            1
        }
    }

    fn supported_features(&self) -> u64 {
        if PerfExperiment::NetworkOffload.enabled() {
            NET_F_CSUM | NET_F_HOST_TSO4 | NET_F_HOST_TSO6
        } else {
            0
        }
    }

    /// Guest is sending a frame. Strip the virtio-net header and enqueue
    /// the raw ethernet frame for smoltcp.
    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
        if hdr_len > buf.len() {
            tracing::warn!(
                hdr_len,
                buffer_len = buf.len(),
                "dropping malformed virtio-net frame"
            );
            return Ok(());
        }

        let frames = if PerfExperiment::NetworkOffload.enabled() {
            match prepare_guest_tx_frames(&buf[..hdr_len], &buf[hdr_len..]) {
                Ok(frames) => frames,
                Err(reason) => {
                    tracing::warn!(%reason, "dropping malformed guest offload frame");
                    return Ok(());
                }
            }
        } else {
            vec![buf[hdr_len..].to_vec()]
        };

        // A segmented packet is atomic at this boundary. Publishing only a prefix would create a
        // valid-looking but permanently truncated TCP stream, so drop the whole group if bounded
        // queue capacity cannot hold it.
        if self.shared.tx_ring.capacity() - self.shared.tx_ring.len() < frames.len() {
            // This backend exposes a wake pipe to libkrun, not a real writable
            // socket. Returning NothingWritten would make the virtio worker
            // undo the TX pop and wait for write readiness that cannot signal
            // tx_ring capacity. Treat overflow like a lossy NIC queue instead:
            // drop the frame and let upper layers retransmit if needed.
            tracing::debug!(
                segments = frames.len(),
                "dropping guest network frame because tx_ring is full"
            );
            return Ok(());
        }

        let mut total_len = 0usize;
        for frame in frames {
            total_len = total_len.saturating_add(frame.len());
            // Capacity was reserved logically above. The stack is the only consumer, so concurrent
            // activity can only create more free slots before these pushes.
            self.shared
                .tx_ring
                .push(frame)
                .expect("preflighted network queue capacity");
        }
        self.shared.add_tx_bytes(total_len);
        self.shared.notify_tx();
        Ok(())
    }

    /// Deliver a frame from smoltcp to the guest. Prepends a zeroed
    /// virtio-net header.
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        self.shared.rx_wake.drain();

        let frame = self.shared.rx_ring.pop().ok_or(ReadError::NothingRead)?;

        let total_len = VIRTIO_NET_HDR_LEN + frame.len();
        if total_len > buf.len() {
            // Frame too large for the buffer — drop it to avoid panicking.
            tracing::debug!(
                frame_len = frame.len(),
                buf_len = buf.len(),
                "dropping oversized frame from rx_ring"
            );
            self.shared.recycle_frame_buffer(frame);
            return Err(ReadError::NothingRead);
        }

        // Prepend zeroed virtio-net header.
        buf[..VIRTIO_NET_HDR_LEN].fill(0);
        buf[VIRTIO_NET_HDR_LEN..total_len].copy_from_slice(&frame);
        self.shared.recycle_frame_buffer(frame);

        Ok(total_len)
    }

    /// No partial writes — queue push is atomic.
    fn has_unfinished_write(&self) -> bool {
        false
    }

    /// No partial writes — nothing to finish.
    fn try_finish_write(&mut self, _hdr_len: usize, _buf: &[u8]) -> Result<(), WriteError> {
        Ok(())
    }

    /// File descriptor for NetWorker's epoll. Becomes readable when
    /// `rx_ring` has frames for the guest (i.e. when smoltcp's
    /// `SmoltcpDevice::transmit()` pushes a frame and wakes `rx_wake`).
    #[cfg(unix)]
    fn raw_socket_fd(&self) -> RawFd {
        self.shared.rx_wake.as_raw_fd()
    }

    /// Waitable event source for NetWorker on Windows.
    #[cfg(windows)]
    fn event_source(&self, token: EventToken) -> EventSource {
        EventSource::waitable_handle(self.shared.rx_wake.as_raw_handle(), token)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn prepare_guest_tx_frames(header: &[u8], frame: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    let header = parse_virtio_net_header(header)?;
    let gso_type = header.gso_type & !VIRTIO_NET_HDR_GSO_ECN;
    if gso_type == VIRTIO_NET_HDR_GSO_NONE {
        let mut frame = frame.to_vec();
        if header.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
            complete_transport_checksum(&mut frame, header.csum_start, header.csum_offset)?;
        }
        return Ok(vec![frame]);
    }

    if !matches!(
        gso_type,
        VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_TCPV6
    ) {
        return Err("unsupported GSO type");
    }
    segment_tcp_frame(frame, header, gso_type)
}

fn parse_virtio_net_header(header: &[u8]) -> Result<VirtioNetHeader, &'static str> {
    if header.len() < VIRTIO_NET_HDR_LEN {
        return Err("virtio-net header is truncated");
    }
    Ok(VirtioNetHeader {
        flags: header[0],
        gso_type: header[1],
        hdr_len: u16::from_le_bytes([header[2], header[3]]) as usize,
        gso_size: u16::from_le_bytes([header[4], header[5]]) as usize,
        csum_start: u16::from_le_bytes([header[6], header[7]]) as usize,
        csum_offset: u16::from_le_bytes([header[8], header[9]]) as usize,
    })
}

fn segment_tcp_frame(
    frame: &[u8],
    header: VirtioNetHeader,
    gso_type: u8,
) -> Result<Vec<Vec<u8>>, &'static str> {
    if header.gso_size == 0 || header.hdr_len > frame.len() || header.csum_start >= header.hdr_len {
        return Err("invalid TCP GSO geometry");
    }
    if header.csum_start + 20 > header.hdr_len {
        return Err("TCP header is truncated");
    }
    let tcp_header_len = usize::from(frame[header.csum_start + 12] >> 4) * 4;
    if tcp_header_len < 20 || header.csum_start + tcp_header_len != header.hdr_len {
        return Err("TCP data offset does not match GSO header length");
    }

    let (ip_start, ethertype) = ethernet_network_header(frame)?;
    let expected_ethertype = if gso_type == VIRTIO_NET_HDR_GSO_TCPV4 {
        ETHERTYPE_IPV4
    } else {
        ETHERTYPE_IPV6
    };
    if ethertype != expected_ethertype {
        return Err("GSO type does not match network header");
    }

    let payload = &frame[header.hdr_len..];
    if payload.is_empty() {
        return Err("TCP GSO packet has no payload");
    }
    let segment_count = payload.len().div_ceil(header.gso_size).max(1);
    let initial_sequence = read_be_u32(frame, header.csum_start + 4)?;
    let initial_ipv4_id = (ethertype == ETHERTYPE_IPV4)
        .then(|| read_be_u16(frame, ip_start + 4))
        .transpose()?;
    let mut segments = Vec::with_capacity(segment_count);

    for (index, chunk) in payload.chunks(header.gso_size).enumerate() {
        let mut segment = Vec::with_capacity(header.hdr_len + chunk.len());
        segment.extend_from_slice(&frame[..header.hdr_len]);
        segment.extend_from_slice(chunk);
        write_be_u32(
            &mut segment,
            header.csum_start + 4,
            initial_sequence.wrapping_add((index * header.gso_size) as u32),
        )?;

        let last = index + 1 == segment_count;
        if !last {
            // FIN and PSH describe the original aggregate and belong only on its final segment.
            segment[header.csum_start + 13] &= !(0x01 | 0x08);
        }
        if index > 0 {
            // CWR is emitted only on the first segment of an ECN-capable aggregate.
            segment[header.csum_start + 13] &= !0x80;
        }

        if ethertype == ETHERTYPE_IPV4 {
            let ip_packet_len = segment.len() - ip_start;
            let ip_header_len = usize::from(segment[ip_start] & 0x0f) * 4;
            if ip_header_len < 20 || ip_start + ip_header_len > header.csum_start {
                return Err("invalid IPv4 header length");
            }
            write_be_u16(&mut segment, ip_start + 2, ip_packet_len)?;
            write_be_u16(
                &mut segment,
                ip_start + 4,
                usize::from(initial_ipv4_id.unwrap().wrapping_add(index as u16)),
            )?;
            write_be_u16(&mut segment, ip_start + 10, 0)?;
            let checksum = internet_checksum(&segment[ip_start..ip_start + ip_header_len]);
            write_be_u16(&mut segment, ip_start + 10, usize::from(checksum))?;
        } else {
            if ip_start + 40 > header.csum_start {
                return Err("IPv6 header is truncated");
            }
            let ipv6_payload_len = segment.len() - ip_start - 40;
            write_be_u16(&mut segment, ip_start + 4, ipv6_payload_len)?;
        }
        complete_transport_checksum(&mut segment, header.csum_start, header.csum_offset)?;
        segments.push(segment);
    }

    Ok(segments)
}

fn complete_transport_checksum(
    frame: &mut [u8],
    transport_start: usize,
    checksum_offset: usize,
) -> Result<(), &'static str> {
    let checksum_at = transport_start
        .checked_add(checksum_offset)
        .ok_or("checksum offset overflow")?;
    if checksum_at + 2 > frame.len() || transport_start >= frame.len() {
        return Err("checksum field is outside frame");
    }
    let (ip_start, ethertype) = ethernet_network_header(frame)?;
    let protocol = match ethertype {
        ETHERTYPE_IPV4 => {
            if ip_start + 20 > frame.len() || frame[ip_start] >> 4 != 4 {
                return Err("invalid IPv4 packet");
            }
            frame[ip_start + 9]
        }
        ETHERTYPE_IPV6 => {
            if ip_start + 40 > frame.len() || frame[ip_start] >> 4 != 6 {
                return Err("invalid IPv6 packet");
            }
            frame[ip_start + 6]
        }
        _ => return Err("checksum offload requires IPv4 or IPv6"),
    };
    if !matches!(protocol, IP_PROTOCOL_TCP | IP_PROTOCOL_UDP) {
        return Err("checksum offload requires TCP or UDP");
    }

    frame[checksum_at..checksum_at + 2].fill(0);
    let transport_len = frame.len() - transport_start;
    let mut sum = match ethertype {
        ETHERTYPE_IPV4 => checksum_sum(&frame[ip_start + 12..ip_start + 20]),
        ETHERTYPE_IPV6 => checksum_sum(&frame[ip_start + 8..ip_start + 40]),
        _ => unreachable!(),
    };
    if ethertype == ETHERTYPE_IPV6 {
        sum += u64::from(transport_len as u32 >> 16);
    }
    sum += u64::from((transport_len as u32) & 0xffff);
    sum += u64::from(protocol);
    sum += checksum_sum(&frame[transport_start..]);
    let checksum = fold_checksum(sum);
    write_be_u16(frame, checksum_at, usize::from(checksum))
}

fn ethernet_network_header(frame: &[u8]) -> Result<(usize, u16), &'static str> {
    if frame.len() < 14 {
        return Err("Ethernet frame is truncated");
    }
    let mut offset = 14usize;
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    while matches!(ethertype, ETHERTYPE_VLAN | ETHERTYPE_PROVIDER_VLAN) {
        if offset + 4 > frame.len() {
            return Err("VLAN header is truncated");
        }
        ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }
    Ok((offset, ethertype))
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    fold_checksum(checksum_sum(bytes))
}

fn checksum_sum(bytes: &[u8]) -> u64 {
    let mut chunks = bytes.chunks_exact(2);
    let mut sum = chunks
        .by_ref()
        .map(|word| u64::from(u16::from_be_bytes([word[0], word[1]])))
        .sum::<u64>();
    if let Some(byte) = chunks.remainder().first() {
        sum += u64::from(*byte) << 8;
    }
    sum
}

fn fold_checksum(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn read_be_u16(bytes: &[u8], offset: usize) -> Result<u16, &'static str> {
    let word = bytes.get(offset..offset + 2).ok_or("field is truncated")?;
    Ok(u16::from_be_bytes([word[0], word[1]]))
}

fn read_be_u32(bytes: &[u8], offset: usize) -> Result<u32, &'static str> {
    let word = bytes.get(offset..offset + 4).ok_or("field is truncated")?;
    Ok(u32::from_be_bytes([word[0], word[1], word[2], word[3]]))
}

fn write_be_u16(bytes: &mut [u8], offset: usize, value: usize) -> Result<(), &'static str> {
    let value = u16::try_from(value).map_err(|_| "16-bit field overflow")?;
    let field = bytes
        .get_mut(offset..offset + 2)
        .ok_or("field is truncated")?;
    field.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn write_be_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), &'static str> {
    let field = bytes
        .get_mut(offset..offset + 4)
        .ok_or("field is truncated")?;
    field.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, unix))]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn read_frame_drains_rx_wake_pipe() {
        let shared = Arc::new(SharedState::new(4));
        let mut backend = SmoltcpBackend::new(shared.clone());
        let mut buf = [0u8; 64];

        assert!(shared.push_rx_frame_and_wake(vec![0xaa, 0xbb]));
        assert!(fd_is_readable(backend.raw_socket_fd()));

        let n = backend.read_frame(&mut buf).expect("frame should be read");
        assert_eq!(n, VIRTIO_NET_HDR_LEN + 2);
        assert_eq!(&buf[VIRTIO_NET_HDR_LEN..n], &[0xaa, 0xbb]);
        assert!(!fd_is_readable(backend.raw_socket_fd()));

        assert!(shared.push_rx_frame_and_wake(vec![0xcc]));
        assert!(fd_is_readable(backend.raw_socket_fd()));
    }

    #[test]
    fn write_frame_enqueues_guest_frame_and_wakes_poll_loop() {
        let shared = Arc::new(SharedState::new(1));
        let mut backend = SmoltcpBackend::new(shared.clone());
        let mut buf = vec![0u8; VIRTIO_NET_HDR_LEN + 3];
        buf[VIRTIO_NET_HDR_LEN..].copy_from_slice(&[0xaa, 0xbb, 0xcc]);

        backend
            .write_frame(VIRTIO_NET_HDR_LEN, &mut buf)
            .expect("accepted frame should be queued");

        assert_eq!(shared.tx_bytes(), 3);
        assert!(fd_is_readable(shared.tx_wake.as_raw_fd()));
        assert_eq!(shared.tx_ring.pop(), Some(vec![0xaa, 0xbb, 0xcc]));
    }

    #[test]
    fn write_frame_drops_guest_frame_when_tx_ring_is_full() {
        let shared = Arc::new(SharedState::new(1));
        shared.tx_ring.push(vec![0x11]).unwrap();
        let mut backend = SmoltcpBackend::new(shared.clone());
        let mut buf = vec![0u8; VIRTIO_NET_HDR_LEN + 2];
        buf[VIRTIO_NET_HDR_LEN..].copy_from_slice(&[0xaa, 0xbb]);

        backend
            .write_frame(VIRTIO_NET_HDR_LEN, &mut buf)
            .expect("overflow should not stall the virtio TX queue");

        assert_eq!(shared.tx_bytes(), 0);
        assert_eq!(shared.tx_ring.pop(), Some(vec![0x11]));
        assert_eq!(shared.tx_ring.pop(), None);
    }

    #[test]
    fn checksum_offload_completes_ipv4_udp_checksum() {
        let mut frame = ipv4_transport_frame(IP_PROTOCOL_UDP, 8, 32);
        let header = virtio_header(
            VIRTIO_NET_HDR_F_NEEDS_CSUM,
            VIRTIO_NET_HDR_GSO_NONE,
            0,
            34,
            6,
        );

        let frames = prepare_guest_tx_frames(&header, &frame).unwrap();
        assert_eq!(frames.len(), 1);
        frame = frames.into_iter().next().unwrap();
        assert_ne!(read_be_u16(&frame, 40).unwrap(), 0);

        let mut sum = checksum_sum(&frame[26..34]);
        sum += u64::from((frame.len() - 34) as u16);
        sum += u64::from(IP_PROTOCOL_UDP);
        sum += checksum_sum(&frame[34..]);
        assert_eq!(fold_checksum(sum), 0);
    }

    #[test]
    fn tcpv4_gso_segments_payload_and_updates_sequence_and_flags() {
        let mut frame = ipv4_transport_frame(IP_PROTOCOL_TCP, 20, 3_000);
        frame[47] = 0x19; // ACK + PSH + FIN.
        write_be_u32(&mut frame, 38, 1000).unwrap();
        let header = virtio_header(
            VIRTIO_NET_HDR_F_NEEDS_CSUM,
            VIRTIO_NET_HDR_GSO_TCPV4,
            1_200,
            34,
            16,
        );

        let segments = prepare_guest_tx_frames(&header, &frame).unwrap();
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].len(), 54 + 1_200);
        assert_eq!(segments[1].len(), 54 + 1_200);
        assert_eq!(segments[2].len(), 54 + 600);
        assert_eq!(read_be_u32(&segments[0], 38).unwrap(), 1000);
        assert_eq!(read_be_u32(&segments[1], 38).unwrap(), 2200);
        assert_eq!(read_be_u32(&segments[2], 38).unwrap(), 3400);
        assert_eq!(segments[0][47] & (0x01 | 0x08), 0);
        assert_eq!(segments[1][47] & (0x01 | 0x08), 0);
        assert_eq!(segments[2][47] & (0x01 | 0x08), 0x01 | 0x08);
        for segment in segments {
            assert_eq!(
                usize::from(read_be_u16(&segment, 16).unwrap()),
                segment.len() - 14
            );
            assert_eq!(internet_checksum(&segment[14..34]), 0);
        }
    }

    fn virtio_header(
        flags: u8,
        gso_type: u8,
        gso_size: u16,
        csum_start: u16,
        csum_offset: u16,
    ) -> [u8; 12] {
        let mut header = [0u8; 12];
        header[0] = flags;
        header[1] = gso_type;
        header[2..4].copy_from_slice(&54u16.to_le_bytes());
        header[4..6].copy_from_slice(&gso_size.to_le_bytes());
        header[6..8].copy_from_slice(&csum_start.to_le_bytes());
        header[8..10].copy_from_slice(&csum_offset.to_le_bytes());
        header
    }

    fn ipv4_transport_frame(
        protocol: u8,
        transport_header_len: usize,
        payload_len: usize,
    ) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 20 + transport_header_len + payload_len];
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame[14] = 0x45;
        frame[22] = 64;
        frame[23] = protocol;
        frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
        frame[30..34].copy_from_slice(&[198, 51, 100, 2]);
        let total_len = frame.len() - 14;
        write_be_u16(&mut frame, 16, total_len).unwrap();
        if protocol == IP_PROTOCOL_TCP {
            frame[46] = 5 << 4;
        } else {
            let udp_len = transport_header_len + payload_len;
            write_be_u16(&mut frame, 38, udp_len).unwrap();
        }
        for (index, byte) in frame[14 + 20 + transport_header_len..]
            .iter_mut()
            .enumerate()
        {
            *byte = index as u8;
        }
        frame
    }

    fn fd_is_readable(fd: RawFd) -> bool {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };

        // SAFETY: `pfd` points to a valid pollfd for a live file descriptor.
        let ret = unsafe { libc::poll(&mut pfd, 1, 0) };
        assert!(ret >= 0, "poll failed: {}", std::io::Error::last_os_error());

        ret == 1 && pfd.revents & libc::POLLIN != 0
    }
}
