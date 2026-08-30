use std::collections::VecDeque;
use std::io;
use std::num::Wrapping;
use std::sync::{Arc, Mutex};

#[cfg(unix)]
use std::collections::HashMap;

use utils::epoll::EventSet;
use vm_memory::GuestMemoryMmap;

use super::super::Queue as VirtQueue;
use super::defs::{self, uapi};
use super::muxer::{push_packet, MuxerRx};
use super::muxer_rxq::MuxerRxQ;
use super::packet::VsockPacket;
#[cfg(unix)]
use super::packet::{TsiAcceptReq, TsiConnectReq, TsiListenReq, TsiSendtoAddr};
use super::proxy::{Proxy, ProxyRemoval, ProxyStatus, ProxyUpdate, RecvPkt};
use super::{VsockConnectState, VsockNotifier, VsockPollable, VsockShutdown, VsockStreamBackend};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Platform-neutral proxy around a custom stream backend.
pub struct CustomStreamProxy {
    id: u64,
    cid: u64,
    backend: Box<dyn VsockStreamBackend>,
    notifier: VsockNotifier,
    status: ProxyStatus,
    mem: GuestMemoryMmap,
    queue: Arc<Mutex<VirtQueue>>,
    rxq: Arc<Mutex<MuxerRxQ>>,
    peer_port: u32,
    local_port: u32,
    peer_fwd_cnt: Wrapping<u32>,
    peer_buf_alloc: u32,
    tx_cnt: Wrapping<u32>,
    last_tx_cnt_sent: Wrapping<u32>,
    rx_cnt: Wrapping<u32>,
    pending_write: VecDeque<u8>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CustomStreamProxy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: u64,
        cid: u64,
        local_port: u32,
        peer_port: u32,
        backend: Box<dyn VsockStreamBackend>,
        notifier: VsockNotifier,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        rxq: Arc<Mutex<MuxerRxQ>>,
    ) -> io::Result<Self> {
        let status = match backend.connect_state()? {
            VsockConnectState::Connecting => ProxyStatus::Connecting,
            VsockConnectState::Connected => ProxyStatus::Connected,
        };

        Ok(Self {
            id,
            cid,
            backend,
            notifier,
            status,
            mem,
            queue,
            rxq,
            peer_port,
            local_port,
            peer_fwd_cnt: Wrapping(0),
            peer_buf_alloc: 0,
            tx_cnt: Wrapping(0),
            last_tx_cnt_sent: Wrapping(0),
            rx_cnt: Wrapping(0),
            pending_write: VecDeque::new(),
        })
    }

    pub fn is_connecting(&self) -> bool {
        self.status == ProxyStatus::Connecting
    }

    /// Record peer flow-control state while a route connection is pending.
    pub fn prepare_connect(&mut self, pkt: &VsockPacket) {
        self.peer_buf_alloc = pkt.buf_alloc();
        self.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());
        self.local_port = pkt.dst_port();
        self.peer_port = pkt.src_port();
    }

    fn uses_notifier(&self) -> bool {
        self.backend.pollable().is_none()
    }

    fn event_pollable(&self) -> VsockPollable {
        self.backend
            .pollable()
            .unwrap_or_else(|| self.notifier.pollable())
    }

    fn connected_poll_events(&self) -> EventSet {
        if self.uses_notifier() || self.pending_write.is_empty() {
            EventSet::IN
        } else {
            EventSet::IN | EventSet::OUT
        }
    }

    fn connecting_poll_events(&self) -> EventSet {
        if self.uses_notifier() {
            EventSet::IN
        } else {
            EventSet::IN | EventSet::OUT
        }
    }

    fn clear_notification(&self) {
        if self.uses_notifier() {
            if let Err(err) = self.notifier.clear() {
                warn!("failed to clear custom vsock notification: {err}");
            }
        }
    }

    fn push_connect_response(&self) {
        push_packet(
            self.cid,
            MuxerRx::OpResponse {
                local_port: self.local_port,
                peer_port: self.peer_port,
            },
            &self.rxq,
            &self.queue,
            &self.mem,
        );
    }

    fn push_reset(&self) {
        push_packet(
            self.cid,
            MuxerRx::Reset {
                local_port: self.local_port,
                peer_port: self.peer_port,
            },
            &self.rxq,
            &self.queue,
            &self.mem,
        );
    }

    fn peer_avail_credit(&self) -> usize {
        (Wrapping(self.peer_buf_alloc) - (self.rx_cnt - self.peer_fwd_cnt)).0 as usize
    }

    fn recv_to_pkt(&self, pkt: &mut VsockPacket) -> RecvPkt {
        let Some(buf) = pkt.buf_mut() else {
            return RecvPkt::Error;
        };
        let max_len = buf.len().min(self.peer_avail_credit());
        if max_len == 0 {
            return RecvPkt::WaitForCredit;
        }

        match self.backend.read(&mut buf[..max_len]) {
            Ok(0) => RecvPkt::Close,
            Ok(count) if count <= max_len => RecvPkt::Read(count),
            Ok(count) => {
                warn!(
                    "vsock backend returned invalid read length: count={count}, capacity={max_len}"
                );
                RecvPkt::Error
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => RecvPkt::Error,
            Err(err) => {
                debug!("custom vsock backend read failed: {err}");
                RecvPkt::Error
            }
        }
    }

    fn recv_pkt(&mut self) -> (bool, bool) {
        let mut have_used = false;
        let mut wait_credit = false;
        let mut queue = self.queue.lock().unwrap();

        while let Some(head) = queue.pop(&self.mem) {
            let len = match VsockPacket::from_rx_virtq_head(&head) {
                Ok(mut pkt) => match self.recv_to_pkt(&mut pkt) {
                    RecvPkt::WaitForCredit => {
                        wait_credit = true;
                        0
                    }
                    RecvPkt::Read(count) => {
                        self.rx_cnt += Wrapping(count as u32);
                        self.init_data_pkt(&mut pkt);
                        pkt.set_len(count as u32);
                        pkt.hdr().len() + count
                    }
                    RecvPkt::Close => {
                        self.status = ProxyStatus::Closed;
                        0
                    }
                    RecvPkt::Error => 0,
                },
                Err(err) => {
                    debug!("custom vsock RX queue error: {err:?}");
                    0
                }
            };

            if len == 0 {
                queue.undo_pop();
                break;
            }
            have_used = true;
            if let Err(err) = queue.add_used(&self.mem, head.index, len as u32) {
                error!("failed to add used elements to the queue: {err:?}");
            }
        }

        (have_used, wait_credit)
    }

    fn flush_pending_write(&mut self) -> io::Result<usize> {
        let mut total_written = 0;
        while !self.pending_write.is_empty() {
            let (front, back) = self.pending_write.as_slices();
            let buf = if front.is_empty() { back } else { front };
            match self.backend.write(buf) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
                Ok(written) if written <= buf.len() => {
                    self.pending_write.drain(..written);
                    self.tx_cnt += Wrapping(written as u32);
                    total_written += written;
                }
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "vsock backend returned a write length larger than its input",
                    ));
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(total_written),
                Err(err) => return Err(err),
            }
        }
        Ok(total_written)
    }

    /// Return stream credit only after the host backend has consumed bytes
    /// from the bounded proxy queue.
    fn maybe_push_credit_update(&mut self, update: &mut ProxyUpdate) {
        if ((self.tx_cnt - self.last_tx_cnt_sent).0 as usize) < defs::CONN_TX_BUF_SIZE / 2 {
            return;
        }

        self.last_tx_cnt_sent = self.tx_cnt;
        push_packet(
            self.cid,
            MuxerRx::CreditUpdate {
                local_port: self.local_port,
                peer_port: self.peer_port,
                fwd_cnt: self.tx_cnt.0,
            },
            &self.rxq,
            &self.queue,
            &self.mem,
        );
        update.signal_queue = true;
    }

    fn init_data_pkt(&self, pkt: &mut VsockPacket) {
        pkt.set_op(uapi::VSOCK_OP_RW)
            .set_src_cid(uapi::VSOCK_HOST_CID)
            .set_dst_cid(self.cid)
            .set_src_port(self.local_port)
            .set_dst_port(self.peer_port)
            .set_type(uapi::VSOCK_TYPE_STREAM)
            .set_buf_alloc(defs::CONN_TX_BUF_SIZE as u32)
            .set_fwd_cnt(self.tx_cnt.0);
    }

    fn fail(&mut self, update: &mut ProxyUpdate, context: &str, err: &io::Error) {
        warn!("{context}: {err}");
        self.push_reset();
        self.status = ProxyStatus::Closed;
        update.signal_queue = true;
        update.remove_proxy = ProxyRemoval::Deferred;
        update.polling = Some((self.id, self.event_pollable(), EventSet::empty()));
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Proxy for CustomStreamProxy {
    #[cfg(unix)]
    fn id(&self) -> u64 {
        self.id
    }

    fn pollable(&self) -> VsockPollable {
        self.event_pollable()
    }

    fn status(&self) -> ProxyStatus {
        self.status
    }

    #[cfg(unix)]
    fn connect(&mut self, _pkt: &VsockPacket, _req: TsiConnectReq) -> ProxyUpdate {
        unreachable!("custom streams do not implement TSI connect")
    }

    fn confirm_connect(&mut self, pkt: &VsockPacket) -> Option<ProxyUpdate> {
        self.prepare_connect(pkt);
        // A duplicate request can arrive while an asynchronous host connect is
        // still pending. Do not acknowledge it until connect_state reports the
        // backend is actually ready.
        if self.status == ProxyStatus::Connected {
            self.push_connect_response();
        }
        None
    }

    #[cfg(unix)]
    fn getpeername(&mut self, _pkt: &VsockPacket) {
        unreachable!("custom streams do not implement TSI getpeername")
    }

    fn sendmsg(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        let mut update = ProxyUpdate::default();
        let Some(buf) = pkt.payload() else {
            let err = io::Error::new(
                io::ErrorKind::InvalidData,
                "vsock packet payload does not match its declared length",
            );
            self.fail(&mut update, "invalid custom vsock packet", &err);
            update.remove_proxy = ProxyRemoval::Immediate;
            return update;
        };

        // Flush previously accepted bytes before checking the fixed receive
        // window. This lets a backend that has become writable make room
        // without ever allocating beyond the advertised credit.
        if let Err(err) = self.flush_pending_write() {
            self.fail(&mut update, "custom vsock backend write failed", &err);
            return update;
        }
        if buf.len() > defs::CONN_TX_BUF_SIZE.saturating_sub(self.pending_write.len()) {
            let err = io::Error::new(
                io::ErrorKind::InvalidData,
                "guest exceeded the custom vsock stream receive window",
            );
            self.fail(&mut update, "invalid custom vsock stream credit", &err);
            update.remove_proxy = ProxyRemoval::Immediate;
            return update;
        }

        self.pending_write.extend(buf);
        if let Err(err) = self.flush_pending_write() {
            self.fail(&mut update, "custom vsock backend write failed", &err);
            return update;
        }
        update.polling = Some((self.id, self.event_pollable(), self.connected_poll_events()));
        self.maybe_push_credit_update(&mut update);

        update
    }

    #[cfg(unix)]
    fn sendto_addr(&mut self, _req: TsiSendtoAddr) -> ProxyUpdate {
        unreachable!("custom streams do not implement TSI sendto")
    }

    #[cfg(unix)]
    fn listen(
        &mut self,
        _pkt: &VsockPacket,
        _req: TsiListenReq,
        _host_port_map: &Option<HashMap<u16, u16>>,
    ) -> ProxyUpdate {
        unreachable!("custom streams do not implement TSI listen")
    }

    #[cfg(unix)]
    fn accept(&mut self, _req: TsiAcceptReq) -> ProxyUpdate {
        unreachable!("custom streams do not implement TSI accept")
    }

    fn update_peer_credit(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        self.peer_buf_alloc = pkt.buf_alloc();
        self.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());
        self.status = ProxyStatus::Connected;
        self.kick();

        ProxyUpdate {
            polling: Some((self.id, self.event_pollable(), self.connected_poll_events())),
            ..Default::default()
        }
    }

    fn process_op_response(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        self.peer_buf_alloc = pkt.buf_alloc();
        self.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());
        self.status = ProxyStatus::Connected;
        ProxyUpdate {
            polling: Some((self.id, self.event_pollable(), self.connected_poll_events())),
            ..Default::default()
        }
    }

    fn shutdown(&mut self, pkt: &VsockPacket) {
        let recv_off = pkt.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_RCV != 0;
        let send_off = pkt.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_SEND != 0;
        let how = match (recv_off, send_off) {
            (true, true) => VsockShutdown::Both,
            (true, false) => VsockShutdown::Read,
            (false, _) => VsockShutdown::Write,
        };
        if let Err(err) = self.backend.shutdown(how) {
            warn!("error shutting down custom vsock backend: {err}");
        }
    }

    fn release(&mut self) -> ProxyUpdate {
        self.status = ProxyStatus::Closed;
        ProxyUpdate {
            polling: Some((self.id, self.event_pollable(), EventSet::empty())),
            remove_proxy: ProxyRemoval::Immediate,
            ..Default::default()
        }
    }

    fn process_event(&mut self, evset: EventSet) -> ProxyUpdate {
        let mut update = ProxyUpdate::default();

        if evset.contains(EventSet::HANG_UP) {
            let err = io::Error::new(io::ErrorKind::ConnectionReset, "backend event closed");
            self.fail(&mut update, "custom vsock backend closed", &err);
            return update;
        }

        if self.status == ProxyStatus::Connecting {
            self.clear_notification();
            match self.backend.connect_state() {
                Ok(VsockConnectState::Connecting) => {
                    update.polling = Some((
                        self.id,
                        self.event_pollable(),
                        self.connecting_poll_events(),
                    ));
                    return update;
                }
                Ok(VsockConnectState::Connected) => {
                    self.status = ProxyStatus::Connected;
                    self.push_connect_response();
                    update.signal_queue = true;
                }
                Err(err) => {
                    self.fail(&mut update, "custom vsock backend connect failed", &err);
                    return update;
                }
            }
        } else if evset.contains(EventSet::IN) {
            self.clear_notification();
        }

        if self.status == ProxyStatus::Connected && !self.pending_write.is_empty() {
            if let Err(err) = self.flush_pending_write() {
                self.fail(&mut update, "custom vsock backend write failed", &err);
                return update;
            }
            self.maybe_push_credit_update(&mut update);
        }

        if self.status == ProxyStatus::Connected && evset.contains(EventSet::IN) {
            let (signal_queue, wait_credit) = self.recv_pkt();
            update.signal_queue |= signal_queue;
            if wait_credit {
                self.status = ProxyStatus::WaitingCreditUpdate;
                update.push_credit_req = Some(MuxerRx::CreditRequest {
                    local_port: self.local_port,
                    peer_port: self.peer_port,
                    fwd_cnt: self.tx_cnt.0,
                });
            }

            if self.status == ProxyStatus::Closed {
                self.push_reset();
                update.signal_queue = true;
                update.polling = Some((self.id, self.event_pollable(), EventSet::empty()));
                update.remove_proxy = ProxyRemoval::Immediate;
                return update;
            }
        }

        update.polling = Some((
            self.id,
            self.event_pollable(),
            if self.status == ProxyStatus::WaitingCreditUpdate {
                EventSet::empty()
            } else {
                self.connected_poll_events()
            },
        ));
        update
    }

    fn kick(&self) {
        if let Err(err) = self.notifier.notify() {
            warn!("failed to kick custom vsock backend: {err}");
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use vm_memory::{Bytes, GuestAddress};

    use super::super::packet::VSOCK_PKT_HDR_SIZE;
    use super::*;
    use crate::virtio::{Descriptor, DescriptorChain};

    struct TestStreamState {
        blocked: AtomicBool,
        written: Mutex<Vec<u8>>,
    }

    struct TestStream {
        state: Arc<TestStreamState>,
    }

    impl VsockStreamBackend for TestStream {
        fn read(&self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }

        fn write(&self, buf: &[u8]) -> io::Result<usize> {
            let mut written = self.state.written.lock().unwrap();
            if self.state.blocked.load(Ordering::Relaxed) && written.len() >= 2 {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            let count = if self.state.blocked.load(Ordering::Relaxed) {
                buf.len().min(2)
            } else {
                buf.len()
            };
            written.extend_from_slice(&buf[..count]);
            Ok(count)
        }

        fn shutdown(&self, _how: VsockShutdown) -> io::Result<()> {
            Ok(())
        }
    }

    fn tx_packet(mem: &GuestMemoryMmap, declared_len: u32, descriptor: &[u8]) -> VsockPacket {
        const DESC_TABLE: u64 = 0x1000;
        const HEADER: u64 = 0x2000;
        const PAYLOAD: u64 = 0x3000;

        mem.write_obj(
            Descriptor {
                addr: HEADER,
                len: VSOCK_PKT_HDR_SIZE as u32,
                flags: 1,
                next: 1,
            },
            GuestAddress(DESC_TABLE),
        )
        .unwrap();
        mem.write_obj(
            Descriptor {
                addr: PAYLOAD,
                len: descriptor.len() as u32,
                flags: 0,
                next: 0,
            },
            GuestAddress(DESC_TABLE + 16),
        )
        .unwrap();

        let mut header = [0u8; VSOCK_PKT_HDR_SIZE];
        header[24..28].copy_from_slice(&declared_len.to_le_bytes());
        mem.write_slice(&header, GuestAddress(HEADER)).unwrap();
        mem.write_slice(descriptor, GuestAddress(PAYLOAD)).unwrap();

        let head = DescriptorChain::checked_new(mem, GuestAddress(DESC_TABLE), 2, 0).unwrap();
        VsockPacket::from_tx_virtq_head(&head).unwrap()
    }

    fn test_proxy(state: Arc<TestStreamState>, mem: GuestMemoryMmap) -> CustomStreamProxy {
        CustomStreamProxy::new(
            1,
            3,
            5000,
            4000,
            Box::new(TestStream { state }),
            VsockNotifier::new().unwrap(),
            mem,
            Arc::new(Mutex::new(VirtQueue::new(256))),
            Arc::new(Mutex::new(MuxerRxQ::new())),
        )
        .unwrap()
    }

    #[test]
    fn buffers_partial_writes_without_losing_bytes() {
        let state = Arc::new(TestStreamState {
            blocked: AtomicBool::new(true),
            written: Mutex::new(Vec::new()),
        });
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mut proxy = test_proxy(Arc::clone(&state), mem);

        proxy.pending_write.extend(b"hello");
        proxy.flush_pending_write().unwrap();
        assert_eq!(&*state.written.lock().unwrap(), b"he");
        assert_eq!(proxy.pending_write.len(), 3);
        assert_eq!(proxy.tx_cnt.0, 2);

        state.blocked.store(false, Ordering::Relaxed);
        proxy.flush_pending_write().unwrap();
        assert_eq!(&*state.written.lock().unwrap(), b"hello");
        assert!(proxy.pending_write.is_empty());
        assert_eq!(proxy.tx_cnt.0, 5);
    }

    #[test]
    fn forwards_only_the_declared_packet_payload() {
        let state = Arc::new(TestStreamState {
            blocked: AtomicBool::new(false),
            written: Mutex::new(Vec::new()),
        });
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let pkt = tx_packet(&mem, 1, b"a-secret-tail");
        let mut proxy = test_proxy(Arc::clone(&state), mem.clone());

        let update = proxy.sendmsg(&pkt);

        assert!(matches!(update.remove_proxy, ProxyRemoval::Keep));
        assert_eq!(&*state.written.lock().unwrap(), b"a");
        assert_eq!(proxy.tx_cnt.0, 1);
    }

    #[test]
    fn rejects_writes_beyond_the_bounded_receive_window() {
        let state = Arc::new(TestStreamState {
            blocked: AtomicBool::new(true),
            // The test backend returns WouldBlock after accepting two bytes.
            written: Mutex::new(vec![0, 0]),
        });
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let pkt = tx_packet(&mem, 1, b"x");
        let mut proxy = test_proxy(state, mem.clone());
        proxy.pending_write.resize(defs::CONN_TX_BUF_SIZE, 0);

        let update = proxy.sendmsg(&pkt);

        assert!(matches!(update.remove_proxy, ProxyRemoval::Immediate));
        assert_eq!(proxy.pending_write.len(), defs::CONN_TX_BUF_SIZE);
    }
}
