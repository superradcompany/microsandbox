use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

use vm_memory::GuestMemoryMmap;

use super::super::Queue as VirtQueue;
use super::backend::{VsockDatagramBackend, VsockNotifier};
use super::defs;
use super::muxer::{push_packet, MuxerRx};
use super::muxer_rxq::MuxerRxQ;
use super::packet::{TsiAcceptReq, TsiConnectReq, TsiListenReq, TsiSendtoAddr, VsockPacket};
use super::proxy::{Proxy, ProxyRemoval, ProxyStatus, ProxyUpdate};
use utils::epoll::EventSet;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Bound the work performed for one readiness event so a busy datagram service
/// cannot monopolize the shared vsock muxer thread.
const MAX_RECEIVE_BATCH: usize = 32;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One host endpoint associated with a guest datagram source port.
pub struct DatagramProxy {
    id: u64,
    cid: u64,
    local_port: u32,
    peer_port: u32,
    backend: Box<dyn VsockDatagramBackend>,
    notifier: VsockNotifier,
    mem: GuestMemoryMmap,
    queue: Arc<Mutex<VirtQueue>>,
    rxq: Arc<Mutex<MuxerRxQ>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DatagramProxy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: u64,
        cid: u64,
        local_port: u32,
        peer_port: u32,
        backend: Box<dyn VsockDatagramBackend>,
        notifier: VsockNotifier,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        rxq: Arc<Mutex<MuxerRxQ>>,
    ) -> Self {
        Self {
            id,
            cid,
            local_port,
            peer_port,
            backend,
            notifier,
            mem,
            queue,
            rxq,
        }
    }

    fn uses_notifier(&self) -> bool {
        self.backend.pollable().is_none()
    }

    fn receive_batch(&self) -> io::Result<(bool, Option<io::Error>)> {
        if self.uses_notifier() {
            self.notifier.clear()?;
        }

        let mut delivered = false;
        let mut exhausted_batch = true;
        for _ in 0..MAX_RECEIVE_BATCH {
            let mut data = vec![0; defs::MAX_PKT_BUF_SIZE];
            let read = match self.backend.receive(&mut data) {
                Ok(read) => read,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    exhausted_batch = false;
                    break;
                }
                // Preserve messages already copied to the guest receive queue.
                // Connected Unix datagram sockets on macOS can report
                // ECONNRESET immediately after the peer replies and closes;
                // dropping the pending IRQ here would strand that valid reply.
                Err(err) if delivered => return Ok((true, Some(err))),
                Err(err) => return Err(err),
            };

            if read.len > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "vsock datagram backend returned a length larger than its buffer",
                ));
            }
            if read.truncated {
                warn!(
                    "dropping oversized host datagram for vsock port {}",
                    self.local_port
                );
                continue;
            }

            data.truncate(read.len);
            push_packet(
                self.cid,
                MuxerRx::Datagram {
                    local_port: self.local_port,
                    peer_port: self.peer_port,
                    data,
                },
                &self.rxq,
                &self.queue,
                &self.mem,
            );
            delivered = true;
        }

        // Notifier-backed endpoints commonly signal only on an empty-to-ready
        // transition. Preserve fairness without stranding a 33rd message after
        // clearing that notification above.
        if exhausted_batch && self.uses_notifier() {
            self.notifier.notify()?;
        }

        Ok((delivered, None))
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl AsRawFd for DatagramProxy {
    fn as_raw_fd(&self) -> RawFd {
        self.backend
            .pollable()
            .unwrap_or_else(|| self.notifier.event().as_raw_fd())
    }
}

impl Proxy for DatagramProxy {
    fn id(&self) -> u64 {
        self.id
    }

    fn pollable(&self) -> RawFd {
        self.as_raw_fd()
    }

    fn status(&self) -> ProxyStatus {
        ProxyStatus::Connected
    }

    fn connect(&mut self, _pkt: &VsockPacket, _req: TsiConnectReq) -> ProxyUpdate {
        ProxyUpdate::default()
    }

    fn getpeername(&mut self, _pkt: &VsockPacket) {}

    fn sendmsg(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        let Some(payload) = pkt.payload() else {
            warn!("dropping custom vsock datagram with an invalid payload length");
            return ProxyUpdate::default();
        };
        match self.backend.send(payload) {
            Ok(()) => ProxyUpdate::default(),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                debug!(
                    "dropping guest datagram for busy host port {}",
                    self.local_port
                );
                ProxyUpdate::default()
            }
            Err(err) => {
                warn!(
                    "vsock datagram backend failed for host port {}: {err}",
                    self.local_port
                );
                ProxyUpdate {
                    polling: Some((self.id, self.as_raw_fd(), EventSet::empty())),
                    remove_proxy: ProxyRemoval::Immediate,
                    ..Default::default()
                }
            }
        }
    }

    fn sendto_addr(&mut self, _req: TsiSendtoAddr) -> ProxyUpdate {
        ProxyUpdate::default()
    }

    fn listen(
        &mut self,
        _pkt: &VsockPacket,
        _req: TsiListenReq,
        _host_port_map: &Option<HashMap<u16, u16>>,
    ) -> ProxyUpdate {
        ProxyUpdate::default()
    }

    fn accept(&mut self, _req: TsiAcceptReq) -> ProxyUpdate {
        ProxyUpdate::default()
    }

    fn update_peer_credit(&mut self, _pkt: &VsockPacket) -> ProxyUpdate {
        // Datagram packets deliberately do not participate in stream credit accounting.
        ProxyUpdate::default()
    }

    fn process_op_response(&mut self, _pkt: &VsockPacket) -> ProxyUpdate {
        ProxyUpdate::default()
    }

    fn release(&mut self) -> ProxyUpdate {
        ProxyUpdate {
            polling: Some((self.id, self.as_raw_fd(), EventSet::empty())),
            remove_proxy: ProxyRemoval::Immediate,
            ..Default::default()
        }
    }

    fn process_event(&mut self, evset: EventSet) -> ProxyUpdate {
        if evset.contains(EventSet::HANG_UP) {
            return self.release();
        }

        if !evset.contains(EventSet::IN) {
            return ProxyUpdate::default();
        }

        match self.receive_batch() {
            Ok((delivered, None)) => ProxyUpdate {
                signal_queue: delivered,
                polling: Some((self.id, self.as_raw_fd(), EventSet::IN)),
                ..Default::default()
            },
            Ok((delivered, Some(err))) => {
                warn!(
                    "host datagram endpoint closed after delivering data for vsock port {}: {err}",
                    self.local_port
                );
                let mut update = self.release();
                update.signal_queue = delivered;
                update
            }
            Err(err) => {
                warn!(
                    "failed to receive host datagram for vsock port {}: {err}",
                    self.local_port
                );
                self.release()
            }
        }
    }

    fn kick(&self) {
        if self.uses_notifier() {
            if let Err(err) = self.notifier.notify() {
                warn!("failed to kick custom vsock datagram backend: {err}");
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use vm_memory::GuestAddress;

    use super::super::backend::VsockDatagramRead;
    use super::*;

    struct QueueDatagrams {
        messages: Mutex<VecDeque<Vec<u8>>>,
        terminal_when_empty: bool,
    }

    impl VsockDatagramBackend for QueueDatagrams {
        fn send(&self, _payload: &[u8]) -> io::Result<()> {
            Ok(())
        }

        fn receive(&self, buf: &mut [u8]) -> io::Result<VsockDatagramRead> {
            let Some(message) = self.messages.lock().unwrap().pop_front() else {
                if self.terminal_when_empty {
                    return Err(io::Error::from(io::ErrorKind::ConnectionReset));
                }
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            };
            let len = message.len().min(buf.len());
            buf[..len].copy_from_slice(&message[..len]);
            Ok(VsockDatagramRead {
                len,
                truncated: message.len() > buf.len(),
            })
        }
    }

    #[test]
    fn notifier_rearms_after_a_full_receive_batch() {
        let messages = (0..=MAX_RECEIVE_BATCH)
            .map(|index| vec![index as u8])
            .collect();
        let notifier = VsockNotifier::new().unwrap();
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let rxq = Arc::new(Mutex::new(MuxerRxQ::new()));
        let proxy = DatagramProxy::new(
            1,
            3,
            5000,
            4000,
            Box::new(QueueDatagrams {
                messages: Mutex::new(messages),
                terminal_when_empty: false,
            }),
            notifier.clone(),
            mem,
            Arc::new(Mutex::new(VirtQueue::new(256))),
            Arc::clone(&rxq),
        );

        assert!(proxy.receive_batch().unwrap().0);
        assert_eq!(rxq.lock().unwrap().len(), MAX_RECEIVE_BATCH);
        // The full batch explicitly re-signals so the remaining datagram is
        // observable even when the backend only signals empty-to-ready.
        notifier.event().read().unwrap();

        assert!(proxy.receive_batch().unwrap().0);
        assert_eq!(rxq.lock().unwrap().len(), MAX_RECEIVE_BATCH + 1);
    }

    #[test]
    fn terminal_error_after_data_preserves_the_pending_interrupt() {
        let notifier = VsockNotifier::new().unwrap();
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let rxq = Arc::new(Mutex::new(MuxerRxQ::new()));
        let mut proxy = DatagramProxy::new(
            1,
            3,
            5000,
            4000,
            Box::new(QueueDatagrams {
                messages: Mutex::new(VecDeque::from([b"reply".to_vec()])),
                terminal_when_empty: true,
            }),
            notifier,
            mem,
            Arc::new(Mutex::new(VirtQueue::new(256))),
            Arc::clone(&rxq),
        );

        let update = proxy.process_event(EventSet::IN);
        assert!(update.signal_queue);
        assert!(matches!(update.remove_proxy, ProxyRemoval::Immediate));
        assert_eq!(rxq.lock().unwrap().len(), 1);
    }
}
