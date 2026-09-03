use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use crossbeam_channel::{unbounded, Sender};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vm_memory::GuestMemoryMmap;

use super::super::Queue as VirtQueue;
use super::custom_stream::CustomStreamProxy;
use super::defs::uapi;
use super::muxer_rxq::{rx_to_pkt, MuxerRxQ};
use super::muxer_thread::MuxerThread;
use super::packet::VsockPacket;
use super::proxy::{Proxy, ProxyRemoval, ProxyUpdate};
use super::reaper::ReaperThread;
use super::{
    TsiFlags, VsockConnectRequest, VsockDatagramPortBackend, VsockNotifier, VsockPollable,
    VsockPortBackend,
};
use crate::virtio::InterruptTransport;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub type ProxyMap = Arc<RwLock<HashMap<u64, Mutex<Box<dyn Proxy>>>>>;

/// A muxer RX queue item used by the direct stream transport on Windows.
#[allow(dead_code)]
#[derive(Debug)]
pub enum MuxerRx {
    Reset {
        local_port: u32,
        peer_port: u32,
    },
    OpRequest {
        local_port: u32,
        peer_port: u32,
    },
    OpResponse {
        local_port: u32,
        peer_port: u32,
    },
    CreditRequest {
        local_port: u32,
        peer_port: u32,
        fwd_cnt: u32,
    },
    CreditUpdate {
        local_port: u32,
        peer_port: u32,
        fwd_cnt: u32,
    },
}

pub struct VsockMuxer {
    cid: u64,
    queue: Option<Arc<Mutex<VirtQueue>>>,
    mem: Option<GuestMemoryMmap>,
    rxq: Arc<Mutex<MuxerRxQ>>,
    epoll: Arc<Epoll>,
    interrupt: Option<InterruptTransport>,
    proxy_map: ProxyMap,
    reaper_sender: Option<Sender<u64>>,
    custom_port_map: Option<HashMap<u32, Arc<dyn VsockPortBackend>>>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub fn push_packet(
    cid: u64,
    rx: MuxerRx,
    rxq_mutex: &Arc<Mutex<MuxerRxQ>>,
    queue_mutex: &Arc<Mutex<VirtQueue>>,
    mem: &GuestMemoryMmap,
) {
    let mut queue = queue_mutex.lock().unwrap();
    let mut rxq = rxq_mutex.lock().unwrap();
    if !rxq.is_empty() {
        rxq.push(rx);
        return;
    }

    if let Some(head) = queue.pop(mem) {
        if let Ok(mut pkt) = VsockPacket::from_rx_virtq_head(&head) {
            if rx_to_pkt(cid, rx, &mut pkt) {
                if let Err(err) =
                    queue.add_used(mem, head.index, pkt.hdr().len() as u32 + pkt.len())
                {
                    error!("failed to add used elements to the queue: {err:?}");
                }
            } else {
                queue.undo_pop();
            }
        }
    } else {
        rxq.push(rx);
    }
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl VsockMuxer {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        cid: u64,
        _host_port_map: Option<HashMap<u16, u16>>,
        _unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
        custom_port_map: Option<HashMap<u32, Arc<dyn VsockPortBackend>>>,
        _custom_dgram_port_map: Option<HashMap<u32, Arc<dyn VsockDatagramPortBackend>>>,
        _tsi_flags: TsiFlags,
    ) -> Self {
        Self {
            cid,
            queue: None,
            mem: None,
            rxq: Arc::new(Mutex::new(MuxerRxQ::new())),
            epoll: Arc::new(Epoll::new().unwrap()),
            interrupt: None,
            proxy_map: Arc::new(RwLock::new(HashMap::new())),
            reaper_sender: None,
            custom_port_map,
        }
    }

    pub(crate) fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        interrupt: InterruptTransport,
    ) {
        self.queue = Some(queue.clone());
        self.mem = Some(mem.clone());
        self.interrupt = Some(interrupt.clone());

        let (sender, receiver) = unbounded();
        MuxerThread::new(
            self.cid,
            self.epoll.clone(),
            self.rxq.clone(),
            self.proxy_map.clone(),
            mem,
            queue,
            interrupt,
            sender.clone(),
        )
        .run();
        self.reaper_sender = Some(sender);
        ReaperThread::new(receiver, self.proxy_map.clone()).run();
    }

    pub(crate) fn has_pending_rx(&self) -> bool {
        !self.rxq.lock().unwrap().is_empty()
    }

    pub(crate) fn recv_pkt(&mut self, pkt: &mut VsockPacket) -> super::Result<()> {
        if self.rxq.lock().unwrap().is_empty() {
            return Err(super::VsockError::NoData);
        }
        let mut rxq = self.rxq.lock().unwrap();
        while let Some(rx) = rxq.pop() {
            if rx_to_pkt(self.cid, rx, pkt) {
                return Ok(());
            }
        }
        Err(super::VsockError::NoData)
    }

    /// Retry proxy work after the caller has released the guest RX queue.
    pub(crate) fn kick_backends(&self) {
        for proxy in self.proxy_map.read().unwrap().values() {
            proxy.lock().unwrap().kick();
        }
    }

    fn update_polling(&self, id: u64, pollable: VsockPollable, events: EventSet) {
        let _ = self
            .epoll
            .ctl(ControlOperation::Delete, pollable, &EpollEvent::default());
        if !events.is_empty() {
            let _ = self.epoll.ctl(
                ControlOperation::Add,
                pollable,
                &EpollEvent::new(events, id),
            );
        }
    }

    fn process_proxy_update(&self, id: u64, update: ProxyUpdate) {
        if let Some((poll_id, pollable, events)) = update.polling {
            self.update_polling(poll_id, pollable, events);
        }
        match update.remove_proxy {
            ProxyRemoval::Keep => {}
            ProxyRemoval::Immediate => {
                self.proxy_map.write().unwrap().remove(&id);
            }
            ProxyRemoval::Deferred => {
                if self
                    .reaper_sender
                    .as_ref()
                    .is_none_or(|sender| sender.send(id).is_err())
                {
                    self.proxy_map.write().unwrap().remove(&id);
                }
            }
        }
        if update.signal_queue {
            if let Some(interrupt) = &self.interrupt {
                interrupt.signal_used_queue();
            }
        }
    }

    fn push_reset(&self, pkt: &VsockPacket) {
        if let (Some(mem), Some(queue)) = (&self.mem, &self.queue) {
            push_packet(
                self.cid,
                MuxerRx::Reset {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                },
                &self.rxq,
                queue,
                mem,
            );
        }
    }

    fn process_op_request(&self, pkt: &VsockPacket) {
        let id = ((pkt.src_port() as u64) << 32) | pkt.dst_port() as u64;
        let existing = self
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .map(|proxy| proxy.lock().unwrap().confirm_connect(pkt));
        if let Some(update) = existing {
            if let Some(update) = update {
                self.process_proxy_update(id, update);
            }
            return;
        }

        let Some(service) = self
            .custom_port_map
            .as_ref()
            .and_then(|routes| routes.get(&pkt.dst_port()))
            .cloned()
        else {
            self.push_reset(pkt);
            return;
        };
        let (Some(mem), Some(queue)) = (&self.mem, &self.queue) else {
            return;
        };
        let notifier = match VsockNotifier::new() {
            Ok(notifier) => notifier,
            Err(err) => {
                warn!("failed to create custom vsock notifier: {err}");
                self.push_reset(pkt);
                return;
            }
        };
        let request = VsockConnectRequest {
            guest_cid: pkt.src_cid(),
            guest_port: pkt.src_port(),
            host_port: pkt.dst_port(),
        };
        let backend = match service.connect(request, notifier.clone()) {
            Ok(backend) => backend,
            Err(err) => {
                warn!(
                    "custom vsock service rejected port {}: {err}",
                    pkt.dst_port()
                );
                self.push_reset(pkt);
                return;
            }
        };
        let mut proxy = match CustomStreamProxy::new(
            id,
            self.cid,
            pkt.dst_port(),
            pkt.src_port(),
            backend,
            notifier,
            mem.clone(),
            queue.clone(),
            self.rxq.clone(),
        ) {
            Ok(proxy) => proxy,
            Err(err) => {
                warn!(
                    "custom vsock service failed to initialize port {}: {err}",
                    pkt.dst_port()
                );
                self.push_reset(pkt);
                return;
            }
        };
        let connecting = proxy.is_connecting();
        if connecting {
            proxy.prepare_connect(pkt);
        }
        let pollable = proxy.pollable();
        if pollable.is_null() {
            warn!("custom vsock service returned a null waitable handle");
            self.push_reset(pkt);
            return;
        }
        // Publish the proxy before registering its handle. A named-pipe worker
        // can complete immediately, and the muxer thread must be able to find
        // the proxy if the wait wakes as soon as the handle is registered.
        self.proxy_map
            .write()
            .unwrap()
            .insert(id, Mutex::new(Box::new(proxy)));
        if let Err(err) = self.epoll.ctl(
            ControlOperation::Add,
            pollable,
            &EpollEvent::new(EventSet::IN, id),
        ) {
            self.proxy_map.write().unwrap().remove(&id);
            warn!("custom vsock service returned an unusable waitable handle: {err}");
            self.push_reset(pkt);
            return;
        }
        if !connecting {
            if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
                proxy.lock().unwrap().confirm_connect(pkt);
            }
        }
    }

    fn with_proxy_update(&self, pkt: &VsockPacket, f: impl FnOnce(&mut dyn Proxy) -> ProxyUpdate) {
        let id = ((pkt.src_port() as u64) << 32) | pkt.dst_port() as u64;
        let update = self
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .map(|proxy| f(proxy.lock().unwrap().as_mut()));
        if let Some(update) = update {
            self.process_proxy_update(id, update);
        }
    }

    pub(crate) fn send_stream_pkt(&mut self, pkt: &VsockPacket) -> super::Result<()> {
        if pkt.dst_cid() != uapi::VSOCK_HOST_CID {
            return Ok(());
        }
        match pkt.op() {
            uapi::VSOCK_OP_REQUEST => self.process_op_request(pkt),
            uapi::VSOCK_OP_RESPONSE => {
                self.with_proxy_update(pkt, |proxy| proxy.process_op_response(pkt));
            }
            uapi::VSOCK_OP_SHUTDOWN => {
                let id = ((pkt.src_port() as u64) << 32) | pkt.dst_port() as u64;
                if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
                    proxy.lock().unwrap().shutdown(pkt);
                }
            }
            uapi::VSOCK_OP_CREDIT_UPDATE => {
                self.with_proxy_update(pkt, |proxy| proxy.update_peer_credit(pkt));
            }
            uapi::VSOCK_OP_RW => {
                let id = ((pkt.src_port() as u64) << 32) | pkt.dst_port() as u64;
                let found = self.proxy_map.read().unwrap().contains_key(&id);
                if found {
                    self.with_proxy_update(pkt, |proxy| proxy.sendmsg(pkt));
                } else {
                    self.push_reset(pkt);
                }
            }
            uapi::VSOCK_OP_RST => {
                self.with_proxy_update(pkt, |proxy| proxy.release());
            }
            _ => warn!("stream: unhandled op={}", pkt.op()),
        }
        Ok(())
    }

    pub(crate) fn send_dgram_pkt(&mut self, _pkt: &VsockPacket) -> super::Result<()> {
        // Windows does not advertise VIRTIO_VSOCK_F_DGRAM, so a conforming guest
        // never reaches this path. Drop malformed traffic without affecting streams.
        Ok(())
    }
}
