use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use super::super::Queue as VirtQueue;
use super::custom_stream::CustomStreamProxy;
use super::defs;
use super::defs::uapi;
use super::dgram::DatagramProxy;
use super::muxer_rxq::{rx_to_pkt, MuxerRxQ};
use super::muxer_thread::MuxerThread;
use super::packet::{TsiGetnameRsp, VsockPacket};
use super::proxy::{Proxy, ProxyRemoval, ProxyUpdate};
use super::reaper::ReaperThread;
#[cfg(target_os = "macos")]
use super::timesync::TimesyncThread;
use super::tsi_dgram::TsiDgramProxy;
use super::tsi_stream::TsiStreamProxy;
use super::unix::UnixProxy;
use super::VsockError;
use super::{
    TsiFlags, VsockConnectRequest, VsockDatagramPeer, VsockDatagramPortBackend, VsockNotifier,
    VsockPortBackend,
};
use crossbeam_channel::{unbounded, Sender};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vm_memory::GuestMemoryMmap;

use crate::virtio::InterruptTransport;
use std::net::{Ipv4Addr, SocketAddrV4};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Bound connectionless peer state per exposed host port. The least recently
/// used peer is retired before a new peer is opened at the limit.
const MAX_DGRAM_PEERS_PER_PORT: usize = 256;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub type ProxyMap = Arc<RwLock<HashMap<u64, Mutex<Box<dyn Proxy>>>>>;

#[derive(Clone, Copy)]
struct DgramPeerEntry {
    id: u64,
    last_used: u64,
}

/// A muxer RX queue item.
#[derive(Debug)]
pub enum MuxerRx {
    Reset {
        local_port: u32,
        peer_port: u32,
    },
    GetnameResponse {
        local_port: u32,
        peer_port: u32,
        data: TsiGetnameRsp,
    },
    ConnResponse {
        local_port: u32,
        peer_port: u32,
        result: i32,
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
    ListenResponse {
        local_port: u32,
        peer_port: u32,
        result: i32,
    },
    AcceptResponse {
        local_port: u32,
        peer_port: u32,
        result: i32,
    },
    Datagram {
        local_port: u32,
        peer_port: u32,
        data: Vec<u8>,
    },
}

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
                if let Err(e) = queue.add_used(mem, head.index, pkt.hdr().len() as u32 + pkt.len())
                {
                    error!("failed to add used elements to the queue: {e:?}");
                }
            } else {
                queue.undo_pop();
            }
        }
    } else {
        error!("couldn't push pkt to queue, adding it to rxq");
        rxq.push(rx);
    }
}

pub struct VsockMuxer {
    cid: u64,
    host_port_map: Option<HashMap<u16, u16>>,
    queue: Option<Arc<Mutex<VirtQueue>>>,
    mem: Option<GuestMemoryMmap>,
    rxq: Arc<Mutex<MuxerRxQ>>,
    epoll: Epoll,
    interrupt: Option<InterruptTransport>,
    proxy_map: ProxyMap,
    reaper_sender: Option<Sender<u64>>,
    unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
    custom_port_map: Option<HashMap<u32, Arc<dyn VsockPortBackend>>>,
    custom_dgram_port_map: Option<HashMap<u32, Arc<dyn VsockDatagramPortBackend>>>,
    dgram_peer_map: Mutex<HashMap<(u32, u32), DgramPeerEntry>>,
    next_dgram_proxy_id: AtomicU64,
    next_dgram_activity: AtomicU64,
    tsi_flags: TsiFlags,
}

impl VsockMuxer {
    pub(crate) fn new(
        cid: u64,
        host_port_map: Option<HashMap<u16, u16>>,
        unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
        custom_port_map: Option<HashMap<u32, Arc<dyn VsockPortBackend>>>,
        custom_dgram_port_map: Option<HashMap<u32, Arc<dyn VsockDatagramPortBackend>>>,
        tsi_flags: TsiFlags,
    ) -> Self {
        VsockMuxer {
            cid,
            host_port_map,
            queue: None,
            mem: None,
            rxq: Arc::new(Mutex::new(MuxerRxQ::new())),
            epoll: Epoll::new().unwrap(),
            interrupt: None,
            proxy_map: Arc::new(RwLock::new(HashMap::new())),
            reaper_sender: None,
            unix_ipc_port_map,
            custom_port_map,
            custom_dgram_port_map,
            dgram_peer_map: Mutex::new(HashMap::new()),
            // Direct stream proxy ids use the low 32 bits for a non-zero host
            // port. Keeping those bits zero gives datagram event tokens a
            // disjoint namespace without changing the legacy stream ids.
            next_dgram_proxy_id: AtomicU64::new(1),
            next_dgram_activity: AtomicU64::new(1),
            tsi_flags,
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

        #[cfg(target_os = "macos")]
        {
            let timesync =
                TimesyncThread::new(self.cid, mem.clone(), queue.clone(), interrupt.clone());
            timesync.run();
        }

        let (sender, receiver) = unbounded();

        let thread = MuxerThread::new(
            self.cid,
            self.epoll.clone(),
            self.rxq.clone(),
            self.proxy_map.clone(),
            mem,
            queue,
            interrupt.clone(),
            sender.clone(),
            self.unix_ipc_port_map.clone().unwrap_or_default(),
        );
        thread.run();

        self.reaper_sender = Some(sender);
        let reaper = ReaperThread::new(receiver, self.proxy_map.clone());
        reaper.run();
    }

    pub(crate) fn has_pending_rx(&self) -> bool {
        !self.rxq.lock().unwrap().is_empty()
    }

    pub(crate) fn recv_pkt(&mut self, pkt: &mut VsockPacket) -> super::Result<()> {
        debug!("recv_stream_pkt");
        if self.rxq.lock().unwrap().is_empty() {
            return Err(VsockError::NoData);
        }

        let mut rxq = self.rxq.lock().unwrap();
        while let Some(rx) = rxq.pop() {
            if rx_to_pkt(self.cid, rx, pkt) {
                return Ok(());
            }
        }
        Err(VsockError::NoData)
    }

    /// Retry proxy work after the caller has released the guest RX queue.
    pub(crate) fn kick_backends(&self) {
        for proxy in self.proxy_map.read().unwrap().values() {
            proxy.lock().unwrap().kick();
        }
    }

    fn push_packet(&self, rx: MuxerRx) {
        let mem = match self.mem.as_ref() {
            Some(m) => m,
            None => {
                error!("proxy creation without mem");
                return;
            }
        };
        let queue_mutex = match self.queue.as_ref() {
            Some(q) => q,
            None => {
                error!("stream proxy creation without stream queue");
                return;
            }
        };

        let mut queue = queue_mutex.lock().unwrap();
        let mut rxq = self.rxq.lock().unwrap();
        if !rxq.is_empty() {
            rxq.push(rx);
            return;
        }

        if let Some(head) = queue.pop(mem) {
            if let Ok(mut pkt) = VsockPacket::from_rx_virtq_head(&head) {
                if rx_to_pkt(self.cid, rx, &mut pkt) {
                    if let Err(e) =
                        queue.add_used(mem, head.index, pkt.hdr().len() as u32 + pkt.len())
                    {
                        error!("failed to add used elements to the queue: {e:?}");
                    }
                } else {
                    queue.undo_pop();
                }
            }
        } else {
            error!("couldn't push pkt to queue, adding it to rxq");
            rxq.push(rx);
        }
    }

    pub fn update_polling(&self, id: u64, fd: RawFd, evset: EventSet) {
        debug!("update_polling id={id} fd={fd:?} evset={evset:?}");
        let _ = self
            .epoll
            .ctl(ControlOperation::Delete, fd, &EpollEvent::default());
        if !evset.is_empty() {
            let _ = self
                .epoll
                .ctl(ControlOperation::Add, fd, &EpollEvent::new(evset, id));
        }
    }

    fn process_proxy_update(&self, id: u64, update: ProxyUpdate) {
        if let Some(polling) = update.polling {
            self.update_polling(polling.0, polling.1, polling.2);
        }

        match update.remove_proxy {
            ProxyRemoval::Keep => {}
            ProxyRemoval::Immediate => {
                info!("immediately removing proxy: {id}");
                self.remove_proxy(id);
            }
            ProxyRemoval::Deferred => {
                info!("deferring proxy removal: {id}");
                if let Some(reaper_sender) = &self.reaper_sender {
                    if reaper_sender.send(id).is_err() {
                        self.proxy_map.write().unwrap().remove(&id);
                    }
                }
            }
        }

        if update.signal_queue {
            if let Some(interrupt) = &self.interrupt {
                interrupt.signal_used_queue();
            }
        }
    }

    /// Remove polling, proxy ownership, and any connectionless peer index as
    /// one lifecycle operation.
    fn remove_proxy(&self, id: u64) {
        let proxy = self.proxy_map.write().unwrap().remove(&id);
        if let Some(proxy) = proxy {
            let pollable = proxy.lock().unwrap().pollable();
            self.update_polling(id, pollable, EventSet::empty());
        }
        self.dgram_peer_map
            .lock()
            .unwrap()
            .retain(|_, entry| entry.id != id);
    }

    fn evict_oldest_dgram_peer(&self, host_port: u32) {
        let evicted = {
            let mut peers = self.dgram_peer_map.lock().unwrap();
            if peers.keys().filter(|(_, port)| *port == host_port).count()
                < MAX_DGRAM_PEERS_PER_PORT
            {
                None
            } else {
                let oldest = peers
                    .iter()
                    .filter(|((_, port), _)| *port == host_port)
                    .min_by_key(|(_, entry)| entry.last_used)
                    .map(|(key, entry)| (*key, entry.id));
                oldest.and_then(|(key, id)| peers.remove(&key).map(|_| id))
            }
        };

        if let Some(id) = evicted {
            self.remove_proxy(id);
        }
    }

    fn process_proxy_create(&self, pkt: &VsockPacket) {
        debug!("proxy create request");
        if let Some(req) = pkt.read_proxy_create() {
            debug!(
                "proxy create request: peer_port={}, type={}",
                req.peer_port, req._type
            );
            let mem = match self.mem.as_ref() {
                Some(m) => m,
                None => {
                    error!("proxy creation without mem");
                    return;
                }
            };
            let queue = match self.queue.as_ref() {
                Some(q) => q,
                None => {
                    error!("stream proxy creation without stream queue");
                    return;
                }
            };
            match req._type {
                defs::SOCK_STREAM => {
                    debug!("proxy create stream");
                    let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
                    if req.family as i32 == libc::AF_UNIX
                        && !self.tsi_flags.contains(TsiFlags::HIJACK_UNIX)
                    {
                        warn!("rejecting stream unix proxy because HIJACK_UNIX is disabled");
                        return;
                    }
                    if (req.family as i32 == libc::AF_INET || req.family as i32 == libc::AF_INET6)
                        && !self.tsi_flags.contains(TsiFlags::HIJACK_INET)
                    {
                        warn!("rejecting stream inet proxy because HIJACK_INET is disabled");
                        return;
                    }
                    match TsiStreamProxy::new(
                        id,
                        self.cid,
                        req.family,
                        defs::TSI_PROXY_PORT,
                        req.peer_port,
                        pkt.src_port(),
                        mem.clone(),
                        queue.clone(),
                        self.rxq.clone(),
                    ) {
                        Ok(proxy) => {
                            self.proxy_map
                                .write()
                                .unwrap()
                                .insert(id, Mutex::new(Box::new(proxy)));
                        }
                        Err(e) => debug!("error creating tcp proxy: {e}"),
                    }
                }
                defs::SOCK_DGRAM => {
                    debug!("proxy create dgram");
                    let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
                    if req.family as i32 == libc::AF_UNIX
                        && !self.tsi_flags.contains(TsiFlags::HIJACK_UNIX)
                    {
                        warn!("rejecting dgram unix proxy because HIJACK_UNIX is disabled");
                        return;
                    }
                    if (req.family as i32 == libc::AF_INET || req.family as i32 == libc::AF_INET6)
                        && !self.tsi_flags.contains(TsiFlags::HIJACK_INET)
                    {
                        warn!("rejecting dgram inet proxy because HIJACK_INET is disabled");
                        return;
                    }
                    match TsiDgramProxy::new(
                        id,
                        self.cid,
                        req.family,
                        req.peer_port,
                        mem.clone(),
                        queue.clone(),
                        self.rxq.clone(),
                    ) {
                        Ok(proxy) => {
                            self.proxy_map
                                .write()
                                .unwrap()
                                .insert(id, Mutex::new(Box::new(proxy)));
                        }
                        Err(e) => debug!("error creating udp proxy: {e}"),
                    }
                }
                _ => debug!("unknown type on connection request"),
            };
        }
    }

    fn process_connect(&self, pkt: &VsockPacket) {
        debug!("proxy connect request");
        if let Some(req) = pkt.read_connect_req() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("proxy connect request: id={id}");
            match self.proxy_map.read().unwrap().get(&id) {
                Some(proxy) => {
                    self.process_proxy_update(id, proxy.lock().unwrap().connect(pkt, req));
                }
                None => self.push_packet(MuxerRx::ConnResponse {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                    result: -libc::ECONNREFUSED,
                }),
            }
        }
    }

    fn process_getname(&self, pkt: &VsockPacket) {
        debug!("new getname request");
        if let Some(req) = pkt.read_getname_req() {
            let id = ((req.peer_port as u64) << 32) | (req.local_port as u64);
            debug!(
                "new getname request: id={}, peer_port={}, local_port={}",
                id, req.peer_port, req.local_port
            );

            match self.proxy_map.read().unwrap().get(&id) {
                Some(proxy) => proxy.lock().unwrap().getpeername(pkt),
                None => self.push_packet(MuxerRx::GetnameResponse {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                    data: TsiGetnameRsp {
                        result: -libc::EINVAL,
                        addr_len: 0,
                        addr: SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into(),
                    },
                }),
            }
        }
    }

    fn process_sendto_addr(&self, pkt: &VsockPacket) {
        debug!("new DGRAM sendto addr: src={}", pkt.src_port());
        if let Some(req) = pkt.read_sendto_addr() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("new DGRAM sendto addr: id={id}");
            let update = self
                .proxy_map
                .read()
                .unwrap()
                .get(&id)
                .map(|proxy| proxy.lock().unwrap().sendto_addr(req));

            if let Some(update) = update {
                self.process_proxy_update(id, update);
            }
        }
    }

    fn process_sendto_data(&self, pkt: &VsockPacket) {
        let id = ((pkt.src_port() as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
        debug!("DGRAM sendto data: id={} src={}", id, pkt.src_port());
        if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
            proxy.lock().unwrap().sendto_data(pkt);
        }
    }

    fn process_listen_request(&self, pkt: &VsockPacket) {
        debug!("DGRAM listen request: src={}", pkt.src_port());
        if let Some(req) = pkt.read_listen_req() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("DGRAM listen request: id={id}");
            match self.proxy_map.read().unwrap().get(&id) {
                Some(proxy) => self.process_proxy_update(
                    id,
                    proxy.lock().unwrap().listen(pkt, req, &self.host_port_map),
                ),
                None => self.push_packet(MuxerRx::ListenResponse {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                    result: -libc::EPERM,
                }),
            };
        }
    }

    fn process_accept_request(&self, pkt: &VsockPacket) {
        debug!("DGRAM accept request: src={}", pkt.src_port());
        if let Some(req) = pkt.read_accept_req() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("DGRAM accept request: id={id}");
            match self.proxy_map.read().unwrap().get(&id) {
                Some(proxy) => self.process_proxy_update(id, proxy.lock().unwrap().accept(req)),
                None => self.push_packet(MuxerRx::AcceptResponse {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                    result: -libc::EINVAL,
                }),
            }
        }
    }

    fn process_proxy_release(&self, pkt: &VsockPacket) {
        debug!("DGRAM release request: src={}", pkt.src_port());
        if let Some(req) = pkt.read_release_req() {
            let id = ((req.peer_port as u64) << 32) | (req.local_port as u64);
            debug!(
                "DGRAM release request: id={} local_port={} peer_port={}",
                id, req.local_port, req.peer_port
            );
            let update = if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
                Some(proxy.lock().unwrap().release())
            } else {
                debug!(
                    "release without proxy: id={}, proxies={}",
                    id,
                    self.proxy_map.read().unwrap().len()
                );
                None
            };

            if let Some(update) = update {
                self.process_proxy_update(id, update);
            }
        }
        debug!(
            "DGRAM release request: proxies={}",
            self.proxy_map.read().unwrap().len()
        );
    }

    fn process_dgram_rw(&self, pkt: &VsockPacket) {
        debug!("DGRAM OP_RW");
        let id = ((pkt.src_port() as u64) << 32) | (defs::TSI_PROXY_PORT as u64);

        let update = self
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .map(|proxy| proxy.lock().unwrap().sendmsg(pkt));
        if let Some(update) = update {
            debug!("DGRAM allowing OP_RW for {}", pkt.src_port());
            self.process_proxy_update(id, update);
        } else {
            debug!("DGRAM ignoring OP_RW for {}", pkt.src_port());
        }
    }

    fn process_custom_dgram(&self, pkt: &VsockPacket) {
        let Some(service) = self
            .custom_dgram_port_map
            .as_ref()
            .and_then(|routes| routes.get(&pkt.dst_port()))
            .cloned()
        else {
            return;
        };

        let peer_key = (pkt.src_port(), pkt.dst_port());
        let activity = self.next_dgram_activity.fetch_add(1, Ordering::Relaxed);
        let existing = {
            let mut peers = self.dgram_peer_map.lock().unwrap();
            peers.get_mut(&peer_key).map(|entry| {
                entry.last_used = activity;
                entry.id
            })
        };
        if let Some(id) = existing {
            let update = self
                .proxy_map
                .read()
                .unwrap()
                .get(&id)
                .map(|proxy| proxy.lock().unwrap().sendmsg(pkt));
            if let Some(update) = update {
                self.process_proxy_update(id, update);
                return;
            }
            self.dgram_peer_map.lock().unwrap().remove(&peer_key);
        }

        self.evict_oldest_dgram_peer(pkt.dst_port());

        let Some(mem) = self.mem.as_ref() else {
            warn!("vsock datagram without guest memory");
            return;
        };
        let Some(queue) = self.queue.as_ref() else {
            warn!("vsock datagram without receive queue");
            return;
        };

        let notifier = match VsockNotifier::new() {
            Ok(notifier) => notifier,
            Err(err) => {
                warn!("failed to create custom vsock datagram notifier: {err}");
                return;
            }
        };
        let peer = VsockDatagramPeer {
            guest_cid: pkt.src_cid(),
            guest_port: pkt.src_port(),
            host_port: pkt.dst_port(),
        };
        let backend = match service.open_peer(peer, notifier.clone()) {
            Ok(backend) => backend,
            Err(err) => {
                warn!(
                    "custom vsock datagram service rejected port {}: {err}",
                    pkt.dst_port()
                );
                return;
            }
        };

        let id = self.next_dgram_proxy_id.fetch_add(1, Ordering::Relaxed) << 32;
        let proxy = DatagramProxy::new(
            id,
            self.cid,
            pkt.dst_port(),
            pkt.src_port(),
            backend,
            notifier,
            mem.clone(),
            queue.clone(),
            self.rxq.clone(),
        );
        let poll_fd = proxy.as_raw_fd();
        if poll_fd < 0 {
            warn!(
                "custom vsock datagram service for port {} returned an invalid poll fd",
                pkt.dst_port()
            );
            return;
        }

        // Publish the proxy before registering its pollable. A host service can
        // reply synchronously from `sendmsg`; if readiness wakes the muxer
        // thread before this map entry exists, that event can be consumed with
        // no proxy available to drain the datagram.
        self.proxy_map
            .write()
            .unwrap()
            .insert(id, Mutex::new(Box::new(proxy)));
        if let Err(err) = self.epoll.ctl(
            ControlOperation::Add,
            poll_fd,
            &EpollEvent::new(EventSet::IN, id),
        ) {
            warn!(
                "custom vsock datagram service for port {} returned an unusable poll fd: {err}",
                pkt.dst_port()
            );
            self.proxy_map.write().unwrap().remove(&id);
            return;
        }

        self.dgram_peer_map.lock().unwrap().insert(
            peer_key,
            DgramPeerEntry {
                id,
                last_used: activity,
            },
        );
        let update = self
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .map(|proxy| proxy.lock().unwrap().sendmsg(pkt));
        if let Some(update) = update {
            self.process_proxy_update(id, update);
        }
    }

    pub(crate) fn send_dgram_pkt(&mut self, pkt: &VsockPacket) -> super::Result<()> {
        debug!(
            "send_dgram_pkt: src_port={} dst_port={}",
            pkt.src_port(),
            pkt.dst_port()
        );

        if pkt.dst_cid() != uapi::VSOCK_HOST_CID {
            debug!("dropping guest packet for unknown CID: {:?}", pkt.hdr());
            return Ok(());
        }

        if self
            .custom_dgram_port_map
            .as_ref()
            .is_some_and(|routes| routes.contains_key(&pkt.dst_port()))
        {
            if pkt.op() == uapi::VSOCK_OP_RW {
                self.process_custom_dgram(pkt);
            } else {
                debug!("dropping non-RW packet for direct datagram route");
            }
            return Ok(());
        }

        match pkt.dst_port() {
            defs::TSI_PROXY_CREATE if self.tsi_flags.tsi_enabled() => {
                self.process_proxy_create(pkt)
            }
            defs::TSI_CONNECT if self.tsi_flags.tsi_enabled() => self.process_connect(pkt),
            defs::TSI_GETNAME if self.tsi_flags.tsi_enabled() => self.process_getname(pkt),
            defs::TSI_SENDTO_ADDR if self.tsi_flags.tsi_enabled() => self.process_sendto_addr(pkt),
            defs::TSI_SENDTO_DATA if self.tsi_flags.tsi_enabled() => self.process_sendto_data(pkt),
            defs::TSI_LISTEN if self.tsi_flags.tsi_enabled() => self.process_listen_request(pkt),
            defs::TSI_ACCEPT if self.tsi_flags.tsi_enabled() => self.process_accept_request(pkt),
            defs::TSI_PROXY_RELEASE if self.tsi_flags.tsi_enabled() => {
                self.process_proxy_release(pkt)
            }
            _ => {
                if pkt.op() == uapi::VSOCK_OP_RW {
                    self.process_dgram_rw(pkt);
                } else {
                    error!("unexpected dgram pkt: {}", pkt.op());
                }
            }
        }

        Ok(())
    }

    fn process_op_request(&mut self, pkt: &VsockPacket) {
        debug!("OP_REQUEST");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);

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

        let Some(mem) = self.mem.as_ref() else {
            warn!("vsock connection request without guest memory");
            return;
        };
        let Some(queue) = self.queue.as_ref() else {
            warn!("vsock connection request without receive queue");
            return;
        };

        if let Some(service) = self
            .custom_port_map
            .as_ref()
            .and_then(|routes| routes.get(&pkt.dst_port()))
            .cloned()
        {
            let request = VsockConnectRequest {
                guest_cid: pkt.src_cid(),
                guest_port: pkt.src_port(),
                host_port: pkt.dst_port(),
            };
            let notifier = match VsockNotifier::new() {
                Ok(notifier) => notifier,
                Err(err) => {
                    warn!("failed to create custom vsock notifier: {err}");
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
                    return;
                }
            };
            match service.connect(request, notifier.clone()) {
                Ok(backend) => {
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
                            return;
                        }
                    };
                    let connecting = proxy.is_connecting();
                    if connecting {
                        proxy.prepare_connect(pkt);
                    }
                    let poll_fd = proxy.pollable();
                    if poll_fd < 0 {
                        warn!(
                            "custom vsock service for port {} returned an invalid poll fd",
                            pkt.dst_port()
                        );
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
                        return;
                    }
                    self.proxy_map
                        .write()
                        .unwrap()
                        .insert(id, Mutex::new(Box::new(proxy)));
                    if let Err(err) = self.epoll.ctl(
                        ControlOperation::Add,
                        poll_fd,
                        &EpollEvent::new(
                            if connecting {
                                EventSet::IN | EventSet::OUT
                            } else {
                                EventSet::IN
                            },
                            id,
                        ),
                    ) {
                        self.proxy_map.write().unwrap().remove(&id);
                        warn!(
                            "custom vsock service for port {} returned an unusable poll fd: {err}",
                            pkt.dst_port()
                        );
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
                        return;
                    }
                    if !connecting {
                        if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
                            proxy.lock().unwrap().confirm_connect(pkt);
                        }
                    }
                }
                Err(err) => {
                    warn!(
                        "custom vsock service rejected port {}: {err}",
                        pkt.dst_port()
                    );
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
            return;
        }

        if let Some((path, listen)) = self
            .unix_ipc_port_map
            .as_ref()
            .and_then(|routes| routes.get(&pkt.dst_port()))
        {
            if *listen {
                warn!("attempting to connect a vsock port configured for Unix listen mode");
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
                return;
            }

            let mut unix = match UnixProxy::new(
                id,
                self.cid,
                pkt.dst_port(),
                pkt.src_port(),
                mem.clone(),
                queue.clone(),
                self.rxq.clone(),
                path.to_path_buf(),
            ) {
                Ok(proxy) => proxy,
                Err(err) => {
                    warn!(
                        "failed to create Unix proxy for host port {}: {err}",
                        pkt.dst_port()
                    );
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
                    return;
                }
            };
            let update = match unix.connect_vsock() {
                Ok(update) => update,
                Err(errno) => {
                    warn!(
                        "failed to connect Unix route for host port {}: errno {}",
                        pkt.dst_port(),
                        errno
                    );
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
                    return;
                }
            };
            if unix.status == super::proxy::ProxyStatus::Connected {
                unix.confirm_vsock_connect(pkt);
            } else {
                unix.prepare_vsock_connect(pkt);
            }
            self.proxy_map
                .write()
                .unwrap()
                .insert(id, Mutex::new(Box::new(unix)));
            self.process_proxy_update(id, update);
        }
    }

    fn process_op_response(&self, pkt: &VsockPacket) {
        debug!("OP_RESPONSE");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        let update = self
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .map(|proxy| proxy.lock().unwrap().process_op_response(pkt));
        update
            .as_ref()
            .and_then(|u| u.push_accept)
            .and_then(|(_id, parent_id)| {
                self.proxy_map
                    .read()
                    .unwrap()
                    .get(&parent_id)
                    .map(|proxy| proxy.lock().unwrap().enqueue_accept())
            });

        if let Some(update) = update {
            self.process_proxy_update(id, update);
        }
    }

    fn process_op_shutdown(&self, pkt: &VsockPacket) {
        debug!("OP_SHUTDOWN");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
            proxy.lock().unwrap().shutdown(pkt);
        }
    }

    fn process_op_credit_update(&self, pkt: &VsockPacket) {
        debug!("OP_CREDIT_UPDATE");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        let update = self
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .map(|proxy| proxy.lock().unwrap().update_peer_credit(pkt));
        if let Some(update) = update {
            self.process_proxy_update(id, update);
        }
    }

    fn process_stream_rw(&self, pkt: &VsockPacket) {
        debug!("OP_RW");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        let update = self
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .map(|proxy| proxy.lock().unwrap().sendmsg(pkt));
        if let Some(update) = update {
            debug!(
                "allowing OP_RW: src={} dst={}",
                pkt.src_port(),
                pkt.dst_port()
            );
            self.process_proxy_update(id, update);
        } else {
            debug!("invalid OP_RW for {}, sending reset", pkt.src_port());
            let mem = match self.mem.as_ref() {
                Some(m) => m,
                None => {
                    warn!("OP_RW without mem");
                    return;
                }
            };
            let queue = match self.queue.as_ref() {
                Some(q) => q,
                None => {
                    warn!("OP_RW without queue");
                    return;
                }
            };

            // This response goes to the connection.
            let rx = MuxerRx::Reset {
                local_port: pkt.dst_port(),
                peer_port: pkt.src_port(),
            };
            push_packet(self.cid, rx, &self.rxq, queue, mem);
        }
    }

    fn process_stream_rst(&self, pkt: &VsockPacket) {
        debug!("OP_RST");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        let update = self
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .map(|proxy| proxy.lock().unwrap().release());
        if let Some(update) = update {
            debug!(
                "allowing OP_RST: id={} src={} dst={}",
                id,
                pkt.src_port(),
                pkt.dst_port()
            );
            self.process_proxy_update(id, update);
        } else {
            debug!("invalid OP_RST for {}", pkt.src_port());
        }
    }

    pub(crate) fn send_stream_pkt(&mut self, pkt: &VsockPacket) -> super::Result<()> {
        debug!(
            "send_pkt: src_port={} dst_port={}, op={}",
            pkt.src_port(),
            pkt.dst_port(),
            pkt.op()
        );

        if pkt.dst_cid() != uapi::VSOCK_HOST_CID {
            debug!("dropping guest packet for unknown CID: {:?}", pkt.hdr());
            return Ok(());
        }

        match pkt.op() {
            uapi::VSOCK_OP_REQUEST => self.process_op_request(pkt),
            uapi::VSOCK_OP_RESPONSE => self.process_op_response(pkt),
            uapi::VSOCK_OP_SHUTDOWN => self.process_op_shutdown(pkt),
            uapi::VSOCK_OP_CREDIT_UPDATE => self.process_op_credit_update(pkt),
            uapi::VSOCK_OP_RW => self.process_stream_rw(pkt),
            uapi::VSOCK_OP_RST => self.process_stream_rst(pkt),
            _ => warn!("stream: unhandled op={}", pkt.op()),
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_peer_limit_evicts_the_least_recently_used_peer_per_port() {
        let muxer = VsockMuxer::new(3, None, None, None, None, TsiFlags::empty());
        {
            let mut peers = muxer.dgram_peer_map.lock().unwrap();
            for source_port in 1..=MAX_DGRAM_PEERS_PER_PORT as u32 {
                peers.insert(
                    (source_port, 5000),
                    DgramPeerEntry {
                        id: source_port as u64,
                        last_used: source_port as u64,
                    },
                );
            }
            peers.insert(
                (1, 6000),
                DgramPeerEntry {
                    id: u32::MAX as u64,
                    last_used: 0,
                },
            );
        }

        muxer.evict_oldest_dgram_peer(5000);

        let peers = muxer.dgram_peer_map.lock().unwrap();
        assert!(!peers.contains_key(&(1, 5000)));
        assert_eq!(
            peers.keys().filter(|(_, port)| *port == 5000).count(),
            MAX_DGRAM_PEERS_PER_PORT - 1
        );
        assert!(peers.contains_key(&(1, 6000)));
    }
}
