use std::sync::{Arc, Mutex};
use std::thread;

use crossbeam_channel::Sender;
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vm_memory::GuestMemoryMmap;

use super::super::Queue as VirtQueue;
use super::muxer::ProxyMap;
use super::muxer_rxq::MuxerRxQ;
use super::proxy::{ProxyRemoval, ProxyUpdate};
use super::VsockPollable;
use crate::virtio::InterruptTransport;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct MuxerThread {
    cid: u64,
    epoll: Arc<Epoll>,
    rxq: Arc<Mutex<MuxerRxQ>>,
    proxy_map: ProxyMap,
    mem: GuestMemoryMmap,
    queue: Arc<Mutex<VirtQueue>>,
    interrupt: InterruptTransport,
    reaper_sender: Sender<u64>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MuxerThread {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cid: u64,
        epoll: Arc<Epoll>,
        rxq: Arc<Mutex<MuxerRxQ>>,
        proxy_map: ProxyMap,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        interrupt: InterruptTransport,
        reaper_sender: Sender<u64>,
    ) -> Self {
        Self {
            cid,
            epoll,
            rxq,
            proxy_map,
            mem,
            queue,
            interrupt,
            reaper_sender,
        }
    }

    pub fn run(self) {
        thread::Builder::new()
            .name("vsock muxer".into())
            .spawn(|| self.work())
            .unwrap();
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
        if let Some(credit) = update.push_credit_req {
            super::muxer::push_packet(self.cid, credit, &self.rxq, &self.queue, &self.mem);
        }
        match update.remove_proxy {
            ProxyRemoval::Keep => {}
            ProxyRemoval::Immediate => {
                self.proxy_map.write().unwrap().remove(&id);
            }
            ProxyRemoval::Deferred => {
                if self.reaper_sender.send(id).is_err() {
                    self.proxy_map.write().unwrap().remove(&id);
                }
            }
        }
        if update.signal_queue {
            self.interrupt.signal_used_queue();
        }
    }

    fn work(self) {
        loop {
            let mut events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
            match self.epoll.wait(events.len(), -1, &mut events) {
                Ok(count) => {
                    for event in events.iter().take(count) {
                        let id = event.data();
                        let update =
                            self.proxy_map.read().unwrap().get(&id).map(|proxy| {
                                proxy.lock().unwrap().process_event(event.event_set())
                            });
                        if let Some(update) = update {
                            self.process_proxy_update(id, update);
                        }
                    }
                }
                Err(err) => debug!("failed to consume vsock wait event: {err}"),
            }
        }
    }
}
