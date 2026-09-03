#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

use polly::event_manager::{EventManager, Pollable, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use super::device::{Mem, REQ_INDEX};
use crate::virtio::device::VirtioDevice;

impl Mem {
    fn queue_event(&self, idx: usize) -> &std::sync::Arc<utils::eventfd::EventFd> {
        &self.queues.as_ref().expect("queues should exist")[idx].event
    }

    pub(crate) fn handle_req_event(&mut self, event: &EpollEvent) {
        debug!("virtio-mem: request queue event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("virtio-mem: request queue unexpected event {event_set:?}");
            return;
        }

        if let Err(e) = self.queue_event(REQ_INDEX).read() {
            error!("Failed to read virtio-mem request queue event: {e:?}");
        } else if self.process_req_queue() {
            self.device_state.signal_used_queue();
        }
    }

    fn handle_activate_event(&mut self, event_manager: &mut EventManager) {
        debug!("virtio-mem: activate event");
        if let Err(e) = self.activate_evt.read() {
            error!("Failed to consume virtio-mem activate event: {e:?}");
        }

        // The subscriber must exist as we previously registered activate_evt via
        // `interest_list()`.
        let activate_evt = eventfd_pollable(&self.activate_evt);
        let self_subscriber = event_manager.subscriber(activate_evt).unwrap();

        let req = eventfd_pollable(self.queue_event(REQ_INDEX));

        event_manager
            .register(req, pollable_event(req), self_subscriber.clone())
            .unwrap_or_else(|e| {
                error!("Failed to register virtio-mem request queue with event manager: {e:?}");
            });

        event_manager.unregister(activate_evt).unwrap_or_else(|e| {
            error!("Failed to unregister virtio-mem activate evt: {e:?}");
        })
    }
}

impl Subscriber for Mem {
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
        let source = event.fd();
        let req = eventfd_pollable(self.queue_event(REQ_INDEX));
        let activate_evt = eventfd_pollable(&self.activate_evt);

        if self.is_activated() {
            match source {
                _ if source == req => self.handle_req_event(event),
                _ if source == activate_evt => {
                    self.handle_activate_event(event_manager);
                }
                _ => warn!("Unexpected virtio-mem event received: {source:?}"),
            }
        } else {
            warn!(
                "virtio-mem: The device is not yet activated. Spurious event received: {source:?}"
            );
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![pollable_event(eventfd_pollable(&self.activate_evt))]
    }
}

#[cfg(unix)]
fn eventfd_pollable(event: &utils::eventfd::EventFd) -> Pollable {
    event.as_raw_fd()
}

#[cfg(windows)]
fn eventfd_pollable(event: &utils::eventfd::EventFd) -> Pollable {
    event.as_raw_handle()
}

fn pollable_event(pollable: Pollable) -> EpollEvent {
    EpollEvent::new(EventSet::IN, pollable_token(pollable))
}

#[cfg(unix)]
fn pollable_token(pollable: Pollable) -> u64 {
    pollable as u64
}

#[cfg(windows)]
fn pollable_token(pollable: Pollable) -> u64 {
    pollable as usize as u64
}
