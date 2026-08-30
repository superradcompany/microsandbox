use std::os::unix::io::AsRawFd;

use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use super::device::{Rng, REQ_INDEX};
use crate::virtio::device::VirtioDevice;

impl Rng {
    pub(crate) fn handle_req_event(&mut self, event: &EpollEvent) {
        debug!("rng: request queue event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("rng: request queue unexpected event {event_set:?}");
            return;
        }

        if let Err(e) = self.queue_event(REQ_INDEX).read() {
            error!("Failed to read request queue event: {e:?}");
        } else if self.process_req() {
            self.device_state.signal_used_queue();
        }
    }

    fn handle_activate_event(&self, event_manager: &mut EventManager) {
        debug!("rng: activate event");
        if let Err(e) = self.activate_evt.read() {
            error!("Failed to consume rng activate event: {e:?}");
        }

        // The subscriber must exist as we previously registered activate_evt via
        // `interest_list()`.
        let self_subscriber = event_manager
            .subscriber(self.activate_evt.as_raw_fd())
            .unwrap();

        event_manager
            .register(
                self.queue_event(REQ_INDEX).as_raw_fd(),
                EpollEvent::new(EventSet::IN, self.queue_event(REQ_INDEX).as_raw_fd() as u64),
                self_subscriber.clone(),
            )
            .unwrap_or_else(|e| {
                error!("Failed to register rng frq with event manager: {e:?}");
            });

        event_manager
            .unregister(self.activate_evt.as_raw_fd())
            .unwrap_or_else(|e| {
                error!("Failed to unregister rng activate evt: {e:?}");
            })
    }
}

impl Subscriber for Rng {
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
        let source = event.fd();
        let req = self.queue_event(REQ_INDEX).as_raw_fd();
        let activate_evt = self.activate_evt.as_raw_fd();

        if self.is_activated() {
            match source {
                _ if source == req => self.handle_req_event(event),
                _ if source == activate_evt => {
                    self.handle_activate_event(event_manager);
                }
                _ => warn!("Unexpected rng event received: {source:?}"),
            }
        } else {
            warn!("rng: The device is not yet activated. Spurious event received: {source:?}");
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![EpollEvent::new(
            EventSet::IN,
            self.activate_evt.as_raw_fd() as u64,
        )]
    }
}
