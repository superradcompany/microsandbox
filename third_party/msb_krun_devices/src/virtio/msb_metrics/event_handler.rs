#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

use polly::event_manager::{EventManager, Pollable, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use super::device::{MsbMetrics, RX_INDEX};
use crate::virtio::device::VirtioDevice;

impl MsbMetrics {
    pub(crate) fn handle_rx_event(&mut self, event: &EpollEvent) {
        debug!("msb_metrics: rx queue event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("msb_metrics: rx queue unexpected event {event_set:?}");
            return;
        }

        if let Err(err) = self.queue_event(RX_INDEX).read() {
            error!("msb_metrics: failed to read rx queue event: {err:?}");
        } else if self.process_rx() {
            self.device_state.signal_used_queue();
        }
    }

    fn handle_activate_event(&self, event_manager: &mut EventManager) {
        debug!("msb_metrics: activate event");
        if let Err(err) = self.activate_evt.read() {
            error!("msb_metrics: failed to consume activate event: {err:?}");
        }

        let activate_evt = eventfd_pollable(&self.activate_evt);
        let self_subscriber = event_manager.subscriber(activate_evt).unwrap();

        let rx = eventfd_pollable(self.queue_event(RX_INDEX));

        event_manager
            .register(rx, pollable_event(rx), self_subscriber.clone())
            .unwrap_or_else(|err| {
                error!("msb_metrics: failed to register rx queue: {err:?}");
            });

        event_manager
            .unregister(activate_evt)
            .unwrap_or_else(|err| {
                error!("msb_metrics: failed to unregister activate event: {err:?}");
            })
    }
}

impl Subscriber for MsbMetrics {
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
        let source = event.fd();
        let activate_evt = eventfd_pollable(&self.activate_evt);

        if source == activate_evt {
            if !self.is_activated() {
                warn!("msb_metrics: device is not activated; spurious event received: {source:?}");
                return;
            }

            self.handle_activate_event(event_manager);
            return;
        }

        if !self.is_activated() {
            warn!("msb_metrics: device is not activated; spurious event received: {source:?}");
            return;
        }

        let rx = eventfd_pollable(self.queue_event(RX_INDEX));
        match source {
            _ if source == rx => self.handle_rx_event(event),
            _ => warn!("msb_metrics: unexpected event received: {source:?}"),
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
