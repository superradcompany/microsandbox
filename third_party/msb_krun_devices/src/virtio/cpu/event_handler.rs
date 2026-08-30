#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

use polly::event_manager::{EventManager, Pollable, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use super::device::Cpu;

impl Cpu {
    fn queue_event(&self, idx: usize) -> &std::sync::Arc<utils::eventfd::EventFd> {
        &self.queues.as_ref().expect("queues should exist")[idx].event
    }

    fn handle_activate_event(&mut self, event_manager: &mut EventManager) {
        debug!("virtio-msb-cpu: activate event");
        if let Err(e) = self.activate_evt.read() {
            error!("Failed to consume virtio-msb-cpu activate event: {e:?}");
        }
        // All host<->guest communication happens through config space; the
        // declared queue exists only to satisfy transport expectations, so
        // there is nothing further to register.
        let activate_evt = eventfd_pollable(&self.activate_evt);
        event_manager.unregister(activate_evt).unwrap_or_else(|e| {
            error!("Failed to unregister virtio-msb-cpu activate evt: {e:?}");
        })
    }
}

impl Subscriber for Cpu {
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
        let source = event.fd();
        let activate_evt = eventfd_pollable(&self.activate_evt);
        let req = eventfd_pollable(self.queue_event(0));

        if source == activate_evt {
            self.handle_activate_event(event_manager);
        } else if source == req {
            let _ = self.queue_event(0).read();
        } else {
            warn!("Unexpected virtio-msb-cpu event received: {source:?}");
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![EpollEvent::new(
            EventSet::IN,
            pollable_token(eventfd_pollable(&self.activate_evt)),
        )]
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

#[cfg(unix)]
fn pollable_token(pollable: Pollable) -> u64 {
    pollable as u64
}

#[cfg(windows)]
fn pollable_token(pollable: Pollable) -> u64 {
    pollable as usize as u64
}
