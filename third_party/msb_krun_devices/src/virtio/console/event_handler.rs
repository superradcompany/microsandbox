use polly::event_manager::{EventManager, Pollable, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use super::device::Console;
use super::{eventfd_pollable, pollable_token};
use crate::virtio::console::device::{CONTROL_RXQ_INDEX, CONTROL_TXQ_INDEX};
use crate::virtio::console::port_queue_mapping::{queue_idx_to_port_id, QueueDirection};
use crate::virtio::device::VirtioDevice;

impl Console {
    pub(crate) fn read_queue_event(&self, queue_index: usize, event: &EpollEvent) -> bool {
        log::trace!("Event on queue {queue_index}: {:?}", event.event_set());

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("Unexpected event from queue index {queue_index}: {event_set:?}");
            return false;
        }

        if let Err(e) = self.queue_events[queue_index].read() {
            error!("Failed to read event from queue index {queue_index}: {e:?}");
            return false;
        }

        true
    }

    fn notify_port_queue_event(&mut self, queue_index: usize) {
        let (direction, port_id) = queue_idx_to_port_id(queue_index);
        match direction {
            QueueDirection::Rx => {
                log::trace!("Notify rx (queue event)");
                self.ports[port_id].notify_rx()
            }
            QueueDirection::Tx => {
                log::trace!("Notify tx (queue event)");
                self.ports[port_id].notify_tx()
            }
        }
    }

    fn handle_activate_event(&self, event_manager: &mut EventManager) {
        debug!("console: activate event");
        let activate_evt = eventfd_pollable(&self.activate_evt);

        if let Err(e) = self.activate_evt.read() {
            error!("Failed to consume console activate event: {e:?}");
        }

        // The subscriber must exist as we previously registered activate_evt via
        // `interest_list()`.
        let self_subscriber = event_manager.subscriber(activate_evt).unwrap();

        for queue_index in 0..self.queues.len() {
            let queue_evt = eventfd_pollable(&self.queue_events[queue_index]);
            event_manager
                .register(
                    queue_evt,
                    EpollEvent::new(EventSet::IN, pollable_token(queue_evt)),
                    self_subscriber.clone(),
                )
                .unwrap_or_else(|e| {
                    error!(
                        "Failed to register queue index {queue_index} with event manager: {e:?}"
                    );
                });
        }

        event_manager.unregister(activate_evt).unwrap_or_else(|e| {
            error!("Failed to unregister fs activate evt: {e:?}");
        })
    }

    fn handle_sigwinch_event(&mut self, event: &EpollEvent) {
        debug!("console: SIGWINCH event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("console: sigwinch unexpected event {event_set:?}");
        }

        if let Err(e) = self.sigwinch_evt.read() {
            error!("Failed to read the sigwinch event: {e:?}");
        }

        for i in 0..self.ports.len() {
            if let Some(term) = self.ports[i].terminal() {
                let (cols, rows) = term.get_win_size();
                self.update_console_size(i as u32, cols, rows);
            }
        }
    }

    fn read_control_queue_event(&mut self, event: &EpollEvent) {
        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("Unexpected event {event_set:?}");
        }

        if let Err(e) = self.control.queue_evt().read() {
            error!("Failed to read the ConsoleControl event: {e:?}");
        }
    }
}

impl Subscriber for Console {
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
        let source = event.fd();

        let control_rxq = eventfd_pollable(&self.queue_events[CONTROL_RXQ_INDEX]);
        let control_txq = eventfd_pollable(&self.queue_events[CONTROL_TXQ_INDEX]);
        let control_rxq_control = eventfd_pollable(self.control.queue_evt());

        let activate_evt = eventfd_pollable(&self.activate_evt);
        let sigwinch_evt = eventfd_pollable(&self.sigwinch_evt);

        if self.is_activated() {
            let mut raise_irq = false;

            if source == control_txq {
                raise_irq |=
                    self.read_queue_event(CONTROL_TXQ_INDEX, event) && self.process_control_tx()
            } else if source == control_rxq_control {
                self.read_control_queue_event(event);
                raise_irq |= self.process_control_rx();
            } else if source == control_rxq {
                raise_irq |= self.read_queue_event(CONTROL_RXQ_INDEX, event)
            }
            /* Guest signaled input/output on port */
            else if let Some(queue_index) = self
                .queue_events
                .iter()
                .position(|fd| eventfd_pollable(fd) == source)
            {
                raise_irq |= self.read_queue_event(queue_index, event);
                self.notify_port_queue_event(queue_index);
            } else if source == activate_evt {
                self.handle_activate_event(event_manager);
            } else if source == sigwinch_evt {
                self.handle_sigwinch_event(event);
            } else {
                log::warn!("Unexpected console event received: {source:?}")
            }
            if raise_irq {
                self.device_state.signal_used_queue();
            }
        } else {
            warn!("console: The device is not yet activated. Spurious event received: {source:?}");
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        fn event(event: Pollable) -> EpollEvent {
            EpollEvent::new(EventSet::IN, pollable_token(event))
        }

        vec![
            event(eventfd_pollable(&self.activate_evt)),
            event(eventfd_pollable(&self.sigwinch_evt)),
            event(eventfd_pollable(self.control.queue_evt())),
        ]
    }
}
