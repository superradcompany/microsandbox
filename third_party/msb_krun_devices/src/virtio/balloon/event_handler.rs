#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

use polly::event_manager::{EventManager, Pollable, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use super::device::{
    Balloon, BalloonStat, DFQ_INDEX, FRQ_INDEX, IFQ_INDEX, MAX_STATS_DESC_LEN, PHQ_INDEX,
    STQ_INDEX, VIRTIO_BALLOON_S_AVAIL,
};
use crate::virtio::descriptor_utils::Reader;
use crate::virtio::device::VirtioDevice;

impl Balloon {
    fn queue_event(&self, idx: usize) -> &std::sync::Arc<utils::eventfd::EventFd> {
        &self.queues.as_ref().expect("queues should exist")[idx].event
    }

    pub(crate) fn handle_ifq_event(&mut self, event: &EpollEvent) {
        error!("balloon: unsupported inflate queue event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("balloon: inflate unexpected event {event_set:?}");
            return;
        }

        if let Err(e) = self.queue_event(IFQ_INDEX).read() {
            error!("Failed to read balloon inflate queue event: {e:?}");
        }
    }

    pub(crate) fn handle_dfq_event(&mut self, event: &EpollEvent) {
        error!("balloon: unsupported deflate queue event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("balloon: deflate unexpected event {event_set:?}");
            return;
        }

        if let Err(e) = self.queue_event(DFQ_INDEX).read() {
            error!("Failed to read balloon inflate queue event: {e:?}");
        }
    }

    pub(crate) fn handle_stq_event(&mut self, event: &EpollEvent) {
        debug!("balloon: stats queue event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("balloon: stats unexpected event {event_set:?}");
            return;
        }

        if let Err(e) = self.queue_event(STQ_INDEX).read() {
            error!("Failed to read balloon stats queue event: {e:?}");
        } else {
            self.process_stq();
        }
    }

    pub(crate) fn handle_stats_timer_event(&mut self, event: &EpollEvent) {
        debug!("balloon: stats timer event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("balloon: stats timer unexpected event {event_set:?}");
            return;
        }

        if let Err(e) = self.stats_timer.read() {
            error!("Failed to read balloon stats timer event: {e:?}");
        } else {
            self.trigger_stats_update();
        }
    }

    pub(crate) fn handle_phq_event(&mut self, event: &EpollEvent) {
        error!("balloon: unsupported page-hinting queue event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("balloon: page-hinting unexpected event {event_set:?}");
            return;
        }

        if let Err(e) = self.queue_event(PHQ_INDEX).read() {
            error!("Failed to read balloon page-hinting queue event: {e:?}");
        }
    }

    pub(crate) fn handle_frq_event(&mut self, event: &EpollEvent) {
        debug!("balloon: free-page reporting queue event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("balloon: free-page reporting unexpected event {event_set:?}");
            return;
        }

        if let Err(e) = self.queue_event(FRQ_INDEX).read() {
            error!("Failed to read balloon free-page reporting queue event: {e:?}");
        } else if self.process_frq() {
            self.device_state.signal_used_queue();
        }
    }

    fn process_stq(&mut self) {
        let mem = match self.device_state {
            crate::virtio::DeviceState::Activated(ref mem, _) => mem,
            crate::virtio::DeviceState::Inactive => unreachable!(),
        };
        let metrics = self.metrics.clone();
        while let Some(head) = {
            let queues = self
                .queues
                .as_mut()
                .expect("queues should exist when activated");
            queues[STQ_INDEX].queue.pop(mem)
        } {
            let index = head.index;

            if let Some(prev_index) = self.stats_desc_index.take() {
                error!("balloon: driver is not compliant, more than one stats buffer received");
                let add_result = {
                    let queues = self
                        .queues
                        .as_mut()
                        .expect("queues should exist when activated");
                    queues[STQ_INDEX].queue.add_used(mem, prev_index, 0)
                };
                if let Err(e) = add_result {
                    error!("balloon: failed to add stale used stats element: {e:?}");
                } else {
                    self.device_state.signal_used_queue();
                }
            }

            match stats_descriptor_len(&head) {
                Some(len) if len <= MAX_STATS_DESC_LEN => {}
                Some(len) => {
                    warn!(
                        "balloon: stats descriptor too large: {} > {}, skipping",
                        len, MAX_STATS_DESC_LEN
                    );
                    self.stats_desc_index = Some(index);
                    self.arm_stats_timer();
                    continue;
                }
                None => {
                    error!("balloon: stats descriptor length overflow");
                    self.stats_desc_index = Some(index);
                    self.arm_stats_timer();
                    continue;
                }
            }

            let mut reader = match Reader::new(mem, head) {
                Ok(reader) => reader,
                Err(e) => {
                    error!("balloon: invalid stats descriptor chain: {e:?}");
                    self.stats_desc_index = Some(index);
                    self.arm_stats_timer();
                    continue;
                }
            };

            while reader.available_bytes() >= std::mem::size_of::<BalloonStat>() {
                match reader.read_obj::<BalloonStat>() {
                    Ok(stat) => {
                        if stat.tag.to_native() == VIRTIO_BALLOON_S_AVAIL {
                            metrics.set_memory_available_bytes(stat.val.to_native());
                        }
                    }
                    Err(e) => {
                        error!("balloon: failed to read stat: {e:?}");
                        break;
                    }
                }
            }

            self.stats_desc_index = Some(index);
            self.arm_stats_timer();
        }
    }

    fn arm_stats_timer(&self) {
        let Some(interval) = self.stats_polling_interval else {
            return;
        };

        if let Err(e) = self.stats_timer.arm_oneshot(interval) {
            error!("balloon: failed to arm stats timer: {e:?}");
        }
    }

    fn trigger_stats_update(&mut self) {
        let Some(index) = self.stats_desc_index.take() else {
            debug!("balloon: stats timer fired without a retained descriptor");
            return;
        };

        let mem = match self.device_state {
            crate::virtio::DeviceState::Activated(ref mem, _) => mem,
            crate::virtio::DeviceState::Inactive => unreachable!(),
        };
        let queues = self
            .queues
            .as_mut()
            .expect("queues should exist when activated");

        if let Err(e) = queues[STQ_INDEX].queue.add_used(mem, index, 0) {
            error!("balloon: failed to add used stats element: {e:?}");
        } else {
            self.device_state.signal_used_queue();
        }
    }

    fn handle_activate_event(&mut self, event_manager: &mut EventManager) {
        debug!("balloon: activate event");
        if let Err(e) = self.activate_evt.read() {
            error!("Failed to consume balloon activate event: {e:?}");
        }

        // The subscriber must exist as we previously registered activate_evt via
        // `interest_list()`.
        let activate_evt = eventfd_pollable(&self.activate_evt);
        let self_subscriber = event_manager.subscriber(activate_evt).unwrap();

        let ifq = eventfd_pollable(self.queue_event(IFQ_INDEX));
        let dfq = eventfd_pollable(self.queue_event(DFQ_INDEX));
        let stq = eventfd_pollable(self.queue_event(STQ_INDEX));
        let phq = eventfd_pollable(self.queue_event(PHQ_INDEX));
        let frq = eventfd_pollable(self.queue_event(FRQ_INDEX));
        let stats_timer = timerfd_pollable(&self.stats_timer);

        event_manager
            .register(ifq, pollable_event(ifq), self_subscriber.clone())
            .unwrap_or_else(|e| {
                error!("Failed to register balloon ifq with event manager: {e:?}");
            });

        event_manager
            .register(dfq, pollable_event(dfq), self_subscriber.clone())
            .unwrap_or_else(|e| {
                error!("Failed to register balloon dfq with event manager: {e:?}");
            });

        if self.stats_enabled() {
            event_manager
                .register(stq, pollable_event(stq), self_subscriber.clone())
                .unwrap_or_else(|e| {
                    error!("Failed to register balloon stq with event manager: {e:?}");
                });

            event_manager
                .register(
                    stats_timer,
                    pollable_event(stats_timer),
                    self_subscriber.clone(),
                )
                .unwrap_or_else(|e| {
                    error!("Failed to register balloon stats timer with event manager: {e:?}");
                });
        }

        event_manager
            .register(phq, pollable_event(phq), self_subscriber.clone())
            .unwrap_or_else(|e| {
                error!("Failed to register balloon dfq with event manager: {e:?}");
            });

        event_manager
            .register(frq, pollable_event(frq), self_subscriber.clone())
            .unwrap_or_else(|e| {
                error!("Failed to register balloon frq with event manager: {e:?}");
            });

        event_manager.unregister(activate_evt).unwrap_or_else(|e| {
            error!("Failed to unregister balloon activate evt: {e:?}");
        })
    }
}

impl Subscriber for Balloon {
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
        let source = event.fd();
        let ifq = eventfd_pollable(self.queue_event(IFQ_INDEX));
        let dfq = eventfd_pollable(self.queue_event(DFQ_INDEX));
        let stq = eventfd_pollable(self.queue_event(STQ_INDEX));
        let phq = eventfd_pollable(self.queue_event(PHQ_INDEX));
        let frq = eventfd_pollable(self.queue_event(FRQ_INDEX));
        let activate_evt = eventfd_pollable(&self.activate_evt);
        let stats_timer = timerfd_pollable(&self.stats_timer);

        if self.is_activated() {
            match source {
                _ if source == ifq => self.handle_ifq_event(event),
                _ if source == dfq => self.handle_dfq_event(event),
                _ if source == stq => self.handle_stq_event(event),
                _ if self.stats_enabled() && source == stats_timer => {
                    self.handle_stats_timer_event(event)
                }
                _ if source == phq => self.handle_phq_event(event),
                _ if source == frq => self.handle_frq_event(event),
                _ if source == activate_evt => {
                    self.handle_activate_event(event_manager);
                }
                _ => warn!("Unexpected balloon event received: {source:?}"),
            }
        } else {
            warn!("balloon: The device is not yet activated. Spurious event received: {source:?}");
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

#[cfg(unix)]
fn timerfd_pollable(timer: &utils::timerfd::TimerFd) -> Pollable {
    timer.as_raw_fd()
}

#[cfg(windows)]
fn timerfd_pollable(timer: &utils::timerfd::TimerFd) -> Pollable {
    timer.as_raw_handle()
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

fn stats_descriptor_len(head: &crate::virtio::DescriptorChain<'_>) -> Option<u32> {
    let mut len = 0u32;
    for desc in head.clone().into_iter().readable() {
        len = len.checked_add(desc.len)?;
    }
    Some(len)
}
