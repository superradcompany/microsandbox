// Copyright 2026 Super Rad Company.
// SPDX-License-Identifier: Apache-2.0

//! Windows waitable-handle backend exposed through libkrun's epoll-shaped API.

use std::collections::HashMap;
use std::io;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bitflags::bitflags;

use crate::event::{EventNotifier, EventSource, WaitContext, WaitEvent};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Internal token used to rebuild a blocking wait after a registration change.
const CONTROL_TOKEN: u64 = u64::MAX;

#[repr(i32)]
pub enum ControlOperation {
    Add,
    Modify,
    Delete,
}

bitflags! {
    pub struct EventSet: u32 {
        const IN = 0b0000_0001;
        const OUT = 0b0000_0010;
        const ERROR = 0b0000_0100;
        const READ_HANG_UP = 0b0000_1000;
        const EDGE_TRIGGERED = 0b0001_0000;
        const HANG_UP = 0b0010_0000;
        const PRIORITY = 0b0100_0000;
        const WAKE_UP = 0b1000_0000;
        const ONE_SHOT = 0b0001_0000_0000;
        const EXCLUSIVE = 0b0010_0000_0000;
    }
}

#[derive(Clone, Copy, Default)]
pub struct EpollEvent {
    events: u32,
    data: u64,
}

#[derive(Debug)]
pub struct Epoll {
    context: Mutex<WaitContext>,
    // Store opaque handle values as integers so the synchronized registry is
    // safely movable with an event loop thread.
    registrations: Mutex<HashMap<usize, u64>>,
    control: EventNotifier,
}

impl EpollEvent {
    pub fn new(events: EventSet, data: u64) -> Self {
        Self {
            events: events.bits(),
            data,
        }
    }

    pub fn events(&self) -> u32 {
        self.events
    }

    pub fn event_set(&self) -> EventSet {
        EventSet::from_bits_truncate(self.events)
    }

    pub fn data(&self) -> u64 {
        self.data
    }

    pub fn fd(&self) -> RawHandle {
        self.data as usize as RawHandle
    }
}

impl std::fmt::Debug for EpollEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ events: {}, data: {} }}", self.events(), self.data())
    }
}

impl Epoll {
    pub fn new() -> io::Result<Self> {
        let control = EventNotifier::new()?;
        let mut context = WaitContext::new();
        context.add(
            control.event_source(CONTROL_TOKEN),
            crate::event::EventSet::IN,
        )?;

        Ok(Self {
            context: Mutex::new(context),
            registrations: Mutex::new(HashMap::new()),
            control,
        })
    }

    pub fn ctl(
        &self,
        operation: ControlOperation,
        handle: RawHandle,
        event: &EpollEvent,
    ) -> io::Result<()> {
        let mut context = self.context.lock().unwrap();
        let mut registrations = self.registrations.lock().unwrap();

        let result = match operation {
            ControlOperation::Add => {
                if event.data == CONTROL_TOKEN {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "event token is reserved for epoll control",
                    ));
                }
                context.add(
                    EventSource::waitable_handle(handle, event.data),
                    event_set_to_wait_event_set(event.event_set()),
                )?;
                registrations.insert(handle as usize, event.data);
                Ok(())
            }
            ControlOperation::Modify => {
                let token = registrations
                    .get(&(handle as usize))
                    .copied()
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, "handle is not registered")
                    })?;
                context.modify(token, event_set_to_wait_event_set(event.event_set()))
            }
            ControlOperation::Delete => {
                let token = registrations.remove(&(handle as usize)).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "handle is not registered")
                })?;
                context.delete(token)
            }
        };

        // Wake any waiter so it can rebuild its handle snapshot. The context
        // lock is intentionally still held here, preventing the waiter from
        // draining this notification before the mutation is visible.
        if result.is_ok() {
            self.control.wake()?;
        }
        result
    }

    pub fn wait(
        &self,
        max_events: usize,
        timeout: i32,
        events: &mut [EpollEvent],
    ) -> io::Result<usize> {
        let output_capacity = max_events.min(events.len());
        if output_capacity == 0 {
            return Ok(0);
        }

        let deadline = (timeout >= 0).then(|| {
            Instant::now()
                .checked_add(Duration::from_millis(timeout as u64))
                .unwrap_or_else(Instant::now)
        });

        loop {
            // Drain and snapshot under the same lock used by ctl(). A control
            // mutation after this point will signal the notifier contained in
            // the snapshot and force another iteration.
            let snapshot = {
                let context = self.context.lock().unwrap();
                self.control.drain()?;
                context.clone()
            };
            let wait_timeout = remaining_timeout(timeout, deadline);
            let mut wait_events = vec![WaitEvent::default(); output_capacity + 1];
            let count = snapshot.wait(wait_timeout, &mut wait_events)?;

            let mut written = 0;
            let mut control_ready = false;
            for event in wait_events.into_iter().take(count) {
                if event.token() == CONTROL_TOKEN {
                    control_ready = true;
                    continue;
                }
                if written == output_capacity {
                    break;
                }
                events[written] =
                    EpollEvent::new(wait_event_set_to_event_set(event.events()), event.token());
                written += 1;
            }

            if written > 0 || !control_ready || wait_timeout == 0 {
                return Ok(written);
            }
        }
    }
}

impl AsRawHandle for Epoll {
    fn as_raw_handle(&self) -> RawHandle {
        std::ptr::null_mut()
    }
}

fn event_set_to_wait_event_set(events: EventSet) -> crate::event::EventSet {
    let mut wait_events = crate::event::EventSet::empty();
    if events.contains(EventSet::IN) {
        wait_events |= crate::event::EventSet::IN;
    }
    if events.contains(EventSet::OUT) {
        wait_events |= crate::event::EventSet::OUT;
    }
    wait_events
}

fn wait_event_set_to_event_set(events: crate::event::EventSet) -> EventSet {
    let mut epoll_events = EventSet::empty();
    if events.contains(crate::event::EventSet::IN) {
        epoll_events |= EventSet::IN;
    }
    if events.contains(crate::event::EventSet::OUT) {
        epoll_events |= EventSet::OUT;
    }
    if events.contains(crate::event::EventSet::ERROR) {
        epoll_events |= EventSet::ERROR;
    }
    if events.contains(crate::event::EventSet::HANG_UP) {
        epoll_events |= EventSet::HANG_UP;
    }
    if events.contains(crate::event::EventSet::READ_HANG_UP) {
        epoll_events |= EventSet::READ_HANG_UP;
    }
    epoll_events
}

fn remaining_timeout(timeout: i32, deadline: Option<Instant>) -> i32 {
    let Some(deadline) = deadline else {
        return timeout;
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return 0;
    }

    remaining.as_millis().clamp(1, i32::MAX as u128) as i32
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::{mpsc, Arc};
    use std::thread;

    use crate::event::RawEventSource;

    use super::*;

    #[test]
    fn registration_wakes_a_blocked_waiter_without_locking_ctl() {
        let epoll = Arc::new(Epoll::new().unwrap());
        let waiter_epoll = Arc::clone(&epoll);
        let (wait_tx, wait_rx) = mpsc::channel();
        let waiter = thread::spawn(move || {
            let mut events = [EpollEvent::default(); 1];
            let result = waiter_epoll
                .wait(events.len(), -1, &mut events)
                .map(|count| (count, events[0].data()));
            wait_tx.send(result).unwrap();
        });

        // Give the waiter time to enter its infinite wait with only the
        // internal control event registered.
        thread::sleep(Duration::from_millis(20));

        let notifier = EventNotifier::new().unwrap();
        let handle = match notifier.event_source(7).raw() {
            RawEventSource::WaitableHandle(handle) => handle as usize,
            RawEventSource::CompletionHandle(_) => unreachable!(),
        };
        let ctl_epoll = Arc::clone(&epoll);
        let (ctl_tx, ctl_rx) = mpsc::channel();
        thread::spawn(move || {
            ctl_tx
                .send(ctl_epoll.ctl(
                    ControlOperation::Add,
                    handle as RawHandle,
                    &EpollEvent::new(EventSet::IN, 7),
                ))
                .unwrap();
        });

        ctl_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("ctl must not block behind the wait thread")
            .unwrap();
        notifier.wake().unwrap();

        let (count, token) = wait_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("registered event should wake the rebuilt wait set")
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(token, 7);
        waiter.join().unwrap();
    }
}
