// Copyright 2026 Super Rad Company.
// SPDX-License-Identifier: Apache-2.0

//! Platform-neutral event sources for readiness and wake notifications.
//!
//! Unix platforms represent readiness sources as file descriptors. Windows
//! represents readiness sources as waitable handles and reserves IOCP for
//! overlapped I/O completions.

use std::io;
#[cfg(windows)]
use std::time::Duration;

use bitflags::bitflags;

#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};

#[cfg(unix)]
use crate::eventfd::{EventFd, EFD_NONBLOCK};

#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, FALSE, HANDLE, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, ResetEvent, SetEvent, WaitForMultipleObjects,
    WaitForSingleObject,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

#[cfg(windows)]
const INFINITE_TIMEOUT: u32 = u32::MAX;

#[cfg(windows)]
const MAXIMUM_WAIT_OBJECTS: usize = 64;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Stable identifier returned with a ready event.
pub type EventToken = u64;

bitflags! {
    /// Portable event interest/readiness flags.
    pub struct EventSet: u32 {
        /// The source is readable or has data to consume.
        const IN = 0b0000_0001;
        /// The source is writable or can accept more data.
        const OUT = 0b0000_0010;
        /// An error condition is present on the source.
        const ERROR = 0b0000_0100;
        /// The peer has hung up.
        const HANG_UP = 0b0000_1000;
        /// The peer closed the read side.
        const READ_HANG_UP = 0b0001_0000;
        /// Request edge-triggered delivery where the backend supports it.
        const EDGE_TRIGGERED = 0b0010_0000;
    }
}

/// Platform-specific event source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventSource {
    token: EventToken,
    raw: RawEventSource,
}

/// Platform-specific event source identity.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawEventSource {
    /// Unix readiness source backed by a file descriptor.
    Fd(RawFd),
}

/// Platform-specific event source identity.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawEventSource {
    /// Windows readiness source backed by a waitable handle.
    WaitableHandle(RawHandle),
    /// Windows completion source backed by a handle associated with IOCP.
    CompletionHandle(RawHandle),
}

/// Event returned from [`WaitContext::wait`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitEvent {
    events: EventSet,
    token: EventToken,
}

/// Context that waits on registered event sources.
#[derive(Clone, Debug, Default)]
pub struct WaitContext {
    sources: Vec<RegisteredSource>,
}

// Windows HANDLE values are process-wide opaque identifiers. WaitContext never
// dereferences them, and callers synchronize mutation, so moving a context to
// its dedicated event-loop thread is safe.
#[cfg(windows)]
unsafe impl Send for WaitContext {}

#[derive(Clone, Copy, Debug)]
struct RegisteredSource {
    source: EventSource,
    interest: EventSet,
}

/// Cross-platform readiness notifier.
#[derive(Debug)]
pub struct EventNotifier {
    #[cfg(unix)]
    eventfd: EventFd,
    #[cfg(windows)]
    handle: HANDLE,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl EventSource {
    /// Create a new event source from a raw platform source and token.
    pub fn new(raw: RawEventSource, token: EventToken) -> Self {
        Self { token, raw }
    }

    /// Create a Unix file-descriptor source.
    #[cfg(unix)]
    pub fn fd(fd: RawFd, token: EventToken) -> Self {
        Self::new(RawEventSource::Fd(fd), token)
    }

    /// Create a Windows waitable-handle source.
    #[cfg(windows)]
    pub fn waitable_handle(handle: RawHandle, token: EventToken) -> Self {
        Self::new(RawEventSource::WaitableHandle(handle), token)
    }

    /// Create a Windows completion-handle source.
    #[cfg(windows)]
    pub fn completion_handle(handle: RawHandle, token: EventToken) -> Self {
        Self::new(RawEventSource::CompletionHandle(handle), token)
    }

    /// Token returned when this source is ready.
    pub fn token(&self) -> EventToken {
        self.token
    }

    /// Raw platform source.
    pub fn raw(&self) -> RawEventSource {
        self.raw
    }
}

impl WaitEvent {
    /// Create a ready event.
    pub fn new(events: EventSet, token: EventToken) -> Self {
        Self { events, token }
    }

    /// Ready event flags.
    pub fn events(&self) -> EventSet {
        self.events
    }

    /// Token associated with the ready source.
    pub fn token(&self) -> EventToken {
        self.token
    }
}

impl WaitContext {
    /// Create an empty wait context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a source to the wait context.
    pub fn add(&mut self, source: EventSource, interest: EventSet) -> io::Result<()> {
        if self.sources.iter().any(|s| s.source.token == source.token) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "event token already registered",
            ));
        }

        validate_source(&source)?;

        #[cfg(windows)]
        if self.sources.len() == MAXIMUM_WAIT_OBJECTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many Windows wait handles",
            ));
        }

        self.sources.push(RegisteredSource { source, interest });
        Ok(())
    }

    /// Modify the interest set for an existing source.
    pub fn modify(&mut self, token: EventToken, interest: EventSet) -> io::Result<()> {
        let Some(source) = self.sources.iter_mut().find(|s| s.source.token == token) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "event token is not registered",
            ));
        };

        source.interest = interest;
        Ok(())
    }

    /// Remove a source by token.
    pub fn delete(&mut self, token: EventToken) -> io::Result<()> {
        let Some(index) = self.sources.iter().position(|s| s.source.token == token) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "event token is not registered",
            ));
        };

        self.sources.swap_remove(index);
        Ok(())
    }

    /// Wait for ready sources, returning the number of entries written to `events`.
    pub fn wait(&self, timeout_ms: i32, events: &mut [WaitEvent]) -> io::Result<usize> {
        if events.is_empty() {
            return Ok(0);
        }

        wait_platform(&self.sources, timeout_ms, events)
    }
}

impl EventNotifier {
    /// Create a new readiness notifier.
    pub fn new() -> io::Result<Self> {
        new_event_notifier()
    }

    /// Signal the notifier.
    pub fn wake(&self) -> io::Result<()> {
        wake_event_notifier(self)
    }

    /// Consume or reset all pending notifications.
    pub fn drain(&self) -> io::Result<()> {
        drain_event_notifier(self)
    }

    /// Return this notifier as an event source.
    pub fn event_source(&self, token: EventToken) -> EventSource {
        event_notifier_source(self, token)
    }
}

impl Default for EventNotifier {
    fn default() -> Self {
        Self::new().expect("failed to create event notifier")
    }
}

impl Default for WaitEvent {
    fn default() -> Self {
        Self {
            events: EventSet::empty(),
            token: 0,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[cfg(windows)]
unsafe impl Send for EventNotifier {}

#[cfg(windows)]
unsafe impl Sync for EventNotifier {}

#[cfg(windows)]
impl Drop for EventNotifier {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(unix)]
fn wait_platform(
    sources: &[RegisteredSource],
    timeout_ms: i32,
    events: &mut [WaitEvent],
) -> io::Result<usize> {
    let mut poll_fds = sources
        .iter()
        .map(|source| libc::pollfd {
            fd: match source.source.raw {
                RawEventSource::Fd(fd) => fd,
            },
            events: event_set_to_poll_events(source.interest),
            revents: 0,
        })
        .collect::<Vec<_>>();

    let count = unsafe {
        libc::poll(
            poll_fds.as_mut_ptr(),
            poll_fds.len() as libc::nfds_t,
            timeout_ms,
        )
    };

    if count < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut written = 0;
    for (index, poll_fd) in poll_fds.iter().enumerate() {
        if poll_fd.revents == 0 {
            continue;
        }

        events[written] = WaitEvent::new(
            poll_events_to_event_set(poll_fd.revents),
            sources[index].source.token,
        );
        written += 1;

        if written == events.len() {
            break;
        }
    }

    Ok(written)
}

#[cfg(windows)]
fn wait_platform(
    sources: &[RegisteredSource],
    timeout_ms: i32,
    events: &mut [WaitEvent],
) -> io::Result<usize> {
    if sources.is_empty() {
        if timeout_ms > 0 {
            std::thread::sleep(Duration::from_millis(timeout_ms as u64));
        }
        return Ok(0);
    }

    // Wait on duplicated handles so callers can unregister and close their
    // originals immediately after waking the control source. Windows leaves a
    // wait undefined if one of its raw handles is closed concurrently.
    let process = unsafe { GetCurrentProcess() };
    let mut owned_handles = Vec::with_capacity(sources.len());
    for source in sources {
        match source.source.raw {
            RawEventSource::WaitableHandle(handle) => {
                let mut duplicate = std::ptr::null_mut();
                let result = unsafe {
                    DuplicateHandle(
                        process,
                        handle as HANDLE,
                        process,
                        &mut duplicate,
                        0,
                        FALSE,
                        DUPLICATE_SAME_ACCESS,
                    )
                };
                if result == FALSE {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: DuplicateHandle returned a new owned process handle.
                owned_handles.push(unsafe { OwnedHandle::from_raw_handle(duplicate) });
            }
            RawEventSource::CompletionHandle(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "IOCP completion sources require the completion backend",
                ));
            }
        }
    }
    let handles = owned_handles
        .iter()
        .map(|handle| handle.as_raw_handle() as HANDLE)
        .collect::<Vec<_>>();

    let timeout = if timeout_ms < 0 {
        INFINITE_TIMEOUT
    } else {
        timeout_ms as u32
    };

    let result =
        unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), FALSE, timeout) };

    if result == WAIT_TIMEOUT {
        return Ok(0);
    }
    if result == WAIT_FAILED {
        return Err(io::Error::last_os_error());
    }

    let first_index = result
        .checked_sub(WAIT_OBJECT_0)
        .filter(|index| (*index as usize) < handles.len())
        .ok_or_else(io::Error::last_os_error)? as usize;

    let mut written = 0;
    events[written] = WaitEvent::new(
        sources[first_index].interest,
        sources[first_index].source.token,
    );
    written += 1;

    for index in 0..handles.len() {
        if index == first_index || written == events.len() {
            continue;
        }

        let result = unsafe { WaitForSingleObject(handles[index], 0) };
        if result == WAIT_OBJECT_0 {
            events[written] = WaitEvent::new(sources[index].interest, sources[index].source.token);
            written += 1;
        } else if result == WAIT_FAILED {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(written)
}

#[cfg(unix)]
fn validate_source(source: &EventSource) -> io::Result<()> {
    match source.raw {
        RawEventSource::Fd(fd) if fd < 0 => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "event source file descriptor is invalid",
        )),
        RawEventSource::Fd(_) => Ok(()),
    }
}

#[cfg(windows)]
fn validate_source(source: &EventSource) -> io::Result<()> {
    match source.raw {
        RawEventSource::WaitableHandle(handle) if handle.is_null() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "event source waitable handle is null",
        )),
        RawEventSource::WaitableHandle(_) => Ok(()),
        RawEventSource::CompletionHandle(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "IOCP completion sources require the completion backend",
        )),
    }
}

#[cfg(unix)]
fn event_set_to_poll_events(events: EventSet) -> libc::c_short {
    let mut poll_events = 0;

    if events.contains(EventSet::IN) {
        poll_events |= libc::POLLIN;
    }
    if events.contains(EventSet::OUT) {
        poll_events |= libc::POLLOUT;
    }

    poll_events
}

#[cfg(unix)]
fn poll_events_to_event_set(events: libc::c_short) -> EventSet {
    let mut event_set = EventSet::empty();

    if events & libc::POLLIN != 0 {
        event_set |= EventSet::IN;
    }
    if events & libc::POLLOUT != 0 {
        event_set |= EventSet::OUT;
    }
    if events & libc::POLLERR != 0 {
        event_set |= EventSet::ERROR;
    }
    if events & libc::POLLHUP != 0 {
        event_set |= EventSet::HANG_UP;
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if events & libc::POLLRDHUP != 0 {
        event_set |= EventSet::READ_HANG_UP;
    }

    event_set
}

#[cfg(unix)]
fn new_event_notifier() -> io::Result<EventNotifier> {
    Ok(EventNotifier {
        eventfd: EventFd::new(EFD_NONBLOCK)?,
    })
}

#[cfg(windows)]
fn new_event_notifier() -> io::Result<EventNotifier> {
    let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };

    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }

    Ok(EventNotifier { handle })
}

#[cfg(unix)]
fn wake_event_notifier(notifier: &EventNotifier) -> io::Result<()> {
    match notifier.eventfd.write(1) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(windows)]
fn wake_event_notifier(notifier: &EventNotifier) -> io::Result<()> {
    if unsafe { SetEvent(notifier.handle) } == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(unix)]
fn drain_event_notifier(notifier: &EventNotifier) -> io::Result<()> {
    loop {
        match notifier.eventfd.read() {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(err) => return Err(err),
        }
    }
}

#[cfg(windows)]
fn drain_event_notifier(notifier: &EventNotifier) -> io::Result<()> {
    if unsafe { ResetEvent(notifier.handle) } == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(unix)]
fn event_notifier_source(notifier: &EventNotifier, token: EventToken) -> EventSource {
    EventSource::fd(notifier.eventfd.as_raw_fd(), token)
}

#[cfg(windows)]
fn event_notifier_source(notifier: &EventNotifier, token: EventToken) -> EventSource {
    EventSource::waitable_handle(notifier.handle as RawHandle, token)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    const TOKEN_A: EventToken = 11;
    const TOKEN_B: EventToken = 22;

    #[test]
    fn wait_times_out() {
        let notifier = EventNotifier::new().unwrap();
        let mut context = WaitContext::new();
        context
            .add(notifier.event_source(TOKEN_A), EventSet::IN)
            .unwrap();

        let started = Instant::now();
        let mut events = [WaitEvent::default(); 1];
        let count = context.wait(25, &mut events).unwrap();

        assert_eq!(count, 0);
        assert!(started.elapsed() >= Duration::from_millis(10));
    }

    #[test]
    fn wake_dispatches_token() {
        let notifier = EventNotifier::new().unwrap();
        let mut context = WaitContext::new();
        context
            .add(notifier.event_source(TOKEN_A), EventSet::IN)
            .unwrap();

        notifier.wake().unwrap();

        let mut events = [WaitEvent::default(); 1];
        let count = context.wait(100, &mut events).unwrap();

        assert_eq!(count, 1);
        assert_eq!(events[0].token(), TOKEN_A);
        assert!(events[0].events().contains(EventSet::IN));
    }

    #[test]
    fn two_sources_are_distinguished_by_token() {
        let notifier_a = EventNotifier::new().unwrap();
        let notifier_b = EventNotifier::new().unwrap();
        let mut context = WaitContext::new();
        context
            .add(notifier_a.event_source(TOKEN_A), EventSet::IN)
            .unwrap();
        context
            .add(notifier_b.event_source(TOKEN_B), EventSet::IN)
            .unwrap();

        notifier_b.wake().unwrap();

        let mut events = [WaitEvent::default(); 2];
        let count = context.wait(100, &mut events).unwrap();

        assert_eq!(count, 1);
        assert_eq!(events[0].token(), TOKEN_B);
    }

    #[test]
    fn drain_quiets_source() {
        let notifier = EventNotifier::new().unwrap();
        let mut context = WaitContext::new();
        context
            .add(notifier.event_source(TOKEN_A), EventSet::IN)
            .unwrap();

        notifier.wake().unwrap();
        notifier.drain().unwrap();

        let mut events = [WaitEvent::default(); 1];
        let count = context.wait(25, &mut events).unwrap();

        assert_eq!(count, 0);
    }

    #[test]
    fn repeated_wakes_coalesce_until_drain() {
        let notifier = EventNotifier::new().unwrap();
        let mut context = WaitContext::new();
        context
            .add(notifier.event_source(TOKEN_A), EventSet::IN)
            .unwrap();

        notifier.wake().unwrap();
        notifier.wake().unwrap();
        notifier.wake().unwrap();

        let mut events = [WaitEvent::default(); 1];
        let count = context.wait(100, &mut events).unwrap();

        assert_eq!(count, 1);
        assert_eq!(events[0].token(), TOKEN_A);

        notifier.drain().unwrap();
        let count = context.wait(25, &mut events).unwrap();

        assert_eq!(count, 0);
    }

    #[test]
    fn wake_from_another_thread_unblocks_wait() {
        let notifier = Arc::new(EventNotifier::new().unwrap());
        let mut context = WaitContext::new();
        context
            .add(notifier.event_source(TOKEN_A), EventSet::IN)
            .unwrap();

        let notifier_for_thread = notifier.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(25));
            notifier_for_thread.wake().unwrap();
        });

        let mut events = [WaitEvent::default(); 1];
        let count = context.wait(1000, &mut events).unwrap();

        assert_eq!(count, 1);
        assert_eq!(events[0].token(), TOKEN_A);
    }

    #[test]
    fn duplicate_tokens_are_rejected() {
        let notifier_a = EventNotifier::new().unwrap();
        let notifier_b = EventNotifier::new().unwrap();
        let mut context = WaitContext::new();
        context
            .add(notifier_a.event_source(TOKEN_A), EventSet::IN)
            .unwrap();

        let err = context
            .add(notifier_b.event_source(TOKEN_A), EventSet::IN)
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[cfg(unix)]
    #[test]
    fn invalid_fd_sources_are_rejected() {
        let mut context = WaitContext::new();
        let err = context
            .add(EventSource::fd(-1, TOKEN_A), EventSet::IN)
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(windows)]
    #[test]
    fn completion_sources_wait_for_iocp_backend() {
        let mut context = WaitContext::new();
        let handle = 1usize as RawHandle;
        let err = context
            .add(
                EventSource::completion_handle(handle, TOKEN_A),
                EventSet::IN,
            )
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
