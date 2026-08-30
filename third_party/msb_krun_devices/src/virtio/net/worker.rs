use crate::virtio::net::backend::ConnectError;
#[cfg(windows)]
use crate::virtio::net::namedpipe::NamedPipe;
#[cfg(target_os = "linux")]
use crate::virtio::net::tap::Tap;
#[cfg(unix)]
use crate::virtio::net::unixgram::Unixgram;
#[cfg(unix)]
use crate::virtio::net::unixstream::Unixstream;
use crate::virtio::net::{MAX_BUFFER_SIZE, QUEUE_SIZE};
use crate::virtio::{DeviceQueue, InterruptTransport};

use super::backend::{NetBackend, ReadError, WriteError};
use super::device::{FrontendError, RxError, TxError, VirtioNetBackend};
use super::rate_limit::{RateLimiter, RateLimiters};
use super::vnet_hdr_len;

use std::io;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::thread;
use std::time::{Duration, Instant};
use std::{cmp, result};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::event::{EventSource, RawEventSource};
use utils::eventfd::EventFd;
use utils::timerfd::TimerFd;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

#[cfg(unix)]
type Pollable = std::os::fd::RawFd;
#[cfg(windows)]
type Pollable = RawHandle;

const RX_QUEUE_EVENT: u64 = 0;
const TX_QUEUE_EVENT: u64 = 1;
const BACKEND_EVENT: u64 = 2;
const RATE_LIMIT_TIMER_EVENT: u64 = 3;

pub struct NetWorker {
    rx_q: DeviceQueue,
    tx_q: DeviceQueue,
    interrupt: InterruptTransport,

    mem: GuestMemoryMmap,
    backend: Box<dyn NetBackend + Send>,

    rx_frame_buf: [u8; MAX_BUFFER_SIZE],
    rx_frame_buf_len: usize,
    rx_has_deferred_frame: bool,
    rx_has_rate_limit_permit: bool,
    rx_rate_limiter: Option<RateLimiter>,
    rx_resume_at: Option<Instant>,

    tx_iovec: Vec<(GuestAddress, usize)>,
    tx_frame_buf: [u8; MAX_BUFFER_SIZE],
    tx_frame_len: usize,
    tx_has_rate_limit_permit: bool,
    tx_rate_limiter: Option<RateLimiter>,
    tx_resume_at: Option<Instant>,

    rate_limit_timer: Option<TimerFd>,
    armed_rate_limit_deadline: Option<Instant>,
}

impl NetWorker {
    pub fn new(
        rx_q: DeviceQueue,
        tx_q: DeviceQueue,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        _vnet_features: u64,
        cfg_backend: VirtioNetBackend,
        rate_limiters: &RateLimiters,
    ) -> Result<Self, ConnectError> {
        let backend = match cfg_backend {
            #[cfg(unix)]
            VirtioNetBackend::UnixstreamFd(fd) => {
                // SAFETY: we need to trust that the library user has configured
                // the backend with a healthy file descriptor.
                let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Box::new(Unixstream::new(owned_fd)) as Box<dyn NetBackend + Send>
            }
            #[cfg(unix)]
            VirtioNetBackend::UnixstreamPath(path) => {
                Box::new(Unixstream::open(path)?) as Box<dyn NetBackend + Send>
            }
            #[cfg(unix)]
            VirtioNetBackend::UnixgramFd(fd) => {
                // SAFETY: we need to trust that the library user has configured
                // the backend with a healthy file descriptor.
                let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Box::new(Unixgram::new(owned_fd)) as Box<dyn NetBackend + Send>
            }
            #[cfg(unix)]
            VirtioNetBackend::UnixgramPath(path, vfkit_magic) => {
                Box::new(Unixgram::open(path, vfkit_magic)?) as Box<dyn NetBackend + Send>
            }
            #[cfg(target_os = "linux")]
            VirtioNetBackend::Tap(tap_name) => {
                Box::new(Tap::new(tap_name, _vnet_features)?) as Box<dyn NetBackend + Send>
            }
            #[cfg(windows)]
            VirtioNetBackend::NamedPipe(name) => {
                Box::new(NamedPipe::open(name)?) as Box<dyn NetBackend + Send>
            }
            VirtioNetBackend::Custom(backend) => backend,
        };

        let now = Instant::now();
        let rx_rate_limiter = rate_limiters
            .rx
            .as_ref()
            .map(|config| RateLimiter::new(config, now).expect("validated RX rate limiter"));
        let tx_rate_limiter = rate_limiters
            .tx
            .as_ref()
            .map(|config| RateLimiter::new(config, now).expect("validated TX rate limiter"));
        let rate_limit_timer = if rate_limiters.is_empty() {
            None
        } else {
            Some(TimerFd::new().map_err(ConnectError::RateLimitTimer)?)
        };

        Ok(Self {
            rx_q,
            tx_q,

            mem,
            backend,
            interrupt,

            rx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            rx_frame_buf_len: 0,
            rx_has_deferred_frame: false,
            rx_has_rate_limit_permit: false,
            rx_rate_limiter,
            rx_resume_at: None,

            tx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            tx_frame_len: 0,
            tx_iovec: Vec::with_capacity(QUEUE_SIZE as usize),
            tx_has_rate_limit_permit: false,
            tx_rate_limiter,
            tx_resume_at: None,

            rate_limit_timer,
            armed_rate_limit_deadline: None,
        })
    }

    pub fn run(self) {
        thread::Builder::new()
            .name("virtio-net worker".into())
            .spawn(|| self.work())
            .unwrap();
    }

    fn work(mut self) {
        let virtq_rx_ev = eventfd_pollable(&self.rx_q.event);
        let virtq_tx_ev = eventfd_pollable(&self.tx_q.event);
        let backend_source = self.backend.event_source(BACKEND_EVENT);
        let backend_pollable = match event_source_pollable(backend_source) {
            Ok(pollable) => pollable,
            Err(err) => {
                log::error!("virtio-net backend event source is unsupported: {err}");
                return;
            }
        };

        let epoll = Epoll::new().unwrap();

        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_rx_ev,
            &EpollEvent::new(EventSet::IN, RX_QUEUE_EVENT),
        );
        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_tx_ev,
            &EpollEvent::new(EventSet::IN, TX_QUEUE_EVENT),
        );
        let _ = epoll.ctl(
            ControlOperation::Add,
            backend_pollable,
            &EpollEvent::new(
                EventSet::IN | EventSet::OUT | EventSet::EDGE_TRIGGERED | EventSet::READ_HANG_UP,
                BACKEND_EVENT,
            ),
        );
        if let Some(timer) = &self.rate_limit_timer {
            let _ = epoll.ctl(
                ControlOperation::Add,
                timerfd_pollable(timer),
                &EpollEvent::new(EventSet::IN, RATE_LIMIT_TIMER_EVENT),
            );
        }

        loop {
            let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.data();
                        let event_set = event.event_set();
                        match source {
                            RX_QUEUE_EVENT if event_set.contains(EventSet::IN) => {
                                self.process_rx_queue_event();
                            }
                            TX_QUEUE_EVENT if event_set.contains(EventSet::IN) => {
                                self.process_tx_queue_event();
                            }
                            BACKEND_EVENT => {
                                if event_set.contains(EventSet::HANG_UP)
                                    || event_set.contains(EventSet::READ_HANG_UP)
                                {
                                    log::error!("Got {event_set:?} on backend fd, virtio-net will stop working");
                                    eprintln!("LIBKRUN VIRTIO-NET FATAL: Backend process seems to have quit or crashed! Networking is now disabled!");
                                } else {
                                    if event_set.contains(EventSet::IN) {
                                        self.process_backend_socket_readable()
                                    }

                                    if event_set.contains(EventSet::OUT) {
                                        self.process_backend_socket_writeable()
                                    }
                                }
                            }
                            RATE_LIMIT_TIMER_EVENT if event_set.contains(EventSet::IN) => {
                                self.process_rate_limit_timer_event();
                            }
                            _ => {
                                log::warn!(
                                    "Received unknown virtio-net event: {event_set:?} token={source}"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("vsock: failed to consume muxer epoll event: {e}");
                }
            }
        }
    }

    pub(crate) fn process_rx_queue_event(&mut self) {
        if let Err(e) = self.rx_q.event.read() {
            log::error!("Failed to get rx event from queue: {e:?}");
        }
        if let Err(e) = self.rx_q.queue.disable_notification(&self.mem) {
            error!("error disabling queue notifications: {e:?}");
        }
        if let Err(e) = self.process_rx() {
            log::error!("Failed to process rx: {e:?} (triggered by queue event)")
        };
        if let Err(e) = self.rx_q.queue.enable_notification(&self.mem) {
            error!("error disabling queue notifications: {e:?}");
        }
    }

    pub(crate) fn process_tx_queue_event(&mut self) {
        match self.tx_q.event.read() {
            Ok(_) => {
                log::debug!("virtio-net tx queue event");
                self.process_tx_loop()
            }
            Err(e) => {
                log::error!("Failed to get tx queue event from queue: {e:?}");
            }
        }
    }

    pub(crate) fn process_backend_socket_readable(&mut self) {
        if let Err(e) = self.rx_q.queue.enable_notification(&self.mem) {
            error!("error disabling queue notifications: {e:?}");
        }
        if let Err(e) = self.process_rx() {
            log::error!("Failed to process rx: {e:?} (triggered by backend socket readable)");
        };
        if let Err(e) = self.rx_q.queue.disable_notification(&self.mem) {
            error!("error disabling queue notifications: {e:?}");
        }
    }

    pub(crate) fn process_backend_socket_writeable(&mut self) {
        match self
            .backend
            .try_finish_write(vnet_hdr_len(), &self.tx_frame_buf[..self.tx_frame_len])
        {
            Ok(()) => self.process_tx_loop(),
            Err(WriteError::PartialWrite | WriteError::NothingWritten) => {}
            Err(e @ WriteError::Internal(_)) => {
                log::error!("Failed to finish write: {e:?}");
            }
            Err(e @ WriteError::ProcessNotRunning) => {
                log::debug!("Failed to finish write: {e:?}");
            }
        }
    }

    fn process_rx(&mut self) -> result::Result<(), RxError> {
        let now = self.rx_rate_limiter.as_ref().map(|_| Instant::now());
        self.process_rx_at(now)
    }

    fn process_rx_at(&mut self, now: Option<Instant>) -> result::Result<(), RxError> {
        let mut signal_queue = false;

        // if we have a deferred frame we try to process it first,
        // if that is not possible, we don't continue processing other frames
        if self.rx_has_deferred_frame {
            if let Some(now) = now {
                if !self.reserve_rx_tokens(now) {
                    return Ok(());
                }
            }
            if self.write_frame_to_guest() {
                self.rx_has_deferred_frame = false;
                if now.is_some() {
                    self.rx_has_rate_limit_permit = false;
                }
                signal_queue = true;
            } else {
                return Ok(());
            }
        }

        // Read as many frames as possible.
        let result = loop {
            match self.read_into_rx_frame_buf_from_backend() {
                Ok(()) => {
                    if let Some(now) = now {
                        if !self.reserve_rx_tokens(now) {
                            self.rx_has_deferred_frame = true;
                            break Ok(());
                        }
                    }
                    if self.write_frame_to_guest() {
                        if now.is_some() {
                            self.rx_has_rate_limit_permit = false;
                        }
                        signal_queue = true;
                    } else {
                        self.rx_has_deferred_frame = true;
                        break Ok(());
                    }
                }
                Err(ReadError::NothingRead) => break Ok(()),
                Err(e @ ReadError::Internal(_)) => break Err(RxError::Backend(e)),
            }
        };

        // At this point we processed as many Rx frames as possible.
        // We have to wake the guest if at least one descriptor chain has been used.
        if signal_queue {
            self.interrupt
                .try_signal_used_queue()
                .map_err(RxError::DeviceError)?;
        }

        result
    }

    fn reserve_rx_tokens(&mut self, now: Instant) -> bool {
        if self.rx_has_rate_limit_permit {
            return true;
        }

        let frame_len = self.rx_frame_buf_len.saturating_sub(vnet_hdr_len()) as u64;
        if let Some(limiter) = &mut self.rx_rate_limiter {
            match limiter.try_consume_frame(frame_len, now) {
                Ok(()) => {}
                Err(deadline) => {
                    self.rx_resume_at = Some(deadline);
                    self.arm_rate_limit_timer(now);
                    return false;
                }
            }
        }

        self.rx_has_rate_limit_permit = true;
        if self.rx_resume_at.take().is_some() {
            self.arm_rate_limit_timer(now);
        }
        true
    }

    fn process_tx_loop(&mut self) {
        loop {
            self.tx_q.queue.disable_notification(&self.mem).unwrap();

            if let Err(e) = self.process_tx() {
                log::error!("Failed to process rx: {e:?} (triggered by backend socket readable)");
            };

            let rate_limited = self.tx_resume_at.is_some();
            if !self.tx_q.queue.enable_notification(&self.mem).unwrap() || rate_limited {
                break;
            }
        }
    }

    fn process_tx(&mut self) -> result::Result<(), TxError> {
        let now = self.tx_rate_limiter.as_ref().map(|_| Instant::now());
        self.process_tx_at(now)
    }

    fn process_tx_at(&mut self, now: Option<Instant>) -> result::Result<(), TxError> {
        let tx_queue = &mut self.tx_q.queue;

        if self.backend.has_unfinished_write()
            && self
                .backend
                .try_finish_write(vnet_hdr_len(), &self.tx_frame_buf[..self.tx_frame_len])
                .is_err()
        {
            log::trace!("Cannot process tx because of unfinished partial write!");
            return Ok(());
        }

        let mut raise_irq = false;
        let mut rate_limit_changed = false;

        while let Some(head) = tx_queue.pop(&self.mem) {
            let head_index = head.index;
            let mut next_desc = Some(head);

            self.tx_iovec.clear();
            while let Some(desc) = next_desc {
                if desc.is_write_only() {
                    self.tx_iovec.clear();
                    break;
                }
                self.tx_iovec.push((desc.addr, desc.len as usize));
                next_desc = desc.next_descriptor();
            }

            // Copy buffer from across multiple descriptors.
            let mut read_count = 0;
            for (desc_addr, desc_len) in self.tx_iovec.drain(..) {
                let limit = cmp::min(read_count + desc_len, self.tx_frame_buf.len());

                let read_result = self
                    .mem
                    .read_slice(&mut self.tx_frame_buf[read_count..limit], desc_addr);
                match read_result {
                    Ok(()) => {
                        read_count += limit - read_count;
                    }
                    Err(e) => {
                        log::error!("Failed to read slice: {e:?}");
                        read_count = 0;
                        break;
                    }
                }
            }

            self.tx_frame_len = read_count;
            log::debug!("virtio-net tx descriptor: head={head_index}, bytes={read_count}");

            if let Some(now) = now {
                if !self.tx_has_rate_limit_permit {
                    let frame_len = read_count.saturating_sub(vnet_hdr_len()) as u64;
                    let limiter = self
                        .tx_rate_limiter
                        .as_mut()
                        .expect("timestamp requires a TX rate limiter");
                    if let Err(deadline) = limiter.try_consume_frame(frame_len, now) {
                        self.tx_resume_at = Some(deadline);
                        rate_limit_changed = true;
                        tx_queue.undo_pop();
                        break;
                    }
                    self.tx_has_rate_limit_permit = true;
                    rate_limit_changed |= self.tx_resume_at.take().is_some();
                }
            }

            match self
                .backend
                .write_frame(vnet_hdr_len(), &mut self.tx_frame_buf[..read_count])
            {
                Ok(()) => {
                    if now.is_some() {
                        self.tx_has_rate_limit_permit = false;
                    }
                    self.tx_frame_len = 0;
                    tx_queue
                        .add_used(&self.mem, head_index, 0)
                        .map_err(TxError::QueueError)?;
                    raise_irq = true;
                }
                Err(WriteError::NothingWritten) => {
                    tx_queue.undo_pop();
                    break;
                }
                Err(WriteError::PartialWrite) => {
                    if now.is_some() {
                        self.tx_has_rate_limit_permit = false;
                    }
                    log::trace!("process_tx: partial write");
                    /*
                    This situation should be pretty rare, assuming reasonably sized socket buffers.
                    We have written only a part of a frame to the backend socket (the socket is full).

                    The frame we have read from the guest remains in tx_frame_buf, and will be sent
                    later.

                    Note that we cannot wait for the backend to process our sending frames, because
                    the backend could be blocked on sending a remainder of a frame to us - us waiting
                    for backend would cause a deadlock.
                     */
                    tx_queue
                        .add_used(&self.mem, head_index, 0)
                        .map_err(TxError::QueueError)?;
                    raise_irq = true;
                    break;
                }
                Err(e @ WriteError::Internal(_) | e @ WriteError::ProcessNotRunning) => {
                    return Err(TxError::Backend(e))
                }
            }
        }

        if raise_irq && tx_queue.needs_notification(&self.mem).unwrap() {
            self.interrupt
                .try_signal_used_queue()
                .map_err(TxError::DeviceError)?;
        }

        if let (true, Some(now)) = (rate_limit_changed, now) {
            self.arm_rate_limit_timer(now);
        }

        Ok(())
    }

    fn process_rate_limit_timer_event(&mut self) {
        let Some(timer) = &self.rate_limit_timer else {
            return;
        };
        if let Err(err) = timer.read() {
            log::error!("failed to consume virtio-net rate-limit timer: {err}");
            return;
        }
        self.armed_rate_limit_deadline = None;

        let now = Instant::now();
        let retry_rx = self.rx_resume_at.is_some_and(|deadline| deadline <= now);
        let retry_tx = self.tx_resume_at.is_some_and(|deadline| deadline <= now);
        if retry_rx {
            self.rx_resume_at = None;
            if let Err(err) = self.process_rx_at(Some(now)) {
                log::error!("failed to process rate-limited RX frame: {err:?}");
            }
        }
        if retry_tx {
            self.tx_resume_at = None;
            self.process_tx_loop();
        }
        self.arm_rate_limit_timer(Instant::now());
    }

    fn arm_rate_limit_timer(&mut self, now: Instant) {
        let Some(timer) = &self.rate_limit_timer else {
            return;
        };
        let deadline = self.rx_resume_at.into_iter().chain(self.tx_resume_at).min();
        if deadline == self.armed_rate_limit_deadline {
            return;
        }
        let result = match deadline {
            Some(deadline) => timer.arm_oneshot(
                deadline
                    .saturating_duration_since(now)
                    .max(Duration::from_nanos(1)),
            ),
            None => timer.disarm(),
        };
        match result {
            Ok(()) => self.armed_rate_limit_deadline = deadline,
            Err(err) => log::error!("failed to arm virtio-net rate-limit timer: {err}"),
        }
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest.
    fn write_frame_to_guest_impl(&mut self) -> result::Result<(), FrontendError> {
        let mut result: std::result::Result<(), FrontendError> = Ok(());

        let queue = &mut self.rx_q.queue;
        let head_descriptor = queue.pop(&self.mem).ok_or(FrontendError::EmptyQueue)?;
        let head_index = head_descriptor.index;

        let mut frame_slice = &self.rx_frame_buf[..self.rx_frame_buf_len];

        let frame_len = frame_slice.len();
        let mut maybe_next_descriptor = Some(head_descriptor);
        while let Some(descriptor) = &maybe_next_descriptor {
            if frame_slice.is_empty() {
                break;
            }

            if !descriptor.is_write_only() {
                result = Err(FrontendError::ReadOnlyDescriptor);
                break;
            }

            let len = std::cmp::min(frame_slice.len(), descriptor.len as usize);
            match self.mem.write_slice(&frame_slice[..len], descriptor.addr) {
                Ok(()) => {
                    frame_slice = &frame_slice[len..];
                }
                Err(e) => {
                    log::error!("Failed to write slice: {e:?}");
                    result = Err(FrontendError::GuestMemory(e));
                    break;
                }
            };

            maybe_next_descriptor = descriptor.next_descriptor();
        }
        if result.is_ok() && !frame_slice.is_empty() {
            log::warn!("Receiving buffer is too small to hold frame of current size");
            result = Err(FrontendError::DescriptorChainTooSmall);
        }

        // Mark the descriptor chain as used. If an error occurred, skip the descriptor chain.
        let used_len = if result.is_err() { 0 } else { frame_len as u32 };
        queue
            .add_used(&self.mem, head_index, used_len)
            .map_err(FrontendError::QueueError)?;
        result
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest. In case of an error retries
    // the operation if possible. Returns true if the operation was successfull.
    fn write_frame_to_guest(&mut self) -> bool {
        let max_iterations = self.rx_q.queue.actual_size();
        for _ in 0..max_iterations {
            match self.write_frame_to_guest_impl() {
                Ok(()) => return true,
                Err(FrontendError::EmptyQueue) => {
                    // retry
                    continue;
                }
                Err(_) => {
                    // retry
                    continue;
                }
            }
        }

        false
    }

    /// Fills self.rx_frame_buf with an ethernet frame from backend and prepends virtio_net_hdr to it
    fn read_into_rx_frame_buf_from_backend(&mut self) -> result::Result<(), ReadError> {
        self.rx_frame_buf_len = self.backend.read_frame(&mut self.rx_frame_buf)?;
        Ok(())
    }
}

#[cfg(unix)]
fn eventfd_pollable(event: &EventFd) -> Pollable {
    event.as_raw_fd()
}

#[cfg(windows)]
fn eventfd_pollable(event: &EventFd) -> Pollable {
    event.as_raw_handle()
}

#[cfg(unix)]
fn timerfd_pollable(timer: &TimerFd) -> Pollable {
    timer.as_raw_fd()
}

#[cfg(windows)]
fn timerfd_pollable(timer: &TimerFd) -> Pollable {
    timer.as_raw_handle()
}

#[cfg(unix)]
fn event_source_pollable(source: EventSource) -> io::Result<Pollable> {
    match source.raw() {
        RawEventSource::Fd(fd) => Ok(fd),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::collections::VecDeque;
    use std::os::fd::{AsRawFd, RawFd};
    use std::sync::{Arc, Mutex};

    use crate::legacy::DummyIrqChip;
    use crate::virtio::net::rate_limit::{RateLimiterConfig, TokenBucketConfig};
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::queue::VIRTQ_DESC_F_WRITE;

    use super::*;

    const QUEUE_MEMORY_SIZE: usize = 0x1_0000;
    const RX_QUEUE_ADDR: GuestAddress = GuestAddress(0);
    const TX_QUEUE_ADDR: GuestAddress = GuestAddress(0x1000);
    const RX_BUFFER_ADDRS: [GuestAddress; 2] = [GuestAddress(0x4000), GuestAddress(0x5000)];
    const TX_BUFFER_ADDRS: [GuestAddress; 2] = [GuestAddress(0x6000), GuestAddress(0x7000)];
    const BUFFER_SIZE: u32 = 0x1000;
    const REFILL_TIME: Duration = Duration::from_millis(100);

    #[derive(Default)]
    struct BackendState {
        rx_frames: VecDeque<Vec<u8>>,
        tx_frames: Vec<Vec<u8>>,
        tx_attempts: usize,
        reject_next_tx: bool,
    }

    struct TestBackend {
        event: EventFd,
        state: Arc<Mutex<BackendState>>,
    }

    impl NetBackend for TestBackend {
        fn read_frame(&mut self, buf: &mut [u8]) -> result::Result<usize, ReadError> {
            let Some(frame) = self.state.lock().unwrap().rx_frames.pop_front() else {
                return Err(ReadError::NothingRead);
            };
            buf[..frame.len()].copy_from_slice(&frame);
            Ok(frame.len())
        }

        fn write_frame(
            &mut self,
            hdr_len: usize,
            buf: &mut [u8],
        ) -> result::Result<(), WriteError> {
            let mut state = self.state.lock().unwrap();
            state.tx_attempts += 1;
            if state.reject_next_tx {
                state.reject_next_tx = false;
                return Err(WriteError::NothingWritten);
            }
            state.tx_frames.push(buf[hdr_len..].to_vec());
            Ok(())
        }

        fn has_unfinished_write(&self) -> bool {
            false
        }

        fn try_finish_write(
            &mut self,
            _hdr_len: usize,
            _buf: &[u8],
        ) -> result::Result<(), WriteError> {
            Ok(())
        }

        fn raw_socket_fd(&self) -> RawFd {
            self.event.as_raw_fd()
        }
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0; vnet_hdr_len()];
        frame.extend_from_slice(payload);
        frame
    }

    fn ops_limiter() -> RateLimiterConfig {
        RateLimiterConfig {
            bandwidth: None,
            ops: Some(TokenBucketConfig {
                size: 1,
                refill_time: REFILL_TIME,
                one_time_burst: 0,
            }),
        }
    }

    fn device_queue(queue: crate::virtio::Queue) -> DeviceQueue {
        DeviceQueue::new(queue, Arc::new(EventFd::new(0).unwrap()))
    }

    fn worker(
        mem: GuestMemoryMmap,
        rx_q: DeviceQueue,
        tx_q: DeviceQueue,
        backend_state: Arc<Mutex<BackendState>>,
        rate_limiters: RateLimiters,
        now: Instant,
    ) -> NetWorker {
        let backend = TestBackend {
            event: EventFd::new(0).unwrap(),
            state: backend_state,
        };
        NetWorker {
            rx_q,
            tx_q,
            interrupt: InterruptTransport::new(DummyIrqChip::new().into(), "test-net".into())
                .unwrap(),
            mem,
            backend: Box::new(backend),
            rx_frame_buf: [0; MAX_BUFFER_SIZE],
            rx_frame_buf_len: 0,
            rx_has_deferred_frame: false,
            rx_has_rate_limit_permit: false,
            rx_rate_limiter: rate_limiters
                .rx
                .as_ref()
                .map(|config| RateLimiter::new(config, now).unwrap()),
            rx_resume_at: None,
            tx_iovec: Vec::with_capacity(QUEUE_SIZE as usize),
            tx_frame_buf: [0; MAX_BUFFER_SIZE],
            tx_frame_len: 0,
            tx_has_rate_limit_permit: false,
            tx_rate_limiter: rate_limiters
                .tx
                .as_ref()
                .map(|config| RateLimiter::new(config, now).unwrap()),
            tx_resume_at: None,
            rate_limit_timer: None,
            armed_rate_limit_deadline: None,
        }
    }

    #[test]
    fn tx_retries_backpressure_without_double_charging_and_resumes_at_deadline() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), QUEUE_MEMORY_SIZE)]).unwrap();
        let rx_vq = VirtQueue::new(RX_QUEUE_ADDR, &mem, 8);
        let tx_vq = VirtQueue::new(TX_QUEUE_ADDR, &mem, 8);
        let frames = [frame(b"first"), frame(b"second")];
        for (index, frame) in frames.iter().enumerate() {
            mem.write_slice(frame, TX_BUFFER_ADDRS[index]).unwrap();
            tx_vq.dtable[index].set(TX_BUFFER_ADDRS[index].0, frame.len() as u32, 0, 0);
            tx_vq.avail.ring[index].set(index as u16);
        }
        tx_vq.avail.idx.set(frames.len() as u16);

        let state = Arc::new(Mutex::new(BackendState {
            reject_next_tx: true,
            ..BackendState::default()
        }));
        let rx_q = device_queue(rx_vq.create_queue());
        let tx_q = device_queue(tx_vq.create_queue());
        let start = Instant::now();
        let mut worker = worker(
            mem.clone(),
            rx_q,
            tx_q,
            Arc::clone(&state),
            RateLimiters {
                rx: None,
                tx: Some(ops_limiter()),
            },
            start,
        );

        worker.process_tx_at(Some(start)).unwrap();
        assert_eq!(worker.tx_q.queue.next_used.0, 0);
        assert_eq!(state.lock().unwrap().tx_attempts, 1);

        worker.process_tx_at(Some(start)).unwrap();
        assert_eq!(worker.tx_q.queue.next_used.0, 1);
        assert_eq!(worker.tx_resume_at, Some(start + REFILL_TIME));
        {
            let state = state.lock().unwrap();
            assert_eq!(state.tx_attempts, 2);
            assert_eq!(state.tx_frames, [b"first".to_vec()]);
        }

        worker
            .process_tx_at(Some(start + REFILL_TIME - Duration::from_nanos(1)))
            .unwrap();
        assert_eq!(worker.tx_q.queue.next_used.0, 1);
        assert_eq!(state.lock().unwrap().tx_attempts, 2);

        worker.process_tx_at(Some(start + REFILL_TIME)).unwrap();
        assert_eq!(worker.tx_q.queue.next_used.0, 2);
        assert_eq!(worker.tx_resume_at, None);
        let state = state.lock().unwrap();
        assert_eq!(state.tx_attempts, 3);
        assert_eq!(state.tx_frames, [b"first".to_vec(), b"second".to_vec()]);
    }

    #[test]
    fn rx_preserves_deferred_frame_and_resumes_at_deadline() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), QUEUE_MEMORY_SIZE)]).unwrap();
        let rx_vq = VirtQueue::new(RX_QUEUE_ADDR, &mem, 8);
        let tx_vq = VirtQueue::new(TX_QUEUE_ADDR, &mem, 8);
        for (index, address) in RX_BUFFER_ADDRS.iter().enumerate() {
            rx_vq.dtable[index].set(address.0, BUFFER_SIZE, VIRTQ_DESC_F_WRITE, 0);
            rx_vq.avail.ring[index].set(index as u16);
        }
        rx_vq.avail.idx.set(RX_BUFFER_ADDRS.len() as u16);

        let frames = [frame(b"first"), frame(b"second")];
        let state = Arc::new(Mutex::new(BackendState {
            rx_frames: frames.iter().cloned().collect(),
            ..BackendState::default()
        }));
        let rx_q = device_queue(rx_vq.create_queue());
        let tx_q = device_queue(tx_vq.create_queue());
        let start = Instant::now();
        let mut worker = worker(
            mem.clone(),
            rx_q,
            tx_q,
            state,
            RateLimiters {
                rx: Some(ops_limiter()),
                tx: None,
            },
            start,
        );

        worker.process_rx_at(Some(start)).unwrap();
        assert_eq!(worker.rx_q.queue.next_used.0, 1);
        assert!(worker.rx_has_deferred_frame);
        assert_eq!(worker.rx_resume_at, Some(start + REFILL_TIME));

        worker
            .process_rx_at(Some(start + REFILL_TIME - Duration::from_nanos(1)))
            .unwrap();
        assert_eq!(worker.rx_q.queue.next_used.0, 1);
        assert!(worker.rx_has_deferred_frame);

        worker.process_rx_at(Some(start + REFILL_TIME)).unwrap();
        assert_eq!(worker.rx_q.queue.next_used.0, 2);
        assert!(!worker.rx_has_deferred_frame);
        assert_eq!(worker.rx_resume_at, None);
        for (index, expected) in frames.iter().enumerate() {
            let mut actual = vec![0; expected.len()];
            worker
                .mem
                .read_slice(&mut actual, RX_BUFFER_ADDRS[index])
                .unwrap();
            assert_eq!(&actual, expected);
        }
    }
}

#[cfg(windows)]
fn event_source_pollable(source: EventSource) -> io::Result<Pollable> {
    match source.raw() {
        RawEventSource::WaitableHandle(handle) => Ok(handle),
        RawEventSource::CompletionHandle(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "virtio-net does not support IOCP completion sources yet",
        )),
    }
}
