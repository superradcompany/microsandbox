#[cfg(any(target_os = "macos", target_os = "windows"))]
use crossbeam_channel::Sender;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use utils::worker_message::WorkerMessage;

#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::sync::atomic::AtomicI32;
use std::sync::Arc;
use std::thread;

use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

use super::super::{FsError, Queue};
use super::defs::{HPQ_INDEX, REQ_INDEX};
use super::descriptor_utils::{Reader, Writer};
use super::filesystem::FileSystem;
use super::server::Server;
use crate::virtio::{InterruptTransport, VirtioShmRegion};

#[cfg(unix)]
type Pollable = RawFd;
#[cfg(windows)]
type Pollable = RawHandle;

const HPQ_EVENT: u64 = 0;
const REQ_EVENT: u64 = 1;
const STOP_EVENT: u64 = 2;

pub struct FsWorker<F: FileSystem + Sync + 'static> {
    queues: Vec<Queue>,
    queue_evts: Vec<Arc<EventFd>>,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    shm_region: Option<VirtioShmRegion>,
    server: Server<F>,
    stop_fd: EventFd,
    exit_code: Arc<AtomicI32>,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    map_sender: Option<Sender<WorkerMessage>>,
}

impl<F: FileSystem + Sync + Send + 'static> FsWorker<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fs: F,
        queues: Vec<Queue>,
        queue_evts: Vec<Arc<EventFd>>,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        shm_region: Option<VirtioShmRegion>,
        stop_fd: EventFd,
        exit_code: Arc<AtomicI32>,
        #[cfg(any(target_os = "macos", target_os = "windows"))] map_sender: Option<
            Sender<WorkerMessage>,
        >,
    ) -> Self {
        Self {
            queues,
            queue_evts,
            interrupt,
            mem,
            shm_region,
            server: Server::new(fs),
            stop_fd,
            exit_code,
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            map_sender,
        }
    }

    pub fn run(self) -> thread::JoinHandle<()> {
        thread::Builder::new()
            .name("fs worker".into())
            .spawn(|| self.work())
            .unwrap()
    }

    fn work(mut self) {
        let virtq_hpq_ev = eventfd_pollable(&self.queue_evts[HPQ_INDEX]);
        let virtq_req_ev = eventfd_pollable(&self.queue_evts[REQ_INDEX]);
        let stop_ev = eventfd_pollable(&self.stop_fd);

        let epoll = Epoll::new().unwrap();

        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_hpq_ev,
            &EpollEvent::new(EventSet::IN, HPQ_EVENT),
        );
        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_req_ev,
            &EpollEvent::new(EventSet::IN, REQ_EVENT),
        );
        let _ = epoll.ctl(
            ControlOperation::Add,
            stop_ev,
            &EpollEvent::new(EventSet::IN, STOP_EVENT),
        );

        loop {
            let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.data();
                        let event_set = event.event_set();
                        match source {
                            HPQ_EVENT if event_set.contains(EventSet::IN) => {
                                self.handle_event(HPQ_INDEX);
                            }
                            REQ_EVENT if event_set.contains(EventSet::IN) => {
                                self.handle_event(REQ_INDEX);
                            }
                            STOP_EVENT if event_set.contains(EventSet::IN) => {
                                debug!("stopping worker thread");
                                let _ = self.stop_fd.read();
                                return;
                            }
                            _ => {
                                log::warn!(
                                    "Received unknown event: {event_set:?} from fd: {source:?}"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("failed to consume muxer epoll event: {e}");
                }
            }
        }
    }

    fn handle_event(&mut self, queue_index: usize) {
        debug!("Fs: queue event: {queue_index}");
        if let Err(e) = self.queue_evts[queue_index].read() {
            error!("Failed to get queue event: {e:?}");
        }

        loop {
            self.queues[queue_index]
                .disable_notification(&self.mem)
                .unwrap();

            self.process_queue(queue_index);

            if !self.queues[queue_index]
                .enable_notification(&self.mem)
                .unwrap()
            {
                break;
            }
        }
    }

    fn process_queue(&mut self, queue_index: usize) {
        let queue = &mut self.queues[queue_index];
        while let Some(head) = queue.pop(&self.mem) {
            let reader = Reader::new(&self.mem, head.clone())
                .map_err(FsError::QueueReader)
                .unwrap();
            let writer = Writer::new(&self.mem, head.clone())
                .map_err(FsError::QueueWriter)
                .unwrap();

            if let Err(e) = self.server.handle_message(
                reader,
                writer,
                &self.shm_region,
                &self.exit_code,
                #[cfg(any(target_os = "macos", target_os = "windows"))]
                &self.map_sender,
            ) {
                error!("error handling message: {e:?}");
            }

            if let Err(e) = queue.add_used(&self.mem, head.index, 0) {
                error!("failed to add used elements to the queue: {e:?}");
            }

            if queue.needs_notification(&self.mem).unwrap() {
                self.interrupt.signal_used_queue();
            }
        }
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
