use crate::virtio::descriptor_utils::{Reader, Writer};

use super::super::DeviceQueue;
use super::device::{CacheType, DiskProperties};
#[cfg(windows)]
use super::windows::{
    PendingWindowsRawFileOperation, WindowsRawFileBuffer, WindowsRawFileCompletion,
};

#[cfg(windows)]
use crate::virtio::queue::DescriptorChain;
use crate::virtio::InterruptTransport;
#[cfg(windows)]
use std::collections::HashMap;
#[cfg(windows)]
use std::io::Read;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::result;
use std::thread;
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use utils::metrics::BlockMetricsWriter;
use virtio_bindings::virtio_blk::*;
#[cfg(windows)]
use vm_memory::{Address, GuestMemoryBackend};
use vm_memory::{ByteValued, GuestMemoryMmap};

#[cfg(unix)]
type Pollable = std::os::fd::RawFd;
#[cfg(windows)]
type Pollable = RawHandle;

const QUEUE_EVENT: u64 = 0;
const STOP_EVENT: u64 = 1;
#[cfg(windows)]
const MAX_PENDING_WINDOWS_RAW_REQUESTS: usize = 64;

#[allow(dead_code)]
#[derive(Debug)]
pub enum RequestError {
    Discarding(io::Error),
    DiscardingToZero(io::Error),
    FlushingToDisk(io::Error),
    InvalidDataLength,
    InvalidMutationRange(io::Error),
    ReadingFromDescriptor(io::Error),
    UnsupportedMutation,
    WritingToDescriptor(io::Error),
    WritingZeroes(io::Error),
    UnknownRequest,
}

/// The request header represents the mandatory fields of each block device request.
///
/// A request header contains the following fields:
///   * request_type: an u32 value mapping to a read, write or flush operation.
///   * reserved: 32 bits are reserved for future extensions of the Virtio Spec.
///   * sector: an u64 value representing the offset where a read/write is to occur.
///
/// The header simplifies reading the request from memory as all request follow
/// the same memory layout.
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct RequestHeader {
    request_type: u32,
    _reserved: u32,
    sector: u64,
}
// Safe because RequestHeader only contains plain data.
unsafe impl ByteValued for RequestHeader {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct DiscardWriteData {
    sector: u64,
    num_sectors: u32,
    flags: u32,
}
// Safe because DiscardWriteData only contains plain data.
unsafe impl ByteValued for DiscardWriteData {}

pub struct BlockWorker {
    device_queue: DeviceQueue,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    disk: DiskProperties,
    stop_fd: EventFd,
    metrics: BlockMetricsWriter,
}

#[cfg(windows)]
struct PendingWindowsBlockRequest {
    head_index: u16,
    mem: GuestMemoryMmap,
    direction: PendingWindowsBlockDirection,
    data_len: usize,
    operation: Option<PendingWindowsRawFileOperation>,
}

#[cfg(windows)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum PendingWindowsBlockDirection {
    Read,
    Write,
}

#[cfg(windows)]
enum WindowsRawSubmission {
    Submitted,
    Fallback,
}

impl BlockWorker {
    pub fn new(
        device_queue: DeviceQueue,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        disk: DiskProperties,
        stop_fd: EventFd,
        metrics: BlockMetricsWriter,
    ) -> Self {
        Self {
            device_queue,
            interrupt,
            mem,
            disk,
            stop_fd,
            metrics,
        }
    }

    pub fn run(self) -> thread::JoinHandle<()> {
        thread::Builder::new()
            .name("block worker".into())
            .spawn(|| self.work())
            .unwrap()
    }

    #[cfg(not(windows))]
    fn work(mut self) {
        let virtq_ev = eventfd_pollable(&self.device_queue.event);
        let stop_ev = eventfd_pollable(&self.stop_fd);

        let epoll = Epoll::new().unwrap();

        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_ev,
            &EpollEvent::new(EventSet::IN, QUEUE_EVENT),
        );

        let _ = epoll.ctl(
            ControlOperation::Add,
            stop_ev,
            &EpollEvent::new(EventSet::IN, STOP_EVENT),
        );

        let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        loop {
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.data();
                        let event_set = event.event_set();
                        match source {
                            QUEUE_EVENT if event_set.contains(EventSet::IN) => {
                                self.process_queue_event();
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

    #[cfg(windows)]
    fn work(mut self) {
        let virtq_ev = eventfd_pollable(&self.device_queue.event);
        let stop_ev = eventfd_pollable(&self.stop_fd);

        let epoll = Epoll::new().unwrap();

        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_ev,
            &EpollEvent::new(EventSet::IN, QUEUE_EVENT),
        );

        let _ = epoll.ctl(
            ControlOperation::Add,
            stop_ev,
            &EpollEvent::new(EventSet::IN, STOP_EVENT),
        );

        let mut pending_raw = HashMap::new();
        let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        loop {
            if !pending_raw.is_empty() {
                self.complete_one_windows_raw_request(&mut pending_raw);
                self.process_virtio_queues(&mut pending_raw);
                continue;
            }

            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.data();
                        let event_set = event.event_set();
                        match source {
                            QUEUE_EVENT if event_set.contains(EventSet::IN) => {
                                self.process_queue_event(&mut pending_raw);
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

    #[cfg(not(windows))]
    fn process_queue_event(&mut self) {
        if let Err(e) = self.device_queue.event.read() {
            error!("Failed to get queue event: {e:?}");
        } else {
            self.process_virtio_queues();
        }
    }

    #[cfg(windows)]
    fn process_queue_event(
        &mut self,
        pending_raw: &mut HashMap<usize, PendingWindowsBlockRequest>,
    ) {
        if let Err(e) = self.device_queue.event.read() {
            error!("Failed to get queue event: {e:?}");
        } else {
            self.process_virtio_queues(pending_raw);
        }
    }

    /// Process device virtio queue(s).
    #[cfg(not(windows))]
    fn process_virtio_queues(&mut self) {
        let mem = self.mem.clone();
        loop {
            self.device_queue.queue.disable_notification(&mem).unwrap();

            self.process_queue(&mem);

            if !self.device_queue.queue.enable_notification(&mem).unwrap() {
                break;
            }
        }
    }

    /// Process device virtio queue(s).
    #[cfg(windows)]
    fn process_virtio_queues(
        &mut self,
        pending_raw: &mut HashMap<usize, PendingWindowsBlockRequest>,
    ) {
        let mem = self.mem.clone();
        loop {
            self.device_queue.queue.disable_notification(&mem).unwrap();

            self.process_queue(&mem, pending_raw);

            let queue_needs_more_processing =
                self.device_queue.queue.enable_notification(&mem).unwrap();

            if pending_raw.len() >= MAX_PENDING_WINDOWS_RAW_REQUESTS {
                break;
            }

            if !queue_needs_more_processing {
                break;
            }
        }
    }

    #[cfg(not(windows))]
    fn process_queue(&mut self, mem: &GuestMemoryMmap) {
        while let Some(head) = self.device_queue.queue.pop(mem) {
            let mut reader = match Reader::new(mem, head.clone()) {
                Ok(r) => r,
                Err(e) => {
                    error!("invalid descriptor chain: {e:?}");
                    continue;
                }
            };
            let mut writer = match Writer::new(mem, head.clone()) {
                Ok(r) => r,
                Err(e) => {
                    error!("invalid descriptor chain: {e:?}");
                    continue;
                }
            };
            let request_header: RequestHeader = match reader.read_obj() {
                Ok(h) => h,
                Err(e) => {
                    error!("invalid request header: {e:?}");
                    continue;
                }
            };

            let (status, len): (u8, usize) =
                match self.process_request(request_header, &mut reader, &mut writer) {
                    Ok(l) => (VIRTIO_BLK_S_OK.try_into().unwrap(), l),
                    Err(e) => {
                        error!("error processing request: {e:?}");
                        (VIRTIO_BLK_S_IOERR.try_into().unwrap(), 0)
                    }
                };

            if let Err(e) = writer.write_obj(status) {
                error!("Failed to write virtio block status: {e:?}")
            }

            if let Err(e) = self
                .device_queue
                .queue
                .add_used(mem, head.index, len as u32)
            {
                error!("failed to add used elements to the queue: {e:?}");
            }

            if self.device_queue.queue.needs_notification(mem).unwrap() {
                if let Err(e) = self.interrupt.try_signal_used_queue() {
                    error!("error signalling queue: {e:?}");
                }
            }
        }
    }

    #[cfg(windows)]
    fn process_queue(
        &mut self,
        mem: &GuestMemoryMmap,
        pending_raw: &mut HashMap<usize, PendingWindowsBlockRequest>,
    ) {
        while pending_raw.len() < MAX_PENDING_WINDOWS_RAW_REQUESTS {
            let Some(head) = self.device_queue.queue.pop(mem) else {
                break;
            };

            let mut reader = match Reader::new(mem, head.clone()) {
                Ok(r) => r,
                Err(e) => {
                    error!("invalid descriptor chain: {e:?}");
                    continue;
                }
            };
            let mut writer = match Writer::new(mem, head.clone()) {
                Ok(r) => r,
                Err(e) => {
                    error!("invalid descriptor chain: {e:?}");
                    continue;
                }
            };
            let request_header: RequestHeader = match reader.read_obj() {
                Ok(h) => h,
                Err(e) => {
                    error!("invalid request header: {e:?}");
                    continue;
                }
            };

            match self.try_submit_windows_raw_request(
                mem,
                head.clone(),
                request_header,
                &mut reader,
                &mut writer,
                pending_raw,
            ) {
                Ok(WindowsRawSubmission::Submitted) => continue,
                Ok(WindowsRawSubmission::Fallback) => {}
                Err(e) => {
                    error!("error submitting raw Windows block request: {e:?}");
                    self.complete_sync_request(
                        mem,
                        head.index,
                        &mut writer,
                        VIRTIO_BLK_S_IOERR.try_into().unwrap(),
                        0,
                    );
                    continue;
                }
            }

            if !pending_raw.is_empty() {
                self.complete_all_windows_raw_requests(pending_raw);
            }

            let (status, len): (u8, usize) =
                match self.process_request(request_header, &mut reader, &mut writer) {
                    Ok(l) => (VIRTIO_BLK_S_OK.try_into().unwrap(), l),
                    Err(e) => {
                        error!("error processing request: {e:?}");
                        (VIRTIO_BLK_S_IOERR.try_into().unwrap(), 0)
                    }
                };

            self.complete_sync_request(mem, head.index, &mut writer, status, len);
        }
    }

    #[cfg(windows)]
    fn complete_sync_request(
        &mut self,
        mem: &GuestMemoryMmap,
        head_index: u16,
        writer: &mut Writer,
        status: u8,
        len: usize,
    ) {
        if let Err(e) = writer.write_obj(status) {
            error!("Failed to write virtio block status: {e:?}")
        }

        if let Err(e) = self
            .device_queue
            .queue
            .add_used(mem, head_index, len as u32)
        {
            error!("failed to add used elements to the queue: {e:?}");
        }

        if self.device_queue.queue.needs_notification(mem).unwrap() {
            if let Err(e) = self.interrupt.try_signal_used_queue() {
                error!("error signalling queue: {e:?}");
            }
        }
    }

    #[cfg(windows)]
    fn try_submit_windows_raw_request(
        &mut self,
        mem: &GuestMemoryMmap,
        head: DescriptorChain,
        request_header: RequestHeader,
        reader: &mut Reader,
        writer: &mut Writer,
        pending_raw: &mut HashMap<usize, PendingWindowsBlockRequest>,
    ) -> result::Result<WindowsRawSubmission, RequestError> {
        if !self.disk.has_windows_raw_file() {
            return Ok(WindowsRawSubmission::Fallback);
        }

        match request_header.request_type {
            VIRTIO_BLK_T_IN => {
                let data_len = writer
                    .available_bytes()
                    .checked_sub(1)
                    .ok_or(RequestError::InvalidDataLength)?;
                if data_len == 0 {
                    return Ok(WindowsRawSubmission::Fallback);
                }
                if !data_len.is_multiple_of(512) {
                    return Err(RequestError::InvalidDataLength);
                }

                let offset = sector_offset(request_header.sector)?;
                let segments = collect_windows_raw_buffers(mem, head.clone(), true, 0, data_len)
                    .map_err(RequestError::WritingToDescriptor)?;
                let (operation, _) =
                    self.submit_windows_raw_read_operation(offset, data_len, &segments)?;
                self.queue_windows_raw_request(
                    pending_raw,
                    head.index,
                    mem.clone(),
                    PendingWindowsBlockDirection::Read,
                    data_len,
                    operation,
                );
                Ok(WindowsRawSubmission::Submitted)
            }
            VIRTIO_BLK_T_OUT => {
                let data_len = reader.available_bytes();
                if data_len == 0 {
                    return Ok(WindowsRawSubmission::Fallback);
                }
                if !data_len.is_multiple_of(512) {
                    return Err(RequestError::InvalidDataLength);
                }

                let offset = sector_offset(request_header.sector)?;
                let segments = collect_windows_raw_buffers(
                    mem,
                    head.clone(),
                    false,
                    std::mem::size_of::<RequestHeader>(),
                    data_len,
                )
                .map_err(RequestError::ReadingFromDescriptor)?;
                let operation =
                    self.submit_windows_raw_write_operation(offset, data_len, reader, &segments)?;
                self.queue_windows_raw_request(
                    pending_raw,
                    head.index,
                    mem.clone(),
                    PendingWindowsBlockDirection::Write,
                    data_len,
                    operation,
                );
                Ok(WindowsRawSubmission::Submitted)
            }
            _ => Ok(WindowsRawSubmission::Fallback),
        }
    }

    #[cfg(windows)]
    fn submit_windows_raw_read_operation(
        &self,
        offset: u64,
        data_len: usize,
        segments: &[WindowsRawFileBuffer],
    ) -> result::Result<(PendingWindowsRawFileOperation, bool), RequestError> {
        if let Some(buffer) = single_direct_windows_raw_buffer(segments) {
            if self
                .disk
                .windows_raw_can_submit_direct_buffer(buffer, offset)
            {
                let operation = self
                    .disk
                    .submit_windows_raw_read_buffer(buffer, offset)
                    .expect("checked windows raw file presence")
                    .map_err(RequestError::WritingToDescriptor)?;
                return Ok((operation, false));
            }
        }

        log::debug!("using Windows raw block bounce buffer for fragmented or unaligned read");
        let operation = self
            .disk
            .submit_windows_raw_read_bounce(offset, data_len)
            .expect("checked windows raw file presence")
            .map_err(RequestError::WritingToDescriptor)?;
        Ok((operation, true))
    }

    #[cfg(windows)]
    fn submit_windows_raw_write_operation(
        &self,
        offset: u64,
        data_len: usize,
        reader: &mut Reader,
        segments: &[WindowsRawFileBuffer],
    ) -> result::Result<PendingWindowsRawFileOperation, RequestError> {
        if let Some(buffer) = single_direct_windows_raw_buffer(segments) {
            if self
                .disk
                .windows_raw_can_submit_direct_buffer(buffer, offset)
            {
                return self
                    .disk
                    .submit_windows_raw_write_buffer(buffer, offset)
                    .expect("checked windows raw file presence")
                    .map_err(RequestError::ReadingFromDescriptor);
            }
        }

        log::debug!("using Windows raw block bounce buffer for fragmented or unaligned write");
        let mut bounce = vec![0; data_len];
        reader
            .read_exact(&mut bounce)
            .map_err(RequestError::ReadingFromDescriptor)?;
        self.disk
            .submit_windows_raw_write_bounce(offset, bounce)
            .expect("checked windows raw file presence")
            .map_err(RequestError::ReadingFromDescriptor)
    }

    #[cfg(windows)]
    fn queue_windows_raw_request(
        &self,
        pending_raw: &mut HashMap<usize, PendingWindowsBlockRequest>,
        head_index: u16,
        mem: GuestMemoryMmap,
        direction: PendingWindowsBlockDirection,
        data_len: usize,
        operation: PendingWindowsRawFileOperation,
    ) {
        let key = operation.completion_key();
        pending_raw.insert(
            key,
            PendingWindowsBlockRequest {
                head_index,
                mem,
                direction,
                data_len,
                operation: Some(operation),
            },
        );
    }

    #[cfg(windows)]
    fn complete_one_windows_raw_request(
        &mut self,
        pending_raw: &mut HashMap<usize, PendingWindowsBlockRequest>,
    ) {
        let completion = match self.disk.wait_windows_raw_completion() {
            Some(Ok(completion)) => completion,
            Some(Err(e)) => {
                error!("error waiting for Windows raw block completion: {e:?}");
                return;
            }
            None => {
                error!("Windows raw completion requested without a raw file");
                return;
            }
        };

        let key = completion.key();
        let Some(request) = pending_raw.remove(&key) else {
            error!("received completion for unknown Windows raw block request: {key}");
            return;
        };

        self.complete_windows_raw_request(request, completion);
    }

    #[cfg(windows)]
    fn complete_all_windows_raw_requests(
        &mut self,
        pending_raw: &mut HashMap<usize, PendingWindowsBlockRequest>,
    ) {
        while !pending_raw.is_empty() {
            let pending_count = pending_raw.len();
            self.complete_one_windows_raw_request(pending_raw);
            if pending_raw.len() == pending_count {
                break;
            }
        }
    }

    #[cfg(windows)]
    fn complete_windows_raw_request(
        &mut self,
        mut request: PendingWindowsBlockRequest,
        completion: WindowsRawFileCompletion,
    ) {
        let operation = request
            .operation
            .take()
            .expect("pending Windows raw request must own an operation");
        let completed = match operation.complete(completion) {
            Ok(completed) => completed,
            Err(e) => {
                error!("error completing Windows raw block request: {e:?}");
                self.write_windows_raw_completion(
                    &request,
                    VIRTIO_BLK_S_IOERR.try_into().unwrap(),
                    None,
                    0,
                );
                return;
            }
        };

        let status = VIRTIO_BLK_S_OK.try_into().unwrap();
        let used_len = completed.bytes;
        let buffer = completed.buffer.as_deref();
        if self.write_windows_raw_completion(&request, status, buffer, used_len) {
            match request.direction {
                PendingWindowsBlockDirection::Read => self.metrics.add_read_bytes(used_len as u64),
                PendingWindowsBlockDirection::Write => {
                    self.metrics.add_write_bytes(used_len as u64)
                }
            }
        }
    }

    #[cfg(windows)]
    fn write_windows_raw_completion(
        &mut self,
        request: &PendingWindowsBlockRequest,
        mut status: u8,
        bounce_read: Option<&[u8]>,
        used_len: usize,
    ) -> bool {
        let write_result = match request.direction {
            PendingWindowsBlockDirection::Read => {
                self.write_windows_raw_read_completion(request, status, bounce_read)
            }
            PendingWindowsBlockDirection::Write => {
                self.write_windows_raw_write_completion(request, status)
            }
        };

        if let Err(e) = write_result {
            error!("failed to write Windows raw block completion status: {e:?}");
            status = VIRTIO_BLK_S_IOERR.try_into().unwrap();
            let _ = self.write_windows_raw_status_at_offset(request, status);
        }

        let len = if status == VIRTIO_BLK_S_OK.try_into().unwrap() {
            used_len
        } else {
            0
        };
        if let Err(e) =
            self.device_queue
                .queue
                .add_used(&request.mem, request.head_index, len as u32)
        {
            error!("failed to add used elements to the queue: {e:?}");
        }

        if self
            .device_queue
            .queue
            .needs_notification(&request.mem)
            .unwrap()
        {
            if let Err(e) = self.interrupt.try_signal_used_queue() {
                error!("error signalling queue: {e:?}");
            }
        }

        status == VIRTIO_BLK_S_OK.try_into().unwrap()
    }

    #[cfg(windows)]
    fn write_windows_raw_read_completion(
        &self,
        request: &PendingWindowsBlockRequest,
        status: u8,
        bounce_read: Option<&[u8]>,
    ) -> io::Result<()> {
        if let Some(buffer) = bounce_read {
            let mut writer = self.windows_raw_writer(request)?;
            writer.write_all(buffer)?;
            writer.write_obj(status)
        } else {
            self.write_windows_raw_status_at_offset(request, status)
        }
    }

    #[cfg(windows)]
    fn write_windows_raw_write_completion(
        &self,
        request: &PendingWindowsBlockRequest,
        status: u8,
    ) -> io::Result<()> {
        let mut writer = self.windows_raw_writer(request)?;
        writer.write_obj(status)
    }

    #[cfg(windows)]
    fn write_windows_raw_status_at_offset(
        &self,
        request: &PendingWindowsBlockRequest,
        status: u8,
    ) -> io::Result<()> {
        let mut writer = self.windows_raw_writer(request)?;
        let mut status_writer = writer
            .split_at(request.data_len)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        status_writer.write_obj(status)
    }

    #[cfg(windows)]
    fn windows_raw_writer<'a>(
        &self,
        request: &'a PendingWindowsBlockRequest,
    ) -> io::Result<Writer<'a>> {
        let chain = DescriptorChain::checked_new(
            &request.mem,
            self.device_queue.queue.desc_table,
            self.device_queue.queue.actual_size(),
            request.head_index,
        )
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid descriptor chain"))?;
        Writer::new(&request.mem, chain).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn process_request(
        &mut self,
        request_header: RequestHeader,
        reader: &mut Reader,
        writer: &mut Writer,
    ) -> result::Result<usize, RequestError> {
        match request_header.request_type {
            VIRTIO_BLK_T_IN => {
                let data_len = writer
                    .available_bytes()
                    .checked_sub(1)
                    .ok_or(RequestError::InvalidDataLength)?;
                if !data_len.is_multiple_of(512) {
                    Err(RequestError::InvalidDataLength)
                } else {
                    let offset = sector_offset(request_header.sector)?;
                    let len = writer
                        .write_from_at(&self.disk, data_len, offset)
                        .map_err(RequestError::WritingToDescriptor)?;
                    self.metrics.add_read_bytes(len as u64);
                    Ok(len)
                }
            }
            VIRTIO_BLK_T_OUT => {
                let data_len = reader.available_bytes();
                if !data_len.is_multiple_of(512) {
                    Err(RequestError::InvalidDataLength)
                } else {
                    let offset = sector_offset(request_header.sector)?;
                    // Validate the complete descriptor payload before allowing the first backing
                    // write. Bounded mode must never partially apply an out-of-capacity request.
                    self.disk
                        .validate_mutation_range(offset, data_len as u64)
                        .map_err(RequestError::InvalidMutationRange)?;
                    let len = reader
                        .read_to_at(&self.disk, data_len, offset)
                        .map_err(RequestError::ReadingFromDescriptor)?;
                    self.metrics.add_write_bytes(len as u64);
                    Ok(len)
                }
            }
            VIRTIO_BLK_T_FLUSH => match self.disk.cache_type() {
                CacheType::Writeback => {
                    self.disk
                        .flush_to_disk()
                        .map_err(RequestError::FlushingToDisk)?;
                    Ok(0)
                }
                CacheType::Unsafe => Ok(0),
            },
            VIRTIO_BLK_T_GET_ID => {
                let data_len = writer.available_bytes();
                let disk_id = self.disk.image_id();
                if data_len < disk_id.len() {
                    Err(RequestError::InvalidDataLength)
                } else {
                    writer
                        .write_all(disk_id)
                        .map_err(RequestError::WritingToDescriptor)?;
                    Ok(disk_id.len())
                }
            }
            VIRTIO_BLK_T_DISCARD => {
                if self.disk.has_writeback_limit() {
                    // Bounded writeback deliberately does not advertise DISCARD. Reject a guest
                    // that sends it anyway rather than admitting unaccounted metadata mutation.
                    return Err(RequestError::UnsupportedMutation);
                }
                let discard_write_data: DiscardWriteData = reader
                    .read_obj()
                    .map_err(RequestError::ReadingFromDescriptor)?;
                let offset = sector_offset(discard_write_data.sector)?;
                let length = sector_count_bytes(discard_write_data.num_sectors)?;
                self.disk
                    .validate_mutation_range(offset, length)
                    .map_err(RequestError::InvalidMutationRange)?;
                self.disk
                    .discard_to_any(offset, length)
                    .map_err(RequestError::Discarding)?;
                Ok(0)
            }
            VIRTIO_BLK_T_WRITE_ZEROES => {
                let discard_write_data: DiscardWriteData = reader
                    .read_obj()
                    .map_err(RequestError::ReadingFromDescriptor)?;
                let unmap = (discard_write_data.flags & VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP) != 0;
                if self.disk.has_writeback_limit() && unmap {
                    // The bounded device advertises write_zeroes_may_unmap=0. Fail closed if a
                    // non-conforming guest still requests a hole-punching zero operation.
                    return Err(RequestError::UnsupportedMutation);
                }
                let offset = sector_offset(discard_write_data.sector)?;
                let length = sector_count_bytes(discard_write_data.num_sectors)?;
                self.disk
                    .validate_mutation_range(offset, length)
                    .map_err(RequestError::InvalidMutationRange)?;
                if unmap {
                    self.disk
                        .discard_to_zero(offset, length)
                        .map_err(RequestError::DiscardingToZero)?;
                } else {
                    self.disk
                        .write_zeroes(offset, length)
                        .map_err(RequestError::WritingZeroes)?;
                }
                Ok(0)
            }
            _ => Err(RequestError::UnknownRequest),
        }
    }
}

#[cfg(windows)]
fn collect_windows_raw_buffers(
    mem: &GuestMemoryMmap,
    head: DescriptorChain,
    writable: bool,
    mut skip: usize,
    mut remaining: usize,
) -> io::Result<Vec<WindowsRawFileBuffer>> {
    let mut buffers = Vec::new();

    for desc in head.into_iter() {
        if desc.is_write_only() != writable {
            continue;
        }

        let mut addr = desc.addr;
        let mut len = desc.len as usize;
        if skip > 0 {
            let skipped = skip.min(len);
            addr = addr
                .checked_add(skipped as u64)
                .ok_or_else(|| io::Error::other("descriptor address overflow"))?;
            len -= skipped;
            skip -= skipped;
        }
        if len == 0 {
            continue;
        }

        let chunk_len = len.min(remaining);
        let slice = mem
            .get_slice(addr, chunk_len)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let ptr = if writable {
            slice.ptr_guard_mut().as_ptr()
        } else {
            slice.ptr_guard().as_ptr() as *mut u8
        };

        // SAFETY: `ptr` was validated through `GuestMemoryMmap::get_slice`.
        // The pending request keeps a cloned `GuestMemoryMmap` alive until IOCP
        // completion, and the descriptor is not returned to the guest before then.
        let buffer = unsafe { WindowsRawFileBuffer::new(ptr, chunk_len) };
        push_or_merge_windows_raw_buffer(&mut buffers, buffer);

        remaining -= chunk_len;
        if remaining == 0 {
            break;
        }
    }

    if remaining != 0 || skip != 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "descriptor chain does not contain enough raw block data",
        ));
    }

    Ok(buffers)
}

#[cfg(windows)]
fn push_or_merge_windows_raw_buffer(
    buffers: &mut Vec<WindowsRawFileBuffer>,
    buffer: WindowsRawFileBuffer,
) {
    if let Some(last) = buffers.last_mut() {
        let last_end = (last.as_mut_ptr() as usize).saturating_add(last.len());
        if last_end == buffer.as_mut_ptr() as usize {
            // SAFETY: both buffers came from adjacent validated guest-memory
            // ranges and remain covered by the pending request's memory guard.
            *last =
                unsafe { WindowsRawFileBuffer::new(last.as_mut_ptr(), last.len() + buffer.len()) };
            return;
        }
    }

    buffers.push(buffer);
}

#[cfg(windows)]
fn single_direct_windows_raw_buffer(
    buffers: &[WindowsRawFileBuffer],
) -> Option<WindowsRawFileBuffer> {
    match buffers {
        [buffer] => Some(*buffer),
        _ => None,
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

fn sector_offset(sector: u64) -> result::Result<u64, RequestError> {
    sector
        .checked_mul(512)
        .ok_or(RequestError::InvalidDataLength)
}

fn sector_count_bytes(sectors: u32) -> result::Result<u64, RequestError> {
    u64::from(sectors)
        .checked_mul(512)
        .ok_or(RequestError::InvalidDataLength)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sector_offset_rejects_overflow() {
        assert!(matches!(
            sector_offset(u64::MAX),
            Err(RequestError::InvalidDataLength)
        ));
    }

    #[test]
    fn sector_count_bytes_converts_to_bytes() {
        assert_eq!(sector_count_bytes(8).unwrap(), 4096);
    }
}
