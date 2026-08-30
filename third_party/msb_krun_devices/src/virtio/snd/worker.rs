use std::collections::BTreeSet;
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex, RwLock};
use std::{result, thread};

use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::{ByteValued, Bytes, GuestMemoryMmap};

use super::super::DeviceQueue;
use super::audio_backends::{alloc_audio_backend, AudioBackend};
use super::defs::{CTL_INDEX, EVT_INDEX, QUEUE_INDEXES, RXQ_INDEX, TXQ_INDEX};
use super::stream::{Error as StreamError, Stream};
use super::virtio_sound::{
    VirtioSndPcmSetParams, VirtioSoundHeader, VirtioSoundPcmHeader, VirtioSoundPcmInfo,
    VirtioSoundPcmStatus, VirtioSoundPcmXfer, VirtioSoundQueryInfo, VIRTIO_SND_D_INPUT,
    VIRTIO_SND_D_OUTPUT, VIRTIO_SND_S_BAD_MSG, VIRTIO_SND_S_IO_ERR, VIRTIO_SND_S_NOT_SUPP,
    VIRTIO_SND_S_OK,
};
use super::{
    BackendType, Direction, Error, VirtioSoundChmapInfo, VirtioSoundJackInfo, Vring,
    VIRTIO_SND_CHMAP_FL, VIRTIO_SND_CHMAP_FR, VIRTIO_SND_CHMAP_MAX_SIZE, VIRTIO_SND_CHMAP_NONE,
};
use crate::virtio::snd::stream::Buffer;
use crate::virtio::snd::{ControlMessageKind, IOMessage};
use crate::virtio::{DescriptorChain, InterruptTransport};

pub struct SndWorker {
    vrings: Vec<Arc<Mutex<Vring>>>,
    queue_events: Vec<Arc<EventFd>>,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    streams: Arc<RwLock<Vec<Stream>>>,
    streams_no: usize,
    chmaps: Arc<RwLock<Vec<VirtioSoundChmapInfo>>>,
    jacks: Arc<RwLock<Vec<VirtioSoundJackInfo>>>,
    audio_backend: RwLock<Box<dyn AudioBackend + Send + Sync>>,
    stop_fd: EventFd,
}

impl SndWorker {
    pub fn new(
        queues: Vec<DeviceQueue>,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        stop_fd: EventFd,
    ) -> Self {
        let streams = vec![
            Stream {
                id: 0,
                direction: Direction::Output,
                ..Stream::default()
            },
            Stream {
                id: 1,
                direction: Direction::Input,
                ..Stream::default()
            },
        ];
        let streams_no = streams.len();
        let streams = Arc::new(RwLock::new(streams));
        let jacks: Arc<RwLock<Vec<VirtioSoundJackInfo>>> = Arc::new(RwLock::new(Vec::new()));
        let mut positions = [VIRTIO_SND_CHMAP_NONE; VIRTIO_SND_CHMAP_MAX_SIZE];
        positions[0] = VIRTIO_SND_CHMAP_FL;
        positions[1] = VIRTIO_SND_CHMAP_FR;
        let chmaps_info: Vec<VirtioSoundChmapInfo> = vec![
            VirtioSoundChmapInfo {
                direction: VIRTIO_SND_D_OUTPUT,
                channels: 2,
                positions,
                ..VirtioSoundChmapInfo::default()
            },
            VirtioSoundChmapInfo {
                direction: VIRTIO_SND_D_INPUT,
                channels: 2,
                positions,
                ..VirtioSoundChmapInfo::default()
            },
        ];
        let chmaps: Arc<RwLock<Vec<VirtioSoundChmapInfo>>> = Arc::new(RwLock::new(chmaps_info));

        let audio_backend =
            RwLock::new(alloc_audio_backend(BackendType::Pipewire, streams.clone()).unwrap());

        let mut vrings: Vec<Arc<Mutex<Vring>>> = Vec::new();
        let mut queue_events: Vec<Arc<EventFd>> = Vec::new();

        for dq in queues {
            vrings.push(Arc::new(Mutex::new(Vring {
                mem: mem.clone(),
                queue: dq.queue,
                interrupt: interrupt.clone(),
            })));
            queue_events.push(dq.event);
        }

        Self {
            vrings,
            queue_events,
            interrupt,
            mem,
            streams,
            streams_no,
            jacks,
            chmaps,
            audio_backend,
            stop_fd,
        }
    }

    pub fn run(self) -> thread::JoinHandle<()> {
        thread::Builder::new()
            .name("virtio-snd worker".into())
            .spawn(|| self.work())
            .unwrap()
    }

    fn work(mut self) {
        let epoll = Epoll::new().unwrap();

        for idx in QUEUE_INDEXES {
            let fd = self.queue_events[idx].as_raw_fd();
            epoll
                .ctl(
                    ControlOperation::Add,
                    fd,
                    &EpollEvent::new(EventSet::IN, idx as u64),
                )
                .unwrap();
        }

        let stop_ev_fd = self.stop_fd.as_raw_fd();
        epoll
            .ctl(
                ControlOperation::Add,
                stop_ev_fd,
                &EpollEvent::new(EventSet::IN, stop_ev_fd as u64),
            )
            .unwrap();

        loop {
            let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.fd();
                        let data = event.data();
                        let event_set = event.event_set();
                        match event_set {
                            EventSet::IN if data < QUEUE_INDEXES.len() as u64 => {
                                self.handle_event(data.try_into().unwrap());
                            }
                            EventSet::IN if source == stop_ev_fd => {
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
        if let Err(e) = self.queue_events[queue_index].read() {
            error!("Failed to get queue event: {e:?}");
        }

        let vring_lock = &self.vrings[queue_index];

        loop {
            vring_lock
                .lock()
                .unwrap()
                .queue
                .disable_notification(&self.mem)
                .unwrap();

            self.process_queue(vring_lock, queue_index);

            if !vring_lock
                .lock()
                .unwrap()
                .queue
                .enable_notification(&self.mem)
                .unwrap()
            {
                break;
            }
        }
    }

    pub fn process_queue(&self, vring_lock: &Arc<Mutex<Vring>>, queue_index: usize) {
        debug!("snd: process_queue()");

        loop {
            let mut vring = vring_lock.lock().unwrap();
            let head = vring.queue.pop(&self.mem);
            drop(vring);

            if let Some(head) = head {
                let ret = match queue_index {
                    CTL_INDEX => self.process_ctl(vring_lock, head),
                    EVT_INDEX => self.process_evt(vring_lock, head),
                    RXQ_INDEX => self.process_io(vring_lock, head, Direction::Input),
                    TXQ_INDEX => self.process_io(vring_lock, head, Direction::Output),
                    _ => unreachable!(),
                };
                if let Err(err) = ret {
                    error!("error processing queue {queue_index}: {err}");
                }

                if vring_lock
                    .lock()
                    .unwrap()
                    .queue
                    .needs_notification(&self.mem)
                    .unwrap()
                {
                    self.interrupt.signal_used_queue();
                }
            } else {
                break;
            }
        }
    }

    fn process_ctl(
        &self,
        vring_lock: &Arc<Mutex<Vring>>,
        head: DescriptorChain,
    ) -> result::Result<(), Error> {
        let descriptors: Vec<_> = head.clone().into_iter().collect();
        if descriptors.len() < 2 {
            return Err(Error::UnexpectedDescriptorCount(descriptors.len()));
        }

        // Request descriptor.
        let desc_request = &descriptors[0];
        if desc_request.is_write_only() {
            return Err(Error::UnexpectedWriteOnlyDescriptor(0));
        }

        let request = self
            .mem
            .read_obj::<VirtioSoundHeader>(desc_request.addr)
            .map_err(|_| Error::DescriptorReadFailed)?;

        // Keep track of bytes that will be written in the VQ.
        let mut used_len = 0;

        // Reply header descriptor.
        let desc_hdr = &descriptors[1];
        if !desc_hdr.is_write_only() {
            return Err(Error::UnexpectedReadableDescriptor(1));
        }

        let mut resp = VirtioSoundHeader {
            code: VIRTIO_SND_S_OK.into(),
        };

        let code = ControlMessageKind::try_from(request.code.to_native()).unwrap();
        match code {
            ControlMessageKind::ChmapInfo => {
                if descriptors.len() != 3 {
                    log::error!("a CHMAP_INFO request should have three descriptors total.");
                    return Err(Error::UnexpectedDescriptorCount(descriptors.len()));
                } else if !descriptors[2].is_write_only() {
                    log::error!(
                        "a CHMAP_INFO request should have a writeable descriptor for the info \
                             payload response after the header status response"
                    );
                    return Err(Error::UnexpectedReadableDescriptor(2));
                }
                let request = self
                    .mem
                    .read_obj::<VirtioSoundQueryInfo>(desc_request.addr)
                    .map_err(|_| Error::DescriptorReadFailed)?;
                let start_id = u32::from(request.start_id) as usize;
                let count = u32::from(request.count) as usize;
                let chmaps = self.chmaps.read().unwrap();
                if chmaps.len() <= start_id || chmaps.len() < start_id + count {
                    resp.code = VIRTIO_SND_S_BAD_MSG.into();
                } else {
                    let desc_response = &descriptors[2];
                    let mut buf = vec![];

                    for i in chmaps.iter().skip(start_id).take(count) {
                        buf.extend_from_slice(i.as_slice());
                    }
                    drop(chmaps);
                    self.mem
                        .write_slice(&buf, desc_response.addr)
                        .map_err(|_| Error::DescriptorWriteFailed)?;
                    used_len += desc_response.len;
                }
            }
            ControlMessageKind::JackInfo => {
                if descriptors.len() != 3 {
                    log::error!("a JACK_INFO request should have three descriptors total.");
                    return Err(Error::UnexpectedDescriptorCount(descriptors.len()));
                } else if !descriptors[2].is_write_only() {
                    log::error!(
                        "a JACK_INFO request should have a writeable descriptor for the info \
                             payload response after the header status response"
                    );
                    return Err(Error::UnexpectedReadableDescriptor(2));
                }
                let request = self
                    .mem
                    .read_obj::<VirtioSoundQueryInfo>(desc_request.addr)
                    .map_err(|_| Error::DescriptorReadFailed)?;

                let start_id = u32::from(request.start_id) as usize;
                let count = u32::from(request.count) as usize;
                let jacks = self.jacks.read().unwrap();
                if jacks.len() <= start_id || jacks.len() < start_id + count {
                    resp.code = VIRTIO_SND_S_BAD_MSG.into();
                } else {
                    let desc_response = &descriptors[2];
                    let mut buf = vec![];

                    for i in jacks.iter().skip(start_id).take(count) {
                        buf.extend_from_slice(i.as_slice());
                    }
                    drop(jacks);
                    self.mem
                        .write_slice(&buf, desc_response.addr)
                        .map_err(|_| Error::DescriptorWriteFailed)?;
                    used_len += desc_response.len;
                }
            }
            ControlMessageKind::JackRemap => {
                resp.code = VIRTIO_SND_S_NOT_SUPP.into();
            }
            ControlMessageKind::PcmInfo => {
                if descriptors.len() != 3 {
                    log::error!("a PCM_INFO request should have three descriptors total.");
                    return Err(Error::UnexpectedDescriptorCount(descriptors.len()));
                } else if !descriptors[2].is_write_only() {
                    log::error!(
                        "a PCM_INFO request should have a writeable descriptor for the info \
                             payload response after the header status response"
                    );
                    return Err(Error::UnexpectedReadableDescriptor(2));
                }

                let request = self
                    .mem
                    .read_obj::<VirtioSoundQueryInfo>(desc_request.addr)
                    .map_err(|_| Error::DescriptorReadFailed)?;

                let start_id = u32::from(request.start_id) as usize;
                let count = u32::from(request.count) as usize;
                let streams = self.streams.read().unwrap();
                if streams.len() <= start_id || streams.len() < start_id + count {
                    resp.code = VIRTIO_SND_S_BAD_MSG.into();
                } else {
                    let desc_response = &descriptors[2];

                    let mut buf = vec![];
                    let mut p: VirtioSoundPcmInfo;

                    for s in streams
                        .iter()
                        .skip(u32::from(request.start_id) as usize)
                        .take(u32::from(request.count) as usize)
                    {
                        p = VirtioSoundPcmInfo::default();
                        p.hdr.hda_fn_nid = 0.into();
                        p.features = s.params.features;
                        p.formats = s.formats;
                        p.rates = s.rates;
                        p.direction = s.direction as u8;
                        p.channels_min = s.channels_min;
                        p.channels_max = s.channels_max;
                        buf.extend_from_slice(p.as_slice());
                    }
                    drop(streams);
                    self.mem
                        .write_slice(&buf, desc_response.addr)
                        .map_err(|_| Error::DescriptorWriteFailed)?;
                    used_len += desc_response.len;
                }
            }
            ControlMessageKind::PcmSetParams => {
                let request = self
                    .mem
                    .read_obj::<VirtioSndPcmSetParams>(desc_request.addr)
                    .map_err(|_| Error::DescriptorReadFailed)?;
                let stream_id: u32 = request.hdr.stream_id.into();

                if stream_id as usize >= self.streams_no {
                    log::error!("{}", Error::from(StreamError::InvalidStreamId(stream_id)));
                    resp.code = VIRTIO_SND_S_BAD_MSG.into();
                } else if let Err(err) = self
                    .audio_backend
                    .read()
                    .unwrap()
                    .set_parameters(stream_id, request)
                {
                    match err {
                        Error::Stream(_) | Error::StreamWithIdNotFound(_) => {
                            resp.code = VIRTIO_SND_S_BAD_MSG.into()
                        }
                        Error::UnexpectedAudioBackendConfiguration => {
                            resp.code = VIRTIO_SND_S_NOT_SUPP.into()
                        }
                        _ => {
                            log::error!("{err}");
                            resp.code = VIRTIO_SND_S_IO_ERR.into()
                        }
                    }
                }
            }
            ControlMessageKind::PcmPrepare => {
                let request = self
                    .mem
                    .read_obj::<VirtioSoundPcmHeader>(desc_request.addr)
                    .map_err(|_| Error::DescriptorReadFailed)?;
                let stream_id = request.stream_id.into();

                if stream_id as usize >= self.streams_no {
                    log::error!("{}", Error::from(StreamError::InvalidStreamId(stream_id)));
                    resp.code = VIRTIO_SND_S_BAD_MSG.into();
                } else {
                    self.audio_backend
                        .write()
                        .unwrap()
                        .prepare(stream_id)
                        .unwrap();
                }
            }
            ControlMessageKind::PcmRelease => {
                let request = self
                    .mem
                    .read_obj::<VirtioSoundPcmHeader>(desc_request.addr)
                    .map_err(|_| Error::DescriptorReadFailed)?;
                let stream_id = request.stream_id.into();

                if stream_id as usize >= self.streams_no {
                    log::error!("{}", Error::from(StreamError::InvalidStreamId(stream_id)));
                    resp.code = VIRTIO_SND_S_BAD_MSG.into();
                } else if let Err(err) = self.audio_backend.write().unwrap().release(stream_id) {
                    match err {
                        Error::Stream(_) | Error::StreamWithIdNotFound(_) => {
                            resp.code = VIRTIO_SND_S_BAD_MSG.into()
                        }
                        _ => {
                            log::error!("{err}");
                            resp.code = VIRTIO_SND_S_IO_ERR.into()
                        }
                    }
                }
            }
            ControlMessageKind::PcmStart => {
                let request = self
                    .mem
                    .read_obj::<VirtioSoundPcmHeader>(desc_request.addr)
                    .map_err(|_| Error::DescriptorReadFailed)?;
                let stream_id = request.stream_id.into();

                if stream_id as usize >= self.streams_no {
                    log::error!("{}", Error::from(StreamError::InvalidStreamId(stream_id)));
                    resp.code = VIRTIO_SND_S_BAD_MSG.into();
                } else {
                    self.audio_backend
                        .write()
                        .unwrap()
                        .start(stream_id)
                        .unwrap();
                }
            }
            ControlMessageKind::PcmStop => {
                let request = self
                    .mem
                    .read_obj::<VirtioSoundPcmHeader>(desc_request.addr)
                    .map_err(|_| Error::DescriptorReadFailed)?;
                let stream_id = request.stream_id.into();

                if stream_id as usize >= self.streams_no {
                    log::error!("{}", Error::from(StreamError::InvalidStreamId(stream_id)));
                    resp.code = VIRTIO_SND_S_BAD_MSG.into();
                } else {
                    self.audio_backend.write().unwrap().stop(stream_id).unwrap();
                }
            }
        }
        debug!(
            "returned {} for ctrl msg {:?}",
            match u32::from(resp.code) {
                v if v == VIRTIO_SND_S_OK => "OK",
                v if v == VIRTIO_SND_S_BAD_MSG => "BAD_MSG",
                v if v == VIRTIO_SND_S_NOT_SUPP => "NOT_SUPP",
                v if v == VIRTIO_SND_S_IO_ERR => "IO_ERR",
                _ => unreachable!(),
            },
            code
        );

        self.mem.write_obj(resp, desc_hdr.addr).unwrap();
        if let Err(err) = vring_lock
            .lock()
            .unwrap()
            .queue
            .add_used(&self.mem, head.index, used_len)
        {
            error!("Error adding used descriptors to the queue: {err}");
        }

        Ok(())
    }

    fn process_evt(
        &self,
        _vring_lock: &Arc<Mutex<Vring>>,
        _head: DescriptorChain,
    ) -> result::Result<(), Error> {
        error!("virtio_snd: unimplemented process_evt");
        Ok(())
    }

    fn process_io(
        &self,
        vring_lock: &Arc<Mutex<Vring>>,
        desc_chain: DescriptorChain,
        direction: Direction,
    ) -> result::Result<(), Error> {
        #[derive(Copy, Clone, PartialEq, Debug)]
        enum IoState {
            Ready,
            WaitingBufferForStreamId(u32),
            Done,
        }

        let mut stream_ids = BTreeSet::default();

        let mut state = IoState::Ready;
        let mut buffers: Vec<Buffer> = vec![];

        let descriptors: Vec<_> = desc_chain.clone().into_iter().collect();
        let message = Arc::new(IOMessage {
            status: VIRTIO_SND_S_OK.into(),
            used_len: 0.into(),
            latency_bytes: 0.into(),
            head_index: desc_chain.index,
            response_descriptor: descriptors
                .last()
                .ok_or_else(|| {
                    log::error!("Received IO request with an empty descriptor chain.");
                    Error::UnexpectedDescriptorCount(0)
                })?
                .descriptor(),
            vring: vring_lock.clone(),
        });

        for descriptor in &descriptors {
            match state {
                IoState::Done => {
                    return Err(Error::UnexpectedDescriptorCount(descriptors.len()));
                }
                IoState::Ready
                    if matches!(direction, Direction::Output) && descriptor.is_write_only() =>
                {
                    if descriptor.len as usize != size_of::<VirtioSoundPcmStatus>() {
                        return Err(Error::UnexpectedDescriptorSize(
                            size_of::<VirtioSoundPcmStatus>(),
                            descriptor.len,
                        ));
                    }
                    state = IoState::Done;
                }
                IoState::WaitingBufferForStreamId(stream_id)
                    if descriptor.len as usize == size_of::<VirtioSoundPcmStatus>() =>
                {
                    self.streams.write().unwrap()[stream_id as usize]
                        .buffers
                        .extend(std::mem::take(&mut buffers));
                    state = IoState::Done;
                }
                IoState::Ready if descriptor.len as usize != size_of::<VirtioSoundPcmXfer>() => {
                    return Err(Error::UnexpectedDescriptorSize(
                        size_of::<VirtioSoundPcmXfer>(),
                        descriptor.len,
                    ));
                }
                IoState::Ready => {
                    let xfer = self
                        .mem
                        .read_obj::<VirtioSoundPcmXfer>(descriptor.addr)
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    let stream_id: u32 = xfer.stream_id.into();
                    stream_ids.insert(stream_id);

                    state = IoState::WaitingBufferForStreamId(stream_id);
                }
                IoState::WaitingBufferForStreamId(stream_id)
                    if descriptor.len as usize == size_of::<VirtioSoundPcmXfer>() =>
                {
                    return Err(Error::UnexpectedDescriptorSize(
                        u32::from(
                            self.streams.read().unwrap()[stream_id as usize]
                                .params
                                .period_bytes,
                        ) as usize,
                        descriptor.len,
                    ));
                }
                IoState::WaitingBufferForStreamId(_) => {
                    // In the case of TX/Playback:
                    //
                    // Rather than copying the content of a descriptor, buffer keeps a pointer
                    // to it. When we copy just after the request is enqueued, the guest's
                    // userspace may or may not have updated the buffer contents. Guest driver
                    // simply moves buffers from the used ring to the available ring without
                    // knowing whether the content has been updated. The device only reads the
                    // buffer from guest memory when the audio engine requires it, which is
                    // about after a period thus ensuring that the buffer is up-to-date.
                    buffers.push(Buffer::new(
                        descriptor.descriptor(),
                        Arc::clone(&message),
                        direction,
                    ));
                }
            }
        }

        if !stream_ids.is_empty() {
            let b = self.audio_backend.read().unwrap();
            for id in stream_ids {
                b.write(id).unwrap();
            }
        }

        Ok(())
    }
}
