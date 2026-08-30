use std::{
    io::Error as IoError,
    sync::{Arc, Mutex},
};

mod audio_backends;
mod device;
pub mod stream;
#[allow(dead_code)]
mod virtio_sound;
mod worker;

use thiserror::Error as ThisError;
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

pub use self::defs::uapi::VIRTIO_ID_SND as TYPE_SND;
pub use self::device::Snd;
pub use stream::Stream;
use virtio_sound::*;

use super::{Descriptor, InterruptTransport, Queue};
use crate::virtio::snd::virtio_sound::{VirtioSoundHeader, VirtioSoundPcmStatus};

mod defs {
    use super::super::QueueConfig;
    use super::virtio_sound::*;

    pub const SND_DEV_ID: &str = "virtio_snd";
    pub const NUM_QUEUES: usize = 4;
    pub const CTL_INDEX: usize = 0;
    pub const EVT_INDEX: usize = 1;
    pub const TXQ_INDEX: usize = 2;
    pub const RXQ_INDEX: usize = 3;
    pub const QUEUE_INDEXES: [usize; 4] = [CTL_INDEX, EVT_INDEX, TXQ_INDEX, RXQ_INDEX];

    const QUEUE_SIZE: u16 = 256;
    pub static QUEUE_CONFIG: [QueueConfig; NUM_QUEUES] = [QueueConfig::new(QUEUE_SIZE); NUM_QUEUES];

    pub const SUPPORTED_FORMATS: u64 = (1 << VIRTIO_SND_PCM_FMT_U8)
        | (1 << VIRTIO_SND_PCM_FMT_S16)
        | (1 << VIRTIO_SND_PCM_FMT_S24)
        | (1 << VIRTIO_SND_PCM_FMT_S32);

    pub const SUPPORTED_RATES: u64 = (1 << VIRTIO_SND_PCM_RATE_8000)
        | (1 << VIRTIO_SND_PCM_RATE_11025)
        | (1 << VIRTIO_SND_PCM_RATE_16000)
        | (1 << VIRTIO_SND_PCM_RATE_22050)
        | (1 << VIRTIO_SND_PCM_RATE_32000)
        | (1 << VIRTIO_SND_PCM_RATE_44100)
        | (1 << VIRTIO_SND_PCM_RATE_48000);

    pub mod uapi {
        pub const VIRTIO_F_VERSION_1: u32 = 32;
        pub const VIRTIO_ID_SND: u32 = 25;
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Stream direction.
///
/// Equivalent to `VIRTIO_SND_D_OUTPUT` and `VIRTIO_SND_D_INPUT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Direction {
    /// [`VIRTIO_SND_D_OUTPUT`](crate::virtio_sound::VIRTIO_SND_D_OUTPUT)
    Output = VIRTIO_SND_D_OUTPUT,
    /// [`VIRTIO_SND_D_INPUT`](crate::virtio_sound::VIRTIO_SND_D_INPUT)
    Input = VIRTIO_SND_D_INPUT,
}

impl TryFrom<u8> for Direction {
    type Error = Error;

    fn try_from(val: u8) -> std::result::Result<Self, Self::Error> {
        Ok(match val {
            virtio_sound::VIRTIO_SND_D_OUTPUT => Self::Output,
            virtio_sound::VIRTIO_SND_D_INPUT => Self::Input,
            other => {
                return Err(Error::InvalidMessageValue(
                    stringify!(Direction),
                    other.into(),
                ))
            }
        })
    }
}

/// Custom error types
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Notification send failed")]
    SendNotificationFailed,
    #[error("Descriptor not found")]
    DescriptorNotFound,
    #[error("Descriptor read failed")]
    DescriptorReadFailed,
    #[error("Descriptor write failed")]
    DescriptorWriteFailed,
    #[error("Failed to handle event other than EPOLLIN event")]
    HandleEventNotEpollIn,
    #[error("Failed to handle unknown event with id {0}")]
    HandleUnknownEvent(u16),
    #[error("Invalid control message code {0}")]
    InvalidControlMessage(u32),
    #[error("Invalid value in {0}: {1}")]
    InvalidMessageValue(&'static str, u16),
    #[error("Failed to create a new EventFd")]
    EventFdCreate(IoError),
    #[error("Request missing data buffer")]
    SoundReqMissingData,
    #[error("Audio backend not supported")]
    AudioBackendNotSupported,
    #[error("Audio backend unexpected error: {0}")]
    UnexpectedAudioBackendError(String),
    #[error("Audio backend configuration not supported")]
    UnexpectedAudioBackendConfiguration,
    #[error("No memory configured")]
    NoMemoryConfigured,
    #[error("Invalid virtio_snd_hdr size, expected: {0}, found: {1}")]
    UnexpectedSoundHeaderSize(usize, u32),
    #[error("Received unexpected write only descriptor at index {0}")]
    UnexpectedWriteOnlyDescriptor(usize),
    #[error("Received unexpected readable descriptor at index {0}")]
    UnexpectedReadableDescriptor(usize),
    #[error("Invalid descriptor count {0}")]
    UnexpectedDescriptorCount(usize),
    #[error("Invalid descriptor size, expected: {0}, found: {1}")]
    UnexpectedDescriptorSize(usize, u32),
    #[error("Protocol or device error: {0}")]
    Stream(stream::Error),
    #[error("Stream with id {0} not found")]
    StreamWithIdNotFound(u32),
    #[error("Channel number not supported: {0}")]
    ChannelNotSupported(u8),
    #[error("No audio backend in present")]
    MissingAudioBackend,
}

impl From<Error> for IoError {
    fn from(e: Error) -> Self {
        Self::other(e)
    }
}

impl From<stream::Error> for Error {
    fn from(val: stream::Error) -> Self {
        Self::Stream(val)
    }
}

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
pub enum BackendType {
    #[default]
    Pipewire,
}

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidControlMessage(u32);

impl std::fmt::Display for InvalidControlMessage {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "Invalid control message code {}", self.0)
    }
}

impl From<InvalidControlMessage> for Error {
    fn from(val: InvalidControlMessage) -> Self {
        Self::InvalidControlMessage(val.0)
    }
}

impl std::error::Error for InvalidControlMessage {}

pub struct Vring {
    mem: GuestMemoryMmap,
    queue: Queue,
    interrupt: InterruptTransport,
}

impl Vring {
    pub fn signal_used_queue(&self) {
        debug!("snd: raising IRQ");
        if let Err(e) = self.interrupt.try_signal_used_queue() {
            warn!("Failed to signal queue: {e:?}");
        }
    }
}

#[derive(Copy, Debug, Clone, Eq, PartialEq)]
#[repr(u32)]
pub enum ControlMessageKind {
    JackInfo = 1,
    JackRemap = 2,
    PcmInfo = 0x0100,
    PcmSetParams = 0x0101,
    PcmPrepare = 0x0102,
    PcmRelease = 0x0103,
    PcmStart = 0x0104,
    PcmStop = 0x0105,
    ChmapInfo = 0x0200,
}

impl TryFrom<u32> for ControlMessageKind {
    type Error = InvalidControlMessage;

    fn try_from(val: u32) -> std::result::Result<Self, Self::Error> {
        Ok(match val {
            VIRTIO_SND_R_JACK_INFO => Self::JackInfo,
            VIRTIO_SND_R_JACK_REMAP => Self::JackRemap,
            VIRTIO_SND_R_PCM_INFO => Self::PcmInfo,
            VIRTIO_SND_R_PCM_SET_PARAMS => Self::PcmSetParams,
            VIRTIO_SND_R_PCM_PREPARE => Self::PcmPrepare,
            VIRTIO_SND_R_PCM_RELEASE => Self::PcmRelease,
            VIRTIO_SND_R_PCM_START => Self::PcmStart,
            VIRTIO_SND_R_PCM_STOP => Self::PcmStop,
            VIRTIO_SND_R_CHMAP_INFO => Self::ChmapInfo,
            other => return Err(InvalidControlMessage(other)),
        })
    }
}

pub struct ControlMessage {
    pub kind: ControlMessageKind,
    pub code: u32,
    pub desc_addr: GuestAddress,
    pub head_index: u16,
    pub vring: Arc<Mutex<Vring>>,
}

impl std::fmt::Debug for ControlMessage {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.debug_struct(stringify!(ControlMessage))
            .field("kind", &self.kind)
            .field("code", &self.code)
            .finish()
    }
}

impl Drop for ControlMessage {
    fn drop(&mut self) {
        debug!(
            "dropping ControlMessage {:?} reply = {}",
            self.kind,
            match self.code {
                virtio_sound::VIRTIO_SND_S_OK => "VIRTIO_SND_S_OK",
                virtio_sound::VIRTIO_SND_S_BAD_MSG => "VIRTIO_SND_S_BAD_MSG",
                virtio_sound::VIRTIO_SND_S_NOT_SUPP => "VIRTIO_SND_S_NOT_SUPP",
                virtio_sound::VIRTIO_SND_S_IO_ERR => "VIRTIO_SND_S_IO_ERR",
                _ => "other",
            }
        );
        let resp = VirtioSoundHeader {
            code: self.code.into(),
        };

        let mut vring = self.vring.lock().unwrap();
        let mem = vring.mem.clone();

        if let Err(err) = vring.mem.write_obj(resp, self.desc_addr) {
            log::error!("Error::DescriptorWriteFailed: {err}");
            return;
        }
        if let Err(err) = vring
            .queue
            .add_used(&mem, self.head_index, resp.as_slice().len() as u32)
        {
            log::error!("Error adding used descriptors: {err}");
            return;
        }
        vring.signal_used_queue();
    }
}

pub struct IOMessage {
    status: std::sync::atomic::AtomicU32,
    pub used_len: std::sync::atomic::AtomicU32,
    pub latency_bytes: std::sync::atomic::AtomicU32,

    head_index: u16,
    response_descriptor: Descriptor,
    vring: Arc<Mutex<Vring>>,
}

impl Drop for IOMessage {
    fn drop(&mut self) {
        let resp = VirtioSoundPcmStatus {
            status: self.status.load(std::sync::atomic::Ordering::SeqCst).into(),
            latency_bytes: self
                .latency_bytes
                .load(std::sync::atomic::Ordering::SeqCst)
                .into(),
        };
        let used_len: u32 = self.used_len.load(std::sync::atomic::Ordering::SeqCst);
        log::trace!("dropping IOMessage {resp:?}");

        let mut vring = self.vring.lock().unwrap();
        let mem = vring.mem.clone();
        if let Err(err) = mem.write_obj(resp, GuestAddress(self.response_descriptor.addr)) {
            log::error!("Error::DescriptorWriteFailed: {err}");
            return;
        }
        if let Err(err) = vring.queue.add_used(
            &mem,
            self.head_index,
            resp.as_slice().len() as u32 + used_len,
        ) {
            log::error!("Couldn't add used bytes count to vring: {err}");
        }
        vring.signal_used_queue();
    }
}
