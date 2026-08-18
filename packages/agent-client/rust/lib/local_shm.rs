//! Unix-local shared-memory bulk transport carried by the existing agent socket.
//!
//! This module deliberately keeps operation semantics out of shared memory. The mappings contain
//! payload bytes only; fixed descriptors and releases remain ordered on `agent.sock`.

#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::fs::File;
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{Ordering, fence};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use memmap2::{Mmap, MmapMut, MmapOptions};
use microsandbox_protocol::bulk::{BulkFlow, BulkKind, BulkRecord, MAX_BULK_RECORD_PAYLOAD};
use microsandbox_protocol::codec::{self, RawFrame};
use nix::errno::Errno;
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use tokio::net::UnixStream;
use tokio::sync::{Notify, mpsc};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// First shared-arena descriptor format.
pub const LOCAL_SHM_FORMAT_V1: u8 = 1;

/// Total bytes mapped for each transfer direction.
pub const LOCAL_SHM_ARENA_BYTES: usize = 64 * 1024 * 1024;

/// Bytes in one small record slot.
pub const LOCAL_SHM_SMALL_SLOT_BYTES: usize = 256 * 1024;

/// Number of small record slots.
pub const LOCAL_SHM_SMALL_SLOTS: u16 = 64;

/// Bytes in one large filesystem record slot.
pub const LOCAL_SHM_LARGE_SLOT_BYTES: usize = 3 * 1024 * 1024;

/// Number of large filesystem record slots.
pub const LOCAL_SHM_LARGE_SLOTS: u16 = 16;

/// Total number of independently leased slots.
pub const LOCAL_SHM_SLOT_COUNT: u16 = LOCAL_SHM_SMALL_SLOTS + LOCAL_SHM_LARGE_SLOTS;

const LOCAL_MAGIC: [u8; 4] = *b"MSBS";
const LOCAL_KIND_UPGRADE_REQUEST: u8 = 1;
const LOCAL_KIND_BULK_REF: u8 = 2;
const LOCAL_KIND_BULK_RELEASE: u8 = 3;
const LOCAL_UPGRADE_ACK: [u8; 4] = *b"MSBA";
const LOCAL_UPGRADE_ACK_BYTES: usize = 8;
const LOCAL_UPGRADE_ACCEPTED: u8 = 0;
const LOCAL_UPGRADE_REJECTED: u8 = 1;
const LOCAL_BULK_REF_BYTES: usize = 32;
const LOCAL_BULK_RELEASE_BYTES: usize = 12;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Errors raised while negotiating or using the local shared arena.
#[derive(Debug, thiserror::Error)]
pub enum LocalShmError {
    /// A system call or memory mapping failed.
    #[error("local shared arena I/O: {0}")]
    Io(#[from] std::io::Error),

    /// A socket ancillary-data operation failed.
    #[error("local shared arena socket: {0}")]
    Socket(#[from] Errno),

    /// A local descriptor violated the fixed format or ownership rules.
    #[error("local shared arena protocol: {0}")]
    Protocol(String),

    /// The selected shared arena has no fitting free slot right now.
    #[error("local shared arena has no free {0} slot")]
    Full(&'static str),
}

/// Result alias for local shared-arena operations.
pub type LocalShmResult<T> = Result<T, LocalShmError>;

/// One validated local transport message carried at correlation ID zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalShmFrame {
    /// Ask the relay to establish format 1 and transfer both arena descriptors.
    UpgradeRequest,

    /// Refer to one immutable payload retained in a leased slot.
    BulkRef(LocalBulkRef),

    /// Return one exact slot generation to its producer.
    BulkRelease(LocalBulkRelease),
}

/// Metadata referring to one generation-7 bulk payload in a shared slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalBulkRef {
    /// Arena slot containing the payload.
    pub slot: u16,
    /// Nonzero producer generation for this lease.
    pub generation: u32,
    /// Agent-protocol correlation ID.
    pub id: u32,
    /// Filesystem or TCP bulk kind.
    pub kind: BulkKind,
    /// Legal protocol flow direction.
    pub flow: BulkFlow,
    /// Logical byte offset inside the operation.
    pub offset: u64,
    /// Exact payload bytes stored in the slot.
    pub payload_len: u32,
}

/// Exact slot lease returned to a producer after the final consumer drops it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalBulkRelease {
    /// Arena slot being returned.
    pub slot: u16,
    /// Exact generation being returned.
    pub generation: u32,
}

/// Relay-side mappings and producer state for one SDK connection.
pub struct LocalShmServer {
    /// SDK-to-runtime payload consumer.
    pub inbound: SharedArenaConsumer,
    /// Runtime-to-SDK payload producer.
    pub outbound: SharedArenaProducer,
    inbound_file: File,
    outbound_file: File,
}

/// SDK-side mappings and producer state for one local relay connection.
pub struct LocalShmClient {
    /// SDK-to-runtime payload producer.
    pub outbound: SharedArenaProducer,
    /// Runtime-to-SDK payload consumer.
    pub inbound: SharedArenaConsumer,
}

/// Producer for one directional shared arena.
#[derive(Clone)]
pub struct SharedArenaProducer {
    inner: Arc<ProducerInner>,
}

struct ProducerInner {
    mapping: Mutex<MmapMut>,
    slots: Mutex<ProducerSlots>,
    available: Notify,
}

struct ProducerSlots {
    generations: Vec<u32>,
    leased: Vec<Option<u32>>,
}

/// Consumer for one directional shared arena.
#[derive(Clone)]
pub struct SharedArenaConsumer {
    inner: Arc<ConsumerInner>,
}

struct ConsumerInner {
    mapping: Arc<Mmap>,
    leased: Mutex<Vec<Option<u32>>>,
}

/// A prepared local descriptor whose slot is reclaimed unless physical socket admission commits it.
pub struct PreparedLocalBulk {
    producer: SharedArenaProducer,
    descriptor: LocalBulkRef,
    committed: bool,
}

struct SharedPayload {
    consumer: SharedArenaConsumer,
    offset: usize,
    len: usize,
    release: LocalBulkRelease,
    release_tx: mpsc::UnboundedSender<LocalBulkRelease>,
}

/// Result of the fixed ancillary descriptor exchange.
pub enum LocalShmUpgrade {
    /// The relay accepted the upgrade and transferred the SDK-to-runtime then runtime-to-SDK FDs.
    Accepted([OwnedFd; 2]),

    /// The relay could not create safe arenas; the caller may continue in-band.
    Rejected,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalShmServer {
    /// Create and map both directional arenas for one SDK connection.
    pub fn create() -> LocalShmResult<Self> {
        let inbound_file = create_arena_file("msb-agent-h2g")?;
        let outbound_file = create_arena_file("msb-agent-g2h")?;
        let inbound = SharedArenaConsumer::map(&inbound_file)?;
        let outbound = SharedArenaProducer::map(&outbound_file)?;
        Ok(Self {
            inbound,
            outbound,
            inbound_file,
            outbound_file,
        })
    }

    /// File descriptors transferred to the SDK in the fixed direction order.
    pub fn client_fds(&self) -> [RawFd; 2] {
        [
            self.inbound_file.as_raw_fd(),
            self.outbound_file.as_raw_fd(),
        ]
    }
}

impl LocalShmClient {
    /// Map the fixed SDK-to-runtime then runtime-to-SDK descriptor pair.
    pub fn from_fds(fds: [OwnedFd; 2]) -> LocalShmResult<Self> {
        let [outbound_fd, inbound_fd] = fds;
        let outbound_file = File::from(outbound_fd);
        let inbound_file = File::from(inbound_fd);
        validate_arena_file(&outbound_file)?;
        validate_arena_file(&inbound_file)?;
        Ok(Self {
            outbound: SharedArenaProducer::map(&outbound_file)?,
            inbound: SharedArenaConsumer::map(&inbound_file)?,
        })
    }
}

impl SharedArenaProducer {
    fn map(file: &File) -> LocalShmResult<Self> {
        validate_arena_file(file)?;
        // SAFETY: The file has the exact fixed length, remains referenced by this mapping, and
        // slot leasing guarantees that only one producer task writes each disjoint range at once.
        let mapping = unsafe {
            MmapOptions::new()
                .len(LOCAL_SHM_ARENA_BYTES)
                .map_mut(file)?
        };
        Ok(Self {
            inner: Arc::new(ProducerInner {
                mapping: Mutex::new(mapping),
                slots: Mutex::new(ProducerSlots {
                    generations: vec![0; LOCAL_SHM_SLOT_COUNT as usize],
                    leased: vec![None; LOCAL_SHM_SLOT_COUNT as usize],
                }),
                available: Notify::new(),
            }),
        })
    }

    /// Copy one bulk payload into a fitting slot, waiting for bounded arena capacity when needed.
    pub async fn prepare(&self, record: &BulkRecord) -> LocalShmResult<PreparedLocalBulk> {
        loop {
            let notified = self.inner.available.notified();
            match self.try_prepare(record) {
                Ok(prepared) => return Ok(prepared),
                Err(LocalShmError::Full(_)) => notified.await,
                Err(error) => return Err(error),
            }
        }
    }

    /// Copy one payload if a fitting slot is immediately available.
    pub fn try_prepare(&self, record: &BulkRecord) -> LocalShmResult<PreparedLocalBulk> {
        let payload_len = record.payload.len();
        if payload_len == 0 || payload_len > MAX_BULK_RECORD_PAYLOAD as usize {
            return Err(LocalShmError::Protocol(format!(
                "payload length {payload_len} is outside 1..={MAX_BULK_RECORD_PAYLOAD}"
            )));
        }
        record
            .offset
            .checked_add(payload_len as u64)
            .ok_or_else(|| LocalShmError::Protocol("record end offset overflows u64".into()))?;

        let (slot, generation) = self.lease_slot(payload_len)?;
        let (offset, capacity) = slot_range(slot)?;
        debug_assert!(payload_len <= capacity);
        {
            let mut mapping = self.inner.mapping.lock().unwrap();
            mapping[offset..offset + payload_len].copy_from_slice(&record.payload);
        }
        fence(Ordering::Release);

        Ok(PreparedLocalBulk {
            producer: self.clone(),
            descriptor: LocalBulkRef {
                slot,
                generation,
                id: record.id,
                kind: record.kind,
                flow: record.flow,
                offset: record.offset,
                payload_len: payload_len as u32,
            },
            committed: false,
        })
    }

    /// Return an exact remotely released slot generation.
    pub fn release(&self, release: LocalBulkRelease) -> LocalShmResult<()> {
        let index = validate_slot(release.slot)?;
        let mut slots = self.inner.slots.lock().unwrap();
        match slots.leased[index] {
            Some(generation) if generation == release.generation => {
                slots.leased[index] = None;
                drop(slots);
                self.inner.available.notify_one();
                Ok(())
            }
            Some(generation) => Err(LocalShmError::Protocol(format!(
                "stale release for slot {} generation {}, current generation is {generation}",
                release.slot, release.generation
            ))),
            None => Err(LocalShmError::Protocol(format!(
                "duplicate release for free slot {} generation {}",
                release.slot, release.generation
            ))),
        }
    }

    fn lease_slot(&self, payload_len: usize) -> LocalShmResult<(u16, u32)> {
        let mut slots = self.inner.slots.lock().unwrap();
        let preferred = if payload_len <= LOCAL_SHM_SMALL_SLOT_BYTES {
            0..LOCAL_SHM_SMALL_SLOTS
        } else {
            LOCAL_SHM_SMALL_SLOTS..LOCAL_SHM_SLOT_COUNT
        };
        let fallback = (payload_len <= LOCAL_SHM_SMALL_SLOT_BYTES)
            .then_some(LOCAL_SHM_SMALL_SLOTS..LOCAL_SHM_SLOT_COUNT);
        let slot = preferred
            .chain(fallback.into_iter().flatten())
            .find(|slot| slots.leased[*slot as usize].is_none())
            .ok_or(LocalShmError::Full(
                if payload_len <= LOCAL_SHM_SMALL_SLOT_BYTES {
                    "small or large"
                } else {
                    "large"
                },
            ))?;
        let index = slot as usize;
        let mut generation = slots.generations[index].wrapping_add(1);
        if generation == 0 {
            generation = 1;
        }
        slots.generations[index] = generation;
        slots.leased[index] = Some(generation);
        Ok((slot, generation))
    }

    fn release_uncommitted(&self, release: LocalBulkRelease) {
        let Ok(index) = validate_slot(release.slot) else {
            return;
        };
        let mut slots = self.inner.slots.lock().unwrap();
        if slots.leased[index] == Some(release.generation) {
            slots.leased[index] = None;
            drop(slots);
            self.inner.available.notify_one();
        }
    }
}

impl SharedArenaConsumer {
    fn map(file: &File) -> LocalShmResult<Self> {
        validate_arena_file(file)?;
        // SAFETY: The file has the exact fixed length and the mapping owns a kernel reference to
        // the anonymous object. This side never receives a mutable Rust slice for the mapping.
        let mapping = unsafe { MmapOptions::new().len(LOCAL_SHM_ARENA_BYTES).map(file)? };
        Ok(Self {
            inner: Arc::new(ConsumerInner {
                mapping: Arc::new(mapping),
                leased: Mutex::new(vec![None; LOCAL_SHM_SLOT_COUNT as usize]),
            }),
        })
    }

    /// Validate and expose one descriptor payload without copying it from the mapping.
    pub fn receive(
        &self,
        descriptor: LocalBulkRef,
        release_tx: mpsc::UnboundedSender<LocalBulkRelease>,
    ) -> LocalShmResult<BulkRecord> {
        if descriptor.generation == 0 {
            return Err(LocalShmError::Protocol(
                "slot generation cannot be zero".into(),
            ));
        }
        if descriptor.id == 0 {
            return Err(LocalShmError::Protocol(
                "bulk descriptor cannot use correlation ID zero".into(),
            ));
        }
        let payload_len = descriptor.payload_len as usize;
        let (offset, capacity) = slot_range(descriptor.slot)?;
        if payload_len == 0 || payload_len > capacity {
            return Err(LocalShmError::Protocol(format!(
                "payload length {payload_len} exceeds slot {} capacity {capacity}",
                descriptor.slot
            )));
        }
        descriptor
            .offset
            .checked_add(payload_len as u64)
            .ok_or_else(|| LocalShmError::Protocol("record end offset overflows u64".into()))?;

        let index = descriptor.slot as usize;
        {
            let mut leased = self.inner.leased.lock().unwrap();
            if let Some(generation) = leased[index] {
                return Err(LocalShmError::Protocol(format!(
                    "slot {} generation {generation} is still retained",
                    descriptor.slot
                )));
            }
            leased[index] = Some(descriptor.generation);
        }
        fence(Ordering::Acquire);

        let payload = Bytes::from_owner(SharedPayload {
            consumer: self.clone(),
            offset,
            len: payload_len,
            release: LocalBulkRelease {
                slot: descriptor.slot,
                generation: descriptor.generation,
            },
            release_tx,
        });
        Ok(BulkRecord {
            id: descriptor.id,
            kind: descriptor.kind,
            flow: descriptor.flow,
            offset: descriptor.offset,
            payload,
        })
    }
}

impl PreparedLocalBulk {
    /// Descriptor sent over `agent.sock` after the payload has been published.
    pub fn descriptor(&self) -> LocalBulkRef {
        self.descriptor
    }

    /// Mark the descriptor physically admitted. Only a matching remote release may now reuse it.
    pub fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for PreparedLocalBulk {
    fn drop(&mut self) {
        if !self.committed {
            self.producer.release_uncommitted(LocalBulkRelease {
                slot: self.descriptor.slot,
                generation: self.descriptor.generation,
            });
        }
    }
}

impl AsRef<[u8]> for SharedPayload {
    fn as_ref(&self) -> &[u8] {
        &self.consumer.inner.mapping[self.offset..self.offset + self.len]
    }
}

impl Drop for SharedPayload {
    fn drop(&mut self) {
        let index = self.release.slot as usize;
        let mut leased = self.consumer.inner.leased.lock().unwrap();
        if leased[index] == Some(self.release.generation) {
            leased[index] = None;
            drop(leased);
            let _ = self.release_tx.send(self.release);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Local framing
//--------------------------------------------------------------------------------------------------

/// Build the reserved post-Ready shared-arena upgrade request.
pub fn local_upgrade_request_frame() -> RawFrame {
    RawFrame {
        id: 0,
        flags: 0,
        body: vec![
            LOCAL_MAGIC[0],
            LOCAL_MAGIC[1],
            LOCAL_MAGIC[2],
            LOCAL_MAGIC[3],
            LOCAL_SHM_FORMAT_V1,
            LOCAL_KIND_UPGRADE_REQUEST,
        ],
    }
}

/// Encode one shared payload descriptor as a reserved local frame.
pub fn encode_local_bulk_ref(descriptor: LocalBulkRef) -> LocalShmResult<Bytes> {
    let mut body = Vec::with_capacity(LOCAL_BULK_REF_BYTES);
    body.extend_from_slice(&LOCAL_MAGIC);
    body.push(LOCAL_SHM_FORMAT_V1);
    body.push(LOCAL_KIND_BULK_REF);
    body.extend_from_slice(&descriptor.slot.to_be_bytes());
    body.extend_from_slice(&descriptor.generation.to_be_bytes());
    body.extend_from_slice(&descriptor.id.to_be_bytes());
    body.push(descriptor.kind as u8);
    body.push(descriptor.flow as u8);
    body.extend_from_slice(&[0, 0]);
    body.extend_from_slice(&descriptor.offset.to_be_bytes());
    body.extend_from_slice(&descriptor.payload_len.to_be_bytes());
    debug_assert_eq!(body.len(), LOCAL_BULK_REF_BYTES);
    encode_local_body(body)
}

/// Encode one exact slot release as a reserved local frame.
pub fn encode_local_bulk_release(release: LocalBulkRelease) -> LocalShmResult<Bytes> {
    let mut body = Vec::with_capacity(LOCAL_BULK_RELEASE_BYTES);
    body.extend_from_slice(&LOCAL_MAGIC);
    body.push(LOCAL_SHM_FORMAT_V1);
    body.push(LOCAL_KIND_BULK_RELEASE);
    body.extend_from_slice(&release.slot.to_be_bytes());
    body.extend_from_slice(&release.generation.to_be_bytes());
    debug_assert_eq!(body.len(), LOCAL_BULK_RELEASE_BYTES);
    encode_local_body(body)
}

/// Decode one reserved local body after the outer ID and flags were validated.
pub fn decode_local_body(body: &[u8]) -> LocalShmResult<LocalShmFrame> {
    if body.len() < 6 || body[..4] != LOCAL_MAGIC {
        return Err(LocalShmError::Protocol(
            "missing MSBS local-frame magic".into(),
        ));
    }
    if body[4] != LOCAL_SHM_FORMAT_V1 {
        return Err(LocalShmError::Protocol(format!(
            "unsupported local-frame format {}",
            body[4]
        )));
    }
    match body[5] {
        LOCAL_KIND_UPGRADE_REQUEST if body.len() == 6 => Ok(LocalShmFrame::UpgradeRequest),
        LOCAL_KIND_BULK_REF if body.len() == LOCAL_BULK_REF_BYTES => {
            if body[18] != 0 || body[19] != 0 {
                return Err(LocalShmError::Protocol(
                    "bulk descriptor reserved bytes must be zero".into(),
                ));
            }
            let kind = BulkKind::from_wire(body[16]).ok_or_else(|| {
                LocalShmError::Protocol(format!("unknown bulk kind {}", body[16]))
            })?;
            let flow = BulkFlow::from_wire(body[17]).ok_or_else(|| {
                LocalShmError::Protocol(format!("unknown bulk flow {}", body[17]))
            })?;
            Ok(LocalShmFrame::BulkRef(LocalBulkRef {
                slot: u16::from_be_bytes(body[6..8].try_into().unwrap()),
                generation: u32::from_be_bytes(body[8..12].try_into().unwrap()),
                id: u32::from_be_bytes(body[12..16].try_into().unwrap()),
                kind,
                flow,
                offset: u64::from_be_bytes(body[20..28].try_into().unwrap()),
                payload_len: u32::from_be_bytes(body[28..32].try_into().unwrap()),
            }))
        }
        LOCAL_KIND_BULK_RELEASE if body.len() == LOCAL_BULK_RELEASE_BYTES => {
            Ok(LocalShmFrame::BulkRelease(LocalBulkRelease {
                slot: u16::from_be_bytes(body[6..8].try_into().unwrap()),
                generation: u32::from_be_bytes(body[8..12].try_into().unwrap()),
            }))
        }
        kind => Err(LocalShmError::Protocol(format!(
            "invalid local-frame kind {kind} or body length {}",
            body.len()
        ))),
    }
}

fn encode_local_body(body: Vec<u8>) -> LocalShmResult<Bytes> {
    let mut wire = Vec::with_capacity(9 + body.len());
    codec::encode_raw_to_buf(
        &RawFrame {
            id: 0,
            flags: 0,
            body,
        },
        &mut wire,
    )
    .map_err(|error| LocalShmError::Protocol(error.to_string()))?;
    Ok(Bytes::from(wire))
}

//--------------------------------------------------------------------------------------------------
// Functions: Descriptor passing
//--------------------------------------------------------------------------------------------------

/// Send an accepted or rejected fixed upgrade acknowledgement, attaching two FDs on success.
pub async fn send_local_shm_upgrade(
    stream: &UnixStream,
    fds: Option<[RawFd; 2]>,
) -> LocalShmResult<()> {
    send_local_shm_upgrade_fd(stream.as_raw_fd(), fds).await
}

/// Send the fixed upgrade acknowledgement through an already serialized socket writer.
///
/// Runtime relays retain a duplicated raw descriptor beside their Tokio write half so ancillary
/// data and ordinary frames still have one writer actor and cannot interleave.
pub async fn send_local_shm_upgrade_fd(
    socket_fd: RawFd,
    fds: Option<[RawFd; 2]>,
) -> LocalShmResult<()> {
    let mut ack = [0u8; LOCAL_UPGRADE_ACK_BYTES];
    ack[..4].copy_from_slice(&LOCAL_UPGRADE_ACK);
    ack[4] = LOCAL_SHM_FORMAT_V1;
    ack[5] = if fds.is_some() {
        LOCAL_UPGRADE_ACCEPTED
    } else {
        LOCAL_UPGRADE_REJECTED
    };
    ack[6] = if fds.is_some() { 2 } else { 0 };

    let mut offset = 0usize;
    let mut attach = fds;
    while offset < ack.len() {
        let iov = [IoSlice::new(&ack[offset..])];
        let result = if let Some(fds) = attach.as_ref() {
            sendmsg::<()>(
                socket_fd,
                &iov,
                &[ControlMessage::ScmRights(fds)],
                local_send_flags(),
                None,
            )
        } else {
            sendmsg::<()>(socket_fd, &iov, &[], local_send_flags(), None)
        };
        match result {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into()),
            Ok(sent) => {
                offset += sent;
                attach = None;
            }
            Err(Errno::EAGAIN) => {
                tokio::task::yield_now().await;
            }
            Err(error) => return Err(LocalShmError::Socket(error)),
        }
    }
    Ok(())
}

/// Receive the fixed upgrade acknowledgement and its exact descriptor pair.
pub async fn receive_local_shm_upgrade(stream: &UnixStream) -> LocalShmResult<LocalShmUpgrade> {
    let mut ack = [0u8; LOCAL_UPGRADE_ACK_BYTES];
    let mut received = 0usize;
    let mut owned_fds = Vec::<OwnedFd>::new();
    let mut first = true;

    while received < ack.len() {
        stream.readable().await?;
        let mut raw_fds = Vec::<RawFd>::new();
        let result = stream.try_io(tokio::io::Interest::READABLE, || {
            if first {
                let mut cmsgspace = nix::cmsg_space!([RawFd; 2]);
                let mut iov = [IoSliceMut::new(&mut ack[received..])];
                let message = recvmsg::<()>(
                    stream.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsgspace),
                    MsgFlags::MSG_DONTWAIT,
                )?;
                for cmsg in message.cmsgs()? {
                    if let ControlMessageOwned::ScmRights(fds) = cmsg {
                        raw_fds.extend(fds);
                    }
                }
                Ok(message.bytes)
            } else {
                stream.try_read(&mut ack[received..])
            }
        });
        match result {
            Ok(0) => {
                return Err(LocalShmError::Protocol(
                    "relay closed during local shared-arena upgrade".into(),
                ));
            }
            Ok(bytes) => {
                if first {
                    first = false;
                    for fd in raw_fds {
                        set_close_on_exec(fd)?;
                        // SAFETY: SCM_RIGHTS returned a new descriptor owned by this process.
                        owned_fds.push(unsafe { OwnedFd::from_raw_fd(fd) });
                    }
                }
                received += bytes;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error.into()),
        }
    }

    if ack[..4] != LOCAL_UPGRADE_ACK || ack[4] != LOCAL_SHM_FORMAT_V1 || ack[7] != 0 {
        return Err(LocalShmError::Protocol(
            "malformed local shared-arena acknowledgement".into(),
        ));
    }
    match (ack[5], ack[6], owned_fds.len()) {
        (LOCAL_UPGRADE_ACCEPTED, 2, 2) => {
            let mut fds = owned_fds.into_iter();
            Ok(LocalShmUpgrade::Accepted([
                fds.next().unwrap(),
                fds.next().unwrap(),
            ]))
        }
        (LOCAL_UPGRADE_REJECTED, 0, 0) => Ok(LocalShmUpgrade::Rejected),
        _ => Err(LocalShmError::Protocol(format!(
            "upgrade status={}, advertised_fds={}, received_fds={}",
            ack[5],
            ack[6],
            owned_fds.len()
        ))),
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Arena files and layout
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn create_arena_file(name: &str) -> LocalShmResult<File> {
    let name = CString::new(name)
        .map_err(|_| LocalShmError::Protocol("arena name contains NUL".into()))?;
    // SAFETY: `name` is a valid NUL-terminated C string and flags are the documented memfd set.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    } as libc::c_int;
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: The successful syscall returned a newly owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    file.set_len(LOCAL_SHM_ARENA_BYTES as u64)?;
    let seals = libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // SAFETY: `file` is a memfd created with MFD_ALLOW_SEALING.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn create_arena_file(_name: &str) -> LocalShmResult<File> {
    let file = tempfile::tempfile()?;
    file.set_len(LOCAL_SHM_ARENA_BYTES as u64)?;
    Ok(file)
}

fn validate_arena_file(file: &File) -> LocalShmResult<()> {
    let len = file.metadata()?.len();
    if len != LOCAL_SHM_ARENA_BYTES as u64 {
        return Err(LocalShmError::Protocol(format!(
            "arena length is {len}, expected {LOCAL_SHM_ARENA_BYTES}"
        )));
    }
    Ok(())
}

fn validate_slot(slot: u16) -> LocalShmResult<usize> {
    if slot >= LOCAL_SHM_SLOT_COUNT {
        return Err(LocalShmError::Protocol(format!(
            "slot {slot} is outside 0..{LOCAL_SHM_SLOT_COUNT}"
        )));
    }
    Ok(slot as usize)
}

fn slot_range(slot: u16) -> LocalShmResult<(usize, usize)> {
    validate_slot(slot)?;
    if slot < LOCAL_SHM_SMALL_SLOTS {
        return Ok((
            slot as usize * LOCAL_SHM_SMALL_SLOT_BYTES,
            LOCAL_SHM_SMALL_SLOT_BYTES,
        ));
    }
    let large = (slot - LOCAL_SHM_SMALL_SLOTS) as usize;
    let offset = LOCAL_SHM_SMALL_SLOTS as usize * LOCAL_SHM_SMALL_SLOT_BYTES
        + large * LOCAL_SHM_LARGE_SLOT_BYTES;
    Ok((offset, LOCAL_SHM_LARGE_SLOT_BYTES))
}

fn set_close_on_exec(fd: RawFd) -> LocalShmResult<()> {
    // SAFETY: `fd` is live and owned by the caller; F_GETFD/F_SETFD do not alter ownership.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn local_send_flags() -> MsgFlags {
    let flags = MsgFlags::MSG_DONTWAIT;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let flags = flags | MsgFlags::MSG_NOSIGNAL;
    flags
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_descriptor_round_trips() {
        let descriptor = LocalBulkRef {
            slot: 65,
            generation: 7,
            id: 42,
            kind: BulkKind::Filesystem,
            flow: BulkFlow::HostToGuest,
            offset: 99,
            payload_len: 1_000_000,
        };
        let wire = encode_local_bulk_ref(descriptor).unwrap();
        let body = &wire[9..];
        assert_eq!(
            decode_local_body(body).unwrap(),
            LocalShmFrame::BulkRef(descriptor)
        );
    }

    #[tokio::test]
    async fn shared_payload_is_zero_copy_and_releases_exact_generation() {
        let server = LocalShmServer::create().unwrap();
        let outbound_fd = server.inbound_file.try_clone().unwrap().into();
        let inbound_fd = server.outbound_file.try_clone().unwrap().into();
        let client = LocalShmClient::from_fds([outbound_fd, inbound_fd]).unwrap();
        let record = BulkRecord {
            id: 9,
            kind: BulkKind::Filesystem,
            flow: BulkFlow::HostToGuest,
            offset: 3,
            payload: Bytes::from(vec![0xA5; LOCAL_SHM_SMALL_SLOT_BYTES + 1]),
        };
        let mut prepared = client.outbound.prepare(&record).await.unwrap();
        let descriptor = prepared.descriptor();
        prepared.commit();
        let (release_tx, mut release_rx) = mpsc::unbounded_channel();
        let received = server.inbound.receive(descriptor, release_tx).unwrap();
        assert_eq!(received.payload, record.payload);
        drop(received);
        let release = release_rx.try_recv().unwrap();
        client.outbound.release(release).unwrap();
    }

    #[test]
    fn duplicate_release_is_rejected() {
        let server = LocalShmServer::create().unwrap();
        let record = BulkRecord {
            id: 1,
            kind: BulkKind::Tcp,
            flow: BulkFlow::GuestToHost,
            offset: 0,
            payload: Bytes::from_static(b"payload"),
        };
        let mut prepared = server.outbound.try_prepare(&record).unwrap();
        let release = LocalBulkRelease {
            slot: prepared.descriptor().slot,
            generation: prepared.descriptor().generation,
        };
        prepared.commit();
        server.outbound.release(release).unwrap();
        assert!(server.outbound.release(release).is_err());
    }

    #[test]
    fn slot_classes_exhaust_and_uncommitted_drop_reclaims_capacity() {
        let server = LocalShmServer::create().unwrap();
        let record = BulkRecord {
            id: 1,
            kind: BulkKind::Tcp,
            flow: BulkFlow::GuestToHost,
            offset: 0,
            payload: Bytes::from_static(b"x"),
        };
        let mut leased = Vec::new();
        for _ in 0..LOCAL_SHM_SLOT_COUNT {
            leased.push(server.outbound.try_prepare(&record).unwrap());
        }
        assert!(matches!(
            server.outbound.try_prepare(&record),
            Err(LocalShmError::Full(_))
        ));

        drop(leased.pop());
        assert!(server.outbound.try_prepare(&record).is_ok());
    }

    #[test]
    fn large_boundary_and_oversize_are_validated_before_leasing() {
        let server = LocalShmServer::create().unwrap();
        let mut record = BulkRecord {
            id: 7,
            kind: BulkKind::Filesystem,
            flow: BulkFlow::HostToGuest,
            offset: 0,
            payload: Bytes::from(vec![0x5a; LOCAL_SHM_SMALL_SLOT_BYTES + 1]),
        };
        let prepared = server.outbound.try_prepare(&record).unwrap();
        assert!(prepared.descriptor().slot >= LOCAL_SHM_SMALL_SLOTS);
        drop(prepared);

        record.payload = Bytes::from(vec![0u8; MAX_BULK_RECORD_PAYLOAD as usize + 1]);
        assert!(matches!(
            server.outbound.try_prepare(&record),
            Err(LocalShmError::Protocol(_))
        ));
    }

    #[test]
    fn generation_wrap_skips_zero_and_rejects_stale_release() {
        let server = LocalShmServer::create().unwrap();
        server.outbound.inner.slots.lock().unwrap().generations[0] = u32::MAX;
        let record = BulkRecord {
            id: 3,
            kind: BulkKind::Tcp,
            flow: BulkFlow::GuestToHost,
            offset: 0,
            payload: Bytes::from_static(b"payload"),
        };
        let mut prepared = server.outbound.try_prepare(&record).unwrap();
        let descriptor = prepared.descriptor();
        assert_eq!(descriptor.generation, 1);
        prepared.commit();
        assert!(
            server
                .outbound
                .release(LocalBulkRelease {
                    slot: descriptor.slot,
                    generation: u32::MAX,
                })
                .is_err()
        );
        server
            .outbound
            .release(LocalBulkRelease {
                slot: descriptor.slot,
                generation: descriptor.generation,
            })
            .unwrap();
    }

    #[tokio::test]
    async fn upgrade_transfers_exact_descriptor_pair_on_existing_socket() {
        let server = LocalShmServer::create().unwrap();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let sent = send_local_shm_upgrade(&sender, Some(server.client_fds()));
        let received = receive_local_shm_upgrade(&receiver);
        let (sent, received) = tokio::join!(sent, received);
        sent.unwrap();
        let LocalShmUpgrade::Accepted(fds) = received.unwrap() else {
            panic!("descriptor-bearing upgrade was rejected");
        };
        let client = LocalShmClient::from_fds(fds).unwrap();

        let record = BulkRecord {
            id: 11,
            kind: BulkKind::Filesystem,
            flow: BulkFlow::HostToGuest,
            offset: 0,
            payload: Bytes::from_static(b"through-the-transferred-fd"),
        };
        let mut prepared = client.outbound.try_prepare(&record).unwrap();
        let descriptor = prepared.descriptor();
        prepared.commit();
        let (release_tx, mut release_rx) = mpsc::unbounded_channel();
        let received = server.inbound.receive(descriptor, release_tx).unwrap();
        assert_eq!(received.payload, record.payload);
        drop(received);
        client
            .outbound
            .release(release_rx.recv().await.unwrap())
            .unwrap();
    }
}
