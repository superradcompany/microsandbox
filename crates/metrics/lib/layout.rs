//! Binary layout of the shared-memory metrics registry.
//!
//! Defines the header and slot in-memory representation. All multi-byte fields
//! that participate in cross-process reads/writes are accessed as atomics; the
//! seqlock pattern (see [`registry`](super::registry)) guards the non-atomic
//! per-sample bytes against torn reads.
//!
//! # Memory layout
//!
//! The mapped region is `HEADER_SIZE + capacity * SLOT_SIZE` bytes
//! (`256 + capacity * 512`). The header lives at offset 0, slot N at offset
//! `256 + N * 512`. Field offsets below include the implicit alignment
//! padding the compiler inserts for `#[repr(C)]` — the `const _ = assert!`
//! checks at the bottom of this file guard the total struct sizes against
//! drift.
//!
//! ```text
//! +-----------------------------------------------------------------+ 0x000
//! | HEADER (256 bytes)                                              |
//! |  0x00  magic            u64   "MSBMET01" tag                    |
//! |  0x08  version          u32   layout version (1)                |
//! |  0x0c  header_len       u32   = 256                             |
//! |  0x10  slot_len         u32   = 512                             |
//! |  0x14  capacity         u32   number of slots                   |
//! |  0x18  state            AU32  uninit | initializing | ready     |
//! |  0x1c  -- padding --                                            |
//! |  0x20  created_at_ms    i64   first-create wall clock           |
//! |  0x28  global_generation AU64 monotonically increasing          |
//! |  0x30  _reserved        [u8; 208] (room for future fields)      |
//! +-----------------------------------------------------------------+ 0x100
//! | SLOT 0 (512 bytes)                                              |
//! |  0x00  state            AU32  free | reserved | active | stale  |
//! |  0x04  -- padding --                                            |
//! |  0x08  generation       AU64  ABA stamp, bumped on every reuse  |
//! |  0x10  seq              AU64  seqlock (odd = writer mid-write)  |
//! |  0x18  sandbox_id       AI32  catalog sandbox id                |
//! |  0x1c  run_id           AI32  catalog run id (0 until activate) |
//! |  0x20  pid              AI32  host pid of the writer            |
//! |  0x24  _pad0            u32                                     |
//! |  0x28  started_at_ms    AI64                                    |
//! |  0x30  sampled_at_ms    AI64  0 until first sample              |
//! |  0x38  memory_limit     AU64  bytes                             |
//! |  0x40  cpu_percent_bits AU32  f32 bits                          |
//! |  0x44  -- padding --                                            |
//! |  0x48  memory_bytes     AU64                                    |
//! |  0x50  disk_read_bytes  AU64                                    |
//! |  0x58  disk_write_bytes AU64                                    |
//! |  0x60  net_rx_bytes     AU64                                    |
//! |  0x68  net_tx_bytes     AU64                                    |
//! |  0x70  name_len         AU16                                    |
//! |  0x72  _pad1            [AU8; 6]                                |
//! |  0x78  name_bytes       [AU8; 128]                              |
//! |  0xf8  _tail            [u8; 264]                               |
//! +-----------------------------------------------------------------+ 0x300
//! | SLOT 1 ... SLOT capacity-1                                      |
//! ~                                                                 ~
//! +-----------------------------------------------------------------+
//! ```
//!
//! Prefix `A` denotes `Atomic` (e.g. `AU64` is [`AtomicU64`]). The seqlock
//! contract: a writer increments `seq` to odd, stores the per-sample fields
//! with `Relaxed` ordering, then increments `seq` to even. A reader observes
//! the slot's `state` and `generation`, loads `seq` twice around the field
//! reads, and accepts the snapshot only when both seqs are equal-even,
//! the generation has not advanced, and the state stayed in
//! `{Active, Stale}` throughout.

use std::sync::atomic::{AtomicI32, AtomicI64, AtomicU8, AtomicU16, AtomicU32, AtomicU64};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Magic value identifying a microsandbox metrics registry.
///
/// ASCII "MSBMET01" (8 bytes).
pub const REGISTRY_MAGIC: u64 = 0x3130_5445_4d42_534d;

/// On-disk layout version. Bump on any incompatible layout change.
pub const REGISTRY_VERSION: u32 = 1;

/// Default slot capacity used by the host process when global config does
/// not override it. At 512 bytes per slot, 1024 slots = ~512 KiB plus the
/// 256-byte header — enough headroom for the documented 20–560 sandbox
/// range without paying an 8 MiB always-mapped tax for capacity nobody uses.
pub const DEFAULT_CAPACITY: u32 = 1024;

/// Maximum bytes reserved for the sandbox name inside a slot.
pub const NAME_BYTES: usize = 128;

/// Size of one slot in bytes. Sized at 512 bytes so a slot occupies a single
/// CPU cache-line group on common platforms while leaving headroom for future
/// fields without breaking compatibility within the current version.
pub const SLOT_SIZE: usize = 512;

/// Size of the registry header in bytes.
pub const HEADER_SIZE: usize = 256;

//--------------------------------------------------------------------------------------------------
// Constants: Header state values
//--------------------------------------------------------------------------------------------------

/// Header state: uninitialized memory after `ftruncate`.
pub const HEADER_STATE_UNINIT: u32 = 0;
/// Header state: the creating process is still writing the header.
pub const HEADER_STATE_INITIALIZING: u32 = 1;
/// Header state: header is valid and slots are usable.
pub const HEADER_STATE_READY: u32 = 2;

//--------------------------------------------------------------------------------------------------
// Constants: Slot state values
//--------------------------------------------------------------------------------------------------

/// Slot state: free for allocation.
pub const SLOT_FREE: u32 = 0;
/// Slot state: reserved by the launcher, runtime has not attached yet.
pub const SLOT_RESERVED: u32 = 1;
/// Slot state: runtime attached and writing samples.
pub const SLOT_ACTIVE: u32 = 2;
/// Slot state: writer exited cleanly; last sample preserved for readers and
/// the slot may be reused by the allocator.
pub const SLOT_STALE: u32 = 3;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Registry header. Lives at offset `0` of the mapped region.
#[repr(C)]
pub struct Header {
    /// Magic identifier (`REGISTRY_MAGIC`).
    pub magic: u64,
    /// Layout version (`REGISTRY_VERSION`).
    pub version: u32,
    /// Length of the header in bytes (`HEADER_SIZE`).
    pub header_len: u32,
    /// Length of one slot in bytes (`SLOT_SIZE`).
    pub slot_len: u32,
    /// Number of slots allocated after the header.
    pub capacity: u32,
    /// Initialization state (`HEADER_STATE_*`).
    pub state: AtomicU32,
    /// Unix milliseconds at which the registry was created.
    pub created_at_unix_ms: i64,
    /// Monotonically increasing counter used to mint per-slot generations.
    pub global_generation: AtomicU64,
    /// Reserved for future fields. Keeps the header at a fixed `HEADER_SIZE`
    /// so callers built against older versions can map newer registries
    /// after a version bump that is binary-compatible.
    _reserved: [u8; HEADER_SIZE - 48],
}

const _: () = assert!(std::mem::size_of::<Header>() == HEADER_SIZE);

/// One metrics slot. Lives at offset `HEADER_SIZE + slot_index * SLOT_SIZE`.
#[repr(C)]
pub struct Slot {
    /// Slot lifecycle state (`SLOT_*`).
    pub state: AtomicU32,
    /// Generation stamp paired with the slot index for ABA protection.
    pub generation: AtomicU64,
    /// Seqlock counter. Odd while a writer is mutating the sample.
    pub seq: AtomicU64,
    /// Catalog sandbox id of the current owner.
    pub sandbox_id: AtomicI32,
    /// Catalog run id of the current owner. `0` while reserved.
    pub run_id: AtomicI32,
    /// PID of the runtime process. `0` while reserved.
    pub pid: AtomicI32,
    /// Padding to align the i64 fields without depending on the compiler.
    _pad0: u32,
    /// Unix milliseconds at which the sandbox process started.
    pub started_at_unix_ms: AtomicI64,
    /// Unix milliseconds at which the most recent sample was written.
    pub sampled_at_unix_ms: AtomicI64,
    /// Configured memory limit in bytes.
    pub memory_limit_bytes: AtomicU64,
    /// Raw bits of an `f32` carrying CPU usage as a percentage.
    pub cpu_percent_bits: AtomicU32,
    /// Resident memory in bytes.
    pub memory_bytes: AtomicU64,
    /// Cumulative disk bytes read.
    pub disk_read_bytes: AtomicU64,
    /// Cumulative disk bytes written.
    pub disk_write_bytes: AtomicU64,
    /// Cumulative network bytes received.
    pub net_rx_bytes: AtomicU64,
    /// Cumulative network bytes transmitted.
    pub net_tx_bytes: AtomicU64,
    /// Length of the bytes in `name_bytes` that are valid UTF-8 name data.
    pub name_len: AtomicU16,
    /// Padding before the byte array so trailing atomics align cleanly.
    _pad1: [AtomicU8; 6],
    /// UTF-8 encoded sandbox name, truncated to `NAME_BYTES`.
    pub name_bytes: [AtomicU8; NAME_BYTES],
    /// Padding to round the struct up to `SLOT_SIZE`.
    _tail: [u8; SLOT_TAIL_PAD],
}

// Layout accounting (with `#[repr(C)]` alignment), in offset order:
//   state(4) + pad(4) + generation(8) + seq(8)                              =  24
//   sandbox_id(4) + run_id(4) + pid(4) + _pad0(4)                           = +16  -> 40
//   started_at(8) + sampled_at(8) + memory_limit_bytes(8)                   = +24  -> 64
//   cpu_percent_bits(4) + pad(4) + memory_bytes(8)                          = +16  -> 80
//   disk_read(8) + disk_write(8) + net_rx(8) + net_tx(8)                    = +32  -> 112
//   name_len(2) + _pad1(6) + name_bytes(NAME_BYTES)                         = +8 + NAME_BYTES
const SLOT_BASE_BYTES: usize = 120 + NAME_BYTES;

const SLOT_TAIL_PAD: usize = SLOT_SIZE - SLOT_BASE_BYTES;

const _: () = assert!(std::mem::size_of::<Slot>() == SLOT_SIZE);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Total bytes required to map a registry with `capacity` slots.
pub const fn registry_size(capacity: u32) -> usize {
    HEADER_SIZE + (capacity as usize) * SLOT_SIZE
}
