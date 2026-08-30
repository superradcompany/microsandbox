// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

mod backend;
mod custom_stream;
mod device;
#[cfg(unix)]
mod dgram;
mod event_handler;
#[cfg(unix)]
mod muxer;
#[cfg(windows)]
#[path = "muxer_windows.rs"]
mod muxer;
mod muxer_rxq;
#[cfg(unix)]
mod muxer_thread;
#[cfg(windows)]
#[path = "muxer_thread_windows.rs"]
mod muxer_thread;
#[allow(dead_code)]
mod packet;
mod proxy;
mod reaper;
#[cfg(target_os = "macos")]
mod timesync;
#[cfg(unix)]
mod tsi_dgram;
#[cfg(unix)]
mod tsi_stream;
#[cfg(unix)]
mod unix;

pub use self::backend::{
    VsockConnectRequest, VsockConnectState, VsockDatagramBackend, VsockDatagramPeer,
    VsockDatagramPortBackend, VsockDatagramRead, VsockNotifier, VsockPollable, VsockPortBackend,
    VsockShutdown, VsockStreamBackend,
};
pub use self::defs::uapi::VIRTIO_ID_VSOCK as TYPE_VSOCK;
pub use self::defs::TsiFlags;
pub use self::device::Vsock;

use bitflags::bitflags;
use vm_memory::GuestMemoryError;

mod defs {
    use super::bitflags;

    bitflags! {
        /// TSI (Transparent Socket Impersonation) feature flags.
        ///
        /// These flags control which socket families are hijacked by TSI.
        pub struct TsiFlags: u32 {
            /// Hijack AF_INET and AF_INET6 sockets
            const HIJACK_INET = 1 << 0;
            /// Hijack AF_UNIX sockets
            const HIJACK_UNIX = 1 << 1;
        }
    }

    impl TsiFlags {
        /// Returns true if any TSI hijacking is enabled.
        pub fn tsi_enabled(&self) -> bool {
            !self.is_empty()
        }
    }

    impl Default for TsiFlags {
        fn default() -> Self {
            TsiFlags::empty()
        }
    }
    /// Device ID used in MMIO device identification.
    /// Because Vsock is unique per-vm, this ID can be hardcoded.
    pub const VSOCK_DEV_ID: &str = "vsock";

    use crate::virtio::QueueConfig;

    /// Number of virtio queues.
    pub const NUM_QUEUES: usize = 3;
    const QUEUE_SIZE: u16 = 256;
    /// Virtio queue config.
    /// There are 3 queues for a virtio device (in this order): RX, TX, Event
    pub static QUEUE_CONFIG: [QueueConfig; NUM_QUEUES] = [QueueConfig::new(QUEUE_SIZE); NUM_QUEUES];

    /// Max vsock packet data/buffer size.
    pub const MAX_PKT_BUF_SIZE: usize = 64 * 1024;

    /// Size of the muxer RX packet queue.
    pub const MUXER_RXQ_SIZE: usize = 256;

    // Kernel side doesn't play nice with us supporting so many bytes
    //pub const CONN_TX_BUF_SIZE: usize = i32::MAX as usize;
    pub const CONN_TX_BUF_SIZE: usize = 8 * 1024 * 1024;
    #[cfg(unix)]
    pub const SOCK_STREAM: u16 = 1;
    #[cfg(unix)]
    pub const SOCK_DGRAM: u16 = 2;

    /// Misc
    #[cfg(unix)]
    pub const TSI_PROXY_PORT: u32 = 620;
    #[cfg(unix)]
    pub const TSI_PROXY_CREATE: u32 = 1024;
    #[cfg(unix)]
    pub const TSI_CONNECT: u32 = 1025;
    #[cfg(unix)]
    pub const TSI_GETNAME: u32 = 1026;
    #[cfg(unix)]
    pub const TSI_SENDTO_ADDR: u32 = 1027;
    #[cfg(unix)]
    pub const TSI_SENDTO_DATA: u32 = 1028;
    #[cfg(unix)]
    pub const TSI_LISTEN: u32 = 1029;
    #[cfg(unix)]
    pub const TSI_ACCEPT: u32 = 1030;
    #[cfg(unix)]
    pub const TSI_PROXY_RELEASE: u32 = 1031;

    // Linux definitions that we need for cross-platform compatibility.
    #[cfg(unix)]
    pub const LINUX_AF_UNIX: u16 = 1;
    #[cfg(unix)]
    pub const LINUX_AF_INET: u16 = 2;
    #[cfg(unix)]
    pub const LINUX_AF_INET6: u16 = 10;

    pub mod uapi {

        /// Virtio feature flags.
        /// Defined in `/include/uapi/linux/virtio_config.h`.
        ///
        /// The device processes available buffers in the same order in which the device
        /// offers them.
        pub const VIRTIO_F_IN_ORDER: usize = 35;
        /// The device conforms to the virtio spec version 1.0.
        pub const VIRTIO_F_VERSION_1: u32 = 32;
        /// The device supports DGRAM.
        pub const VIRTIO_VSOCK_F_DGRAM: u32 = 3;

        /// Virtio vsock device ID.
        /// Defined in `include/uapi/linux/virtio_ids.h`.
        pub const VIRTIO_ID_VSOCK: u32 = 19;

        /// Vsock packet operation IDs.
        /// Defined in `/include/uapi/linux/virtio_vsock.h`.
        ///
        /// Connection request.
        pub const VSOCK_OP_REQUEST: u16 = 1;
        /// Connection response.
        pub const VSOCK_OP_RESPONSE: u16 = 2;
        /// Connection reset.
        pub const VSOCK_OP_RST: u16 = 3;
        /// Connection clean shutdown.
        pub const VSOCK_OP_SHUTDOWN: u16 = 4;
        /// Connection data (read/write).
        pub const VSOCK_OP_RW: u16 = 5;
        /// Flow control credit update.
        pub const VSOCK_OP_CREDIT_UPDATE: u16 = 6;
        /// Flow control credit update request.
        pub const VSOCK_OP_CREDIT_REQUEST: u16 = 7;

        /// Vsock packet flags.
        /// Defined in `/include/uapi/linux/virtio_vsock.h`.
        ///
        /// Valid with a VSOCK_OP_SHUTDOWN packet: the packet sender will receive no more data.
        pub const VSOCK_FLAGS_SHUTDOWN_RCV: u32 = 1;
        /// Valid with a VSOCK_OP_SHUTDOWN packet: the packet sender will send no more data.
        pub const VSOCK_FLAGS_SHUTDOWN_SEND: u32 = 2;

        /// Vsock packet type.
        /// Defined in `/include/uapi/linux/virtio_vsock.h`.
        ///
        /// Stream / connection-oriented packet (the only currently valid type).
        pub const VSOCK_TYPE_STREAM: u16 = 1;
        //pub const VSOCK_TYPE_SEQPACKET: u16 = 2;
        pub const VSOCK_TYPE_DGRAM: u16 = 3;

        pub const VSOCK_HOST_CID: u64 = 2;
    }
}

#[derive(Debug)]
pub enum VsockError {
    /// The vsock data/buffer virtio descriptor length is smaller than expected.
    BufDescTooSmall,
    /// The vsock data/buffer virtio descriptor is expected, but missing.
    BufDescMissing,
    /// Chained GuestMemoryMmap error.
    GuestMemoryMmap(GuestMemoryError),
    /// Bounds check failed on guest memory pointer.
    GuestMemoryBounds,
    /// The vsock header descriptor length is too small.
    HdrDescTooSmall(u32),
    /// The vsock header `len` field holds an invalid value.
    InvalidPktLen(u32),
    /// A data fetch was attempted when no data was available.
    NoData,
    /// A data buffer was expected for the provided packet, but it is missing.
    PktBufMissing,
    /// Encountered an unexpected write-only virtio descriptor.
    UnreadableDescriptor,
    /// Encountered an unexpected read-only virtio descriptor.
    UnwritableDescriptor,
    /// EventFd error
    EventFd(std::io::Error),
}

type Result<T> = std::result::Result<T, VsockError>;
