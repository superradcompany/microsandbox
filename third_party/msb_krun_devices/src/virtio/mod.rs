// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Implements virtio devices, queues, and transport mechanisms.
use std;
use std::any::Any;
use std::io::Error as IOError;

#[cfg(not(feature = "tee"))]
pub mod balloon;
#[allow(dead_code)]
#[allow(non_camel_case_types)]
pub mod bindings;
#[cfg(feature = "blk")]
pub mod block;
pub mod console;
pub mod descriptor_utils;
pub mod device;
#[cfg(any(not(target_os = "windows"), feature = "blk"))]
pub mod file_traits;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub mod fs;
#[cfg(feature = "gpu")]
pub mod gpu;
#[cfg(feature = "input")]
pub mod input;
// linux_errno.rs is now compiled on Windows too: its match arms use symbolic
// libc:: constants, so `libc::ENOSYS => LINUX_ENOSYS` correctly translates the
// Windows CRT value (40) to the Linux value (38). Arms for errnos absent from
// the Windows CRT are cfg-gated inside the module. This replaces the old
// Windows inline stub that passed the host errno through untranslated, which
// mistranslated ENOSYS(40) into Linux ELOOP(40) and broke guest statx().
pub mod linux_errno;
// The CPU capacity module is compiled under every feature: TEE builds never
// instantiate the device (extra capacity is rejected at config time), but the
// vCPU run loops still reference its enforcement types unconditionally.
pub mod cpu;
#[cfg(not(feature = "tee"))]
pub mod mem;
mod mmio;
pub mod msb_metrics;
#[cfg(feature = "net")]
pub mod net;
mod queue;
#[cfg(all(not(target_os = "windows"), not(feature = "tee")))]
pub mod rng;
#[cfg(feature = "snd")]
pub mod snd;
// Preserve vsock for existing Unix TEE builds while enabling it for ordinary
// Windows guests. Windows TEE combinations continue to omit the device.
#[cfg(any(not(target_os = "windows"), not(feature = "tee")))]
pub mod vsock;

#[cfg(not(feature = "tee"))]
pub use self::balloon::*;
#[cfg(feature = "blk")]
pub use self::block::{Block, CacheType};
pub use self::console::*;
pub use self::cpu::*;
pub use self::device::*;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub use self::fs::*;
#[cfg(feature = "gpu")]
pub use self::gpu::*;
#[cfg(not(feature = "tee"))]
pub use self::mem::*;
pub use self::mmio::*;
pub use self::msb_metrics::*;
#[cfg(feature = "net")]
pub use self::net::Net;
pub use self::queue::{Descriptor, DescriptorChain, Queue};
#[cfg(all(not(target_os = "windows"), not(feature = "tee")))]
pub use self::rng::*;
#[cfg(feature = "snd")]
pub use self::snd::Snd;
#[cfg(any(not(target_os = "windows"), not(feature = "tee")))]
pub use self::vsock::*;

/// When the driver initializes the device, it lets the device know about the
/// completed stages using the Device Status Field.
///
/// These following consts are defined in the order in which the bits would
/// typically be set by the driver. INIT -> ACKNOWLEDGE -> DRIVER and so on.
///
/// This module is a 1:1 mapping for the Device Status Field in the virtio 1.0
/// specification, section 2.1.
mod device_status {
    pub const INIT: u32 = 0;
    pub const ACKNOWLEDGE: u32 = 1;
    pub const DRIVER: u32 = 2;
    pub const FAILED: u32 = 128;
    pub const FEATURES_OK: u32 = 8;
    pub const DRIVER_OK: u32 = 4;
}

/// Types taken from linux/virtio_ids.h.
/// Type 0 is not used by virtio. Use it as wildcard for non-virtio devices
pub const TYPE_NET: u32 = 1;
pub const TYPE_BLOCK: u32 = 2;

/// Interrupt flags (re: interrupt status & acknowledge registers).
/// See linux/virtio_mmio.h.
pub const VIRTIO_MMIO_INT_VRING: u32 = 0x01;
pub const VIRTIO_MMIO_INT_CONFIG: u32 = 0x02;

/// Offset from the base MMIO address of a virtio device used by the guest to notify the device of
/// queue events.
pub const NOTIFY_REG_OFFSET: u32 = 0x50;

#[derive(Debug)]
pub enum ActivateError {
    EpollCtl(IOError),
    BadActivate,
}

pub type ActivateResult = std::result::Result<(), ActivateError>;

/// Trait that helps in upcasting an object to Any
pub trait AsAny {
    fn as_any(&self) -> &dyn Any;

    fn as_mut_any(&mut self) -> &mut dyn Any;
}
impl<T: Any> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}
