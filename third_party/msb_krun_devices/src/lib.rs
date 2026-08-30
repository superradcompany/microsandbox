// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Emulates virtual and hardware devices.

#[macro_use]
extern crate log;

use std::fmt;
use std::io;

mod bus;
#[cfg(all(
    any(target_arch = "aarch64", target_arch = "riscv64"),
    any(target_arch = "aarch64", not(target_os = "windows"))
))]
pub mod fdt;
pub mod legacy;
pub mod virtio;
#[cfg(target_os = "windows")]
pub(crate) mod windows;

pub use self::bus::{Bus, BusDevice, Error as BusError};

#[derive(Debug)]
pub enum Error {
    FailedReadingQueue {
        event_type: &'static str,
        underlying: io::Error,
    },
    FailedReadTap,
    FailedSignalingUsedQueue(io::Error),
    PayloadExpected,
    IoError(io::Error),
    NoAvailBuffers,
    SpuriousEvent,
}

/// Types of devices that can get attached to this platform.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Copy)]
pub enum DeviceType {
    /// Device Type: Virtio.
    Virtio(u32),
    /// Device Type: GPIO (PL061).
    #[cfg(target_arch = "aarch64")]
    Gpio,
    /// Device Type: Serial.
    #[cfg(all(
        any(target_arch = "aarch64", target_arch = "riscv64"),
        any(target_arch = "aarch64", not(target_os = "windows"))
    ))]
    Serial,
    /// Device Type: RTC.
    #[cfg(target_arch = "aarch64")]
    RTC,
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
