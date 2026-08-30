// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

pub mod aia;
pub mod gic;
#[cfg(target_os = "macos")]
mod gicv3;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod hvfgicv3;
mod i8042;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod ioapic;
mod irqchip;
#[cfg(all(target_os = "linux", target_arch = "riscv64"))]
mod kvmaia;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod kvmgicv2;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod kvmgicv3;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod kvmioapic;
#[cfg(all(not(target_os = "windows"), target_arch = "aarch64"))]
mod rtc_pl031;
#[cfg(target_os = "macos")]
mod vcpu;
#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
use x86_64::cmos;
#[cfg(target_arch = "x86_64")]
use x86_64::serial;
#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(all(not(target_os = "windows"), target_arch = "aarch64"))]
use aarch64::gpio;
#[cfg(target_arch = "aarch64")]
use aarch64::serial;
#[cfg(target_arch = "riscv64")]
mod riscv64;
#[cfg(target_arch = "riscv64")]
use riscv64::serial;

#[cfg(target_arch = "x86_64")]
pub use self::cmos::Cmos;
#[cfg(target_os = "macos")]
pub use self::gicv3::GicV3;
#[cfg(all(not(target_os = "windows"), target_arch = "aarch64"))]
pub use self::gpio::Gpio;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use self::hvfgicv3::HvfGicV3;
pub use self::i8042::Error as I8042DeviceError;
pub use self::i8042::I8042Device;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use self::ioapic::IoApic;
#[cfg(any(test, feature = "test_utils"))]
pub use self::irqchip::test_utils::DummyIrqChip;
pub use self::irqchip::{IrqChip, IrqChipDevice, IrqChipT};
#[cfg(all(target_os = "linux", target_arch = "riscv64"))]
pub use self::kvmaia::KvmAia;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use self::kvmgicv2::KvmGicV2;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use self::kvmgicv3::KvmGicV3;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use self::kvmioapic::KvmIoapic;
#[cfg(all(not(target_os = "windows"), target_arch = "aarch64"))]
pub use self::rtc_pl031::RTC;
#[cfg(any(
    not(target_os = "windows"),
    target_arch = "aarch64",
    target_arch = "x86_64"
))]
pub use self::serial::Serial;
#[cfg(target_os = "macos")]
pub use self::vcpu::VcpuList;

// Cannot use multiple types as bounds for a trait object, so we define our own trait
// which is a composition of the desired bounds. In this case, io::Read and AsRawFd.
// Run `rustc --explain E0225` for more details.
/// Trait that composes the `std::io::Read` and `std::os::unix::io::AsRawFd` traits.
#[cfg(unix)]
pub trait ReadableFd: std::io::Read + std::os::fd::AsRawFd {}

#[cfg(unix)]
impl ReadableFd for std::fs::File {}

#[cfg(windows)]
pub trait ReadableFd: std::io::Read {}

#[cfg(windows)]
impl<T: std::io::Read> ReadableFd for T {}

#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct GicV3 {}

#[cfg(target_os = "linux")]
impl GicV3 {
    pub fn set_irq(&self, _irq: u32) {}
}
