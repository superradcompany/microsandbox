// Copyright 2025 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub trait AIADevice {
    /// Returns the compatibility property of APLIC
    fn aplic_compatibility(&self) -> &str;

    /// Returns an array with APLIC device properties
    fn aplic_properties(&self) -> [u32; 4];

    /// Returns the compatibility property of IMSIC
    fn imsic_compatibility(&self) -> &str;

    /// Returns an array with IMSIC device properties
    fn imsic_properties(&self) -> [u32; 4];

    /// Returns the number of vCPUs this AIA handles
    fn vcpu_count(&self) -> u32;

    /// Returns whether the AIA device is MSI compatible or not
    fn msi_compatible(&self) -> bool;
}
