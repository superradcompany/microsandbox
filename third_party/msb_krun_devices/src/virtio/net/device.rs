// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
use crate::virtio::net::Result;
use crate::virtio::net::{NUM_QUEUES, QUEUE_CONFIG};
use crate::virtio::queue::Error as QueueError;
use crate::virtio::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, InterruptTransport, QueueConfig,
    VirtioDevice, TYPE_NET,
};
use crate::Error as DeviceError;

use super::backend::{NetBackend, ReadError, WriteError};
use super::rate_limit::RateLimiters;
use super::worker::NetWorker;

use std::cmp;
use std::io::Write;
#[cfg(unix)]
use std::os::fd::RawFd;
#[cfg(unix)]
use std::path::PathBuf;
use virtio_bindings::virtio_net::VIRTIO_NET_F_MAC;
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::{ByteValued, GuestMemoryError, GuestMemoryMmap};

const VIRTIO_F_VERSION_1: u32 = 32;

#[derive(Debug)]
pub enum FrontendError {
    DescriptorChainTooSmall,
    EmptyQueue,
    GuestMemory(GuestMemoryError),
    QueueError(QueueError),
    ReadOnlyDescriptor,
}

#[derive(Debug)]
pub enum RxError {
    Backend(ReadError),
    DeviceError(DeviceError),
}

#[derive(Debug)]
pub enum TxError {
    Backend(WriteError),
    DeviceError(DeviceError),
    QueueError(QueueError),
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioNetConfig {
    mac: [u8; 6],
    status: u16,
    max_virtqueue_pairs: u16,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioNetConfig {}

pub enum VirtioNetBackend {
    #[cfg(unix)]
    UnixstreamFd(RawFd),
    #[cfg(unix)]
    UnixstreamPath(PathBuf),
    #[cfg(unix)]
    UnixgramFd(RawFd),
    #[cfg(unix)]
    UnixgramPath(PathBuf, bool),
    #[cfg(target_os = "linux")]
    Tap(String),
    #[cfg(windows)]
    NamedPipe(String),
    Custom(Box<dyn NetBackend + Send>),
}

pub struct Net {
    id: String,
    pub cfg_backend: Option<VirtioNetBackend>,
    rate_limiters: RateLimiters,

    avail_features: u64,
    acked_features: u64,

    pub(crate) device_state: DeviceState,

    config: VirtioNetConfig,
}

impl Net {
    /// Create a new virtio network device using the backend
    pub fn new(
        id: String,
        cfg_backend: VirtioNetBackend,
        mac: [u8; 6],
        features: u32,
    ) -> Result<Self> {
        Self::new_with_rate_limiters(id, cfg_backend, mac, features, RateLimiters::default())
    }

    /// Create a virtio network device with receive and transmit rate limiters.
    pub fn new_with_rate_limiters(
        id: String,
        cfg_backend: VirtioNetBackend,
        mac: [u8; 6],
        features: u32,
        rate_limiters: RateLimiters,
    ) -> Result<Self> {
        if let Some(config) = &rate_limiters.rx {
            config
                .validate()
                .map_err(super::Error::InvalidRxRateLimiter)?;
        }
        if let Some(config) = &rate_limiters.tx {
            config
                .validate()
                .map_err(super::Error::InvalidTxRateLimiter)?;
        }

        let avail_features = features as u64
            | (1 << VIRTIO_NET_F_MAC)
            | (1 << VIRTIO_RING_F_EVENT_IDX)
            | (1 << VIRTIO_F_VERSION_1);

        let config = VirtioNetConfig {
            mac,
            status: 0,
            max_virtqueue_pairs: 0,
        };

        Ok(Net {
            id,
            cfg_backend: Some(cfg_backend),
            rate_limiters,

            avail_features,
            acked_features: 0u64,

            device_state: DeviceState::Inactive,
            config,
        })
    }

    /// Provides the ID of this net device.
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl VirtioDevice for Net {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn device_type(&self) -> u32 {
        TYPE_NET
    }

    fn device_name(&self) -> &str {
        "net"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &QUEUE_CONFIG
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        log::warn!(
            "Net: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        let [rx_q, tx_q]: [_; NUM_QUEUES] = queues.try_into().map_err(|_| {
            error!("Cannot perform activate. Expected {} queue(s)", NUM_QUEUES);
            ActivateError::BadActivate
        })?;

        let cfg_backend = self.cfg_backend.take().ok_or_else(|| {
            error!("Cannot activate net device: backend already taken");
            ActivateError::BadActivate
        })?;
        match NetWorker::new(
            rx_q,
            tx_q,
            interrupt.clone(),
            mem.clone(),
            self.acked_features,
            cfg_backend,
            &self.rate_limiters,
        ) {
            Ok(worker) => {
                worker.run();
                self.device_state = DeviceState::Activated(mem, interrupt);
                Ok(())
            }
            Err(err) => {
                error!(
                    "Error activating virtio-net ({}) backend: {err:?}",
                    self.id()
                );
                Err(ActivateError::BadActivate)
            }
        }
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }
}
