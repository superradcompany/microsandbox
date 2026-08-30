// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{io, mem, result};

use virtio_bindings::virtio_net::virtio_net_hdr_v1;

use super::QueueConfig;

pub const MAX_BUFFER_SIZE: usize = 65562;
const QUEUE_SIZE: u16 = 1024;
pub const NUM_QUEUES: usize = 2;
pub static QUEUE_CONFIG: [QueueConfig; NUM_QUEUES] = [QueueConfig::new(QUEUE_SIZE); NUM_QUEUES];

pub mod backend;
pub mod device;
#[cfg(windows)]
pub mod namedpipe;
pub mod rate_limit;
#[cfg(target_os = "linux")]
mod tap;
#[cfg(unix)]
pub mod unixgram;
#[cfg(unix)]
pub mod unixstream;
mod worker;

fn vnet_hdr_len() -> usize {
    mem::size_of::<virtio_net_hdr_v1>()
}

// This initializes to all 0 the virtio_net_hdr part of a buf and return the length of the header
// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-2050006
fn write_virtio_net_hdr(buf: &mut [u8]) -> usize {
    let len = vnet_hdr_len();
    buf[0..len].fill(0);
    len
}

pub use self::device::Net;
#[derive(Debug)]
pub enum Error {
    /// EventFd error.
    EventFd(io::Error),
    /// Invalid receive rate limiter.
    InvalidRxRateLimiter(rate_limit::RateLimiterConfigError),
    /// Invalid transmit rate limiter.
    InvalidTxRateLimiter(rate_limit::RateLimiterConfigError),
}

pub type Result<T> = result::Result<T, Error>;
