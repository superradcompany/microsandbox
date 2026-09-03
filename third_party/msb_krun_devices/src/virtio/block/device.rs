// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#[cfg(target_os = "linux")]
use std::cell::RefCell;
use std::cmp;
use std::convert::From;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::os::macos::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::result;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use imago::{
    file::File as ImagoFile, qcow2::Qcow2, raw::Raw, vmdk::Vmdk, DynStorage, FormatDriverBuilder,
    PermissiveImplicitOpenGate, Storage, StorageOpenOptions, SyncFormatAccess,
};
use log::{error, warn};
use utils::eventfd::{EventFd, EFD_NONBLOCK};
use utils::metrics::BlockMetricsWriter;
use virtio_bindings::{
    virtio_blk::*, virtio_config::VIRTIO_F_VERSION_1, virtio_ring::VIRTIO_RING_F_EVENT_IDX,
};
#[cfg(windows)]
use vm_memory::VolatileSlice;
use vm_memory::{ByteValued, GuestMemoryMmap};

#[cfg(windows)]
use super::windows::{
    PendingWindowsRawFileOperation, WindowsRawFile, WindowsRawFileBuffer, WindowsRawFileCompletion,
};
use super::worker::BlockWorker;
#[cfg(target_os = "linux")]
use super::writeback::{
    BufferedWritebackConfig, BufferedWritebackController, WritebackOutcome, WritebackReservation,
    MINIMUM_WRITEBACK_BUDGET_BYTES,
};
use super::{
    super::{ActivateResult, DeviceQueue, DeviceState, QueueConfig, VirtioDevice, TYPE_BLOCK},
    Error, WritebackLimit, NUM_QUEUES, QUEUE_CONFIG, SECTOR_SHIFT, SECTOR_SIZE,
};

use crate::virtio::{
    block::{ImageType, SyncMode},
    ActivateError, InterruptTransport,
};

#[cfg(target_os = "linux")]
const EXPLICIT_ZERO_BUFFER_BYTES: usize = 1024 * 1024;

/// Configuration options for disk caching.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CacheType {
    /// Flushing mechanic will be advertised to the guest driver, but
    /// the operation will be a noop.
    #[default]
    Unsafe,
    /// Flushing mechanic will be advertised to the guest driver and
    /// flush requests coming from the guest will be performed using
    /// `fsync`.
    Writeback,
}

impl CacheType {
    /// Picks the appropriate cache type based on disk image or device path.
    /// Special files like `/dev/rdisk*` on macOS do not support flush/sync.
    pub fn auto(_path: &str) -> CacheType {
        #[cfg(target_os = "macos")]
        if _path.starts_with("/dev/rdisk") {
            return CacheType::Unsafe;
        }
        CacheType::Writeback
    }
}

/// Helper object for setting up all `Block` fields derived from its backing file.
pub(crate) struct DiskProperties {
    cache_type: CacheType,
    pub(crate) file: Arc<Mutex<SyncFormatAccess<Box<dyn DynStorage>>>>,
    #[cfg(target_os = "linux")]
    // One block worker owns each DiskProperties instance. RefCell preserves the `&self` volatile
    // I/O trait while avoiding mutex atomics on every guest write; this must be revisited before
    // increasing NUM_QUEUES or sharing one DiskProperties between workers.
    writeback_controller: Option<RefCell<BufferedWritebackController>>,
    #[cfg(target_os = "linux")]
    // Keep the shared configuration handle so teardown sync results survive the per-activation
    // controller and can fail a later activation closed.
    writeback_config: Option<BufferedWritebackConfig>,
    #[cfg(target_os = "linux")]
    // Bounded mode must account real dirty data, so WRITE_ZEROES reuses this buffer instead of
    // invoking a filesystem hole-punch or metadata-only zeroing operation.
    explicit_zero_buffer: Option<Box<[u8]>>,
    #[cfg(windows)]
    windows_raw_file: Option<Arc<WindowsRawFile>>,
    #[cfg(windows)]
    pub(crate) windows_formatted_io_runtime: tokio::runtime::Runtime,
    nsectors: u64,
    image_id: Vec<u8>,
}

/// An exact mutation chunk paired with an optional Linux writeback reservation.
pub(crate) struct BufferedMutationPlan {
    length: u64,
    #[cfg(target_os = "linux")]
    reservation: Option<WritebackReservation>,
}

impl BufferedMutationPlan {
    pub(crate) fn len(&self) -> u64 {
        self.length
    }
}

impl DiskProperties {
    pub fn new(
        disk_image: Arc<Mutex<SyncFormatAccess<Box<dyn DynStorage>>>>,
        disk_image_id: Vec<u8>,
        cache_type: CacheType,
    ) -> io::Result<Self> {
        let disk_size = disk_image.lock().unwrap().size();

        // We only support disk size, which uses the first two words of the configuration space.
        // If the image is not a multiple of the sector size, the tail bits are not exposed.
        if !disk_size.is_multiple_of(SECTOR_SIZE) {
            warn!(
                "Disk size {disk_size} is not a multiple of sector size {SECTOR_SIZE}; \
                 the remainder will not be visible to the guest."
            );
        }

        Ok(Self {
            cache_type,
            nsectors: disk_size >> SECTOR_SHIFT,
            image_id: disk_image_id,
            file: disk_image,
            #[cfg(target_os = "linux")]
            writeback_controller: None,
            #[cfg(target_os = "linux")]
            writeback_config: None,
            #[cfg(target_os = "linux")]
            explicit_zero_buffer: None,
            #[cfg(windows)]
            windows_raw_file: None,
            #[cfg(windows)]
            windows_formatted_io_runtime: tokio::runtime::Builder::new_current_thread().build()?,
        })
    }

    pub fn nsectors(&self) -> u64 {
        self.nsectors
    }

    pub fn image_id(&self) -> &[u8] {
        &self.image_id
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn build_device_id(disk_file: &File) -> result::Result<String, Error> {
        let blk_metadata = disk_file.metadata().map_err(Error::GetFileMetadata)?;
        // This is how kvmtool does it.
        let device_id = format!(
            "{}{}{}",
            blk_metadata.st_dev(),
            blk_metadata.st_rdev(),
            blk_metadata.st_ino()
        );
        Ok(device_id)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn build_device_id(_disk_file: &File) -> result::Result<String, Error> {
        Err(Error::GetFileMetadata(io::Error::new(
            io::ErrorKind::Unsupported,
            "platform does not expose Unix device metadata",
        )))
    }

    fn build_disk_image_id(disk_file: &File) -> Vec<u8> {
        let mut default_id = vec![0; VIRTIO_BLK_ID_BYTES as usize];
        match Self::build_device_id(disk_file) {
            Err(_) => {
                warn!("Could not generate device id. We'll use a default.");
            }
            Ok(m) => {
                // The kernel only knows to read a maximum of VIRTIO_BLK_ID_BYTES.
                // This will also zero out any leftover bytes.
                let disk_id = m.as_bytes();
                let bytes_to_copy = cmp::min(disk_id.len(), VIRTIO_BLK_ID_BYTES as usize);
                default_id[..bytes_to_copy].clone_from_slice(&disk_id[..bytes_to_copy])
            }
        }
        default_id
    }

    pub fn cache_type(&self) -> CacheType {
        self.cache_type
    }

    pub(crate) fn flush_to_disk(&self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        let quiesce_error = self
            .writeback_controller
            .as_ref()
            .and_then(|controller| controller.borrow_mut().quiesce().err());

        #[cfg(windows)]
        if let Some(raw_file) = &self.windows_raw_file {
            raw_file.flush()?;
        }

        // The full Imago flush remains the guest-visible durability fence, so run it even after
        // the background controller fails. A successful later sync cannot erase a writeback error
        // already reported through the file description; that controller remains failed closed.
        let sync_result = {
            let diskfile = self.file.lock().unwrap();
            diskfile.flush().and_then(|_| diskfile.sync())
        };

        #[cfg(target_os = "linux")]
        match &sync_result {
            Ok(()) => {
                let config_healthy = self
                    .writeback_config
                    .as_ref()
                    .is_none_or(BufferedWritebackConfig::record_full_sync_success);
                let controller_healthy = self
                    .writeback_controller
                    .as_ref()
                    .is_none_or(|controller| controller.borrow_mut().reset_after_flush());

                if let Some(error) = quiesce_error {
                    warn!(
                        "Buffered writeback remains permanently failed after the full disk sync: \
                         {error}"
                    );
                    return Err(error);
                }
                if !config_healthy || !controller_healthy {
                    return Err(io::Error::other(
                        "buffered writeback remains permanently failed after the full disk sync",
                    ));
                }
            }
            Err(error) => {
                if let Some(config) = &self.writeback_config {
                    config.record_full_sync_failure(error);
                }
            }
        }

        sync_result
    }

    pub(crate) fn plan_buffered_mutation(
        &self,
        offset: u64,
        requested: u64,
    ) -> io::Result<BufferedMutationPlan> {
        #[cfg(not(target_os = "linux"))]
        let _ = offset;

        #[cfg(target_os = "linux")]
        {
            if requested != 0 {
                if let Some(controller) = &self.writeback_controller {
                    let reservation = controller.borrow_mut().plan_write(offset, requested)?;
                    return Ok(BufferedMutationPlan {
                        length: reservation.len(),
                        reservation: Some(reservation),
                    });
                }
            }
        }

        Ok(BufferedMutationPlan {
            length: requested,
            #[cfg(target_os = "linux")]
            reservation: None,
        })
    }

    pub(crate) fn finish_buffered_mutation(
        &self,
        plan: BufferedMutationPlan,
        operation_result: io::Result<()>,
    ) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        let accounting_result = match plan.reservation {
            Some(reservation) => {
                let outcome = if operation_result.is_ok() {
                    WritebackOutcome::Written(plan.length)
                } else {
                    // Imago may have completed a prefix before returning an error. Charge the
                    // entire reservation conservatively so repeated failing writes cannot bypass
                    // the hard budget.
                    WritebackOutcome::Failed
                };
                self.writeback_controller
                    .as_ref()
                    .expect("reservation requires an active writeback controller")
                    .borrow_mut()
                    .finish_write(reservation, outcome)
            }
            None => Ok(()),
        };

        #[cfg(not(target_os = "linux"))]
        let accounting_result: io::Result<()> = {
            let _ = plan;
            Ok(())
        };

        match operation_result {
            Ok(()) => accounting_result,
            Err(operation_error) => {
                if let Err(accounting_error) = accounting_result {
                    warn!(
                        "Buffered mutation failed and writeback accounting also failed: {accounting_error}"
                    );
                }
                Err(operation_error)
            }
        }
    }

    pub(crate) fn has_writeback_limit(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.writeback_config.is_some()
        }

        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Rejects a complete bounded mutation before any prefix can reach the backing image.
    ///
    /// Legacy disks retain Imago's existing range behavior. Bounded mode is stricter because
    /// truncating a request at the visible edge would violate its all-or-error range contract and
    /// let controller accounting describe a different mutation from the one the guest submitted.
    pub(crate) fn validate_mutation_range(&self, offset: u64, length: u64) -> io::Result<()> {
        if self.has_writeback_limit() {
            Self::validate_range_against_capacity(self.nsectors, offset, length)?;
        }
        Ok(())
    }

    fn validate_range_against_capacity(nsectors: u64, offset: u64, length: u64) -> io::Result<()> {
        let visible_size = nsectors.checked_mul(SECTOR_SIZE).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "visible block capacity overflow",
            )
        })?;
        let end = offset.checked_add(length).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "block mutation range overflow")
        })?;
        if end > visible_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "block mutation extends beyond visible capacity",
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn set_writeback_config(&mut self, config: Option<&BufferedWritebackConfig>) -> io::Result<()> {
        // Retain the shared health handle before any fallible setup. If controller recovery or
        // buffer allocation fails, DiskProperties::drop can still report its final sync result.
        self.writeback_config = config.cloned();
        let controller = config
            .map(BufferedWritebackConfig::controller)
            .transpose()?
            .map(RefCell::new);
        let explicit_zero_buffer = if config.is_some() {
            let mut buffer = Vec::new();
            buffer
                .try_reserve_exact(EXPLICIT_ZERO_BUFFER_BYTES)
                .map_err(io::Error::other)?;
            buffer.resize(EXPLICIT_ZERO_BUFFER_BYTES, 0);
            Some(buffer.into_boxed_slice())
        } else {
            None
        };

        self.explicit_zero_buffer = explicit_zero_buffer;
        self.writeback_controller = controller;
        Ok(())
    }

    pub(crate) fn discard_to_any(&self, offset: u64, length: u64) -> io::Result<()> {
        if self.has_writeback_limit() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "discard is disabled by the bounded writeback policy",
            ));
        }
        self.validate_mutation_range(offset, length)?;

        #[cfg(windows)]
        if let Some(raw_file) = &self.windows_raw_file {
            return raw_file.discard_to_any(offset, length);
        }

        let mut diskfile = self.file.lock().unwrap();
        diskfile.discard_to_any(offset, length)
    }

    pub(crate) fn discard_to_zero(&self, offset: u64, length: u64) -> io::Result<()> {
        if self.has_writeback_limit() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unmapping zero writes are disabled by the bounded writeback policy",
            ));
        }
        self.validate_mutation_range(offset, length)?;

        #[cfg(windows)]
        if let Some(raw_file) = &self.windows_raw_file {
            return raw_file.discard_to_zero(offset, length);
        }

        self.run_buffered_mutation(offset, length, None, |chunk_offset, chunk_length| {
            let mut diskfile = self.file.lock().unwrap();
            diskfile.discard_to_zero(chunk_offset, chunk_length)
        })
    }

    pub(crate) fn write_zeroes(&self, offset: u64, length: u64) -> io::Result<()> {
        self.validate_mutation_range(offset, length)?;

        #[cfg(target_os = "linux")]
        if let Some(zero_buffer) = &self.explicit_zero_buffer {
            return self.run_buffered_mutation(
                offset,
                length,
                Some(zero_buffer.len() as u64),
                |chunk_offset, chunk_length| {
                    let chunk_length = usize::try_from(chunk_length)
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
                    let diskfile = self.file.lock().unwrap();
                    diskfile.write(&zero_buffer[..chunk_length], chunk_offset)
                },
            );
        }

        #[cfg(windows)]
        if let Some(raw_file) = &self.windows_raw_file {
            return raw_file.write_zeroes(offset, length);
        }

        self.run_buffered_mutation(offset, length, None, |chunk_offset, chunk_length| {
            let diskfile = self.file.lock().unwrap();
            diskfile.write_zeroes(chunk_offset, chunk_length)
        })
    }

    fn run_buffered_mutation<F>(
        &self,
        offset: u64,
        length: u64,
        maximum_chunk: Option<u64>,
        mut operation: F,
    ) -> io::Result<()>
    where
        F: FnMut(u64, u64) -> io::Result<()>,
    {
        self.validate_mutation_range(offset, length)?;

        let mut chunk_offset = offset;
        let mut remaining = length;

        while remaining != 0 {
            let requested = maximum_chunk.map_or(remaining, |maximum| remaining.min(maximum));
            let plan = self.plan_buffered_mutation(chunk_offset, requested)?;
            let chunk_length = plan.len();
            let operation_result = operation(chunk_offset, chunk_length);
            self.finish_buffered_mutation(plan, operation_result)?;

            remaining -= chunk_length;
            if remaining != 0 {
                chunk_offset = chunk_offset.checked_add(chunk_length).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "block mutation range overflow")
                })?;
            }
        }

        Ok(())
    }

    #[cfg(windows)]
    fn set_windows_raw_file(&mut self, file: Option<Arc<WindowsRawFile>>) {
        self.windows_raw_file = file;
    }

    #[cfg(windows)]
    pub(crate) fn has_windows_raw_file(&self) -> bool {
        self.windows_raw_file.is_some()
    }

    #[cfg(windows)]
    pub(crate) fn windows_raw_can_submit_direct_buffer(
        &self,
        buffer: WindowsRawFileBuffer,
        offset: u64,
    ) -> bool {
        self.windows_raw_file
            .as_ref()
            .is_some_and(|file| file.can_submit_direct_buffer(buffer, offset))
    }

    #[cfg(windows)]
    pub(crate) fn submit_windows_raw_read_buffer(
        &self,
        buffer: WindowsRawFileBuffer,
        offset: u64,
    ) -> Option<io::Result<PendingWindowsRawFileOperation>> {
        self.windows_raw_file
            .as_ref()
            .map(|file| file.submit_read_buffer(buffer, offset))
    }

    #[cfg(windows)]
    pub(crate) fn submit_windows_raw_write_buffer(
        &self,
        buffer: WindowsRawFileBuffer,
        offset: u64,
    ) -> Option<io::Result<PendingWindowsRawFileOperation>> {
        self.windows_raw_file
            .as_ref()
            .map(|file| file.submit_write_buffer(buffer, offset))
    }

    #[cfg(windows)]
    pub(crate) fn submit_windows_raw_read_bounce(
        &self,
        offset: u64,
        len: usize,
    ) -> Option<io::Result<PendingWindowsRawFileOperation>> {
        self.windows_raw_file
            .as_ref()
            .map(|file| file.submit_read_bounce(offset, len))
    }

    #[cfg(windows)]
    pub(crate) fn submit_windows_raw_write_bounce(
        &self,
        offset: u64,
        buffer: Vec<u8>,
    ) -> Option<io::Result<PendingWindowsRawFileOperation>> {
        self.windows_raw_file
            .as_ref()
            .map(|file| file.submit_write_bounce(offset, buffer))
    }

    #[cfg(windows)]
    pub(crate) fn wait_windows_raw_completion(
        &self,
    ) -> Option<io::Result<WindowsRawFileCompletion>> {
        self.windows_raw_file
            .as_ref()
            .map(|file| file.wait_for_completion())
    }

    #[cfg(windows)]
    pub(crate) fn windows_raw_read_vectored_at_volatile(
        &self,
        bufs: &[VolatileSlice],
        offset: u64,
    ) -> Option<io::Result<usize>> {
        self.windows_raw_file
            .as_ref()
            .map(|file| file.read_vectored_at_volatile(bufs, offset))
    }

    #[cfg(windows)]
    pub(crate) fn windows_raw_write_vectored_at_volatile(
        &self,
        bufs: &[VolatileSlice],
        offset: u64,
    ) -> Option<io::Result<usize>> {
        self.windows_raw_file
            .as_ref()
            .map(|file| file.write_vectored_at_volatile(bufs, offset))
    }
}

impl Drop for DiskProperties {
    fn drop(&mut self) {
        match self.cache_type {
            CacheType::Writeback => {
                if self.flush_to_disk().is_err() {
                    error!("Failed to flush block data on drop.");
                }
            }
            CacheType::Unsafe => {
                // This is a noop.
            }
        };
    }
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioBlkGeometry {
    cylinders: u16,
    heads: u8,
    sectors: u8,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioBlkTopology {
    physical_block_exp: u8,
    alignment_offset: u8,
    min_io_size: u16,
    opt_io_size: u32,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioBlkConfig {
    capacity: u64,
    size_max: u32,
    seg_max: u32,
    geometry: VirtioBlkGeometry,
    blk_size: u32,
    topology: VirtioBlkTopology,
    writeback: u8,
    unused0: u8,
    num_queues: u16,
    max_discard_sectors: u32,
    max_discard_seg: u32,
    discard_sector_alignment: u32,
    max_write_zeroes_sectors: u32,
    max_write_zeroes_seg: u32,
    write_zeroes_may_unmap: u8,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioBlkConfig {}

/// Virtio device for exposing block level read/write operations on a host file.
pub struct Block {
    // Host file and properties.
    disk: Option<DiskProperties>,
    cache_type: CacheType,
    disk_image: Arc<Mutex<SyncFormatAccess<Box<dyn DynStorage>>>>,
    disk_image_id: Vec<u8>,
    #[cfg(target_os = "linux")]
    writeback_config: Option<BufferedWritebackConfig>,
    #[cfg(windows)]
    windows_raw_file: Option<Arc<WindowsRawFile>>,
    metrics: BlockMetricsWriter,
    worker_thread: Option<JoinHandle<()>>,
    worker_stopfd: EventFd,

    // Virtio fields.
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    config: VirtioBlkConfig,

    // Transport related fields.
    pub(crate) device_state: DeviceState,

    // Implementation specific fields.
    pub(crate) id: String,
    pub(crate) partuuid: Option<String>,
}

impl Block {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        partuuid: Option<String>,
        cache_type: CacheType,
        disk_image_path: String,
        disk_image_format: ImageType,
        is_disk_read_only: bool,
        direct_io: bool,
        sync_mode: SyncMode,
        metrics: BlockMetricsWriter,
    ) -> io::Result<Block> {
        Self::new_with_writeback_limit(
            id,
            partuuid,
            cache_type,
            disk_image_path,
            disk_image_format,
            is_disk_read_only,
            direct_io,
            sync_mode,
            None,
            metrics,
        )
    }

    /// Create a virtio block device with an optional hard buffered-writeback budget.
    ///
    /// Bounded writeback is supported on Linux for writable raw disks using writeback caching,
    /// buffered I/O and an active sync mode. The configured value is the per-device hard budget;
    /// libkrun derives smaller background batches and releases their credits only after completed
    /// range writeback. This does not replace the full sync that completes a guest flush. A zero
    /// value disables the policy.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_writeback_limit(
        id: String,
        partuuid: Option<String>,
        cache_type: CacheType,
        disk_image_path: String,
        disk_image_format: ImageType,
        is_disk_read_only: bool,
        direct_io: bool,
        sync_mode: SyncMode,
        writeback_limit_bytes: Option<u64>,
        metrics: BlockMetricsWriter,
    ) -> io::Result<Block> {
        Self::new_with_writeback_limit_handle(
            id,
            partuuid,
            cache_type,
            disk_image_path,
            disk_image_format,
            is_disk_read_only,
            direct_io,
            sync_mode,
            writeback_limit_bytes.map(WritebackLimit::new),
            metrics,
        )
    }

    /// Create a virtio block device with an optional live buffered-writeback budget.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_writeback_limit_handle(
        id: String,
        partuuid: Option<String>,
        cache_type: CacheType,
        disk_image_path: String,
        disk_image_format: ImageType,
        is_disk_read_only: bool,
        direct_io: bool,
        sync_mode: SyncMode,
        writeback_limit: Option<WritebackLimit>,
        metrics: BlockMetricsWriter,
    ) -> io::Result<Block> {
        // Keep zero equivalent to the builder's disabled state for callers of this lower-level API.
        let writeback_limit = writeback_limit.filter(|limit| limit.maximum_bytes() != 0);

        if matches!(disk_image_format, ImageType::Vmdk) && !is_disk_read_only {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "VMDK write support is not available; configure the disk as read-only",
            ));
        }

        if let Some(_hard_budget_bytes) =
            writeback_limit.as_ref().map(WritebackLimit::maximum_bytes)
        {
            #[cfg(target_os = "linux")]
            if _hard_budget_bytes < MINIMUM_WRITEBACK_BUDGET_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "writeback hard budget must be at least {MINIMUM_WRITEBACK_BUDGET_BYTES} bytes"
                    ),
                ));
            }

            #[cfg(not(target_os = "linux"))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "bounded writeback is only supported on Linux hosts",
            ));

            #[cfg(target_os = "linux")]
            if !matches!(disk_image_format, ImageType::Raw)
                || is_disk_read_only
                || direct_io
                || cache_type != CacheType::Writeback
                || sync_mode == SyncMode::None
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "bounded writeback requires a writable raw disk with writeback caching, buffered I/O and an active sync mode",
                ));
            }
        }

        let disk_image = OpenOptions::new()
            .read(true)
            .write(!is_disk_read_only)
            .open(PathBuf::from(&disk_image_path))?;

        #[cfg(windows)]
        let windows_raw_file = if matches!(&disk_image_format, ImageType::Raw) {
            Some(Arc::new(WindowsRawFile::open(
                &disk_image_path,
                is_disk_read_only,
                direct_io,
            )?))
        } else {
            None
        };

        // Use the caller-supplied `id` as the virtio-blk disk image id so
        // it surfaces in the guest at `/sys/block/<dev>/serial` and (when
        // udev is available) `/dev/disk/by-id/virtio-<id>`. Falls back to
        // the rdev+inode-derived default if `id` is empty.
        let disk_image_id = if id.is_empty() {
            DiskProperties::build_disk_image_id(&disk_image)
        } else {
            let mut padded = vec![0u8; VIRTIO_BLK_ID_BYTES as usize];
            let bytes = id.as_bytes();
            let n = cmp::min(bytes.len(), padded.len());
            padded[..n].copy_from_slice(&bytes[..n]);
            padded
        };

        #[cfg(target_os = "linux")]
        let writeback_config = match writeback_limit {
            Some(limit) => Some(BufferedWritebackConfig::new(
                Arc::new(disk_image.try_clone()?),
                limit,
            )?),
            None => None,
        };

        // Keep Imago on its established open path. When advisory writeback is active, procfs
        // provides a race-free name for the already-verified inode without giving Imago the
        // controller's file description or changing its storage implementation.
        #[cfg(target_os = "linux")]
        let imago_path = writeback_config
            .as_ref()
            .map(|_| format!("/proc/self/fd/{}", disk_image.as_raw_fd()))
            .unwrap_or_else(|| disk_image_path.clone());
        #[cfg(not(target_os = "linux"))]
        let imago_path = disk_image_path.clone();

        let file_opts = StorageOpenOptions::new()
            .write(!is_disk_read_only)
            .filename(&imago_path)
            .direct(direct_io);

        // Do not attach `RWF_DONTCACHE` to bounded writes. The controller already reserves every
        // dirty page before mutation and returns that credit only after verified writeback, while
        // the per-write hint would start eager writeback and collapse the finite cache window that
        // the hard budget is intended to bound.

        #[cfg(target_os = "macos")]
        let file_opts = file_opts.relaxed_sync(sync_mode == SyncMode::Relaxed);

        let file = ImagoFile::open_sync(file_opts)?;
        let discard_alignment = file.discard_align();

        let disk_image = match disk_image_format {
            ImageType::Qcow2 => {
                let mut qcow2 =
                    Qcow2::<Box<dyn DynStorage>, Arc<imago::FormatAccess<_>>>::open_image_sync(
                        Box::new(file),
                        !is_disk_read_only,
                    )?;
                qcow2.open_implicit_dependencies_sync()?;
                SyncFormatAccess::new(qcow2)?
            }
            ImageType::Raw => {
                let raw = Raw::<Box<dyn DynStorage>>::open_image_sync(
                    Box::new(file),
                    !is_disk_read_only,
                )?;
                SyncFormatAccess::new(raw)?
            }
            ImageType::Vmdk => {
                let vmdk = Vmdk::<Box<dyn DynStorage>, Arc<imago::FormatAccess<_>>>::builder(
                    Box::new(file),
                )
                .open_sync(PermissiveImplicitOpenGate::default())?;
                SyncFormatAccess::new(vmdk)?
            }
        };

        let disk_image = Arc::new(Mutex::new(disk_image));

        let disk_properties = {
            let disk_properties =
                DiskProperties::new(disk_image.clone(), disk_image_id.clone(), cache_type)?;
            #[cfg(windows)]
            {
                let mut disk_properties = disk_properties;
                disk_properties.set_windows_raw_file(windows_raw_file.clone());
                disk_properties
            }
            #[cfg(not(windows))]
            {
                disk_properties
            }
        };

        #[cfg(target_os = "linux")]
        let bounded_writeback_enabled = writeback_config.is_some();
        #[cfg(not(target_os = "linux"))]
        let bounded_writeback_enabled = false;

        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1)
            | (1u64 << VIRTIO_BLK_F_SEG_MAX)
            | (1u64 << VIRTIO_BLK_F_WRITE_ZEROES)
            | (1u64 << VIRTIO_RING_F_EVENT_IDX);

        // DISCARD and WRITE_ZEROES|UNMAP can create metadata-only holes that are invisible to
        // sync_file_range() accounting. Keep ordinary WRITE_ZEROES, but force it through explicit
        // zero-data writes while the hard writeback budget is active.
        if !bounded_writeback_enabled {
            avail_features |= 1u64 << VIRTIO_BLK_F_DISCARD;
        }

        if sync_mode != SyncMode::None {
            avail_features |= 1u64 << VIRTIO_BLK_F_FLUSH;
        }

        if is_disk_read_only {
            avail_features |= 1u64 << VIRTIO_BLK_F_RO;
        };

        let config = VirtioBlkConfig {
            capacity: disk_properties.nsectors(),
            size_max: 0,
            // QUEUE_SIZE - 2
            seg_max: 254,
            max_discard_sectors: if bounded_writeback_enabled {
                0
            } else {
                u32::MAX
            },
            max_discard_seg: u32::from(!bounded_writeback_enabled),
            discard_sector_alignment: if bounded_writeback_enabled {
                0
            } else {
                discard_alignment as u32 / 512
            },
            max_write_zeroes_sectors: u32::MAX,
            max_write_zeroes_seg: 1,
            write_zeroes_may_unmap: u8::from(!bounded_writeback_enabled),
            ..Default::default()
        };

        Ok(Block {
            id,
            partuuid,
            config,
            disk: Some(disk_properties),
            cache_type,
            disk_image,
            disk_image_id,
            #[cfg(target_os = "linux")]
            writeback_config,
            #[cfg(windows)]
            windows_raw_file,
            metrics,
            avail_features,
            acked_features: 0u64,
            device_state: DeviceState::Inactive,
            worker_thread: None,
            worker_stopfd: EventFd::new(EFD_NONBLOCK)?,
        })
    }

    /// Provides the ID of this block device.
    pub fn id(&self) -> &String {
        &self.id
    }

    /// Provides the PARTUUID of this block device.
    pub fn partuuid(&self) -> Option<&String> {
        self.partuuid.as_ref()
    }

    /// Specifies if this block device is read only.
    pub fn is_read_only(&self) -> bool {
        self.avail_features & (1u64 << VIRTIO_BLK_F_RO) != 0
    }

    fn stop_worker(&mut self) {
        if let Some(worker) = self.worker_thread.take() {
            if let Err(error) = self.worker_stopfd.write(1) {
                error!("error signaling block worker to stop: {error}");
            }
            if let Err(error) = worker.join() {
                error!("error waiting for block worker thread: {error:?}");
            }
        }
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if self.writeback_config.is_some() {
            // Dropping a JoinHandle detaches it. A detached bounded-writeback worker would retain
            // DiskProperties indefinitely, skipping its final sync and shared health update.
            self.stop_worker();
        }
    }
}

impl VirtioDevice for Block {
    fn device_type(&self) -> u32 {
        TYPE_BLOCK
    }

    fn device_name(&self) -> &str {
        "block"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &QUEUE_CONFIG
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
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

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        error!("Guest attempted to write config");
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if self.worker_thread.is_some() {
            panic!("virtio_blk: worker thread already exists");
        }

        let [blk_q]: [_; NUM_QUEUES] = queues.try_into().map_err(|_| {
            error!("Cannot perform activate. Expected {} queue(s)", NUM_QUEUES);
            ActivateError::BadActivate
        })?;

        let disk = match self.disk.take() {
            Some(d) => d,
            None => {
                let disk = DiskProperties::new(
                    Arc::clone(&self.disk_image),
                    self.disk_image_id.clone(),
                    self.cache_type,
                )
                .map_err(|_| ActivateError::BadActivate)?;
                #[cfg(windows)]
                {
                    let mut disk = disk;
                    disk.set_windows_raw_file(self.windows_raw_file.clone());
                    disk
                }
                #[cfg(not(windows))]
                {
                    disk
                }
            }
        };

        #[cfg(target_os = "linux")]
        let disk = {
            let mut disk = disk;
            disk.set_writeback_config(self.writeback_config.as_ref())
                .map_err(|error| {
                    error!("Cannot start bounded block writeback: {error}");
                    ActivateError::BadActivate
                })?;
            disk
        };

        let worker = BlockWorker::new(
            blk_q,
            interrupt.clone(),
            mem.clone(),
            disk,
            self.worker_stopfd.try_clone().unwrap(),
            self.metrics.clone(),
        );
        self.worker_thread = Some(worker.run());

        self.device_state = DeviceState::Activated(mem, interrupt);
        Ok(())
    }

    fn reset(&mut self) -> bool {
        self.stop_worker();
        self.device_state = DeviceState::Inactive;
        true
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use utils::metrics::MetricsWriter;
    #[cfg(target_os = "linux")]
    use utils::tempfile::TempFile;

    use super::*;

    #[test]
    fn writable_vmdk_is_rejected() {
        let result = Block::new(
            "vmdk".to_string(),
            None,
            CacheType::Unsafe,
            "missing.vmdk".to_string(),
            ImageType::Vmdk,
            false,
            false,
            SyncMode::None,
            MetricsWriter::default().register_block_device("vmdk".to_string()),
        );

        let error = match result {
            Ok(_) => panic!("writable VMDK should be rejected"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("VMDK write support"));
    }

    #[test]
    fn zero_writeback_limit_disables_the_policy() {
        let result = Block::new_with_writeback_limit(
            "raw".to_string(),
            None,
            CacheType::Unsafe,
            "missing.raw".to_string(),
            ImageType::Raw,
            false,
            true,
            SyncMode::None,
            Some(0),
            MetricsWriter::default().register_block_device("raw".to_string()),
        );

        let error = match result {
            Ok(_) => panic!("missing raw disk should fail"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn bounded_mutation_range_requires_full_visible_capacity() {
        let nsectors = 8;
        assert!(DiskProperties::validate_range_against_capacity(nsectors, 512, 3584).is_ok());

        let crossing_end =
            DiskProperties::validate_range_against_capacity(nsectors, 512, 4096).unwrap_err();
        assert_eq!(crossing_end.kind(), io::ErrorKind::InvalidInput);
        assert!(crossing_end.to_string().contains("visible capacity"));

        let past_end =
            DiskProperties::validate_range_against_capacity(nsectors, 4096, 512).unwrap_err();
        assert_eq!(past_end.kind(), io::ErrorKind::InvalidInput);

        let overflow =
            DiskProperties::validate_range_against_capacity(nsectors, u64::MAX, 1).unwrap_err();
        assert_eq!(overflow.kind(), io::ErrorKind::InvalidInput);
        assert!(overflow.to_string().contains("range overflow"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_writeback_advertises_only_accountable_zeroing() {
        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(4 * 1024 * 1024).unwrap();
        let block = Block::new_with_writeback_limit(
            "bounded".to_string(),
            None,
            CacheType::Writeback,
            backing.as_path().to_string_lossy().into_owned(),
            ImageType::Raw,
            false,
            false,
            SyncMode::Full,
            Some(MINIMUM_WRITEBACK_BUDGET_BYTES),
            MetricsWriter::default().register_block_device("bounded".to_string()),
        )
        .unwrap();

        assert_eq!(block.avail_features & (1u64 << VIRTIO_BLK_F_DISCARD), 0);
        assert_ne!(
            block.avail_features & (1u64 << VIRTIO_BLK_F_WRITE_ZEROES),
            0
        );
        let max_discard_sectors = block.config.max_discard_sectors;
        let max_discard_seg = block.config.max_discard_seg;
        let discard_sector_alignment = block.config.discard_sector_alignment;
        let write_zeroes_may_unmap = block.config.write_zeroes_may_unmap;
        assert_eq!(max_discard_sectors, 0);
        assert_eq!(max_discard_seg, 0);
        assert_eq!(discard_sector_alignment, 0);
        assert_eq!(write_zeroes_may_unmap, 0);

        let legacy = Block::new(
            "legacy".to_string(),
            None,
            CacheType::Writeback,
            backing.as_path().to_string_lossy().into_owned(),
            ImageType::Raw,
            false,
            false,
            SyncMode::Full,
            MetricsWriter::default().register_block_device("legacy".to_string()),
        )
        .unwrap();
        let legacy_may_unmap = legacy.config.write_zeroes_may_unmap;
        assert_ne!(legacy.avail_features & (1u64 << VIRTIO_BLK_F_DISCARD), 0);
        assert_eq!(legacy_may_unmap, 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_writeback_rejects_too_small_budget() {
        let result = Block::new_with_writeback_limit(
            "raw".to_string(),
            None,
            CacheType::Writeback,
            "missing.raw".to_string(),
            ImageType::Raw,
            false,
            false,
            SyncMode::Full,
            Some(MINIMUM_WRITEBACK_BUDGET_BYTES - 1),
            MetricsWriter::default().register_block_device("raw".to_string()),
        );

        let error = match result {
            Ok(_) => panic!("too-small writeback budget should fail"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("at least"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_writeback_rejects_incompatible_disk_settings() {
        let result = Block::new_with_writeback_limit(
            "raw".to_string(),
            None,
            CacheType::Writeback,
            "missing.raw".to_string(),
            ImageType::Raw,
            false,
            true,
            SyncMode::Full,
            Some(128 * 1024 * 1024),
            MetricsWriter::default().register_block_device("raw".to_string()),
        );

        let error = match result {
            Ok(_) => panic!("bounded writeback with direct I/O should fail"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("buffered I/O"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn bounded_writeback_is_rejected_on_unsupported_hosts() {
        let result = Block::new_with_writeback_limit(
            "raw".to_string(),
            None,
            CacheType::Writeback,
            "missing.raw".to_string(),
            ImageType::Raw,
            false,
            false,
            SyncMode::Full,
            Some(128 * 1024 * 1024),
            MetricsWriter::default().register_block_device("raw".to_string()),
        );

        let error = match result {
            Ok(_) => panic!("bounded writeback should fail on unsupported hosts"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
}
