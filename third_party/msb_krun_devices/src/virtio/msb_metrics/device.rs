use utils::eventfd::EventFd;
use utils::metrics::MetricsWriter;
use vm_memory::{ByteValued, Bytes, GuestMemoryMmap, Le32, Le64};

use super::super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, QueueConfig, VirtioDevice,
};
use super::{defs, defs::uapi, MsbMetricsError};
use crate::virtio::InterruptTransport;

pub(crate) const RX_INDEX: usize = 0;
const SAMPLE_VERSION: u32 = 1;
const SAMPLE_SIZE: u32 = std::mem::size_of::<UpperFilesystemSample>() as u32;
pub(crate) const AVAIL_FEATURES: u64 = 1 << uapi::VIRTIO_F_VERSION_1 as u64;

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct UpperFilesystemSample {
    pub version: Le32,
    pub size: Le32,
    pub upper_used_bytes: Le64,
    pub upper_free_bytes: Le64,
}

unsafe impl ByteValued for UpperFilesystemSample {}

pub struct MsbMetrics {
    pub(crate) queues: Option<Vec<DeviceQueue>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    metrics: MetricsWriter,
}

impl MsbMetrics {
    pub(crate) fn queue_event(&self, idx: usize) -> &std::sync::Arc<utils::eventfd::EventFd> {
        &self.queues.as_ref().expect("queues should exist")[idx].event
    }

    pub fn new(metrics: MetricsWriter) -> super::Result<MsbMetrics> {
        Ok(MsbMetrics {
            queues: None,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(MsbMetricsError::EventFd)?,
            device_state: DeviceState::Inactive,
            metrics,
        })
    }

    pub fn id(&self) -> &str {
        defs::MSB_METRICS_DEV_ID
    }

    pub(crate) fn process_rx(&mut self) -> bool {
        debug!("msb_metrics: process_rx()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem,
            DeviceState::Inactive => unreachable!(),
        };
        let metrics = self.metrics.clone();

        let queues = self
            .queues
            .as_mut()
            .expect("queues should exist when activated");
        let mut have_used = false;

        while let Some(head) = queues[RX_INDEX].queue.pop(mem) {
            let index = head.index;
            let mut processed = 0;

            for desc in head.into_iter() {
                if desc.is_write_only() {
                    continue;
                }
                if desc.len < SAMPLE_SIZE {
                    warn!(
                        "msb_metrics: short sample descriptor len={} expected={}",
                        desc.len, SAMPLE_SIZE
                    );
                    continue;
                }

                match mem.read_obj::<UpperFilesystemSample>(desc.addr) {
                    Ok(sample) => process_upper_filesystem_sample(&metrics, sample),
                    Err(err) => warn!("msb_metrics: failed to read sample descriptor: {err:?}"),
                }
                processed = SAMPLE_SIZE;
                break;
            }

            have_used = true;
            if let Err(err) = queues[RX_INDEX].queue.add_used(mem, index, processed) {
                error!("msb_metrics: failed to add used element: {err:?}");
            }
        }

        have_used
    }
}

fn process_upper_filesystem_sample(metrics: &MetricsWriter, sample: UpperFilesystemSample) {
    if sample.version.to_native() != SAMPLE_VERSION || sample.size.to_native() != SAMPLE_SIZE {
        warn!(
            "msb_metrics: unsupported sample version={} size={}",
            sample.version.to_native(),
            sample.size.to_native()
        );
        return;
    }

    metrics.set_upper_filesystem_bytes(
        sample.upper_used_bytes.to_native(),
        sample.upper_free_bytes.to_native(),
    );
}

impl VirtioDevice for MsbMetrics {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_MSB_METRICS
    }

    fn device_name(&self) -> &str {
        "msb_metrics"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn read_config(&self, _offset: u64, _data: &mut [u8]) {
        error!("msb_metrics: invalid request to read config space");
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "msb_metrics: guest driver attempted to write device config (offset={:x}, len={:x})",
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
        if queues.len() != defs::NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                defs::NUM_QUEUES,
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        self.queues = Some(queues);
        self.device_state = DeviceState::Activated(mem, interrupt);

        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt");
            self.queues = None;
            self.device_state = DeviceState::Inactive;
            return Err(ActivateError::BadActivate);
        }

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn reset(&mut self) -> bool {
        self.queues = None;
        self.device_state = DeviceState::Inactive;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_sample_updates_filesystem_metrics() {
        let writer = MetricsWriter::default();

        process_upper_filesystem_sample(
            &writer,
            UpperFilesystemSample {
                version: Le32::from(SAMPLE_VERSION),
                size: Le32::from(SAMPLE_SIZE),
                upper_used_bytes: Le64::from(4096),
                upper_free_bytes: Le64::from(8192),
            },
        );

        assert_eq!(
            writer.handle().snapshot().filesystem.upper_used_bytes,
            Some(4096)
        );
        assert_eq!(
            writer.handle().snapshot().filesystem.upper_free_bytes,
            Some(8192)
        );
    }

    #[test]
    fn invalid_sample_is_ignored() {
        let writer = MetricsWriter::default();

        process_upper_filesystem_sample(
            &writer,
            UpperFilesystemSample {
                version: Le32::from(SAMPLE_VERSION + 1),
                size: Le32::from(SAMPLE_SIZE),
                upper_used_bytes: Le64::from(4096),
                upper_free_bytes: Le64::from(8192),
            },
        );

        assert_eq!(writer.handle().snapshot().filesystem.upper_used_bytes, None);
        assert_eq!(writer.handle().snapshot().filesystem.upper_free_bytes, None);
    }
}
