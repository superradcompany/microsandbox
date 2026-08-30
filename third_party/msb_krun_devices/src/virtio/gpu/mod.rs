mod device;
pub mod display;
mod edid;
mod protocol;
mod virtio_gpu;
mod worker;

use super::descriptor_utils::Error as DescriptorError;

pub use self::defs::uapi::VIRTIO_ID_GPU as TYPE_GPU;
pub use self::device::Gpu;

/// virglrenderer init flags the device inspects to choose its renderer.
pub(crate) const VIRGL_RENDERER_VENUS: u32 = 1 << 6;
pub(crate) const VIRGL_RENDERER_NO_VIRGL: u32 = 1 << 7;

/// `NO_VIRGL` without `VENUS` means the host offers no 3D renderer at all
/// (macOS without a display server, for instance). Run as a plain 2D
/// virtio-gpu on rutabaga's software component instead of virglrenderer,
/// which rejects every non-blob resource when vrend is not initialized.
pub(crate) fn is_2d_only(virgl_flags: u32) -> bool {
    virgl_flags & VIRGL_RENDERER_NO_VIRGL != 0 && virgl_flags & VIRGL_RENDERER_VENUS == 0
}

mod defs {
    pub const GPU_DEV_ID: &str = "virtio_gpu";
    pub const NUM_QUEUES: usize = 2;

    #[allow(dead_code)]
    pub mod uapi {
        use vm_memory::ByteValued;

        pub const VIRTIO_F_VERSION_1: u32 = 32;
        pub const VIRTIO_ID_GPU: u32 = 16;

        pub const VIRTIO_GPU_F_VIRGL: u32 = 0;
        pub const VIRTIO_GPU_F_EDID: u32 = 1;
        pub const VIRTIO_GPU_F_RESOURCE_UUID: u32 = 2;
        pub const VIRTIO_GPU_F_RESOURCE_BLOB: u32 = 3;
        pub const VIRTIO_GPU_F_CONTEXT_INIT: u32 = 4;
        /* The following capabilities are not upstreamed. */
        pub const VIRTIO_GPU_F_RESOURCE_SYNC: u32 = 5;
        pub const VIRTIO_GPU_F_CREATE_GUEST_HANDLE: u32 = 6;

        #[derive(Copy, Clone, Debug, Default)]
        #[repr(C)]
        pub struct virtio_gpu_config {
            pub events_read: u32,
            pub events_clear: u32,
            pub num_scanouts: u32,
            pub num_capsets: u32,
        }
        unsafe impl ByteValued for virtio_gpu_config {}
    }
}

#[derive(Debug)]
pub enum GpuError {
    /// Failed to create event fd.
    EventFd(std::io::Error),
    /// Failed to decode incoming command.
    DecodeCommand(std::io::Error),
    /// Error creating Reader for Queue.
    QueueReader(DescriptorError),
    /// Error creating Writer for Queue.
    QueueWriter(DescriptorError),
    /// Error writting to the Queue.
    WriteDescriptor(std::io::Error),
    /// Error reading Guest Memory,
    GuestMemory,
}

type Result<T> = std::result::Result<T, GpuError>;
