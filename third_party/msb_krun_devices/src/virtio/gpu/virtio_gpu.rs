use std::collections::BTreeMap;
use std::env;
use std::io::IoSliceMut;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use super::super::Queue as VirtQueue;
use super::protocol::GpuResponse::*;
use super::protocol::{
    GpuResponse, GpuResponsePlaneInfo, VirtioGpuResult, VIRTIO_GPU_BLOB_FLAG_CREATE_GUEST_HANDLE,
    VIRTIO_GPU_BLOB_MEM_HOST3D, VIRTIO_GPU_MAX_SCANOUTS,
};
#[cfg(target_os = "macos")]
use crossbeam_channel::{unbounded, Sender};
use krun_display::{
    DisplayBackend, DisplayBackendBasicFramebuffer, DisplayBackendInstance, Rect, ResourceFormat,
};
use libc::c_void;
#[cfg(target_os = "macos")]
use rutabaga_gfx::RUTABAGA_MEM_HANDLE_TYPE_APPLE;
#[cfg(all(not(feature = "virgl_resource_map2"), target_os = "linux"))]
use rutabaga_gfx::RUTABAGA_MEM_HANDLE_TYPE_OPAQUE_FD;
#[cfg(all(feature = "virgl_resource_map2", target_os = "linux"))]
use rutabaga_gfx::RUTABAGA_MEM_HANDLE_TYPE_SHM;
use rutabaga_gfx::{
    ResourceCreate3D, ResourceCreateBlob, Rutabaga, RutabagaBuilder, RutabagaChannel,
    RutabagaFence, RutabagaFenceHandler, RutabagaIovec, Transfer3D, RUTABAGA_CHANNEL_TYPE_WAYLAND,
    RUTABAGA_MAP_CACHE_MASK,
};
#[cfg(target_os = "linux")]
use rutabaga_gfx::{
    RUTABAGA_CHANNEL_TYPE_PW, RUTABAGA_CHANNEL_TYPE_X11, RUTABAGA_MAP_ACCESS_MASK,
    RUTABAGA_MAP_ACCESS_READ, RUTABAGA_MAP_ACCESS_RW, RUTABAGA_MAP_ACCESS_WRITE,
};
#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;
use vm_memory::{GuestAddress, GuestMemoryBackend, GuestMemoryMmap, VolatileSlice};

use super::{GpuError, Result};
use crate::virtio::display::DisplayInfo;
use crate::virtio::fs::ExportTable;
use crate::virtio::gpu::protocol::VIRTIO_GPU_FLAG_INFO_RING_IDX;
use crate::virtio::{InterruptTransport, VirtioShmRegion};

fn sglist_to_rutabaga_iovecs(
    vecs: &[(GuestAddress, usize)],
    mem: &GuestMemoryMmap,
) -> Result<Vec<RutabagaIovec>> {
    if vecs
        .iter()
        .any(|&(addr, len)| mem.get_slice(addr, len).is_err())
    {
        return Err(GpuError::GuestMemory);
    }

    let mut rutabaga_iovecs: Vec<RutabagaIovec> = Vec::new();
    for &(addr, len) in vecs {
        let slice = mem.get_slice(addr, len).unwrap();
        rutabaga_iovecs.push(RutabagaIovec {
            base: slice.ptr_guard_mut().as_ptr() as *mut c_void,
            len,
        });
    }
    Ok(rutabaga_iovecs)
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub enum VirtioGpuRing {
    Global,
    ContextSpecific { ctx_id: u32, ring_idx: u8 },
}

struct FenceDescriptor {
    ring: VirtioGpuRing,
    fence_id: u64,
    desc_index: u16,
    len: u32,
}

#[derive(Default)]
pub struct FenceState {
    descs: Vec<FenceDescriptor>,
    completed_fences: BTreeMap<VirtioGpuRing, u64>,
}

#[derive(Copy, Clone, Debug, Default)]
struct AssociatedScanouts(u32);

impl AssociatedScanouts {
    fn enable(&mut self, scanout_id: u32) {
        self.0 |= 1 << scanout_id;
    }

    fn disable(&mut self, scanout_id: u32) {
        self.0 ^= 1 << scanout_id;
    }

    const fn has_any_enabled(self) -> bool {
        self.0 != 0
    }

    fn iter_enabled(self) -> impl Iterator<Item = u32> {
        (0..VIRTIO_GPU_MAX_SCANOUTS).filter(move |i| ((self.0 >> i) & 1) == 1)
    }
}

#[derive(Copy, Clone)]
struct VirtioGpuResource {
    id: u32,
    width: u32,
    height: u32,
    scanouts: AssociatedScanouts,
    format: Option<ResourceFormat>,
    size: u64, // only for blob resources
    shmem_offset: Option<u64>,
    rutabaga_external_mapping: bool,
}

impl VirtioGpuResource {
    /// Creates a new VirtioGpuResource with the given metadata.  Width and height are used by the
    /// display, while size is useful for hypervisor mapping.
    pub fn new(
        resource_id: u32,
        width: u32,
        height: u32,
        format: Option<ResourceFormat>,
        size: u64,
    ) -> VirtioGpuResource {
        VirtioGpuResource {
            id: resource_id,
            width,
            height,
            scanouts: Default::default(),
            size,
            format,
            shmem_offset: None,
            rutabaga_external_mapping: false,
        }
    }
}

pub struct VirtioGpuScanout {
    resource_id: u32,
    /// Size of the scanout rectangle the guest asked for; also the size of
    /// the frame buffers the display backend hands out for this scanout.
    width: u32,
    height: u32,
}

pub struct VirtioGpu {
    rutabaga: Rutabaga,
    resources: BTreeMap<u32, VirtioGpuResource>,
    fence_state: Arc<Mutex<FenceState>>,
    #[cfg(target_os = "macos")]
    map_sender: Sender<WorkerMessage>,
    scanouts: [Option<VirtioGpuScanout>; VIRTIO_GPU_MAX_SCANOUTS as usize],
    displays: Box<[DisplayInfo]>,
    display_backend: DisplayBackendInstance,
}

impl VirtioGpu {
    fn create_fence_handler(
        mem: GuestMemoryMmap,
        queue_ctl: Arc<Mutex<VirtQueue>>,
        fence_state: Arc<Mutex<FenceState>>,
        interrupt: InterruptTransport,
    ) -> RutabagaFenceHandler {
        RutabagaFenceHandler::new(move |completed_fence: RutabagaFence| {
            debug!(
                "XXX - fence called: id={}, ring_idx={}",
                completed_fence.fence_id, completed_fence.ring_idx
            );

            let mut queue = queue_ctl.lock().unwrap();
            let mut fence_state = fence_state.lock().unwrap();
            let mut i = 0;

            let ring = match completed_fence.flags & VIRTIO_GPU_FLAG_INFO_RING_IDX {
                0 => VirtioGpuRing::Global,
                _ => VirtioGpuRing::ContextSpecific {
                    ctx_id: completed_fence.ctx_id,
                    ring_idx: completed_fence.ring_idx,
                },
            };

            while i < fence_state.descs.len() {
                debug!("XXX - fence_id: {}", fence_state.descs[i].fence_id);
                if fence_state.descs[i].ring == ring
                    && fence_state.descs[i].fence_id <= completed_fence.fence_id
                {
                    let completed_desc = fence_state.descs.remove(i);
                    debug!(
                        "XXX - found fence: desc_index={}",
                        completed_desc.desc_index
                    );

                    if let Err(e) =
                        queue.add_used(&mem, completed_desc.desc_index, completed_desc.len)
                    {
                        error!("failed to add used elements to the queue: {e:?}");
                    }

                    interrupt.signal_used_queue();
                } else {
                    i += 1;
                }
            }
            // Update the last completed fence for this context
            fence_state
                .completed_fences
                .insert(ring, completed_fence.fence_id);
        })
    }

    pub fn create_rutabaga(
        mem: GuestMemoryMmap,
        queue_ctl: Arc<Mutex<VirtQueue>>,
        interrupt: InterruptTransport,
        fence_state: Arc<Mutex<FenceState>>,
        virgl_flags: u32,
        export_table: Option<ExportTable>,
    ) -> Option<Rutabaga> {
        if super::is_2d_only(virgl_flags) {
            let fence = Self::create_fence_handler(mem, queue_ctl, fence_state, interrupt);
            return RutabagaBuilder::new(rutabaga_gfx::RutabagaComponentType::Rutabaga2D, 0, 0)
                .build(fence, None)
                .ok();
        }

        let xdg_runtime_dir = match env::var("XDG_RUNTIME_DIR") {
            Ok(dir) => dir,
            Err(_) => "/run/user/1000".to_string(),
        };
        let wayland_display = match env::var("WAYLAND_DISPLAY") {
            Ok(display) => display,
            Err(_) => "wayland-0".to_string(),
        };
        let path = PathBuf::from(format!("{xdg_runtime_dir}/{wayland_display}"));

        #[allow(unused_mut)]
        let mut rutabaga_channels: Vec<RutabagaChannel> = vec![RutabagaChannel {
            base_channel: path,
            channel_type: RUTABAGA_CHANNEL_TYPE_WAYLAND,
        }];

        #[cfg(target_os = "linux")]
        if let Ok(x_display) = env::var("DISPLAY") {
            if let Some(x_display) = x_display.strip_prefix(":") {
                let x_path = PathBuf::from(format!("/tmp/.X11-unix/X{x_display}"));
                rutabaga_channels.push(RutabagaChannel {
                    base_channel: x_path,
                    channel_type: RUTABAGA_CHANNEL_TYPE_X11,
                });
            }
        }
        #[cfg(target_os = "linux")]
        if let Ok(pw_sock_dir) = env::var("PIPEWIRE_RUNTIME_DIR")
            .or_else(|_| env::var("XDG_RUNTIME_DIR"))
            .or_else(|_| env::var("USERPROFILE"))
        {
            let name = env::var("PIPEWIRE_REMOTE").unwrap_or_else(|_| "pipewire-0".to_string());
            let mut pw_path = PathBuf::from(pw_sock_dir);
            pw_path.push(name);
            rutabaga_channels.push(RutabagaChannel {
                base_channel: pw_path,
                channel_type: RUTABAGA_CHANNEL_TYPE_PW,
            });
        }
        let rutabaga_channels_opt = Some(rutabaga_channels);

        let builder = RutabagaBuilder::new(
            rutabaga_gfx::RutabagaComponentType::VirglRenderer,
            virgl_flags,
            0,
        )
        .set_rutabaga_channels(rutabaga_channels_opt);
        let builder = if let Some(export_table) = export_table {
            builder.set_export_table(export_table)
        } else {
            builder
        };

        let fence =
            Self::create_fence_handler(mem, queue_ctl.clone(), fence_state.clone(), interrupt);
        builder.clone().build(fence.clone(), None).ok()
    }

    pub fn create_fallback_rutabaga(
        mem: GuestMemoryMmap,
        queue_ctl: Arc<Mutex<VirtQueue>>,
        interrupt: InterruptTransport,
        fence_state: Arc<Mutex<FenceState>>,
    ) -> Option<Rutabaga> {
        // The software 2D component has no host dependencies, so it is the
        // one renderer that can always be built.
        let builder = RutabagaBuilder::new(rutabaga_gfx::RutabagaComponentType::Rutabaga2D, 0, 0);

        let fence =
            Self::create_fence_handler(mem, queue_ctl.clone(), fence_state.clone(), interrupt);
        builder.clone().build(fence.clone(), None).ok()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mem: GuestMemoryMmap,
        queue_ctl: Arc<Mutex<VirtQueue>>,
        interrupt: InterruptTransport,
        virgl_flags: u32,
        #[cfg(target_os = "macos")] map_sender: Sender<WorkerMessage>,
        export_table: Option<ExportTable>,
        displays: Box<[DisplayInfo]>,
        display_backend: DisplayBackend,
    ) -> Self {
        let fence_state = Arc::new(Mutex::new(Default::default()));

        let rutabaga = match Self::create_rutabaga(
            mem.clone(),
            queue_ctl.clone(),
            interrupt.clone(),
            fence_state.clone(),
            virgl_flags,
            export_table.clone(),
        ) {
            Some(rutabaga) => rutabaga,
            None => {
                warn!("Failed to create virtio_gpu backend with the requested parameters. Falling back to safe defaults.");
                Self::create_fallback_rutabaga(
                    mem.clone(),
                    queue_ctl.clone(),
                    interrupt.clone(),
                    fence_state.clone(),
                )
                .expect("Fallback rutabaga initialization failed")
            }
        };

        let display_backend = display_backend
            .create_instance()
            .expect("Failed to create display backend instance!");

        Self {
            rutabaga,
            resources: Default::default(),
            fence_state,
            scanouts: Default::default(),
            displays,
            display_backend,
            #[cfg(target_os = "macos")]
            map_sender,
        }
    }

    // Non-public function -- no doc comment needed!
    fn result_from_query(&mut self, resource_id: u32) -> GpuResponse {
        match self.rutabaga.query(resource_id) {
            Ok(query) => {
                let mut plane_info = Vec::with_capacity(4);
                for plane_index in 0..4 {
                    plane_info.push(GpuResponsePlaneInfo {
                        stride: query.strides[plane_index],
                        offset: query.offsets[plane_index],
                    });
                }
                let format_modifier = query.modifier;
                OkResourcePlaneInfo {
                    format_modifier,
                    plane_info,
                }
            }
            Err(_) => OkNoData,
        }
    }

    pub fn force_ctx_0(&self) {
        self.rutabaga.force_ctx_0()
    }

    /// Creates a 3D resource with the given properties and resource_id.
    pub fn resource_create_3d(
        &mut self,
        resource_id: u32,
        resource_create_3d: ResourceCreate3D,
    ) -> VirtioGpuResult {
        self.rutabaga
            .resource_create_3d(resource_id, resource_create_3d)?;

        let format = ResourceFormat::try_from(resource_create_3d.format).ok();
        if format.is_none() {
            debug!(
                "Unknown format {} for resource {}",
                resource_create_3d.format, resource_id
            );
        }

        let resource = VirtioGpuResource::new(
            resource_id,
            resource_create_3d.width,
            resource_create_3d.height,
            format,
            0,
        );

        // Rely on rutabaga to check for duplicate resource ids.
        self.resources.insert(resource_id, resource);
        Ok(self.result_from_query(resource_id))
    }

    /// Releases guest kernel reference on the resource.
    pub fn unref_resource(&mut self, resource_id: u32) -> VirtioGpuResult {
        let resource = self
            .resources
            .remove(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        if resource.scanouts.has_any_enabled() {
            warn!(
                "The driver requested unref_resource, but resource {resource_id} has \
                     associated scanouts, refusing to delete the resource."
            );
            return Err(ErrUnspec);
        }

        if resource.rutabaga_external_mapping {
            self.rutabaga.unmap(resource_id)?;
        }

        self.rutabaga.unref_resource(resource_id)?;
        Ok(OkNoData)
    }

    pub fn set_scanout(
        &mut self,
        scanout_id: u32,
        resource_id: u32,
        width: u32,
        height: u32,
    ) -> VirtioGpuResult {
        let scanout = self
            .scanouts
            .get_mut(scanout_id as usize)
            .ok_or(ErrInvalidScanoutId)?;

        // If a resource is already associated with this scanout, make sure to disable
        // this scanout for that resource
        if let Some(resource_id) = scanout.as_ref().map(|scanout| scanout.resource_id) {
            let resource = self
                .resources
                .get_mut(&resource_id)
                .ok_or(ErrInvalidResourceId)?;

            resource.scanouts.disable(scanout_id);
        }

        // Virtio spec: "The driver can use resource_id = 0 to disable a scanout."
        if resource_id == 0 {
            debug!("Disabling scanout {scanout_id:?}");
            *scanout = None;
            self.display_backend.disable_scanout(scanout_id)?;
            return Ok(OkNoData);
        }

        // Enable the scanout
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;
        resource.scanouts.enable(scanout_id);

        let Some(format) = resource.format else {
            warn!("Cannot use resource {resource_id} with unknown format for scanout");
            return Err(ErrUnspec);
        };

        let display_info = self
            .displays
            .get(scanout_id as usize)
            .ok_or(ErrInvalidScanoutId)?;

        self.display_backend.configure_scanout(
            scanout_id,
            display_info.width,
            display_info.height,
            width,
            height,
            format,
        )?;

        *scanout = Some(VirtioGpuScanout {
            resource_id,
            width,
            height,
        });
        Ok(OkNoData)
    }

    /// Copies the top-left `dst_width` x `dst_height` pixels of `resource`
    /// into `output`, whose rows are `dst_width` pixels wide. The resource
    /// may be larger than the scanout (padded strides, oversized dumb
    /// buffers) or, if the guest is misbehaving, smaller; only the
    /// intersection is transferred.
    fn read_2d_resource(
        rutabaga: &mut Rutabaga,
        resource: VirtioGpuResource,
        output: &mut [u8],
        dst_width: u32,
        dst_height: u32,
    ) -> VirtioGpuResult {
        let transfer = Transfer3D {
            x: 0,
            y: 0,
            z: 0,
            w: resource.width.min(dst_width),
            h: resource.height.min(dst_height),
            d: 1,
            level: 0,
            stride: dst_width * ResourceFormat::BYTES_PER_PIXEL as u32,
            layer_stride: 0,
            offset: 0,
        };

        rutabaga
            .transfer_read(0, resource.id, transfer, Some(IoSliceMut::new(output)))
            .map_err(|e| {
                log::error!(
                    "transfer_read of resource {} ({}x{}) into a {}x{} frame failed: {e}",
                    resource.id, resource.width, resource.height, dst_width, dst_height
                );
                ErrUnspec
            })?;

        Ok(OkNoData)
    }

    /// If the resource is the scanout resource, flush it to the display.
    pub fn flush_resource(&mut self, resource_id: u32, rect: Rect) -> VirtioGpuResult {
        if resource_id == 0 {
            return Ok(OkNoData);
        }

        let resource = *self
            .resources
            .get(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        for scanout_id in resource.scanouts.iter_enabled() {
            let (dst_width, dst_height) = match self.scanouts.get(scanout_id as usize) {
                Some(Some(scanout)) => (scanout.width, scanout.height),
                _ => return Err(ErrInvalidScanoutId),
            };
            let (frame_id, buffer) = self.display_backend.alloc_frame(scanout_id)?;
            if let Err(e) = Self::read_2d_resource(
                &mut self.rutabaga,
                resource,
                buffer,
                dst_width,
                dst_height,
            ) {
                log::error!("Failed to read resource {resource_id} for scanout {scanout_id}: {e}");
                return Err(ErrUnspec);
            }
            self.display_backend
                .present_frame(scanout_id, frame_id, Some(&rect))?
        }

        #[cfg(windows)]
        match self.rutabaga.resource_flush(resource_id) {
            Ok(_) => return Ok(OkNoData),
            Err(RutabagaError::Unsupported) => {}
            Err(e) => return Err(ErrRutabaga(e)),
        }

        Ok(OkNoData)
    }

    pub fn display_info(&self) -> VirtioGpuResult {
        let display_info = self
            .displays
            .iter()
            .map(|d| (d.width, d.height, true))
            .collect();

        Ok(OkDisplayInfo(display_info))
    }

    pub fn get_edid(&self, scanout_id: u32) -> VirtioGpuResult {
        let display = self
            .displays
            .get(scanout_id as usize)
            .ok_or(ErrInvalidScanoutId)?;

        Ok(OkEdid(display.edid_bytes()))
    }

    /// Copies data to host resource from the attached iovecs. Can also be used to flush caches.
    pub fn transfer_write(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        transfer: Transfer3D,
    ) -> VirtioGpuResult {
        self.rutabaga
            .transfer_write(ctx_id, resource_id, transfer)?;
        Ok(OkNoData)
    }

    /// Copies data from the host resource to:
    ///    1) To the optional volatile slice
    ///    2) To the host resource's attached iovecs
    ///
    /// Can also be used to invalidate caches.
    pub fn transfer_read(
        &mut self,
        _ctx_id: u32,
        _resource_id: u32,
        _transfer: Transfer3D,
        _buf: Option<VolatileSlice>,
    ) -> VirtioGpuResult {
        panic!("virtio_gpu: transfer_read unimplemented");
    }

    /// Attaches backing memory to the given resource, represented by a `Vec` of `(address, size)`
    /// tuples in the guest's physical address space. Converts to RutabagaIovec from the memory
    /// mapping.
    pub fn attach_backing(
        &mut self,
        resource_id: u32,
        mem: &GuestMemoryMmap,
        vecs: Vec<(GuestAddress, usize)>,
    ) -> VirtioGpuResult {
        let rutabaga_iovecs = sglist_to_rutabaga_iovecs(&vecs[..], mem).map_err(|_| ErrUnspec)?;
        self.rutabaga.attach_backing(resource_id, rutabaga_iovecs)?;
        Ok(OkNoData)
    }

    /// Detaches any previously attached iovecs from the resource.
    pub fn detach_backing(&mut self, resource_id: u32) -> VirtioGpuResult {
        self.rutabaga.detach_backing(resource_id)?;
        Ok(OkNoData)
    }

    /// Returns a uuid for the resource.
    pub fn resource_assign_uuid(&self, resource_id: u32) -> VirtioGpuResult {
        if !self.resources.contains_key(&resource_id) {
            return Err(ErrInvalidResourceId);
        }

        // TODO(stevensd): use real uuids once the virtio wayland protocol is updated to
        // handle more than 32 bits. For now, the virtwl driver knows that the uuid is
        // actually just the resource id.
        let mut uuid: [u8; 16] = [0; 16];
        for (idx, byte) in resource_id.to_be_bytes().iter().enumerate() {
            uuid[12 + idx] = *byte;
        }
        Ok(OkResourceUuid { uuid })
    }

    /// Gets rutabaga's capset information associated with `index`.
    pub fn get_capset_info(&self, index: u32) -> VirtioGpuResult {
        let (capset_id, version, size) = self.rutabaga.get_capset_info(index)?;
        Ok(OkCapsetInfo {
            capset_id,
            version,
            size,
        })
    }

    /// Gets a capset from rutabaga.
    pub fn get_capset(&self, capset_id: u32, version: u32) -> VirtioGpuResult {
        let capset = self.rutabaga.get_capset(capset_id, version)?;
        Ok(OkCapset(capset))
    }

    /// Creates a rutabaga context.
    pub fn create_context(
        &mut self,
        ctx_id: u32,
        context_init: u32,
        context_name: Option<&str>,
    ) -> VirtioGpuResult {
        self.rutabaga
            .create_context(ctx_id, context_init, context_name)?;
        Ok(OkNoData)
    }

    /// Destroys a rutabaga context.
    pub fn destroy_context(&mut self, ctx_id: u32) -> VirtioGpuResult {
        self.rutabaga.destroy_context(ctx_id)?;
        Ok(OkNoData)
    }

    /// Attaches a resource to a rutabaga context.
    pub fn context_attach_resource(&mut self, ctx_id: u32, resource_id: u32) -> VirtioGpuResult {
        self.rutabaga.context_attach_resource(ctx_id, resource_id)?;
        Ok(OkNoData)
    }

    /// Detaches a resource from a rutabaga context.
    pub fn context_detach_resource(&mut self, ctx_id: u32, resource_id: u32) -> VirtioGpuResult {
        self.rutabaga.context_detach_resource(ctx_id, resource_id)?;
        Ok(OkNoData)
    }

    /// Submits a command buffer to a rutabaga context.
    pub fn submit_command(
        &mut self,
        ctx_id: u32,
        commands: &mut [u8],
        fence_ids: &[u64],
    ) -> VirtioGpuResult {
        self.rutabaga.submit_command(ctx_id, commands, fence_ids)?;
        Ok(OkNoData)
    }

    /// Creates a fence with the RutabagaFence that can be used to determine when the previous
    /// command completed.
    pub fn create_fence(&mut self, rutabaga_fence: RutabagaFence) -> VirtioGpuResult {
        self.rutabaga.create_fence(rutabaga_fence)?;
        Ok(OkNoData)
    }

    pub fn process_fence(
        &mut self,
        ring: VirtioGpuRing,
        fence_id: u64,
        desc_index: u16,
        len: u32,
    ) -> bool {
        // In case the fence is signaled immediately after creation, don't add a return
        // FenceDescriptor.
        let mut fence_state = self.fence_state.lock().unwrap();
        if fence_id > *fence_state.completed_fences.get(&ring).unwrap_or(&0) {
            fence_state.descs.push(FenceDescriptor {
                ring,
                fence_id,
                desc_index,
                len,
            });

            false
        } else {
            true
        }
    }

    /// Creates a blob resource using rutabaga.
    pub fn resource_create_blob(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        resource_create_blob: ResourceCreateBlob,
        vecs: Vec<(GuestAddress, usize)>,
        mem: &GuestMemoryMmap,
    ) -> VirtioGpuResult {
        let mut rutabaga_iovecs = None;

        if resource_create_blob.blob_flags & VIRTIO_GPU_BLOB_FLAG_CREATE_GUEST_HANDLE != 0 {
            panic!("GUEST_HANDLE unimplemented");
        } else if resource_create_blob.blob_mem != VIRTIO_GPU_BLOB_MEM_HOST3D {
            rutabaga_iovecs =
                Some(sglist_to_rutabaga_iovecs(&vecs[..], mem).map_err(|_| ErrUnspec)?);
        }

        self.rutabaga.resource_create_blob(
            ctx_id,
            resource_id,
            resource_create_blob,
            rutabaga_iovecs,
            None,
        )?;

        let resource = VirtioGpuResource::new(resource_id, 0, 0, None, resource_create_blob.size);

        // Rely on rutabaga to check for duplicate resource ids.
        self.resources.insert(resource_id, resource);
        Ok(self.result_from_query(resource_id))
    }

    /// Uses the hypervisor to map the rutabaga blob resource.
    ///
    /// When sandboxing is disabled, external_blob is unset and opaque fds are mapped by
    /// rutabaga as ExternalMapping.
    /// When sandboxing is enabled, external_blob is set and opaque fds must be mapped in the
    /// hypervisor process by Vulkano using metadata provided by Rutabaga::vulkan_info().
    #[cfg(all(not(feature = "virgl_resource_map2"), target_os = "linux"))]
    pub fn resource_map_blob(
        &mut self,
        resource_id: u32,
        shm_region: &VirtioShmRegion,
        offset: u64,
    ) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        let map_info = self.rutabaga.map_info(resource_id).map_err(|_| ErrUnspec)?;

        if let Ok(export) = self.rutabaga.export_blob(resource_id) {
            if export.handle_type != RUTABAGA_MEM_HANDLE_TYPE_OPAQUE_FD {
                let prot = match map_info & RUTABAGA_MAP_ACCESS_MASK {
                    RUTABAGA_MAP_ACCESS_READ => libc::PROT_READ,
                    RUTABAGA_MAP_ACCESS_WRITE => libc::PROT_WRITE,
                    RUTABAGA_MAP_ACCESS_RW => libc::PROT_READ | libc::PROT_WRITE,
                    _ => panic!("unexpected prot mode for mapping"),
                };

                if offset + resource.size > shm_region.size as u64 {
                    error!("mapping DOES NOT FIT");
                }
                let addr = shm_region.host_addr + offset;
                debug!(
                    "mapping: host_addr={:x}, addr={:x}, size={}",
                    shm_region.host_addr, addr, resource.size
                );
                let ret = unsafe {
                    libc::mmap(
                        addr as *mut libc::c_void,
                        resource.size as usize,
                        prot,
                        libc::MAP_SHARED | libc::MAP_FIXED,
                        export.os_handle.as_raw_fd(),
                        0 as libc::off_t,
                    )
                };
                if ret == libc::MAP_FAILED {
                    return Err(ErrUnspec);
                }
            } else {
                return Err(ErrUnspec);
            }
        } else {
            return Err(ErrUnspec);
        }

        resource.shmem_offset = Some(offset);
        // Access flags not a part of the virtio-gpu spec.
        Ok(OkMapInfo {
            map_info: map_info & RUTABAGA_MAP_CACHE_MASK,
        })
    }
    #[cfg(all(feature = "virgl_resource_map2", target_os = "linux"))]
    pub fn resource_map_blob(
        &mut self,
        resource_id: u32,
        shm_region: &VirtioShmRegion,
        offset: u64,
    ) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        let map_info = self.rutabaga.map_info(resource_id).map_err(|_| ErrUnspec)?;

        let prot = match map_info & RUTABAGA_MAP_ACCESS_MASK {
            RUTABAGA_MAP_ACCESS_READ => libc::PROT_READ,
            RUTABAGA_MAP_ACCESS_WRITE => libc::PROT_WRITE,
            RUTABAGA_MAP_ACCESS_RW => libc::PROT_READ | libc::PROT_WRITE,
            _ => panic!("unexpected prot mode for mapping"),
        };

        if offset + resource.size > shm_region.size as u64 {
            error!("resource map doesn't fit in shm region");
            return Err(ErrUnspec);
        }
        let addr = shm_region.host_addr + offset;

        if let Ok(export) = self.rutabaga.export_blob(resource_id) {
            if export.handle_type == RUTABAGA_MEM_HANDLE_TYPE_SHM {
                let ret = unsafe {
                    libc::mmap(
                        addr as *mut libc::c_void,
                        resource.size as usize,
                        prot,
                        libc::MAP_SHARED | libc::MAP_FIXED,
                        export.os_handle.as_raw_fd(),
                        0 as libc::off_t,
                    )
                };
                if ret == libc::MAP_FAILED {
                    error!("failed to mmap resource in shm region");
                    return Err(ErrUnspec);
                }
            } else {
                self.rutabaga.resource_map(
                    resource_id,
                    addr,
                    resource.size,
                    prot,
                    libc::MAP_SHARED | libc::MAP_FIXED,
                )?;
            }
        }

        resource.shmem_offset = Some(offset);
        // Access flags not a part of the virtio-gpu spec.
        Ok(OkMapInfo {
            map_info: map_info & RUTABAGA_MAP_CACHE_MASK,
        })
    }
    #[cfg(target_os = "macos")]
    pub fn resource_map_blob(
        &mut self,
        resource_id: u32,
        shm_region: &VirtioShmRegion,
        offset: u64,
    ) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        let map_info = self.rutabaga.map_info(resource_id).map_err(|_| ErrUnspec)?;
        let map_ptr = self.rutabaga.map_ptr(resource_id).map_err(|_| ErrUnspec)?;

        if let Ok(export) = self.rutabaga.export_blob(resource_id) {
            if export.handle_type == RUTABAGA_MEM_HANDLE_TYPE_APPLE {
                if offset + resource.size > shm_region.size as u64 {
                    error!("mapping DOES NOT FIT");
                    return Err(ErrUnspec);
                }

                let guest_addr = shm_region.guest_addr + offset;
                debug!(
                    "mapping: map_ptr={:x}, guest_addr={:x}, size={}",
                    map_ptr, guest_addr, resource.size
                );

                let (reply_sender, reply_receiver) = unbounded();
                self.map_sender
                    .send(WorkerMessage::GpuAddMapping(
                        reply_sender,
                        map_ptr,
                        guest_addr,
                        resource.size,
                    ))
                    .unwrap();
                if !reply_receiver.recv().unwrap() {
                    return Err(ErrUnspec);
                }
            } else {
                return Err(ErrUnspec);
            }
        } else {
            return Err(ErrUnspec);
        }

        resource.shmem_offset = Some(offset);
        // Access flags not a part of the virtio-gpu spec.
        Ok(OkMapInfo {
            map_info: map_info & RUTABAGA_MAP_CACHE_MASK,
        })
    }

    /// Uses the hypervisor to unmap the blob resource.
    #[cfg(target_os = "linux")]
    pub fn resource_unmap_blob(
        &mut self,
        resource_id: u32,
        shm_region: &VirtioShmRegion,
    ) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        let shmem_offset = resource.shmem_offset.ok_or(ErrUnspec)?;

        let addr = shm_region.host_addr + shmem_offset;

        let ret = unsafe {
            libc::mmap(
                addr as *mut libc::c_void,
                resource.size as usize,
                libc::PROT_NONE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_FIXED,
                -1,
                0_i64,
            )
        };
        if ret == libc::MAP_FAILED {
            panic!("UNMAP failed");
        }

        resource.shmem_offset = None;

        Ok(OkNoData)
    }
    #[cfg(target_os = "macos")]
    pub fn resource_unmap_blob(
        &mut self,
        resource_id: u32,
        shm_region: &VirtioShmRegion,
    ) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        debug!("resource_unmap_blob");
        let shmem_offset = resource.shmem_offset.ok_or(ErrUnspec)?;

        let guest_addr = shm_region.guest_addr + shmem_offset;
        debug!(
            "unmapping: guest_addr={:x}, size={}",
            guest_addr, resource.size
        );

        let (reply_sender, reply_receiver) = unbounded();
        self.map_sender
            .send(WorkerMessage::GpuRemoveMapping(
                reply_sender,
                guest_addr,
                resource.size,
            ))
            .unwrap();
        if !reply_receiver.recv().unwrap() {
            return Err(ErrUnspec);
        }

        resource.shmem_offset = None;

        Ok(OkNoData)
    }
}
#[cfg(test)]
mod test {
    use crate::virtio::gpu::protocol::VIRTIO_GPU_MAX_SCANOUTS;

    #[test]
    fn test_virtio_gpu_associated_scanouts() {
        use super::AssociatedScanouts;

        let mut scanouts = AssociatedScanouts::default();

        assert!(!scanouts.has_any_enabled());
        assert_eq!(scanouts.iter_enabled().next(), None);

        scanouts.enable(1);
        assert!(scanouts.has_any_enabled());
        scanouts.disable(1);
        assert!(!scanouts.has_any_enabled());

        (0..VIRTIO_GPU_MAX_SCANOUTS).for_each(|scanout| scanouts.enable(scanout));
        assert!(scanouts.has_any_enabled());
        assert_eq!(
            scanouts.iter_enabled().collect::<Vec<u32>>(),
            (0..VIRTIO_GPU_MAX_SCANOUTS).collect::<Vec<u32>>()
        );

        (0..VIRTIO_GPU_MAX_SCANOUTS)
            .filter(|&i| i % 2 == 0)
            .for_each(|scanout| scanouts.disable(scanout));
        assert_eq!(
            scanouts.iter_enabled().collect::<Vec<u32>>(),
            (1..VIRTIO_GPU_MAX_SCANOUTS)
                .step_by(2)
                .collect::<Vec<u32>>()
        );

        (0..VIRTIO_GPU_MAX_SCANOUTS)
            .filter(|&i| i % 2 != 0)
            .for_each(|scanout| scanouts.disable(scanout));
        assert!(!scanouts.has_any_enabled());
    }
}
