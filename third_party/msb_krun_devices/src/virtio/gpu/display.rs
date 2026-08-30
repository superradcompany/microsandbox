use super::edid::EdidInfo;
use krun_display::{
    DisplayBackendBasicFramebuffer, DisplayBackendError, DisplayBackendNew, Rect, ResourceFormat,
};
use virtio_bindings::virtio_gpu::VIRTIO_GPU_MAX_SCANOUTS;

#[derive(Clone, Debug)]
pub struct DisplayInfo {
    pub width: u32,
    pub height: u32,
    pub edid: DisplayInfoEdid,
}

impl DisplayInfo {
    pub fn edid_bytes(&self) -> Box<[u8]> {
        match &self.edid {
            DisplayInfoEdid::Provided(edid_bytes) => edid_bytes.clone(),
            DisplayInfoEdid::Generated(edid_params) => {
                let edid_info = EdidInfo::new(self.width, self.height, edid_params);
                edid_info.bytes()
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum DisplayInfoEdid {
    Generated(EdidParams),
    Provided(Box<[u8]>),
}

#[derive(Debug, Clone, Copy)]
pub struct EdidParams {
    pub refresh_rate: u32,
    pub physical_size: PhysicalSize,
}

impl Default for EdidParams {
    fn default() -> Self {
        EdidParams {
            refresh_rate: 60,
            physical_size: PhysicalSize::Dpi(300),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum PhysicalSize {
    Dpi(u32),
    DimensionsMillimeters(u16, u16),
}

impl DisplayInfo {
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            edid: DisplayInfoEdid::Generated(EdidParams::default()),
        }
    }
}

pub const MAX_DISPLAYS: usize = VIRTIO_GPU_MAX_SCANOUTS as usize;

pub struct NoopDisplayBackend;

impl DisplayBackendNew<()> for NoopDisplayBackend {
    fn new(_userdata: Option<&()>) -> Self {
        Self
    }
}

impl DisplayBackendBasicFramebuffer for NoopDisplayBackend {
    fn configure_scanout(
        &mut self,
        _scanout_id: u32,
        _display_width: u32,
        _display_height: u32,
        _width: u32,
        _height: u32,
        _format: ResourceFormat,
    ) -> Result<(), DisplayBackendError> {
        Err(DisplayBackendError::InvalidScanoutId)
    }

    fn disable_scanout(&mut self, _scanout_id: u32) -> Result<(), DisplayBackendError> {
        Err(DisplayBackendError::InvalidScanoutId)
    }

    fn alloc_frame(&mut self, _scanout_id: u32) -> Result<(u32, &mut [u8]), DisplayBackendError> {
        Err(DisplayBackendError::InvalidScanoutId)
    }

    fn present_frame(
        &mut self,
        _scanout_id: u32,
        _frame_id: u32,
        _rect: Option<&Rect>,
    ) -> Result<(), DisplayBackendError> {
        Err(DisplayBackendError::InvalidScanoutId)
    }
}
