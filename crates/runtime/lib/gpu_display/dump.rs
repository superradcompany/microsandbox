//! Debug scanout sink: keeps the latest frame of each scanout in
//! `<dir>/scanout<N>.raw` (tightly packed 32-bit pixels in the guest's
//! format) next to a one-line `scanout<N>.txt` describing it, so the host
//! side of the display path can be verified without a window.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use msb_krun::krun_display::{
    DisplayBackend, DisplayBackendBasicFramebuffer, DisplayBackendError, DisplayBackendNew,
    IntoDisplayBackend, Rect, ResourceFormat, MAX_DISPLAYS,
};

/// Only every `DUMP_EVERY`th presented frame is written; the raw file is 8 MiB
/// at 1920x1080 and the compositor can flush at the display's refresh rate.
const DUMP_EVERY: u64 = 30;

struct Scanout {
    width: u32,
    height: u32,
    format: ResourceFormat,
    buffer: Vec<u8>,
    presented: u64,
}

/// Debug scanout sink: keeps the latest frame of each scanout on disk.
pub struct FrameDumpBackend {
    dir: PathBuf,
    scanouts: Vec<Option<Scanout>>,
}

impl DisplayBackendNew<PathBuf> for FrameDumpBackend {
    fn new(userdata: Option<&PathBuf>) -> Self {
        let dir = userdata
            .cloned()
            .expect("frame_dump_backend passes the directory as userdata");
        Self {
            dir,
            scanouts: (0..MAX_DISPLAYS).map(|_| None).collect(),
        }
    }
}

fn dump(dir: &Path, scanout_id: u32, scanout: &Scanout, rect: Option<&Rect>) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    let raw = dir.join(format!("scanout{scanout_id}.raw"));
    let tmp = dir.join(format!(".scanout{scanout_id}.raw.tmp"));
    fs::write(&tmp, &scanout.buffer)?;
    fs::rename(&tmp, &raw)?;
    let rect = rect
        .map(|r| format!("{}x{}+{}+{}", r.width, r.height, r.x, r.y))
        .unwrap_or_else(|| "full".to_string());
    fs::write(
        dir.join(format!("scanout{scanout_id}.txt")),
        format!(
            "width={} height={} format={:?} presented={} last_rect={}\n",
            scanout.width, scanout.height, scanout.format, scanout.presented, rect
        ),
    )
}

impl DisplayBackendBasicFramebuffer for FrameDumpBackend {
    fn configure_scanout(
        &mut self,
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        width: u32,
        height: u32,
        format: ResourceFormat,
    ) -> Result<(), DisplayBackendError> {
        let slot = self
            .scanouts
            .get_mut(scanout_id as usize)
            .ok_or(DisplayBackendError::InvalidScanoutId)?;
        tracing::info!(
            scanout_id,
            display_width,
            display_height,
            width,
            height,
            ?format,
            "gpu: scanout configured"
        );
        let size = width as usize * height as usize * ResourceFormat::BYTES_PER_PIXEL;
        *slot = Some(Scanout {
            width,
            height,
            format,
            buffer: vec![0; size],
            presented: 0,
        });
        Ok(())
    }

    fn disable_scanout(&mut self, scanout_id: u32) -> Result<(), DisplayBackendError> {
        let slot = self
            .scanouts
            .get_mut(scanout_id as usize)
            .ok_or(DisplayBackendError::InvalidScanoutId)?;
        tracing::info!(scanout_id, "gpu: scanout disabled");
        *slot = None;
        Ok(())
    }

    fn alloc_frame(&mut self, scanout_id: u32) -> Result<(u32, &mut [u8]), DisplayBackendError> {
        let scanout = self
            .scanouts
            .get_mut(scanout_id as usize)
            .and_then(Option::as_mut)
            .ok_or(DisplayBackendError::InvalidScanoutId)?;
        Ok((1, scanout.buffer.as_mut_slice()))
    }

    fn present_frame(
        &mut self,
        scanout_id: u32,
        _frame_id: u32,
        rect: Option<&Rect>,
    ) -> Result<(), DisplayBackendError> {
        let scanout = self
            .scanouts
            .get_mut(scanout_id as usize)
            .and_then(Option::as_mut)
            .ok_or(DisplayBackendError::InvalidScanoutId)?;
        scanout.presented += 1;
        if scanout.presented % DUMP_EVERY == 1 {
            if let Err(e) = dump(&self.dir, scanout_id, scanout, rect) {
                tracing::warn!(scanout_id, error = %e, "gpu: frame dump failed");
                return Err(DisplayBackendError::InternalError);
            }
        }
        Ok(())
    }
}

static DUMP_DIR: OnceLock<PathBuf> = OnceLock::new();

/// A display backend that dumps frames under `dir`. The directory is stored
/// process-wide because the backend needs `'static` userdata.
pub fn frame_dump_backend(dir: &Path) -> DisplayBackend<'static> {
    let dir = DUMP_DIR.get_or_init(|| dir.to_path_buf());
    FrameDumpBackend::into_display_backend(Some(dir))
}
