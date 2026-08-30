//! Host side of the experimental virtio-gpu display.
//!
//! The VMM hands every flushed scanout frame to a `krun_display` backend on
//! the gpu worker thread. Two backends live here:
//!
//! * [`SharedFrameBackend`] (via [`DisplayServer`]) copies frames into a
//!   memory-mapped file per scanout and tells a viewer connected to the
//!   sandbox's `display.sock` which slot is fresh; the viewer's keyboard and
//!   pointer events come back over the same socket and are queued into two
//!   virtio-input devices. `msb display <sandbox>` is that viewer.
//! * [`dump::FrameDumpBackend`] keeps the latest frame on disk for debugging.
//!
//! `present_frame` must never wait for a viewer: the guest's FLUSH is only
//! answered once it returns.

pub mod dump;
pub mod input;
pub mod protocol;

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use memmap2::{MmapMut, MmapOptions};
use msb_krun::krun_display::{
    DisplayBackend, DisplayBackendBasicFramebuffer, DisplayBackendError, DisplayBackendNew,
    IntoDisplayBackend, Rect, ResourceFormat, MAX_DISPLAYS,
};
use msb_krun::krun_input::{InputConfigBackend, InputEvent, InputEventProviderBackend};
use msb_krun_utils::pollable_channel::PollableChannelSender;

pub use dump::frame_dump_backend;
use input::{event, syn, InputDevice};
use protocol::evdev::*;
use protocol::{ServerMsg, ViewerMsg, SLOTS};

/// A viewer connection; only one is served at a time.
struct Viewer {
    id: u64,
    stream: UnixStream,
}

struct ScanoutInfo {
    width: u32,
    height: u32,
    format: String,
    path: PathBuf,
}

/// State shared between the gpu worker thread (frames), the accept thread
/// and the per-connection reader threads (input).
struct Shared {
    sandbox: String,
    fb_dir: PathBuf,
    viewer: Mutex<Option<Viewer>>,
    scanouts: Mutex<Vec<Option<ScanoutInfo>>>,
    keyboard_tx: PollableChannelSender<InputEvent>,
    pointer_tx: PollableChannelSender<InputEvent>,
}

impl Shared {
    fn send(&self, msg: &ServerMsg) {
        let mut guard = self.viewer.lock().unwrap_or_else(|e| e.into_inner());
        let Some(viewer) = guard.as_mut() else { return };
        let mut line = serde_json::to_vec(msg).expect("protocol messages serialize");
        line.push(b'\n');
        if let Err(e) = viewer.stream.write_all(&line) {
            tracing::info!(viewer = viewer.id, error = %e, "gpu display: dropping viewer");
            *guard = None;
        }
    }

    fn attach(&self, id: u64, stream: UnixStream) {
        // A stalled viewer must not stall the guest's FLUSH.
        let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
        {
            let mut guard = self.viewer.lock().unwrap_or_else(|e| e.into_inner());
            *guard = Some(Viewer { id, stream });
        }
        tracing::info!(viewer = id, "gpu display: viewer attached");
        self.send(&ServerMsg::Hello {
            sandbox: self.sandbox.clone(),
        });
        let scanouts = self.scanouts.lock().unwrap_or_else(|e| e.into_inner());
        for (scanout, info) in scanouts.iter().enumerate() {
            if let Some(info) = info {
                self.send(&configure_msg(scanout as u32, info));
            }
        }
    }

    fn detach(&self, id: u64) {
        let mut guard = self.viewer.lock().unwrap_or_else(|e| e.into_inner());
        if guard.as_ref().is_some_and(|v| v.id == id) {
            *guard = None;
            tracing::info!(viewer = id, "gpu display: viewer detached");
        }
    }

    fn handle(&self, msg: ViewerMsg) {
        let result = match msg {
            ViewerMsg::Key { code, down } => self
                .keyboard_tx
                .send_many([event(EV_KEY, code, u32::from(down)), syn()]),
            ViewerMsg::Abs { x, y } => self.pointer_tx.send_many([
                event(EV_ABS, ABS_X, x),
                event(EV_ABS, ABS_Y, y),
                syn(),
            ]),
            ViewerMsg::Btn { code, down } => self
                .pointer_tx
                .send_many([event(EV_KEY, code, u32::from(down)), syn()]),
            ViewerMsg::Rel { code, value } => self
                .pointer_tx
                .send_many([event(EV_REL, code, value as u32), syn()]),
        };
        if let Err(e) = result {
            tracing::warn!(error = %e, "gpu display: input event dropped");
        }
    }
}

fn configure_msg(scanout: u32, info: &ScanoutInfo) -> ServerMsg {
    ServerMsg::Configure {
        scanout,
        width: info.width,
        height: info.height,
        format: info.format.clone(),
        path: info.path.to_string_lossy().into_owned(),
        slots: SLOTS,
    }
}

/// Serves scanout frames and accepts input on the sandbox's display socket.
pub struct DisplayServer {
    shared: &'static &'static Shared,
    keyboard: Option<InputDevice>,
    pointer: Option<InputDevice>,
}

impl DisplayServer {
    /// Listen on `socket`; frame files go under `fb_dir`.
    pub fn start(sandbox: &str, fb_dir: &Path, socket: &Path) -> io::Result<Self> {
        let keyboard = input::keyboard()?;
        let pointer = input::pointer()?;
        let shared: &'static Shared = Box::leak(Box::new(Shared {
            sandbox: sandbox.to_string(),
            fb_dir: fb_dir.to_path_buf(),
            viewer: Mutex::new(None),
            scanouts: Mutex::new((0..MAX_DISPLAYS).map(|_| None).collect()),
            keyboard_tx: keyboard.tx.clone(),
            pointer_tx: pointer.tx.clone(),
        }));
        fs::create_dir_all(fb_dir)?;
        let _ = fs::remove_file(socket);
        let listener = UnixListener::bind(socket)?;
        std::thread::Builder::new()
            .name("gpu display".into())
            .spawn(move || accept_loop(shared, listener))?;
        tracing::info!(socket = %socket.display(), "gpu display: listening");
        Ok(Self {
            shared: Box::leak(Box::new(shared)),
            keyboard: Some(keyboard),
            pointer: Some(pointer),
        })
    }

    /// The display backend to hand to the VM builder.
    pub fn display_backend(&self) -> DisplayBackend<'static> {
        SharedFrameBackend::into_display_backend(Some(self.shared))
    }

    /// The virtual keyboard's backends (once).
    pub fn take_keyboard(
        &mut self,
    ) -> Option<(InputConfigBackend<'static>, InputEventProviderBackend<'static>)> {
        self.keyboard.take().map(|d| (d.config, d.events))
    }

    /// The virtual pointer's backends (once).
    pub fn take_pointer(
        &mut self,
    ) -> Option<(InputConfigBackend<'static>, InputEventProviderBackend<'static>)> {
        self.pointer.take().map(|d| (d.config, d.events))
    }
}

fn accept_loop(shared: &'static Shared, listener: UnixListener) {
    let mut next_id = 1u64;
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(e) => {
                tracing::warn!(error = %e, "gpu display: accept failed");
                continue;
            }
        };
        let id = next_id;
        next_id += 1;
        let writer = match stream.try_clone() {
            Ok(writer) => writer,
            Err(e) => {
                tracing::warn!(error = %e, "gpu display: clone failed");
                continue;
            }
        };
        shared.attach(id, writer);
        if let Err(e) = std::thread::Builder::new()
            .name(format!("gpu display viewer {id}"))
            .spawn(move || read_loop(shared, id, stream))
        {
            tracing::warn!(error = %e, "gpu display: reader thread failed");
            shared.detach(id);
        }
    }
}

fn read_loop(shared: &'static Shared, id: u64, stream: UnixStream) {
    for line in BufReader::new(stream).lines() {
        let Ok(line) = line else { break };
        match serde_json::from_str::<ViewerMsg>(&line) {
            Ok(msg) => shared.handle(msg),
            Err(e) => tracing::debug!(error = %e, "gpu display: bad viewer message"),
        }
    }
    shared.detach(id);
}

struct Frames {
    mmap: MmapMut,
    frame_size: usize,
    format: ResourceFormat,
    seq: u64,
    slot: usize,
}

/// Display backend writing frames into per-scanout shared files.
pub struct SharedFrameBackend {
    shared: &'static Shared,
    frames: Vec<Option<Frames>>,
}

impl DisplayBackendNew<&'static Shared> for SharedFrameBackend {
    fn new(userdata: Option<&&'static Shared>) -> Self {
        Self {
            shared: *userdata.expect("DisplayServer passes its state as userdata"),
            frames: (0..MAX_DISPLAYS).map(|_| None).collect(),
        }
    }
}

fn map_frames(path: &Path, frame_size: usize) -> io::Result<MmapMut> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.set_len((frame_size * SLOTS as usize) as u64)?;
    // SAFETY: the file is private to the sandbox runtime dir and only ever
    // remapped read-only by the viewer.
    unsafe { MmapOptions::new().map_mut(&file) }
}

impl DisplayBackendBasicFramebuffer for SharedFrameBackend {
    fn configure_scanout(
        &mut self,
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        width: u32,
        height: u32,
        format: ResourceFormat,
    ) -> Result<(), DisplayBackendError> {
        if scanout_id as usize >= self.frames.len() {
            return Err(DisplayBackendError::InvalidScanoutId);
        }
        let frame_size = width as usize * height as usize * ResourceFormat::BYTES_PER_PIXEL;
        // The guest re-issues SET_SCANOUT on every page flip; keep the
        // mapping (and the viewer's) when nothing about it changed.
        if let Some(frames) = &self.frames[scanout_id as usize] {
            if frames.frame_size == frame_size && frames.format == format {
                return Ok(());
            }
        }
        let path = self.shared.fb_dir.join(format!("scanout{scanout_id}.fb"));
        let mmap = map_frames(&path, frame_size).map_err(|e| {
            tracing::warn!(scanout_id, error = %e, "gpu display: cannot map frame file");
            DisplayBackendError::InternalError
        })?;
        tracing::info!(
            scanout_id,
            display_width,
            display_height,
            width,
            height,
            ?format,
            "gpu display: scanout configured"
        );
        self.frames[scanout_id as usize] = Some(Frames {
            mmap,
            frame_size,
            format,
            seq: 0,
            slot: 0,
        });
        let info = ScanoutInfo {
            width,
            height,
            format: format!("{format:?}"),
            path,
        };
        let msg = configure_msg(scanout_id, &info);
        {
            let mut scanouts = self.shared.scanouts.lock().unwrap_or_else(|e| e.into_inner());
            scanouts[scanout_id as usize] = Some(info);
        }
        self.shared.send(&msg);
        Ok(())
    }

    fn disable_scanout(&mut self, scanout_id: u32) -> Result<(), DisplayBackendError> {
        let slot = self
            .frames
            .get_mut(scanout_id as usize)
            .ok_or(DisplayBackendError::InvalidScanoutId)?;
        *slot = None;
        let path = {
            let mut scanouts = self.shared.scanouts.lock().unwrap_or_else(|e| e.into_inner());
            scanouts[scanout_id as usize].take().map(|info| info.path)
        };
        if let Some(path) = path {
            let _ = fs::remove_file(path);
        }
        tracing::info!(scanout_id, "gpu display: scanout disabled");
        self.shared.send(&ServerMsg::Disable {
            scanout: scanout_id,
        });
        Ok(())
    }

    fn alloc_frame(&mut self, scanout_id: u32) -> Result<(u32, &mut [u8]), DisplayBackendError> {
        let frames = self
            .frames
            .get_mut(scanout_id as usize)
            .and_then(Option::as_mut)
            .ok_or(DisplayBackendError::InvalidScanoutId)?;
        frames.slot = ((frames.seq + 1) % u64::from(SLOTS)) as usize;
        let start = frames.slot * frames.frame_size;
        let end = start + frames.frame_size;
        Ok((frames.slot as u32, &mut frames.mmap[start..end]))
    }

    fn present_frame(
        &mut self,
        scanout_id: u32,
        frame_id: u32,
        rect: Option<&Rect>,
    ) -> Result<(), DisplayBackendError> {
        let frames = self
            .frames
            .get_mut(scanout_id as usize)
            .and_then(Option::as_mut)
            .ok_or(DisplayBackendError::InvalidScanoutId)?;
        frames.seq += 1;
        self.shared.send(&ServerMsg::Frame {
            scanout: scanout_id,
            slot: frame_id,
            seq: frames.seq,
            rect: rect.map(|r| [r.x, r.y, r.width, r.height]),
        });
        Ok(())
    }
}
