//! `msb display` — show a sandbox's virtio-gpu scanout in a native window and
//! feed keyboard/pointer events back to it (macOS only).
//!
//! The sandbox process serves frames through a memory-mapped file per
//! scanout and a JSON-lines socket (see
//! `microsandbox_runtime::gpu_display::protocol`); this command is the viewer.
//! It runs the window event loop on the process's main thread, before the
//! Tokio runtime starts.

use clap::Args;

/// Open a native window on a running sandbox's display.
#[derive(Debug, Args)]
pub struct DisplayArgs {
    /// Sandbox whose display to show.
    pub name: String,
}

/// Execute `msb display`. Never returns.
#[cfg(not(target_os = "macos"))]
pub fn run(_args: DisplayArgs) -> ! {
    eprintln!("msb display is only available on macOS in this build");
    std::process::exit(2);
}

/// Execute `msb display`. Never returns.
#[cfg(target_os = "macos")]
pub fn run(args: DisplayArgs) -> ! {
    match macos::run(&args.name) {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Write};
    use std::num::NonZeroU32;
    use std::os::unix::net::UnixStream;
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};

    use anyhow::{anyhow, Context};
    use memmap2::Mmap;
    use microsandbox_runtime::gpu_display::protocol::evdev::*;
    use microsandbox_runtime::gpu_display::protocol::{ServerMsg, ViewerMsg, ABS_RANGE};
    use microsandbox_runtime::ipc::{display_socket_path_for, sandbox_socket_paths};
    use winit::application::ApplicationHandler;
    use winit::dpi::PhysicalSize;
    use winit::event::{ElementState, MouseButton, MouseScrollDelta, WindowEvent};
    use winit::event_loop::{ActiveEventLoop, EventLoop, EventLoopProxy};
    use winit::keyboard::{KeyCode, PhysicalKey};
    use winit::window::{Window, WindowId};

    /// Only the first scanout is shown.
    const SCANOUT: u32 = 0;

    enum UserEvent {
        Server(ServerMsg),
        Disconnected,
    }

    struct Scanout {
        width: u32,
        height: u32,
        frame_size: usize,
        mmap: Mmap,
        slot: usize,
    }

    struct Sender(Mutex<UnixStream>);

    impl Sender {
        fn send(&self, msg: &ViewerMsg) {
            let mut line = serde_json::to_vec(msg).expect("protocol messages serialize");
            line.push(b'\n');
            let mut stream = self.0.lock().unwrap_or_else(|e| e.into_inner());
            let _ = stream.write_all(&line);
        }
    }

    struct App {
        sandbox: String,
        sender: Arc<Sender>,
        window: Option<Rc<Window>>,
        surface: Option<softbuffer::Surface<Rc<Window>, Rc<Window>>>,
        scanout: Option<Scanout>,
        wheel_carry: (f32, f32),
    }

    impl App {
        fn ensure_window(&mut self, event_loop: &ActiveEventLoop, width: u32, height: u32) {
            if let Some(window) = &self.window {
                let _ = window.request_inner_size(PhysicalSize::new(width, height));
                return;
            }
            let attrs = Window::default_attributes()
                .with_title(format!("{} — microsandbox", self.sandbox))
                .with_inner_size(PhysicalSize::new(width, height));
            let window = match event_loop.create_window(attrs) {
                Ok(window) => Rc::new(window),
                Err(e) => {
                    eprintln!("error: cannot create window: {e}");
                    event_loop.exit();
                    return;
                }
            };
            let context = softbuffer::Context::new(window.clone()).expect("softbuffer context");
            let surface = softbuffer::Surface::new(&context, window.clone()).expect("surface");
            self.window = Some(window);
            self.surface = Some(surface);
        }

        fn redraw(&mut self) {
            let (Some(window), Some(surface), Some(scanout)) =
                (&self.window, &mut self.surface, &self.scanout)
            else {
                return;
            };
            let size = window.inner_size();
            let (Some(w), Some(h)) = (NonZeroU32::new(size.width), NonZeroU32::new(size.height))
            else {
                return;
            };
            if surface.resize(w, h).is_err() {
                return;
            }
            let Ok(mut buffer) = surface.buffer_mut() else { return };
            let start = scanout.slot * scanout.frame_size;
            let src = &scanout.mmap[start..start + scanout.frame_size];
            let (sw, sh) = (scanout.width as usize, scanout.height as usize);
            let (dw, dh) = (size.width as usize, size.height as usize);
            if (sw, sh) == (dw, dh) {
                for (dst, px) in buffer.iter_mut().zip(src.chunks_exact(4)) {
                    *dst = u32::from_le_bytes([px[0], px[1], px[2], 0]);
                }
            } else {
                // Nearest-neighbour scale; the window is usually the scanout
                // size or its HiDPI multiple.
                for y in 0..dh {
                    let sy = y * sh / dh;
                    let row = &src[sy * sw * 4..(sy + 1) * sw * 4];
                    let out = &mut buffer[y * dw..(y + 1) * dw];
                    for (x, dst) in out.iter_mut().enumerate() {
                        let sx = x * sw / dw;
                        let px = &row[sx * 4..sx * 4 + 4];
                        *dst = u32::from_le_bytes([px[0], px[1], px[2], 0]);
                    }
                }
            }
            let _ = buffer.present();
        }

        fn pointer_abs(&self, x: f64, y: f64) -> Option<(u32, u32)> {
            let size = self.window.as_ref()?.inner_size();
            if size.width == 0 || size.height == 0 {
                return None;
            }
            let scale = |v: f64, max: u32| -> u32 {
                ((v / f64::from(max)).clamp(0.0, 1.0) * f64::from(ABS_RANGE)).round() as u32
            };
            Some((scale(x, size.width), scale(y, size.height)))
        }
    }

    impl ApplicationHandler<UserEvent> for App {
        fn resumed(&mut self, _event_loop: &ActiveEventLoop) {}

        fn user_event(&mut self, event_loop: &ActiveEventLoop, event: UserEvent) {
            match event {
                UserEvent::Server(ServerMsg::Hello { sandbox }) => {
                    eprintln!("connected to {sandbox}");
                }
                UserEvent::Server(ServerMsg::Configure {
                    scanout,
                    width,
                    height,
                    format,
                    path,
                    slots,
                }) => {
                    if scanout != SCANOUT {
                        return;
                    }
                    let frame_size = width as usize * height as usize * 4;
                    let mmap = File::open(&path)
                        .and_then(|f| unsafe { Mmap::map(&f) })
                        .ok()
                        .filter(|m| m.len() >= frame_size * slots as usize);
                    let Some(mmap) = mmap else {
                        eprintln!("error: cannot map {path}");
                        return;
                    };
                    eprintln!("scanout {scanout}: {width}x{height} {format}");
                    self.scanout = Some(Scanout {
                        width,
                        height,
                        frame_size,
                        mmap,
                        slot: 0,
                    });
                    self.ensure_window(event_loop, width, height);
                    if let Some(window) = &self.window {
                        window.request_redraw();
                    }
                }
                UserEvent::Server(ServerMsg::Frame { scanout, slot, .. }) => {
                    if scanout != SCANOUT {
                        return;
                    }
                    if let Some(s) = &mut self.scanout {
                        s.slot = slot as usize;
                    }
                    if let Some(window) = &self.window {
                        window.request_redraw();
                    }
                }
                UserEvent::Server(ServerMsg::Disable { scanout }) => {
                    if scanout == SCANOUT {
                        self.scanout = None;
                    }
                }
                UserEvent::Disconnected => {
                    eprintln!("sandbox display closed");
                    event_loop.exit();
                }
            }
        }

        fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
            match event {
                WindowEvent::CloseRequested => event_loop.exit(),
                WindowEvent::RedrawRequested => self.redraw(),
                WindowEvent::Resized(_) | WindowEvent::ScaleFactorChanged { .. } => {
                    if let Some(window) = &self.window {
                        window.request_redraw();
                    }
                }
                WindowEvent::KeyboardInput { event, .. } => {
                    if event.repeat {
                        return;
                    }
                    let PhysicalKey::Code(code) = event.physical_key else { return };
                    let Some(code) = keycode_to_evdev(code) else { return };
                    self.sender.send(&ViewerMsg::Key {
                        code,
                        down: event.state == ElementState::Pressed,
                    });
                }
                WindowEvent::CursorMoved { position, .. } => {
                    if let Some((x, y)) = self.pointer_abs(position.x, position.y) {
                        self.sender.send(&ViewerMsg::Abs { x, y });
                    }
                }
                WindowEvent::MouseInput { state, button, .. } => {
                    let code = match button {
                        MouseButton::Left => BTN_LEFT,
                        MouseButton::Right => BTN_RIGHT,
                        MouseButton::Middle => BTN_MIDDLE,
                        _ => return,
                    };
                    self.sender.send(&ViewerMsg::Btn {
                        code,
                        down: state == ElementState::Pressed,
                    });
                }
                WindowEvent::MouseWheel { delta, .. } => {
                    let (dx, dy) = match delta {
                        MouseScrollDelta::LineDelta(x, y) => (x, y),
                        MouseScrollDelta::PixelDelta(p) => (p.x as f32 / 40.0, p.y as f32 / 40.0),
                    };
                    self.wheel_carry.0 += dx;
                    self.wheel_carry.1 += dy;
                    let steps_x = self.wheel_carry.0.trunc();
                    let steps_y = self.wheel_carry.1.trunc();
                    self.wheel_carry.0 -= steps_x;
                    self.wheel_carry.1 -= steps_y;
                    if steps_y != 0.0 {
                        self.sender.send(&ViewerMsg::Rel {
                            code: REL_WHEEL,
                            value: steps_y as i32,
                        });
                    }
                    if steps_x != 0.0 {
                        self.sender.send(&ViewerMsg::Rel {
                            code: REL_HWHEEL,
                            value: steps_x as i32,
                        });
                    }
                }
                _ => {}
            }
        }
    }

    fn reader(stream: UnixStream, proxy: EventLoopProxy<UserEvent>) {
        for line in BufReader::new(stream).lines() {
            let Ok(line) = line else { break };
            match serde_json::from_str::<ServerMsg>(&line) {
                Ok(msg) => {
                    if proxy.send_event(UserEvent::Server(msg)).is_err() {
                        return;
                    }
                }
                Err(e) => eprintln!("warning: bad message from sandbox: {e}"),
            }
        }
        let _ = proxy.send_event(UserEvent::Disconnected);
    }

    pub fn run(name: &str) -> anyhow::Result<()> {
        let run_dir = microsandbox_utils::resolve_home().join(microsandbox_utils::RUN_SUBDIR);
        let paths = sandbox_socket_paths(&run_dir, name);
        let socket = display_socket_path_for(&paths.agent);
        let stream = UnixStream::connect(&socket).with_context(|| {
            format!(
                "cannot connect to {}; is `{name}` running with MSB_GPU=1?",
                socket.display()
            )
        })?;
        let reader_stream = stream.try_clone().context("clone socket")?;
        let event_loop = EventLoop::<UserEvent>::with_user_event()
            .build()
            .map_err(|e| anyhow!("event loop: {e}"))?;
        let proxy = event_loop.create_proxy();
        std::thread::Builder::new()
            .name("display reader".into())
            .spawn(move || reader(reader_stream, proxy))
            .context("spawn reader")?;
        let mut app = App {
            sandbox: name.to_string(),
            sender: Arc::new(Sender(Mutex::new(stream))),
            window: None,
            surface: None,
            scanout: None,
            wheel_carry: (0.0, 0.0),
        };
        event_loop
            .run_app(&mut app)
            .map_err(|e| anyhow!("event loop: {e}"))
    }

    /// winit physical key → Linux `KEY_*` code.
    fn keycode_to_evdev(code: KeyCode) -> Option<u16> {
        use KeyCode::*;
        Some(match code {
            Escape => KEY_ESC,
            Digit1 => KEY_1,
            Digit2 => KEY_2,
            Digit3 => KEY_3,
            Digit4 => KEY_4,
            Digit5 => KEY_5,
            Digit6 => KEY_6,
            Digit7 => KEY_7,
            Digit8 => KEY_8,
            Digit9 => KEY_9,
            Digit0 => KEY_0,
            Minus => KEY_MINUS,
            Equal => KEY_EQUAL,
            Backspace => KEY_BACKSPACE,
            Tab => KEY_TAB,
            KeyQ => KEY_Q,
            KeyW => KEY_W,
            KeyE => KEY_E,
            KeyR => KEY_R,
            KeyT => KEY_T,
            KeyY => KEY_Y,
            KeyU => KEY_U,
            KeyI => KEY_I,
            KeyO => KEY_O,
            KeyP => KEY_P,
            BracketLeft => KEY_LEFTBRACE,
            BracketRight => KEY_RIGHTBRACE,
            Enter => KEY_ENTER,
            ControlLeft => KEY_LEFTCTRL,
            KeyA => KEY_A,
            KeyS => KEY_S,
            KeyD => KEY_D,
            KeyF => KEY_F,
            KeyG => KEY_G,
            KeyH => KEY_H,
            KeyJ => KEY_J,
            KeyK => KEY_K,
            KeyL => KEY_L,
            Semicolon => KEY_SEMICOLON,
            Quote => KEY_APOSTROPHE,
            Backquote => KEY_GRAVE,
            ShiftLeft => KEY_LEFTSHIFT,
            Backslash => KEY_BACKSLASH,
            KeyZ => KEY_Z,
            KeyX => KEY_X,
            KeyC => KEY_C,
            KeyV => KEY_V,
            KeyB => KEY_B,
            KeyN => KEY_N,
            KeyM => KEY_M,
            Comma => KEY_COMMA,
            Period => KEY_DOT,
            Slash => KEY_SLASH,
            ShiftRight => KEY_RIGHTSHIFT,
            NumpadMultiply => KEY_KPASTERISK,
            AltLeft => KEY_LEFTALT,
            Space => KEY_SPACE,
            CapsLock => KEY_CAPSLOCK,
            F1 => KEY_F1,
            F2 => KEY_F2,
            F3 => KEY_F3,
            F4 => KEY_F4,
            F5 => KEY_F5,
            F6 => KEY_F6,
            F7 => KEY_F7,
            F8 => KEY_F8,
            F9 => KEY_F9,
            F10 => KEY_F10,
            NumLock => KEY_NUMLOCK,
            ScrollLock => KEY_SCROLLLOCK,
            Numpad7 => KEY_KP7,
            Numpad8 => KEY_KP8,
            Numpad9 => KEY_KP9,
            NumpadSubtract => KEY_KPMINUS,
            Numpad4 => KEY_KP4,
            Numpad5 => KEY_KP5,
            Numpad6 => KEY_KP6,
            NumpadAdd => KEY_KPPLUS,
            Numpad1 => KEY_KP1,
            Numpad2 => KEY_KP2,
            Numpad3 => KEY_KP3,
            Numpad0 => KEY_KP0,
            NumpadDecimal => KEY_KPDOT,
            IntlBackslash => KEY_102ND,
            F11 => KEY_F11,
            F12 => KEY_F12,
            NumpadEnter => KEY_KPENTER,
            ControlRight => KEY_RIGHTCTRL,
            NumpadDivide => KEY_KPSLASH,
            PrintScreen => KEY_SYSRQ,
            AltRight => KEY_RIGHTALT,
            Home => KEY_HOME,
            ArrowUp => KEY_UP,
            PageUp => KEY_PAGEUP,
            ArrowLeft => KEY_LEFT,
            ArrowRight => KEY_RIGHT,
            End => KEY_END,
            ArrowDown => KEY_DOWN,
            PageDown => KEY_PAGEDOWN,
            Insert => KEY_INSERT,
            Delete => KEY_DELETE,
            AudioVolumeMute => KEY_MUTE,
            AudioVolumeDown => KEY_VOLUMEDOWN,
            AudioVolumeUp => KEY_VOLUMEUP,
            NumpadEqual => KEY_KPEQUAL,
            Pause => KEY_PAUSE,
            SuperLeft => KEY_LEFTMETA,
            SuperRight => KEY_RIGHTMETA,
            ContextMenu => KEY_COMPOSE,
            _ => return None,
        })
    }
}
