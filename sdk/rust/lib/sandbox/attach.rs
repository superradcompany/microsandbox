//! Interactive attach types for terminal bridging with sandboxes.

use microsandbox_types::EnvVar;

use crate::MicrosandboxResult;

use super::exec::Rlimit;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Options for attaching to a sandbox with an interactive session.
///
/// The host terminal is set to raw mode for the duration of the attach session.
/// The guest process runs in a PTY, enabling terminal features (colors, line
/// editing, Ctrl+C → SIGINT).
#[derive(Debug, Clone, Default)]
pub struct AttachOptions {
    /// Arguments.
    pub(crate) args: Vec<String>,

    /// Environment variables (merged with sandbox env).
    pub(crate) env: Vec<EnvVar>,

    /// Working directory (default: sandbox's workdir).
    pub(crate) cwd: Option<String>,

    /// Guest user override for the attached command.
    pub(crate) user: Option<String>,

    /// Detach key sequence (default: `"ctrl-]"`).
    ///
    /// Uses Docker-style syntax: `"ctrl-<char>"` for control keys,
    /// comma-separated for multi-key sequences (e.g., `"ctrl-p,ctrl-q"`).
    pub(crate) detach_keys: Option<String>,

    /// Resource limits.
    pub(crate) rlimits: Vec<Rlimit>,
}

/// Builder for `AttachOptions`.
#[derive(Default)]
pub struct AttachOptionsBuilder {
    options: AttachOptions,
}

/// Parsed detach key sequence.
///
/// Matches raw stdin bytes against the configured detach sequence.
pub(crate) struct DetachKeys {
    /// The byte sequence that triggers detach.
    sequence: Vec<u8>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AttachOptionsBuilder {
    /// Append a command-line argument to the attached command.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.options.args.push(arg.into());
        self
    }

    /// Append multiple command-line arguments.
    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.options.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Override the working directory for the attached session.
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.options.cwd = Some(cwd.into());
        self
    }

    /// Override the guest user for the attached session.
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.options.user = Some(user.into());
        self
    }

    /// Set an environment variable for the attached session. Merged on
    /// top of sandbox-level env vars.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.env.push(EnvVar::new(key, value));
        self
    }

    /// Set multiple environment variables for the attached session.
    pub fn envs(
        mut self,
        vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.options
            .env
            .extend(vars.into_iter().map(|(key, value)| EnvVar::new(key, value)));
        self
    }

    /// Key sequence to detach from the session without stopping it.
    /// Uses Docker-style syntax: `"ctrl-]"` (default), `"ctrl-p,ctrl-q"`,
    /// or a single character like `"q"`.
    pub fn detach_keys(mut self, keys: impl Into<String>) -> Self {
        self.options.detach_keys = Some(keys.into());
        self
    }

    /// Set a resource limit (soft = hard).
    pub fn rlimit(mut self, resource: super::exec::RlimitResource, limit: u64) -> Self {
        self.options.rlimits.push(Rlimit {
            resource,
            soft: limit,
            hard: limit,
        });
        self
    }

    /// Set a resource limit with different soft/hard values.
    pub fn rlimit_range(
        mut self,
        resource: super::exec::RlimitResource,
        soft: u64,
        hard: u64,
    ) -> Self {
        self.options.rlimits.push(Rlimit {
            resource,
            soft,
            hard,
        });
        self
    }

    /// Finalize the options. Called automatically when using the closure form.
    ///
    /// Returns an error if any rlimit entry has `soft > hard`.
    pub fn build(self) -> MicrosandboxResult<AttachOptions> {
        super::exec::validate_rlimits(&self.options.rlimits)?;
        Ok(self.options)
    }
}

impl DetachKeys {
    /// Default detach key: Ctrl+] (0x1D).
    const DEFAULT: u8 = 0x1d;

    /// Parse a detach key specification string.
    ///
    /// Supports Docker-style syntax:
    /// - `"ctrl-]"` → `[0x1D]`
    /// - `"ctrl-a"` → `[0x01]`
    /// - `"ctrl-p,ctrl-q"` → `[0x10, 0x11]`
    pub fn parse(spec: &str) -> MicrosandboxResult<Self> {
        let mut sequence = Vec::new();
        for part in spec.split(',') {
            let part = part.trim();
            if let Some(ch) = part.strip_prefix("ctrl-") {
                let byte = match ch {
                    "]" => 0x1d,
                    "[" => 0x1b,
                    "\\" => 0x1c,
                    "^" => 0x1e,
                    "_" => 0x1f,
                    "@" => 0x00,
                    c if c.len() == 1 => {
                        let b = c.as_bytes()[0];
                        if b.is_ascii_lowercase() {
                            b - b'a' + 1
                        } else if b.is_ascii_uppercase() {
                            b - b'A' + 1
                        } else {
                            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                                "invalid detach key: {part}"
                            )));
                        }
                    }
                    _ => {
                        return Err(crate::MicrosandboxError::InvalidConfig(format!(
                            "invalid detach key: {part}"
                        )));
                    }
                };
                sequence.push(byte);
            } else if part.len() == 1 {
                sequence.push(part.as_bytes()[0]);
            } else {
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "invalid detach key: {part}"
                )));
            }
        }

        if sequence.is_empty() {
            sequence.push(Self::DEFAULT);
        }

        Ok(Self { sequence })
    }

    /// Create the default detach keys (Ctrl+]).
    pub fn default_keys() -> Self {
        Self {
            sequence: vec![Self::DEFAULT],
        }
    }

    /// Returns the detach key sequence bytes.
    pub fn sequence(&self) -> &[u8] {
        &self.sequence
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn input_contains_detach_sequence(
    data: &[u8],
    detach_seq: &[u8],
    match_pos: &mut usize,
) -> bool {
    if detach_seq.is_empty() {
        return false;
    }

    for &byte in data {
        if byte == detach_seq[*match_pos] {
            *match_pos += 1;
            if *match_pos == detach_seq.len() {
                return true;
            }
        } else {
            *match_pos = 0;
            if byte == detach_seq[0] {
                *match_pos = 1;
            }
        }
    }

    false
}

//--------------------------------------------------------------------------------------------------
// Module: local (free fn impls called by LocalBackend's SandboxBackend impl)
//--------------------------------------------------------------------------------------------------

#[cfg(unix)]
pub(crate) mod local {
    //! Local attach impl: bridges the host TTY to a PTY exec session in the
    //! named sandbox. Owns the host terminal's raw mode for the duration.

    use std::os::fd::AsRawFd;
    use std::sync::Arc;

    use microsandbox_protocol::{
        exec::{ExecExited, ExecResize, ExecStdin, ExecStdout},
        message::MessageType,
    };
    use tokio::io::{AsyncWriteExt, unix::AsyncFd};

    use crate::{
        MicrosandboxResult,
        backend::LocalBackend,
        sandbox::{
            AttachOptionsBuilder, SandboxConfig, build_exec_request,
            open_nonblocking_terminal_input, read_from_fd, terminal_path_for_fd,
        },
    };

    use super::{DetachKeys, input_contains_detach_sequence};

    pub(crate) async fn attach(
        local: &LocalBackend,
        name: &str,
        config: &SandboxConfig,
        cmd: String,
        opts_builder: AttachOptionsBuilder,
    ) -> MicrosandboxResult<i32> {
        let opts = opts_builder.build()?;

        let client = Arc::new(super::super::fs::local::connect_agent(local, name).await?);

        let detach_keys = match &opts.detach_keys {
            Some(spec) => DetachKeys::parse(spec)?,
            None => DetachKeys::default_keys(),
        };

        let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));

        let req = build_exec_request(
            config,
            cmd,
            opts.args,
            opts.cwd,
            opts.user,
            &opts.env,
            &opts.rlimits,
            true,
            rows,
            cols,
        );
        let (id, mut rx) = client.stream(MessageType::ExecRequest, &req).await?;

        crossterm::terminal::enable_raw_mode()
            .map_err(|e| crate::MicrosandboxError::Terminal(e.to_string()))?;
        let _raw_guard = scopeguard::guard((), |_| {
            let _ = crossterm::terminal::disable_raw_mode();
        });

        let tty_input_path = terminal_path_for_fd(std::io::stdin().as_raw_fd())
            .map_err(|e| crate::MicrosandboxError::Terminal(format!("resolve tty path: {e}")))?;
        let tty_input = open_nonblocking_terminal_input(&tty_input_path)
            .map_err(|e| crate::MicrosandboxError::Terminal(format!("open tty input: {e}")))?;
        let stdin_async = AsyncFd::new(tty_input)
            .map_err(|e| crate::MicrosandboxError::Terminal(format!("async tty input: {e}")))?;

        let mut stdout = tokio::io::stdout();
        let mut sigwinch =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
                .map_err(|e| crate::MicrosandboxError::Runtime(format!("sigwinch: {e}")))?;

        let mut exit_code: i32 = -1;
        let mut spawn_failure: Option<microsandbox_protocol::exec::ExecFailed> = None;
        let detach_seq = detach_keys.sequence();
        let mut match_pos = 0usize;

        loop {
            tokio::select! {
                result = stdin_async.readable() => {
                    let mut guard = match result {
                        Ok(g) => g,
                        Err(_) => break,
                    };

                    let mut input_buf = [0u8; 1024];
                    match guard.try_io(|inner| {
                        read_from_fd(inner.get_ref().as_raw_fd(), &mut input_buf)
                    }) {
                        Ok(Ok(0)) => break,
                        Ok(Ok(n)) => {
                            let data = &input_buf[..n];

                            if input_contains_detach_sequence(data, detach_seq, &mut match_pos) {
                                break;
                            }

                            let payload = ExecStdin { data: data.to_vec() };
                            if client.send(id, MessageType::ExecStdin, &payload).await.is_err() {
                                break;
                            }
                        }
                        Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Ok(Err(_)) => break,
                        Err(_would_block) => continue,
                    }
                }

                msg = rx.recv() => {
                    let Some(msg) = msg else {
                        break;
                    };

                    let mut should_break = false;

                    match msg.t {
                        MessageType::ExecStdout => {
                            if let Ok(out) = msg.payload::<ExecStdout>() {
                                let _ = stdout.write_all(&out.data).await;
                            }
                        }
                        MessageType::ExecExited => {
                            if let Ok(exited) = msg.payload::<ExecExited>() {
                                exit_code = exited.code;
                            }
                            should_break = true;
                        }
                        MessageType::ExecFailed => {
                            if let Ok(failed) =
                                msg.payload::<microsandbox_protocol::exec::ExecFailed>()
                            {
                                spawn_failure = Some(failed);
                            }
                            should_break = true;
                        }
                        _ => {}
                    }

                    if !should_break {
                        while let Ok(next) = rx.try_recv() {
                            match next.t {
                                MessageType::ExecStdout => {
                                    if let Ok(out) = next.payload::<ExecStdout>() {
                                        let _ = stdout.write_all(&out.data).await;
                                    }
                                }
                                MessageType::ExecExited => {
                                    if let Ok(exited) = next.payload::<ExecExited>() {
                                        exit_code = exited.code;
                                    }
                                    should_break = true;
                                    break;
                                }
                                MessageType::ExecFailed => {
                                    if let Ok(failed) = next
                                        .payload::<microsandbox_protocol::exec::ExecFailed>()
                                    {
                                        spawn_failure = Some(failed);
                                    }
                                    should_break = true;
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }

                    let _ = stdout.flush().await;

                    if should_break {
                        break;
                    }
                }

                _ = sigwinch.recv() => {
                    if let Ok((new_cols, new_rows)) = crossterm::terminal::size() {
                        let payload = ExecResize { rows: new_rows, cols: new_cols };
                        let _ = client.send(id, MessageType::ExecResize, &payload).await;
                    }
                }
            }
        }

        if let Some(failure) = spawn_failure {
            return Err(crate::MicrosandboxError::ExecFailed(failure));
        }
        Ok(exit_code)
    }
}

#[cfg(windows)]
pub(crate) mod local {
    use std::os::windows::io::AsRawHandle;
    use std::{ptr, sync::Arc, thread, time::Duration};

    use microsandbox_protocol::{
        exec::{ExecExited, ExecResize, ExecStdin, ExecStdout},
        message::MessageType,
    };
    use tokio::sync::mpsc;
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
            WAIT_TIMEOUT,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, ReadFile, WriteFile,
        },
        System::{
            Console::{
                CONSOLE_SCREEN_BUFFER_INFO, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
                ENABLE_MOUSE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
                ENABLE_VIRTUAL_TERMINAL_PROCESSING, ENABLE_WINDOW_INPUT, GetConsoleMode,
                GetConsoleScreenBufferInfo, GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
                SetConsoleMode,
            },
            IO::CancelSynchronousIo,
            Threading::{CreateEventW, SetEvent, WaitForMultipleObjects},
        },
    };

    use crate::{
        MicrosandboxError, MicrosandboxResult,
        backend::LocalBackend,
        sandbox::{AttachOptionsBuilder, SandboxConfig, build_exec_request},
    };

    use super::{DetachKeys, input_contains_detach_sequence};

    const TERMINAL_EVENT_POLL_INTERVAL: Duration = Duration::from_millis(100);
    const TERMINAL_INPUT_BUFFER_SIZE: usize = 4096;

    struct ConsoleHandle {
        raw: HANDLE,
        owned: bool,
    }

    unsafe impl Send for ConsoleHandle {}

    struct OwnedWindowsHandle(HANDLE);

    unsafe impl Send for OwnedWindowsHandle {}

    pub(crate) struct WindowsTerminalGuard {
        input: ConsoleHandle,
        output: ConsoleHandle,
        input_mode: u32,
        output_mode: u32,
    }

    pub(crate) struct WindowsTerminalEventPump {
        stop: OwnedWindowsHandle,
        handle: Option<thread::JoinHandle<()>>,
        rx: mpsc::UnboundedReceiver<WindowsTerminalEvent>,
    }

    pub(crate) enum WindowsTerminalEvent {
        Input(Vec<u8>),
        Resize { cols: u16, rows: u16 },
        Error(String),
    }

    pub(crate) async fn attach(
        local: &LocalBackend,
        name: &str,
        config: &SandboxConfig,
        cmd: String,
        opts_builder: AttachOptionsBuilder,
    ) -> MicrosandboxResult<i32> {
        let opts = opts_builder.build()?;

        let client = Arc::new(super::super::fs::local::connect_agent(local, name).await?);

        let detach_keys = match &opts.detach_keys {
            Some(spec) => DetachKeys::parse(spec)?,
            None => DetachKeys::default_keys(),
        };

        let (cols, rows) = current_terminal_size().unwrap_or((80, 24));

        let req = build_exec_request(
            config,
            cmd,
            opts.args,
            opts.cwd,
            opts.user,
            &opts.env,
            &opts.rlimits,
            true,
            rows,
            cols,
        );
        let (id, mut rx) = client.stream(MessageType::ExecRequest, &req).await?;

        let terminal_guard = WindowsTerminalGuard::enter()?;
        let mut terminal_events = WindowsTerminalEventPump::spawn_for_guard(&terminal_guard)?;
        let mut exit_code: i32 = -1;
        let mut spawn_failure: Option<microsandbox_protocol::exec::ExecFailed> = None;
        let detach_seq = detach_keys.sequence();
        let mut match_pos = 0usize;

        loop {
            tokio::select! {
                Some(event) = terminal_events.recv() => {
                    match event {
                        WindowsTerminalEvent::Input(data) => {
                            if input_contains_detach_sequence(&data, detach_seq, &mut match_pos) {
                                break;
                            }

                            let payload = ExecStdin { data };
                            let _ = client.send(id, MessageType::ExecStdin, &payload).await;
                        }
                        WindowsTerminalEvent::Resize { cols, rows } => {
                            let payload = ExecResize { rows, cols };
                            let _ = client.send(id, MessageType::ExecResize, &payload).await;
                        }
                        WindowsTerminalEvent::Error(error) => {
                            return Err(MicrosandboxError::Terminal(error));
                        }
                    }
                }

                Some(msg) = rx.recv() => {
                    let mut should_break = false;

                    match msg.t {
                        MessageType::ExecStdout => {
                            if let Ok(out) = msg.payload::<ExecStdout>() {
                                let _ = terminal_guard.write_output(&out.data);
                            }
                        }
                        MessageType::ExecExited => {
                            if let Ok(exited) = msg.payload::<ExecExited>() {
                                exit_code = exited.code;
                            }
                            should_break = true;
                        }
                        MessageType::ExecFailed => {
                            if let Ok(failed) =
                                msg.payload::<microsandbox_protocol::exec::ExecFailed>()
                            {
                                spawn_failure = Some(failed);
                            }
                            should_break = true;
                        }
                        _ => {}
                    }

                    if !should_break {
                        while let Ok(next) = rx.try_recv() {
                            match next.t {
                                MessageType::ExecStdout => {
                                    if let Ok(out) = next.payload::<ExecStdout>() {
                                        let _ = terminal_guard.write_output(&out.data);
                                    }
                                }
                                MessageType::ExecExited => {
                                    if let Ok(exited) = next.payload::<ExecExited>() {
                                        exit_code = exited.code;
                                    }
                                    should_break = true;
                                    break;
                                }
                                MessageType::ExecFailed => {
                                    if let Ok(failed) = next
                                        .payload::<microsandbox_protocol::exec::ExecFailed>()
                                    {
                                        spawn_failure = Some(failed);
                                    }
                                    should_break = true;
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }

                    if should_break {
                        break;
                    }
                }
            }
        }

        if let Some(failure) = spawn_failure {
            return Err(MicrosandboxError::ExecFailed(failure));
        }
        Ok(exit_code)
    }

    impl WindowsTerminalGuard {
        pub(crate) fn enter() -> MicrosandboxResult<Self> {
            let (input, input_mode) = get_console_handle(STD_INPUT_HANDLE, "stdin")?;
            let (output, output_mode) = get_console_handle(STD_OUTPUT_HANDLE, "stdout")?;

            let mut guard = Self {
                input,
                output,
                input_mode,
                output_mode,
            };

            if let Err(error) = guard.enable_virtual_terminal_modes() {
                guard.restore();
                return Err(error);
            }

            Ok(guard)
        }

        fn enable_virtual_terminal_modes(&mut self) -> MicrosandboxResult<()> {
            let raw_input_mode = console_mode(&self.input, "stdin")?;
            let raw_output_mode = console_mode(&self.output, "stdout")?;

            let input_mode = (raw_input_mode | ENABLE_VIRTUAL_TERMINAL_INPUT)
                & !(ENABLE_LINE_INPUT
                    | ENABLE_ECHO_INPUT
                    | ENABLE_PROCESSED_INPUT
                    | ENABLE_WINDOW_INPUT
                    | ENABLE_MOUSE_INPUT);
            set_console_mode(&self.input, input_mode, "configure stdin")?;

            let output_mode = raw_output_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            set_console_mode(&self.output, output_mode, "configure stdout")?;

            Ok(())
        }

        fn restore(&mut self) {
            let _ = unsafe { SetConsoleMode(self.input.raw, self.input_mode) };
            let _ = unsafe { SetConsoleMode(self.output.raw, self.output_mode) };
        }

        pub(crate) fn write_output(&self, data: &[u8]) -> MicrosandboxResult<()> {
            let mut offset = 0usize;
            while offset < data.len() {
                let remaining = data.len() - offset;
                let chunk_len = remaining.min(u32::MAX as usize);
                let mut written = 0u32;
                let result = unsafe {
                    WriteFile(
                        self.output.raw,
                        data[offset..].as_ptr().cast(),
                        chunk_len as u32,
                        &mut written,
                        ptr::null_mut(),
                    )
                };
                if result == 0 {
                    return Err(MicrosandboxError::Terminal(format!(
                        "terminal output: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                if written == 0 {
                    break;
                }
                offset += written as usize;
            }

            Ok(())
        }
    }

    impl Drop for WindowsTerminalGuard {
        fn drop(&mut self) {
            self.restore();
        }
    }

    impl WindowsTerminalEventPump {
        pub(crate) fn spawn_for_guard(guard: &WindowsTerminalGuard) -> MicrosandboxResult<Self> {
            Self::spawn(guard.input.raw, guard.output.raw)
        }

        fn spawn(input: HANDLE, output: HANDLE) -> MicrosandboxResult<Self> {
            let (tx, rx) = mpsc::unbounded_channel();
            let stop = create_event("terminal stop")?;
            let input_handle = input as isize;
            let output_handle = output as isize;
            let stop_handle = stop.0 as isize;
            let handle = thread::spawn(move || {
                let input = input_handle as HANDLE;
                let output = output_handle as HANDLE;
                let stop_handle = stop_handle as HANDLE;
                let mut last_size = terminal_size_from_output(output);
                let wait_handles = [input, stop_handle];
                let timeout_ms = TERMINAL_EVENT_POLL_INTERVAL.as_millis() as u32;

                loop {
                    let wait_result = unsafe {
                        WaitForMultipleObjects(
                            wait_handles.len() as u32,
                            wait_handles.as_ptr(),
                            0,
                            timeout_ms,
                        )
                    };

                    if wait_result == WAIT_OBJECT_0 + 1 {
                        break;
                    }

                    if wait_result == WAIT_OBJECT_0 {
                        let mut input_buf = [0u8; TERMINAL_INPUT_BUFFER_SIZE];
                        let mut bytes_read = 0u32;
                        let result = unsafe {
                            ReadFile(
                                input,
                                input_buf.as_mut_ptr().cast(),
                                input_buf.len() as u32,
                                &mut bytes_read,
                                ptr::null_mut(),
                            )
                        };

                        if result == 0 {
                            let _ = tx.send(WindowsTerminalEvent::Error(format!(
                                "terminal input: {}",
                                std::io::Error::last_os_error()
                            )));
                            break;
                        }

                        if bytes_read == 0 {
                            break;
                        }

                        let data = input_buf[..bytes_read as usize].to_vec();
                        if tx.send(WindowsTerminalEvent::Input(data)).is_err() {
                            break;
                        }
                    } else if wait_result != WAIT_TIMEOUT {
                        let _ = tx.send(WindowsTerminalEvent::Error(format!(
                            "terminal wait: {}",
                            std::io::Error::last_os_error()
                        )));
                        break;
                    }

                    let size = terminal_size_from_output(output);
                    if size != last_size {
                        last_size = size;
                        if let Some((cols, rows)) = size
                            && tx
                                .send(WindowsTerminalEvent::Resize { cols, rows })
                                .is_err()
                        {
                            break;
                        }
                    }
                }
            });

            Ok(Self {
                stop,
                handle: Some(handle),
                rx,
            })
        }

        pub(crate) async fn recv(&mut self) -> Option<WindowsTerminalEvent> {
            self.rx.recv().await
        }
    }

    impl Drop for WindowsTerminalEventPump {
        fn drop(&mut self) {
            let _ = unsafe { SetEvent(self.stop.0) };
            if let Some(handle) = self.handle.take() {
                // The pump thread may already be blocked in a synchronous
                // console ReadFile. The stop event only prevents the next
                // wait from entering another read, so cancel the in-flight
                // read before joining or finite guest commands appear to
                // hang until the user presses another key.
                let _ = unsafe { CancelSynchronousIo(handle.as_raw_handle() as HANDLE) };
                let _ = handle.join();
            }
        }
    }

    impl ConsoleHandle {
        fn borrowed(raw: HANDLE) -> Self {
            Self { raw, owned: false }
        }

        fn owned(raw: HANDLE) -> Self {
            Self { raw, owned: true }
        }
    }

    impl Drop for ConsoleHandle {
        fn drop(&mut self) {
            if self.owned {
                let _ = unsafe { CloseHandle(self.raw) };
            }
        }
    }

    fn get_console_handle(kind: u32, name: &str) -> MicrosandboxResult<(ConsoleHandle, u32)> {
        let handle = unsafe { GetStdHandle(kind) };
        if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
            let handle = ConsoleHandle::borrowed(handle);
            if let Ok(mode) = console_mode(&handle, name) {
                return Ok((handle, mode));
            }
        }

        let handle = open_console_device(kind, name)?;
        let mode = console_mode(&handle, name)?;
        Ok((handle, mode))
    }

    fn open_console_device(kind: u32, name: &str) -> MicrosandboxResult<ConsoleHandle> {
        let device = match kind {
            STD_INPUT_HANDLE => "CONIN$",
            STD_OUTPUT_HANDLE => "CONOUT$",
            _ => {
                return Err(MicrosandboxError::Terminal(format!(
                    "{name} console handle is unavailable"
                )));
            }
        };
        let wide = device
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>();
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(MicrosandboxError::Terminal(format!(
                "{name} console handle is unavailable: {}",
                std::io::Error::last_os_error()
            )));
        }

        Ok(ConsoleHandle::owned(raw))
    }

    fn console_mode(handle: &ConsoleHandle, name: &str) -> MicrosandboxResult<u32> {
        let mut mode = 0u32;
        let result = unsafe { GetConsoleMode(handle.raw, &mut mode) };
        if result == 0 {
            return Err(MicrosandboxError::Terminal(format!(
                "{name} is not an interactive Windows console: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(mode)
    }

    fn set_console_mode(
        handle: &ConsoleHandle,
        mode: u32,
        context: &str,
    ) -> MicrosandboxResult<()> {
        let result = unsafe { SetConsoleMode(handle.raw, mode) };
        if result == 0 {
            return Err(MicrosandboxError::Terminal(format!(
                "{context}: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn create_event(context: &str) -> MicrosandboxResult<OwnedWindowsHandle> {
        let handle = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if handle.is_null() {
            return Err(MicrosandboxError::Terminal(format!(
                "{context}: {}",
                std::io::Error::last_os_error()
            )));
        }

        Ok(OwnedWindowsHandle(handle))
    }

    pub(crate) fn current_terminal_size() -> Option<(u16, u16)> {
        let (output, _) = get_console_handle(STD_OUTPUT_HANDLE, "stdout").ok()?;
        terminal_size_from_output(output.raw)
    }

    fn terminal_size_from_output(output: HANDLE) -> Option<(u16, u16)> {
        let mut info = CONSOLE_SCREEN_BUFFER_INFO {
            dwSize: Default::default(),
            dwCursorPosition: Default::default(),
            wAttributes: 0,
            srWindow: Default::default(),
            dwMaximumWindowSize: Default::default(),
        };

        let result = unsafe { GetConsoleScreenBufferInfo(output, &mut info) };
        if result == 0 {
            return None;
        }

        let cols = i32::from(info.srWindow.Right) - i32::from(info.srWindow.Left) + 1;
        let rows = i32::from(info.srWindow.Bottom) - i32::from(info.srWindow.Top) + 1;
        if cols <= 0 || rows <= 0 {
            return None;
        }

        Some((
            cols.min(i32::from(u16::MAX)) as u16,
            rows.min(i32::from(u16::MAX)) as u16,
        ))
    }

    impl Drop for OwnedWindowsHandle {
        fn drop(&mut self) {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detach_keys_default() {
        let keys = DetachKeys::default_keys();
        assert_eq!(keys.sequence(), &[0x1d]);
    }

    #[test]
    fn test_detach_keys_ctrl_bracket() {
        let keys = DetachKeys::parse("ctrl-]").unwrap();
        assert_eq!(keys.sequence(), &[0x1d]);
    }

    #[test]
    fn test_detach_keys_ctrl_letter() {
        let keys = DetachKeys::parse("ctrl-a").unwrap();
        assert_eq!(keys.sequence(), &[0x01]);

        let keys = DetachKeys::parse("ctrl-z").unwrap();
        assert_eq!(keys.sequence(), &[0x1a]);
    }

    #[test]
    fn test_detach_keys_multi_sequence() {
        let keys = DetachKeys::parse("ctrl-p,ctrl-q").unwrap();
        assert_eq!(keys.sequence(), &[0x10, 0x11]);
    }

    #[test]
    #[allow(clippy::byte_char_slices)] // intentional: comparing to a single-byte slice
    fn test_detach_keys_single_char() {
        let keys = DetachKeys::parse("q").unwrap();
        assert_eq!(keys.sequence(), b"q");
    }

    #[test]
    fn test_detach_keys_invalid() {
        assert!(DetachKeys::parse("ctrl-").is_err());
        assert!(DetachKeys::parse("ctrl-ab").is_err());
    }

    #[test]
    fn test_input_contains_detach_sequence_across_chunks() {
        let keys = DetachKeys::parse("ctrl-p,ctrl-q").unwrap();
        let mut match_pos = 0;

        assert!(!input_contains_detach_sequence(
            &[0x10],
            keys.sequence(),
            &mut match_pos
        ));
        assert_eq!(match_pos, 1);

        assert!(input_contains_detach_sequence(
            &[0x11],
            keys.sequence(),
            &mut match_pos
        ));
    }

    #[test]
    fn test_input_contains_detach_sequence_restarts_partial_match() {
        let keys = DetachKeys::parse("ctrl-p,ctrl-q").unwrap();
        let mut match_pos = 0;

        assert!(!input_contains_detach_sequence(
            &[0x10, 0x10],
            keys.sequence(),
            &mut match_pos
        ));
        assert_eq!(match_pos, 1);
    }
}
