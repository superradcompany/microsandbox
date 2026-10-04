//! Optional host-terminal adapter built entirely on public attachment operations.

use std::io::{IsTerminal, Write};

use super::{JobAttachment, JobError, JobEvent, JobResult};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl JobAttachment {
    /// Bridge a host terminal until process completion or Ctrl-] detach.
    ///
    /// Returns the guest exit code, or None on detach. Restores terminal state on every return.
    /// Applications using redirected input should drive `recv` and `write_stdin` directly.
    pub async fn interact_terminal(&self) -> JobResult<Option<i32>> {
        if !std::io::stdin().is_terminal() {
            return Err(JobError::operation(
                "invalid_options",
                "terminal interaction requires terminal stdin",
            ));
        }
        let tty = self.job.inspect().await?.tty;
        let (writes, mut queued) = tokio::sync::mpsc::channel::<Vec<u8>>(4);
        let writer = async {
            while let Some(bytes) = queued.recv().await {
                self.write_stdin(bytes).await?;
            }
            Ok::<(), JobError>(())
        };
        tokio::pin!(writer);

        #[cfg(unix)]
        {
            use crate::sandbox::{
                open_nonblocking_terminal_input, read_from_fd, terminal_path_for_fd,
            };
            use std::os::fd::AsRawFd;
            use tokio::io::unix::AsyncFd;

            let input = open_nonblocking_terminal_input(&terminal_path_for_fd(
                std::io::stdin().as_raw_fd(),
            )?)?;
            let input = AsyncFd::new(input)?;
            crossterm::terminal::enable_raw_mode()?;
            let _raw_guard = scopeguard::guard((), |_| {
                let _ = crossterm::terminal::disable_raw_mode();
            });
            let mut resize =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())?;
            if tty && !self.read_only {
                let (cols, rows) = usable_size(crossterm::terminal::size().unwrap_or((80, 24)));
                self.resize(rows, cols).await?;
            }
            loop {
                tokio::select! {
                    result = &mut writer => { result?; return Ok(None); },
                    ready = input.readable() => {
                        let mut ready = ready?;
                        let mut bytes = [0; 8192];
                        match ready.try_io(|input| read_from_fd(input.get_ref().as_raw_fd(), &mut bytes)) {
                            Ok(Ok(0)) => { self.detach().await?; return Ok(None); },
                            Ok(Ok(count)) => {
                                let before_detach = bytes[..count].iter().position(|byte| *byte == 0x1d);
                                let end = before_detach.unwrap_or(count);
                                if end > 0 && !self.read_only { writes.try_send(bytes[..end].to_vec()).map_err(|_| JobError::operation("input_busy", "terminal input buffer is full; detached without terminating the job"))?; }
                                if before_detach.is_some() { self.detach().await?; return Ok(None); }
                            }
                            Ok(Err(error)) => return Err(error.into()),
                            Err(_) => {},
                        }
                    }
                    _ = resize.recv(), if tty && !self.read_only => {
                        let (cols, rows) = usable_size(crossterm::terminal::size().unwrap_or((80, 24)));
                        self.resize(rows, cols).await?;
                    }
                    event = self.recv() => {
                        if let Some(result) = render(event?)? { return Ok(result); }
                    }
                }
            }
        }
        #[cfg(windows)]
        {
            use crate::sandbox::terminal::{
                WindowsTerminalEvent, WindowsTerminalEventPump, WindowsTerminalGuard,
                current_terminal_size,
            };
            let mut guard = WindowsTerminalGuard::enter()?;
            let mut input = WindowsTerminalEventPump::spawn_for_guard(&guard)?;
            if tty && !self.read_only {
                let (cols, rows) = usable_size(current_terminal_size().unwrap_or((80, 24)));
                self.resize(rows, cols).await?;
            }
            loop {
                tokio::select! {
                    result = &mut writer => { result?; return Ok(None); },
                    event = input.recv() => match event {
                        Some(WindowsTerminalEvent::Input(bytes)) => {
                            let before_detach = bytes.iter().position(|byte| *byte == 0x1d);
                            let end = before_detach.unwrap_or(bytes.len());
                            if end > 0 && !self.read_only { writes.try_send(bytes[..end].to_vec()).map_err(|_| JobError::operation("input_busy", "terminal input buffer is full; detached without terminating the job"))?; }
                            if before_detach.is_some() { self.detach().await?; guard.finish_output()?; return Ok(None); }
                        }
                        Some(WindowsTerminalEvent::Resize { rows, cols }) if tty && !self.read_only => {
                            let (cols, rows) = usable_size((cols, rows));
                            self.resize(rows, cols).await?;
                        },
                        Some(WindowsTerminalEvent::Error(error)) => return Err(JobError::operation("terminal_error", error)),
                        None => { self.detach().await?; guard.finish_output()?; return Ok(None); }
                        _ => {},
                    },
                    event = self.recv() => match event? {
                        Some(JobEvent::Output(entry)) => guard.write_output(&entry.data)?,
                        event => if let Some(result) = render(event)? { guard.finish_output()?; return Ok(result); },
                    }
                }
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn render(event: Option<JobEvent>) -> JobResult<Option<Option<i32>>> {
    match event {
        Some(JobEvent::Output(entry)) => {
            if entry.source == "stderr" {
                let mut output = std::io::stderr().lock();
                output.write_all(&entry.data)?;
                output.flush()?;
            } else {
                let mut output = std::io::stdout().lock();
                output.write_all(&entry.data)?;
                output.flush()?;
            }
            Ok(None)
        }
        Some(JobEvent::Gap { .. }) => {
            eprintln!("[job output was pruned before it could be replayed]");
            Ok(None)
        }
        Some(JobEvent::Completed(info)) => match info.exit_code {
            Some(code) => Ok(Some(Some(code))),
            None => Err(JobError::operation(
                "job_lost",
                info.error
                    .unwrap_or_else(|| "job ended without a confirmed exit code".into()),
            )),
        },
        None => Ok(Some(None)),
    }
}

fn usable_size((cols, rows): (u16, u16)) -> (u16, u16) {
    // Newly created or headless PTYs can report a successful query with zero dimensions.
    (
        if cols == 0 { 80 } else { cols },
        if rows == 0 { 24 } else { rows },
    )
}
