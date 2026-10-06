//! Optional host-terminal adapter built entirely on public attachment operations.

use std::io::{IsTerminal, Write};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;

use super::{JobAttachment, JobError, JobEvent, JobResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const INPUT_QUEUE: usize = 4;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct TerminalInput {
    writes: Option<mpsc::Sender<Vec<u8>>>,
    deadline: Option<Instant>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TerminalInput {
    fn new() -> (Self, mpsc::Receiver<Vec<u8>>) {
        let (writes, queued) = mpsc::channel(INPUT_QUEUE);
        (
            Self {
                writes: Some(writes),
                deadline: None,
            },
            queued,
        )
    }

    fn can_read(&self, read_only: bool) -> bool {
        // This loop is the sole producer. Reserve room before reading another terminal chunk
        // rather than losing already-read bytes or blocking the loop that also drives the writer.
        self.writes
            .as_ref()
            .is_some_and(|writes| read_only || writes.capacity() > 0)
    }

    fn accept(&mut self, bytes: &[u8], read_only: bool) -> JobResult<()> {
        let detach = bytes.iter().position(|byte| *byte == 0x1d);
        let end = detach.unwrap_or(bytes.len());
        if end > 0 && !read_only {
            self.writes
                .as_ref()
                .ok_or_else(|| {
                    JobError::operation("attachment_closed", "terminal input is draining")
                })?
                .try_send(bytes[..end].to_vec())
                .map_err(|_| {
                    JobError::operation("terminal_error", "terminal input writer is unavailable")
                })?;
        }
        if detach.is_some() {
            self.finish();
        }
        Ok(())
    }

    fn finish(&mut self) {
        // Closing only the local queue lets the writer drain its prefix. It is deliberately
        // separate from guest EOF and from releasing the attachment's runtime input lease.
        if self.writes.take().is_some() {
            self.deadline = Some(Instant::now() + DRAIN_TIMEOUT);
        }
    }

    fn writer_result(&self, result: JobResult<()>) -> JobResult<Option<i32>> {
        result.map_err(|error| {
            if self.deadline.is_some() {
                input_not_flushed(error)
            } else {
                error
            }
        })?;
        Ok(None)
    }
}

impl JobAttachment {
    /// Bridge a host terminal until process completion or Ctrl-] detach.
    ///
    /// Returns the guest exit code, or None on detach. Restores terminal state on every return.
    /// Detach drains prior input to runtime admission for at most two seconds. A failed drain
    /// returns `input_not_flushed`; it never closes guest stdin or terminates the job.
    /// Applications using redirected input should drive `recv` and `write_stdin` directly.
    pub async fn interact_terminal(&self) -> JobResult<Option<i32>> {
        if !std::io::stdin().is_terminal() {
            return Err(JobError::operation(
                "invalid_options",
                "terminal interaction requires terminal stdin",
            ));
        }
        let tty = self.job.inspect().await?.tty;
        let result = self.run_terminal(tty).await;
        let detached = self.detach().await;
        // Always release input ownership, including after an incomplete or ambiguous write.
        // Preserve the original failure rather than hiding it behind a cleanup failure.
        match result {
            Err(error) => Err(error),
            Ok(value) => {
                detached?;
                Ok(value)
            }
        }
    }

    async fn run_terminal(&self, tty: bool) -> JobResult<Option<i32>> {
        let (mut input_state, mut queued) = TerminalInput::new();
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
                    result = &mut writer => return input_state.writer_result(result),
                    _ = drain_expired(input_state.deadline) => return Err(input_not_flushed("runtime admission did not finish within two seconds")),
                    ready = input.readable(), if input_state.can_read(self.read_only) => {
                        let mut ready = ready?;
                        let mut bytes = [0; 8192];
                        match ready.try_io(|input| read_from_fd(input.get_ref().as_raw_fd(), &mut bytes)) {
                            Ok(Ok(0)) => input_state.finish(),
                            Ok(Ok(count)) => input_state.accept(&bytes[..count], self.read_only)?,
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
            let mut input = WindowsTerminalEventPump::spawn_bounded_for_guard(&guard, INPUT_QUEUE)?;
            if tty && !self.read_only {
                let (cols, rows) = usable_size(current_terminal_size().unwrap_or((80, 24)));
                self.resize(rows, cols).await?;
            }
            let result = loop {
                tokio::select! {
                    result = &mut writer => break input_state.writer_result(result),
                    _ = drain_expired(input_state.deadline) => break Err(input_not_flushed("runtime admission did not finish within two seconds")),
                    event = input.recv(), if input_state.can_read(self.read_only) => match event {
                        Some(WindowsTerminalEvent::Input(bytes)) => input_state.accept(&bytes, self.read_only)?,
                        Some(WindowsTerminalEvent::Resize { rows, cols }) if tty && !self.read_only => {
                            let (cols, rows) = usable_size((cols, rows));
                            self.resize(rows, cols).await?;
                        },
                        Some(WindowsTerminalEvent::Error(error)) => return Err(JobError::operation("terminal_error", error)),
                        None => input_state.finish(),
                        _ => {},
                    },
                    event = self.recv() => match event? {
                        Some(JobEvent::Output(entry)) => guard.write_output(&entry.data)?,
                        event => if let Some(result) = render(event)? { break Ok(result); },
                    }
                }
            };
            let finish = guard.finish_output();
            result.and_then(|value| {
                finish?;
                Ok(value)
            })
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn drain_expired(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

fn input_not_flushed(reason: impl std::fmt::Display) -> JobError {
    JobError::operation(
        "input_not_flushed",
        format!(
            "terminal input could not be fully flushed before detach: {reason}; detaching does not terminate the job or close stdin; do not automatically resend unconfirmed input"
        ),
    )
}

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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn detach_keeps_the_prefix_and_closes_only_the_local_queue() {
        let (mut input, mut queued) = TerminalInput::new();
        input.accept(b"earlier", false).unwrap();
        input.accept(b"last\x1dignored", false).unwrap();
        assert!(!input.can_read(false));
        assert_eq!(queued.recv().await.unwrap(), b"earlier");
        assert_eq!(queued.recv().await.unwrap(), b"last");
        assert!(queued.recv().await.is_none());
    }

    #[tokio::test]
    async fn full_input_buffer_waits_for_writer_progress() {
        let (mut input, mut queued) = TerminalInput::new();
        for _ in 0..INPUT_QUEUE {
            input.accept(b"queued", false).unwrap();
        }
        assert!(!input.can_read(false));
        assert_eq!(queued.recv().await.unwrap(), b"queued");
        assert!(input.can_read(false));
        input.accept(b"tail\x1d", false).unwrap();
        for _ in 1..INPUT_QUEUE {
            assert_eq!(queued.recv().await.unwrap(), b"queued");
        }
        assert_eq!(queued.recv().await.unwrap(), b"tail");
        assert!(queued.recv().await.is_none());
    }

    #[tokio::test]
    async fn read_only_detach_never_sends_input() {
        let (mut input, mut queued) = TerminalInput::new();
        input.accept(b"ignored\x1d", true).unwrap();
        assert!(queued.recv().await.is_none());
    }

    #[tokio::test]
    async fn drain_deadline_and_delivery_failure_are_explicit() {
        let (mut input, _queued) = TerminalInput::new();
        input.finish();
        let error = input
            .writer_result(Err(JobError::operation("io", "delivery unknown")))
            .unwrap_err();
        assert_eq!(error.code(), "input_not_flushed");
        assert!(error.to_string().contains("do not automatically resend"));
        tokio::time::timeout(
            Duration::from_millis(100),
            drain_expired(Some(Instant::now())),
        )
        .await
        .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), drain_expired(None))
                .await
                .is_err()
        );
    }
}
