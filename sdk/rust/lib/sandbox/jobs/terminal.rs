//! Optional host-terminal adapter built entirely on public attachment operations.

use std::collections::VecDeque;
use std::io::{IsTerminal, Write};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;

use super::{JobAttachment, JobError, JobEvent, JobResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const INPUT_QUEUE: usize = 4;
const INPUT_CHUNK_SIZE: usize = 8192;
const INPUT_LOOKAHEAD_LIMIT: usize = 1024 * 1024;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct TerminalInput {
    writes: Option<mpsc::Sender<Vec<u8>>>,
    pending: VecDeque<u8>,
    deadline: Option<Instant>,
    overflowed: bool,
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
                pending: VecDeque::new(),
                deadline: None,
                overflowed: false,
            },
            queued,
        )
    }

    fn can_read(&self) -> bool {
        // Ctrl-] shares the input byte stream with pasted text. Queue pressure must not disable
        // shortcut reads; the bounded lookahead reports overflow instead of hanging the terminal.
        self.writes.is_some() && self.deadline.is_none()
    }

    fn accept(&mut self, bytes: &[u8], read_only: bool) -> JobResult<()> {
        let detach = bytes.iter().position(|byte| *byte == 0x1d);
        let end = detach.unwrap_or(bytes.len());
        if end > 0 && !read_only {
            if !self.can_read() {
                return Err(JobError::operation(
                    "attachment_closed",
                    "terminal input is draining",
                ));
            }
            if !self.overflowed {
                if end > INPUT_LOOKAHEAD_LIMIT - self.pending.len() {
                    self.overflowed = true;
                    // Returning now could hand the rest of a guest paste to the host shell.
                    // Consume and discard later input until an explicit detach, reporting loss
                    // once here and again in the final result even if the prefix fully drains.
                    eprintln!(
                        "[input_not_flushed: terminal input lookahead exceeded {INPUT_LOOKAHEAD_LIMIT} bytes; further input is discarded; attachment remains open; press Ctrl-] to detach; do not automatically resend unconfirmed input]"
                    );
                } else {
                    // Store bytes rather than one allocation per keystroke, so the bound also
                    // controls memory when Windows delivers small console input events.
                    self.pending.extend(&bytes[..end]);
                }
            }
        }
        if detach.is_some() {
            self.finish();
        }
        Ok(())
    }

    fn finish(&mut self) {
        // Start the deadline as soon as the shortcut/host EOF is observed, even when the writer
        // is full. Keep the sender until lookahead drains, then close only this local queue.
        if self.deadline.is_none() {
            self.deadline = Some(Instant::now() + DRAIN_TIMEOUT);
        }
        self.close_if_drained();
    }

    fn pending_writes(&self) -> Option<mpsc::Sender<Vec<u8>>> {
        if self.pending.is_empty() {
            None
        } else {
            self.writes.clone()
        }
    }

    fn send_pending(&mut self, permit: JobResult<mpsc::OwnedPermit<Vec<u8>>>) -> JobResult<()> {
        let permit = permit.map_err(|error| self.delivery_error(error))?;
        let count = self.pending.len().min(INPUT_CHUNK_SIZE);
        debug_assert!(count > 0);
        permit.send(self.pending.drain(..count).collect());
        self.close_if_drained();
        Ok(())
    }

    fn close_if_drained(&mut self) {
        if self.deadline.is_some() && self.pending.is_empty() {
            self.writes.take();
        }
    }

    fn delivery_error(&self, error: JobError) -> JobError {
        if self.deadline.is_some() || self.overflowed {
            input_not_flushed(error)
        } else {
            error
        }
    }

    fn writer_result(&self, result: JobResult<()>) -> JobResult<Option<i32>> {
        result.map_err(|error| self.delivery_error(error))?;
        self.completion_result(None)
    }

    fn completion_result(&self, code: Option<i32>) -> JobResult<Option<i32>> {
        if self.overflowed {
            Err(input_not_flushed(format!(
                "input was discarded after terminal input lookahead exceeded {INPUT_LOOKAHEAD_LIMIT} bytes"
            )))
        } else {
            Ok(code)
        }
    }
}

impl JobAttachment {
    /// Bridge a host terminal until process completion or Ctrl-] detach.
    ///
    /// Returns the guest exit code, or None on detach. Restores terminal state on every return.
    /// Detach drains prior input to runtime admission for at most two seconds. A failed drain
    /// returns `input_not_flushed`; it never closes guest stdin or terminates the job.
    /// A 1 MiB lookahead keeps shortcut detection active while guest input is blocked. Overflow
    /// reports input loss and discards further input while keeping the attachment open until
    /// Ctrl-], host EOF or process completion. The final result returns `input_not_flushed`.
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
                    permit = reserve_input(input_state.pending_writes()) => input_state.send_pending(permit)?,
                    ready = input.readable(), if input_state.can_read() => {
                        let mut ready = ready?;
                        let mut bytes = [0; INPUT_CHUNK_SIZE];
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
                        if let Some(result) = render(event?)? { return input_state.completion_result(result); }
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
                    permit = reserve_input(input_state.pending_writes()) => {
                        if let Err(error) = input_state.send_pending(permit) { break Err(error); }
                    },
                    event = input.recv(), if input_state.can_read() => match event {
                        Some(WindowsTerminalEvent::Input(bytes)) => {
                            if let Err(error) = input_state.accept(&bytes, self.read_only) { break Err(error); }
                        },
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
                        event => if let Some(result) = render(event)? { break input_state.completion_result(result); },
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

async fn reserve_input(
    writes: Option<mpsc::Sender<Vec<u8>>>,
) -> JobResult<mpsc::OwnedPermit<Vec<u8>>> {
    match writes {
        Some(writes) => writes.reserve_owned().await.map_err(|_| {
            JobError::operation("terminal_error", "terminal input writer is unavailable")
        }),
        None => std::future::pending().await,
    }
}

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

    async fn flush_one(input: &mut TerminalInput) {
        let permit = reserve_input(input.pending_writes()).await;
        input.send_pending(permit).unwrap();
    }

    #[tokio::test]
    async fn detach_keeps_the_prefix_and_closes_only_the_local_queue() {
        let (mut input, mut queued) = TerminalInput::new();
        input.accept(b"earlier", false).unwrap();
        input.accept(b"last\x1dignored", false).unwrap();
        assert!(!input.can_read());
        assert!(input.deadline.is_some());
        flush_one(&mut input).await;
        assert_eq!(queued.recv().await.unwrap(), b"earlierlast");
        assert!(queued.recv().await.is_none());
    }

    #[tokio::test]
    async fn full_writer_queue_still_reads_detach_and_wakes_to_drain_without_new_input() {
        let (mut input, mut queued) = TerminalInput::new();
        for _ in 0..INPUT_QUEUE {
            input.accept(b"queued", false).unwrap();
            flush_one(&mut input).await;
        }
        assert_eq!(input.writes.as_ref().unwrap().capacity(), 0);
        assert!(input.can_read());
        input.accept(b"tail\x1d", false).unwrap();
        assert!(!input.can_read());
        assert!(input.deadline.is_some());
        // The outer select must wake on writer capacity itself, even after terminal reads stop.
        let permit = reserve_input(input.pending_writes());
        tokio::pin!(permit);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut permit)
                .await
                .is_err()
        );
        assert_eq!(queued.recv().await.unwrap(), b"queued");
        let permit = tokio::time::timeout(Duration::from_secs(1), &mut permit)
            .await
            .unwrap();
        input.send_pending(permit).unwrap();
        for _ in 1..INPUT_QUEUE {
            assert_eq!(queued.recv().await.unwrap(), b"queued");
        }
        assert_eq!(queued.recv().await.unwrap(), b"tail");
        assert!(queued.recv().await.is_none());
    }

    #[tokio::test]
    async fn lookahead_drains_in_bounded_chunks_without_reordering() {
        let (mut input, mut queued) = TerminalInput::new();
        let prefix: Vec<u8> = (0..INPUT_CHUNK_SIZE)
            .map(|index| b'a' + (index % 26) as u8)
            .collect();
        input.accept(&prefix, false).unwrap();
        input.accept(b"last\x1d", false).unwrap();
        flush_one(&mut input).await;
        assert_eq!(queued.recv().await.unwrap(), prefix);
        assert!(input.writes.is_some());
        flush_one(&mut input).await;
        assert_eq!(queued.recv().await.unwrap(), b"last");
        assert!(queued.recv().await.is_none());
    }

    #[tokio::test]
    async fn lookahead_overflow_keeps_reading_without_accepting_the_excess() {
        let (mut input, _queued) = TerminalInput::new();
        input
            .accept(&vec![b'x'; INPUT_LOOKAHEAD_LIMIT], false)
            .unwrap();
        input.accept(b"excess", false).unwrap();
        assert!(input.overflowed);
        assert!(input.can_read());
        assert!(input.deadline.is_none());
        assert_eq!(input.pending.len(), INPUT_LOOKAHEAD_LIMIT);
        // A shortcut at the limit is still recognized; trailing bytes are outside the attachment.
        input.accept(b"\x1dignored", false).unwrap();
        assert!(input.deadline.is_some());
        assert_eq!(input.pending.len(), INPUT_LOOKAHEAD_LIMIT);
    }

    #[tokio::test]
    async fn overflow_does_not_resume_forwarding_when_writer_capacity_recovers() {
        let (mut input, mut queued) = TerminalInput::new();
        input
            .accept(&vec![b'x'; INPUT_LOOKAHEAD_LIMIT], false)
            .unwrap();
        input.accept(b"lost", false).unwrap();
        while !input.pending.is_empty() {
            flush_one(&mut input).await;
            assert!(
                queued
                    .recv()
                    .await
                    .unwrap()
                    .iter()
                    .all(|byte| *byte == b'x')
            );
        }
        input.accept(b"must stay discarded", false).unwrap();
        assert!(input.pending.is_empty());
        assert!(input.can_read());
        assert!(input.deadline.is_none());
        input.accept(b"\x1d", false).unwrap();
        assert!(queued.recv().await.is_none());
        let error = input.writer_result(Ok(())).unwrap_err();
        assert_eq!(error.code(), "input_not_flushed");
        assert!(error.to_string().contains("lookahead"));
        assert!(error.to_string().contains("do not automatically resend"));
    }

    #[tokio::test]
    async fn overflow_in_a_shortcut_chunk_and_process_completion_preserve_input_loss() {
        let (mut input, _queued) = TerminalInput::new();
        input
            .accept(&vec![b'x'; INPUT_LOOKAHEAD_LIMIT], false)
            .unwrap();
        input.accept(b"excess\x1dignored", false).unwrap();
        assert!(!input.can_read());
        assert!(input.deadline.is_some());
        assert_eq!(input.pending.len(), INPUT_LOOKAHEAD_LIMIT);
        assert_eq!(
            input.completion_result(Some(0)).unwrap_err().code(),
            "input_not_flushed"
        );
        let (input, _queued) = TerminalInput::new();
        assert_eq!(input.completion_result(Some(7)).unwrap(), Some(7));
    }

    #[tokio::test]
    async fn host_eof_keeps_pending_input_and_does_not_extend_the_drain_deadline() {
        let (mut input, mut queued) = TerminalInput::new();
        input.accept(b"pending", false).unwrap();
        input.finish();
        let deadline = input.deadline;
        input.finish();
        assert_eq!(input.deadline, deadline);
        assert!(!input.can_read());
        flush_one(&mut input).await;
        assert_eq!(queued.recv().await.unwrap(), b"pending");
        assert!(queued.recv().await.is_none());
    }

    #[tokio::test]
    async fn read_only_detach_never_sends_or_buffers_input() {
        let (mut input, mut queued) = TerminalInput::new();
        input
            .accept(&vec![b'x'; INPUT_LOOKAHEAD_LIMIT + 1], true)
            .unwrap();
        assert!(input.pending.is_empty());
        input.accept(b"ignored\x1d", true).unwrap();
        assert!(queued.recv().await.is_none());
    }

    #[tokio::test]
    async fn writer_capacity_failure_while_draining_is_explicit() {
        let (mut input, queued) = TerminalInput::new();
        input.accept(b"pending\x1d", false).unwrap();
        drop(queued);
        let permit = reserve_input(input.pending_writes()).await;
        assert_eq!(
            input.send_pending(permit).unwrap_err().code(),
            "input_not_flushed"
        );
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
