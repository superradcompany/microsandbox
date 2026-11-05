//! Temporary I/O ownership; disconnect is deliberately separate from EOF and termination.

use std::collections::VecDeque;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use microsandbox_protocol::jobs::{JOB_CHUNK_BYTES, JobOperation, JobResponse};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};

use super::client::invalid_response;
use super::execution::token;
use super::{
    Job, JobAttachOptionsBuilder, JobError, JobEvent, JobLogOptions, JobReplay, JobResult,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One temporary attachment. Reads may run concurrently with writes, resize, and detach.
///
/// Only one `recv` call may be active. Dropping this handle releases input ownership without
/// closing guest stdin; abrupt client death releases ownership when the runtime lease expires.
pub struct JobAttachment {
    pub(super) job: Job,
    token: String,
    pub(super) read_only: bool,
    receiver: Mutex<Receiver>,
    receiving: AtomicBool,
    closed: CancellationToken,
    heartbeat: AbortOnDropHandle<()>,
}

struct Receiver {
    cursor: u64,
    pending: VecDeque<JobEvent>,
    done: bool,
}

struct ReadGuard<'a>(&'a AtomicBool);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Job {
    /// Connect to the existing process without starting another command.
    pub async fn attach(&self) -> JobResult<JobAttachment> {
        self.attach_with(|options| options).await
    }

    /// Acquire input or observe read-only, with optional bounded replay.
    pub async fn attach_with(
        &self,
        configure: impl FnOnce(JobAttachOptionsBuilder) -> JobAttachOptionsBuilder,
    ) -> JobResult<JobAttachment> {
        let options = configure(JobAttachOptionsBuilder::default());
        if let JobReplay::Recent { max_bytes } = options.replay
            && max_bytes > 1024 * 1024
        {
            return Err(JobError::operation(
                "invalid_options",
                "attachment replay cannot exceed one MiB",
            ));
        }
        let attachment = token()?;
        let response = self
            .request(JobOperation::Attach {
                id: self.id.clone(),
                attachment: attachment.clone(),
                read_only: options.read_only,
            })
            .await?;
        let JobResponse::Attached {
            info,
            cursor: admitted_cursor,
        } = response
        else {
            return Err(invalid_response());
        };
        let setup = async {
            let mut cursor = admitted_cursor;
            let mut pending = VecDeque::new();
            match options.replay {
                JobReplay::None => {}
                JobReplay::After(ref after) => {
                    cursor = self.parse_cursor(after)?;
                }
                JobReplay::Recent { max_bytes } => {
                    let mut records = self.logs(&JobLogOptions::default()).await?;
                    records.retain(|record| {
                        self.parse_cursor(&record.cursor)
                            .is_ok_and(|sequence| sequence <= admitted_cursor)
                    });
                    let mut remaining = max_bytes;
                    for mut record in records.into_iter().rev() {
                        if remaining == 0 {
                            break;
                        }
                        if record.data.len() > remaining {
                            record.data = record.data.slice(record.data.len() - remaining..);
                        }
                        remaining -= record.data.len();
                        pending.push_front(JobEvent::Output(record));
                    }
                }
            }
            if !info.state.is_active()
                && matches!(options.replay, JobReplay::None | JobReplay::Recent { .. })
            {
                pending.push_back(JobEvent::Completed(info.clone()));
            }
            Ok::<_, JobError>((cursor, pending))
        }
        .await;
        let (cursor, pending) = match setup {
            Ok(value) => value,
            Err(error) => {
                let _ = self
                    .expect_ok(JobOperation::Detach {
                        id: self.id.clone(),
                        attachment,
                    })
                    .await;
                return Err(error);
            }
        };
        let closed = CancellationToken::new();
        let heartbeat_job = self.clone();
        let heartbeat_token = attachment.clone();
        let cancellation = closed.clone();
        let heartbeat = AbortOnDropHandle::new(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(10)) => {
                        if heartbeat_job.expect_ok(JobOperation::Renew { id: heartbeat_job.id.clone(), attachment: heartbeat_token.clone() }).await.is_err() { break; }
                    }
                }
            }
        }));
        Ok(JobAttachment {
            job: self.clone(),
            token: attachment,
            read_only: options.read_only,
            receiver: Mutex::new(Receiver {
                cursor,
                pending,
                done: !info.state.is_active() && !matches!(options.replay, JobReplay::After(_)),
            }),
            receiving: AtomicBool::new(false),
            closed,
            heartbeat,
        })
    }
}

impl JobAttachment {
    /// Receive one event; returns None after completion or explicit detach.
    pub async fn recv(&self) -> JobResult<Option<JobEvent>> {
        if self.receiving.swap(true, Ordering::AcqRel) {
            return Err(JobError::operation(
                "reader_busy",
                "only one attachment receiver may run at a time",
            ));
        }
        let _guard = ReadGuard(&self.receiving);
        loop {
            if self.closed.is_cancelled() {
                return Ok(None);
            }
            let cursor = {
                let mut receiver = self.receiver.lock().unwrap();
                if let Some(event) = receiver.pending.pop_front() {
                    return Ok(Some(event));
                }
                if receiver.done {
                    return Ok(None);
                }
                receiver.cursor
            };
            let page = tokio::select! {
                _ = self.closed.cancelled() => return Ok(None),
                result = self.job.read_page(cursor, Some(self.token.clone())) => result?,
            };
            let empty = page.items.is_empty();
            {
                let mut receiver = self.receiver.lock().unwrap();
                receiver.cursor = page.cursor;
                if let Some(first) = page.gap_before {
                    receiver.pending.push_back(JobEvent::Gap {
                        cursor: self.job.cursor(first.saturating_sub(1)),
                    });
                }
                for record in page.items {
                    receiver
                        .pending
                        .push_back(JobEvent::Output(self.job.decode_output(record)?));
                }
                if !page.info.state.is_active() && empty {
                    receiver.pending.push_back(JobEvent::Completed(page.info));
                    receiver.done = true;
                }
                if !receiver.pending.is_empty() {
                    continue;
                }
            }
            tokio::select! {
                _ = self.closed.cancelled() => return Ok(None),
                _ = tokio::time::sleep(Duration::from_millis(50)) => {},
            }
        }
    }

    /// Write one bounded input chunk. Empty data is a no-op, never EOF.
    ///
    /// Limit each write to 16 KiB so rejection cannot conceal partial admission.
    pub async fn write_stdin(&self, data: impl AsRef<[u8]>) -> JobResult<()> {
        self.require_input()?;
        let data = data.as_ref();
        if data.len() > JOB_CHUNK_BYTES {
            return Err(JobError::operation(
                "invalid_options",
                "input writes are limited to 16 KiB per call",
            ));
        }
        loop {
            self.require_input()?;
            let result = self
                .job
                .expect_ok(JobOperation::Write {
                    id: self.job.id.clone(),
                    attachment: self.token.clone(),
                    data_base64: STANDARD.encode(data),
                })
                .await;
            match result {
                Err(JobError::Operation { ref code, .. }) if code == "input_busy" => {
                    // Retry only a definitive refusal, never an ambiguous transport failure.
                    tokio::select! {
                        _ = self.closed.cancelled() => self.require_input()?,
                        _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                    }
                }
                result => return result,
            }
        }
    }

    /// Resize the existing PTY; only the input-owning attachment may do this.
    pub async fn resize(&self, rows: u16, cols: u16) -> JobResult<()> {
        self.require_input()?;
        self.job
            .expect_ok(JobOperation::Resize {
                id: self.job.id.clone(),
                attachment: self.token.clone(),
                rows,
                cols,
            })
            .await
    }

    /// Release this connection while preserving the job and its stdin.
    pub async fn detach(&self) -> JobResult<()> {
        self.closed.cancel();
        self.heartbeat.abort();
        self.job
            .expect_ok(JobOperation::Detach {
                id: self.job.id.clone(),
                attachment: self.token.clone(),
            })
            .await
    }

    fn require_input(&self) -> JobResult<()> {
        if self.closed.is_cancelled() {
            return Err(JobError::operation(
                "attachment_closed",
                "attachment was detached",
            ));
        }
        if self.read_only {
            return Err(JobError::operation(
                "read_only",
                "attachment does not own input",
            ));
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for ReadGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Drop for JobAttachment {
    fn drop(&mut self) {
        let already_closed = self.closed.is_cancelled();
        self.closed.cancel();
        self.heartbeat.abort();
        if !already_closed && let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let job = self.job.clone();
            let attachment = self.token.clone();
            runtime.spawn(async move {
                let _ = job
                    .expect_ok(JobOperation::Detach {
                        id: job.id.clone(),
                        attachment,
                    })
                    .await;
            });
        }
    }
}
