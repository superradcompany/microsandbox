//! Managed jobs share runtime ownership with the Rust SDK; native handles never kill on drop.

use std::sync::atomic::{AtomicBool, Ordering};

use futures::StreamExt;
use microsandbox::sandbox::jobs::{
    Job, JobAttachment, JobError, JobId, JobListBuilder, JobLogOptions, JobLogStream, JobReplay,
};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use tokio::sync::{Mutex, Notify};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Sandbox-scoped job handle; dropping it does not terminate the guest process.
#[napi(js_name = "Job")]
pub struct JsJob {
    pub(crate) inner: Job,
}

/// Renewable output attachment with optional exclusive stdin ownership.
#[napi(js_name = "JobAttachment")]
pub struct JsJobAttachment {
    inner: JobAttachment,
}

/// Cancellable iterator over retained output and optional live updates.
#[napi(js_name = "JobLogStream")]
pub struct JsJobLogStream {
    inner: Mutex<Option<JobLogStream>>,
    closed: AtomicBool,
    notify: Notify,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsJob {
    /// Return the opaque job identity, scoped to its sandbox.
    #[napi(getter)]
    pub fn id(&self) -> String {
        self.inner.id().to_string()
    }

    /// Return current lifecycle metadata as JSON, including capture or runtime errors.
    #[napi]
    pub async fn inspect(&self) -> Result<String> {
        json(self.inner.inspect().await.map_err(job_error)?)
    }

    /// Wait for a terminal state and return its exit result as JSON.
    #[napi]
    pub async fn wait(&self) -> Result<String> {
        json(self.inner.wait().await.map_err(job_error)?)
    }

    /// Request delivery of a signal to this job; use `wait` to confirm its exit.
    #[napi]
    pub async fn signal(&self, signal: i32) -> Result<()> {
        self.inner.signal(signal).await.map_err(job_error)
    }

    /// Request SIGKILL without waiting for confirmed process termination.
    #[napi]
    pub async fn kill(&self) -> Result<()> {
        self.inner.kill().await.map_err(job_error)
    }

    /// Permanently close pipe stdin after previously admitted input; PTY jobs reject EOF.
    #[napi]
    pub async fn eof(&self) -> Result<()> {
        self.inner.eof().await.map_err(job_error)
    }

    /// Return retained log entries as JSON using JSON-encoded log options.
    #[napi]
    pub async fn logs(&self, options: String) -> Result<String> {
        let options: JobLogOptions = serde_json::from_str(&options).map_err(invalid)?;
        json(self.inner.logs(&options).await.map_err(job_error)?)
    }

    /// Replay retained logs and optionally follow output using JSON-encoded log options.
    #[napi]
    pub async fn log_stream(&self, options: String) -> Result<JsJobLogStream> {
        let options: JobLogOptions = serde_json::from_str(&options).map_err(invalid)?;
        Ok(JsJobLogStream {
            closed: AtomicBool::new(false),
            notify: Notify::new(),
            inner: Mutex::new(Some(
                self.inner.log_stream(&options).await.map_err(job_error)?,
            )),
        })
    }

    /// Attach with optional recent-byte or cursor replay; the replay selectors are exclusive.
    /// A writable attachment acquires the job's stdin lease; read-only observers do not.
    #[napi]
    pub async fn attach(
        &self,
        read_only: bool,
        replay_bytes: Option<u32>,
        cursor: Option<String>,
    ) -> Result<JsJobAttachment> {
        if replay_bytes.is_some() && cursor.is_some() {
            return Err(invalid("replayBytes and cursor are mutually exclusive"));
        }
        let replay = match (replay_bytes, cursor) {
            (_, Some(cursor)) => JobReplay::After(cursor),
            (Some(max_bytes), _) => JobReplay::Recent {
                max_bytes: max_bytes as usize,
            },
            _ => JobReplay::None,
        };
        Ok(JsJobAttachment {
            inner: self
                .inner
                .attach_with(|b| b.read_only(read_only).replay(replay))
                .await
                .map_err(job_error)?,
        })
    }
}

#[napi]
impl JsJobAttachment {
    /// Receive the next JSON-encoded event, or `None` when the attachment ends.
    #[napi]
    pub async fn recv(&self) -> Result<Option<String>> {
        self.inner
            .recv()
            .await
            .map_err(job_error)?
            .map(json)
            .transpose()
    }
    /// Admit bytes to guest stdin through this attachment's writable lease.
    #[napi]
    pub async fn write_stdin(&self, data: Buffer) -> Result<()> {
        self.inner
            .write_stdin(data.as_ref())
            .await
            .map_err(job_error)
    }
    /// Resize a PTY job's terminal through this attachment's writable lease.
    #[napi]
    pub async fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        self.inner.resize(rows, cols).await.map_err(job_error)
    }
    /// Release the attachment without closing guest stdin or terminating the job.
    #[napi]
    pub async fn detach(&self) -> Result<()> {
        self.inner.detach().await.map_err(job_error)
    }
}

#[napi]
impl JsJobLogStream {
    /// Read the next JSON-encoded log entry, or `None` after completion or closure.
    #[napi]
    pub async fn next(&self) -> Result<Option<String>> {
        let notified = self.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let mut guard = self.inner.lock().await;
        if self.closed.load(Ordering::Acquire) {
            return Ok(None);
        }
        let Some(stream) = guard.as_mut() else {
            return Ok(None);
        };
        tokio::select! { _ = notified => None, item = stream.next() => item }
            .transpose()
            .map_err(job_error)?
            .map(json)
            .transpose()
    }
    /// Idempotently close this iterator and wake a pending read without stopping the job.
    #[napi]
    pub async fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify.notify_waiters();
        self.inner.lock().await.take();
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn job_error(error: JobError) -> Error {
    let id = match &error {
        JobError::LaunchUnconfirmed { id, .. } => Some(id.to_string()),
        _ => None,
    };
    Error::new(
        Status::GenericFailure,
        format!(
            "[Job] {}",
            serde_json::json!({ "code": error.code(), "message": error.to_string(), "jobId": id })
        ),
    )
}

pub(crate) fn invalid(error: impl std::fmt::Display) -> Error {
    Error::new(Status::InvalidArg, error.to_string())
}

pub(crate) fn json(value: impl serde::Serialize) -> Result<String> {
    serde_json::to_string(&value).map_err(invalid)
}

pub(crate) fn list_options(
    all: bool,
    limit: u32,
    cursor: Option<String>,
) -> Result<JobListBuilder> {
    let mut builder = JobListBuilder::default().all(all).limit(limit as usize);
    if let Some(cursor) = cursor {
        builder = builder.cursor(JobId::parse(cursor).map_err(invalid)?);
    }
    Ok(builder)
}
