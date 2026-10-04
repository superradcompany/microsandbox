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

#[napi(js_name = "Job")]
pub struct JsJob {
    pub(crate) inner: Job,
}

#[napi(js_name = "JobAttachment")]
pub struct JsJobAttachment {
    inner: JobAttachment,
}

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
    #[napi(getter)]
    pub fn id(&self) -> String {
        self.inner.id().to_string()
    }

    #[napi]
    pub async fn inspect(&self) -> Result<String> {
        json(self.inner.inspect().await.map_err(job_error)?)
    }

    #[napi]
    pub async fn wait(&self) -> Result<String> {
        json(self.inner.wait().await.map_err(job_error)?)
    }

    #[napi]
    pub async fn signal(&self, signal: i32) -> Result<()> {
        self.inner.signal(signal).await.map_err(job_error)
    }

    #[napi]
    pub async fn kill(&self) -> Result<()> {
        self.inner.kill().await.map_err(job_error)
    }

    #[napi]
    pub async fn eof(&self) -> Result<()> {
        self.inner.eof().await.map_err(job_error)
    }

    #[napi]
    pub async fn logs(&self, options: String) -> Result<String> {
        let options: JobLogOptions = serde_json::from_str(&options).map_err(invalid)?;
        json(self.inner.logs(&options).await.map_err(job_error)?)
    }

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
    #[napi]
    pub async fn recv(&self) -> Result<Option<String>> {
        self.inner
            .recv()
            .await
            .map_err(job_error)?
            .map(json)
            .transpose()
    }
    #[napi]
    pub async fn write_stdin(&self, data: Buffer) -> Result<()> {
        self.inner
            .write_stdin(data.as_ref())
            .await
            .map_err(job_error)
    }
    #[napi]
    pub async fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        self.inner.resize(rows, cols).await.map_err(job_error)
    }
    #[napi]
    pub async fn detach(&self) -> Result<()> {
        self.inner.detach().await.map_err(job_error)
    }
}

#[napi]
impl JsJobLogStream {
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
